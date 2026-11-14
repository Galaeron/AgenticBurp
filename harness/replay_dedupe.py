"""replay_dedupe.py -- replay each distinct captured request once in the coverage drive.

One identity often captures one endpoint many times: a client polls, or adds a
cache-buster to every fetch. The coverage drive replayed every capture with the
whole check battery. In r9, one long-polling route had 23 captures that differed
only by their transport framing (`t`, `sid`), and it took about half of a 4 h drive.

`distinct_replays` keeps one capture from each group of captures that would test
the same thing. Two captures are merged only when ALL of these hold:

- The same identity. The caller passes one identity's captures, and the key also
  carries the capture's identity key, so captures made as two different principals
  are never compared. Access control needs both.
- The same replay shape. That covers the method, the origin, and the raw path with
  its path object ids. It covers `path_ids`, `object_id` and the content type. It
  covers every query and body input by location and name, and every input value
  except a throwaway one (see below). A body that is neither a JSON object nor a
  form is kept verbatim.
- The same response. That is the status code, the media type and, for a JSON body,
  its top-level keys (an array's first object's keys). A 200 listing never merges
  with a 403 denial. A capture whose body was not kept (an access-matrix probe)
  merges only with one whose body hash is identical.

A value is throwaway when one of these holds:

- `volatile_params.is_volatile_value` calls it a cache-buster.
- It is Engine.IO framing (`t`, `sid`) on a polling-transport request.
- It is LEARNED from the endpoint's own captures, from all identities. To be
  learned, an input must meet all of these:
  - it was seen in at least `MIN_SAMPLES` captures, with a different value each time;
  - every value is an opaque token: letters and digits, not a number, hex, a UUID
    or a word;
  - its name is not named as an identifier;
  - none of its values appears in any captured response body (that would be an id
    or token the server handed out).

An identifier-named input (`id`, `basketId`, `user_id`, `key`) is never throwaway,
so captures of different objects always stay apart, wherever the id is carried.

The first capture of each group, in capture order, is the one replayed. The same
captures therefore give the same replays and the same resume keys. Nothing here
sends a request or rewrites a capture.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

from harness.volatile_params import _is_identifier_name, is_polling_transport, is_volatile_value

# A name must be seen this many times, each with a new value, before its values
# are learned as throwaway. Two values is a coincidence; three is a pattern.
MIN_SAMPLES = 3
# Engine.IO's own query framing on a polling request: `t` is its cache-buster and
# `sid` names the transport session, not an application object.
POLLING_FRAMING = frozenset({"t", "sid"})

_OPAQUE = re.compile(r"^[A-Za-z0-9_.~-]{6,128}$")
_HEX_OR_UUID = re.compile(r"^[0-9a-fA-F-]+$")
_WORD = re.compile(r"^[A-Za-z]+$")


def _is_opaque_token(value: str) -> bool:
    """Letters AND digits, nothing a person or a database would pick as a key:
    not a number, not hex or a UUID, not a word."""
    v = (value or "").strip()
    return bool(_OPAQUE.match(v) and not v.isdigit() and not _HEX_OR_UUID.match(v)
                and not _WORD.match(v) and re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def _json_object(text):
    try:
        data = json.loads(text) if text else None
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _inputs(variant) -> tuple[list[tuple[str, str, str]], str | None]:
    """((location, name, value), ...) for each query and body input of a capture's
    template, plus the raw body when it is neither a JSON object nor a form."""
    template = variant.get("template") or {}
    inputs = [("query", name, value) for name, value in
              parse_qsl(template.get("query") or "", keep_blank_values=True)]
    body = template.get("body") or ""
    parsed = _json_object(body)
    if parsed is not None:
        inputs += [("body", str(name), value if isinstance(value, str)
                    else json.dumps(value, sort_keys=True)) for name, value in parsed.items()]
        return inputs, None
    if "x-www-form-urlencoded" in (template.get("content_type") or "").lower():
        return inputs + [("body", name, value) for name, value in
                         parse_qsl(body, keep_blank_values=True)], None
    return inputs, body or None


def learned_throwaway(variants) -> frozenset:
    """The (location, name) inputs whose values the endpoint's own captures show
    are throwaway; see the module docstring for the rule."""
    seen: dict[tuple[str, str], list[str]] = {}
    for variant in variants or []:
        for location, name, value in _inputs(variant)[0]:
            seen.setdefault((location, name), []).append(value)
    bodies = [str(v.get("response_body") or "") for v in variants or []]
    learned = set()
    for (location, name), values in seen.items():
        if (len(values) >= MIN_SAMPLES and len(set(values)) == len(values)
                and not _is_identifier_name(name)
                and all(_is_opaque_token(value) for value in values)
                and not any(value in body for value in values for body in bodies)):
            learned.add((location, name))
    return frozenset(learned)


def replay_shape(variant, throwaway: frozenset = frozenset()) -> str:
    """What a replay of this capture sends, with each throwaway value masked."""
    template = variant.get("template") or {}
    url = urlsplit(variant.get("url") or "")
    polling = is_polling_transport(variant.get("url") or "")
    inputs, raw_body = _inputs(variant)

    def masked(location, name, value):
        if ((location, name) in throwaway or is_volatile_value(name, value)
                or (polling and location == "query" and name in POLLING_FRAMING)):
            return "\x00throwaway"
        return value
    return json.dumps([
        str(template.get("method") or "GET").upper(), url.scheme, url.netloc, url.path,
        [str(i) for i in template.get("path_ids") or []],
        None if template.get("object_id") is None else str(template.get("object_id")),
        str(template.get("content_type") or "").lower(),
        sorted([location, name, masked(location, name, value)] for location, name, value in inputs),
        raw_body,
    ])


def _json_keys(body):
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return None
    if isinstance(data, dict):
        return ["object", sorted(map(str, data))]
    if isinstance(data, list):
        first = next((item for item in data if isinstance(item, dict)), None)
        return ["array", sorted(map(str, first)) if first is not None else []]
    return ["scalar"]


def response_signature(variant) -> str:
    """The response a capture drew, as far as merging cares: status, media type and
    JSON top-level keys. A body that was not kept is compared by its hash."""
    headers = variant.get("response_headers") or {}
    media = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
    media = media.split(";", 1)[0].strip().lower()
    body = variant.get("response_body") or ""
    if not body and variant.get("response_body_sha256"):
        shape = ["unread", variant.get("response_body_sha256")]
    else:
        shape = _json_keys(body) if body else ["empty"]
    return json.dumps([variant.get("response_status"), media, shape])


def replay_group_key(variant, throwaway: frozenset = frozenset()) -> str:
    return hashlib.sha256("\n".join((
        str(variant.get("identity_key") or ""), replay_shape(variant, throwaway),
        response_signature(variant))).encode()).hexdigest()


def distinct_replays(variants, *, endpoint_variants=None) -> list:
    """`variants` (one identity's captures, in capture order) with each group of
    same-shape, same-response captures reduced to its first. `endpoint_variants`
    (every capture of the endpoint, all identities) is what throwaway inputs are
    learned from; it defaults to `variants`."""
    throwaway = learned_throwaway(variants if endpoint_variants is None else endpoint_variants)
    kept, seen = [], set()
    for variant in variants or []:
        key = replay_group_key(variant, throwaway)
        if key not in seen:
            seen.add(key)
            kept.append(variant)
    return kept
