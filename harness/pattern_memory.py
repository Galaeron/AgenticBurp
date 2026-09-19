"""Cross-host pattern memory (P2.5).

An append-only, host-agnostic memory of "this SHAPE of endpoint, on some
past engagement, turned out to be this vulnerability class" -- so a new
engagement against a DIFFERENT host can be nudged toward the right
specialist for a familiar-looking endpoint, without re-deriving that
signal from scratch every time.

No private data ever crosses engagements: a pattern is keyed on
(vulnerability_class, signature), where `signature` is built ONLY from the
request's structural shape -- HTTP method, the normalized path template
(engagement.normalize_path collapses object ids, so /orders/42 and
/orders/{id} are the same shape), and the SORTED PARAMETER NAMES (never
values). No host, no query values, no headers, no credentials, no evidence
text, no summary prose ever enters the store. This is deliberately a much
narrower signal than a Finding -- it cannot leak a secret because it never
carries anything but shape.

Storage is a plain append-only JSONL file (one line per confirmed pattern
observation) -- simple, human-auditable, and trivially portable; no schema
migration machinery needed for something this small. Duplicate observations
of the same (vulnerability_class, signature) are harmless (the file is a
log, not a keyed table) and collapse naturally at read time.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from harness.engagement import normalize_path

DEFAULT_PATH = Path(__file__).parent / "pattern_memory.jsonl"


def _query_param_names(url: str) -> list[str]:
    """Query parameter NAMES only, never values -- the values are exactly
    the kind of private/host-specific data this store must never carry."""
    try:
        return [k for k, _v in parse_qsl(urlsplit(url or "").query, keep_blank_values=True)]
    except ValueError:
        return []


def _method_and_url(exchange) -> tuple[str, str]:
    if isinstance(exchange, dict):
        return (exchange.get("method") or "GET"), (exchange.get("url") or "")
    return (getattr(exchange, "method", None) or "GET"), (getattr(exchange, "url", None) or "")


def signature_for(method: str, url: str, param_names: list[str] | None = None) -> str:
    """A host-agnostic structural signature: METHOD + normalized path
    template + sorted parameter NAMES. Never includes host, query/body
    VALUES, headers, or any evidence/response content.

    `param_names=None` (the default) auto-extracts query parameter NAMES
    from `url` itself; pass an explicit list to use different/additional
    names instead (e.g. signature_for_finding folding in a finding's own
    parameter_name)."""
    path = normalize_path(url)
    names = _query_param_names(url) if param_names is None else param_names
    names = sorted({str(p) for p in names if p})
    return f"{(method or 'GET').upper()} {path} params={','.join(names)}"


def signature_for_finding(finding: dict, exchange) -> str:
    """Convenience: build a signature from a confirmed finding + the
    exchange it was confirmed on. A finding's own parameter_name is folded
    in ONLY when its parameter_location is "query" or "body" -- a
    path-scoped object id (parameter_location empty/"path") is already
    represented by normalize_path's {id} collapse, so adding the raw id
    value's "name" there would make the signature depend on incidental
    naming rather than shape and could fail to match an otherwise
    identical endpoint. Only NAMES ever enter the signature -- see
    signature_for's docstring."""
    if isinstance(finding, dict):
        loc = (finding.get("parameter_location") or "").strip().lower()
        pname = finding.get("parameter_name") or ""
    else:
        loc = (getattr(finding, "parameter_location", "") or "").strip().lower()
        pname = getattr(finding, "parameter_name", "") or ""
    method, url = _method_and_url(exchange)
    params = set(_query_param_names(url))
    if pname and loc in ("query", "body"):
        params.add(pname)
    return signature_for(method, url, sorted(params))


def record_pattern(vulnerability_class: str, signature: str, *, path: Path | str = DEFAULT_PATH) -> None:
    """Append one observation. Append-only: never rewrites or dedupes the
    file in place (that would need a read-modify-write race window this
    module deliberately avoids -- see known_patterns() for read-time dedup)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {"vulnerability_class": vulnerability_class, "signature": signature,
              "recorded_at": time.time()}
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def known_patterns(path: Path | str = DEFAULT_PATH) -> set[tuple[str, str]]:
    """Every distinct (vulnerability_class, signature) ever recorded. Missing
    file -> empty set, never an error (a fresh install has no memory yet)."""
    p = Path(path)
    if not p.exists():
        return set()
    seen: set[tuple[str, str]] = set()
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            vc, sig = rec.get("vulnerability_class"), rec.get("signature")
            if vc and sig:
                seen.add((vc, sig))
    return seen


def suggest_classes_for_exchange(exchange, *, path: Path | str = DEFAULT_PATH) -> list[str]:
    """On a NEW exchange (any host), check pattern memory FIRST: does this
    exchange's structural shape match a vulnerability class seen on some
    PAST engagement? Returns the matching vulnerability classes (there can
    be more than one pattern for the same shape), sorted for determinism.
    Empty when the memory has nothing for this shape -- never guesses."""
    method, url = _method_and_url(exchange)
    sig = signature_for(method, url, _query_param_names(url))
    return sorted({vc for (vc, s) in known_patterns(path) if s == sig})
