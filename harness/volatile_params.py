"""volatile_params.py -- query parameters that change on every request.

A client adds a cache-buster (an epoch timestamp, a random token, the current
date and time) so that no cache answers the request. Such a parameter says
nothing about what the request tests, but it made every capture of one request a
new plan and a new confirmation case: the same listing, fetched twice, was
planned and validated twice. Like cache.py's `_VOLATILE_HEADER_NAMES` does for
headers, `stable_url` drops these parameters from the URL before it is used as
key material. The parameter is detected by its VALUE shape, and the test is conservative: a
small integer, a hex or UUID object id, a word or a date without a time is kept,
a parameter named as an identifier (`id`, `orderId`, `key`) is always kept, and a
random token counts only under a conventional cache-buster name, so real
identifiers still split keys.

`is_polling_transport` recognises an Engine.IO long-polling request by its
protocol markers (an `EIO` version and `transport=polling`). Its body is a
transport frame, not an HTTP form or query an injection or CSRF check can mean
anything against, so those checks are not planned for it (websocket checks
still see it). Engine.IO defines `t` as its cache-buster, so on a polling URL
`t` is dropped whatever its shape.

Key material only: the exchange itself, its stored URL and the binding
fingerprint (planner.exchange_fingerprint) are never rewritten.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

# Epoch seconds and milliseconds between 2010-01-01 and 2100-01-01: a smaller or
# shorter number is an ordinary id or count.
_EPOCH_MIN_S = 1_262_304_000
_EPOCH_MAX_S = 4_102_444_800
# An ISO 8601 date WITH a time ("2026-11-09T12:34:56", "2026-11-09 12:34:56.123Z").
_ISO_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?$", re.I)
# RFC 1123 / JavaScript Date.toString / toUTCString: a weekday or month name next
# to a clock time ("Mon, 09 Nov 2026 12:34:56 GMT", "Mon Nov 09 2026 12:34:56 GMT+0100").
_NAMED_DATETIME = re.compile(
    r"^(mon|tue|wed|thu|fri|sat|sun)[a-z]*,? .*\b\d{1,2}:\d{2}:\d{2}\b", re.I)
# Math.random(): a fraction with at least eight decimals.
_RANDOM_FRACTION = re.compile(r"^0\.\d{8,}$")
# A short random token: letters of both cases AND digits, nothing else but - and _.
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{6,16}$")


def _is_random_token(value: str) -> bool:
    return bool(_TOKEN.match(value) and re.search(r"[a-z]", value)
                and re.search(r"[A-Z]", value) and re.search(r"\d", value))


# A random token is a cache-buster only under a name clients conventionally give
# one, or a name that starts with an underscore (jQuery's `_`, `_t`, `_cb`). Any
# other short name is not enough: `v`, `p`, `k`, `ref` and `key` carry opaque
# mixed-case object ids (a video or share id) as often as noise.
_TOKEN_NAMES = frozenset({"t", "r", "ts", "cb", "rnd", "rand", "nc", "nocache", "cachebust",
                          "cachebuster", "buster"})
# A parameter named as an identifier is never dropped, whatever its value looks
# like: `id=1762689296` is an object, not an epoch.
# Conservative: any name ending in "id" (id, oid, orderId, user_id) counts.
_IDENTIFIER_NAME = re.compile(r"id$|^(key|ref|sku|code|uuid|guid)$", re.I)


def _is_identifier_name(name: str) -> bool:
    return bool(_IDENTIFIER_NAME.search(name.strip()))


def is_volatile_value(name: str, value: str) -> bool:
    """Whether a query parameter's value has the shape of a cache-buster.

    A parameter named as an identifier (`id`, `orderId`, `user_id`, `key`) is
    never one. A random token counts only under a conventional cache-buster name
    (`t`, `r`, `ts`, `cb`, ...) or one that starts with an underscore: any other
    name with a mixed-case value is more likely a code or an opaque id, and is
    kept."""
    v = (value or "").strip()
    key = (name or "").strip()
    if not v or _is_identifier_name(key):
        return False
    if v.isdigit():
        n = int(v)
        if len(v) == 10:
            return _EPOCH_MIN_S <= n <= _EPOCH_MAX_S
        if len(v) == 13:
            return _EPOCH_MIN_S * 1000 <= n <= _EPOCH_MAX_S * 1000
        return False
    if _ISO_DATETIME.match(v) or _NAMED_DATETIME.match(v) or _RANDOM_FRACTION.match(v):
        return True
    return (key.lower() in _TOKEN_NAMES or key.startswith("_")) and _is_random_token(v)


def _pairs(query: str) -> list[tuple[str, str, str]]:
    """(raw segment, decoded name, decoded value) for each `&`-separated segment."""
    out = []
    for segment in query.split("&"):
        if not segment:
            continue
        name, _, value = segment.partition("=")
        out.append((segment, unquote_plus(name), unquote_plus(value)))
    return out


def is_polling_transport(url: str) -> bool:
    """An Engine.IO / socket.io long-polling request: an `EIO` protocol version and
    `transport=polling` in the query."""
    query = urlsplit(url or "").query
    if not query:
        return False
    params = {name.lower(): value for _, name, value in _pairs(query)}
    return params.get("eio", "").strip().isdigit() and (
        params.get("transport", "").strip().lower() == "polling")


def stable_url(url: str) -> str:
    """`url` without its cache-buster query parameters, for use as key material.

    Every other segment keeps its raw spelling and order; a URL with nothing to
    drop is returned unchanged."""
    parts = urlsplit(url or "")
    if not parts.query:
        return url or ""
    polling = is_polling_transport(url)
    pairs = _pairs(parts.query)
    kept = [seg for seg, name, value in pairs
            if not ((polling and name == "t") or is_volatile_value(name, value))]
    if len(kept) == len(pairs):
        return url
    return urlunsplit(parts._replace(query="&".join(kept)))
