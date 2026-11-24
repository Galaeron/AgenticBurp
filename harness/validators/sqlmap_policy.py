"""sqlmap request budgets, tool capability labels and the create-endpoint classifier: moved
verbatim out of sqlmap.py (ARC-9). create_endpoint_reason only names a reason; it sends nothing."""

from __future__ import annotations

import json as _json
import re
from urllib.parse import urlsplit

from harness.models import HttpExchange


# Create endpoints get a light sqlmap (owner decision, #28): every request sqlmap
# sends to one may create an object (the 8h juice-shop run: one sqlmap scan sent
# 4,765 requests to POST /api/Users and 685 of them created accounts). Level 1,
# risk 1, boolean + error based only (no stacked, time or union queries), and a
# hard per-endpoint request cap enforced by the run's tool proxy.
LIGHT_TECHNIQUES = "BE"
DEFAULT_CREATE_ENDPOINT_MAX_REQUESTS = 200
# PUT/PATCH get the same light scan with a much tighter cap (r6: a full scan spent
# 2-3k requests on each of ~10 write endpoints), counted against the case's
# mutating ceiling. Every request may change state, so the harness also never
# replays one to reproduce a hit. DELETE is not scanned at all (no restore).
WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
WRITE_ENDPOINT_MAX_REQUESTS = 20
# DELETE is never scanned: there is no restore for a deleted object, and every
# sqlmap request to it may delete one.
NO_SCAN_WRITE_METHODS = frozenset({"DELETE"})
# The capabilities a write scan and a harness reproduction send under. A mutating
# send is counted against the case's mutating ceiling under that name
# (validators.mutating_ceiling_by_check, else max_mutating_requests_per_finding,
# both capped at the gate's hard ceiling).
_TOOL_CAPABILITY = "sqlmap_tool"
_TECHNIQUE_PROBE_CAPABILITY = "sqlmap_technique_probe"
_ERROR_PROBE_SENDS = 5          # baseline, breaking x2, control x2
_UNION_PROBE_MIN_SENDS = 4      # baseline, echo control, one UNION and its repeat
_ID_KEYS = ("id", "_id", "uuid", "guid")
_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$", re.I)
_COLLECTION_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z_-]*[a-z]s$")


def _has_new_object_id(body: str) -> bool:
    try:
        doc = _json.loads(body or "")
    except ValueError:
        return False
    for obj in (doc, doc.get("data") if isinstance(doc, dict) else None):
        if isinstance(obj, dict) and any(obj.get(k) not in (None, "") for k in _ID_KEYS):
            return True
    return False


def create_endpoint_reason(exchange: HttpExchange) -> str:
    """Why this captured request looks like it creates an object, or "".

    A POST/PUT whose base capture answered 201, or a POST to a collection path
    (no id as its last segment) that answered with a new object id or whose last
    segment is a plural collection name (/api/Users, /api/BasketItems). A
    registration is a create even though its body carries a password; a login
    (no 201, not a collection path, answering a session token) is not."""
    method = exchange.method.upper()
    if method not in ("POST", "PUT"):
        return ""
    path = urlsplit(exchange.url).path
    if exchange.response_status == 201:
        return f"{method} {path} answered 201 Created in the base capture"
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if method != "POST" or not last or _ID_SEGMENT.match(last):
        return ""
    # A login that answers with the user object and a session token is not a create.
    if ((exchange.response_status or 0) // 100 == 2
            and "token" not in (exchange.response_body or "").lower()
            and _has_new_object_id(exchange.response_body)):
        return f"POST {path} answered with a new object id in the base capture"
    if _COLLECTION_SEGMENT.match(last):
        return f"POST {path} targets a collection"
    return ""


def _light_note(reason: str, cap: int, proxy) -> str:
    sent = (f"; {proxy.forwarded} request(s) sent"
            + (", cap reached" if proxy.stop_reason == "tool_cap" else "")) if proxy is not None else ""
    return (f"light sqlmap ({reason}): level 1, risk 1, "
            f"techniques {LIGHT_TECHNIQUES}, at most {cap} requests{sent}")
