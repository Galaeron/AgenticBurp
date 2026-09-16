"""
Anonymized feature projection for the cloud coordinator.

The cloud coordinator (see coordinator.py / config `coordinator.cloud`) runs
OFF-PREM. Sending it raw request/response bodies or raw header values would
leak whatever the captured traffic contains -- credentials, session tokens,
PII, proprietary payloads. That is unacceptable for a security-testing
harness whose entire input is sensitive by construction.

This module produces the MINIMAL projection the coordinator actually needs to
make a routing decision -- "which specialist agents plausibly apply to this
exchange" -- and nothing more:

  method / URL path / query-and-body param NAMES / response status /
  response structural shape / non-sensitive header PRESENCE flags

It deliberately DROPS:
  - all request and response bodies (only names/shape survive, never values)
  - all header VALUES (only a small set of presence booleans survive)
  - query-string and JSON VALUES (only the parameter names survive)

Design contract (mirrors fast_path.py's own "superset, never narrower"
discipline): the projection must preserve every signal the coordinator uses
to route, while being safe to transmit off-prem. When in doubt, a field is
dropped, not included -- a coordinator that occasionally over-dispatches on a
thinner projection is recoverable; a leaked secret is not.

The projection is a plain dataclass with a `to_prompt_dict()` for the
coordinator prompt and a `to_dict()` for logging/audit. It performs NO
network or LLM calls and is fully deterministic, so it is unit-tested without
a live model.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

if TYPE_CHECKING:
    from harness.models import HttpExchange


# A path segment that is "just an id" -- numeric, uuid, or long hex/base64ish.
# Used only to FLAG that the path carries a resource id (a strong IDOR/authz
# routing signal), and to redact the id value itself out of the projected
# path so no real identifier is transmitted.
_NUMERIC_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_LONG_HEXISH_SEG = re.compile(r"^[0-9a-fA-F]{16,}$")

# Response-body structural fingerprints. These match on SHAPE, never on the
# specific values -- e.g. "this looks like a directory listing" or "this is a
# server stack trace", both of which are routing-relevant (recon/misconfig,
# info_disclosure) but carry no value we need to transmit.
_STACK_TRACE_RE = re.compile(
    r"at (?:com|org|net|java)\.|Traceback \(most recent call last\)|"
    r'File ".*", line \d+|\bStack ?[Tt]race\b',
)
_DIR_LISTING_RE = re.compile(
    r"<title>Index of |Directory listing for |"
    r'<a href="[^"]+/?">[^<]+</a>\s*</?(?:li|td|pre)',
    re.IGNORECASE,
)
_SQL_ERROR_RE = re.compile(
    r"SQL syntax|SQLITE_ERROR|ORA-\d{5}|"
    r"PG::|psycopg2|MySQLdumper|You have an error in your SQL",
    re.IGNORECASE,
)

# Response size buckets -- a coarse magnitude, never the exact length.
_SIZE_BUCKETS = ((0, "empty"), (512, "small"), (16384, "medium"), (262144, "large"))


def _bucket_size(n: int) -> str:
    label = "huge"
    for threshold, name in _SIZE_BUCKETS:
        if n <= threshold:
            return name
        label = name
    return "huge" if n > _SIZE_BUCKETS[-1][0] else label


def _path_and_id_flag(url: str) -> tuple[str, bool]:
    """Return (redacted_path, has_resource_id).

    The path itself is an endpoint name, not a secret, and is highly
    routing-relevant, so it is preserved -- EXCEPT that individual id-shaped
    segments (numeric / uuid / long hex) are replaced with `{id}` so no real
    identifier value leaves the premises. Whether any such segment existed is
    returned separately as a boolean, because "this path addresses a specific
    resource by id" is exactly the IDOR/BOLA routing signal.
    """
    try:
        path = urlparse(url).path or "/"
    except (ValueError, TypeError):
        return "/", False
    has_id = False
    out_segs = []
    for seg in path.split("/"):
        if seg and (_NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg) or _LONG_HEXISH_SEG.match(seg)):
            has_id = True
            out_segs.append("{id}")
        else:
            out_segs.append(seg)
    return "/".join(out_segs) or "/", has_id


def _query_param_names(url: str, limit: int) -> list[str]:
    try:
        query = urlparse(url).query
    except (ValueError, TypeError):
        return []
    if not query:
        return []
    names = []
    for name, _value in parse_qsl(query, keep_blank_values=True):
        if name not in names:
            names.append(name)
        if len(names) >= limit:
            break
    return names


def _json_key_names(body: str, limit: int) -> tuple[list[str], str | None]:
    """Top-level key NAMES of a JSON body (values dropped), plus a coarse
    JSON shape label. Returns ([], None) for non-JSON or unparseable input --
    failing closed, never guessing."""
    if not body:
        return [], None
    stripped = body.lstrip()
    if not stripped or stripped[0] not in "{[":
        return [], None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return [], None
    if isinstance(data, dict):
        names = list(data.keys())[:limit]
        return [str(n) for n in names], "json_object"
    if isinstance(data, list):
        # A list of objects: surface the first element's key names as the
        # representative shape (names only), still no values.
        if data and isinstance(data[0], dict):
            return [str(n) for n in list(data[0].keys())[:limit]], "json_array_of_objects"
        return [], "json_array"
    return [], "json_scalar"


def _content_type(headers: dict[str, str]) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type":
            # Keep only the media type, drop any charset/boundary params.
            return value.split(";", 1)[0].strip().lower()
    return ""


def _has_header(headers: dict[str, str], target: str) -> bool:
    target = target.lower()
    return any(name.lower() == target for name in headers)


def _response_shape(exchange: "HttpExchange", content_type: str) -> list[str]:
    """Structural, value-free fingerprints of the response body. Each entry
    is a routing signal, never a transmitted value."""
    shapes = []
    body = exchange.response_body or ""
    if not body:
        return shapes
    # Cap the scan so a huge body can't blow up matching cost.
    sample = body[:20000]
    if _STACK_TRACE_RE.search(sample):
        shapes.append("stack_trace")
    if _DIR_LISTING_RE.search(sample):
        shapes.append("directory_listing")
    if _SQL_ERROR_RE.search(sample):
        shapes.append("sql_error")
    if "text/html" in content_type or re.match(r"\s*<(?:!doctype|html)", sample, re.IGNORECASE):
        shapes.append("html_document")
    return shapes


@dataclass
class ExchangeProjection:
    """The anonymized, off-prem-safe view of one exchange."""
    method: str
    path: str
    has_resource_id: bool
    query_param_names: list[str] = field(default_factory=list)
    body_param_names: list[str] = field(default_factory=list)
    request_content_type: str = ""
    request_json_shape: str | None = None
    response_status: int | None = None
    response_content_type: str = ""
    response_size_bucket: str = "empty"
    response_shape: list[str] = field(default_factory=list)
    # Non-sensitive PRESENCE flags (booleans only -- never the header value).
    has_authorization: bool = False
    has_cookie: bool = False
    request_has_cors_origin: bool = False
    response_has_cors_headers: bool = False

    def to_prompt_dict(self) -> dict:
        """Compact dict for the coordinator prompt. Omits false/empty fields
        to keep the routing prompt short and the signal dense."""
        d: dict = {
            "method": self.method,
            "path": self.path,
            "response_status": self.response_status,
        }
        if self.has_resource_id:
            d["has_resource_id"] = True
        if self.query_param_names:
            d["query_param_names"] = self.query_param_names
        if self.body_param_names:
            d["body_param_names"] = self.body_param_names
        if self.request_content_type:
            d["request_content_type"] = self.request_content_type
        if self.response_content_type:
            d["response_content_type"] = self.response_content_type
        if self.response_size_bucket and self.response_size_bucket != "empty":
            d["response_size"] = self.response_size_bucket
        if self.response_shape:
            d["response_shape"] = self.response_shape
        for flag in (
            "has_authorization", "has_cookie",
            "request_has_cors_origin", "response_has_cors_headers",
        ):
            if getattr(self, flag):
                d[flag] = True
        return d

    def to_dict(self) -> dict:
        """Full dict for audit logging -- every field, still value-free."""
        return {
            "method": self.method,
            "path": self.path,
            "has_resource_id": self.has_resource_id,
            "query_param_names": self.query_param_names,
            "body_param_names": self.body_param_names,
            "request_content_type": self.request_content_type,
            "request_json_shape": self.request_json_shape,
            "response_status": self.response_status,
            "response_content_type": self.response_content_type,
            "response_size_bucket": self.response_size_bucket,
            "response_shape": self.response_shape,
            "has_authorization": self.has_authorization,
            "has_cookie": self.has_cookie,
            "request_has_cors_origin": self.request_has_cors_origin,
            "response_has_cors_headers": self.response_has_cors_headers,
        }


# Response headers whose mere PRESENCE is a CORS routing signal.
_CORS_RESP_HEADER_PREFIX = "access-control-"


def project_exchange(exchange: "HttpExchange", max_param_names: int = 24) -> ExchangeProjection:
    """Build the anonymized projection of an exchange for the cloud
    coordinator. Deterministic, no network/LLM. Drops every body and every
    header value; keeps only names, shapes, status, and presence booleans."""
    path, has_id = _path_and_id_flag(exchange.url)
    query_names = _query_param_names(exchange.url, max_param_names)
    body_names, json_shape = _json_key_names(exchange.request_body, max_param_names)

    req_ct = _content_type(exchange.request_headers)
    resp_ct = _content_type(exchange.response_headers)

    response_has_cors = any(
        name.lower().startswith(_CORS_RESP_HEADER_PREFIX)
        for name in exchange.response_headers
    )

    return ExchangeProjection(
        method=(exchange.method or "").upper(),
        path=path,
        has_resource_id=has_id,
        query_param_names=query_names,
        body_param_names=body_names,
        request_content_type=req_ct,
        request_json_shape=json_shape,
        response_status=exchange.response_status,
        response_content_type=resp_ct,
        response_size_bucket=_bucket_size(len(exchange.response_body or "")),
        response_shape=_response_shape(exchange, resp_ct),
        has_authorization=_has_header(exchange.request_headers, "authorization"),
        has_cookie=_has_header(exchange.request_headers, "cookie"),
        request_has_cors_origin=_has_header(exchange.request_headers, "origin"),
        response_has_cors_headers=response_has_cors,
    )
