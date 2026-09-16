"""
Burp sitemap import -- seed the engagement surface from a human's browsing.

The recurring frontier gap (sessions 11/13/15): route/vocabulary guessing
provably cannot reach an app's real agent-role feature surface. A ticket created
by driving a form, an integration call the app makes for you, a template rendered
after a workflow, a pickle carried in a session cookie -- none of these is a
GET route a wordlist can "find". They only exist as REQUESTS a real session
produced. Burp already holds exactly those requests when a human browses the app
through it, so this module ingests Burp's "Save selected items" / site-map XML
export and turns every captured request/response into an analyzable
`HttpExchange` -- with its real headers, cookies, and body intact.

That is the point: an exchange imported here CARRIES the authenticated session
(the pickle cookie for V26, the XML body for XXE, the URL param for SSRF), so the
existing shape-driven confirmation legs bite on it even though no crawler could
have discovered the endpoint. This is the deterministic, human-in-the-loop
counterpart to the stateful feature crawl (`feature_workflow.py`).

Pure parsing: no network, no LLM. The XML is untrusted input, so parsing is
defensive (a malformed item is skipped, never fatal) and hardened against XXE:
`_safe_fromstring` uses defusedxml when installed and otherwise rejects any
DTD/ENTITY declaration outright, blocking external-entity resolution and
entity-expansion ("billion laughs") bombs. Scope-gating to allowed_hosts is
applied on request.
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from harness.models import HttpExchange

log = logging.getLogger("harness.burp_sitemap")

# Prefer defusedxml (forbids DTDs/entities/entity-expansion bombs) when installed;
# otherwise the DTD/ENTITY reject-guard below is the dependency-free equivalent.
try:  # pragma: no cover - exercised whichever way the host is provisioned
    import defusedxml.ElementTree as _DEFUSED_ET
except Exception:
    _DEFUSED_ET = None

# A Burp site-map export never legitimately carries a DTD or entity declaration.
# Rejecting one up front deterministically blocks XXE external-entity resolution
# AND billion-laughs entity expansion even on the stdlib parser (Bandit B313).
_DOCTYPE_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _safe_fromstring(xml_text: str):
    """Parse XML with external-entity / entity-expansion attacks disabled. The
    Burp export is operator-supplied but still treated as untrusted input."""
    probe = (xml_text or "").encode("utf-8", "ignore") if isinstance(xml_text, str) else (xml_text or b"")
    if _DOCTYPE_RE.search(probe):
        raise ValueError("refusing to parse a Burp export containing a DTD/ENTITY "
                         "declaration (XXE / entity-expansion guard)")
    if _DEFUSED_ET is not None:
        return _DEFUSED_ET.fromstring(xml_text)
    return ET.fromstring(xml_text)


@dataclass
class BurpItem:
    """One <item> from a Burp site-map export, decoded to its parts."""
    url: str
    method: str
    path: str
    host: str
    port: int | None
    protocol: str
    status: int | None
    mimetype: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    comment: str = ""


def _text(elem, tag: str) -> str:
    child = elem.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text


def _maybe_b64(elem, tag: str) -> str:
    """Return the (decoded) text of a Burp request/response element. Burp marks
    base64 payloads with base64="true"; a plaintext export has no attribute. A
    decode failure falls back to the raw text so a mangled item still parses as
    much as possible rather than being lost."""
    child = elem.find(tag)
    if child is None or child.text is None:
        return ""
    raw = child.text
    if (child.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return raw
    return raw


def _split_message(raw: str) -> tuple[str, dict, str]:
    """Split a raw HTTP message into (start_line, headers, body).

    Handles CRLF and bare-LF separators. The header/body boundary is the first
    blank line. Repeated headers are PRESERVED (weakness #9): Set-Cookie keeps each
    cookie separate (newline-joined, since commas occur inside Expires dates) so a
    multi-cookie session isn't silently reduced to one; other repeated headers are
    combined per RFC 7230 (comma-joined)."""
    if not raw:
        return "", {}, ""
    # Normalise line endings so a bare-LF export parses the same as CRLF.
    norm = raw.replace("\r\n", "\n")
    head, sep, body = norm.partition("\n\n")
    lines = head.split("\n")
    start_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            name = name.strip()
            value = value.strip()
            if name in headers:
                joiner = "\n" if name.lower() == "set-cookie" else ", "
                headers[name] = headers[name] + joiner + value
            else:
                headers[name] = value
    return start_line, headers, body


def _parse_request(raw: str) -> tuple[str, str, dict, str]:
    """(method, request_target, headers, body) from a raw HTTP request."""
    start, headers, body = _split_message(raw)
    parts = start.split(" ")
    method = parts[0].upper() if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    return method, target, headers, body


def _parse_response(raw: str) -> tuple[int | None, dict, str]:
    """(status, headers, body) from a raw HTTP response."""
    start, headers, body = _split_message(raw)
    status: int | None = None
    parts = start.split(" ")
    if len(parts) > 1:
        try:
            status = int(parts[1])
        except ValueError:
            status = None
    return status, headers, body


def _build_url(protocol: str, host: str, port: int | None, path: str) -> str:
    """Reconstruct the absolute URL, omitting a default port."""
    proto = (protocol or "http").lower()
    netloc = host or ""
    if port and not ((proto == "http" and port == 80) or (proto == "https" and port == 443)):
        netloc = f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{proto}://{netloc}{path}"


def parse_sitemap(source: str) -> list[BurpItem]:
    """Parse a Burp site-map XML export into decoded `BurpItem`s.

    `source` is the XML text itself, or a path to a `.xml` file. Malformed items
    are skipped with a debug log; a completely unparseable document raises
    ValueError so the caller knows the input was not a Burp export."""
    xml_text = _read_source(source)
    try:
        # Hardened parse: defusedxml when present, else a DTD/ENTITY reject-guard --
        # blocks XXE external-entity resolution and entity-expansion bombs.
        root = _safe_fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"not a parseable Burp XML export: {e}") from e

    items: list[BurpItem] = []
    for elem in root.iter("item"):
        try:
            item = _item_from_elem(elem)
        except Exception as e:  # one bad item must not sink the import
            log.debug("burp_sitemap: skipped a malformed <item>: %s", e)
            continue
        if item is not None:
            items.append(item)
    return items


def _read_source(source: str) -> str:
    """Accept either raw XML or a filesystem path to an .xml export."""
    s = source or ""
    stripped = s.lstrip()
    if stripped.startswith("<"):
        return s
    # Treat as a path; read as bytes and decode leniently (Burp exports are UTF-8
    # but may carry stray bytes in CDATA). `s` is an OPERATOR-supplied export path
    # (the tester points the harness at their own saved Burp file), not attacker-
    # controlled input, so this open is trusted by the harness's threat model.
    try:
        with open(s, "rb") as fh:  # nosec B108 - operator-supplied export path, not user input
            return fh.read().decode("utf-8", "replace")
    except OSError as e:
        raise ValueError(f"burp_sitemap source is neither XML nor a readable file: {e}") from e


def _item_from_elem(elem) -> BurpItem | None:
    method_x = _text(elem, "method").strip().upper()
    protocol = _text(elem, "protocol").strip() or "http"
    host = _text(elem, "host").strip()
    path = _text(elem, "path").strip() or "/"
    port_raw = _text(elem, "port").strip()
    try:
        port: int | None = int(port_raw) if port_raw else None
    except ValueError:
        port = None
    status_raw = _text(elem, "status").strip()
    try:
        status: int | None = int(status_raw) if status_raw else None
    except ValueError:
        status = None

    req_raw = _maybe_b64(elem, "request")
    resp_raw = _maybe_b64(elem, "response")

    r_method, r_target, req_headers, req_body = _parse_request(req_raw)
    r_status, resp_headers, resp_body = _parse_response(resp_raw)

    method = method_x or r_method or "GET"
    if r_target and r_target != "/" and (r_target.startswith("/") or "://" in r_target):
        # Prefer the request line's target -- it carries the query string, which
        # the <path> element strips (and query params are where SSRF/redirect
        # /SQLi injection points live).
        if "://" in r_target:
            path = urlsplit(r_target).path + (
                "?" + urlsplit(r_target).query if urlsplit(r_target).query else "")
        else:
            path = r_target
    # Host from a request Host header if the <host> element is empty.
    if not host:
        host = (req_headers.get("Host") or req_headers.get("host") or "").split(":")[0]

    url_elem = _text(elem, "url").strip()
    url = url_elem or _build_url(protocol, host, port, path)

    if status is None:
        status = r_status

    return BurpItem(
        url=url, method=method, path=path, host=host, port=port, protocol=protocol,
        status=status, mimetype=_text(elem, "mimetype").strip(),
        request_headers=req_headers, request_body=req_body,
        response_headers=resp_headers, response_body=resp_body,
        comment=_text(elem, "comment").strip(),
    )


def item_to_exchange(item: BurpItem) -> HttpExchange:
    """Project a decoded BurpItem to an analyzable HttpExchange."""
    return HttpExchange(
        url=item.url, method=item.method,
        request_headers=dict(item.request_headers or {}),
        request_body=item.request_body or "",
        response_status=item.status,
        response_headers=dict(item.response_headers or {}),
        response_body=item.response_body or "",
        analyst_note=(f"imported from Burp site-map (HTTP {item.status})"
                      + (f" -- {item.comment}" if item.comment else "")),
    )


def _host_allowed(url: str, allowed_hosts: list[str] | None) -> bool:
    if not allowed_hosts:
        return True
    host = (urlsplit(url).hostname or "").lower()
    return any(host == h.lower() or host.endswith("." + h.lower()) for h in allowed_hosts)


def load_exchanges(source: str, *, allowed_hosts: list[str] | None = None,
                   max_items: int = 2000, include_out_of_scope: bool = False) -> list[HttpExchange]:
    """The main entry: a Burp XML export -> analyzable `HttpExchange` list.

    Scope-gated to `allowed_hosts` (an out-of-scope item is dropped unless
    `include_out_of_scope`) so an imported browsing session can't smuggle a
    third-party host into the run. Bounded by `max_items`."""
    items = parse_sitemap(source)
    out: list[HttpExchange] = []
    dropped = 0
    for item in items[:max_items]:
        if not include_out_of_scope and not _host_allowed(item.url, allowed_hosts):
            dropped += 1
            continue
        out.append(item_to_exchange(item))
    log.info("burp_sitemap: imported %d exchange(s) from %d item(s) (%d out-of-scope dropped)",
             len(out), len(items), dropped)
    return out


def seed_engagement_state(state, exchanges: list[HttpExchange]) -> int:
    """Fold imported exchanges into an `EngagementState`'s surface.

    Each import becomes a `SurfaceEndpoint` (keyed METHOD+normalized path), with
    object-scoping inferred from the path and the response retained as a reachable
    signal, so the Burp-discovered surface enters the fused worklist and the
    coverage matrix exactly like a crawl-discovered one. Returns the number of
    endpoints touched. The credential-bearing exchange itself is what the
    confirmation legs need, so callers should ALSO run these exchanges through
    analyze()/the precondition legs; this just makes the surface visible for
    prioritisation."""
    import harness.engagement as eng
    n = 0
    for ex in exchanges or []:
        path = eng.normalize_path(ex.url)
        ep = state._ep(ex.method, path)
        # object-scoping is a stored field on SurfaceEndpoint (unlike role_crawl's
        # computed property), so set it from the normalized path shape.
        if "{id}" in path:
            ep.object_scoped = True
        # A 2xx with a substantive body means this identity reached it.
        if ex.response_status and 200 <= ex.response_status < 300 and len((ex.response_body or "").strip()) > 2:
            if "imported:burp" not in ep.reachable_roles:
                ep.reachable_roles.append("imported:burp")
        n += 1
    return n
