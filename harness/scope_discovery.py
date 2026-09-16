"""
Autonomous scope-discovery MVP.

Deliberately the smallest real slice of this project's largest known
architectural gap (see REVIEW.md's #3/#8 and HANDOVER.md's "the harness has
no autonomous action capability" note): every real exploit tested against
this harness has been manually crafted and sent by a human -- nothing in
the pipeline reacts to "this exchange just proved a privilege escalation"
by looking any further.

This is GET-only by design (SAFE tier per safety_gate.py's own
classification -- see that module's classify()), so it never needs
allow_mutating_replay authorization. It is opt-in via
autonomous_discovery.enabled (config.yaml), off by default, the same
pattern already established for validators.active_enabled/
allow_mutating_replay.

Explicitly NOT a general-purpose crawler -- that's recon_validator.py's
job, already built, already real (it does genuine recursive multi-request
crawling, just triggered by an agent's own "recon"-classified finding, not
by a scope-change signal). This module checks a short, fixed, curated list
of commonly-interesting paths with the SAME credentials a just-proven
privilege escalation used, nothing more.

Deliberately a top-level module, not under validators/: Validator
subclasses (validators/base.py) are dispatched by matching an INDIVIDUAL
finding's vulnerability_class -- that shape doesn't fit "did ANY finding
on this whole exchange indicate a scope change," which needs to look
across all of an exchange's findings at once.
"""
from __future__ import annotations
import ipaddress
import logging
from urllib.parse import urlparse

import httpx

from harness.categories import canonicalize
from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.scope_discovery")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _parse_allow_entry(entry: str):
    """Parse one allowed_hosts entry into (scheme, host, port, network).

    Supported, all backward compatible with the historical bare-host form:
      host                     -> host (and its subdomains), any scheme/port
      host:port                -> only that port
      scheme://host[:port]     -> also constrain the scheme
      1.2.3.4  or  10.0.0.0/24 -> single IP / CIDR network match

    Any field left None is an unconstrained wildcard for that dimension, so a
    plain "example.com" behaves exactly as before (matches every port/scheme).
    """
    entry = (entry or "").strip().lower()
    if not entry:
        return (None, None, None, None)
    scheme = None
    if "://" in entry:
        scheme, entry = entry.split("://", 1)
        scheme = scheme or None
    # CIDR / bare-IP network first: a CIDR's '/' would otherwise be mistaken for
    # a path separator below.
    try:
        return (scheme, None, None, ipaddress.ip_network(entry, strict=False))
    except ValueError:
        pass
    entry = entry.split("/", 1)[0]  # drop any path
    port = None
    host = entry
    if entry.count(":") == 1:  # host:port (bare IPv6 literals are not a scope form)
        maybe_host, maybe_port = entry.rsplit(":", 1)
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)
    host = host.lstrip("*.")
    return (scheme, host or None, port, None)


def is_host_allowed(url: str, allowed_hosts: list[str], *, active_mode: bool = False) -> bool:
    """Decide whether `url`'s host is within the configured engagement scope.

    Matching understands scheme + host + port + CIDR (see _parse_allow_entry),
    while a bare "example.com" entry keeps its historical meaning: that host and
    its subdomains on any scheme/port. Extracted so it can be applied per-URL,
    not just once at analyze()'s entry -- nothing otherwise re-checked a URL a
    validator or discovery feature constructs after that single check.

    Empty `allowed_hosts` means "no application-level scope configured". In
    PASSIVE mode that fails open (historical behavior -- passive analysis sends
    nothing), but in ACTIVE mode (`active_mode=True`) it fails CLOSED (W-17):
    dispatching live probes against an undeclared scope is precisely what must
    never happen by default. Passive callers omit `active_mode`, so their
    behavior is unchanged.
    """
    if not allowed_hosts:
        return not active_mode
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
    url_port = parsed.port
    url_scheme = (parsed.scheme or "").lower()
    try:
        url_ip = ipaddress.ip_address(hostname)
    except ValueError:
        url_ip = None
    for entry in allowed_hosts:
        scheme, host, port, network = _parse_allow_entry(entry)
        if scheme and url_scheme and scheme != url_scheme:
            continue
        if network is not None:
            if url_ip is not None and url_ip in network:
                return True
            continue
        if not host:
            continue
        if not (hostname == host or hostname.endswith("." + host)):
            continue
        if port is not None:
            effective = url_port if url_port is not None else _DEFAULT_PORTS.get(url_scheme)
            if effective != port:
                continue
        return True
    return False


def _should_trigger(findings: list[Finding], trigger_categories: list[str]) -> bool:
    trigger_set = set(trigger_categories)
    for f in findings:
        if not f.confirmed:
            continue
        category = canonicalize(f.vulnerability_class)
        if category in trigger_set:
            return True
    return False


async def discover_from_scope_change(
    exchange: HttpExchange,
    findings: list[Finding],
    config: dict,
    allowed_hosts: list[str],
    run_context=None,
) -> list[HttpExchange]:
    """
    Given the exchange just analyzed and the findings it produced, decide
    whether a real, confirmed privilege escalation happened, and if so,
    probe a short list of commonly-interesting paths on the SAME host
    using the SAME credentials (copied verbatim from the triggering
    exchange's own Authorization/Cookie headers -- no new identity/session
    data model needed; confirmed this session that HttpExchange/Finding
    have no identity linkage today, and the credentials that produced the
    escalation are already sitting right there in exchange.request_headers).

    Returns a list of new HttpExchange objects built from real responses,
    ready to be fed back through orchestrator.analyze(). Never raises for
    an individual candidate's failure (connection refused, timeout, 404 --
    a candidate path not existing on this particular target is the normal
    case, not an error); only construction-level misconfiguration (a
    missing config section) is allowed to surface as an exception.
    """
    discovery_cfg = config.get("autonomous_discovery", {})
    if not discovery_cfg.get("enabled", False):
        return []

    trigger_categories = discovery_cfg.get("trigger_categories", [])
    if not _should_trigger(findings, trigger_categories):
        return []

    candidate_paths = discovery_cfg.get("candidate_paths", [])
    max_requests = discovery_cfg.get("max_new_requests_per_trigger", 5)

    parsed = urlparse(exchange.url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    carried_headers = {
        k: v for k, v in exchange.request_headers.items()
        if k.lower() in ("authorization", "cookie")
    }

    discovered: list[HttpExchange] = []
    client = None if run_context is not None else httpx.AsyncClient(
        timeout=10.0, follow_redirects=False)
    try:
        for path in candidate_paths[:max_requests]:
            candidate_url = base + path
            if not is_host_allowed(candidate_url, allowed_hosts):
                log.warning(
                    "scope_discovery: skipping %s -- outside server.allowed_hosts scope", candidate_url
                )
                continue
            try:
                if run_context is not None:
                    from harness.run_context import TypedRequest
                    session_ref, request_headers = run_context.sessions.bind_headers(carried_headers)
                    outcome = await run_context.executor().execute(
                        TypedRequest("GET", candidate_url, headers=request_headers),
                        capability="scope_discovery", session_ref=session_ref)
                    if not outcome.ok:
                        continue
                    status, response_headers, response_body = (
                        outcome.status, outcome.headers, outcome.body)
                else:
                    from harness import global_throttle
                    await global_throttle.acquire()
                    resp = await client.get(candidate_url, headers=carried_headers)
                    status, response_headers, response_body = (
                        resp.status_code, dict(resp.headers), resp.text)
            except httpx.HTTPError as e:
                log.debug("scope_discovery: %s unreachable (%s) -- normal, not an error", candidate_url, e)
                continue

            discovered.append(HttpExchange(
                url=candidate_url,
                method="GET",
                request_headers={"Host": parsed.netloc, **carried_headers},
                request_body="",
                response_status=status,
                response_headers=dict(response_headers or {}),
                response_body=response_body or "",
                analyst_note=f"Autonomous discovery, triggered by a confirmed finding on {exchange.url}",
            ))
    finally:
        if client is not None:
            await client.aclose()

    if discovered:
        log.info(
            "scope_discovery: triggered by %s, probed %d candidate path(s), got %d real response(s)",
            exchange.url, min(len(candidate_paths), max_requests), len(discovered),
        )
    return discovered
