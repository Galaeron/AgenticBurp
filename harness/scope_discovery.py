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
import logging
from urllib.parse import urlparse

import httpx

from categories import canonicalize
from models import Finding, HttpExchange

log = logging.getLogger("harness.scope_discovery")


def is_host_allowed(url: str, allowed_hosts: list[str]) -> bool:
    """Same hostname-match logic as orchestrator.analyze()'s own
    server.allowed_hosts check (urlparse(url).hostname only, port
    stripped -- see that function's own comment on this exact limitation).
    Extracted so it can be applied per-URL here too, not just once at
    analyze()'s entry -- found live, this session, that nothing previously
    re-checked a URL a validator (or a new discovery feature) constructs
    after that single entry-point check. An empty allowed_hosts list means
    "no application-level scope restriction configured" (matches
    orchestrator.py's own `if self.allowed_hosts:` behavior), NOT "nothing
    is allowed" -- deliberately fails open the same way the existing check
    already does, so this doesn't become a stricter, inconsistent second
    scope policy.
    """
    if not allowed_hosts:
        return True
    hostname = (urlparse(url).hostname or "").lower()
    allowed = {h.lower().lstrip("*.") for h in allowed_hosts}
    return bool(hostname) and any(hostname == h or hostname.endswith("." + h) for h in allowed)


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
                    from run_context import TypedRequest
                    session_ref, request_headers = run_context.sessions.bind_headers(carried_headers)
                    outcome = await run_context.executor().execute(
                        TypedRequest("GET", candidate_url, headers=request_headers),
                        capability="scope_discovery", session_ref=session_ref)
                    if not outcome.ok:
                        continue
                    status, response_headers, response_body = (
                        outcome.status, outcome.headers, outcome.body)
                else:
                    import global_throttle
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
