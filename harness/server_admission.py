"""ARC-1 active-traffic admission, shared by every server router (ARC-9).

This module is the single source of the admission dependency and its registry:
the router modules (harness/server_routes_*.py) import `_ACTIVE_TRAFFIC` and
`_admit_active_traffic` from here, never a copy. Scope admission
(_require_active_scope, _require_target_fetch) stays in harness.server beside the
orchestrator whose scope it reads.

The dependency serves whichever server module built the app: harness.server sets
`app.state.harness_server` to itself, and the dependency reads the auth token and
the orchestrator through it at request time.
"""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request


def _admit_active_traffic(orchestrator) -> None:
    """The active-mode master switch (validators.active_enabled, live value
    including the POST /settings toggle) for a request that sends target traffic.
    require_active_traffic applies it to whole routes; a route that sends only
    behind a body flag calls it before that branch."""
    if not orchestrator.validator_registry.active_enabled:
        raise HTTPException(
            status_code=403,
            detail="refused: active operations are disabled. This route sends live "
                   "requests to the target, so it requires validators.active_enabled "
                   "(set it in config.local.yaml, or arm active mode via POST /settings "
                   "/ the Burp 'Active testing' toggle), on top of a configured scope.")


async def require_active_traffic(request: Request,
                                 authorization: str | None = Header(default=None)) -> None:
    """ARC-1: the ONE admission dependency for every route that sends target
    traffic. It authenticates first (401 before 403), then applies the master
    switch, before the handler parses or does anything else. Scope admission
    stays per route, because each route names its target differently."""
    srv = getattr(request.app.state, "harness_server", None)
    if srv is None:  # fail closed: an app no harness server built admits nothing
        raise HTTPException(status_code=500,
                            detail="active-traffic admission is not bound to a harness server")
    srv._require_auth(authorization)
    _admit_active_traffic(srv.orchestrator)


# ARC-1 admission registry: every route whose handler reaches RunContext.create,
# standalone_context or transport_for. test_active_traffic_admission scans
# app.routes and requires this registry to list exactly those routes, so a new
# traffic-sending route cannot ship without an admission decision.
#   ACTIVE_TRAFFIC_ROUTES  carry Depends(require_active_traffic).
#   ACTIVE_TRAFFIC_WHEN    send only when the named body flag is set; the handler
#                          calls _admit_active_traffic() before that branch.
#   PASSIVE_RUN_ROUTES     own a run but send nothing to the target while active
#                          mode is off (the documented passive-default workflow).
ACTIVE_TRAFFIC_ROUTES = frozenset({
    ("POST", "/crawl"),
    ("POST", "/crawl-roles"),
    ("POST", "/engagement/{host}/advance"),
    ("POST", "/engagement/{host}/investigate"),
    ("POST", "/probe-missing-auth"),
    ("POST", "/active-probe"),
})
ACTIVE_TRAFFIC_WHEN = {("POST", "/engagement/{host}/run"): "execute"}
PASSIVE_RUN_ROUTES = {
    ("POST", "/analyze"): "Burp 'Send to LLM Harness': reviews the supplied exchange. Its run's "
                          "gate carries the live active_enabled, so a passive analysis sends "
                          "nothing to the target (test_captured_shapes_passive, "
                          "test_engagement_atomic_passive).",
}
_ACTIVE_TRAFFIC = [Depends(require_active_traffic)]
