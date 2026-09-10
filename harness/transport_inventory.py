"""transport_inventory.py -- the auditable inventory of every outbound-transport
call-site in the harness (Astra T08, inventory + routing-gap audit).

The T03 run-scoped executor (`run_context.Executor`, fronted by
`safety_gate.GatedAsyncClient`) is meant to become the ONE policy-aware transport
for target-directed traffic: scope enforced before every hop, per-session cookie
jars, credential-forwarding rules, mutation ceilings, cancellation, and captured
outcome artifacts. Migrating every send to it is incremental (T03 -> T08); the
danger is that a NEW direct send is added and silently bypasses the gate/executor
-- exactly the "green tests, dead pipeline" failure mode this project guards
against, one channel down.

This module makes the transport surface *auditable and enforced*:

  - `TRANSPORT_SITES` is a curated registry: every production module that opens an
    outbound channel (HTTP, container, browser, raw socket), with its scope
    (target | egress | llm | infra), its current routing, an owner, and -- for a
    target-directed send not yet on the executor -- the specific remaining gap.
  - `scan_http_client_modules()` scans the source tree for `httpx` client
    constructions. The paired test asserts the scan and the registry agree, so a
    new un-inventoried direct send fails CI until it is either routed through the
    executor or explicitly documented here with an owner.

This is inventory + audit only: it changes no transport behavior. Actually
migrating a gap (and re-qualifying the retired oracles) is the follow-on work the
registry's `owner`/`gap` fields point at.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# Transport channels the harness can open.
CHANNEL_HTTP = "http"           # httpx client
CHANNEL_CONTAINER = "container"  # docker/subprocess (tool_runner)
CHANNEL_BROWSER = "browser"     # playwright/chromium
CHANNEL_SOCKET = "raw_socket"   # hand-rolled socket/ssl

# Where the traffic goes -- only `target` traffic is in scope for the run-scoped
# executor. Egress (public advisory/registry APIs), llm (Ollama), and infra (the
# executor/gate themselves) are deliberately not target-executor-routed.
SCOPE_TARGET = "target"
SCOPE_EGRESS = "egress"
SCOPE_LLM = "llm"
SCOPE_INFRA = "infra"

# Current routing of the site.
ROUTING_ADAPTER = "adapter"     # this IS the routed transport (executor/gate/tool_runner/browser_driver)
ROUTING_GATED = "gated"         # target send that passes through the SafetyGate/GatedAsyncClient
ROUTING_DIRECT = "direct"       # a direct send NOT (yet) on the executor -- a routing gap if target-scoped


@dataclass(frozen=True)
class TransportSite:
    module: str                 # path relative to the harness dir
    channel: str
    scope: str
    routing: str
    owner: str
    note: str = ""
    gap: str = ""               # the specific remaining migration gap (target+direct only)

    @property
    def is_routing_gap(self) -> bool:
        return self.scope == SCOPE_TARGET and self.routing == ROUTING_DIRECT


# --------------------------------------------------------------------------- #
# The registry. Every production module that constructs an httpx client (see
# `scan_http_client_modules`) plus the container/browser/socket channels.
# --------------------------------------------------------------------------- #

TRANSPORT_SITES: tuple[TransportSite, ...] = (
    # ---- infra: the routed transport itself ----
    TransportSite("run_context.py", CHANNEL_HTTP, SCOPE_INFRA, ROUTING_ADAPTER,
                  owner="astra-identity (T03)",
                  note="RunContext.Executor + ManagedSession -- the run-scoped, "
                       "scope/cookie/credential-aware transport target sends migrate onto."),
    TransportSite("safety_gate.py", CHANNEL_HTTP, SCOPE_INFRA, ROUTING_ADAPTER,
                  owner="astra-identity (T03)",
                  note="SafetyGate + GatedAsyncClient -- the mutation/scope gate the "
                       "executor and mutating validators send through."),
    TransportSite("tool_runner.py", CHANNEL_CONTAINER, SCOPE_INFRA, ROUTING_ADAPTER,
                  owner="tools",
                  note="docker/subprocess adapter (sqlmap/ffuf); force-removes the "
                       "container on timeout. Executor container adapter is T08 follow-on."),
    TransportSite("browser_driver.py", CHANNEL_BROWSER, SCOPE_INFRA, ROUTING_ADAPTER,
                  owner="tools",
                  note="Playwright/Chromium adapter for browser_xss/dom_xss/stored_xss. "
                       "Executor browser adapter is T08 follow-on."),

    # ---- egress: public intelligence APIs, NOT the target ----
    TransportSite("github_advisories.py", CHANNEL_HTTP, SCOPE_EGRESS, ROUTING_DIRECT,
                  owner="recon", note="GitHub advisory API; public egress, out of target-executor scope."),
    TransportSite("kev_check.py", CHANNEL_HTTP, SCOPE_EGRESS, ROUTING_DIRECT,
                  owner="recon", note="CISA KEV feed; public egress."),
    TransportSite("package_registry_checks.py", CHANNEL_HTTP, SCOPE_EGRESS, ROUTING_DIRECT,
                  owner="recon", note="npm/PyPI registry lookups; public egress."),

    # ---- llm: model transport, NOT the target ----
    TransportSite("ollama_client.py", CHANNEL_HTTP, SCOPE_LLM, ROUTING_DIRECT,
                  owner="agents", note="Ollama chat/tags transport; model plane, not target."),

    # ---- target: discovery / crawl (routing gaps -- not yet on the executor) ----
    TransportSite("api_surface_discovery.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T03/T08)",
                  gap="surface discovery sends directly; route through the executor so "
                      "discovery hops are scope-checked and captured as artifacts."),
    TransportSite("crawler.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T03/T08)",
                  gap="crawl sends directly (follow_redirects=True) -- redirect hops are "
                      "not scope-gated by the executor."),
    TransportSite("role_crawl.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (F01/T03)",
                  gap="role crawl remains on old transport (review F01); it should source "
                      "identities from the run and send per-session through the executor."),
    TransportSite("scope_discovery.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T03/T08)",
                  gap="scope-probe sends directly; migrate to the executor's scope check."),
    TransportSite("feature_workflow.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T07)",
                  gap="stateful workflow crawl fetches directly; the T07 workflow engine "
                      "routes steps through the executor with per-session state."),
    TransportSite("missing_auth_probe.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T03/T08)",
                  gap="unauthenticated-access probe sends directly."),
    TransportSite("iterative_agent.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="agents (T09)",
                  gap="agent tool-fetch sends directly; route through the executor so "
                      "agent-driven hops obey scope/budget/cancellation."),
    TransportSite("orchestrator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (T03/T08)",
                  gap="second-order/discovery-confirm/coverage-seed sends open ad-hoc "
                      "clients; route through the executor and carry the run's evidence sink."),

    # ---- target: confirmation legs (validators) ----
    # Mutating legs pass through the SafetyGate/GatedAsyncClient; read-only legs open
    # their own client. Full migration to the run-scoped executor (per-session
    # isolation, cancellation, artifact capture) is F01/F04/T08 follow-on.
    TransportSite("validators/cross_identity_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="astra-identity (F04/T03)",
                  gap="partially migrated (T03): even with a context it sends session_ref=None "
                      "so identities share one cookie jar and read process-global headers (F04). "
                      "Bind every identity/anon call to isolated session state from the run."),
    TransportSite("validators/jwt_forge_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="read-only forge+replay; opens its own client."),
    TransportSite("validators/rate_limit_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="authorize-burst replay; provisional oracle."),
    TransportSite("validators/toctou_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="concurrent authority-write race; provisional oracle."),
    TransportSite("validators/race_condition_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="concurrent-request differential."),
    TransportSite("validators/sqlmap.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation",
                  note="container leg via tool_runner; a direct httpx boolean-probe fallback "
                       "when Docker is unavailable."),
    TransportSite("validators/api_security_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_GATED,
                  owner="confirmation", note="mass-assignment/BOLA checks; mutating sends via the gate."),
    TransportSite("validators/cors_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="read-only CORS preflight/probe."),
    TransportSite("validators/csp_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="read-only header fetch."),
    TransportSite("validators/oauth_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="OAuth/OIDC endpoint probes."),
    TransportSite("validators/header_injection_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="CRLF/header-injection probe."),
    TransportSite("validators/http_request_smuggling_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation",
                  note="CL/TE desync; needs a raw-protocol adapter (T08) -- ordinary HTTP "
                       "anomalies do not qualify it."),
    TransportSite("validators/recon_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="read-only recon fetches (.git/.env/docs)."),
    TransportSite("validators/subdomain_takeover_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="dangling-record fingerprint fetch."),
    TransportSite("validators/web_cache_poisoning_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation", note="unkeyed-input cache probe."),

    # ---- target: raw socket ----
    TransportSite("validators/websocket_validator.py", CHANNEL_SOCKET, SCOPE_TARGET, ROUTING_DIRECT,
                  owner="confirmation",
                  note="hand-rolled WebSocket upgrade over socket+ssl (no ws library); "
                       "CSWSH origin check. Its own raw-socket adapter, not httpx."),
)


def harness_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _iter_production_py(root: str):
    """Yield (relpath, text) for every production .py under the harness dir and
    validators/, excluding tests, __pycache__, and this module."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            if fn == "transport_inventory.py":
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8") as f:
                    yield rel, f.read()
            except (OSError, UnicodeDecodeError):
                continue


def scan_http_client_modules(root: str | None = None) -> set[str]:
    """Production modules (relpaths) that construct an httpx client -- the live
    HTTP transport surface, discovered from source, not the registry."""
    root = root or harness_dir()
    found = set()
    for rel, text in _iter_production_py(root):
        if "httpx.AsyncClient(" in text or "httpx.Client(" in text:
            found.add(rel)
    return found


def http_modules_in_registry() -> set[str]:
    return {s.module for s in TRANSPORT_SITES if s.channel == CHANNEL_HTTP}


def routing_gaps() -> tuple[TransportSite, ...]:
    """Target-directed sends not yet on the run-scoped executor (the audit list)."""
    return tuple(s for s in TRANSPORT_SITES if s.is_routing_gap)


def summary() -> dict:
    by_scope: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    for s in TRANSPORT_SITES:
        by_scope[s.scope] = by_scope.get(s.scope, 0) + 1
        by_channel[s.channel] = by_channel.get(s.channel, 0) + 1
    return {
        "total_sites": len(TRANSPORT_SITES),
        "routing_gaps": len(routing_gaps()),
        "by_scope": by_scope,
        "by_channel": by_channel,
    }
