"""transport_inventory.py -- the auditable inventory of every outbound-transport
call-site in the harness (Astra T08, inventory + routing-gap audit).

The run-scoped `run_context.TargetTransport` (the class formerly named `Executor`,
fronted by `safety_gate.GatedAsyncClient`) is THE ONE policy-aware transport for
target-directed traffic: scope enforced before every hop, per-session cookie jars,
credential-forwarding rules, mutation ceilings, cancellation, and captured outcome
artifacts. As of W-16 every target-directed send is on it -- `routing_gaps()` is
empty (the migration ran T03 -> T08 -> W-16). The danger this module still guards
against is that a NEW direct send is added and silently bypasses the
gate/transport -- exactly the "green tests, dead pipeline" failure mode this
project guards against, one channel down.

This module makes the transport surface *auditable*, with two guards:

  - `TRANSPORT_SITES` is a curated registry: every production module that opens an
    outbound channel (HTTP, container, browser, raw socket), with its scope
    (target | egress | llm | infra), its current routing, an owner, and -- for a
    target-directed send not yet on the executor -- the specific remaining gap.
  - ARC-7: `raw_client_site_counts()` walks every production module's AST and finds
    each raw `httpx` client construction by (module, qualified function), counting
    them; `import httpx as h`, `from httpx import AsyncClient` and httpx's module-level
    helpers (`httpx.get(...)`) are seen too. `RAW_CLIENT_ALLOWLIST` names every
    allowed site with a category and a reason; the paired test requires the scan and
    the allowlist to agree exactly, so a new raw client -- in a new module, a new
    function, or a second construction inside an allowed function -- fails CI until it
    is routed through `run_context` or listed here with a reason.

Limits of the guard (do not overstate it). It finds httpx constructions only: not
`requests`/`aiohttp`/raw sockets (those channels are listed in `TRANSPORT_SITES`), not a
client built through `getattr`, and not a client handed in from another module. An
allowlisted `legacy_no_run` site is a raw client that a validator falls back to when it
has no run context; it is listed, not fixed (see the ARC-7 HANDOFF).

The inventory began as an audit and is updated as each production route migrates.
"""
from __future__ import annotations

import ast
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
ROUTING_EXECUTOR = "executor"   # production path uses the invocation RunContext executor
ROUTING_CAPABILITY_ADAPTER = "capability_adapter"  # non-HTTP adapter applies equivalent run policy
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
    # Whether this module constructs its OWN httpx client (matched by
    # scan_http_client_modules). Fully routed HTTP consumers that only send
    # through GatedAsyncClient / the run executor -- e.g. cors_validator after
    # W-1 removed its raw fallback -- set this False: they are real HTTP
    # transport sites worth auditing, but they delegate client construction to
    # the routed adapter, so the scan-vs-registry check must not expect to find
    # an httpx.AsyncClient(...) in their source.
    constructs_client: bool = True

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
                  note="docker/subprocess adapter (sqlmap/ffuf). I05-C: every tool runs as "
                       "an owned process tree (Windows Job Object / POSIX process group) with "
                       "bounded output; cancel or timeout stops the tree and force-removes "
                       "the exact container before returning. Executor container adapter "
                       "is T08 follow-on."),
    TransportSite("tool_proxy.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="tools", constructs_client=False,
                  note="I05: loopback reverse proxy an external tool (sqlmap) is pointed at "
                       "inside a run; each tool request is replayed through the run's "
                       "TargetTransport (budget, scope, gate, cancellation, TLS), and an "
                       "exhausted budget stops the tool."),
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
    TransportSite("openai_provider.py", CHANNEL_HTTP, SCOPE_LLM, ROUTING_DIRECT,
                  owner="llm_provider (P1.1)",
                  note="OpenAI-compatible chat-completions transport for the optional remote "
                       "coordinator/critique provider; model plane, not target. Constructed only "
                       "on explicit config opt-in + $OPENAI_API_KEY (see llm_provider.py)."),
    TransportSite("anthropic_provider.py", CHANNEL_HTTP, SCOPE_LLM, ROUTING_DIRECT,
                  owner="llm_provider (P1.1)",
                  note="Anthropic Messages-API transport for the optional remote coordinator/"
                       "critique provider; model plane, not target. Constructed only on explicit "
                       "config opt-in + $ANTHROPIC_API_KEY (see llm_provider.py)."),

    # ---- target: discovery / crawl (routing gaps -- not yet on the executor) ----
    TransportSite("api_surface_discovery.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08)",
                  constructs_client=False,
                  note="production role discovery uses the run executor; legacy standalone "
                       "callers retain a direct compatibility path. ARC-9: the facade keeps "
                       "SurfaceDiscovery and its run_context; the sends are in api_surface_probe.py."),
    TransportSite("api_surface_probe.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08)",
                  constructs_client=False,
                  note="ARC-9 sibling of api_surface_discovery.py (_ProbeMixin): every probe goes "
                       "through run_context.executor().execute, or through transport_for for a "
                       "standalone caller (scope, budget and the connect-time pin apply)."),
    TransportSite("crawler.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08)",
                  constructs_client=False,
                  note="production role crawl routes page/script fetches through the run "
                       "executor, including manual scope-checked redirects."),
    TransportSite("role_crawl.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (F01/T03)",
                  constructs_client=False,
                  note="production access-matrix probes bind each principal to an isolated "
                       "run session; direct transport remains compatibility-only."),
    TransportSite("scope_discovery.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08)",
                  constructs_client=False,
                  note="production scope-change probes preserve the triggering run session and "
                       "use executor scope, budget, cancellation, and evidence policy."),
    TransportSite("feature_workflow.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T07)",
                  constructs_client=False,
                  note="production stateful feature crawl and declared T07 workflows route "
                       "through the executor with per-session state; direct fetch is legacy."),
    TransportSite("missing_auth_probe.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08)",
                  constructs_client=False,
                  note="API probes run in a bounded invocation context; anonymous and garbage-token "
                       "controls use distinct executor session state."),
    TransportSite("iterative_agent.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="agents (T09/W-16)", constructs_client=False,
                  note="W-16: the agent's send->observe loop (_execute) now routes every "
                       "hop through the single TargetTransport (run_context.transport_for), "
                       "so scope, the safety gate, budget, and evidence apply in one place. "
                       "It no longer constructs its own httpx client."),
    TransportSite("orchestrator_chain.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08/W-16)", constructs_client=False,
                  note="W-16: the ChainMixin's target sends -- the engagement-driver GET and the "
                       "credential probe -- route through the single TargetTransport "
                       "(this run's when present, else a standalone one). No direct httpx client "
                       "remains, closing the last graph-loop routing gap."),
    TransportSite("orchestrator_chain_legs.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08/W-16)", constructs_client=False,
                  note="ARC-9: the investigate_engagement stage that holds the confirmation legs; its "
                       "access-control baseline read (moved here from orchestrator_chain.py) routes "
                       "through the single TargetTransport exactly as before. No direct httpx client."),
    TransportSite("orchestrator_chain_worklist.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (T03/T08/W-16)", constructs_client=False,
                  note="ARC-9: the investigate_engagement stages that hold the second-order plant and "
                       "read (moved here from orchestrator_chain.py); both travel the run's one "
                       "TargetTransport via second_order.send_through_run. No direct httpx client."),

    # ---- target: confirmation legs (validators) ----
    # Mutating legs pass through the SafetyGate/GatedAsyncClient; read-only legs open
    # their own client. Full migration to the run-scoped executor (per-session
    # isolation, cancellation, artifact capture) is F01/F04/T08 follow-on.
    TransportSite("validators/cross_identity_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="astra-identity (F04/T03)",
                  constructs_client=False,
                  note="production graph validation binds every identity and anonymous replay "
                       "to isolated RunContext sessions; legacy registry use remains compatible."),
    TransportSite("validators/jwt_forge_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="graph forge/control replays use isolated ephemeral "
                       "sessions through the invocation executor; legacy registry path remains."),
    TransportSite("validators/rate_limit_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="session-bound replay burst uses invocation gate, "
                       "budget and executor; oracle remains observation-only/provisional."),
    TransportSite("validators/toctou_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="graph authority reads and concurrent write burst use "
                       "the invocation gate, session binding, budget and executor; provisional oracle."),
    TransportSite("validators/race_condition_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="registry validation binds a per-dispatch run context; "
                       "concurrent burst uses its gate, session, budget and executor."),
    TransportSite("validators/sqlmap.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation",
                  note="container leg remains isolated behind tool_runner; its direct HTTP "
                       "boolean-probe fallback uses the invocation executor."),
    TransportSite("validators/api_security_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_GATED,
                  owner="confirmation", constructs_client=False,
                  note="mass-assignment and unbounded-limit probes both send through "
                       "GatedAsyncClient, so inside an entered run they spend that run. I05 "
                       "removed the limit probe's raw httpx client."),
    TransportSite("validators/cors_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", constructs_client=False,
                  note="registry CORS probes use per-dispatch invocation scope, budget, "
                       "cancellation and executor routing. W-1 removed the raw httpx fallback: "
                       "the no-run_context path now sends through GatedAsyncClient, so this "
                       "module no longer constructs its own client."),
    TransportSite("validators/csp_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="fresh CSP/framing header fetch uses per-dispatch "
                       "invocation scope, budget, cancellation and redirect policy."),
    TransportSite("validators/oauth_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="redirect_uri exact-match probe uses per-dispatch "
                       "invocation scope, budget, cancellation and executor routing."),
    TransportSite("validators/header_injection_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="bounded CRLF query probes use per-dispatch invocation "
                       "scope, budget, cancellation and executor routing."),
    TransportSite("validators/http_request_smuggling_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation",
                  note="ordinary-HTTP anomaly sampler uses invocation policy/executor; raw CL/TE "
                       "framing is still unsupported and therefore never qualifies confirmation."),
    TransportSite("validators/recon_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="crawl/common-file/fingerprint fetches use per-dispatch "
                       "invocation scope, budget, cancellation and executor routing."),
    TransportSite("validators/subdomain_takeover_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="provider fingerprint fetch uses per-dispatch invocation "
                       "scope, budget, cancellation and executor routing."),
    TransportSite("validators/web_cache_poisoning_validator.py", CHANNEL_HTTP, SCOPE_TARGET, ROUTING_EXECUTOR,
                  owner="confirmation", note="cacheability/unkeyed/deception probes use per-dispatch "
                       "invocation scope, budget, cancellation and executor routing."),

    # ---- target: raw socket ----
    TransportSite("validators/websocket_validator.py", CHANNEL_SOCKET, SCOPE_TARGET, ROUTING_CAPABILITY_ADAPTER,
                  owner="confirmation",
                  note="raw WebSocket Upgrade adapter applies invocation scope, cancellation, "
                       "gate, budget, and registered-session cookie policy before connect."),
)


# --------------------------------------------------------------------------- #
# ARC-7: every raw httpx client construction that is allowed to exist, by function.
# --------------------------------------------------------------------------- #

RAW_EGRESS = "egress"          # public intelligence API, never the target
RAW_LLM = "llm"                # the model plane, never the target
RAW_INFRA = "infra"            # the run-scoped transport's own client
RAW_GATE = "gate"              # the safety gate's no-run client: every send authorised first
RAW_LEGACY_NO_RUN = "legacy_no_run"   # target-capable, used only when there is no run context
RAW_CATEGORIES = frozenset({RAW_EGRESS, RAW_LLM, RAW_INFRA, RAW_GATE, RAW_LEGACY_NO_RUN})


@dataclass(frozen=True)
class RawClientSite:
    module: str          # path relative to the harness dir
    function: str        # qualified name, e.g. "Class.method" or "<module>"
    category: str
    reason: str
    count: int = 1       # how many constructions the function holds

    @property
    def key(self) -> tuple[str, str]:
        return (self.module, self.function)


def _site(module, function, category, reason, count=1):
    return RawClientSite(module, function, category, reason, count)


_NO_RUN = ("the run-context branch sends through the executor; this else-branch is the "
           "no-run fallback and is a raw client. Left open (ARC-7): converting it means "
           "requiring run_context on a registry validator and rewriting the tests that "
           "patch httpx.AsyncClient.")

RAW_CLIENT_ALLOWLIST: tuple[RawClientSite, ...] = (
    # ---- egress: public APIs, not the target ----
    _site("github_advisories.py", "GitHubAdvisoryClient._lookup_network", RAW_EGRESS,
          "GitHub advisory API lookup; public egress."),
    _site("kev_check.py", "KevClient._ensure_loaded", RAW_EGRESS,
          "CISA KEV feed download; public egress."),
    _site("package_registry_checks.py", "PackageRegistryClient._check_npm", RAW_EGRESS,
          "npm registry lookup; public egress."),
    _site("package_registry_checks.py", "PackageRegistryClient._check_pypi", RAW_EGRESS,
          "PyPI registry lookup; public egress."),
    _site("package_registry_checks.py", "PackageRegistryClient._load_malware_feeds", RAW_EGRESS,
          "public malware-feed download; public egress."),
    # ---- llm: the model plane ----
    _site("ollama_client.py", "OllamaClient._probe_context_windows", RAW_LLM,
          "model-server context-window probe (the configured Ollama / llama-server host)."),
    _site("ollama_client.py", "OllamaClient._probe_openai_window", RAW_LLM,
          "model-server context-window probe, OpenAI-compatible wire."),
    _site("ollama_client.py", "OllamaClient._probe_show_window", RAW_LLM,
          "model-server /api/show probe."),
    _site("ollama_client.py", "OllamaClient._send_once", RAW_LLM,
          "model chat request to the configured model server."),
    _site("ollama_client.py", "OllamaClient.health_check", RAW_LLM,
          "model-server health check."),
    _site("ollama_client.py", "OllamaClient.list_models", RAW_LLM,
          "model-server tags listing."),
    _site("openai_provider.py", "OpenAiProvider.chat_json", RAW_LLM,
          "optional remote OpenAI-compatible coordinator/critique provider (opt-in)."),
    _site("anthropic_provider.py", "AnthropicProvider.chat_json", RAW_LLM,
          "optional remote Anthropic Messages provider (opt-in)."),
    # ---- infra ----
    _site("run_context.py", "_target_client", RAW_INFRA,
          "the TargetTransport's own client: pinned connect, trust_env=False (ARC-14)."),
    _site("safety_gate.py", "GatedAsyncClient.__init__", RAW_GATE,
          "backs the no-run path of ~40 validator send sites: SafetyGate.authorize() "
          "(scope, tier; an empty scope fails closed under active mode) runs before every "
          "send, and a bound or ambient run reroutes through the TargetTransport. It has "
          "no budget or connect pin outside a run. Left open (ARC-7)."),
    # ---- target-capable validators with a no-run fallback (left open) ----
    _site("validators/csp_validator.py", "CspValidator._fetch_fresh_headers",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/header_injection_validator.py", "HeaderInjectionValidator._probe_param",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/http_request_smuggling_validator.py",
          "HttpRequestSmugglingValidator.__aenter__", RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/http_request_smuggling_validator.py",
          "HttpRequestSmugglingValidator._perform_hrs_tests", RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/http_request_smuggling_validator.py",
          "HttpRequestSmugglingValidator._send_raw_request", RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/jwt_forge_validator.py", "JwtForgeValidator._probe",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/oauth_validator.py", "OAuthValidator._check_redirect_uri_validation",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/race_condition_validator.py", "RaceConditionValidator.validate",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/rate_limit_validator.py", "RateLimitValidator.validate",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/recon_validator.py", "ReconValidator.__aenter__",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/recon_validator.py", "ReconValidator._send_request",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/sqlmap.py", "SqlmapValidator._boolean_probe_fallback.routed",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/subdomain_takeover_validator.py",
          "SubdomainTakeoverValidator._check_fingerprint", RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/toctou_validator.py", "ToctouValidator._get_json",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/toctou_validator.py", "ToctouValidator.validate.fire_one",
          RAW_LEGACY_NO_RUN, _NO_RUN),
    _site("validators/web_cache_poisoning_validator.py", "WebCachePoisoningValidator._send",
          RAW_LEGACY_NO_RUN, _NO_RUN),
)

# Modules whose raw clients ARC-7 removed. The guard test asserts none comes back.
ARC7_CONVERTED_MODULES: tuple[str, ...] = (
    "feature_workflow.py", "engagement_builder.py", "missing_auth_probe.py",
    "api_surface_discovery.py", "role_crawl.py", "crawler.py", "scope_discovery.py",
    "validators/cross_identity_validator.py",
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


# --------------------------------------------------------------------------- #
# ARC-7: the function-level scan. A call site is (module, qualified function), found by
# walking the AST, so a SECOND raw client added inside an already-registered module is a
# new site, and `import httpx as h` / `from httpx import AsyncClient` are seen too.
# --------------------------------------------------------------------------- #

_CLIENT_CTORS = frozenset({"AsyncClient", "Client"})
# httpx's module-level helpers each build a throwaway client of their own.
_HELPER_FUNCS = frozenset({"get", "post", "put", "patch", "delete", "head", "options",
                           "request", "stream"})


def _raw_call_sites(tree: "ast.AST") -> list[tuple[str, int]]:
    """(qualified function, line) of every raw httpx client construction in `tree`.
    "<module>" names a module-level call; "Class.method" a method."""
    modules: set[str] = set()      # local names bound to the httpx module
    ctors: set[str] = set()        # local names bound to httpx.AsyncClient / Client / helpers
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "httpx":
                    modules.add(a.asname or "httpx")
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            for a in node.names:
                if a.name in _CLIENT_CTORS or a.name in _HELPER_FUNCS:
                    ctors.add(a.asname or a.name)
    found: list[tuple[str, int]] = []

    def visit(node, stack):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack = stack + [node.name]
        if isinstance(node, ast.Call):
            f = node.func
            hit = ((isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                    and f.value.id in modules
                    and (f.attr in _CLIENT_CTORS or f.attr in _HELPER_FUNCS))
                   or (isinstance(f, ast.Name) and f.id in ctors))
            if hit:
                found.append((".".join(stack) or "<module>", node.lineno))
        for child in ast.iter_child_nodes(node):
            visit(child, stack)

    visit(tree, [])
    return found


def raw_client_sites_in_source(text: str) -> list[tuple[str, int]]:
    """The raw-client call sites of one source text (the unit the negative controls
    inject into)."""
    return _raw_call_sites(ast.parse(text))


def raw_client_site_counts(root: str | None = None) -> dict[tuple[str, str], int]:
    """(module, qualified function) -> number of raw httpx client constructions, over
    the production tree, discovered from source."""
    root = root or harness_dir()
    found: dict[tuple[str, str], int] = {}
    for rel, text in _iter_production_py(root):
        try:
            sites = raw_client_sites_in_source(text)
        except SyntaxError:
            continue
        for qualname, _line in sites:
            found[(rel, qualname)] = found.get((rel, qualname), 0) + 1
    return found


def scan_raw_client_sites(root: str | None = None) -> set[tuple[str, str]]:
    """Every (module, qualified function) in the production tree that constructs a raw
    httpx client."""
    return set(raw_client_site_counts(root))


def raw_client_drift(counts: dict[tuple[str, str], int] | None = None
                     ) -> tuple[list, list, list]:
    """Compare the scan with RAW_CLIENT_ALLOWLIST: (unlisted sites, stale allowlist
    entries, sites whose construction count differs from the allowlist)."""
    counts = raw_client_site_counts() if counts is None else counts
    allowed = {site.key: site.count for site in RAW_CLIENT_ALLOWLIST}
    unlisted = sorted(k for k in counts if k not in allowed)
    stale = sorted(k for k in allowed if k not in counts)
    miscounted = sorted((k, counts[k], allowed[k]) for k in counts
                        if k in allowed and counts[k] != allowed[k])
    return unlisted, stale, miscounted


def scan_http_client_modules(root: str | None = None) -> set[str]:
    """Production modules (relpaths) that construct an httpx client -- the live
    HTTP transport surface, discovered from source, not the registry."""
    return {module for module, _ in scan_raw_client_sites(root)}


def http_modules_in_registry() -> set[str]:
    # Only modules that construct their OWN httpx client are expected to be
    # found by scan_http_client_modules(); fully routed consumers
    # (constructs_client=False) send through the gate/executor adapter and
    # deliberately have no client of their own to scan.
    return {s.module for s in TRANSPORT_SITES
            if s.channel == CHANNEL_HTTP and s.constructs_client}


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
