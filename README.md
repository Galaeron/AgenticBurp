# AgenticVibe

A Burp Suite copilot that uses locally-hosted LLMs to analyze captured HTTP traffic for security vulnerabilities, then confirms or refutes those findings with deterministic validators.

> **Status: working research prototype, effectiveness unproven.** The software
> runs and ~2,400 Python / ~230 Java tests pass, but nothing in the repo
> measures how well it finds real bugs on an unfamiliar app, and its tuning
> corpora ship with answer keys. Read **[docs/LIMITATIONS.md](docs/LIMITATIONS.md)**
> before trusting any result, and **[docs/USER_MANUAL.md](docs/USER_MANUAL.md)**
> to run it safely.
>
> **Out of the box it is passive and deliberately quiet:** active testing,
> autonomous discovery and the cloud seams are OFF and no scope is set, so it
> only reviews the exact traffic you send it with a small local model. If it
> "finds almost nothing," that is why — check `GET /health` first (it reports
> whether Ollama is reachable and the model is pulled), then enable active
> testing on a scoped host per the user manual.

## How It Works

```
+-------------------+  POST /analyze  +-------------------+  /api/chat  +-------------+
|  Burp Extension   | --------------> |  Harness Server   | ----------> |   Ollama    |
|  (Java, Montoya)  |                 |  (FastAPI :8787)  |             |  (local)    |
|                   |                 |                   |             +-------------+
|  2 suite tabs:    |                 |  Orchestrator     |
|  - LLM Harness    |                 |    |              |
|  - Harness Tools  |                 |    +-> Agents (36)|
|  + context menu   |                 |    +-> Validators |
+-------------------+                 |    +-> Ledger     |
                                      +-------------------+
```

### The `/analyze` pipeline (`orchestrator_detect.py: analyze()`)

This is the core path. When the Burp extension sends an HTTP exchange to `POST /analyze`, the orchestrator runs this sequence:

1. **Cache check** -- skip if this exchange was already analyzed (`cache.py`).
2. **Scope check** -- reject if the host is outside `server.allowed_hosts` (when configured).
3. **Budget check** -- reject if the effort budget is exhausted.
4. **Agent selection** -- `fast_path.py` tries deterministic pattern matching first (URL regexes, header patterns, response signatures, body anomalies). If no strong signal, falls back to the **coordinator LLM** which picks agents from the available set. On coordinator failure, fails open to all agents (or a curated core subset, depending on `coordinator.fail_open_mode`).
5. **Agent dispatch** -- `AgentManager.run_multiple_agents()` runs selected agents in parallel, bounded by an asyncio semaphore (`concurrency.max_parallel_agents`). Each agent sends a vulnerability-class-specific prompt + the exchange to Ollama and returns structured findings. Optionally, agents can be grouped into 6 families for fewer model calls (`coordinator.routing_mode: "families"`, ships OFF).
6. **Access control gate** -- caps IDOR/authz findings that are refuted by 401/403/405 status codes.
7. **Header noise gate** -- caps CORS/CSP/clickjacking findings to "low" severity.
8. **Critique** -- adversarial LLM review of surviving findings. Each is verdicted "survived", "downgraded", or "rejected". Rejected findings are removed.
9. **Adaptive re-spin** -- if nothing actionable survived and cloud reasoning is enabled, asks the coordinator for follow-up agents and dispatches another round (up to `max_rounds`).
10. **Credential detection** -- flags credential endpoints in the exchange.
11. **Shape precondition** -- deterministic findings from endpoint shape (e.g. missing security headers).
12. **Validation** -- `ValidatorRegistry.for_finding()` matches findings to validators. Each validator sends targeted probes and returns machine-verifiable results. Active validators only run when `validators.active_enabled` is set.
13. **Confirmation gate** -- classifies each unconfirmed finding:
    - **CONFIRMED** -- a validator proved it. Ships at true severity.
    - **REFUTED** -- a live-verified validator ran, produced a controlled negative. Demoted to "low", confidence <= 0.35.
    - **UNVERIFIED** -- a live-verified validator ran but produced no controlled negative. Demoted to "low".
    - **UNPROVEN** -- the validator is only smoke-tested (not proven against live targets). Capped at "medium", confidence <= 0.5.
14. **Known-vulnerability resolution** -- extracts software components from agent reports, verifies against exchange text, looks up GitHub Advisories + CISA KEV.
15. **Supplemental scans** -- confidential info (regex-based secrets/PII), verbose error detection, secret disclosure.
16. **Chain detection** -- links findings into attack chain hypotheses (`chaining.py`, `chain_linker.py`).
17. **Auto-escalation** -- if engagement policy allows, escalates to deeper investigation.
18. **Persist + respond** -- findings stored in SQLite (`store.py`), response returned.

### Evidence ledger

Every step emits events to an append-only ledger (`evidence_ledger.py`). Events carry a `Provenance` envelope (code version, config fingerprint, model tag). The ledger is wired into agents (HYPOTHESIS events), validators (EXECUTION events), the confirmation gate (FINDING_REVISION events), and the orchestrator (RUN_SUMMARY). Persisted to SQLite and exposed via `GET /findings/{finding_ref}/evidence`.

## Components

### Harness Server (`harness/server.py`)

FastAPI on `127.0.0.1:8787`. At startup: loads and validates config, constructs a single `Orchestrator`, generates an ephemeral bearer token (or uses configured one), installs trusted-host and CSRF middleware. ~50 endpoints including:

| Endpoint | Purpose |
|---|---|
| `POST /analyze` | Core analysis pipeline (above) |
| `POST /engagement/{host}/run` | Graph-driven engagement: plan worklist, optionally execute |
| `POST /engagement/{host}/investigate` | Background graph investigation job |
| `POST /crawl` | Page fetch + JS bundle mining for endpoint discovery |
| `POST /crawl-roles` | Multi-role crawl with identity sessions + access matrix + IDOR detection |
| `POST /probe-missing-auth` | Strip auth headers and probe for unauthenticated access |
| `POST /active-probe` | Iterative agent with pivot memory |
| `POST /retry-agents` | Per-vulnerability retry loop with budget governor |
| `GET /report` | Markdown report for a host's findings |
| `GET /settings` / `POST /settings` | Runtime toggles: active validation, cross-identity, throttle, cloud reasoning |
| `POST /scan/confidential` | Deterministic regex secrets/PII scan (no model) |
| `GET /findings/{ref}/evidence` | Evidence ledger reconstruction + reproduction recipe |
| `POST /validation-results` | Accept Burp-side validation submissions |

### Orchestrator (`harness/orchestrator.py`)

Assembled from four mixins. `__init__` constructs: `OllamaClient`, coordinator + critique LLM providers (local Ollama or optional remote), `Coordinator`, `AgentManager`, `AnalysisPipeline`, `FastPathSelector`, `ValidatorRegistry`, `EffortBudget`, GitHub Advisory + KEV + package registry clients, engagement policy, global throttle.

| Mixin | Module | Key methods |
|---|---|---|
| `DetectMixin` | `orchestrator_detect.py` | `analyze()`, `_choose_agents()`, `_maybe_adaptive_respin()`, `_resolve_known_vulnerabilities()` |
| `ConfirmMixin` | `orchestrator_confirm.py` | `_validate_findings()`, `run_active_probe()`, `run_retry_agents()`, `_coverage_proof()` |
| `ChainMixin` | `orchestrator_chain.py` | `plan_engagement()`, `run_engagement()`, `investigate_engagement()` |
| `ReportMixin` | `orchestrator_report.py` | `plan_allocation()`, `estimate_for_urls()`, `list_models()`, `set_coordinator_model()` |

### Agents (`harness/agents/`)

36 specialist agents, each a `BaseAgent` subclass with a `name` attribute, discovered at runtime by `AgentPluginSystem` (file scan of the `agents/` directory). `BaseAgent` handles: prompt construction with exchange body truncation (preserves high-signal content like stack traces beyond the truncation point via regex), quarantine fencing (random-nonce boundaries to contain prompt injection from target responses), and structured finding extraction.

The default routing mode dispatches each agent as an individual model call. An opt-in family routing mode (`coordinator.routing_mode: "families"`) groups all 36 into 6 families and issues one composed call per family:

| Family | Members |
|---|---|
| injection | sqli, nosql, command_injection, ssti, xss, xxe |
| access_control | idor, auth, csrf, oauth, jwt, race_condition |
| server_side | ssrf, deserialization, http_request_smuggling, web_cache_poisoning, open_redirect, websocket |
| config_headers | cors, csp, header_injection, misconfig, info_disclosure, crypto |
| api_logic | api_security, graphql, business_logic, business_logic_enhanced, rate_limit, ai_security |
| recon_supply | recon, subdomain_takeover, supply_chain, anomaly, ai_llm, file_upload |

Family routing ships OFF. Any agent not in a family falls back to a solo call.

### Validators (`harness/validators/registry.py`)

35 validators registered in `ValidatorRegistry.__init__()`, each togglable. Matched to findings via `for_finding()` based on vulnerability class. Categories:

**Passive (no network):** `deserialization` (format fingerprinting), `verbose_error` (stack trace/debug detection).

**Active (gated by `validators.active_enabled`):**
- **In-band probes:** ssti, path_traversal, open_redirect, verb_tamper, cors, csp, crypto, header_injection, csrf, oauth, http_request_smuggling, web_cache_poisoning, api_security, websocket, recon, subdomain_takeover
- **Out-of-band (collaborator callbacks):** ssrf, xxe, command_injection, deserialization_oob -- use an in-process HTTP callback server (`collaborator.py`) on an ephemeral loopback port
- **Replay/forge:** jwt_forge, sqlmap (Docker), race_condition (concurrent burst), rate_limit, toctou
- **Multi-request:** sequence, auth_sequence, stored_xss, file_upload, reset_token
- **Browser-driven:** browser_xss (headless execution), dom_xss (fragment-only taint)
- **Cross-identity:** cross_identity (Autorize-style, default OFF, opt-in)

Mutating validators are gated by `safety_gate.py` -- hard ceilings on burst size and allowed methods that config cannot raise.

### Safety

| Module | Enforcement |
|---|---|
| `safety_gate.py` | Checkpoint for mutating/amplifying requests. Hard ceilings baked into code; config can only restrict further. Every gated decision is logged. |
| `run_context.py` | Per-run isolation: own safety gate, scope, budget, cancellation. `TargetTransport` wraps httpx with manual redirect loop -- scope enforced before every hop, credentials not forwarded across origins. |
| `scope_lock.py` | Single `host_in_scope()` function shared by all validators and the gate. Fail-open when unconfigured; fail-closed once `allowed_hosts` is set. Hostname check only (no DNS pinning). |

### Burp Suite Extension (`burp-extension/`)

Java plugin using Burp's Montoya API. Connects to `http://localhost:8787`. Registers:

- **"LLM Harness" tab** -- `UnifiedHarnessView` combining `AttackSurfacePanel` (site map import, prioritization) and `HarnessPanel` (connection test, analysis results, findings display).
- **"Harness Tools" tab** -- `HarnessToolsPanel` with model selection, discovery controls, active testing toggles, budget/effort display, tool catalog, confidential scan, activity feed.
- **Context menu** -- `HarnessContextMenu` for right-click "Send to LLM Harness" from Proxy/Repeater/Target.
- **`ValidationExecutor`** -- executes test plans returned by the server using Burp's HTTP stack.
- **`logic/` package** -- 32 client-side modules: most are per-vulnerability-class deterministic checks (SQLi, XSS, SSRF, XXE, JWT forgery, CSRF, mass assignment, etc.), plus shared identity/URL/pool-comparison helpers (`IdentityCompareLogic`, `UrlIdentifierDiff`, `PoolCandidateResolver`, `WorkflowReplayLogic`) they build on.

### Configuration

Two files: `harness/config.yaml` (safe defaults, checked in) + `harness/config.local.yaml` (operator overrides, git-ignored). `load_config()` deep-merges local over base and tracks which keys were explicitly set.

**Operating profiles** (`config_schema.py`) bundle behavioral toggles:

| Profile | Key settings |
|---|---|
| `none` (default) | All knobs keep their config.yaml values |
| `passive-only` | All active/mutating/discovery/oracle OFF (safety-authoritative -- overrides even explicit settings) |
| `laptop` | Curated routing, serial dispatch, passive only, qwen3:8b |
| `workstation` | Parallel dispatch (3), active validation on, mutating replay off |
| `deep-assessment` | Active + mutating + autonomous discovery + oracle, all on |
| `ci-eval` | Curated routing, serial, deterministic, quarantine unverified leads |

An operator's explicit `config.local.yaml` value wins over a profile preset (except `passive-only`'s safety-authoritative overrides).

## Prerequisites

- **Python 3.12+** with dependencies (FastAPI, httpx, PyYAML, pydantic)
- **Ollama** running locally with a pulled model (e.g. `ollama pull qwen3:8b`)
- **Docker** (optional) -- sqlmap validator runs in a container
- **JDK + Gradle** (optional) -- to build the Burp extension JAR
- **Burp Suite** (Community or Pro) -- for the extension UI

## Quick Start

```bash
# 1. Start Ollama
ollama serve

# 2. Start the harness server (127.0.0.1:8787)
python -m harness.server

# 3. (Optional) Build and load the Burp extension
cd burp-extension
gradle shadowJar
# Load the JAR in Burp Suite > Extensions
```

## Testing

```bash
python -m harness.suite smoke   # fast subset
python -m harness.suite full    # unittest + pytest + evaluation integrity
```

## Project Structure

```
AgenticVibe/
+-- harness/                 # Python backend (FastAPI)
|   +-- agents/              # 36 specialist agents (plugin-discovered)
|   +-- validators/          # 35 deterministic validators
|   +-- server.py            # API entry point (:8787)
|   +-- orchestrator.py      # Mixin assembly
|   +-- agent_families.py    # Opt-in family routing (ships OFF)
|   +-- config.yaml          # Safe defaults (checked in)
+-- burp-extension/          # Java Burp Suite plugin (Montoya API)
|   +-- src/main/java/com/harness/llm/
+-- testing/                 # Target apps and evaluation harnesses
+-- evaluation_integrity/    # Scoring correctness tests
```
