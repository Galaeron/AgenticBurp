# AgenticVibe

A Burp Suite copilot that uses locally-hosted LLMs to analyze captured HTTP traffic for security vulnerabilities, then confirms or refutes those findings with deterministic validators.

> **Status: working research prototype, effectiveness unproven.** The software
> runs and its Python and Java test suites are run in CI (`docs/TESTING.md`), but
> nothing in the repo measures how well it finds real bugs on an unfamiliar app, and its tuning
> corpora ship with answer keys. Read **[docs/LIMITATIONS.md](docs/LIMITATIONS.md)**
> before trusting any result, and **[docs/USER_MANUAL.md](docs/USER_MANUAL.md)**
> to run it safely.
> Report a vulnerability privately as described in **[SECURITY.md](SECURITY.md)**;
> changes are in **[CHANGELOG.md](CHANGELOG.md)**.
>
> **Out of the box it is passive and deliberately quiet:** active testing,
> autonomous discovery and the cloud seams are OFF and no scope is set, so it
> only reviews the exact traffic you send it with a small local model. If it
> "finds almost nothing," that is why — check `GET /health/details` first (with
> the pairing token; it reports whether Ollama is reachable and the model is
> pulled), then enable active
> testing on a scoped host per the user manual.

## How It Works

```
+-------------------+  POST /analyze  +-------------------+  /api/chat  +-------------+
|  Burp Extension   | --------------> |  Harness Server   | ----------> |   Ollama    |
|  (Java, Montoya)  |                 |  (FastAPI :8787)  |             |  (local)    |
|                   |                 |                   |             +-------------+
|  2 suite tabs:    |                 |  Orchestrator     |
|  - LLM Harness    |                 |    |              |
|  - Harness Tools  |                 |    +-> Agents     |
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
5. **Agent dispatch** -- `AgentManager.run_multiple_agents()` runs selected agents in parallel, bounded by an asyncio semaphore (`concurrency.max_parallel_agents`). Each agent sends a vulnerability-class-specific prompt + the exchange to Ollama and returns structured findings. Optionally, agents can be grouped into families for fewer model calls (`coordinator.routing_mode: "families"`, ships OFF).
6. **Access control gate** -- caps IDOR/authz findings that are refuted by 401/403/405 status codes.
7. **Header noise gate** -- caps CORS/CSP/clickjacking findings to "low" severity.
8. **Critique** -- adversarial LLM review of surviving findings. Each is verdicted "survived", "downgraded", or "rejected". Rejected findings are removed.
9. **Adaptive re-spin** -- if nothing actionable survived and cloud reasoning is enabled, asks the coordinator for follow-up agents and dispatches another round (up to `max_rounds`).
10. **Credential detection** -- flags credential endpoints in the exchange.
11. **Shape precondition** -- deterministic findings from endpoint shape (e.g. missing security headers).
12. **Validation** -- `ValidatorRegistry.for_finding()` matches findings to validators. Each validator sends targeted probes and returns machine-verifiable results. Active validators only run when `validators.active_enabled` is set. Agents name the parameter a finding is about (`parameter_location` / `parameter_name`); the SSTI, command-injection, path-traversal and open-redirect validators test that parameter first, even past their parameter cap. A negative that did not cover the named parameter, or every input, is marked `named_parameter_untested` / `partial_coverage` and is not a controlled negative (see `harness/validators/README.md`).
13. **Confirmation gate** -- classifies each unconfirmed finding:
    - **CONFIRMED** -- a validator proved it. Ships at true severity.
    - **REFUTED** -- a live-verified validator ran, produced a controlled negative. Demoted to "low", confidence <= 0.35.
    - **UNVERIFIED** -- a live-verified validator ran but produced no controlled negative (including a negative that never tested the finding's parameter). Demoted to "low", labelled inconclusive rather than a likely false positive.
    - **UNPROVEN** -- the validator is only smoke-tested (not proven against live targets). Capped at "medium", confidence <= 0.5.
14. **Known-vulnerability resolution** -- extracts software components from agent reports, verifies against exchange text, looks up GitHub Advisories + CISA KEV.
15. **Supplemental scans** -- confidential info (regex-based secrets/PII), verbose error detection, secret disclosure.
16. **Chain detection** -- links findings into attack chain hypotheses (`chaining.py`, `chain_linker.py`).
17. **Auto-escalation** -- if engagement policy allows, escalates to deeper investigation.
18. **Persist + respond** -- findings stored in SQLite (`store.py`), response returned.

### The engagement investigation (`orchestrator_chain.py: investigate_engagement()`)

`POST /engagement/{host}/investigate` runs a whole-application investigation as a background job, with the supplied identities (roles). In outline:

1. **Build the engagement** -- crawl as every role, discover and probe operations, and build the endpoint graph and its worklist (`engagement_builder.py`).
2. **Header audit** -- run the CORS, CSP and verbose-error validators over every captured exchange.
3. **Worklist sweep** -- the iterative agent investigates the highest-ranked nodes. Each node whose shape warrants it also gets a deterministic confirmation leg, chosen by class: cross-identity replay for access control, sqlmap for SQL injection, the nosql validator for NoSQL injection, a headless browser for XSS, and so on. A NoSQL finding goes to the nosql leg, never to sqlmap.
4. **Capture review** -- the model reviews the captured exchanges. Then chain rounds link findings and re-test with any leaked credential.
5. **Coverage matrix** -- one row per endpoint and check (`coverage_tracker.py`). Optional legs fill in the cells nothing tested (`engagement.coverage_drive_legs`).
6. **Server-error follow-up** (`server_errors.py`, `engagement.server_errors`) -- the transport records the 5xx answers to the run's own requests. It scans the first bodies on each route; it keeps only parameter names, never values. A stack trace or debug page becomes a confirmed `verbose_error_disclosure`. A database error answering suspect input becomes an `sql_injection` / `nosql_injection` lead, bound to the parameter when exactly one parameter carried suspect input. `max_lead_confirmations` leads go to that class's leg, using the route's captured template. The default is 0, because dispatching sends active traffic (`passive-only` forces it to 0). The result's `server_errors` key lists every route that answered 5xx and what each lead became.
7. **Retry rounds** (`retry_rounds.py`, `engagement.retry_rounds`, off by default) -- when the run is time-boxed (`investigation_seconds`), the time left is spent instead of given back. Until `reserve_seconds` before the deadline, rounds re-sweep the nodes an earlier budget skipped, the probes that ended on a model error or ran out of steps, and the captures whose review failed (including a failed critique, whose findings would otherwise ship unreviewed). Each round grows the budgets. Afterwards the server-error pass runs again, and the coverage matrix is refreshed with what the rounds found. A late unconfirmed detection never overturns a leg's verdict; a late confirmation does outrank a leg's negative.

### Evidence ledger

Every step emits events to an append-only ledger (`evidence_ledger.py`). Events carry a `Provenance` envelope (code version, config fingerprint, model tag). The ledger is wired into agents (HYPOTHESIS events), validators (EXECUTION events), the confirmation gate (FINDING_REVISION events), and the orchestrator (RUN_SUMMARY). Persisted to SQLite and exposed via `GET /findings/{finding_ref}/evidence`. Persisted rows are hash-chained per finding; `python tools/verify_evidence_ledger.py` reports an edited, deleted, inserted or reordered row (see the script header for what the chain cannot show).

## Components

### Harness Server (`harness/server.py`)

FastAPI on `127.0.0.1:8787`. At startup: loads and validates config, constructs a single `Orchestrator`, generates an ephemeral bearer token (or uses configured one), installs trusted-host and CSRF middleware. Its routes are listed in `harness/server.py` (the `@app.get/post/put/delete` decorators); the main ones:

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
| `POST /test-plans/{id}/dispatch` | Issue the single-use nonce and the live policy for one Burp-plane run (below) |
| `POST /validation-results` | Accept a Burp-side validation submission, once, under that nonce (below) |

**Burp-plane dispatch.** The Burp extension runs a test plan with its own HTTP stack, so the harness
decides what it may send. `POST /test-plans/{id}/dispatch` (token required) returns
`{plan_id, dispatch_nonce, policy: {active_enabled, allow_mutating_replay}, request_budget}`: the live
values of the two flags and the run request ceiling (`runs.max_requests`). The plane sends mutating
requests only when both flags are on, and stops at the budget. `POST /validation-results` accepts a
result only under the plan's current, unconsumed nonce, for a plan that holds no verdict. A refusal
consumes nothing and answers `{"detail": {"reason": <code>, "message": ...}}`:

| Status | Reason codes |
|---|---|
| 404 | `unknown_plan` |
| 409 | `not_dispatched`, `dispatch_nonce_mismatch`, `duplicate_submission`, `plan_terminal` |
| 422 | `dispatch_nonce_required`, `wrong_execution_plane`, `binding_mismatch`, `executor_mismatch`, `capability_cannot_confirm`, `confirmed_status_invalid` |

The harness and the Burp jar must be upgraded together: an older harness fails the dispatch with a version hint.

### Orchestrator (`harness/orchestrator.py`)

Assembled from the mixins below. `__init__` constructs: `OllamaClient`, coordinator + critique LLM providers (local Ollama or optional remote), `Coordinator`, `AgentManager`, `AnalysisPipeline`, `FastPathSelector`, `ValidatorRegistry`, `EffortBudget`, GitHub Advisory + KEV + package registry clients, engagement policy, global throttle.

| Mixin | Module | Key methods |
|---|---|---|
| `DetectMixin` | `orchestrator_detect.py` | `analyze()`, `_choose_agents()`, `_maybe_adaptive_respin()`, `_resolve_known_vulnerabilities()` |
| `ConfirmMixin` | `orchestrator_confirm.py` | `_validate_findings()`, `run_active_probe()`, `run_retry_agents()`, `_coverage_proof()` |
| `ChainMixin` | `orchestrator_chain.py` | `plan_engagement()`, `run_engagement()`, `investigate_engagement()` |
| `ReportMixin` | `orchestrator_report.py` | `plan_allocation()`, `estimate_for_urls()`, `list_models()`, `set_coordinator_model()` |

### Agents (`harness/agents/`)

The specialist agents are `BaseAgent` subclasses, each with a `name` attribute, discovered at runtime by `AgentPluginSystem` (file scan of the `agents/` directory). `BaseAgent` handles: prompt construction with exchange body truncation (preserves high-signal content like stack traces beyond the truncation point via regex), quarantine fencing (random-nonce boundaries to contain prompt injection from target responses), and structured finding extraction.

The default routing mode dispatches each agent as an individual model call. An opt-in family routing mode (`coordinator.routing_mode: "families"`) groups them into the families below and issues one composed call per family:

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

The validators are registered in `ValidatorRegistry.__init__()`, each togglable. Matched to findings via `for_finding()` based on vulnerability class. Categories:

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
- **`logic/` package** -- the client-side modules: most are per-vulnerability-class deterministic checks (SQLi, XSS, SSRF, XXE, JWT forgery, CSRF, mass assignment, etc.), plus shared identity/URL/pool-comparison helpers (`IdentityCompareLogic`, `UrlIdentifierDiff`, `PoolCandidateResolver`, `WorkflowReplayLogic`) they build on.

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

- **Python 3.11 or newer** (`requires-python` in `pyproject.toml`). CI and the
  lock file use **Python 3.14**, so use 3.14 if you can; see
  [USER_MANUAL.md](docs/USER_MANUAL.md) §8 for the 3.12 proxy-extra caveat.
- **A model backend** -- Ollama with a pulled model (e.g. `ollama pull qwen3:8b`),
  or an OpenAI-compatible server such as llama.cpp's `llama-server`.
- **Docker** (optional) -- the sqlmap validator runs in a container.
- **JDK 17** (optional) -- only to build the Burp extension; the repository ships
  the Gradle wrapper.
- **Burp Suite** (Community or Pro) -- for the extension UI.

## Quick Start

The first-run steps, in order. [docs/USER_MANUAL.md](docs/USER_MANUAL.md) §1 has the
same list with the reasoning. Not yet walked through on a clean machine by someone
new to the tool (**unverified**: the 30-minute target is an owner/live step).

**1. Python.** Python 3.11 or newer; Python 3.14 is what CI tests.

**2. Install from the lock** (from the repo root; the lock is the dependency set CI tests):

```bash
pip install -r harness/requirements.lock
pip install -e . --no-deps
python -m harness.lock_preflight   # warns if installed versions differ from the lock
```

**3. Model and context settings.** Start the backend (`ollama serve`, then
`ollama pull qwen3:8b`) and put your overrides in the git-ignored
`harness/config.local.yaml`:

```yaml
ollama:
  num_ctx: 16384            # context window to ask Ollama for (llama-server: its per-slot window)
  # allow_cloud_models: true   # leave unset unless the engagement permits sending content to Ollama's cloud
```

- `num_ctx`: Ollama loads a model at its own small default window and truncates a
  longer prompt; the harness discards such a reply and marks the run `degraded`, so
  set the window up front. 16384 holds the largest prompt measured.
- Prompt fitting: the harness asks the model server for the window it actually
  has, uses the smaller of that and `num_ctx`, and cuts prompts to fit, listing the
  cuts in the job result's `review_stats.elided`. When it cannot find a window it
  fits to `prompt_budget.unknown_context_tokens` (4096); it never sends unfitted. A call
  that still overflows is discarded and the run is marked `degraded`.
- `ollama.allow_cloud_models` is `false`: a model named `*-cloud` or `*:cloud`
  runs on Ollama's cloud and sends exchange content off this machine, so a run
  that would use one is refused before its first model call (HTTP 409).
- `ollama.rate_limit` paces model calls (shipped: `enabled: true`, `burst_calls: 10`,
  `calls_per_minute: 10`, `max_wait_seconds: 300`). Raising or disabling it
  loosens a safeguard, so do that in `config.local.yaml` only. The run manifest
  records the values under `model_rate_limit`.

**4. Build the Burp extension** (optional; JDK 17 installed, JDK 17-21 on `JAVA_HOME`):

```bash
cd burp-extension
./gradlew shadowJar     # Windows: gradlew.bat shadowJar -> build/libs/*-all.jar
```

The wrapper pins Gradle 8.7 by checksum and the build compiles and tests with a
Java 17 toolchain. Load the `*-all.jar` in Burp Suite > Extensions.

**5. Start the server and pair.**

```bash
python -m harness.server     # 127.0.0.1:8787
```

Every state-changing route needs a token, even from loopback. It is your
`server.auth_token` / `HARNESS_BEARER_TOKEN` if set, else the ephemeral token the
server writes to `harness/.harness_token.lock` at each start. Paste it into the
**Pairing token** field of Burp's LLM Harness tab (or export `HARNESS_BEARER_TOKEN`
before starting Burp). Check it with `GET /pairing/check`, then read readiness at
`GET /health/details` (`/health` is liveness only).

**6. A first `/analyze`.** Save one captured exchange as `exchange.json`:

```json
{"exchange": {"url": "http://127.0.0.1:8080/rest/user/login", "method": "POST",
              "request_headers": {"Content-Type": "application/json"},
              "request_body": "{\"email\":\"a@b.test\",\"password\":\"x\"}",
              "response_status": 401, "response_headers": {"Content-Type": "application/json"},
              "response_body": "{\"error\":\"Invalid email or password.\"}"}}
```

```bash
# $HARNESS_TOKEN is the pairing token from step 5; in PowerShell use curl.exe
curl -s -X POST http://127.0.0.1:8787/analyze \
  -H "Authorization: Bearer $HARNESS_TOKEN" -H "Content-Type: application/json" \
  --data @exchange.json
```

The answer lists `dispatched_agents`, `agent_reports` and a `summary`. If
`degraded` is true or `agent_errors` is non-empty, the model did not answer: fix
that first. The committed defaults are passive, so a first result may be nearly empty.

## Testing

```bash
python -m harness.suite smoke   # fast subset
python -m harness.suite full    # unittest + pytest + evaluation integrity
```

## Project Structure

```
AgenticVibe/
+-- harness/                 # Python backend (FastAPI)
|   +-- agents/              # specialist agents (plugin-discovered)
|   +-- validators/          # deterministic validators
|   +-- server.py            # API entry point (:8787)
|   +-- orchestrator.py      # Mixin assembly
|   +-- agent_families.py    # Opt-in family routing (ships OFF)
|   +-- config.yaml          # Safe defaults (checked in)
+-- burp-extension/          # Java Burp Suite plugin (Montoya API)
|   +-- src/main/java/com/harness/llm/
+-- testing/                 # Target apps and evaluation harnesses
+-- evaluation_integrity/    # Scoring correctness tests
```
