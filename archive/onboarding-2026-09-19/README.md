# Burp LLM Harness

A Burp Suite copilot backed by local Ollama models that reasons over
captured HTTP exchanges and drives a **graph-driven engagement loop**
with deterministic confirmation legs. It discovers attack surface,
prioritises nodes, runs bounded per-node investigation, and links
findings into escalation chains — closing the loop by re-testing as any
leaked credential.

**Default posture: passive.** Out of the box nothing touches the target
beyond what Burp already captured. Active discovery, crawling, and
confirmation legs are all opt-in, scope-gated to `allowed_hosts`, and
throttled. Use it only against applications you're authorised to test.

> **Docs map:** [`CLAUDE.md`](CLAUDE.md) holds the stable orientation
> (architecture, hazards, environment, file map) and
> [`CURRENT_STATE.md`](CURRENT_STATE.md) the per-session delta (branch,
> HEAD, what shipped, what's pending). Those two are the whole onboarding.
> Historical handover files are archived under `archive/` for git-history
> spelunking only.

---

## How it works

The harness has two modes of operation that compose:

### 1. Captured-exchange analysis (the original "copilot" path)

You send a single request/response pair from Burp. The orchestrator
selects specialist agents (36 narrow security classifiers — SQLi, XSS,
IDOR, SSRF, JWT, business logic, and more), runs them concurrently
against the exchange, critiques the high-confidence findings, and
returns structured results to a tab inside Burp.

Agent dispatch is usually **deterministic pattern matching**
(`fast_path.py` — URL shape, parameters, headers, body) with no LLM
call. Only genuinely ambiguous exchanges fall through to a coordinator
model call. If even that returns nothing, it fails open to all agents
rather than silently analysing nothing.

The captured-exchange path also runs the **full validator registry** —
every applicable confirmation leg fires on every finding, including
legs the graph loop doesn't use (CORS, CSP, API security, crypto/TLS,
HTTP smuggling, header injection, race condition, OAuth, recon,
WebSocket, subdomain takeover, web cache poisoning, and passive
deserialization).

### 2. Engagement loop (`investigate_engagement` — the graph-driven path)

The newer, deeper mode. Entry: `orchestrator.investigate_engagement()`.

```
build_engagement(base, roles)                                    [A]
  ├─ api_surface_discovery.SurfaceDiscovery.discover()  → routes
  ├─ role_crawl.crawl_roles(active_discovery=True)      → access matrix + IDOR candidates
  └─ EngagementState.ingest_role_crawl()               → prioritised worklist

worklist_investigator.investigate_worklist(...)                  [B]
  for each top-ranked node: _derive_probe → iterative_agent → ingest_findings
  · shape_precondition_legs fires confirmation by endpoint shape,
    independent of whether an agent labelled that class

chain_linker.link_findings(...)                                  [C]
  ├─ detect/apply_capabilities → escalation edges
  └─ chaining.detect → composed attack chains

  bounded closed loop: re-test AS any leaked credential
```

**Confirmation is decoupled from detection.** The shape of an endpoint
(object-scoped GET → cross-identity; JWT → forge; XML body → XXE; URL
param → SSRF) is a reason to *try* a confirmation leg; only CONFIRMED
results survive. The **coverage matrix** can also drive every applicable
leg per (identity × endpoint × check) cell regardless of LLM labels, so
"every applicable check attempted" is true by construction.

### Deterministic confirmation legs

All legs are live-verified against the test fixture unless marked
*provisional*. The `_cached_validate` wrapper memoises results per
`(validator, method, url, body_hash)` within a run.

| Leg | Class | Mechanism |
|---|---|---|
| `cross_identity` | IDOR / access control | replay as other identities + anonymous |
| `sqlmap` (Docker) | SQLi | sqlmap in container via `tool_runner` |
| `browser_xss` | XSS | Playwright headless Chromium |
| `jwt_forge` | JWT alg:none / kid | forge + replay + garbage-sig control |
| `xxe` | XXE | external-entity → OOB collaborator |
| `ssrf` | SSRF | URL-param redirect → OOB collaborator |
| `ssti` | template injection | nonce-wrapped arithmetic differential |
| `command_injection` | RCE / shell | shell → OOB collaborator callback |
| `path_traversal` | LFI / traversal | canonical system file read |
| `open_redirect` | redirect | off-origin sentinel in Location |
| `sequence` | mass-assignment | write-then-re-read differential |
| `deserialization_oob` | deserialization | benign pickle OOB beacon |
| `auth_sequence` | session-fix/weak-pw/enum | multi-request flows |
| `stored_xss` | stored XSS | plant-then-independent-render |
| `csrf` | CSRF | token-strip replay + SameSite check *(retired — observation only)* |
| `verb_tamper` | method bypass | safe alternates + override headers *(retired — observation only)* |
| `file_upload` | upload bypass | benign .html upload + retrieve |
| `secret_disclosure` | key leaks | HMAC-verified JWT key in response |
| `rate_limit` | no rate limit | replay N× via authorize_burst *(provisional)* |
| `reset_token` | predictable token | sample + deterministic predictability oracle *(provisional)* |
| `dom_xss` | DOM-based XSS | URL fragment → browser execution *(provisional)* |
| `toctou` | priv-esc race | concurrent burst + field-flip verification *(provisional)* |

Second-order chains (SQLi, IDOR) compose plant→trigger pairs via
`chaining.py` + `second_order.py` and run them live when
`allow_mutating_replay` is on.

See [`ORACLE_RETIREMENTS.md`](ORACLE_RETIREMENTS.md) for the legs whose
confirmation verdicts were stood down to observations until they
re-qualify with stronger controls.

---

## Is my machine good enough?

**Yes — a laptop with a discrete GPU or a desktop with an RTX 3070 (8 GB)
can run this.** The only GPU-bound piece is Ollama; Burp, the Python
harness, and the Java extension all run fine on CPU.

- The shipped config uses **`qwen3:8b` everywhere** (~5–6 GB at Q4_K_M).
  Because every agent shares one model there is no VRAM swapping by
  default.
- `config.yaml`'s `concurrency.max_parallel_agents` (default: 1 on this
  machine) caps how many agents run simultaneously. Raise it if you have
  VRAM headroom; set to 0 for unbounded.
- **12 GB+ VRAM** opens the door to mixing in a stronger model for the
  coordinator or harder agents.
- **CPU-only** works, just slowly (5–15× per agent call).

---

## Setup

### 1. Install and start Ollama

```bash
ollama pull qwen3:8b
ollama serve
```

### 2. Start the harness

From the **repository root** (not from inside `harness/`):

```bash
pip install -e .                       # or: pip install -r harness/requirements.txt
python -m harness.server               # or: uvicorn harness.server:app
# -> http://127.0.0.1:8787 — confirm: curl http://127.0.0.1:8787/health
```

Requires Python 3.11+. Optional extras:

```bash
pip install -e ".[browser]"   # Playwright/Chromium for browser_xss
pip install -e ".[proxy]"     # mitmproxy safety proxy addon
```

### 3. Docker (for sqlmap confirmation)

```bash
docker build -t harness/sqlmap:1.10.9 -f tools/sqlmap.Dockerfile tools
```

Set `container_image: harness/sqlmap:1.10.9` in `config.yaml` under
`validators.sqlmap`. Without Docker, sqlmap falls back to a host binary
or boolean probe.

### 4. Build and install the Burp extension

Requires JDK 17+ and Gradle.

```bash
cd burp-extension
gradle shadowJar
```

In Burp: **Extensions → Installed → Add → Java** → select
`build/libs/burp-llm-harness-extension-0.1.0-all.jar`. A new **LLM
Harness** tab appears. Set the harness URL (default `http://localhost:8787`)
and click Test Connection.

### Models & config

`harness/config.yaml` controls everything model-related. As shipped,
every role points at `qwen3:8b`. Live active-mode toggles go in the
git-ignored `harness/config.local.yaml` (deep-merged by
`server.load_config()`). **Never commit `config.yaml` with toggles
flipped; never commit `config.local.yaml`.**

To use a different model, change `agent_defaults.model`. To give harder
agents a stronger model, override them individually under `agents:`.

---

## Architecture overview

```
Burp (Proxy / Repeater / Target site map)
   │
   │  Attack Surface Map tab: local heuristic scoring (no LLM)
   │  right-click → "Send to LLM Harness"
   ▼
Burp extension (Java, Montoya API)
   │  HTTP POST /analyze  (localhost only)
   ▼
harness/server.py  (FastAPI, /analyze + /engagement/{host}/investigate)
   │
   ├── CAPTURED-EXCHANGE PATH (/analyze)
   │    orchestrator.py → fast_path.py (deterministic) or coordinator.py (LLM)
   │    → agents/ (36 specialists, concurrent) → adversarial critique
   │    → validators/registry.py (full registry) → chaining.py
   │
   ├── ENGAGEMENT PATH (/engagement/{host}/investigate)
   │    orchestrator.investigate_engagement()
   │    → engagement_builder.py (discovery + role crawl + prioritisation)
   │    → worklist_investigator.py (iterative_agent per node)
   │    → shape_precondition_legs (deterministic confirmation by shape)
   │    → chain_linker.py (escalation + chaining)
   │    → credential closed loop (re-test as leaked creds)
   │
   ├── COVERAGE MATRIX
   │    coverage_model.py (WSTG check catalog)
   │    coverage_tracker.py (fills during run → auditable report)
   │    coverage_drive_legs: fires every applicable leg per cell
   │
   └── SAFETY
        safety_gate.py (GatedAsyncClient, per-invocation ContextVar)
        collaborator.py (OOB callback server for XXE/SSRF/cmd-inj)
        config.yaml defaults: passive; config.local.yaml for live toggles

Ollama (localhost:11434) ← qwen3:8b (single model, no swap)
   ▼
harness/harness_state.db (SQLite, per-host findings + identity store)
```

### Key modules

| Area | Modules |
|---|---|
| Engagement loop | `orchestrator.py`, `engagement_builder.py`, `engagement.py`, `worklist_investigator.py`, `chain_linker.py`, `chaining.py`, `task_graph.py` |
| Discovery / crawl | `api_surface_discovery.py`, `role_crawl.py`, `scope_discovery.py`, `crawler.py`, `js_endpoint_extractor.py`, `feature_workflow.py`, `burp_sitemap.py` |
| Coverage | `coverage_model.py` (catalog), `coverage_tracker.py` (per-run matrix) |
| Second-order | `chaining.py` (compose pairs), `second_order.py` (plant→trigger differentials) |
| Agents / LLM | `iterative_agent.py`, `agent_manager.py`, `ollama_client.py`, `planner.py`, `analysis_pipeline.py` |
| Confirmation | `validators/` (22+ legs — `registry.py` is the source of truth), `collaborator.py`, `active_verification.py`, `tool_runner.py` |
| Safety / infra | `safety_gate.py`, `safety_proxy_addon.py`, `security.py`, `cache.py`, `store.py`, `config.yaml` |
| Reporting | `report_generator.py`, `categories.py`, `knowledge.py` |
| Burp extension | `burp-extension/` (Java, Montoya API) |

---

## Running tests

From the **repository root**:

```bash
# full suite (~2,000 tests, all hermetic — no model or target needed)
python -m unittest discover -t . -s harness -p "test_*.py"

# a focused module
python -m unittest harness.test_orchestrator_precondition

# the real-pipeline gate (discovery → confirmation, ~11s)
python -m unittest harness.test_pipeline_gate
```

---

## Measured accuracy

### PixelMart corpus (uncontaminated, single-exchange)

`qwen3:8b`, severity ≥ medium, 2026-09-02:

| | value |
|---|---|
| precision | 0.476 |
| recall | 0.909 |
| tp / fp / fn | 10 / 11 / 1 |

See [`testing/SCORECARD.md`](testing/SCORECARD.md) for per-category
breakdown and the false-positive reduction history.

### VulnCorp ground truth (engagement loop, 13-item benchmark)

Best clean run (job `2dc2a3f1ff08`, `qwen3:8b`, 2026-09-17):

| | value |
|---|---|
| **earned** (deterministic-leg confirmed) | 5 / 13 |
| confirmed (any provenance) | 6 / 13 |
| missed | 7 / 13 |

Earned items: IDOR tickets, IDOR reports (cross_identity), path traversal
uploads, JWT forge, BFLA admin/users. The 7 misses trace to two
well-understood causes: discovery budget exhaustion (response/method mining
gets no probes after wordlist phases consume the budget) and missing
request body templates for JS-submitted forms. See `CURRENT_STATE.md` for
the full breakdown.

---

## Known limitations

- **Precision collapses on a truly blind target.** The scored numbers above
  are against purpose-built corpora. A blind helpdesk run held recall at
  2/2 but got 0/6 secure controls clean.
- **5 of 9 VulnCorp "confirmed" findings are agent-asserted with no
  deterministic leg** — the scorer honestly flags them as UNKNOWN
  provenance. The earned headline (5/13) is the trustworthy number.
- **sqlmap confirmation has a known miss rate** against real targets. "Not
  confirmed" is not strong evidence of absence.
- **The coordinator's fail-open fallback** (to all 36 agents) is real and
  currently silent. Watch for cost/latency spikes.
- **8 confirmation oracles are retired** (`ORACLE_RETIREMENTS.md`) — they
  emitted `confirmed=True` from evidence that didn't exclude benign
  explanations. Now observation-only until re-qualified.
- **No chains composed yet** in any live run (second-order SQLi/IDOR path
  produced nothing despite being wired).
- **browser_xss has 0 live confirmations** — kept as smoke-only, not
  promoted to live use.

---

## Competitive placement

This is a **Burp-Suite copilot** in the peer set of PentestGPT / Nebula /
AI-OPS — not an autonomous exploitation engine like XBOW / Shannon / Strix.
It discovers surface, prioritises, confirms deterministically, and tells you
what to try next. See [`COMPETITIVE_LANDSCAPE.md`](COMPETITIVE_LANDSCAPE.md)
for the full teardown.
