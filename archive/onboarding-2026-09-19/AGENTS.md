# AgenticVibe — project context for Codex

Stable orientation for every session. **This file + [`CURRENT_STATE.md`](CURRENT_STATE.md)
are the whole onboarding** — read those two, not the archived handover chain. Everything
here is meant to stay true across sessions; the per-session delta (branch, HEAD, test
count, what's in flight) lives in `CURRENT_STATE.md`.

## What this is

An agentic-AI-pentesting harness: a Burp-Suite copilot backed by local Ollama models that
reasons over captured HTTP exchanges and drives a graph-driven engagement loop
(`orchestrator.investigate_engagement`) with deterministic confirmation legs. It sits in
the *copilot* lane (peer set PentestGPT / Nebula / AI-OPS, not XBOW / Shannon — see
`COMPETITIVE_LANDSCAPE.md`). Detection is broad; the ongoing work is making
**confirmation** as broad as detection.

## The #0 discipline — "green tests, dead pipeline"

Real detection was silently **zero** three separate times while a large mocked suite
stayed green. That is the recurring failure mode of this project, and guarding against it
is the first rule:

- **Tie every claim to a command/test that verifies it, or mark it reported/not-verified.**
  Keep that distinction sharp in `CURRENT_STATE.md` and in what you tell the user. A
  plausible number (test count, finding count) trusted instead of inspected is the trap.
- **New pipeline code that no test exercises is the danger zone.** Add an end-to-end smoke
  test *with a negative control* (`test_smoke_detection.py`, `test_smoke_investigate.py`),
  not just unit tests of the plumbing.
- Make focused, dependency-ordered commits so the suite is green at each. End commit
  messages with the `Co-Authored-By` trailer.

## HAZARDS — read before touching anything

1. **Config-toggle trap.** `harness/config.yaml` stays at safe defaults; live active-mode
   toggles go in git-ignored `harness/config.local.yaml` (deep-merged by
   `server.load_config()`). **Never `git add harness/config.yaml`** with toggles flipped;
   **never commit `config.local.yaml`**.
2. **Never read `*ANSWER_KEY*` or a blind target's `app.py`.** Current target:
   `testing/vulncorp-helpdesk/` (Flask, :5002, ~40 planted vulns, 4 roles / 2 orgs). Its
   `README.md` is safe; `ANSWER_KEY.md` and `app.py` are NOT.
3. **Windows Defender quarantines host-installed offensive tools** — that is why sqlmap
   runs in Docker. Do **not** `pip install sqlmap` on the host. (Chromium/playwright for
   `browser_xss` is a normal browser and stays on the host.)
4. **Restart the server + use a cold cache after any Python change.** A warm `*_cache.db`
   replays the old analysis — delete/rename it (or `cache.init_cache(db_path=...)`) for a
   real re-run. Server runs `reload=False`.
5. **VulnCorp rebuilds `helpdesk.db` on start and is stateless.** "no such table: users"
   means stale/multiple instances on a 0-byte DB — kill them, start ONE (debug off).
6. **Java can't compile here** (no JDK). Burp-panel changes are self-reviewed only; the
   real gate is the user's `gradle shadowJar`.

## Environment (this machine — Windows)

- **Ollama** reachable, model `qwen3:8b`, split ~41% CPU / 59% GPU — the perf bottleneck.
  A full max-coverage run is ~3 h. Check: `curl -s http://localhost:11434/api/tags`.
- **Docker** up, with `harness/sqlmap:1.10.9` built
  (`docker build -t harness/sqlmap:1.10.9 -f tools/sqlmap.Dockerfile tools`). Daemon down
  ⇒ sqlmap silently falls back to host binary / boolean probe.
- Containers reach the host via `host.docker.internal` (not `--network host` — limited on
  Docker Desktop); `tool_runner.py` rewrites loopback URLs.
- No host `javac`.

## Architecture — `investigate_engagement` (the graph-driven loop)

The old pipeline fired ~36 agents at every captured exchange once each and gave up on a
miss. The current flow lets the **engagement graph drive**: discover surface → prioritise
→ bounded per-node investigation → link into chains. Entry: `orchestrator.investigate_engagement()`.

```
build_engagement(base, roles)                                    [A] coverage + ranking
  ├─ api_surface_discovery.SurfaceDiscovery.discover()  → routes
  ├─ role_crawl.crawl_roles(active_discovery=True)      → per-role access matrix + IDOR candidates
  └─ EngagementState.ingest_role_crawl()               → prioritised worklist
       │
worklist_investigator.investigate_worklist(...)                  [B] iterate, don't one-shot
  for each top-ranked node: _derive_probe → iterative_agent (N steps) → ingest_findings
  · a `precondition_fn` seam runs SHAPE-warranted confirmation legs per node,
    independent of whether an agent labelled that class (the §"decoupling" fix)
       │
chain_linker.link_findings(...)                                  [C] escalate + compose
  ├─ detect/apply_capabilities → escalation edges in the task graph
  └─ chaining.detect → composed attack-chain tasks
       │
  bounded closed loop: re-test AS any leaked credential
```

**Confirmation is decoupled from detection.** `orchestrator.shape_precondition_legs(node,
exchange, roles, base_url)` (pure, unit-tested) picks legs by endpoint *shape* —
object-scoped GET → cross-identity; JWT-carrying → jwt-forge; XML body → xxe; URL param →
ssrf — and reuses the live `_confirm` dispatcher. Shape is a reason to *try* a leg; only
CONFIRMED results are kept, so it never adds unconfirmed noise. The captured-exchange path
(`analyze()`) has the analogue: `orchestrator.shape_precondition_findings(exchange)` runs the
XXE/SSRF legs the exchange's own shape warrants (appended as a rule-based report before
validation, pruned to confirmed-only after), so an XML-accepting endpoint no agent labelled
"xxe" still gets its external-entity leg.

### Deterministic confirmation legs

The graph loop's `_confirm` dispatcher routes findings to these legs; all are live-verified
against the vuln_fixture (except `privilege_escalation`, which is provisional). The
`_cached_validate` wrapper memoises results per `(validator, method, url, body_hash)` within
a run. `validators/registry.py` is the source of truth.

| Leg | Class | Mechanism |
|---|---|---|
| `cross_identity` | IDOR / access control | replay as other identities + anon |
| `sqlmap` (container) | SQLi | sqlmap in Docker via `tool_runner` |
| `browser_xss` | XSS | Playwright headless Chromium; declines non-HTML-sink |
| `jwt_forge` | JWT alg:none / kid | forge + replay + garbage-sig control |
| `xxe` | XXE | external-entity → OOB `collaborator` |
| `ssrf` | SSRF | URL-param redirect → OOB `collaborator` |
| `ssti` | template injection | nonce-wrapped arithmetic differential |
| `command_injection` | RCE / shell | shell → OOB `collaborator` callback |
| `path_traversal` | LFI / traversal | canonical system file read |
| `open_redirect` | redirect | off-origin sentinel in Location |
| `sequence` | mass-assignment | write-then-re-read differential |
| `deserialization_oob` | deserialization | benign pickle OOB beacon |
| `auth_sequence` | session-fix/weak-pw/enum | multi-request flows |
| `stored_xss` | stored XSS | plant-then-independent-render |
| `csrf` | CSRF | token-strip replay + SameSite check |
| `verb_tamper` | method bypass | safe read-only alternates + override headers |
| `file_upload` | upload bypass | benign .html upload + retrieve |
| `secret_disclosure` | key leaks | HMAC-verified JWT key in response |
| `rate_limit` | no rate limit / lockout | replay captured auth N× via authorize_burst, confirm no 429/lockout (provisional) |
| `reset_token` | predictable reset token | sample tokens, `analyze_tokens` deterministic predictability oracle (provisional) |
| `dom_xss` | DOM-based XSS | payload in URL fragment (never server-sent) → browser execution = client-side taint (provisional) |
| `verb_tamper` (mutating) | method authz bypass | opt-in PUT/PATCH/DELETE (`try_mutating_methods`, triple-gated) |
| `toctou` | priv-esc race (V19) | baseline read → concurrent burst of an authority write → verify read; confirm on field-flip-under-concurrency + ≥2 clean successes (provisional) |

Second-order chains (V22 SQLi / V17 IDOR) have no single-request leg: `chaining.py`
composes the plant→trigger `(A,B)` pair (`second_order_{sqli,idor}` rules,
`second_order_candidates()`), `second_order.py` supplies the boolean-differential /
cross-identity plant-read primitives, and `investigate_engagement` runs them live
over each pair (`auto_confirm_candidates`, gated on `allow_mutating_replay`).

The **coverage matrix is a driver, not just a recorder** (I1): with
`engagement.coverage_drive_legs` on, `coverage_tracker.build_coverage_driven` fires
every applicable deterministic leg per (identity×endpoint×check) cell regardless of
the LLM label, so "every applicable check attempted" is true by construction and
detection no longer hinges on label variance.

Three legs above are **provisional** — built + hermetically tested but not yet
live-verified on a target, so CONFIRMABLE but not in `LIVE_VERIFIED_MARKERS`. A
finding whose class has **no** leg at all is flagged for human verification
(`engagement.flag_unconfirmable`), never fake-confirmed.

Enable in a run: `active_enabled: true`; sqlmap needs `container_image: harness/sqlmap:1.10.9`
+ Docker; xxe/ssrf/csrf/file_upload need `allow_mutating_replay: true` (mutating sends go
through the safety gate `GatedAsyncClient`). See the current run script (named in
`CURRENT_STATE.md`).

**The registry is wider than the graph `_confirm` set.** The **captured-exchange path
(`analyze()`)** runs the *full* `ValidatorRegistry` via `for_finding()`: the legs above
**plus** `cors`, `csp`/clickjacking, `api_security`, `crypto`/tls,
`http_request_smuggling`, `header_injection`/crlf, `race_condition`, `oauth`/oidc, `recon`,
`websocket`/cswsh, `subdomain_takeover`, `web_cache_poisoning`, and passive-only
`deserialization`. Each declares `finding_classes` + an `active` flag (`validators/base.py`);
**all are `active` except `deserialization`**, so under the safe default `active_enabled:
false` only `deserialization` runs — the rest arm only once a live run turns active mode on.

## Key file map (`harness/`)

| Area | Modules |
|---|---|
| Engagement loop | `orchestrator.py`, `engagement_builder.py`, `engagement.py`, `worklist_investigator.py`, `chain_linker.py`, `chaining.py`, `task_graph.py` |
| Discovery / crawl | `api_surface_discovery.py`, `role_crawl.py`, `scope_discovery.py`, `crawler.py`, `js_endpoint_extractor.py`, `feature_workflow.py` (stateful role workflow crawl), `burp_sitemap.py` (import a human's browsing) |
| Coverage matrix | `coverage_model.py` (catalog), `coverage_tracker.py` (fills it during a run → auditable I1/I2/I5 report in `investigate_engagement` result under `coverage`) |
| Second-order | `chaining.py` (compose `(A,B)`), `second_order.py` (plant→trigger differentials) |
| Agents / LLM | `iterative_agent.py`, `agent_manager.py`, `ollama_client.py`, `planner.py`, `analysis_pipeline.py` |
| Confirmation | `validators/` (18 graph-loop legs + ~8 registry-only — `registry.py` is the source of truth), `collaborator.py`, `active_verification.py`, `tool_runner.py` |
| Coverage | `coverage_model.py` (WSTG check catalog + coverage matrix), `ffuf_runner.py` |
| Safety / infra | `safety_gate.py`, `safety_proxy_addon.py`, `security.py`, `cache.py`, `store.py`, `config.yaml` (+ git-ignored `config.local.yaml`), `server.py` |
| Reporting | `report_generator.py`, `categories.py`, `knowledge.py` |
| Burp side | `burp-extension/` (Java; can't compile here) |

## Commands

```bash
# full suite (run before trusting anything, after every change)
cd harness && python -m unittest discover -p "test_*.py"
# a focused module
cd harness && python -m unittest test_orchestrator_precondition
```
A live max-coverage run is driven by a script named in `CURRENT_STATE.md` (kept in the
scratchpad, not committed). Use a FRESH cache DB (hazard #4).

## Handover protocol — keep onboarding cheap

The whole point of this layout is that a new session reads two short files, not a chain.
To keep it that way:

- **Update `CURRENT_STATE.md` in place** at session end — overwrite it, don't create
  `SESSION_HANDOVER_N+1`. It is the single rolling delta.
- **When you learn something *stable*** (an architecture change, a new hazard, a new leg, a
  moved file), fold it into THIS file rather than re-narrating it in the next handover.
  That is what stops the 100k-token reconstruction from coming back.
- Older `SESSION_HANDOVER_*.md` and `HANDOVER.md` are archived under `archive/` for
  git-history spelunking only — not part of onboarding.
