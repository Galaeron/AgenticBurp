# Current state

## 2026-09-19 — implementation review of P0/P1/P2 completion claims

Reviewed HEAD `8f635110952d50092b23c5f032536d7fea0397fd`; report:
[implementation-review/REVIEW.md](reviews/2026-09-19/implementation-review/REVIEW.md).
Nine findings on evaluation integration, proof binding, health/provenance false
assurance, shared-memory privacy, export/UI state loss, coverage attribution,
comparison causality, and SARIF semantic loss. Synthetic reproduction script is
beside the report. `all_host_findings()` verification-state fix directly verified
with an isolated database; issue export still omits that state.
Clean selected gates: **59 + 16 = 75 tests OK**. Initial broader run had 5
dependency errors; provider/CI module retry blocked by unreadable existing httpx
dependency. No dependency changes, full suite, Java build, hosted CI, or active
target/model execution. Product and pre-existing Ollama edits untouched.
“All P0 done” is not accepted as production integration: P0.4–P0.7 helpers have
no production consumers in the searched paths, and their edge cases overclaim.
Active oracle/probe efficacy and previously “already done” claims not certified
by this bounded evaluation/reporting/privacy review.

## 2026-09-19 (night) — implemented reviews/2026-09-19/IMPLEMENTATION_PLAN.md through P1.7 (22 commits, suite green)

Worked `reviews/2026-09-19/IMPLEMENTATION_PLAN.md` top-to-bottom, autonomously,
starting from the prior session's oracle-framework/off-scope-lock baseline (2067
tests). 22 focused commits on `reconciliation-backlog`, full suite green after
**every** commit (`python -m unittest discover -t . -s harness -p "test_*.py"`,
final count **2201 OK**, ~370s each run). Every task added at least one negative
control, per the plan's own #0-discipline requirement. Nothing pushed; nothing in
`harness/config.yaml` flips a live toggle (all new flags default OFF/safe).

**Known flake, not caused by this session:** `test_store.TestConnectConcurrentMigrationIsIdempotent
.test_concurrent_first_connects_do_not_raise` intermittently raises
`sqlite3.OperationalError: database is locked` under full-suite load on this
Windows/WAL setup (passes reliably in isolation). Reproduced both before and
during this session's edits, unrelated to any touched file — not chased further.

**All P0 items done:**
- **P0.1-WIRE** — `orchestrator_confirm.ConfirmMixin._oracle_gate` runs (or no-ops)
  right where a finding is first confirmed, behind default-off `oracle.enabled`.
- **P0.2-API** — found and fixed a REAL bug: `store.all_host_findings()` never
  selected `oracle_verified`/`verification_state`/`oracle_capsule_id`, so
  `report_generator`'s badge silently showed every finding as "candidate"
  regardless of what was persisted. Fixed; the JSON/API path was already fine
  (pydantic `model_dump()` has no exclusions).
- **P0.3** — proved the OOB oracle reaches `verified` only on a real collaborator
  callback (`test_oob_oracle.py`, real fixture + real in-process collaborator).
- **P0.4** — `harness/score_provenance.py` (fresh/historical/invalid labels).
- **P0.5** — `harness/evidence_audit.py` (verified/rejected/unverifiable; a missing
  proof is `unverifiable`, never conflated with a demonstrated mismatch).
- **P0.6** — `harness/coverage_summary.py` (executed vs inferred vs
  not-a-clean-negative, every % names its denominator, `None` not fabricated
  on 0/0).
- **P0.7** — `harness/eval_health.py` (4 independent process/artifact/target/phase
  flags; target health is never inferred from the exit code).
- **P0.8** — `harness/test_credential_isolation.py` closes the one real gap
  (combined cookie+Authorization cross-origin strip, mid-run cancel) on top of
  T03's already-thorough `test_run_context.py` coverage.
- **P0.9** — `coordinator.is_fallback_reason()` + `AnalysisResponse.coordinator_fallback`;
  the WARN+metric already existed in `_record_fail_open`, the gap was the
  structured per-exchange flag.
- **P0.10** — `testing/nightly_precision.py` + a CPU-only `nightly-precision` CI
  job: a tiny, fully-stubbed 4-exchange corpus proves the SCORING PLUMBING
  (not model accuracy — that's still `scored`'s GPU job) stays wired, writes
  `SCORECARD.md` (now gitignored, regenerable), independently gated so a missing
  file fails the job regardless of the script's own exit code.

**P1/P2 items done:**
- **P1.1 + P2.2** — `harness/llm_provider.py` (+`openai_provider.py`/
  `anthropic_provider.py`): coordinator/critique can opt into a remote model via
  config `provider:` key, but ONLY with the matching `$OPENAI_API_KEY`/
  `$ANTHROPIC_API_KEY` env var also set — missing either raises, never a silent
  Ollama fallback. Redacted `provider_diagnostics()` wired into `GET /settings`.
  `transport_inventory.py` updated (new httpx-client modules registered).
- **P1.6** — `scored-status` CI job reports fresh/historical/not_run/failed for
  the scored tier (a skipped GPU job can no longer read as "passed").
- **P1.7** — `eval_repeat.EvalReport.compare()`: a cross-corpus (or unlabeled)
  delta is never presented as a model-only effect.
- **P1.8** — `issues.apply_merge_overrides` + `store.py`'s `issue_merges` table +
  `POST/DELETE/GET /issues/{host}/merge[s]`: operator-declared root-cause merges,
  reversible by construction (removing the override restores the automatic split).
- **P1.9** — Python-side Finding JSON round-trip proven lossless
  (`test_serialization_roundtrip.py`); Java `AnalysisModels.Finding` POJO was
  missing all 7 oracle/case/proof fields (silently dropped by Gson) — added,
  marked UNBUILT/self-review (no JDK here); a `burp-extension-build` CI job is
  written but also unverified (no committed Gradle wrapper).
- **P2.1** — `harness/mcp_adapter.py`: read-only MCP-resource-shaped adapter
  (results/coverage/provenance), no execution method exists on the class at all,
  bearer-token tenant isolation, pagination.
- **P2.4** — `harness/sarif_adapter.py`: lossless SARIF 2.1.0 export/import;
  an imported finding is UNCONDITIONALLY advisory (candidate) even when the
  source SARIF claims a confirmed exploit.
- **P2.5** — `harness/pattern_memory.py`: append-only, host-agnostic
  (method+normalized-path+param-NAMES-only, never a value/host/evidence)
  cross-host signature memory; wired additively into `analyze()`'s dispatch,
  default off.
- **P2.6** — `IterativeAgent._execute` skips (and logs) a request byte-identical
  to one already sent this active-probe session.
- **P1.12 — verified ALREADY DONE, no action.** `harness/agents/
  http_request_smuggling_agent.py` and `web_cache_poisoning_agent.py` both
  already exist, load via the plugin loader, and appear in every orchestrator's
  36-agent roster — the source list's premise was stale.
- **P1.10 — verified DONE** (`test_fix_verifier.py` still green, no changes needed).

**Not done this session (deliberately, by size/priority):** P1.2 (RAG knowledge
retrieval), P1.3 (multi-role active cross-identity probe), P1.4 (MITRE attack-tree
+ value-ordered search over the task graph), P1.5 (external benchmark corpora +
LLM-as-judge), P1.11 (SAST/code-property-graph corroboration), P1.14 (per-agent
tactical guides), P2.3 (pairs with P1.2, same reason), P2.8 (web3 agents — plan
says "only after P0/P1", low priority), P3.1 (source-code ingestion — plan's own
"large; last"). None of these were attempted or partially started; each remains
exactly as scoped in `reviews/2026-09-19/IMPLEMENTATION_PLAN.md` §5-§7.

**Honest frontier for the next session:** the highest-leverage remaining items are
probably P1.3 (multi-role active probe — directly extends the already-built
`missing_auth_probe.py`/`role_crawl.py`) and P1.4 (attack-tree — extends
`task_graph.py`, no new external dependency). P1.2/P1.5 are both meaningfully
larger (retrieval corpus + versioning; external benchmark integration) and
deserve their own planning pass rather than being squeezed into a continuation.
No live target/model run was performed this session — every new capability is
hermetically tested only; live efficacy (does pattern_memory/the oracle/etc.
actually move recall on VulnCorp) remains unmeasured, as it was before.

## 2026-09-19 — precision oracle framework + off-scope host-lock (2 commits, suite green)

Implemented the P0-precision core and the cheap safety win from the prioritised
coding backlog. Two focused commits on `reconciliation-backlog`; full suite green
after both (`python -m unittest discover -t . -s harness -p "test_*.py"` -> **2067
OK**, ~370s). Nothing pushed. Pre-existing uncommitted Ollama edits + this file
were NOT swept into either commit.

- **Precision oracle framework (items #1/#2/#10).** New `oracle_framework.py`
  (Oracle / OracleRegistry / ProofCapsule), `negative_controls.py` (per-class
  benign-variant builders + the self-controlling OOB set), `fix_verifier.py`
  (CLOSED/PARTIAL/NOT_FIXED/REGRESSED/INCONCLUSIVE). An oracle promotes a finding
  from "a leg fired once" to `verification_state="verified"` only on **N-of-N
  reproduction + a clean paired negative control**; self-controlling OOB legs
  (unique-token callback) reach verified on reproduction alone. `Finding` gains
  `oracle_verified`/`verification_state`/`oracle_capsule_id`/`oracle_reason`
  (all in `AGENT_AUTHORITY_FIELDS` -- agents can't assert them); `store.py` adds
  additive columns (legacy rows stay "candidate"); `report_generator.py` shows a
  VERIFIED/CANDIDATE badge. fix-verifier's CLOSED requires a clean **executed**
  negative -- skip/error/blocked -> INCONCLUSIVE (Q03/Q11). 43 hermetic tests.
- **Off-scope host-lock audit (item #12 / Q06).** `test_offscope_host_lock.py`
  enumerates every ACTIVE validator against an off-scope exchange with httpx AND
  raw sockets patched to raise a non-swallowable BaseException on any send. It
  **found 8 real gaps**: `sqlmap` (no scope check at all -- ran straight at
  exchange.url), `crypto` + `websocket` (raw sockets, bypassed all httpx guards),
  and `recon`/`http_request_smuggling`/`web_cache_poisoning`/`csp`/`header_injection`
  (plain-httpx fallback with follow_redirects, unscoped when no run_context). All
  fixed via the shared `scope_lock.py` helper. The SafetyGate gained an
  OUT_OF_SCOPE tier (checked first) so every gated send is centrally scope-locked;
  `server.allowed_hosts` is folded into the gate at the registry seed + RunContext.

**NOT live-verified.** The oracle is a hermetic framework: it is NOT yet wired into
the live `investigate_engagement`/`analyze()` confirmation path (that seam is the
next step, and must land with an end-to-end smoke test + negative control per the
#0 discipline, gated behind an `oracle.enabled` config flag default-off). No live
VulnCorp run was performed. verification_state therefore defaults to "candidate"
for every real finding until the live wiring + a measured run exist.

**Large remaining backlog (three overlapping reviewer lists, NOT done this session):**
original items #3/#4/#5/#6/#7/#8/#9/#11; evaluation-integrity Q01-Q05/Q07-Q10/Q12-Q15
(run-manifest-bound scoring, proof-audit contract, auditable coverage denominators,
completion-vs-health, provider egress, MCP, RAG citations, SARIF import); and the
P-list (P0.1 coordinator fail-open metric, P0.2 CI precision tier, P0.3 basis UI
filter, P1.1 provider abstraction = #4, P1.2 smuggling/cache agents, P1.3 multi-role
active probe, P2.1 cross-host pattern memory, P2.2 MCP = #11, P2.3 active-probe
idempotency guard). These are separate M-sized tracks; several need a live target
or a JDK/GPU runner. Multi-provider (#4/P1.1) and MCP (#11/P2.2) are the highest-value
self-contained follow-ups.

## 2026-09-19 — comparative review and quality backlog (no implementation)

Report: [PRIORITISED_REVIEW.md](reviews/2026-09-19/PRIORITISED_REVIEW.md).
Reviewed local HEAD `a2e6831` plus explicitly identified concurrent WIP; product
edits were left untouched. Compared the supplied 12 priorities with local source,
the two named public repositories, and 20 additional peer/adjacent projects using
primary documentation (not runtime efficacy verification). Backlog Q01–Q15 covers
evaluation integrity, reporting, safety, and interoperability; no exploit-expansion
implementation plan. Existing evaluation_integrity tooling should be reused.
Verified **18 recall-scorer + 42 evaluation-integrity tests OK**. Inspected scored
CI uses historical cache scoring without revision-bound efficacy provenance.
The inspected integrated_full result contains 37 analyses and null investigate;
it remains a partial artifact, not a new recall result or process-health finding.
No target/model execution, full suite, configuration changes, or commits.

## 2026-09-18 — test-suite rationalisation: real-pipeline gate + dead-test CI holes

Acted on a source audit of the ~2,000-test suite (2,052 `def test_` across 141
files — a source count, not executed). Verified the audit's claims against the
code, then closed the two highest-value gaps. Three focused commits on
`reconciliation-backlog` (`c4c3d49`, `c233869`, `0503e1a`), suite green at each.

- **Real-pipeline gate (`c4c3d49`).** Every prior "real HTTP" slice SUPPLIES
  discovery (test_smoke_investigate patches `build_engagement`; the auth slice
  seeds the object endpoint), so none can catch discovery dropping a
  route/method/body. New `testing_fixtures/discovery_pipeline.py` ADVERTISES its
  surface via `/openapi.json`; new `test_pipeline_gate.py` runs REAL
  api_surface_discovery → role_crawl → worklist → the shape-driven cross-identity
  leg → a CONFIRMED IDOR, stubbing ONLY the model boundary (a silent Ollama; the
  confirmation is the deterministic replay, not an LLM guess — this also stops
  `review_captured_exchanges` from firing the real model at every discovered 2xx,
  the minutes→~11s difference). Carries 3 defect-injection proofs (starve the
  budget, force GET-only crawl, suppress the leg) that each turn the gate red.
  `python -m unittest harness.test_pipeline_gate` → 6 OK, ~11s.
- **Dead pytest tests + tripwire (`c233869`).** `test_plugin_system.py`,
  `test_execution_protocol.py`, `test_hardening.py` use module-level
  pytest functions/fixtures → `unittest discover` collects ZERO from them, so
  ~48 tests (incl. security test `test_prompt_injection_is_data`) ran in NO tier.
  One (`test_load_builtin_agent_class`) was actually FAILING on a stale pre-W-18
  `agents.sqli_agent` path — hidden because nothing ran it. Fixed the path;
  added `test_no_orphan_test_files.py` (tripwire: every `test_*.py` is
  unittest-collectable or in a pytest-native allowlist CI runs via pytest).
- **CI ran from the wrong cwd (`0503e1a`).** Steps used `working-directory:
  harness` + `python -m unittest`/`coverage_manifest.py`, but since W-18 imports
  are `harness.*` and need the repo root — the exact nightly command errors on
  141/146 modules locally, and requirements.lock does not install the package, so
  the unittest steps were **not actually running the tests**. Moved every harness
  step to the repo root (`harness.<mod>`, `discover -t . -s harness`,
  `-m harness.coverage_manifest`); testing/ steps untouched. Wired the gate (fast
  tier) and the pytest-native trio (both tiers) in.

Not done / owed: the ~2,000 tests were NOT pruned (that was the deferred half of
the plan — do the pruning by demonstrated redundancy only after this gate is
trusted). Nothing pushed. Whether the live CI runner somehow installed the
package (masking the cwd bug) is unconfirmed — the fix is correct either way.

## 2026-09-18 — integration and comparable rerun in flight

On `reconciliation-backlog`, `a2bbf87` integrates the sharp-dijkstra
discovery/role-crawl changes with separate late-phase probe reserves,
read-only OPTIONS method mining, multiple operations per path, and a gated
transport for inferred writes. `eb70210` backfills confirming validator
evidence on empty shape-precondition findings. The sharp worktree remains
untouched; its ffuf fix was already on this branch. The isolated runtime
checkout is `.worktrees/integration-measure` at `eb70210`, excluding the
pre-existing uncommitted Ollama JSON-repair changes in the main checkout.
Focused discovery/crawl/confirmation tests: 137 passed. Final full suite:
`2006 tests`, `OK (skipped=2)` using `.review-deps` plus an isolated compatible
`typing_extensions` in `.test-deps`; log:
`harness/run-output/integration_full_suite_final_20260918.log`.

The stateless VulnCorp target was restarted once on :5002. A fresh combined
37-capture PASS1 plus full graph PASS2 run started 2026-09-18 17:35 local
using `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`. It writes
unique `integrated_full` state/cache/results/log artifacts under `maxrun`.
The driver preserves the historical scorer and adds a stricter proof-linked
audit against persisted case/validator records. **No recall result yet.**
After completion: inspect both scores and errors, update this section, then
fast-forward local `main` from `reconciliation-backlog` as requested. Do not
commit the untracked runtime artifacts or the unrelated Ollama edits.

## 2026-09-18 — branch/worktree audit (read-only)

`claude/sharp-dijkstra-9a8830` and `main` both point to `3603b1f`.
`reconciliation-backlog` is its descendant, 12 commits ahead at `0859ca2`.
The sharp-dijkstra worktree has uncommitted discovery/method-propagation,
request-synthesis, and evidence-backfill changes plus tests; its staged ffuf
decode change is already present on `reconciliation-backlog`. Its saved
`postfix_smoke` ran only 3 curated analyses and a small graph budget
(`max_nodes=2`, 600 discovery probes), scoring 3 intended-leg earned items;
it is not comparable to the Step 5b full graph run. No saved `postfix_full`
result or commit of the sharp-dijkstra worktree changes was found. The
evidence-backfill file changed after the smoke artifact was written, so that
artifact does not verify the entire current worktree. No merges or tests were
performed during this audit.

## 2026-09-18 — source/artifact audit of Step 5b (no live rerun)

At HEAD `0859ca2`, inspected `step5b_job_result.json`, `recall_final_step5.json`,
the saved target/harness logs, the 37 curated capture metadata, and the relevant
discovery, graph, validator, coverage, and scorer source. Did not read the target's
`app.py` or any `*ANSWER_KEY*` file. No product code/config changed. The scorer's
18 unit tests passed; four other focused test modules could not import because
the bundled Python lacks `httpx` in this session. No full suite or target run.

Verified: the clean job was `2dc2a3f1ff08`, ran 4.95 h, and scored 5/13 earned,
6/13 confirmed, 7 missed. The score artifact's `job_id` is erroneously hardcoded
to the earlier `b4b5d11ec068` in `score_step5b.py`. The matrix reports
336/1,846 applicable coverage cells attempted; 1,510 were skipped. Those 336
include statuses inferred from findings, not independently audited requests.
`degraded=false` and zero
safety blocks do not establish coverage or target health. The target log contains
78,374 GET 500 responses, mostly to guessed paths; their specific cause was not
determined. The 24,735 run-context request count omits traffic visible in the
target log (84,894 HTTP requests), so it is not an all-traffic count.

Newly verified root cause: `SurfaceDiscovery.discover()` puts bare/id wordlists
and nested wordlists before response, subresource, query, and method mining.
Defaults yield up to 4,134 bare/id candidates plus 22,260 nested candidates
against 6,000 Python probes per role; the log shows all four role sweeps used
exactly 6,000 probes. Later phases therefore have no budget in this configuration
unless an implausibly large number of candidates are skipped as already seen.
`role_crawl.crawl_roles()` then discards discovered route methods and probes only
GET. Thus the result retained empty GET templates for `/api/login`,
`/api/register`, `/api/tickets/import`, `/api/account/profile`, and
`/api/tickets/search`; no parameter `q` was captured for search. The 37 curated
baseline exchanges do contain POST login/register/import, PUT profile, GET
search with `q`, and GET comments with concrete IDs. The graph path did invoke
`analyze()` on 14 discovery and 92 feature captures, but those captures lacked
the decisive request shapes. PASS1 on the curated exchanges was still omitted.

The last score's missed GT01/02/03/06/09/10/13 map to missing input/method/route
preconditions, not a demonstrated model regression. The s19_full combined pass
reported GT01/02/03 confirmed with UNKNOWN leg provenance (not earned),
GT06 and GT09/10 detected-unconfirmed, and GT13 missed. Re-running curated
PASS1 alone is therefore not a verified fix for all seven, nor proof that the
intended SQLi/XXE legs work on those three cases.
Coverage mislabels unknown operations as `not_applicable`: e.g. GET
`/api/tickets/import` makes XXE N/A, GET `/api/account/profile` makes mass
assignment N/A, and parameterless GET `/api/tickets/search` makes SQLi N/A.
The 13-item benchmark is a limited lower bound, not full-app recall; the scorer
trusts `confirmed` plus a leg label without requiring a persisted case-bound proof.

Highest-priority next work: budget/reserve every discovery phase and preserve
methods/query/body templates; ingest real captured traffic or an available spec
before claiming a method's checks N/A; run positive and patched negative controls
for all seven misses; then rerun the exact combined 37-exchange + graph methodology
with a fresh cache and proof-linked scoring. Measure request counts by phase,
per-check attempted/skipped/unknown, distinct confirmed cases, and false positives.

## 2026-09-17 — ◄► CLEAN STEP 5 RE-RUN (job 2dc2a3f1ff08) — 5/13 EARNED ◄►

Re-ran the Step 5 measurement after fixing the bug the first run (job
b4b5d11ec068, below) surfaced. Two fixes landed from peer sessions and were
cherry-picked onto `reconciliation-backlog`:

- **`0acf140` fix(store): make identities-table migration idempotent under
  concurrency** — the pre-existing sqlite race flagged during Step 1-4 work
  (`_connect()`'s check-then-act ALTER TABLE let concurrent callers racing
  inside `analyze()`'s `asyncio.gather()` both see a column missing and
  both ALTER; the loser raised `duplicate column name`). Now swallows only
  that specific outcome.
- **`e65d848` fix(discovery): decode ffuf's base64-encoded FUZZ input before
  using it as a path** — THE root cause of the first Step 5 run's 9/13
  misses. ffuf's `-json` output always base64-encodes each wordlist
  keyword's raw input bytes (so binary/non-UTF8 entries survive JSON
  safely); `ffuf_runner.parse_json_lines()` read it raw, so every route
  ffuf found through the container fast-path was recorded under its
  base64-encoded form (`/LmVudg==` instead of `/.env`,
  `/YXBpL2FjY291bnQvcHJvZmlsZQ==` instead of `/api/account/profile`) and
  fed back into `role_crawl`'s active-discovery queue as a NEW candidate —
  crowding out the real path, which was then never probed at all.

Same methodology as the first run (fresh state/cache, fresh VulnCorp
instance, `active_enabled` armed at runtime via `/settings`, local
qwen3:8b, `max_nodes=60 step_budget=16 max_chain_rounds=3`,
`feature_crawl`+`coverage_drive_legs` on). **Confirmed live: the real GT
paths (`/api/login`, `/api/register`, `/api/account/profile`,
`/api/admin/debug`, `/.env`, ...) are now discovered and probed directly —
zero base64-mangled paths anywhere in the run.** Ran 4.95h, zero
`[safety_gate] BLOCKED` lines, zero tracebacks, `degraded=false`.

**Result: 5/13 earned, 6/13 confirmed, 0/13 detected-unconfirmed, 7/13
missed (1 confirmed by luck).** Up from the buggy run's 4/13 earned — a
real, attributable gain. New earned item: **GT11-bfla-admin-users**
(`/api/admin/users`, `cross_identity`) — reachable and cross-identity-
confirmed now that the real path was discovered directly. GT12
(`/api/admin/debug` disclosure) moved from missed to confirmed-but-lucky
(via `verbose_error_validator`, not the intended `secret_disclosure` leg).

**Why 7/13 are still missed — two distinct, well-understood causes (not
regressions), flagged as a follow-up (`task_0a7f81bc`):**
1. **GT01/GT02 (sqli), GT03 (xxe)** — SQLi/XXE detection in this harness
   comes from the dedicated LLM specialist agents that run during the
   captured-exchange `analyze()` pass ("PASS 1" in the historical
   `run_maxcov_recall.py` driver), which this run did not execute — only
   `investigate_engagement()` ("PASS 2") ran. PASS 2's own worklist only
   derives idor/auth hypotheses, and `shape_precondition_legs` has no
   generic "any parameter could be sqli" branch. A methodology gap, not a
   bug — running PASS 1 too (over the 37 exchanges in
   `testing/vulncorp-helpdesk/maxrun/captured_exchanges.json`) would very
   plausibly close it.
2. **GT09/GT10 (mass-assignment, `/api/account/profile` + `/api/register`)**
   — discovered, but their captured template ended up with an EMPTY body
   (GET, `body=""`): `feature_crawl` never actually submitted a real
   POST/JSON body to them, so Step 3's `_has_settable_body` gate (correct
   and unit-tested) never had a precondition to fire on. Likely cause:
   these forms are JS `fetch()`/XHR-submitted, not classic HTML `<form>`
   elements `feature_workflow.py`'s `_FormParser` can see.
3. **GT06 (nested idor comments) and GT13 (ssrf /api/integrations)** were
   not discovered at all this run either.

Artifacts (all git-ignored/untracked, none committed):
`testing/vulncorp-helpdesk/harness_server_step5b.log`,
`testing/vulncorp-helpdesk/app_step5b_run.log`,
`testing/vulncorp-helpdesk/maxrun/step5b_job_result.json`,
`recall_final_step5.json` (overwrites the prior run's — see
`score_step5b.py`). Both processes stopped cleanly; state/cache DBs backed
up as `harness/*.db.bak-pre-step5b` before the fresh run.

## 2026-09-17 — ◄► LIVE STEP 5 MEASUREMENT RUN (job b4b5d11ec068) — DONE ◄►

Ran Step 5 of `reviews/2026-09-17/GEMMA_RUN_COVERAGE_PLAN.md` against a fresh
VulnCorp instance: state/cache DBs backed up and rebuilt fresh
(`harness/*.db.bak-pre-step5`), one clean `python app.py` (killed two stale
leftover instances from the prior gemma run first), harness server started
fresh, `validators.active_enabled` armed at RUNTIME via `POST /settings`
(not at config load) — the exact scenario Step 1 fixed. Model: local
**qwen3:8b** (config.local.yaml's cloud-model block commented out for this
run), matching the s19_full baseline's model so the comparison isolates
Steps 1–4 as the only changed variable. 6 identities logged in and
registered (alice/bob/carol/dave/admin/eve) via `/api/login` +
`/identities/session-headers`. `POST /engagement/127.0.0.1/investigate`
(max_nodes=60, step_budget=16, max_chain_rounds=3, feature_crawl +
coverage_drive_legs on, budget 400). Ran **5.47h**, finished clean (no
error, degraded=false). Scored with the SAME ground truth the baseline
used (`testing/vulncorp-helpdesk/maxrun/vulncorp_ground_truth.py`, still
present on disk) via a new `testing/vulncorp-helpdesk/maxrun/score_step5.py`.
**NOTE: this run covered PASS2 (investigate_engagement) only — the
baseline's PASS1 (analyze() over 37 curated captured exchanges) was not
re-run, so this is not a byte-for-byte repeat of the s19_full methodology.**

**Result: 4/13 earned, 4/13 confirmed, 0/13 detected-unconfirmed, 9/13
missed** — identical 4 earned items as baseline (GT04 idor ticket, GT05
idor report, GT07 path traversal uploads, GT08 jwt forge), same legs
(cross_identity/path_traversal/jwt_forge). **Earned recall did not regress
(success criterion met) but did not improve either.**

**Step 1 success criterion directly confirmed live:** zero
`[safety_gate] ... BLOCKED` log lines in the entire 5.47h run (grep count
0) — no active leg was blocked by a stale/safe-default gate, despite
`active_enabled` being armed at runtime exactly like the gemma run that
originally exposed the bug. `worklist_summary.skipped_by_reason` shows
only `unreachable`(22)/`missing_template`(3) — no `budget_exhausted`, no
`policy_blocked`; the 60-node budget was never the binding constraint
(only 5 nodes were ever "eligible").

**Why Steps 2–4 didn't move the needle this run — a NEW bug, not a Steps
1–4 regression:** the real paths for 9 of 13 GT items (`/api/login`,
`/api/register`, `/api/tickets/search`, `/api/tickets/import`,
`/api/account/profile`, `/api/admin/users`, `/api/admin/debug`, plus
`/api/tickets/{id}/comments` and `/api/integrations` never being
discovered at all) were **never probed in their real form** — active
discovery (`role_crawl` → `api_surface_discovery.SurfaceDiscovery`)
started feeding BASE64-ENCODED versions of its own already-discovered
paths back into the queue as new candidates (`GET /YXBpL2FjY291bnQvcHJvZmlsZQ==`
etc. — every one decodes cleanly to a real path already found). This
crowded out the real paths and is very likely the dominant reason 9/13
show MISSED instead of at least detected. Root cause narrowed to
`js_endpoint_extractor.py`'s `_ABS_URL` regex (unlike `_QUOTED_PATH`, its
path-capture group allows `=`) but the exact triggering response body was
not pinned down live — **flagged as a follow-up task (`task_31eb6593`),
not fixed this session.** SSRF/nested-IDOR/mass-assignment's Step-3 wiring
is independently unit-tested and correct in isolation
(test_orchestrator_precondition.py, test_worklist_investigator.py); none
of the three got a chance to fire live because their precondition (a real
discovered node with a template) never materialized in this run.

**Also observed, not yet diagnosed:** a huge share of live request volume
(992 `path_traversal` + 248 `open_redirect` + 147 `command_injection` +
126 `ssti` POSTs, all against the single `/web/login?next=...` redirect
param) — `coverage_drive_legs` firing every applicable check across many
payload-encoding variants on one shape-rich endpoint. Plausibly consumed a
large share of the run's wall time without adding coverage elsewhere; not
investigated further this session.

**Honest next steps:** (1) fix the base64-discovery bug (task_31eb6593) —
highest-leverage single fix, since it blocks 9 of 13 GT paths from ever
being reached; (2) re-run Step 5 after that fix; (3) optionally add PASS1
(`analyze()` over the 37 captured exchanges in
`testing/vulncorp-helpdesk/maxrun/captured_exchanges.json`) for a fully
apples-to-apples methodology match with s19_full; (4) only then the model
A/B. Artifacts: `testing/vulncorp-helpdesk/harness_server_step5.log`,
`testing/vulncorp-helpdesk/app_step5_run.log`,
`testing/vulncorp-helpdesk/maxrun/step5_job_result.json`,
`recall_final_step5.json`, `score_step5.py` (none committed — this whole
directory is git-ignored/untracked, matching prior sessions). Both
processes stopped cleanly at session end; `harness/config.local.yaml`
left with `active_enabled: false` (armed only at runtime per run) and the
cloud-model block still commented out.

Separately, `confirmation_gate.active_confirmation_is_unproven` (Step 4)
has a known, not-yet-closed gap raised by a concurrent review this same
day (`reviews/2026-09-17/MEASUREMENT_REVIEW.md`, finding 3): it accepts
`confirmed_by_leg` as sufficient proof on its own, but that field is a
NAME, not an authenticated reference to a persisted proof record the way
`proof_id` is for the `_validate_findings`/coverage-driven paths. The
`_apply`-based graph-loop confirmations (the majority of shape-driven
legs) have no persisted `proof_id` at all by design (no case/proof
persistence step), so a strict proof_id-only requirement isn't currently
implementable there. Not tightened this session — noted for follow-up.

## 2026-09-17 — offline detection-measurement review

Review: [MEASUREMENT_REVIEW.md](reviews/2026-09-17/MEASUREMENT_REVIEW.md), at
HEAD `fceb4e59a52d3adf3b05c5894246078da9c98847` with existing Ollama edits untouched.
Parsed historical Gemma aggregates: 308 attempted / 11,438 total coverage cells,
6,990 not applicable, 4,140 skipped; 13-item score has 4 earned-provenance,
3 unknown-provenance confirmations, 5 unconfirmed detections, 1 missed.
These are artifact-reported statuses, not fresh execution verification.
Executed **18 scorer tests OK** plus a synthetic diagnostic showing the scorer
can award earned credit without a proof ID. Reviewed smoke-test mocking boundaries.
No product/config changes, full suite, active target tests, or model calls.
Latest-fix live efficacy and whole-application recall remain unverified.

## 2026-09-17 — GEMMA_RUN_COVERAGE_PLAN.md Steps 1–4 implemented (branch `reconciliation-backlog`)

Worked [`reviews/2026-09-17/GEMMA_RUN_COVERAGE_PLAN.md`](reviews/2026-09-17/GEMMA_RUN_COVERAGE_PLAN.md)
top-to-bottom through Step 4. Four focused commits, full suite green at each
(1951 → 1953 → 1965 → 1982 tests, exit 0, ~350s each). **Step 5 (one live
VulnCorp run to measure movement) and the model A/B are explicitly NOT
done** — both require starting a live target/server for hours and are
gated on an operator decision, not attempted this session.

- **Step 1 (`eef01df`) — safety-gate invocation scoping.** Root cause: the
  gemma_cloud_full run's log showed SQLMap/CSRF POST probes BLOCKED
  ("active testing... which is off") despite the run having armed
  `active_enabled` via a runtime `/settings` toggle. `get_default_gate()`
  was a process-wide singleton that cached whichever config it saw first;
  `safety_gate.py` now resolves an AMBIENT, per-invocation gate (a
  ContextVar, installed by `RunContext.__aenter__`/`__aexit__` for the
  `async with` block's lifetime — NOT at bare `create()`/`aclose()`, which
  a first attempt showed leaks across the ~70 tests that construct a
  RunContext directly and never close it). `IterativeAgent.gate` is now a
  property (was cached at `__init__`, long before any run's gate exists).
  `server.py` overlays the live `ValidatorRegistry.active_enabled` toggle
  onto the three RunContext-building call sites instead of reading the
  frozen startup config.
- **Step 2 (`a2d0b9c`) — honest coverage ranking/reporting.** `engagement.py`
  penalizes malformed/encoded discovery artifacts and repeat-5xx dead
  endpoints (0.05x multiplicative) and rewards input-bearing routes (+0.2)
  in `fused_score()`. `worklist_investigator.investigate_worklist` gained
  `summary_out` (eligible/investigated/skipped-by-reason:
  budget_exhausted/unreachable/missing_template/policy_blocked), wired into
  `investigate_engagement`'s result as `worklist_summary`.
- **Step 3 (`6f8493a`) — SSRF/nested-IDOR/mass-assignment reach.** The
  graph-driven `shape_precondition_legs` had NO mass-assignment branch at
  all (only the captured-exchange path did) — added. Dead/malformed nodes
  now never spend the shared `max_precondition_legs` budget. New
  `_parent_template_object_id` borrows a nested route's (e.g.
  `/api/tickets/{id}/comments`) PARENT object-scoped route's real captured
  object id when the child has none, so cross-identity replay tests an
  object that actually exists instead of a fabricated id.
- **Step 4 (`ffa805b`) — structured confirmation provenance.** `Finding`
  gains `confirmed_by_leg`, stamped at the same moment as `proof_id` by all
  three production confirmation-stamping paths (`_validate_findings`,
  `coverage_confirmation_finding`, and `orchestrator_chain._apply` — the
  dominant graph-loop path, previously evidence-text-only).
  `confirmation_gate.active_confirmation_is_unproven` downgrades an
  active-class `confirmed=True` claim with no leg proof, wired into
  `engagement.add_finding` as the single chokepoint. `recall_benchmark.
  RecallScore.earned` is the new honest headline (intended-leg-confirmed,
  excluding no-leg-tier observation classes); `report_generator.py` splits
  "Confirmed Exploits" from "Confirmed Observations".

**Honest frontier:** none of this has been measured against a live target
yet — Step 5 (fresh cache, one clean VulnCorp instance, the max-coverage
driver, compare against the 4/13-earned baseline established 2026-09-11)
is the next session's first job, followed by the model A/B only once that
baseline is trustworthy.

## 2026-09-16 — isolated defensive fixes prepared; live checkout unchanged

Implemented the three follow-up findings in `.worktrees/review-safety-fixes/`
(isolated source copy, not a registered Git worktree). Patch:
`reviews/2026-09-16/round2/safety-fixes.patch`; `git apply --check` passed.
Do not apply until the current helpdesk pass finishes. Main product files,
configuration, caches, dependencies and running services were left unchanged.
64 selected offline regression/passive smoke tests passed in the isolated copy;
log: `reviews/2026-09-16/round2/fix-tests.log`. Full suite/live runs not executed.
Uncommitted main-checkout Ollama changes were not copied or overwritten.

## 2026-09-16 — follow-up review of implemented R01–R03 fixes

Report: [`reviews/2026-09-16/round2/REVIEW.md`](reviews/2026-09-16/round2/REVIEW.md).
Reviewed HEAD `4db2fef`, plus uncommitted Ollama client/parser tests. Three residual
findings: chain Markdown redaction (P1), model-supplied case origin metadata (P2),
and registry/gate disagreement on quoted false (P2). Synthetic offline checks
confirm the main direct-confirmation and individual-redaction fixes.
Selected suite: **209 tests, 206 passed, 3 dependency-import errors** (AnyIO /
typing_extensions); not a green-suite claim. No target/model execution or product
changes. Earlier findings outside R01–R03 were not re-certified in this round.

## 2026-09-16 — defensive/platform and product review (no product changes)

Review: [`reviews/2026-09-16/PROJECT_REVIEW.md`](reviews/2026-09-16/PROJECT_REVIEW.md),
23 sections / 15 findings, with commands and limitations in `EXECUTION_LOG.md` beside it.
Baseline **`02a3326cad43c886c6341f197ee3b9c09a4a4848`**, branch initially
`reconciliation-backlog`. Another process refactored orchestration and advanced HEAD
to `99c5712` during review; **that newer revision is not assessed by this report**.
The final tests/diagnostics use the archived original commit, not a mixed working tree.

**Verified this review:** 213 selected offline/passive tests, **OK**, exit 0, 3.164s;
includes the four passive detection/persistence smoke tests with model stubs/negative
controls. Synthetic diagnostics reproduced quoted-boolean configuration disagreement,
model-writeable confirmation/proof fields, Markdown secret retention, artifact-free
legacy confirmation, and per-run cache-key separation. Report distinguishes executed
checks from source findings, historical claims, and product judgments.
**Not verified:** full suite, live efficacy/model, active targets, browser/container,
Java/Burp runtime, dependency audit, or user-study outcomes. No product code or safety
defaults changed; no server/cache reset, no commit/push. Existing work is preserved.

---

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**
Older session narratives are in git history / `archive/`; this file is deliberately short
(review weakness #18: it had become the archived chain again).

---

## ►► PARALLEL TRACK — Opus, branch `astra-wstg-coverage-slice` (WSTG requirement coverage) ◄◄

Branched off `astra-integration`. Adds a **requirement-coverage manifest** kept
deliberately SEPARATE from the per-run `CoverageMatrix`, plus two deterministic
vertical slices. **Not merged.** Commits: `294162c` (scaffold), `1052149` (review
fixes), + a catalog-expansion commit.

- **New modules:** `harness/coverage_manifest.py` (security-requirement ⇄
  regression-test ledger: WSTG/OWASP refs, applicability+rationale, per-aspect
  status, run-bound evidence, `--check` gate) and `harness/coverage_evidence_case.py`
  (`EvidenceCase` records pass/fail/skip THROUGH the runner into a git-ignored,
  run-id-bound `harness/.coverage_runs/<run_id>/`). `coverage_model.Check` gained
  `external_refs` + `is_wstg()`/`reference_label()`.
- **Two slices** (local fixture + REAL validator + evidence, over loopback HTTP):
  mass assignment (`AV-MASSASSIGN-01`, `SequenceValidator`) and open redirect
  (`WSTG-INPV-17`, `OpenRedirectValidator`). Each has 3 labelled aspects:
  patched-fixture invariant, harness confirmation on vulnerable, harness controlled
  negative on patched. Report: 38 requirements, 2 `covered_partial` (6 passing
  aspects), 3 `gap_manual`, 33 `gap_unimplemented` — all gaps flagged.
- **The #0 trap this closes:** a committed passing artifact previously satisfied the
  gate WITHOUT the test running. Now evidence is written fresh per run, bound to the
  commit/run id, and the gate FAILS with no fresh evidence; a failed/skipped run
  records that. Identity/schema/duplicate are validated; every declared automated
  aspect is gated INDEPENDENTLY.
- **WSTG-CONF-09 correction:** it is "Test File Permission" (manual, WSTG v4.2 ref),
  NOT mass assignment — the reviewer's catch. Mass assignment now carries the
  internal id `AV-MASSASSIGN-01` with OWASP-API/Academy `external_refs`.
- **CI (`.github/workflows/ci.yml`):** PR runs the SMOKE SUBSET only (full suite →
  new nightly job — the real per-PR saving); coverage report + evidence uploaded
  with `always()`; the `--check` gate enforces fresh passing evidence.
- **Verify:** `cd harness && python -m unittest test_coverage_manifest
  test_mass_assignment_slice test_open_redirect_slice` then `python
  coverage_manifest.py --check`. Full stdlib discovery: **1,782 OK**, exit 0
  (hermetic; no model/live run). All 8 reviewer findings addressed with regressions.
- **Owed:** merge decision; broaden the catalog with more slices.

---

## ►► LIVE MAX-COVERAGE RUN — s19_full, 2026-09-11 (branch `astra-integration`) ◄◄

The "one measurement still owed" fresh live VulnCorp run was executed. Artifacts in
`testing/vulncorp-helpdesk/maxrun/*s19_full*` (recall_report_s19_full.{md,json},
report_s19_full.md, maxcov_results_s19_full.json, maxcov_s19_full.log). Driver:
`run_maxcov_recall.py` (config built IN MEMORY over config.yaml — on-disk config untouched;
fresh s19_full state+cache DBs). Harness interpreter: python 3.14.7. Target: one clean
fresh-seed instance, debug off (killed a 3-instance hazard-#5 state first). Wall time
**9.75 h** (PASS1 37/37 exchanges ~1h40m; PASS2 investigate_engagement ~8.1h). Exit 0,
no traceback.

**Path-matched recall vs the 13 endpoint-known GT items: 9/13 "confirmed", 3/13
detected-unconfirmed, 1/13 missed — but only 4/13 are leg-EARNED.**
- **Earned (deterministic leg, trustworthy):** GT04 idor tickets/{id} + GT05 idor
  reports/{id} (cross_identity), GT07 path_traversal uploads/{id}, GT08 jwt forge (jwt_forge).
- **Confirmed but UNKNOWN provenance (agent-asserted, `leg=None`, no leg proved them):**
  GT01/GT02 sqli, GT03 xxe import, GT11 bfla admin/users, GT12 admin/debug disclosure.
  Evidence is agent hypothesis ("common target for SQLi… no sanitization"), not leg proof.
- **Detected-unconfirmed:** GT06 idor comments, GT09/GT10 mass_assignment.
- **Missed:** GT13 ssrf /api/integrations (collaborator OOB never fired; 0 in log).

**This REPRODUCES s18 (s18: 9/13, 6 unknown; s19: 9/13, 5 unknown) — no real movement.**
Standing gaps, all persisting: **0 chains composed** (second-order V17/V22 path produced
nothing despite max_chain_rounds=3); **browser_xss 0 confirmations** (keep smoke_only, no
→live promotion); breadth "887 confirmed" is ~552 disclosure-class NOISE (info_disclosure
×413 + verbose_error ×139) from the app's `/`-route 500 verbose-error page.

**Honest frontier for next session:** the dominant issue is that 5/9 GT "confirms" are
agent-set `confirmed=True` with no deterministic leg — the scorer is honest (flags them
UNKNOWN) but the headline "9/13" overstates leg-earned confirmation (really 4/13). SSRF
leg + second-order chaining + disclosure-noise suppression are the levers to move the
EARNED number. Target left running on :5002 (PID was 55264).

---

## ►► PARALLEL TRACK — Opus, branch `astra-t05-t08` (T05/T06/T08) ◄◄

Branched off `codex/astra-review-fixes` @ `e24ca7f` in worktree
`.worktrees/astra-t05-t08`; the identity track through `5f0522a` (F07 run identity,
session/credential isolation, and ownership preservation) is now reconciled here.
Treated the identity contracts
(`evidence.TestCaseRef`/`ProofRecord`/`Verdict`) + case/proof identity (T01
F02/F03/F06) as settled. **Not yet merged into `WorkingSunday`.**

- **Env reconciliation (READ if tests won't run):** the prior env (CPython 3.12 +
  `.review-deps`) was not reproducible — only 3.14 was installed and `.review-deps`
  is cp312. Installed 3.12.10 (`py install 3.12`) + a `typing_extensions==4.16.0`
  scratchpad shim (the bundled one lacks `sentinel` for the newer anyio). Runner:
  `pythoncore-3.12-64\python.exe`, `PYTHONPATH=<shim>;<.review-deps>`, from `harness/`.
  Baseline on `e24ca7f` reconciled to the codex count: **1,581 OK, 2 skipped**.
- **T05/R26 (`fdc50bb`,`e9a9d76`) — DONE.** Concrete per-input/per-state coverage
  case keys aligned to `TestCaseRef` (`coverage_model.CaseKey` + child-case layer +
  aggregation "one confirmed child marks risk, never endpoint completion" + new
  controlled_negative/blocked/inconclusive statuses); `coverage_tracker`
  case-granular driving; `orchestrator._coverage_proof` persists a case-bound proof
  per driven leg. Default-OFF flags `coverage_drive_cases`/`coverage_case_budget`
  gate the new live path (existing coverage semantics unchanged). Per-validator
  PARAMETER attribution left to T08 oracle work.
- **T06 (`04f6d32`) — DONE.** `issues.py`: run-independent stable issue IDs over a
  conservative key (family+method+class+affected-input+read/write boundary), issues
  keep ALL members, redacted `export_issue`/`replay_view`. `store.all_host_findings`
  surfaces method+case coords; `report_generator` uses the issue key + renders issue
  IDs + `export_issues_for_host`. Operator root-cause merge + Burp replay = T10.
- **T08 in progress (`e1ac8e9`, `693b4c8`..`546def9`).** The enforced inventory
  remains 32 sites and is down from **23 to 17 target routing gaps**. Production
  role-matrix, crawler, API-surface, feature-workflow, scope-expansion,
  cross-identity, CSRF, and verb-tamper sends now use invocation-local executor
  sessions. Legacy standalone paths remain compatible. CSRF/verb oracles remain
  observation-only; transport qualification did not promote confirmation claims.
- **Review round (IMPLEMENTATION_REVIEW_T05_T08.md) — all 11 findings addressed**, each
  with a paired regression; reviewer's `review_t05_t08_checks.py` diagnostics all corrected.
  Key fixes: R01 per-input attribution no longer fabricated (leg drives once per cell at
  request level; parameter siblings inconclusive); R02 coverage keys on durable
  `principal_id`; R03 URL/JSON redaction across export+replay; R04 issue id adds host +
  unknown-input disambiguator; R05 errors recorded + budget bounds attempts; R06 error/
  blocked child forbids completion; R07 occurrence encoding `[occ:n]`; R08 findings dedup
  now `(fingerprint,case_id)` so retests persist + export shows full proof history; R09
  verdict by exact proof id; R10 class-keyed invariant + honest artifacts; R11 guard
  reworded module-granular. See EXECUTION_LOG "Review response".
- **Verification:** pre-reconciliation full discovery was **1,671 tests OK, 2 skipped**.
  After merging the identity track through `5f0522a` and binding coverage proofs to its
  invocation-local `RunContext`, the combined focused matrix is **279 tests OK** and full
  stdlib discovery is **1,685 tests OK, 2 skipped**, exit 0, 317.988s. No model / browser /
  container / blind-target / live run performed — all hermetic.
- **Still owed:** merge the reconciled branch into `WorkingSunday`; a fresh live
  max-coverage VulnCorp run to move any
  numbers. New live behavior is flag-gated OFF, so live recall is unchanged until enabled.

- **T07 complete (`ec19ed8`, `cbbc192`, `2b9110a` + final transport controls):** added versioned Workflow/Step/Result
  records; strict prerequisite and placeholder blocking; JSON Pointer, Location, and
  hidden-field extractors; bounded 401 refresh distinct from 403 denial; eager cleanup
  registration and cleanup-after-cancel through the run-scoped executor; declarative
  production wiring in `investigate_engagement`; and an actual-loopback vulnerable/
  patched cross-principal create→approve→independent-read control. Focused T07 caller/
  transport matrix: **102 OK**. Full suite: **1,708 OK, 2 skipped**, 320.729s.
  Skip/repeat/switch variants execute through policy; resume preserves prerequisites;
  failure/cancel cleanup is explicit; actual transport has vulnerable/patched skip,
  exact-two-send repeat, and cross-principal independent-read controls.

- **Pause checkpoint (2026-09-10):** clean focused commits through `546def9`.
  Latest focused gates: role/engagement/investigation **39 OK**; CSRF/verb/context
  **105 OK**; discovery/context **88 OK** plus added actual crawler/surface controls
  **47 OK**; feature workflow **29 OK**; scope/context **30 OK**; inventory **10 OK**.
  The last full suite remains the post-T07 **1,708 OK, 2 skipped** result above;
  no full-suite claim has been made after T08a–f. Resume sequentially at
  `missing_auth_probe.py`, then remaining validator/orchestrator transports.

- **2026-09-11 continuation on `astra-integration`:** T08g–i (`ec450a3`,
  `6d99cd1`, `ddfa95f`) migrate missing-auth anonymous/garbage controls, JWT
  forge/control probes, and rate-limit bursts to invocation-local executor
  sessions. Inventory is now **14 target routing gaps** (from 23 initially).
  Focused final gates: missing-auth/API/context **39 OK**, JWT actual+negative
  controls **6 OK** (broader confirmation matrix **92 OK, 2 skipped**), rate-limit
  matrix **75 OK**, inventory **10 OK** after each slice. The rate-limit oracle
  remains observation-only/provisional.
- **Live S19 status:** `testing/vulncorp-helpdesk/maxrun/` contains the live run.
  Pass 1 completed all **37/37** captured exchanges and wrote the intermediate
  result after **5,946.5s**; Pass 2 `investigate_engagement` is still running as
  of this checkpoint, so `investigate` is null and no final coverage/recall claim
  is reconciled yet. Do not stop or restart its Python/target processes.
- **T08j implemented:** graph TOCTOU authority
  reads and concurrent writes now use the invocation-local gate, bound session,
  request budget, and executor; standalone registry callers retain the legacy
  compatibility path. Real loopback positive and denied-mutation controls pass.
  Corrected focused confirmation/smoke matrix: **108 OK**; inventory is **13**
  target routing gaps. One earlier broad invocation reported 67 tests with one
  loader error because `test_confirmation_routing` does not exist; no product
  failure was hidden, and the corrected named-module run exited 0.
- **T08k implemented:** registry race-condition bursts use invocation-local
  transport. Context is attached to per-dispatch validator copies, preserving
  shared-registry concurrency isolation and the public two-argument registry
  seam. Real loopback session/budget and denied zero-send controls pass. Final
  broader matrix: **155 OK**; inventory is **12** target routing gaps. An initial
  broader run exposed 12 compatibility-seam errors and was corrected before this
  result; no live claim changed.
- **T08l implemented:** SQLMap's Docker/tool-runner path remains unchanged;
  only its direct boolean-differential fallback now uses invocation-bound
  sessions and executor policy. The validator's preflight mutation decision
  also uses the invocation gate. Real loopback identity/budget and denied POST
  zero-send controls pass. Focused matrix: **117 OK**; broader SQLMap,
  safety, evidence, confirmation, and smoke matrix: **187 OK**. Inventory is
  **11** target routing gaps. No live result was inferred from these tests.
- **T08m implemented:** registry CORS probes now use per-dispatch run scope,
  budget, cancellation, redirect policy, and executor routing. Real loopback
  one-send/one-budget and off-scope zero-send controls pass. Focused matrix:
  **77 OK**; broader executor/evidence/confirmation/smoke matrix: **120 OK**.
  Inventory is **10** target routing gaps; CORS oracle semantics were unchanged.
- **T08n implemented:** CSP/clickjacking fresh-header fetches now use the
  per-dispatch executor with run scope, budget, cancellation, and bounded manual
  redirects. Real loopback one-send and off-scope zero-send controls pass. The
  combined CSP/CORS/executor/evidence/confirmation/smoke matrix is **122 OK**;
  inventory is **9** target routing gaps. Header oracle semantics were unchanged.
- **T08o implemented:** OAuth/OIDC redirect-uri exact-match probes now use the
  per-dispatch executor with run scope, budget, cancellation, and redirect
  policy. Real loopback one-send and off-scope zero-send controls pass. Broader
  executor/evidence/confirmation/smoke matrix: **120 OK**. Inventory is **8**
  target routing gaps; passive OAuth checks and oracle semantics are unchanged.
- **T08p implemented:** bounded CRLF/header-injection query probes now use the
  per-dispatch executor with run scope, budget, cancellation, and redirect
  policy. Actual one-send and off-scope zero-send controls pass. Combined
  validator/executor/evidence/confirmation/smoke matrix: **122 OK**. Inventory
  is **7** target routing gaps; the marker-header oracle is unchanged.
- **T08q implemented:** the HTTP-smuggling validator's existing ordinary-HTTP
  anomaly sampler now uses invocation scope, mutation gate, budget, cancellation,
  and executor routing. It remains explicitly **not confirmed** because this is
  not raw-framing transport or paired-proxy proof. Real loopback one-send and
  denied-mutation zero-send controls pass. Clean matrix: **166 OK**; inventory
  is **6** routing gaps. An earlier identical test body passed but its shell
  preamble emitted a read-only-variable error; the clean rerun is canonical.
- **T08r implemented:** recon crawl, common-file, and technology-fingerprint
  fetches now share the per-dispatch run executor, scope, budget, cancellation,
  and redirect policy. Actual loopback one-send and off-scope zero-send controls
  pass. Combined transport/safety/evidence/confirmation/smoke matrix: **168 OK**;
  inventory is **5** routing gaps. Recon result semantics were unchanged.
- **T08s implemented:** subdomain-provider fingerprint fetches now use the
  per-dispatch executor, so referenced third-party hosts must be explicitly in
  run scope and obey budget, cancellation, and redirect policy. Compilation and
  **120 tests OK**; real loopback one-send and off-scope zero-send controls pass.
  Inventory is **4** routing gaps; fingerprint/oracle semantics are unchanged.
- **T08t implemented:** cacheability, unkeyed-header, follow-up, and deceptive-
  path probes now use per-dispatch executor policy. Real loopback one-send and
  off-scope zero-send controls pass; compilation plus **122 tests OK**. The
  validator remains candidate/not-confirmed because it still lacks a distinct
  second-client retrieval proof. Inventory is **3** routing gaps.

---

## ►► SESSION-17 STATE (READ FIRST) ◄◄

**2026-09-10 implementation continuation from `9fdbb11`:** Work continues on
`codex/astra-review-fixes` in an isolated worktree so the occupied
`impl/astra-tickets` worktree and dirty `WorkingSunday` checkout remain untouched.
T01 F02/F06 is complete: legacy `not_confirmed` maps to inconclusive; a controlled
negative requires explicit execution plus a control artifact; artifact-free results
are labelled `legacy/unstructured`. A pre-existing `test_ollama_client` global-httpx
leak was also contained per test so real-transport tests survive full discovery.
Focused verdict/oracle/authorization checks: **37 tests OK**. Ordered transport
isolation regression: **28 tests OK**. Full stdlib discovery: **1,578 tests OK,
2 skipped**, 314.586s.

**T01 F03 complete:** `Finding` now carries originating finding/principal/request/input
coordinates and exact `case_id`/`proof_id` links. `_validate_findings` binds each job,
proof, persistence write, confirmation, and cross-identity downgrade to that concrete
finding; the class-wide assignment was removed. Old proof rows retain their pre-F03
case hash. Focused evidence/engagement/transport checks: **79 tests OK**. Full stdlib
discovery: **1,581 tests OK, 2 skipped**, 314.376s. T01 is now complete against the
reviewed F02/F03/F06 requirements; invocation-local run identity (T03 F07) is next.

**T03 F07 complete:** the server job manifest now owns an invocation-local
`RunContext`, and that immutable run ID is passed into engagement/captured-exchange
analysis and exact proof construction. The singleton lazy run ID was removed.
Configuration is deep-snapshotted, cache namespaces are salted by run ID, request
budgets/cancellation are per context, API cancellation signals the context, and owned
clients close with the job lifecycle. Focused cache/context/proof/manifest/API checks:
**80 tests OK**. Full stdlib discovery: **1,585 tests OK, 2 skipped**, 287.529s.
T03 F04/F05 session and credential isolation is next.

**T03 F04/F05 complete:** graph authorization now registers every principal and an
explicit anonymous session in its invocation context; cross-identity probes no longer
read process-global identities on that path. Unknown session references and credential
headers without a session fail before transport. Credential-bearing sessions require
declared normalized origins; unauthorized initial destinations are blocked, and
cross-origin redirects receive neither session cookies nor retained request bodies.
Focused authorization integration: **73 tests OK**; focused real transport: **18 tests
OK**. Full stdlib discovery: **1,591 tests OK, 2 skipped**, 289.004s. T02 F08–F10
principal metadata and ownership semantics are next.

**T02 F08–F10 complete:** identity re-save uses an additive UPSERT and preserves
tenant, permissions, and trust metadata. Run sessions carry authoritative `Principal`
objects into ownership checks. Object references include run, normalized application
origin, explicit tenant state, path, and the unmodified query selection. Authorized
access is recorded per principal and evaluation continues, so it cannot suppress a
later unauthorized case. Focused principal/ownership/transport/API checks: **84 tests
OK**. Full stdlib discovery: **1,595 tests OK, 2 skipped**, 294.398s. T03 F01
production wiring and transport behavior is next.

**2026-09-10 review-only addendum:** Source inspected at HEAD `8b5c6e1`;
implementation handoff saved to
[`reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md`](reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md).
It defines T00–T10, beginning with a real-transport authorization proof milestone.
No implementation changes, tests, or live runs were performed for this review;
the suite result below remains the previous session's reported result.

**2026-09-10 T00 implementation:** Added a versioned, redacted run manifest and
append-only lifecycle ledger to the existing investigation job API. Focused suite:
9 tests OK. The missing local `pytest` and `mitmproxy` dependencies were subsequently
installed from their existing pins: the pytest-native plugin suite is 26/26 green and
full stdlib discovery is **1,509 tests OK, 2 skipped**, 272.821s. The optional proxy's
`typing-extensions` metadata conflicts with the bundled Pydantic stack, so verification
uses the bundled core runtime first and appends `.review-deps`; details are in the review
directory's `EXECUTION_LOG.md`. T01–T10 remain open.

Branch `WorkingSunday`, **HEAD `f36d454`** (+ any later doc commit). Suite green
(`cd harness && python -m unittest discover -p "test_*.py"`) — **1505 tests OK**,
~277 s, on the committed tree. `config.yaml` at safe defaults;
`config.local.yaml` untouched; hazard #1 intact.

### What session 17 did — implemented the 2026-09-09 project review

Worked [`reviews/2026-09-09/PROJECT_REVIEW.md`](reviews/2026-09-09/PROJECT_REVIEW.md)
top-to-bottom. That file's **IMPLEMENTATION PROGRESS** section is the authoritative
per-item status + the test that verifies each; this is just the summary.

**Closed, each with an offline test + negative control (all HERMETIC — no fresh live run):**

- **All P0 correctness findings:** R01/R02 (coverage stops inventing executed checks;
  honest counts), R03 (cache key includes identity+subtype), R04 (upload uses the real
  `GatedAsyncClient.request()`), R06 (coverage-driven confirmations enter the finding
  pipeline), R07 (monotonic confirmation — a proof is never downgraded), R08
  (execution-aware suppression — REFUTED needs a real controlled negative), R09 (exact
  leg tiers, no substring inheritance), R10 (reject self-comparison + distinct principal
  ids), R12 (second-order SQLi masks reflected payload), R14 (typed discovery-chain
  routing), R16 (per-finding mutation ceiling enforced).
- **Graph/flow:** R05 (replay captured request templates), R18 (`investigate_engagement`
  exposed as a cancellable job API in `server.py`), R19 (credential-feedback map + merge
  derived state), R20 (chain provenance), R21 (per-case completion), R23 (attempt-budget),
  R25 (browser drives AS the identity), R29 (bounded validation fan-out), R30 (operational
  failures surfaced as `result.errors`/`degraded`).
- **Oracle retirements (Phase 5)** — 8 overconfirming verdicts stood down to
  observations/candidates, detectors kept: passive-deserialization, rate_limit,
  reset_token, csrf, verb_tamper, request_smuggling, web_cache; file_upload tightened.
  csrf/verb_tamper removed from `LIVE_VERIFIED_MARKERS`. **See
  [`ORACLE_RETIREMENTS.md`](ORACLE_RETIREMENTS.md)** — the record of what was stood down
  and how to re-qualify each (search code for `RETIRED (review 2026-09-09)`).
- **Precision:** R11 (BFLA needs a privileged-data match), R13 (authenticated
  second-order plant + distinct-identity read).
- **Weaknesses:** #1 (prompt validator observes injection-shaped evidence instead of
  skipping analysis; hard-block opt-in), #5 (repro field isn't remediation), #6 (recall
  UNKNOWN provenance + best-proof), #7 (CSRF WSTG SESS-05), #9 (sitemap header
  multiplicity), #10 (strict ffuf fallback), #11 (tool container force-remove on timeout),
  #13 (high-signal excerpt beyond truncation), #14 (DAG: skipped-required ≠ satisfied),
  #18 (this file trimmed), #19 (removed fabricated token-savings %).

### The honest frontier — NOT done (needs operator direction, per the review's L-phases)

These are the review's dedicated architecture phases or need a schema/design decision;
they were deliberately **not** rewritten unilaterally:

- **Schema / issue-ID model:** R28 per-finding/case-ID binding (synonym match IS done),
  #4 root-cause dedup.
- **Architecture rebuilds:** R15 (one policy-aware executor / registry-only construction),
  R17 (centralized scope/transport + redirect/credential handling), R24 (stateful
  authenticated workflow engine), R26 (per-parameter coverage matrix), R27
  (principal/tenant/session/ownership model), #3 (per-run isolation of global state),
  #8 (OpenAPI schema-driven request construction), #20 (single operator run→export flow).
- **Tuning:** R22 (broaden agent derivation — affects runtime cost), #12 (session reuse
  across raw clients), #2 (cache manifest — over-invalidation risk).
- **Infra/CI:** #15/#16 (packaging/deps), #17 (scored CI tier + Java/browser gates),
  and the **deletion/consolidation table** (Phase 9 — gated on the rebuilds above).
- **The one measurement still owed — DONE 2026-09-11 (s19_full).** See the LIVE
  MAX-COVERAGE RUN section at the top of this file. Result reproduced s18 (9/13 confirmed,
  4 leg-earned); the hermetic review work did not move live recall, as predicted.

### Environment

Ollama `qwen3:8b` + Docker (`harness/sqlmap:1.10.9`, `harness/ffuf:2.1.0`),
Playwright/Chromium — as CLAUDE.md § Environment. No host `javac` (Burp panel is
self-review only; the review's fixes are all Python).

### Commit shape

Focused commits on `WorkingSunday`, one finding-group each, suite green at the batch
boundary. Nothing pushed. The pre-existing session-17 discovery-breadth WIP was
snapshotted first (`33031f9`) before the review fixes landed on top.
