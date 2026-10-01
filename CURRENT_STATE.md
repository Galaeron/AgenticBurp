# Current state — 2026-10-01

## Checkout
- Branch: `reconciliation-backlog`
- HEAD: `6d5a2082` (LB-1 shared source-form helper + unit test); LB-NOTE fixes
  landed in the working tree (tracked-WIP, no isolated commit — see below).
- Working tree is a large, deliberately-uncommitted WIP pile (the 2026-10-01
  live-loop legs, the benchmark harness, the `objective_completion`/IDOR work,
  etc.). Branch convention: each loop iteration commits only the new standalone
  files for its item and preserves the WIP pile. Preserve these edits.
- `harness/config.yaml` remains at safe defaults; live overrides stay in-memory /
  git-ignored `config.local.yaml`.

## Active queue — 2026-10-01 live-loop build batch (LB-*)
Order: **LB-1 → LB-3 → LB-2 → LB-4 → LB-5 → LB-6**, before older queue work.
LB-7 is OWNER/LIVE (skip).
- **LB-1 — DONE (`6d5a2082`, VERIFIED).** Shared in-session source-form replay
  primitive (`harness/validators/source_form.py`): one `fetch_source_form(...)`
  helper + `SourceForm` dataclass + shared `CSRF_FIELD_RE`. The four source-form
  legs (stored_xss, auth_sequence, file_upload, client_trust) are refactored onto
  it with NO behavior change (per-validator form-selection kept as separate caller
  closures; auth_sequence vs client_trust CSRF rules deliberately NOT flattened).
  Committed artifact = helper + `harness/test_source_form.py` (7 tests); the
  validator refactor wiring rides in the uncommitted legs pile.
- **LB-NOTE — DONE (VERIFIED, in-worktree).** Cleared the two pre-existing `full`
  failures: (A) `_ssti_readback_urls` normalizes the by-design dict/object union in
  `orchestrator_chain.py` so the SSTI-readback loop no longer crashes on role_crawl's
  `model_dump()` dicts (+ `test_ssti_readback_urls.py`, non-GET negative control both
  shapes); (B) added the `client_trust` Python-only entry to the execution-plane matrix.
  `full` now green. Fixes land in tracked-WIP (no isolated commit, per branch convention).
- **LB-3 — DONE (VERIFIED, in-worktree).** `_authenticate` now has a bounded 3-attempt
  login GET/POST retry (retries on HTTPError/5xx, happy-path unchanged, injectable
  `transport=None` seam) and a `_auth_info` helper that marks an auth-requested-but-failed
  run `degraded` + `hard_error` (fail-loud, no silent anonymous). 7 new tests (MockTransport,
  no sockets/sleep); `full` green. Lands in untracked runner WIP → doc-close only.
- **Next: LB-2** — driver-based request capture for JS/XHR-built shapes (discovery).
  Mode: LOOP for the capture plumbing + fixture (a real blind-target recall claim is OWNER/LIVE).
  Reuses the Playwright driver; gated behind a discovery flag, OFF by default.

## Verification (this checkout)
- **`full` is GREEN:** unittest `Ran 3061 tests … OK`; pytest-native 38 passed;
  testing 265 OK; integrity 42 OK; exit 0. The two pre-existing failures are cleared
  by LB-NOTE (see below) — the LB-1 note's "8 pre-existing failures" are resolved.
- LB-1 surface: `test_source_form` 7 OK; `test_leg_live_verification` 39 OK (all four
  legs' positives + negative controls); `test_stored_xss_validator` + `test_validators` 26 OK.
- LB-NOTE surface: `test_pipeline_gate + test_execution_planes + test_ssti_readback_urls
  + test_role_crawl` 80 OK.
- No offline tier establishes current model accuracy or blind-target recall.

## Web-objective benchmark
- Contract: `testing/web-objective-benchmark/`; runner: `testing/run_web_objective_smoke.py`;
  scorer: `testing/web_objective_benchmark.py`.
- Durable per-case evidence under `reviews/2026-09-29/`..`2026-09-30/web-objective-smoke/`;
  ledger `reviews/2026-09-29/web-objective-smoke/LOOP_LEDGER.md` (the LB-* source).
- Owner goal: safe detection + non-destructive proof. Do not run destructive objectives.

## Confirmed live capabilities (historical/reported unless re-run this session)
- SQLi hidden-data/login-bypass, reflected + stored XSS, path traversal, simple
  command injection, SSRF, XXE, IDOR read, CSRF method bypass, unrestricted upload,
  JWT unverified signature + RS256/HMAC algorithm confusion (0.90), NoSQL auth bypass,
  Freemarker SSTI arithmetic (0.95), custom-exploit SSTI (0.95, non-destructive).

## Open work / pointers
- `full` green; continue LB-2 → LB-4 → LB-5 → LB-6.
- Older still-open: SC-6 (wheel imports outside checkout), SC-9 (tool broker),
  SC-10/SC-14 (ToolAdapter / install-doctor-serve) — after the LB batch.
- OWNER/LIVE (skip in loop): LB-7 (single-packet race dispatch), P0-3, P1-5, P2-2,
  efficacy/ablation runs, any real-model/blind-recall claim.
- Handoff: `docs/DETERMINISTIC_FIRST_IMPLEMENTATION_CHECKLIST.md`. Preserve
  `test_pipeline_gate.py` and its defect-injection controls.
