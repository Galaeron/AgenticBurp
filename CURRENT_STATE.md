# Current state — 2026-10-01

## Checkout
- Branch: `reconciliation-backlog`
- HEAD: `f952b107` (LB-2 driver-based capture, 6 cleanly-separable files). LB-1 helper
  committed earlier (`6d5a2082`); LB-NOTE/LB-3/LB-4 fixes + LB-2's fixture/integration test
  land in the preserved tracked-WIP (no isolated commit — see below).
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
- **LB-3 — DONE (VERIFIED, in-worktree).** `_authenticate` bounded 3-attempt login retry +
  `_auth_info` degraded/fail-loud marker; 7 new tests; lands in untracked runner WIP (doc-close).
- **LB-2 — DONE (`f952b107`, VERIFIED).** Driver-based capture of JS/XHR-built request shapes:
  `browser_driver.capture_requests` records real fetch/XHR requests (method/URL/content-type/body)
  through the existing browser policy; `driver_capture.discover()` emits them as role_crawl-shaped
  `HttpExchange` dicts so legs fire on JS-built shapes. New `driver_capture` flag OFF + registered
  in the passive force-off list / SafeDefaultGuard. 6 cleanly-separable files committed;
  the /xxe fixture + capture→confirm integration test (XXE via in-process loopback collaborator,
  offline) + passive negative control ride the legs WIP. multipart/file-upload half deferred.
- **LB-4 — DONE (VERIFIED, in-worktree).** Two shape-preconditions in
  `shape_precondition_legs` route the 2fa-bypass + client-trust legs from captured traffic
  (reusing each validator's own predicate); `_confirm` gained a client_trust branch + 2fa/mfa
  match. Dispatch-only, confirm-gated, behavior-neutral for existing classes (reviewer over-match
  check). 6 new precondition assertions + the existing leg confirm/control cases. `full` green.
  Lands in orchestrator WIP → doc-close.
- **Next: LB-5** — cross-site browser PoC capability (CSRF no-defenses). Mode: LOOP for the
  driver extension + fixture controls; ships default-OFF. Re-adds `csrf` to the safety-gate LIVE
  set ONLY once SameSite/Origin/token/bearer controls pass. Then LB-6.

## Verification (this checkout)
- **`full` (LB-4 run) fully GREEN:** unittest `Ran 3073 tests … OK`; pytest-native 38 passed;
  testing 272 OK; integrity 42 OK; exit 0. (The LB-FLAKE timestamp flake did not recur this run;
  it remains filed as a nondeterminism to fix.)
- LB-4 surface: `test_orchestrator_precondition` 74 OK + injection/confirmation leg suites
  (151 OK combined); LB-2: `test_driver_capture` 3 OK (real Playwright), SafeDefaultGuard green;
  `test_leg_live_verification` 42 OK. Earlier LB-1/LB-NOTE/LB-3 surfaces remain green.
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
- continue LB-5 → LB-6; LB-FLAKE (blind-eval timestamp flake) is a quick offline fix.
- Older still-open: SC-6 (wheel imports outside checkout), SC-9 (tool broker),
  SC-10/SC-14 (ToolAdapter / install-doctor-serve) — after the LB batch.
- OWNER/LIVE (skip in loop): LB-7 (single-packet race dispatch), P0-3, P1-5, P2-2,
  efficacy/ablation runs, any real-model/blind-recall claim.
- Handoff: `docs/DETERMINISTIC_FIRST_IMPLEMENTATION_CHECKLIST.md`. Preserve
  `test_pipeline_gate.py` and its defect-injection controls.
