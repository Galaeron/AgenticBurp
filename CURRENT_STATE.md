# Current state — 2026-10-14

## Checkout
- Branch `reconciliation-backlog`; candidate `5aedf787`, base `474ad511`.
- Focused fixes: `ba7a649e` (seed/config), `4d713696` (provenance/caller gate),
  `4374e060` (regression fixtures and traversal applicability), `5aedf787`
  (report fixture independent of uncommitted store API).
- Earlier tracked edits and untracked tests/artifacts remain in the main checkout;
  they are not all included in these commits. Safe `harness/config.yaml` is unchanged.
- The attached `verify-decisive-fixes` worktree isolates the committed candidate.

## Fresh verification
- Main checkout full: 3398 harness tests, 38 pytest, 364 evaluation, 42 integrity,
  all pass; coverage manifest passes. Smoke: 93 pass. No skipped-test proof claimed.
- Isolated focused seed/config/provenance/dispatch/precondition controls: 136 pass.
- Isolated full: 3103 harness, 38 pytest, 284 evaluation and 42 integrity pass;
  17 optional historical-artifact evaluation tests skipped, coverage passes, exit 0.
  The first isolated run exposed a test-fixture dependency, corrected in `5aedf787`.
- Final isolated smoke: 93 pass, coverage check passes, exit 0.
- Actual Java test + shadowJar with JDK17/Gradle8.7: isolated candidate 229 tests;
  main checkout 252 tests; both pass without failures/errors/skips.
- Evidence and commands: docs/DECISIVE_FIX_VERIFICATION.md and
  .test-work/consolidation-20261014/. Earlier results below are historical/reported.

## Remaining work
- Live crAPI identity-B confirmation and secure control remain unverified. Docker's
  Linux engine is unavailable; crAPI localhost:8888 and harness 127.0.0.1:8787
  were unreachable. Ollama's port accepts TCP; model readiness was not established.
- Restart an owned server with the filled decisive overlay and registered test
  identities before using the updated external evaluation launcher. See
  docs/DECISIVE_RUN_PROVENANCE.md. Model digest/runtime version remain unavailable.
- Phase 2.2 vocabulary/agent routing remains open. Committed candidate misses
  63/122 labels (51.64%) and 374/978 occurrences (38.24%); normalization WIP in
  the main checkout yields 60/122 (49.18%) and 272/978 (27.81%). These measure
  class vocabulary compatibility, not production dispatch, accuracy or recall.
- Earlier remediation's intact installed-package/security review (R15/R19), final
  Burp walkthrough (R20), practical study (R25), measurement-led optimization
  (R21), and final release adjudication (R28) remain open; no new release claim.
- Historical remediation detail (local WIP): docs/RECONCILED_REMEDIATION_REGISTER.json,
  docs/RECONCILED_REMEDIATION_LOOP.md and docs/REMEDIATION_RELEASE_GATES.md.

## Working rules
- Follow AGENTS.md; never read answer keys or blind implementations.
- Preserve existing edits/artifacts. Active settings belong only in ignored local
  overrides; restart only owned services after Python changes.
- Python: .venv-rationalisation/Scripts/python.exe (3.12.14).
- Run smoke/full/orchestrator-precondition from the repository root after changes.
- Green offline tests and a JAR build do not establish live model quality or recall.
