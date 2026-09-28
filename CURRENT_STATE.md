# Current state — 2026-09-28

## Checkout and review

Branch `reconciliation-backlog`; reviewed HEAD:
`678dcce5ce79034e0cb3d178044714a8b82b2645`.
Latest: [Pentest-Swarm source comparison](reviews/2026-09-27/swarm-comparison/REVIEW.md).
[Commands/evidence](reviews/2026-09-27/swarm-comparison/VERIFICATION.md).
Compared upstream `Armur-Ai/Pentest-Swarm-AI` at
`661c21828f8a2d0e84ee8b161037d5e9d93942f8`.
Previous state: [snapshot](reviews/2026-09-27/swarm-comparison/CURRENT_STATE_before_comparison.md).
Pre-existing README edits, worktrees and runtime/review artifacts remain.
No review-authored production changes, commits, pushes or active-default changes.
Inventoried source/config hashes remained unchanged during verification.
Loop batch (swarm-comparison SC-*, all loop-consumable items done): **SC-1** `0fea458a`
(non-executed negative control → inconclusive, not VERIFIED), **SC-2** `2764a60`
(credential grant needs a noise-tolerant authorization discriminator, not a byte diff),
**SC-3** `debb3e7` (controlled negatives bind to case+principal; empty-param wildcard
retired), **SC-4** `895dda3` (unknown workflow assertions fail closed at load+runtime),
**SC-5** `6a581d5` (MCP export honors the `reporting.*` gates), **SC-7** `77a0838` offline
half (opt-in gate/budget seam on browser requests), **SC-8** `0522472` (EffortBudget atomic
reserve/commit/release + deadline-at-construction). SC-1..SC-4 are strict
verification-correctness tightenings; SC-5/SC-7/SC-8 add opt-in/presentation seams that are
byte-for-byte no-ops until wired. Also closed the last older-queue loop item: **FR-7** `c2cb427`
(run-independent hypothesis cache, default-OFF; on a hit it falls through to `_validate_findings`
so proof/case/oracle are re-minted per run, never cached/shared — pre-proof reports only).
Re-analysis batch 2: **RA-7** `981c5ff` (cross-identity reject-downgrade now fires only on a genuine
control-held reject via a `control_outcome` discriminator, not on inconclusive observations — the SC-1
anti-pattern on the reject side); **RA-8** `c4a534b` (workflow `status` assertion operand validated
int-coercible at load + fail-closed at runtime; completes SC-4). **All offline loop items now closed —
pool exhausted; loop ended (LOOP_DONE).**
**Owner-deferred:** SC-6 (wheel import needs off-host install + non-checkout-preserving refactor);
SC-7 live browser wiring/health; SC-9..SC-15 (measurement/live-gated); FR-7 hit-rate measurement +
default-ON. Per-item detail + Results in IMPROVEMENT_BACKLOG.md.

## Fresh verification

Repository-root Python 3.12, existing `.venv-rationalisation`:
- Full: exit 0 (harness unittest 2817 OK / 2 skipped, +43 loop tests [SC-1..SC-5,SC-7,SC-8,FR-7,RA-7,RA-8];
  pytest 38 passed, evaluation 221 OK, evaluation integrity 42 OK). Workspace pytest temp dir required.
  (One earlier full run during FR-7 showed a single unattributed transient failure that did not
  reproduce across subsequent green runs; the default-OFF FR-7 no-op is not the cause — worth a
  separate look at flaky full-suite tests.)
- Smoke: 92 OK. Orchestrator preconditions: 60 OK.
- Requirement report still lists 36 gaps; offline passes do not close them.
- Java: actual Gradle 8.7/JDK 17 `test shadowJar` succeeded; 229 tests,
  zero failures/errors/skips. Explicit UTF-8 rebuild clean.
- Wheel builds but importing its server outside checkout fails: config.yaml absent.
- The swarm-review probes for oracle failed-control promotion (SC-1), dynamic-public
  credential acceptance (SC-2), unknown-parameter negative wildcard (SC-3), and unknown
  workflow assertion success (SC-4) are now CLOSED offline (regression tests added); the
  wheel-import failure below (A5/SC-6) remains open (owner).
- No current real-model accuracy, blind recall, live Burp load, browser or
  container-policy verification. Docker/Ollama readiness not established.
- Upstream Go suite has a Windows `true` command failure; five independent
  probes reproduce board delivery loss and weak scope/authorization/proof logic.

## Open work and recommended order

ALL loop-consumable offline items are now closed (SC-1..SC-5, SC-7 offline, SC-8, FR-7, plus the
2026-09-27 re-analysis batch 2: **RA-7** `981c5ff` + **RA-8** `c4a534b`). The offline loop pool is
exhausted: batch 2 was itself a fresh re-analysis over the confirmation/verification, transport/policy,
engagement, and store/report/api clusters and found NO other offline item above the bar; the analyzed
code is unchanged since, so the loop is ended (LOOP_DONE) rather than re-running an identical pass. A
future re-analysis is warranted only after the code changes or the owner lands live-gated work. All
remaining work is owner/live-gated:
1. SC-6 (A5): package config as a resource + separate writable state + exclude tests +
   entry points; verify by a fresh-venv install outside the checkout (needs off-host
   install; not checkout-behavior-preserving in one offline pass).
2. SC-7 live half (A7): wire a real RunContext gate/budget into the live browser
   `visit` call sites + browser health/doctor + WebSocket/service-worker constraints
   (needs a working Playwright browser). SC-8 dispatch-seam wiring (agent_manager/retry/
   critique/coordinator) similarly remains to be wired to the new reserve/commit primitive.
3. SC-9 (A6, needs PR-11) + SC-10..SC-15 (typed tool contracts, versioned workflow packs,
   durable queue, provider routing, install/doctor UX, report polish) — retention gated
   on a matched-budget measurement; treat efficacy runs as OWNER/LIVE.
4. Standing owner items: real-model accuracy / blind recall / live Burp load / container
   policy; faithful budget-matched production ablations. No AGPL upstream code imported.
5. Higher-priority non-loop items also remain owner/live: P1-3 (single-command scorecard,
   live model), P1-5 (Burp UX build), P2-1 (BusinessContextAgent — Effort-L feature,
   retention ablation-gated), P2-3 (needs P1-5), P3-2 (partial: SBOM/dep-audit offline,
   image-digest pinning off-host), P3-3 (team mode, premature). BM-2 (same-class
   secure-vs-vulnerable discriminator) needs real-model FP data to prove. New offline
   loop items require a fresh re-analysis pass to file.

Earlier founder items and implementation history remain in
[founder refresh](reviews/2026-09-26/founder-refresh/REVIEW.md) and
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md); broader requirements remain open.
Preserve `test_pipeline_gate.py` and defect-injection controls.
No blind keys or blind-target implementations read.
Portable audit toolchains/clone/builds remain in `.audit-external` and build dirs.
Keep this file under 100 lines; details belong in the linked review.
