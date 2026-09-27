# Current state — 2026-09-27

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
Loop changes since review: `0fea458a` closes **SC-1** (A1) — a non-executed negative
control (skipped/error/blocked) no longer counts as a clean negative, so it can no
longer manufacture a VERIFIED verdict; INCONCLUSIVE reason + candidate state instead.
`2764a60` closes **SC-2** (A2) — credential grants now require a noise-tolerant
authorization discriminator (trigram similarity ≥ 0.70 vs both controls), so a merely
noisy public response no longer reads as a grant/escalation. `debb3e7` closes **SC-3**
(A3) — controlled negatives bind to the exact case: the empty-parameter wildcard is
retired (empty-neg refutes only an empty-param finding) and a resolved cross-principal
negative no longer suppresses; fail-safe (empty principal never loses a refutation), still
capped on demotion. All three are strict evidence-correctness tightenings.

## Fresh verification

Repository-root Python 3.12, existing `.venv-rationalisation`:
- Full: exit 0 (harness unittest +7 SC-1 +4 SC-2 +3 SC-3 tests, 2 skipped;
  pytest 38 passed, evaluation 221 OK, evaluation integrity 42 OK). Workspace pytest temp dir required.
- Smoke: 92 OK. Orchestrator preconditions: 60 OK.
- Requirement report still lists 36 gaps; offline passes do not close them.
- Java: actual Gradle 8.7/JDK 17 `test shadowJar` succeeded; 229 tests,
  zero failures/errors/skips. Explicit UTF-8 rebuild clean.
- Wheel builds but importing its server outside checkout fails: config.yaml absent.
- New probes reproduce oracle failed-control promotion through `_oracle_gate`,
  dynamic-public credential acceptance, unknown-parameter negative wildcard,
  and unknown workflow assertion success.
- No current real-model accuracy, blind recall, live Burp load, browser or
  container-policy verification. Docker/Ollama readiness not established.
- Upstream Go suite has a Windows `true` command failure; five independent
  probes reproduce board delivery loss and weak scope/authorization/proof logic.

## Open work and recommended order

1. SC-1 + SC-2 + SC-3 done (oracle inconclusive-vs-clean; credential-grant
   authorization discriminator; control-identity case/principal binding). Next:
   SC-4 fail-closed workflow assertions; then SC-5 ReportPolicy parity (MCP).
2. Require positive authorization evidence for learned credentials; preserve
   noisy public-response negative fixtures.
3. Reject unknown workflow assertions; fix wheel resources/writable state paths.
4. Unify browser/tool policy, cancellation, model-budget reservations and exports.
5. Adapt typed tool contracts/versioned workflows/durable jobs from comparison;
   preserve the local evidence model rather than adopting their BOLA/board logic.
6. Add clean-install/JAR checks and faithful budget-matched production ablations.

Earlier founder items and implementation history remain in
[founder refresh](reviews/2026-09-26/founder-refresh/REVIEW.md) and
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md); broader requirements remain open.
Preserve `test_pipeline_gate.py` and defect-injection controls.
No blind keys or blind-target implementations read.
Portable audit toolchains/clone/builds remain in `.audit-external` and build dirs.
Keep this file under 100 lines; details belong in the linked review.
