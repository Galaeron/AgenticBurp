# Current state — 2026-10-17

## Checkout
- Branch `reconciliation-backlog`; base `474ad511`. Pushed tip `64e09ed6` (ARCH-3
  hardening) is the head of [Galaeron/AgenticBurp#1](https://github.com/Galaeron/AgenticBurp/pull/1).
- There are two local commits on top, NOT pushed: `ba080691` (SPA/catch-all discovery
  fixes = the I01 candidate) and the I01 docs commit after it (HEAD).
- Other uncommitted work (W1 cache trust, W2 passive ownership/export, W3 health
  contract, W4 label routing, docs) is left in place and dispositioned, not reverted.
- Safe `harness/config.yaml` is unchanged. The checkout has 13 git worktrees; several
  belong to other agents.
- Earlier discovery-fix evidence (2026-10-16 full run on the mixed tree, mutation log):
  `.test-work/discovery-fixes-*.log`. Historical context: docs/PROJECT_HANDOVER_2026-10-15.md.

## I01 candidate = commit `ba080691`
- `64e09ed6` + `.test-work/i01-candidate-overlay.patch` (12 files: discovery, crawler,
  role crawl, engagement builder, chain wiring, browser driver, tests, SPA doc; only the
  investigate hunks of `server.py`). The commit's diff from `64e09ed6` is byte-identical
  to the patch.
- Manifest, file dispositions, reproduce steps and canonical owner table:
  docs/I01_CANDIDATE_MANIFEST_2026-10-17.md.
- Isolated detached worktree, `.venv-rationalisation` Python 3.12.14, safe defaults:
  precondition 74 OK; smoke 93 OK + coverage gate; full exit 0 (3164 harness, 0 skips;
  38 pytest; 308 evaluation with 17 skips for absent local benchmark artifacts; 42
  integrity; 36 requirement-evidence gaps). Logs: `.test-work/i01-candidate-*.log`.
- The older 3459/371 counts came from the mixed tree, including untracked tests; they
  describe no committed or committable state.
- PR #1 CI at `64e09ed6` (base only, clean checkout): full Python suite + coverage gate,
  Java build + tests and provenance all pass; GPU/nightly scored tiers skipped.

## Reconciled trackers (I01)
- docs/ARCH_RECONCILIATION_TRACKING.md: ARCH-1/2 tests are helper-level, so caller
  verification is open (I03). The false-confirmation test mocks persistence and the
  oracle, so storage/export is open (I02). Records the `64e09ed6` hardening.
- IMPROVEMENT_BACKLOG.md: LB-2 is component-only (rest → I06/I07). DET-SQLI-POST and
  DET-JWT-DETECT have stale diagnoses and are re-scoped to I09. DET-SSRF → I13. A pointer
  to the owner table sits at the top of the backlog.
- W4 (`validators/base.py` spaced-label routing) has no ticket; I09 now owns it.
- 18 untracked test modules pass against the candidate alone. That is regression coverage
  missing from Git, which CI never runs. Another 10 pass only with the W1–W3 WIP. The manifest
  lists both groups.
- W2 changes the default `/analyze` partition to `analyze:<uuid>`, reversing the
  2026-10-09 operator-visibility choice. This needs an owner decision before commit.

## Open work and evidence boundaries
- Ordered list: docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md. Next: I02/I03/I04 and I11.
- Assessment: reviews/2026-10-17-project-assessment/ASSESSMENT.md.
- The live Part B crAPI experiment has not been run. Historical negative crAPI results
  still govern efficacy, and offline tests do not establish recall.
- Browser capture covers page-load traffic only: no login or click-through.
  Catch-all fingerprinting is conservative and can suppress or miss routes.
- Priority-5 release work and live Burp validation remain open. The Java CI pass covers
  committed Java only, not the W2/W3 Java edits.
- Remediation register and release gates: docs/RECONCILED_REMEDIATION_REGISTER.json and
  docs/REMEDIATION_RELEASE_GATES.md (both untracked; W2 docs).

## Working rules
- Follow AGENTS.md; never read answer keys or blind target implementations.
- Preserve prior edits and artifacts; live toggles belong in ignored local config.
- Verify from an isolated worktree, never from this mixed working copy.
- Run smoke/full/precondition after code changes. No offline tier establishes current
  model accuracy, blind recall or production readiness.
