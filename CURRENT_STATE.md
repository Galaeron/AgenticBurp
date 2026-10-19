# Current state — 2026-10-19

## Checkout
- Branch `reconciliation-backlog`; base `474ad511`; head of
  [Galaeron/AgenticBurp#1](https://github.com/Galaeron/AgenticBurp/pull/1) after today's push.
  Auto-fix is on for PR #1.
- Today's commits (oldest first): `ba080691` discovery fixes (I01 candidate), `1715022a`
  I01 docs, `1be5ed04` 16 regression modules, `2a883761` I03 transport, `fe9b8f3` I04 CSRF,
  `9adfa8a` I11, `d5802ec` I09 caller tests, `b9bcd18` gate: two writes for the
  second-order pair, `a9b71f6` CSRF manual-check guidance, `6d10816` docs, `5506ee4` CI fix
  (two W2-dependent tests untracked again; Python 3.14-valid TLS fixtures; short-path
  compare), then a docs commit.
- Since then: `8e1303c` I02-B default history, `c66ce27` docs, `8edf5a9` + `04b3dea` I02-A
  proof binding through storage/export, then a docs commit. `2ba91da` I05-A (sends escaping
  their run) + `5bca380` docs. Then `14747a9` I04 label check, `d7201fc` I11 socket leaks,
  `d8eb094` I11 evidence wiring, and a docs commit. All pushed to PR #1.
- Local, not yet pushed (network/process containment needs owner review per the guide):
  `ae8f287` I05-C tool process lifecycle, `934c3e1` I05-C2 counting proxy, `f7d1321` I05-A2
  standalone analyze publishes its run, and a docs commit.
- The owner approved I03 (including two writes) and I04 (with operator guidance), and I09
  as evidence only.
- Uncommitted WIP remains, dispositioned in docs/I01_CANDIDATE_MANIFEST_2026-10-17.md: W1 cache
  trust, W2 passive ownership/export, W3 health, W4 label routing, docs and untracked tests.
- Safe `harness/config.yaml` is unchanged. Another session's worktree
  `.claude/worktrees/objective-shannon-457fc8` exists; do not touch it.
- Implementation manual: docs/I01_I17_IMPLEMENTATION_GUIDE_2026-10-17.md (track
  implemented / caller-verified / live-validated / released separately).

## What changed today (offline; owned loopback fixtures only)
- I03: engagement legs now all spend the owning run (budget, scope, cancellation, TLS);
  the browser honours run cancellation. The second-order SQLi pair gets 2 writes per case
  (`DEFAULT_MUTATING_CEILING_BY_CHECK`). See docs/ARCH_RECONCILIATION_TRACKING.md.
- I04: the unsound CSRF confirmation is retired. On real targets CSRF is manual-check only
  (LB-5 PoC is self-test only). Unconfirmed cookie-auth candidates show as low-severity
  "NEEDS MANUAL CHECK" items whose next step holds copy-ready steps and a test form.
- I09: caller evidence for label-free body-SQLi and cookie-JWT dispatch; DET-JWT-SCOPE filed.
- I11: LB-FLAKE closed; audit-log file leak fixed; 36 gaps classified in
  docs/COVERAGE_GAP_CLASSIFICATION_2026-10-17.md.
- Handoffs: `.test-work/{i03-transport,i04-csrf,i09-dispatch,i11-hygiene}-20261017-1731/HANDOFF.md`.
- I02-B (2026-10-17) and I02-A (2026-10-19): see the plan's I02 status. Handoffs:
  `.test-work/i02b-history-20261017/HANDOFF.md`, `.test-work/i02a-proofbinding-20261018/HANDOFF.md`.

## Verification
- Verify in the in-repo worktree `.test-work/wt-verify`. Windows Defender deletes
  `file_upload_agent.py` / `FileUploadLogic.java` from worktrees under %TEMP%. Block the
  venv's editable-install leak (it imports modules missing from a worktree from the main
  checkout) with an untracked `sitecustomize.py` there plus `PYTHONPATH=<worktree>`.
- CI runs Python 3.14. Last full verification (`d8eb094` content, isolated worktree
  `.test-work/wt-land`): on both system Python 3.14.7 and venv 3.12.14, precondition 74 OK,
  smoke 146 OK, full exit 0 (3369 harness, 38 pytest, 312 evaluation with 17 artifact-absence
  skips, 42 integrity), 0 ResourceWarnings. The coverage gate reports 25 gaps (was 36).
  Logs: `.test-work/land-20261019/`.
- I05-C was verified at `336f878` + C, and C2+A2 at `ae8f287` + both (isolated worktrees
  `.test-work/wt-verify` and `.test-work/wt-dev`). Both interpreters: smoke 146 OK, full
  exit 0 (3382 then 3397 harness, 38 pytest, 312 evaluation, 42 integrity), coverage gaps
  25. Logs: `.test-work/i05c-*.log`, `.test-work/i05de-*.log`.
- Stopping a background run with TaskStop leaves its process tree running. End it by
  exact PID tree, and never by a pattern that could match another session's processes.

## Owner decisions (2026-10-17)
- `/analyze` grouping: one shared pile per site by default; `engagement_id` = optional named
  pile. The W2 `analyze:<uuid>` server hunk is rejected (do not commit it). A Burp field for the
  named pile is I16 work.

## Open work and evidence boundaries
- Plan: docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md. Partial: I01, I02, I03, I04, I05,
  I09, I11. I02 batches B (default history) and A (proof binding: a missing, stale,
  unresolvable or re-pointed proof no longer exports as confirmed) are fixed. I05 batch A
  (sends escaping their run) is fixed. The I04 storage/export label check and the I11 socket
  trace are done, and 11 of the 14 caller-tested requirements are wired. Next:
  - I05 batches B (redirect/rebinding) and D (browser credential isolation); the no-run
    routes `/crawl`, `/crawl-roles`, `/engagement/{host}/advance`; a real-container proof
    of C (Docker Desktop was off);
  - I02 batch C (non-finding observations): design at
    `.test-work/i02c-observations-20261019/DESIGN.md` awaits owner review;
  - I11: WSTG-ATHZ-02, SESS-01 and INPV-01 are still unwired (blockers in the plan);
  - I16: issue export and SARIF lack `suggested_test` (API and Markdown have it).
- Owner decisions (2026-10-19, I05), now implemented:
  - A standalone `analyze()` publishes its own run (`f7d1321`). Gated validators spend
    `analyze.max_requests` and use the run's TLS policy; trust a self-signed target with
    `transport.tls.ca_bundle` in config.local.yaml. They previously verified against the
    default store with no way to configure trust. The shared Ollama breaker and fail-open
    stats are unchanged.
  - External-tool traffic goes through a counting proxy (`934c3e1`): inside a run sqlmap
    never sees the real target, and an exhausted budget stops it.
- The live Part B crAPI experiment has not been run. Historical negative crAPI results still
  govern efficacy, and offline tests do not establish recall.
- Browser capture covers page-load traffic only; catch-all filtering is conservative.
- Priority-5 release, live Burp validation and the W2/W3 Java edits remain unverified.

## Working rules
- Follow AGENTS.md and the implementation guide; never read answer keys, blind labels or
  blind-target implementations.
- Preserve prior edits; live toggles belong in ignored local config; never `git add -A`.
- Verify in an isolated worktree inside the repo; record exact source identity.
