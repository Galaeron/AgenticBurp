# Current state — 2026-10-20

## Checkout
- Branch `reconciliation-backlog`; base `474ad511`; head of
  [Galaeron/AgenticBurp#1](https://github.com/Galaeron/AgenticBurp/pull/1) after today's push.
  Auto-fix is on for PR #1.
- Commits: `git log --oneline 474ad511..HEAD` (each batch is followed by a docs commit).
  Latest: code review 02 RV-E (`b50ccad`..`f59f91b`), RV-F (`9e6461b`..`937b927`) and RV-I
  (`30ff6d3`..`c648dbd`), after RV-A, RV-G, RV-B, RV-H and RV-D. All pushed to PR #1.
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
- I02-B (2026-10-17), I02-A and I02-C (2026-10-19): see the plan's I02 status. Handoffs:
  `.test-work/i02b-history-20261017/`, `.test-work/i02a-proofbinding-20261018/`,
  `.test-work/i02c-observations-20261019/` (HANDOFF.md in each).

## Verification
- Verify in the in-repo worktree `.test-work/wt-verify`. Windows Defender deletes
  `file_upload_agent.py` / `FileUploadLogic.java` from worktrees under %TEMP%. Block the
  venv's editable-install leak (it imports modules missing from a worktree from the main
  checkout) with an untracked `sitecustomize.py` there plus `PYTHONPATH=<worktree>`.
- CI runs Python 3.14. Last full verification: `c648dbd` exactly (isolated worktree
  `.test-work/wt-land-rvefi`, unchanged during the run).
  - Interpreters: system Python 3.14.7 and venv 3.12.14, with the same results on both.
  - Results: precondition 74 OK, smoke 146 OK, full exit 0.
  - Full breakdown: 3613 harness, 342 evaluation (17 skips), 59 integrity.
  - 0 ResourceWarnings; the coverage gate reports 25 gaps.
  - Logs: `.test-work/land-rv-efi-20261020/`.
- Stopping a background run with TaskStop leaves its process tree running. End it by
  exact PID tree, and never by a pattern that could match another session's processes.

## Owner decisions
- 2026-10-17, `/analyze` grouping: one shared pile per site by default; `engagement_id` = optional named
  pile. The W2 `analyze:<uuid>` server hunk is rejected (do not commit it). A Burp field for the
  named pile is I16 work.
- RV-G interim choices accepted for now (2026-10-19): no request ceiling for the crawl routes
  beyond `runs.max_requests`; the routes send no mutating probes; the Burp missing-auth panel
  stays unconfirmed until I16 adds a baseline.
- 2026-10-20: RV-I's additive `harness/engagement.py` edit (R22 `path_ids`) approved.
- 2026-10-20: stored SSTI stays opt-in (no built-in `ssti` write allowance). Under the default
  gate it reports `blocked`; `validators.mutating_ceiling_by_check: {ssti: 2}` in
  config.local.yaml enables it.

## Open work and evidence boundaries
- Plan: docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md. Partial: I01, I02, I03, I04, I05,
  I09, I11. Fixed so far:
  - I02 batches B (default history), A (proof binding: a missing, stale, unresolvable or
    re-pointed proof no longer exports as confirmed) and C (supplied captures without
    findings are kept as observations).
  - I05 batches A (sends escaping their run), C/C2/A2 (tool lifecycle, counting proxy,
    standalone analyze) and B (redirect and DNS-rebinding destination policy).
  - The I04 storage/export label check and the I11 socket trace; 11 of the 14
    caller-tested requirements are wired.
  - Code review 02 batches:
    - RV-A: tool proxy, Job Object fail-closed, egress probe;
    - RV-G: no-run routes own a run, `/settings` strict booleans, missing-auth probe
      confirmation;
    - RV-B: evaluation certification;
    - RV-H: evidence states (no VERIFIED without proof, standalone session, crash is error);
    - RV-D: false confirmations in CORS, IDOR, open redirect and SSRF (V1 to V3 remain,
      below);
    - RV-E: false confirmations in mass assignment, stored XSS, session fixation and
      attribution;
    - RV-F: blocked or unsent checks are not negatives; stored SSTI checks its restore;
    - RV-I: discovery and anomaly analysis keep what was captured.
    - Status and follow-ups: docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md "Status".

  Next:
  - Code review 02 (`reviews/2026-10-17-code-review-02/FINAL_REVIEW.md`, untracked) has 18
    open findings, in batches RV-C, RV-J and RV-K of
    docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md.
    - Independent verification (`reviews/2026-10-20-rv-implementation-verification/REPORT.md`,
      untracked) found three P1 false confirmations RV-D left: V1 IDOR on an anonymous
      HTTP 500, V2 single-principal IDOR, V3 wildcard CORS with credentials. Batch RV-D2 owns
      them; none is a regression.
    - A second verification (`reviews/2026-10-20-rvei-implementation-verification/REPORT.md`,
      untracked) confirmed RV-I and R33, and found three P1 residuals RV-E left: E1 mass
      assignment without a baseline, E2 the XSS nonce matched as a substring of console text,
      E3 an anonymous HTTP 500 or timeout taken as a session denial. Batch RV-E2 owns them;
      none is a regression.
    - RV-C and RV-J have committed fixes on their own branches, not yet landed. RV-D2 and
      RV-E2 are running their gates. RV-K waits for the I01 W-split (`HarnessPanel.java`
      carries WIP).
    - Owner decision open from RV-F: whether cleanup runs after cancellation.
    - Owner decision needed: `testing/run_web_objective_smoke.py`, the efficacy runner's
      default, is untracked, so a clean checkout cannot run it.
    - RV-A, RV-G and RV-H have landed, so the review's live-target gate is met. Any live
      target still needs the owner's authorization.
  - I05 batch D (browser credential isolation; brief at
    `.test-work/i05d-browsercreds-20261019/BATCH.md`) and a real-container proof of C
    (Docker Desktop was off);
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
  - The connect-time pin is ON by default (`bcd56c9`, owner accepted). A run connects each
    name to its first resolved address. It refuses link-local (including cloud metadata),
    multicast, unspecified and reserved answers. Opt out with
    `security.pin_connect_address: false` in config.local.yaml. Private and loopback
    first answers are accepted, for lab targets. Behind an HTTP(S) proxy, only the
    connection to the proxy is pinned.
- The live Part B crAPI experiment has not been run. Historical negative crAPI results still
  govern efficacy, and offline tests do not establish recall.
- Browser capture covers page-load traffic only; catch-all filtering is conservative.
- Priority-5 release, live Burp validation and the W2/W3 Java edits remain unverified.

## Working rules
- Follow AGENTS.md and the implementation guide; never read answer keys, blind labels or
  blind-target implementations.
- Preserve prior edits; live toggles belong in ignored local config; never `git add -A`.
- Verify in an isolated worktree inside the repo; record exact source identity.
