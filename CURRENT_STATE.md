# Current state — 2026-10-21

## Checkout
- Branch `reconciliation-backlog`; base `474ad511`; head of
  [Galaeron/AgenticBurp#1](https://github.com/Galaeron/AgenticBurp/pull/1) after today's push.
  Auto-fix is on for PR #1.
- Commits: `git log --oneline 474ad511..HEAD` (each batch is followed by a docs commit).
  Latest: the owner's merge of RV-O to RV-S (`49be218`), then the cross-request audit's fix
  batch 1 (`823ff4e`..`7a05995`, after its audit notes `71e8f12`). Before them: the code review
  02 follow-ups RV-L, RV-M and RV-N and batches RV-A to RV-J, RV-D2 and RV-E2. All pushed to
  PR #1.
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
- CI runs Python 3.14. Last full verification: `7a05995` exactly (isolated worktree
  `.test-work/wt-land-xreq2`, unchanged during the run).
  - Interpreters: system Python 3.14.7 and venv 3.12.14, with the same results on both.
  - Results: precondition 74 OK, smoke 147 OK, full exit 0.
  - Full breakdown: 3931 harness, 381 evaluation (17 skips), 59 integrity.
  - 0 ResourceWarnings; the coverage gate reports 25 gaps.
  - Java: `gradle clean test shadowJar` exit 0, 374 tests. Run Gradle 8.7 offline on the
    in-repo JDK 17 (`.audit-external/toolchains/jdk17`) with `GRADLE_RO_DEP_CACHE` set to
    `.audit-external/gradle-cache/caches`; Gradle 8.7 cannot run on the host's JDK 27.
  - Logs: `.test-work/land-xreq2-20261021/`.
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
- 2026-10-21, answers to the RV-L, RV-M and RV-N questions:
  - An MFA step-up redirect (e.g. `/2fa/verify`) is not a denial. The MFA-bypass anonymous
    control takes the rule IDOR and session fixation use (HTTP 401/403, a redirect to a login
    path or a 2xx login page); any other answer leaves a candidate. Landed with RV-R.
  - CORS origin reflection without credentials still confirms, with a clear note: without
    credentials a cross-origin page reads only what it could fetch without the user's cookies.
    Landed with RV-R.
  - api_security's unbounded-limit threshold stays at 1000 counted items.
  - XSS must not miss a sink that only runs `alert()`. A dialog showing the payload's computed
    value confirms, and the result says execution was shown by a dialog only. Any other dialog
    or page error is a clearly labelled candidate, never `not_confirmed`. This applies to
    stored, browser and DOM XSS (landed with RV-O, item O8).
  - The Burp CSRF marker write (one free-text field, up to 6 requests) is accepted.
  - Protected routes come from an operator list of path patterns per target (config.local.yaml
    or the engagement). The chain may confirm missing auth only on a listed route; an unlisted
    route stays a candidate. Landed with RV-S; operator guide docs/PROTECTED_ROUTES.md.
- 2026-10-21, the cross-request branch `fix/cross-request-main-issues` (WL-02, WL-04, WL-05,
  WL-11, WL-12; reviews/2026-10-21-dual-mode-cross-request-audit/FIX_BATCH_1.md) is accepted.
  It landed on PR #1 after RV-S, with WL-04's rule below. Batch RV-T implements the other
  decisions (brief `.test-work/rv-t-crossrequestdecisions-20261021/BATCH.md`):
  - WL-04: a cross-user match without declared ownership is a clearly labelled lead
    (`supported`, "LEAD (not confirmed)", with `manual_verification`), never a confirmation
    or a negative. This answers RV-D2's IDOR question too: leads carry the guidance, and an
    operator declaration counts as ownership evidence.
  - D1: ownership and entitlement are declared per target in config.local.yaml, in the same
    `authz:` block as RV-S's protected paths (`authz.owners`: object URLs or route patterns
    in RV-S's syntax, with owner, shared_with, public, and "all authenticated users" as a
    flag), plus an optional engagement list. The Burp and API wiring goes with I16.
  - D4: `privacy.external_lookups` stays `true` by default, disclosed;
    `operating_profile: passive-only` implies `false`.
  - A confirmed sensitive file takes its severity from its class: private keys and `.env`
    files with credentials high; VCS metadata, backups and config dumps medium;
    existence-only candidates low or informational.
  - The plan-execute driver gets its own request ceiling, nested inside the run's budget.
- Needed (from RV-D2, RV-E2, RV-J and RV-M; the strict interim behaviour has landed):
  - Mass assignment: a confirmation is medium severity (the probe field is invented metadata),
    and a value seen only on a new object's Location is a candidate.
  - RV-J changed five `*Logic` classes outside its file list (used only by
    `ValidationExecutor`, no WIP) and built on JDK 17. Review on PR #1.

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
    - RV-D: false confirmations in CORS, IDOR, open redirect and SSRF;
    - RV-E: false confirmations in mass assignment, stored XSS, session fixation and
      attribution;
    - RV-F: blocked or unsent checks are not negatives; stored SSTI checks its restore;
    - RV-I: discovery and anomaly analysis keep what was captured;
    - RV-C: evaluation provenance (rescore status, manifest hash, duplicate records, payload
      health, historical labels);
    - RV-J: Burp executors (upload fetch-back, CSRF, JWT, mass assignment, XSS, takeover,
      OAuth, CSP);
    - RV-D2 and RV-E2: the six P1 residuals the two independent verifications found (V1 to V3,
      E1 to E3);
    - RV-L: failed or unsent sends in SSRF, open redirect, SSTI and api_security are not
      negatives; api_security's size heuristic; browser and DOM XSS; the MFA control;
    - RV-M: chain missing-auth confirmation, coverage records, manifest, leg_self_test;
    - RV-N: Burp executors (CSRF read-back and headers, JWT carriers, create-style read-back,
      XSS handler contexts);
    - RV-O: failed sends in header injection, command injection, stored XSS and cache
      poisoning are not negatives; SSRF waits out the callback window; coverage records list
      pending, blocked and inconclusive checks; the XSS dialog rule (O8);
    - RV-P: validators whose broad `except` swallowed a failed send (client trust,
      deserialization OOB, rate limit, TOCTOU, verb tampering, path traversal, the source
      form, file upload, JWT forging, reset token);
    - RV-Q: Burp executors (CSRF Origin/Referer and requests a form cannot send, JWT
      non-credential cookies, mass-assignment id keys, XSS script types and `<template>`);
    - RV-R: an MFA step-up redirect is not a denial; the CORS credentials note;
    - RV-S: missing auth confirms only on an operator-declared protected route
      (`authz.protected_paths`, docs/PROTECTED_ROUTES.md).
  - The cross-request audit's fix batch 1
    (reviews/2026-10-21-dual-mode-cross-request-audit/FIX_BATCH_1.md): BOLA/BFLA confirm only
    against declared ownership, otherwise a labelled lead (WL-04); sensitive files by content
    signature (WL-05); one bounded run for `/engagement/{host}/run` (WL-12); a per-principal
    access matrix (WL-02); disclosed and switchable third-party lookups
    (`privacy.external_lookups`, WL-11).
    - Status and follow-ups: docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md "Status".

  Next:
  - Code review 02 (`reviews/2026-10-17-code-review-02/FINAL_REVIEW.md`, untracked) has 5
    open findings, all in batch RV-K of docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md. RV-K waits
    for the I01 W-split (`HarnessPanel.java` carries WIP).
    - The two independent verifications (`reviews/2026-10-20-rv-implementation-verification/`
      and `reviews/2026-10-20-rvei-implementation-verification/`, untracked) found six P1
      residuals, none a regression. RV-D2 and RV-E2 fixed them.
    - RV-T (the cross-request decisions: `authz.owners`, passive-only lookups, sensitive-file
      severity by class, the driver's own ceiling) is next. Brief:
      `.test-work/rv-t-crossrequestdecisions-20261021/BATCH.md`. Until it lands, no cross-user
      BOLA/BFLA can confirm: `ValidatorRegistry.set_ownership` has no production caller, so
      every crossing is a lead.
    - RV-P's sweep found more validators that swallow a failed send: idor_read,
      http_request_smuggling, race_condition, oauth, subdomain_takeover and crypto (partly).
    - Residuals recorded by RV-O to RV-S (detail in each handoff,
      `.test-work/rv-{o-unsentround2,p-swallowedsends,q-burpround3,r-ownerdecisions,s-protectedroutes}-20261021/HANDOFF.md`):
      - RV-O: `store.coverage_report` says tested_clean despite blocked or inconclusive rows;
        `active_verification._STATUS_MAP` maps an unknown status to not confirmed; a partial
        browser or DOM XSS visit error is still `not_confirmed`; SSTI is skipped on refusal;
        `GatedAsyncClient` loses a ConnectError's class.
      - RV-Q: `Origin: null` and method override are not tried; SameSite cookies are not
        modelled, so a confirmed CSRF can be one a browser would not carry out; a
        `<script src>` or `nomodule` script still counts as executable.
      - RV-R: a validator's text does not reach a stored finding that has its own evidence
        (`store.py`, `issues.py`, `report_generator.py`); a null-origin CORS grant does not
        check credentials; the CORS result drops its computed severity; an anonymous 2xx
        step-up page with a password field still confirms MFA bypass (owner decision if
        wanted).
      - RV-S: nothing sets the engagement's protected-route list (I16: `server.py`,
        `HarnessPanel.java`, `store.py`); an app authenticating only through a custom header
        cannot confirm missing auth; the probe's own `_strip_auth` keeps unknown credential
        headers for its other callers.
      - Cross-request (FIX_BATCH_1.md): `worklist_investigator` probes are keyed by role
        (I06); `/engagement/{host}/run` has no HTTP cancel route; coverage_tracker maps
        `supported` as inconclusive without `reachable_principals`.
    - At most three batch sessions run at once.
    - Blocked on the I01 W-split (`store.py` carries WIP): api_security confirmations are not
      persisted, because `store.persist_validation_submission` refuses a capability outside
      `confirmation_capabilities` (pre-existing; RV-L found it).
    - Owner decision open from RV-F: whether cleanup runs after cancellation.
    - Owner decision needed: `testing/run_web_objective_smoke.py`, the efficacy runner's
      default, is untracked, so a clean checkout cannot run it.
    - RV-A, RV-G and RV-H have landed, so the review's live-target gate is met. Any live
      target still needs the owner's authorization.
  - I05 batch D (browser credential isolation) has committed fixes on branch
    `i05d-browser-credentials` (handoff `.test-work/i05d-browsercreds-20261020/HANDOFF.md`). Its
    gates pass at `78ebfef` on 3.14 and 3.12 (full 3660 harness; 23 isolation tests on real
    Chromium). It lands only after the owner's review (containment change). A real-container
    proof of C is still missing (Docker Desktop was off);
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
