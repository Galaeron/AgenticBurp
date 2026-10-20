# Code review 02 triage — 2026-10-19

Source: `reviews/2026-10-17-code-review-02/FINAL_REVIEW.md` (untracked), which reviewed
`a7d03b5` plus the main-checkout WIP. Its reproduction scripts (`*_checks.py`,
`boundary_checks.py`) and logs sit beside it. Nothing has landed since `a7d03b5`, so every
finding is open, except R04.

**R04 needs no work.** It is the rejected W2 `analyze:<uuid>` hunk (owner decision
2026-10-17), which exists only as WIP. It closes when I01 drops that hunk from the WIP.

## Rules for every batch

- Read only your findings' sections of FINAL_REVIEW.md: grep `### Rnn`, then read that range.
- Reproduce first with the reviewer's check: its assertion must fail before your fix.
- Then port the check into a harness test that drives the production caller. That test needs:
  - the reviewer's control as the negative control;
  - one fault injection.
- The reviewer's scripts import from the main checkout (`ROOT = parents[1]`). Copy what you need
  into your worktree; do not run them against a worktree unchanged.
- Work in your own in-repo worktree under `.test-work/`, using `sitecustomize.py` +
  `PYTHONPATH` (CURRENT_STATE "Verification").
- Commit on your own branch only. Never push.
- Four files carry main-checkout WIP: `harness/server.py`, `harness/store.py`,
  `harness/orchestrator_detect.py` and `HarnessPanel.java`. Batches touching them:
  - start only after I02-C lands;
  - land from the index, never with a path-limited commit, which would sweep in W1–W4 WIP.
- Verify precondition, smoke and full on Python 3.14 and the 3.12 venv.
- Write exit codes to a summary file and read only that summary.
- Finish with HANDOFF.md, using the guide's section 6 template, and record per finding:
  - the reproduction before the fix;
  - the fix;
  - the control;
  - the fault injection;
  - the status label.

## Batches

P1 findings are in bold. Batches have disjoint files.

| Batch | Findings | Files | Ticket | Start | Model |
|---|---|---|---|---|---|
| RV-A tool cleanup | **R35, R36**, R34, R37 | `tool_proxy.py`, `tool_runner.py`, `testing/egress_probe.py` | I05 | now | Opus |
| RV-B evaluation certification | **R38, R39, R46**, R40, R47, R48 | `evaluation_integrity/audit.py`, `testing/evidence_grade.py`, `testing/run_web_objective_efficacy.py` | I12 | now | Sonnet |
| RV-C evaluation provenance | R41–R45 | `testing/eval_adapter.py`, `rescore_run.py`, `run_captured_analysis.py`, `score.py` | I12 | when a slot frees | Sonnet |
| RV-D false confirmations I | **R09, R14, R16, R17**, R08 | validators: `cors`, `idor_read`, `open_redirect`, `ssrf` | I10 | when a slot frees | Opus |
| RV-E false confirmations II | **R18, R19, R20, R33** | validators: `api_security`, `stored_xss`, `auth_sequence`; `attribution.py` | I10 | when a slot frees | Opus |
| RV-F blocked is not negative | R10, R11, R12 | validators: `cross_identity`, `ssti`; `coverage_tracker.py` | I10 | when a slot frees | Sonnet |
| RV-G no-run routes and settings | **R01, R02, R03, R15**, R07 | `server.py` (`/settings`, `/crawl`, `/crawl-roles`, `/engagement/{host}/advance`, `/probe-missing-auth`) and crawl helpers | I05 (its planned no-run routes) | after I02-C lands | Opus |
| RV-H evidence states | **R49**, R05, R06 | `store.py`, `orchestrator_detect.py`, `orchestrator_confirm.py` | I02 | after I02-C lands | Opus |
| RV-I discovery and anomalies | R13, R21, R22, R23 | `api_surface_discovery.py`, `validators/recon_validator.py`, `worklist_investigator.py`, `agents/anomaly_agent.py` | I06/I07 | when a slot frees | Sonnet |
| RV-J Burp executors | **R25–R29, R31**, R24, R32 | `ValidationExecutor.java`, `logic/OAuthFlowLogic.java`, `logic/CspClickjackingLogic.java` | I16 | needs a JDK build | Opus |
| RV-K Burp UI | R30, R50–R53 | `ui/HarnessPanel.java` (WIP), `ui/AnalysisTracker.java`, `ui/HarnessToolsPanel.java` | I16 | after I01 W-split; needs a JDK | Sonnet |

## Order

1. **Now**, alongside the I05 session (B, then D): RV-A and RV-B. They hold the P1 cleanup
   and certification findings and touch no WIP file. Keep to at most 3 sessions in parallel.
2. **After I02-C lands:** RV-G and RV-H.
   - RV-G replaces I05's separate "no-run routes" item.
   - Run no live target until RV-A, RV-G and RV-H have landed (the review's step 1).
3. **Then** RV-D and RV-E (P1 confirmation soundness, under I10), followed by RV-F, RV-I
   and RV-C.
4. **RV-J and RV-K** need a real JDK/Gradle build (I15). A Java source change without one
   stays labelled unverified.

The review's own disposition of non-promoted hypotheses (its last two sections) stands. It
adds no findings beyond R01–R53.

## Status

Landed on PR #1 (2026-10-19): RV-A and RV-G, verified together at `9d76c5d`. Both are
caller-verified, not live-validated. Handoffs are in `.test-work/rv-a-toolcleanup-20261019/` and
`.test-work/rv-g-norunroutes-20261019/`.

- **RV-A** (`aa97fc2`, `8b5ed4e`, `cf4a264`):
  - R35: the tool proxy's close() is bounded, and a client that stalls for 30 s gets a 408.
  - R36: on Windows, when no Job Object can contain a tool, the harness refuses to start it
    (outcome `containment_unavailable`). The PID-only fallback is removed.
  - R34: a same-origin redirect is returned origin-relative, so a container client keeps its
    own proxy address. This is checked against an emulated container client only.
  - R37: the egress probe records a connection when it is accepted and drains handlers before
    the verdict.
  - Open: real Docker runs of R34 and of the R37 egress proof.
- **RV-G** (`9d76c5d`):
  - R01: `/settings` rejects non-boolean toggles with a 422 (also `coordinator.cloud_reasoning`).
  - R02: `/crawl`, `/crawl-roles` and `/engagement/{host}/advance` each own a run. Every hop,
    redirects included, passes scope, target policy, the safety gate and budget. Caller headers
    stay on the base origin. Their clients are now pinned, which closes I05 B's limit.
  - R03: `/advance` refuses with a 403 while active testing is off.
  - R07: robots.txt paths and query endpoints that look destructive (`/logout` and similar)
    are suppressed and never fetched.
  - R15: `/probe-missing-auth` confirms only when the endpoint is declared protected and a
    matching authenticated baseline exists. Otherwise the result is an unconfirmed
    `unauthenticated_access` candidate.
  - Interim choices, accepted by the owner for now (2026-10-19):
    - the routes have no request ceiling beyond `runs.max_requests` (unset) and their own
      page caps;
    - they never send mutating probes;
    - the Burp "Probe missing auth" panel sends no baseline, so its results stay
      unconfirmed until an I16 Java change adds one.
  - Follow-ups (not findings):
    - A: orchestrator_chain's missing-auth confirm still hardcodes `expected_protected=True`.
    - B: `_require_target_fetch(bulk=True)` could be relaxed for routes that own a run.
    - C: `/probe-missing-auth` creates its runs without `config=`, so config transport
      settings are not applied there.
    - D: `/probe-missing-auth` sends anonymous GETs while active testing is off.

Landed on PR #1 (2026-10-20): RV-B, RV-H and RV-D, verified together at `7cd6fdd`. All are
caller-verified offline, not live-validated. Handoffs are in `.test-work/rv-b-evalcert-20261019/`,
`.test-work/rv-h-evidencestates-20261019/` and `.test-work/rv-d-falseconfirm1-20261019/`.

- **RV-B** (`268358b`, `e1d946f`, `d70e049`):
  - R38: the audit certifies only inputs listed in the run's manifest.
  - R39: a failed health check on any input fails the audit.
  - R40: a single exchange is not a reproduced baseline/attack differential.
  - R46: the efficacy runner requires an attempt artifact carrying its own run ID and a
    successful exit; an old `attempt.json` in a reused folder is not loaded.
  - R47: a `done` attempt with degraded health is an error, not verified evidence.
  - R48: only real booleans count for `objective_verified`; the string `"false"` does not.
  - Follow-ups:
    - one failed attempt in a batch makes `assemble_run` raise, so the scorecard is lost
      (fail-closed);
    - five other `build_audit` fields still read only the first input;
    - the R46 exit-code contract comes from the untracked `run_web_objective_smoke.py`.
    - artifacts from a test-supplied `runner_fn` are not run-ID checked.
- **RV-H** (`7beb9de`, `a5c7378`, `7fba139`):
  - R49: a missing proof also demotes `oracle_verified` and `verification_state`, so the
    Markdown report no longer shows VERIFIED. Issue export and SARIF were already correct; a
    test now pins them.
  - R05: a standalone `analyze()` in active mode binds the capture's own Authorization/Cookie
    as a run session limited to the captured origin, so bound validators can send.
  - R06: a crashed validator returns a `status="error"` report (never a controlled negative).
  - Follow-ups: engagement-owned runs keep their own session seeding (not re-tested);
    `scope_discovery` (off by default) now sends as the capture in active mode.
- **RV-D** (`6533b18`, `4d9395a`, `2567133`, `0917073`, `7cd6fdd`):
  - R09: CORS confirms only an origin grant to the actual probe origin.
  - R08: an unrun CORS probe is `blocked`, not safe.
  - R14: IDOR needs a protected object (anonymous read refused); public sequential records
    stay candidates. It costs one extra anonymous GET per object.
  - R16: open redirect needs a redirect status and a parsed off-origin Location.
  - R17: an in-band SSRF response difference is a candidate; confirmation needs out-of-band
    evidence. The out-of-band probes now always run.
  - The evaluation score is unchanged. Two existing tests encoded the unsound confirmations
    and were updated, not weakened.
  - **The false-confirmation work is not closed.** The independent verification
    (`reviews/2026-10-20-rv-implementation-verification/REPORT.md`, untracked) reproduced
    three P1 residuals at `7cd6fdd` through the production callers:
    - V1: an anonymous control that returns HTTP 500 counts as "access refused", so IDOR
      confirms;
    - V2: Alice reading two of her own protected objects confirms IDOR. A single principal
      cannot show the object belongs to someone else (the follow-up RV-D recorded);
    - V3: `Access-Control-Allow-Origin: *` with credentials still confirms credentialed
      cross-origin reads, which the Fetch standard forbids.
    - None is a regression: the code before RV-D confirmed all three as well. Batch RV-D2
      (brief `.test-work/rv-d2-falseconfirm-residual-20261020/BATCH.md`) owns them.
  - Other follow-up: all-failed sends in SSRF's out-of-band step and in open redirect still
    read as negatives.

Independent verification (same report) of the code at `7cd6fdd`, exported with `git archive`:
- A, G, H and B pass their scoped checks (159 focused tests, with controls and fault
  injections). Real Docker networking for RV-A was simulated, not tested in a container.
- RV-B's default objective runner, `testing/run_web_objective_smoke.py`, is untracked, so a
  clean checkout cannot run the default efficacy attempt. This predates RV-B. Committing or
  replacing that runner needs an owner decision.
- RV-C is still open: all five findings reproduce (it had not started).

RV-A, RV-G and RV-H have now landed. The review's "no live target" gate is lifted, but any live
target still needs the owner's authorization.

Landed on PR #1 (2026-10-20): RV-E, RV-F and RV-I, verified together at `c648dbd`. All are
caller-verified offline, not live-validated. Handoffs are in `.test-work/rv-e-falseconfirm2-20261020/`,
`.test-work/rv-f-blockednotneg-20261020/` and `.test-work/rv-i-discovery-20261020/`.

- **RV-E** (`b50ccad`, `78e71dc`, `59d5005`, `10e09f4`, `f59f91b`):
  - R18: mass assignment needs an accepted write and an independent read-back. A rejected
    request that echoes the field is a candidate.
  - R19: a raw stored-payload match is a candidate; only the planted nonce executing in a
    browser confirms. Without Playwright, stored XSS is now at most inconclusive.
  - R20: session fixation needs a successful login and authenticated use of the fixed
    identifier. An HTTP 401 with an unrotated cookie no longer confirms.
  - R33: attribution relabels from the leg that executed, never from an unexecuted hint.
  - Stored-XSS tests in two files and the session-fixation fixture encoded the unsound
    confirmations. They were changed to supply real execution or login evidence; their
    assertions stand. The evaluation score is unchanged.
  - **The false-confirmation work is not closed.** A second independent verification
    (`reviews/2026-10-20-rvei-implementation-verification/REPORT.md`, untracked) confirmed R33
    and reproduced three P1 residuals at `c648dbd` through the production callers:
    - E1 (R18): the probe field may already be true before a write that changes nothing; no
      baseline read shows the write changed it;
    - E2 (R19): the nonce matches as a substring of console text, so a page that logs the
      inert payload's source counts as execution (reproduced with real Chromium);
    - E3 (R20): an anonymous HTTP 500 or timeout counts as a session denial (the V1 shape).
    - None is a regression: the code before RV-E confirmed on weaker evidence. Batch RV-E2
      (brief `.test-work/rv-e2-falseconfirm-residual-20261020/BATCH.md`) owns them.
  - Follow-ups:
    - api_security probes that were blocked or unsent still read as passed (R08 shape);
    - the unbounded-limit probe still confirms on a response-size heuristic;
    - two coverage-manifest descriptions (`fixation_confirm`, `stored_xss_confirm`) are out
      of date;
    - leg_self_test's xss case should say it needs Playwright.
- **RV-F** (`9e6461b`, `3e5010b`, `67c07d8`, `937b927`):
  - R10: a cross-identity request that was refused or never sent is `blocked`, never a held
    control.
  - R11: only an executed negative counts as tested coverage; a blocked or skipped leg is
    untested.
  - R12: stored SSTI checks the restore's outcome, discloses residual state, and refuses a
    plant whose restore it cannot afford. Under the default gate (one write per finding) the
    stored-SSTI leg is now `blocked`; `validators.mutating_ceiling_by_check: {ssti: 2}` in
    config.local.yaml enables it.
  - Owner decision (2026-10-20, recorded in RV-F's handoff): stored SSTI stays opt-in, with
    no built-in `ssti` allowance.
  - Owner decision open: whether cleanup should run after cancellation (the restore does not
    pass `allow_cancelled_cleanup`).
  - Follow-ups:
    - `SafetyGate` needs a public headroom accessor; the fix reads private fields and fails
      closed without them;
    - `CoverageMatrix.not_tested()` omits BLOCKED, INCONCLUSIVE and ERROR cells from its list;
    - an SSTI check whose sends all failed still reads as a negative.
- **RV-I** (`30ff6d3`, `fb2fe3a`, `b4344ff`, `c648dbd`):
  - R13: the Allow header is read case-insensitively.
  - R21: recon selects crawl links on the fetched set, so captured links are requested. Scope
    and the destructive-navigation filter still apply.
  - R22: each captured path ID is replayed in its own slot. This adds `path_ids` and
    `path_id_values()` to `harness/engagement.py`, outside the batch's file list; the owner
    approved it (2026-10-20).
  - R23: header names are normalised once before anomaly analysis.
  - The second verification confirmed R13, R21, R22 and R23 independently.
  - Follow-ups:
    - a nested child with no template of its own still gets its parent's single ID in every
      slot;
    - templates stored before this change keep the old behaviour;
    - links shown only in the captured page, not the live page, are still not crawled (a
      design decision).

Next: RV-C (branch `rv-c-evalprovenance`) and RV-J (branch `rv-j-burpexecutors`) have
committed fixes, not yet landed. RV-D2 (P1) and RV-E2 (P1) are running their gates. RV-K waits
for the I01 W-split, because `HarnessPanel.java` carries WIP.
