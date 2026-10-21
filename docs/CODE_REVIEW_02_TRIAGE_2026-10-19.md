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
  - **RV-D did not close the false-confirmation work; RV-D2 did (below).** The independent
    verification (`reviews/2026-10-20-rv-implementation-verification/REPORT.md`, untracked)
    reproduced
    three P1 residuals at `7cd6fdd` through the production callers:
    - V1: an anonymous control that returns HTTP 500 counts as "access refused", so IDOR
      confirms;
    - V2: Alice reading two of her own protected objects confirms IDOR. A single principal
      cannot show the object belongs to someone else (the follow-up RV-D recorded);
    - V3: `Access-Control-Allow-Origin: *` with credentials still confirms credentialed
      cross-origin reads, which the Fetch standard forbids.
    - None is a regression: the code before RV-D confirmed all three as well. Batch RV-D2
      (brief `.test-work/rv-d2-falseconfirm-residual-20261020/BATCH.md`) fixed them.
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
  - **RV-E did not close the false-confirmation work; RV-E2 did (below).** A second
    independent verification
    (`reviews/2026-10-20-rvei-implementation-verification/REPORT.md`, untracked) confirmed R33
    and reproduced three P1 residuals at `c648dbd` through the production callers:
    - E1 (R18): the probe field may already be true before a write that changes nothing; no
      baseline read shows the write changed it;
    - E2 (R19): the nonce matches as a substring of console text, so a page that logs the
      inert payload's source counts as execution (reproduced with real Chromium);
    - E3 (R20): an anonymous HTTP 500 or timeout counts as a session denial (the V1 shape).
    - None is a regression: the code before RV-E confirmed on weaker evidence. Batch RV-E2
      (brief `.test-work/rv-e2-falseconfirm-residual-20261020/BATCH.md`) fixed them.
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

Landed on PR #1 (2026-10-20): RV-C, RV-J, RV-D2 and RV-E2, verified together at `7a97e6e`. All are
caller-verified offline, not live-validated. Handoffs are in `.test-work/rv-c-evalprovenance-20261020/`,
`.test-work/rv-j-burpexecutors-20261020/`, `.test-work/rv-d2-falseconfirm-residual-20261020/` and
`.test-work/rv-e2-falseconfirm-residual-20261020/`.

- **RV-C** (`63876e9`, `a9cb68e`, `c4e5a4d`, `ca2ffe3`):
  - R41: a rescore keeps the source's completion status. A source that does not state
    completion counts as incomplete.
  - R42: the rescore refuses a manifest whose hash does not match its records, before scoring
    (the CLI exits 2).
  - R43: identical case records for one case id collapse to one. Conflicting records stay
    ambiguous.
  - R44: each captured exchange needs HTTP 200, a non-empty `agent_reports` list and a boolean
    `degraded`. Degraded or agent-error exchanges count against the existing 10% tolerance.
  - R45: a cache rescore is labelled `historical` and binds to the cache (`run_id`
    `cache:<inputs_hash>`), not to the revision that rescored it.
  - Two existing tests encoded the unsound behaviour: a `{}` analysis fixture in
    `test_remote_run_provenance.py` (now a healthy analysis) and a test that accepted `fresh`
    for a cache rescore (now requires `historical`). No assertion was loosened. Evaluation
    metrics are unchanged; 39 evaluation tests were added.
  - Follow-ups:
    - the fixture cache stores no git revision, so a historical rescore cannot name the
      revision that produced it;
    - the new payload rule is not checked against a live server.
- **RV-J** (`3991a58`..`69e5fcb`, 10 commits):
  - R24: the upload fetch-back is a GET with no upload body or headers.
  - R25: CSRF confirms only an ambient-cookie request that succeeds without its token, with a
    no-cookie control refused.
  - R26: a JWT bypass needs a refused no-token control.
  - R27: mass assignment needs a successful write and a read-back that shows the field absent
    before and present after.
  - R28: XSS proof needs the whole payload, canary included, in an executable context.
  - R29: a takeover fingerprint is a lead (SUPPORTED). Nothing gathers DNS or
    provider-ownership evidence, so a takeover never confirms.
  - R31: OAuth compares the parsed Location host.
  - R32: CSP frame-ancestors source lists are parsed; a list that admits any origin is not
    protection.
  - The R25–R29 rules live in five `*Logic` classes outside the batch's file list
    (`CsrfLogic`, `JwtForgeryLogic`, `MassAssignmentLogic`, `XssPayloadLogic`,
    `SubdomainTakeoverLogic`). Only `ValidationExecutor` uses them, and none carried WIP.
    Existing tests that confirmed on reflection or on a fingerprint were changed; none was
    loosened.
  - Build: offline Gradle 8.7 on the in-repo JDK 17 (`.audit-external/toolchains/jdk17`),
    because Gradle 8.7 cannot run on JDK 27.
  - Follow-ups:
    - the CSRF and JWT controls strip only `Authorization`, not a token carried in a cookie or
      a custom header;
    - CSRF counts any 2xx as a state change;
    - the mass-assignment read-back uses the write's own path, so create-style endpoints stay
      SUPPORTED;
    - the XSS JavaScript check covers `<script>` blocks only;
    - R25–R27 send extra control requests, so request counts rise.
- **RV-D2** (`e84cacc`, `f190ffc`, `473c252`):
  - V1: the IDOR anonymous control marks an object protected only on HTTP 401/403, a redirect
    to a login path or a 2xx login page. A 5xx, a 404, any other answer or a transport failure
    leaves a weaker candidate. The absent-id control must now be answered, and not with a 5xx.
  - V2: `idor_read` never confirms. A protected object that one session can read is an
    `inconclusive` candidate naming the missing evidence: a second identity (cross_identity) or
    a manual ownership check.
  - V3: `Access-Control-Allow-Origin: *` with credentials is informational, not a grant; the
    Fetch standard rejects that pair for credentialed requests.
  - Four existing tests encoded these confirmations: RV-D's cross-principal test, two
    `test_idor_read_validator` confirmations and the wildcard-with-credentials CORS test. They
    now assert the candidate or informational result; none was loosened. The evaluation score
    is unchanged.
  - Follow-ups:
    - recall: a single-principal IDOR now confirms only through cross_identity, which needs a
      registered second identity;
    - comments in `orchestrator_chain.py` and `objective_profiles.py` still say the read
      differential confirms (batch RV-M);
    - owner decisions: `manual_verification` guidance for the IDOR candidate, and whether a
      declared victim id counts as ownership evidence;
    - an anonymous 404 is treated as uninterpretable, though some apps hide protected objects
      behind a 404;
    - origin reflection without credentials still confirms (batch RV-L records it for an owner
      decision).
- **RV-E2** (`ab63dd4`, `51d5f4e`, `408f717`, `a56caea`, `7a97e6e`):
  - E1: mass assignment reads a baseline first, submits a value the baseline lacks, and confirms
    only on an accepted write followed by a read-back that holds that value. The wording calls
    the field harness-invented metadata: a confirmation shows the endpoint binds an unknown
    field, not that a protected property can change. Severity is medium.
  - E2: the stored-XSS payload logs the product of two random operands, and only a console
    message exactly equal to that product confirms. Dialogs, page errors and echoed source no
    longer count.
  - E3: session fixation counts as denied only on HTTP 401/403, a redirect to a login path or a
    2xx login page (the V1 rule). A 5xx, a 404 or a timeout leaves a candidate.
  - Existing tests changed only for the new request sequence (an extra baseline GET) and the
    payload shape (the doubles compute the product); their assertions are unchanged. The
    evaluation score is unchanged.
  - Follow-ups:
    - the MFA-bypass anonymous control has the E3 shape, and browser and DOM XSS have the E2
      shape (batch RV-L; whether an MFA step-up redirect counts as a denial is an owner
      decision);
    - owner decisions: a value seen only on a new object's Location is a candidate; a
      mass-assignment confirmation is medium severity; a 302 to a non-login page is
      inconclusive.
- **RV-L** (`e75827c`..`a28d6dd`, 9 commits; follow-ups of RV-D, RV-E, RV-F and RV-E2):
  - L1 to L3: in SSRF, open redirect and SSTI, a send refused by scope, gate or budget is
    `blocked` and a transport failure is inconclusive, naming the failed sends. A partial
    failure that leaves a confirming probe unsent is inconclusive.
  - L4: api_security probes that were blocked or never sent are `blocked`, never passed.
  - L5: the unbounded-limit probe confirms only when a large requested limit returns at least
    1000 items counted in the parsed body, more than a small limit and any declared cap. Bytes
    alone stay a candidate.
  - L6: `SafetyGate.mutating_headroom` is a public read-only accessor. SSTI uses it and still
    fails closed.
  - L7: browser and DOM XSS confirm only on a console message exactly equal to a computed
    product (RV-E2's rule). A dialog or page error never confirms.
  - L8: in the MFA-bypass anonymous control, a 5xx, a 404 or a transport error is never a
    denial. A step-up redirect still counts as one (owner decision).
  - Existing tests changed: the browser and DOM XSS doubles compute the product, and
    `test_confirms_on_dialog_execution` became `test_dialog_alone_does_not_confirm`. The
    evaluation score is unchanged.
  - Follow-ups:
    - a record-only sweep found header_injection, command_injection, stored_xss and
      web_cache_poisoning ending `not_confirmed` when every send failed (batch RV-O), and eight
      validators it could not reach that swallow a failed send (batch RV-P);
    - SSRF: a timed-out out-of-band send does not wait for a late callback (batch RV-O);
    - api_security confirmations are not persisted: `store.persist_validation_submission`
      refuses a capability outside `confirmation_capabilities`. This is pre-existing, and
      `store.py` carries WIP;
    - owner decisions: the MFA step-up redirect, CORS reflection without credentials
      (reproduced through the production caller) and the 1000-item threshold.
- **RV-M** (`399ea5d`..`a584384`, 6 commits; follow-ups of RV-G, RV-D2, RV-E and RV-F):
  - M1: the chain no longer takes `expected_protected` from a model label. It passes `False`,
    so it cannot confirm missing auth until protected routes can be declared; the probe still
    reports an unconfirmed candidate.
  - M2: `CoverageMatrix.not_tested()` lists blocked, inconclusive and errored cells too.
  - M3: the manifest describes the current session-fixation and stored-XSS rules.
  - M4: leg_self_test's xss case reports "needs Playwright" when Playwright is absent, through
    `run_self_test(report_out=...)`.
  - M5: comments no longer say the single-principal IDOR read confirms.
  - Follow-ups:
    - a declaration source for protected routes (engagement or operator config) needs
      `engagement.py` or `server.py`;
    - `not_tested()` omits PENDING and RUNNING cells, and the self-test's reasons reach the log
      but not the run report (batch RV-O);
    - three test names and a `LEG_VERIFICATION.md` line still state the old rules (batch RV-O);
    - `playwright_available()` checks only the import (`browser_driver.py` belongs to I05 batch
      D).
- **RV-N** (`2efec4c`..`b8e8057`, 5 commits; RV-J's follow-ups):
  - N1: CSRF confirms only a change read back: the marker is absent before the forged request
    and present in two reads after. A 2xx alone is SUPPORTED.
  - N2: the CSRF forged request keeps only headers a cross-site form can make a browser send,
    and invalidates every token carrier. The JWT probes find the token in any carrier
    (Authorization, another header, a cookie) and remove every other credential. A refused
    forged token counts as REJECTED only when the original token alone is accepted.
  - N3: mass assignment reads a created object back through a same-origin Location or a
    top-level `id`.
  - N4: XSS recognises a quote breakout in an event handler or a `javascript:` URL.
  - Gradle: 335 tests (293 before); each commit passes on its own. Existing tests changed:
    `ValidationExecutorSoundnessTest.cookieGatedTokenIgnored` is store-backed and
    `CsrfLogicTest` passes a shown read-back; none was loosened.
  - Follow-ups (batch RV-Q unless noted):
    - CSRF keeps the captured Origin and Referer, so a server defended only by an Origin or
      Referer check is confirmed (pre-existing false confirmation);
    - a JSON Content-Type, which needs a preflight cross-site, is treated as form-sendable;
    - JWT: a needed non-credential cookie gives INCONCLUSIVE;
    - N3 finds only `Location` or a top-level `id`;
    - XSS: a non-JavaScript `<script type>` and `<template>` content count as executable;
    - owner decision: the CSRF marker is a real write to one free-text field, and a run sends
      up to 6 requests.

RV-O to RV-S landed together through the owner's merge `49be218` (handoffs in
`.test-work/rv-{o-unsentround2,p-swallowedsends,q-burpround3,r-ownerdecisions,s-protectedroutes}-20261021/`).
- **RV-O** (`375e88f`..`ada7372`, O1 to O8; RV-L's and RV-M's follow-ups):
  - O1 to O4: header injection, command injection, stored XSS and cache poisoning report a
    failed or refused send as blocked or inconclusive, not a negative. O5: SSRF waits out the
    callback window before a negative.
  - O6 and O7: `not_tested` lists pending and running checks, and blocked, inconclusive and
    error rows with their reasons; `Orchestrator.leg_self_test_report`; stale test names.
  - O8 (owner decision): a dialog showing the payload's computed value confirms XSS and says
    so; any other dialog or page error is a labelled candidate.
  - Existing tests changed, each encoding a rule this batch changed (none loosens a
    non-confirm): the coverage-model `not_tested` tests, the leg self-test stubs, command
    injection's zero-budget test (`blocked`) and the browser XSS dialog tests.
  - Follow-ups: `store.coverage_report` says tested_clean despite blocked or inconclusive
    rows; `active_verification._STATUS_MAP` maps an unknown status to not confirmed; a partial
    browser or DOM XSS visit error is still `not_confirmed`; SSTI is skipped on refusal;
    `GatedAsyncClient` loses a ConnectError's class.
- **RV-P** (`11faec0`..`7a6108f`, 13 commits, P1 to P9):
  - Validators whose broad `except` swallowed a failed send, each reached first through an
    exchange that passes its preconditions: client trust (P1), deserialization OOB (P3), rate
    limit (P4), TOCTOU (P5), verb tampering (P6), path traversal (P7), the source form (P8),
    file upload, JWT forging and reset token (P9). P2 (CSRF) was already sound.
  - No existing test changed.
  - Follow-ups (the sweep): idor_read, http_request_smuggling, race_condition, oauth,
    subdomain_takeover and crypto (partly) still swallow a failed send.
- **RV-Q** (`c3c8cba`..`cc8ddef`, Q1 to Q5; RV-N's follow-ups; Burp only):
  - Q1: the CSRF forged request carries a foreign Origin and Referer. Q2: a request a form
    cannot send is at most SUPPORTED. Q3: the JWT retry keeps non-credential cookies. Q4: mass
    assignment finds created-object id keys. Q5: XSS models script types and `<template>`.
  - Gradle: 374 tests. One existing assertion changed:
    `ValidationExecutorResidualsTest.csrfCookieOnlyWithHeaderTokenIsConfirmed` asserted the
    captured Referer was kept, the behaviour Q1 fixes.
  - Follow-ups: `Origin: null` and method override are not tried; SameSite cookies are not
    modelled; JS regex literals and a prefix that is already a syntax error are not modelled;
    a `<script src>` or `nomodule` script still counts; declarative shadow DOM content counts
    as inert.
- **RV-R** (`82abc91`..`811b973`; owner decisions of 2026-10-21):
  - R1: an MFA step-up redirect is not a denial; the anonymous control takes IDOR's rule.
    R2: a confirmed CORS origin reflection says what the attacker's page can read.
  - Tests changed: `test_step_up_redirect_is_unchanged` became
    `test_step_up_redirect_is_not_a_denial` (the rule the owner changed). The owner chose to
    change the vulnerable fixture's no-session MFA redirect to `/login` rather than the leg
    test (`vuln_fixture.py`, `82abc91`).
  - Follow-ups: a validator's text does not reach a stored finding that has its own evidence;
    a null-origin grant does not check credentials; the CORS result drops its computed
    severity; an anonymous 2xx step-up page with a password field still confirms (owner
    decision if wanted).
- **RV-S** (`7b98fad`, `516643e`; RV-M M1's follow-up, owner decision of 2026-10-21):
  - S1 to S6: the chain confirms missing auth only on a route that matches an operator pattern
    in `authz.protected_paths` (config.local.yaml, per target) or the engagement's list, and
    only when the anonymous replay returns the authenticated baseline's payload. The evidence
    names the pattern and its source. An unlisted route stays a candidate; a malformed entry is
    ignored with a warning. Operator guide: docs/PROTECTED_ROUTES.md.
  - S3b (found in the batch): on a listed route the anonymous replay drops every header a
    supplied identity sets, not only known credential names. A custom session header had made
    a false confirmation.
  - Follow-ups: nothing sets the engagement's list yet (I16); an app that authenticates only
    through a custom header cannot confirm (fail closed); the probe's own `_strip_auth` keeps
    unknown credential headers for its other callers; an unlisted route's candidate does not
    say how to declare it.
- The cross-request audit's fix batch 1 (`823ff4e`..`7a05995`; not a code review 02 batch;
  reviews/2026-10-21-dual-mode-cross-request-audit/FIX_BATCH_1.md) landed after RV-S. Batch RV-T
  implements its owner decisions.

Next: RV-T, then a batch for RV-P's sweep.
- RV-T (brief `.test-work/rv-t-crossrequestdecisions-20261021/BATCH.md`): `authz.owners`,
  passive-only lookups, sensitive-file severity by class and the driver's own ceiling.
- RV-P's sweep: the validators above that still swallow a failed send.
- The other follow-ups above wait for a batch or the I01 W-split (`store.py`, `issues.py` and
  `HarnessPanel.java` carry WIP).
- I05 batch D (branch `i05d-browser-credentials`) is not a code review 02 batch. It waits for
  the owner's review.

RV-K waits for the I01 W-split, because `HarnessPanel.java` carries WIP.
