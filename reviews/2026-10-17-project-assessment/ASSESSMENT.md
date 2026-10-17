# Project completion and efficacy assessment — 2026-10-17

Verdict: the recent engineering fixes have credible regression and integration
evidence. Practical vulnerability-detection efficacy has not been re-established;
the historical no-go verdict remains unresolved. Routine professional use is not
validated. This is a maintainer self-review, not an independent external audit.

## Scope and evidence

Reviewed branch `reconciliation-backlog`, HEAD
`1644dc5859f7b74d13fc51cd819558cd3c14baf9`, plus existing working-tree changes.
The recent discovery/lifecycle work is local, not committed or pushed. No PR/CI
status or clean-checkout reproducibility claim is made. Existing unrelated WIP
was retained; no configurations, services or dependencies were changed for this
assessment. No active crAPI evaluation was performed.

VERIFIED NOW: collected the completed full-suite process, exit 0. It reports
3,459 harness tests (603.088 seconds), 38 pytest-native tests, 371 evaluation tests
and 42 integrity tests, all passing. The 15 source/test files in the fix's SHA256
manifest still match. This verifies that recorded subset, not a complete release
manifest for every dirty or untracked file.

VERIFIED NOW: a fresh focused execution passed 38 tests in 3.641 seconds, without
skips. It includes the discovery caller tests, a real Chromium-to-engagement
loopback fixture, confirmation-class binding, second-order transport and both
standalone context paths. The model is not measured by these tests. The browser
fixture issues a benign JSON POST; it is not a complete SPA workflow evaluation.

The completed full run's coverage checker still reports 38 requirements: two with
partial passing evidence and 36 gaps (33 labelled gap_unimplemented, three manual).
These are requirement-evidence classifications, not proof that 33 corresponding
product features are absent. A passing checker does not mean complete coverage.
A socket ResourceWarning also appears; the run passed, but it does not prove
universal resource cleanup.

## Todo reconciliation

The backlog contains 133 checkbox headings: 98 checked, 31 unchecked and four
partial. This is an inventory, not a completion percentage: items overlap, include
superseded/deprioritized work and use different acceptance scopes. The remediation
register separately declares 23 fixed_verified, five blocked_external and one
in_progress. Those historical labels were not individually re-certified here.

| Work item | Assessment | Acceptance still missing |
|---|---|---|
| ARCH-1 owning-run iterative probing | Source forwarding exists; focused run-context controls pass | Dedicated real engagement caller negative control remains stronger than probe-only tests |
| ARCH-2 second-order transport | Plant/read source delegates to shared transport; helper controls pass | Existing test calls the transport helper, not the actual engagement plant closure; it cannot alone prove wiring |
| ARCH-3 plus zero-ceiling/seed-failure follow-ups | Implemented locally; focused zero-budget and error-close regressions pass | Commit/release identity and live operational verification |
| Claim-A evidence confirming claim B | Tested fallback mismatch is suppressed; positive and isolation controls pass | Test mocks persistence and oracle; no fresh crAPI adjudication or full API/storage/export regression proves all false confirmations are gone |
| LB-2 JavaScript traffic | Browser capture is now wired to engagement; real page-load JSON POST reaches worklist; module imports/methods preserved | Original acceptance also named XML and multipart confirmation. Multipart was explicitly deferred. Page-load capture is not login/click/navigation automation |
| Catch-all route explosion | Synthetic nested wildcard, distinct-route, query and ffuf controls pass; descendant guessing is pruned | No fresh measurement on the reported 7,460-request/97-minute workload; varying fallbacks and indistinguishable genuine routes remain limitations |
| DET-SQLI-POST | Backlog diagnosis is partly stale: source already schedules injection legs for body parameters | Prove the exact requested body-targeted validator caller behavior and negative control before closure |
| DET-JWT-DETECT | Backlog diagnosis is partly stale: JWT-bearing-role GET scheduling exists without a model label | Reconcile exact supported request/cookie/method scope and caller coverage; not every JWT-bearing request is shown covered |
| DET-SSRF / Part B | Live acceptance unverified | Authorized target, reachable collaborator, fresh source/config provenance, negative controls and adjudication |
| Release / Priority 5 | Open | Exact candidate package/JAR, supported environment, actual Burp walkthrough and release adjudication |

LB-2 illustrates why checked boxes cannot establish integration: its checked entry
explicitly said “no default caller” and recorded deferred multipart work. The new
integration closes a real gap, but does not retroactively satisfy every original
acceptance criterion. ARCH tracking similarly needs its test-boundary wording
corrected: mocked persistence is not storage/export integration.

## Efficacy assessment

HISTORICAL/REPORTED: the Oct15 decisive reproducibility report records three crAPI
runs at `06a128fc`: 0/20, 1/20, 0/20 ground-truth recall, six false confirmations
per run, and approximately 4,154 / 4,010 / 4,069 seconds processing. These were
repeats of the same capture set, not 60 independent vulnerability cases. Six
ground-truth endpoints were structurally unreachable from that capture set.
The report also records genuine orders-IDOR and username-enumeration findings;
“the tool never finds anything” would therefore be inaccurate.

The stated rule was that one false confirmation ends the evaluation. The historical
runs failed that rule. The current implementation addresses identified causes but
has no fresh matched live result overturning the failure. Its current recall,
precision, analyst effort and request/time improvement are UNKNOWN. The historical
negative result itself is known, not “unknown efficacy.”

VERIFIED NOW at the mechanism level: a real browser-generated request reaches the
engagement graph with its body and method; synthetic catch-all routes are filtered;
explicit zero ceilings and context cleanup work in the tested paths. Existing
in-memory fault injections detected disconnected browser capture, module traversal
and wildcard filtering. These are useful prerequisites for measurement, not a
substitute for measured useful findings.

## Prioritized next actions

1. Freeze the candidate and reconcile the trackers. Keep component implementation,
   caller integration, live efficacy and release status separate. Record all WIP
   required for the candidate, not just HEAD; do not blindly commit unrelated edits.
2. Strengthen confirmation trust evidence: drive the actual engagement probe and
   second-order closures through budget-denial controls, then check claim identity
   through real persistence and API/export output. Preserve the current negative
   controls and do not close the global false-confirmation problem from mocks.
3. Validate SPA reach and discovery efficiency against a declared reference surface:
   authenticated page-load and interaction-generated requests, XML/multipart cases,
   true endpoints mixed with root/nested/varying fallbacks. Measure missed genuine
   routes as well as rejected fake ones, and count requests independently.
4. Run the agreed Part B protocol only in its authorized evaluation context: freeze
   source/model/config and target state, use fresh caches and comparable budgets,
   retain complete denominators, repeat runs and adjudicate each confirmation.
   Apply the existing zero-false-confirmation stop rule. No new superiority or
   readiness claim follows until that evidence exists.
5. Complete release gates against that exact candidate: intact packaging, Java
   build and actual Burp workflow. Earlier builds and a local executable on PATH
   do not prove today's artifact or operator experience.

## Evidence locations

- `IMPROVEMENT_BACKLOG.md`, `docs/ARCH_RECONCILIATION_TRACKING.md`,
  `docs/RECONCILED_REMEDIATION_REGISTER.json`, `docs/REMEDIATION_RELEASE_GATES.md`.
- `.test-work/discovery-fixes-full-verified.log` (exit 0),
  `.test-work/project-assessment-20261017.log` (fresh 38 tests, exit 0),
  `.test-work/discovery-fixes-source-hashes.csv` (15 unchanged files),
  `.test-work/discovery-fixes-mutations.log` (three faults detected).
- `docs/SPA_DISCOVERY_FIXES.md` and the caller/test source files named there.
- Historical external report:
  `C:/Users/arthu/Documents/agenticburp-eval/eval-run/REPORT_2026-10-15_decisive_reproducibility.md`.
