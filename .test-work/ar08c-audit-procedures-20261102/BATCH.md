# AR-08c — audit procedures for race, WebSocket and error-based claims (2026-11-02)

Base `ff6f7a0` (main). Backlog: IMPROVEMENT_BACKLOG.md "AR-08c". Offline only: no live target
run, no new assessment, no config default change.

## Where the audit lives
The replay audit is a standalone operator script, not harness code. Batch 08 fixed a copy in
the untracked folder `.test-work/wt-cors-r1/.test-work/batch08-proof-identity-20261030/` (main
checkout); no copy was ever committed. This batch starts from that copy (sha256
`4f4000134ca0...`, byte-identical) and commits it with its test in this folder, so the audit
code is tracked from now on. Entry point: `replay_audit.main(live_dir, inventory_only)`,
routing via `audit_for(claim)`, totals via `summarize(claims)`.

## Decision per class
| Class (validator) | Decision | Reason |
|---|---|---|
| WebSocket / CSWSH (`websocket_validator`) | **procedure `audit_websocket`** | The claim is one handshake fact: the server upgrades despite a foreign Origin. The audit can re-observe it read-only with its own raw handshakes: a same-origin baseline, a foreign-origin attack and an invalid-version control. Origin refused while same-origin upgrades refutes the claim (`false_positive`). An upgrade with no credential at all is a missing Origin check without a shown ambient-credential hijack (`confirmed_hardening`, as for CORS `*` without credentials). A handshake that needs credentials, or that upgrades even an invalid request, stays `inconclusive` (not audited). Message-level authorization is not audited. |
| Error disclosure (`verbose_error_validator`) | **procedure `audit_error_disclosure`** | The claim is a passive fact about a response: the route serves a stack trace, framework debug page or database engine error. The audit replays the claimed GET twice with its own signature rules (no harness code) and records only signature names, never body text. Both replays carry a signature: `confirmed_observation` (sensitivity is a manual judgement). Two identical replays with no signature refute it (`false_positive`), for example a version banner header passed off as an error disclosure. Otherwise (responses vary, a signature in one replay only), or for a non-GET claim whose body the run did not record: `inconclusive`. |
| Race / TOCTOU (`race_condition_validator`, `toctou_validator`) | **stays `unsupported_audit`, with the reason recorded on each claim** | The claim is about a concurrent burst of a captured state-changing request. The audit inventory holds only the method and URL, not the body, credentials or workflow state. Re-firing a burst mutates the target (it consumes the coupon or balance the claim is about), so it would be a new mutating assessment, not a re-observation. There is also no independent oracle for "should succeed at most once" without the application's business limit. |

Error-based SQL injection (`sqlmap`, technique "error-based") is still covered by
`audit_sqlmap`: it reruns the tool, and the technique stays "recorded only", so a lone
error-based point ends `inconclusive` (not audited), never confirmed or refuted.

Totals: every claim gets one `audit_state`. `false_positives` and `false_positive_rate` count
audited claims only and are `None` when nothing was audited. `unsupported_audit` and
`not_audited` claims are never counted as clean.

## Acceptance (tests in test_replay_audit.py, driven through `main()`)
- WebSocket and error procedures: caller-level tests. Each runs main() with the real `Target`,
  which sends real HTTP and raw-socket handshakes to an owned loopback server. Each has a
  positive case plus a negative control the procedure must refute (origin-checking socket;
  clean deterministic route) and an unconfirmed control (handshake needing credentials;
  varying response; non-GET claim).
- Race/TOCTOU: reported `unsupported_audit` with the recorded reason. A run made only of
  unsupported claims has `false_positives is None` and `all_claims_audited` false.
- Batch 08 tests kept (generic CONF-05 not CSP-judged; totals never zero by default).

## Allowlist
This folder only (replay_audit.py, test_replay_audit.py, BATCH.md, HANDOFF.md), plus
IMPROVEMENT_BACKLOG.md for the `[x]` mark. No harness/ file changes.

## Gates
Both interpreters, PYTHONPATH=worktree: `python -m unittest harness.test_orchestrator_precondition`,
`python -m harness.suite smoke`, `python -m harness.suite full`, `git diff --check`, and this
folder's `python -m unittest discover -s .test-work/ar08c-audit-procedures-20261102`. The suites
do not discover this folder, so the last command is the gate that covers the change.
