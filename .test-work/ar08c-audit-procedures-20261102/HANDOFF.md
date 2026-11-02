# AR-08c handoff — audit procedures for race, WebSocket and error-based claims (2026-11-02)

Base `ff6f7a0` (main), branch `claude/ar-08c-audit-procedures-8c425b`. Commit: the one that adds this
folder (hash recorded on AR-08c in IMPROVEMENT_BACKLOG.md).
Not pushed. Scope, decisions and reasons: BATCH.md.

## What changed
- The replay audit script is committed for the first time, in this folder. Before this batch it
  lived only untracked, under `.test-work/wt-cors-r1/.test-work/batch08-proof-identity-20261030/`
  (main checkout). It starts from batch 08's fixed copy (sha256 `4f4000134ca0...`).
- `audit_websocket` (CSWSH) makes three anonymous raw handshakes through a new
  `Target.handshake`: a same-origin baseline, a foreign-Origin attack and an invalid-version
  control. Each handshake is scope-checked, counted against the ceiling and traced.
- `audit_error_disclosure` (`verbose_error_validator`) replays the claimed GET twice and
  checks it with the audit's own signatures (stack frames, debug pages, DB engine errors).
  The report and trace keep signature names only, never body text. It refutes only with two
  identical clean replays of an anonymous claim. A non-GET claim is not sent.
- Race (`race_condition_validator`, `toctou_validator`) stays `unsupported_audit`. The reason
  is recorded on every such claim (`UNSUPPORTED_REASONS`).
- No harness/ file changed. None of the files owned by the other active streams was touched.

## Verification
- Tests first: `before.log` shows the new tests against batch 08's copy: 10 failures and 1 error
  out of 13 (the two batch 08 tests passed).
- Now 14 tests in test_replay_audit.py, run with `-W error::ResourceWarning`. 13 of them go
  through `main()`; the remaining one checks `audit_for` routing directly. The WebSocket and
  error procedures run with the real Target against an owned loopback server. Negative
  controls: an origin-checking socket and a clean deterministic route (both refuted); a socket
  that needs credentials, one that upgrades an invalid handshake, a varying route, a non-GET
  claim and a claim made as another principal (all left unconfirmed).
- Gates (run_gates.py, SUMMARY.json; `harness` imported from this worktree; sources hashed
  before and after each stage, unchanged throughout). Both interpreters, every stage exit 0:
  - system Python 3.14.7: precondition 74 OK; smoke 149 OK; audit 14 OK;
    full: harness 5014 OK, native 38 passed, evaluation 440 OK (17 skipped), integrity 59 OK.
  - venv Python 3.12.14: the same counts, all OK.
  - `git diff --check` clean, and `git diff --cached --check` clean on the staged files.

## Limitations
- The harness suites do not discover `.test-work/`, so the `audit` stage in run_gates.py is the
  gate that covers this change. The full and smoke runs cover the unchanged harness.
- Not run against a live target (out of scope). BASE is still the Juice Shop origin on 3002.
- WebSocket: anonymous handshakes only. A cookie-authenticated socket ends `inconclusive`, and
  message-level authorization is not audited.
- Error-based SQLi reported by sqlmap is still "recorded only" inside `audit_sqlmap`.

## Next
- AR-08a/AR-08b (issue identity) are separate. A live replay of these procedures needs its own
  run task, per IMPLEMENTATION_TASK.md.
- Re-run the gates from the worktree root:
  `python .test-work/ar08c-audit-procedures-20261102/run_gates.py [py314|py312]`
