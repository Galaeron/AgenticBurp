# Verification run summary (audit 2026-10-21)

Source: detached worktree of f5637308e2e4f387aedcc6442ad856754b69565e (clean, 0 modified/untracked files) at <session-scratchpad>/wt-audit
Interpreter: Python 3.13.16 at /usr/bin/python; no virtualenv; no dependency installation performed.
Missing modules (import errors): fastapi, httpx, httpcore, pytest, flask, werkzeug, mitmproxy (playwright Python package also absent; Chromium binaries present under /opt/pw-browsers).

| Command (from worktree root) | Exit | Wall s | Result lines |
|---|---|---|---|
| `python -m unittest harness.test_orchestrator_precondition` | 1 | 1 | FAILED (errors=1)  |
| `python -m harness.suite smoke` | 1 | 3 | Ran 53 tests in 2.702s FAILED (failures=64, errors=9)  |
| `python -m harness.suite full` | 1 | 30 | Ran 1979 tests in 18.175s FAILED (failures=66, errors=367) Ran 346 tests in 9.284s FAILED (errors=36, skipped=18) Ran 59 tests in 0.044s OK  |

full tiers in order: harness unittest discovery; coverage gate; pytest-native (No module named pytest); testing/ evaluation; evaluation_integrity (59 OK).

Import-error counts in full.log:
          1 ModuleNotFoundError: No module named 'fastapi'
          8 ModuleNotFoundError: No module named 'flask'
         46 ModuleNotFoundError: No module named 'httpcore'
        352 ModuleNotFoundError: No module named 'httpx'
          1 ModuleNotFoundError: No module named 'mitmproxy'
          1 ModuleNotFoundError: No module named 'pytest'
         26 ModuleNotFoundError: No module named 'werkzeug'

Non-import FAILs in full.log. The 64 coverage-manifest subtest FAILs report declared tests whose modules did not import ("declared test carries no @evidence_for"). The two leg_self_test FAILs were not diagnosed; they derive their expected set from legs whose modules did not import (INFERRED):
          1 FAIL: test_concurrent_thread_keeps_using_the_real_throttle_during_self_test
         32 FAIL: test_declared_automated_ids_resolve_to_runner_ids
         32 FAIL: test_declared_specs_match_their_decorators
          1 FAIL: test_healthy_executed_pair_still_qualifies

Conclusion: BLOCKED by absent dependencies. These exits say nothing about the committed code's correctness; only the 59 evaluation_integrity tests executed and passed.
Raw logs (not committed; MB-scale): <session-scratchpad>/runs/{precondition,smoke,full}.log
sha256: ab7a89d4fb80db00997269d8565dd98eba3de962ea441add503caa5513db2c9d  precondition.log;c33216630c722b7348d03f73cc7c5ed253d94d45a7e14e3697c4fed63b5089ad  smoke.log;d07413cc0cb9126915d58c52b58b65e7cbfe3337d277ec5f36e7e3228020279a  full.log;
