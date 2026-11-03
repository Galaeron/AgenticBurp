# SC-9 broker (LOOP half) — handoff, 2026-11-02

Branch `claude/sc9-broker-6fdd66`, based on `origin/main` `f817f4c`. Code commit `0102932`;
docs commit follows it. Nothing pushed.

## What changed
- `harness/tool_runner.py`: `ToolBroker` (frozen spec: image, timeout, max_output, egress,
  enforce_egress, require_digest, extra) validates before launch and raises
  `ToolBrokerRejected` for a non-finite or out-of-range timeout/cap, `host` / `container:` / empty
  network, or any docker option outside {`--read-only`, `--tmpfs`, `--workdir`/`-w`, `--user`}.
  `ToolBroker.run` delegates to `run` (I05-C owned tree + exact-name `docker rm -f`) and writes
  `receipt["broker"]` = bounds + `owned` {container_name, cli_pid, containment,
  process_cleanup, container_cleanup} + outcome; the receipt rides on `exc.receipt`.
- `EgressPolicy.confinement()` / `receipt["egress_confinement"]` on every `run`: modes
  `unconfined` | `advisory_proxy_env` | `no_network`; `destinations_enforced` and `proven` are
  always false offline; `allowed_hosts` is reported as `no_proxy_bypass` (that's what NO_PROXY is).
- `receipt["container_cleanup"]`: `force_removed` | `cleanup_failed` | `not_launched` |
  `rm_on_exit_unverified` (a clean exit is never claimed as verified removal).
- `harness/ffuf_runner.py`: `run_sync` goes through `ToolBroker` (no config default touched).
- sqlmap NOT routed (PR #11 owns `validators/sqlmap.py`); it still gets `egress_confinement`.

## Finding
The backlog evidence "run checks cancellation only before execution" was stale: I05-C's
`run_process` already polls cancel and kills the Job Object / process group mid-run
(`test_tool_process_lifecycle.py`). The broker adds bounds, identity and honest policy on top.

## Tests — `harness/test_tool_broker.py` (18)
Real short-lived subprocesses (the I05-C worker + child stand in for `docker run`; fake docker
CLI logs `rm -f`); temp dir under `.test-work/_tmp` (removed in tearDown). No docker run.
- cancel mid-run → tree gone < 5 s, only the owned name `rm -f`'d; timeout → no survivor + rm;
  1 MiB output with 64 KiB cap → truncated, tail kept, drop counted; ffuf caller cancel and
  pre-launch rejection; 40-odd rejection subcases launch nothing; receipt-honesty modes.
- Fault injection in-suite: root-only tree (cancel, timeout), `_force_remove` stubbed, cap
  removed → the same assertion helpers fail.
- Source-level defect injection (manual, reverted): `tree.terminate()` removed → 2 FAIL + 1
  ERROR in `BrokerLifecycleTests`; `removed = True` instead of `_force_remove` → 3 FAIL.

## Gates (PYTHONPATH=worktree, head `0102932`; status files in this dir, logs untracked)
| gate | venv 3.12.14 | system 3.14.7 |
|---|---|---|
| `unittest harness.test_orchestrator_precondition` | 0 | 0 |
| `unittest harness.test_tool_broker` | 0 (18 OK) | 0 (18 OK) |
| `harness.suite smoke` | 0 | 0 |
| `harness.suite full` | 0 (harness 5186, native 38, eval 451/17 skip, integrity 59) | 0 (same counts) |
| `git diff --check` | 0 | — |
Both interpreters ran in parallel; docs commit made after the gates (docs only).

## Owner questions
1. Route sqlmap's container branch through `ToolBroker` once PR #11 lands? (one-line swap at
   `validators/sqlmap.py` `call_cancellable(tool_runner.run, ...)`.)
2. Should a broker *require* a pinned digest by default for sqlmap/ffuf? Not done: it would
   change behaviour for unpinned local images (P3-2 left `require_digest` opt-in).
3. Is `--network none` + host alias (or a per-run proxy network) the NC-O1 target? The receipt
   will report `no_network`/`advisory_proxy_env` but `proven: false` until the live proof.
4. "Malformed output is inconclusive" (SC-9 acceptance) is validator-side parsing; file it under
   SC-10 adapters or keep it in SC-9?

## Not done / OWNER-LIVE
Container confinement on a real docker host (NC-O1); Java untouched; no live runs.
