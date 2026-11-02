# PR #12 follow-up — owner decisions 2026-11-02 (AR-10 P3 sealed scorer)

Branch `claude/pr12-followup-144cf5` (from `ar10-p3` 19ba7a6). Not pushed.

## Commits
- 28ce37c merge: PR #9 (P1 iterative diagnostics) from origin/main (1f89f73, merged there).
- 542c00a Q6: a confirmed claim matching two mapping entries (match or equivalents,
  available or not) is BadInput (exit 3); message names no entry; never double-counted.
- 4be24dc Q5: per-probe `steps` (transcript length) in P1's `iterative_diagnostics`
  (totals + by_stop_reason; None if any probe lacks it) and a top-level `costs`
  {model_calls, model_errors, retries, wall_seconds} from the model-client counters.
- fbcdadb Q4: `harness/ar10_acceptance.py` (acceptance.json) + `harness/ar10_freeze.py`
  (freeze manifest writer run after the last repeat).
- 58b3a27 merge: origin/main 7a35fac (PR #10 I16 persist, PR #8), at the parent's
  request. The merge was clean and the result_blocks hunks are intact.
- (this commit) HANDOFF + test helpers.

Q1, Q2, Q3, Q7: accepted as implemented; no code.

## Hunks outside the scorer (listed as asked)
- `harness/orchestrator_chain.py`: 2 one-line hunks, `_objective_result` and the final
  engagement result: `"instrumentation": _instr.snapshot()` ->
  `**_instr.result_blocks()`. No overlap with PR #13's hunks.
- `harness/instrumentation.py`: `run_costs()` + `RunInstrumentation.result_blocks()`.
- `harness/worklist_investigator.py`: `steps` in `_probe_diagnostics`/`iterative_diagnostics`.
- Not touched: ollama_client.py, server.py, orchestrator.py. No config default changed.

## Q4 flow (part B -> part C)
    python -m harness.ar10_freeze --out-dir <dir> --mapping-sha256 <hex> \
      --repeat A1 A <run_dir> ... [--canaries A1 <operator canary file>]
    python -m harness.ar10_scorer --manifest <dir>/freeze.json --mapping <sealed> --out ...
- `--canaries` (L10) is opt-in: `*-private.json` is never opened implicitly (spec 3.1).
  Without it, L10 is `unknown` (the metric-redaction half still fails on its own).
- Missing input = `unknown` + reason; present but violating = `fail`.
- Part B must write `enabled-features.json` (the spec 3.2 feature manifest) in the run
  dir; L2 fails without it. The name is mine. Please confirm or rename it.
- L5 basis is the export's `issue_accounting`, not the store's proof_records.
- L9 is always `unknown`: engagement_builder reports "capture unbound" only in the
  role crawl's own errors, and result.json exports no supplied/bound capture counts.
  **Producer follow-up:** export seed-capture binding (supplied, bound, unbound names).
- Read-only sanity check on v10 (no canaries): L1 pass; L2, L5 and L7 fail (pre-AR-08c
  audit, no feature manifest, no orphan list); L3/L4 unknown; L10 fail on 4 redacted
  auth/csrf metric counts. These are expected for a run that predates these producers.

## Tests (synthetic only)
- test_ar10_scorer: overlap refusal (3 subtests + control).
- test_ar10_run_costs_steps: real investigate_engagement; steps vs the scripted model's
  turns; costs vs a scripted wire's request count; controls.
- test_ar10_acceptance_freeze: each criterion pass/fail/unknown; real
  confirmed_issue_accounting output; freeze CLI -> scorer CLI end to end; refusals.
- Defect injection (`inject.sh`): every injected defect was caught. Two first escapes
  (digest masked by size; dropped orphan masked by count) got dedicated cases.

## Gates (final tree, PYTHONPATH=worktree; all exit 0 on 3.12 venv and 3.14 system)
- precondition 74 OK; focused 80 OK; smoke 149 OK; diff-check 0.
- full: harness 5139 OK, evaluation 440 OK (17 skipped), integrity 59 OK.
- An earlier smoke run failed test_no_orphan_test_files because RunCostsTests was not a
  TestCase. Fixed in ddd2f0f before this run.
- Runner: `bash .test-work/pr12-followup-20261102/gates.sh <label> <python>`.
