# coverage_evidence/

Documentation only. **No pass/fail artifacts are committed here** — that was the
original mistake (a committed passing artifact let the coverage gate go green without
the test ever running, and a later failed/skipped run could not invalidate it).

Evidence is now written FRESH per run into a **run-specific, git-ignored directory**
and bound to the run/commit id:

- Location: `harness/.coverage_runs/<run_id>/` by default, or the path in
  `COVERAGE_EVIDENCE_DIR`. `run_id` is `COVERAGE_RUN_ID` (CI sets it to the commit
  sha) or the current git HEAD.
- Written by the **test runner**, not the test body: a regression test subclasses
  `coverage_evidence_case.EvidenceCase` and marks a method with `@evidence_for(...)`.
  The runner stamps the actual outcome (`pass` / `fail` / `skipped`) — so a failed or
  skipped test records that, and never leaves a stale `pass` behind.
- Each artifact separates a reproducible `observation` block from per-run `execution`
  metadata (status, `run_id`, timestamp), and carries a `schema_version`.

The gate (`coverage_manifest.py --check`) reconciles ONLY artifacts whose `run_id`
matches the current run, requires an exact non-empty `test_id` match, validates the
schema, and rejects duplicates — so nothing but a real, fresh pass counts as coverage.

```bash
# regenerate this run's evidence, then reconcile + gate it
cd harness
python -m unittest test_mass_assignment_slice
python coverage_manifest.py --check
```
