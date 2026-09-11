# coverage_evidence/

Machine-generated evidence artifacts for the requirement-coverage manifest
([`../coverage_manifest.py`](../coverage_manifest.py)).

Each `*.json` file is written by a deterministic regression test on the path where
its security assertions actually held (see `coverage_manifest.write_evidence`). The
manifest reconciles these artifacts against `REQUIREMENT_TESTS` to compute
requirement coverage — kept deliberately separate from test outcomes:

- A passing test yields only **partial** coverage of a WSTG requirement (the one
  aspect it exercises), never "complete".
- **Missing evidence, a skipped/failed test, or a manual-only check never counts as
  covered.** Coverage is computed from these artifacts, not from a test merely
  existing — delete an artifact and its requirement reverts to a gap.

Artifacts are deterministic (sorted keys, no wall clock, seeded fixture markers), so
a green re-run reproduces byte-identical files and leaves the working tree clean.
Regenerate by running the owning test, e.g.:

```bash
cd harness && python -m unittest test_mass_assignment_slice
```

View the reconciled report:

```bash
cd harness && python coverage_manifest.py            # Markdown report
cd harness && python coverage_manifest.py --check     # non-zero if a declared automated check lost coverage
```
