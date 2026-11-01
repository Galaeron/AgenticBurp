# Reproducible verification snapshots

Create a new destination from the intended source tree using the interpreter that
will run verification:

```powershell
python -m harness.verification_snapshot create --source . --destination .test-work/verify-fresh
$env:PYTHONPATH = (Resolve-Path .test-work/verify-fresh).Path
Set-Location .test-work/verify-fresh
python -m harness.verification_snapshot check
python -m harness.suite full
```

The source inventory is Git's tracked/staged filenames plus the explicit required
verification dependency list. Working-tree edits to those files are copied. New
untracked work must be staged or passed by repeated `--include relative/file.py`;
there is no bulk untracked-directory import. Missing files fail before copying.

`verification-inventory.json` records each copied file's SHA-256, aggregate source
hash, Git revision (which alone does not describe local changes), creation
interpreter/version, installed test dependency versions and excluded filenames.
The benchmark manifest is copied and hashed as opaque bytes; its labels are not
parsed or printed by this tool. Answer keys and target app implementations are
excluded before opening them. Historical/run directories, databases, local config
and generated caches are excluded; the whole testing tree is not excluded.

A fresh destination is mandatory. Existing destinations are never overwritten.
The suite preflight checks required modules/assets and installed test packages
before starting any test groups. Inside a snapshot it also verifies every source
hash and rejects existing harness/runtime databases. Create a new snapshot for a
new run after runtime databases exist; do not reuse assessment state.

The generated `sitecustomize.py`, activated by the snapshot-only PYTHONPATH,
restricts harness/testing/evaluation_integrity imports to the snapshot, including
namespace packages, and disables editable finders. Missing local modules raise
instead of falling back to the parent checkout. Failure to load the guard exits
the interpreter immediately. This does not disable normal third-party packages.
Keep PYTHONPATH set for child interpreters and do not use Python's -S/-I switches,
which suppress this bootstrap. Full retains unittest, native pytest, evaluation
and integrity groups; source inventory is not evidence of a passing suite.

The supplemental dependencies recovered for Ticket 2 are explicitly named in
`harness.verification_snapshot.REQUIRED`: passive-study summary and tests,
web-objective smoke runner and its auth/benchmark tests, remediation scoring tests,
and the benchmark manifest. No target run or live traffic is part of creation.

The exact safe regression infrastructure `testing/blind-target-2/run_blind_eval.py`
and `testing/blind-target-2/blind_eval_exchanges.json` is explicitly required and
copied opaquely. The exception applies only to these two paths; target app files,
answer keys and other files under excluded target directories remain excluded.
Nested runner orchestration unit tests mock preflight because the outer suite
already created runtime state; production suite preflight still rejects reused
snapshot databases. Separate caller controls verify that missing dependencies,
changed source and stale databases fail before test execution.
