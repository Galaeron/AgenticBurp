# Verify the repaired source before a passive trial

The run `7d6b115acbec` loaded `.test-work/active-eval-js-full8h-20261030/source/harness/server.py`, not the implementation checkout. Its snapshot retains the old catch-all `missing_template` reporting. Restarting that snapshot would keep the old behavior.

The intended implementation checkout is:

`C:\Users\arthu\Documents\AgenticVibe\.test-work\wt-cors-r1`

Observed on 2026-10-30: branch `codex/experiment-lifecycle-repair`, HEAD `bcc2b95a7db18d84cd2cb823f0a3899b188ddc54`. Its three latest commits are `bcc2b95` (coverage attempt facts), `9404f29` (decoded-response contract), and `fe8859b` (initial architecture repair). There is also a tracked working-tree modification. CURRENT_STATE.md still records an older baseline. Neither a branch name nor these commits alone proves that every intended fix is included.

## 1. Establish which files will be tested

Use a fresh PowerShell session and the project's existing test environment. Run from the implementation root:

```powershell
Set-Location -LiteralPath 'C:\Users\arthu\Documents\AgenticVibe\.test-work\wt-cors-r1'
git branch --show-current
git rev-parse HEAD
git status --short
git diff --check
python --version
python -m pip check
```

Preserve working-tree changes. Review them against the implementation handoff before deciding that this is the complete candidate. Do not reset, clean, stage everything, or copy the main checkout over it. The prior verification handoff is `.test-work/verification-repair-20261029/HANDOFF.md`; its results are historical until rerun against the current files.

## 2. Verify Python import provenance

```powershell
python -c "import pathlib, sys, harness, harness.worklist_investigator as w, harness.engagement_builder as b; root=pathlib.Path.cwd().resolve(); print('python:',sys.executable); print('package:',harness.__file__); print('worklist:',w.__file__); print('builder:',b.__file__); assert all(pathlib.Path(m.__file__).resolve().is_relative_to(root) for m in (harness,w,b)), 'Wrong checkout imported'"
```

Stop on a failed assertion. Resolve the environment/import mismatch before interpreting test results. An editable install or stale PYTHONPATH can load another checkout. The same provenance check must hold in the process used for a passive trial; a successful check in another shell does not establish server provenance.

For any separately prepared snapshot, inventory relative paths and SHA-256 hashes for every included source/configuration file, including relevant uncommitted and untracked implementation files. Compare the destination inventory to the reviewed candidate before and after testing. A fresh `git archive HEAD` alone omits working-tree fixes. Record the effective configuration separately with secrets redacted; never export credential files into the handoff.

## 3. Run current-source offline verification

Use the dependencies specified in this checkout's `docs/TESTING.md` and `harness/requirements.lock`. Do not replace missing dependencies with stubs. Save full logs and read only summaries/failures:

```powershell
$trialDir = Join-Path (Get-Location) ('.test-work/source-verification-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $trialDir | Out-Null
$results = @()
foreach ($tier in @('smoke', 'full')) {
    $logPath = Join-Path $trialDir ($tier + '.log')
    python -m harness.suite $tier *> $logPath
    $results += [pscustomobject]@{ check=$tier; exit_code=$LASTEXITCODE; log=$logPath }
}
$preconditionLog = Join-Path $trialDir 'precondition.log'
python -m unittest harness.test_orchestrator_precondition *> $preconditionLog
$results += [pscustomobject]@{ check='precondition'; exit_code=$LASTEXITCODE; log=$preconditionLog }
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $trialDir 'SUMMARY.json')
$results | Format-Table
Get-ChildItem -LiteralPath $trialDir -Filter '*.log' |
    Select-String -Pattern 'Ran \d+ tests','\d+ passed','FAILED','^ERROR','^FAIL:','skipped='
```

Require exit zero for all three checks. Record counts and skips; a skipped test establishes nothing about that behavior. Preserve caller-level regression tests and defect-injection negative controls. Offline success does not establish live recall or model accuracy.

## 4. Passive trial acceptance

Use the application's existing captured-only/passive flow with safe defaults. This document does not configure or launch active discovery, exploit validation, or autonomous engagement execution.

- The owning process must report its executable, loaded source paths, revision, and source hashes matching the tested candidate. Python reload is disabled: an existing process does not acquire changed files. Any restart must be limited to the identified owned process.
- Use fresh isolated runtime/cache state so earlier outcomes cannot masquerade as new evidence. Preserve the old run and its snapshot unchanged.
- Confirm the reporting distinction between a genuinely absent request template and no applicable hypothesis. Do not require all skips to disappear or relabel them as completed checks.
- Keep unmatched-identity captures explicitly rejected. Six of eight supplied seeds in the old invocation carried Cookie headers, while its supplied identities used either no credentials or Authorization. Do not strip cookies or guess ownership to make ingestion pass. A diagnostic should expose header names and rejection counts, never credential values.
- Keep request totals, executed coverage, inferred coverage, and assessment completeness separate. The old artifact recorded 19,361 requests but only 4/4,420 executed coverage cells; those counters measure different things.

Deliver a redacted provenance record, source inventory, test summary, and passive-trial outcome. State exactly which checks were exercised and which remain unverified. Do not claim that all fixes are included until the candidate inventory has been reconciled with the intended implementation files.
