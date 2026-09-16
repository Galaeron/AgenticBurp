# Supplemental S-task execution log

## Checkout and scope

- Base/integrated revision:
  `0dc6a523d56cd7268f6f50b46399d5dc4c998a46`.
- Branch: `codex/supplemental-evidence`.
- Worktree:
  `C:\Users\arthu\Documents\AgenticVibe\.worktrees\supplemental-evidence`.
- The existing `reconciliation-backlog` checkout was dirty before work began. It
  was not switched, reset, stashed, cleaned, staged, or modified.
- Owned paths only: `evaluation_integrity/` and `reviews/2026-09-15/` in the
  isolated worktree. No `harness/`, scorer, CI, config, or `CURRENT_STATE.md`
  changes were made.
- No target, model, browser, database, or offensive-tool execution occurred.

## Offline tests

Interpreter:
`C:\Users\arthu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.

Canonical command from the isolated worktree:

```powershell
& 'C:\Users\arthu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -m unittest discover -s evaluation_integrity/tests -p 'test_*.py'
```

Result: **42 tests ran, OK**, exit 0, on the revision above plus the S-task
changes. The suite is synthetic/offline and makes no live-efficacy claim.

Environment limitation: the requested shorthand `python -m unittest ...` could
not run because neither `python` nor `py` is on this shell's `PATH`. The first
attempt failed before test discovery. The canonical result uses the explicitly
identified bundled interpreter above. `compileall -q evaluation_integrity` also
completed with exit 0.

## S19 offline audit

Inputs were explicitly selected from the pre-existing saved bundle:

- `maxcov_results_s19_full.json`
- `recall_report_s19_full.json`

Command:

```powershell
& 'C:\Users\arthu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -m evaluation_integrity.audit `
  --input 'C:\Users\arthu\Documents\AgenticVibe\testing\vulncorp-helpdesk\maxrun\maxcov_results_s19_full.json' `
  --input 'C:\Users\arthu\Documents\AgenticVibe\testing\vulncorp-helpdesk\maxrun\recall_report_s19_full.json' `
  --json 'reviews\2026-09-15\S19_EVIDENCE_AUDIT.json' `
  --markdown 'reviews\2026-09-15\S19_EVIDENCE_AUDIT.md'
```

Result: exit 0. The readers verified that source bytes were unchanged during
each read and recorded their SHA-256 hashes. Output was written only under the
review directory, separate from original run artifacts.

This was a consistency/support audit, **not a revalidation**. The legacy bundle
has no evaluation manifest and no benign health-control records, so freshness
and evaluation validity are unknown. Of 167 normalized confirmation claims, 115
carry proof pointers but the supplied files contain no proof ledger; 52 are bare
booleans. Therefore zero claims are independently proof-supported by this
artifact set. This means unverifiable, not false. The original reported totals
(2,428 occurrences, 887 confirmed, endpoint-known result 9/13) remain present
alongside the diagnostic and are not silently rewritten.
