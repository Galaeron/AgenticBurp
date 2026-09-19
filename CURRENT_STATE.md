# Current state — 2026-09-19

## Checkout

Branch `reconciliation-backlog`. Consolidation committed in `8325b05`; the final
test run completed on that HEAD plus the pre-existing uncommitted
`harness/ollama_client.py` and `harness/test_ollama_client.py` edits. Preserve them.
All 377 recorded source/config hashes stayed unchanged during final verification.
The clean commit alone was not the tested tree.

## What changed

AGENTS.md is the shared onboarding source; CLAUDE.md redirects there. README.md
covers setup, docs/ indexes task-specific architecture and evidence boundaries.
The old accumulated onboarding is preserved in archive/onboarding-2026-09-19/.

Seven transport adapters now share 14 positive/denied scenarios in
`test_validator_transport.py`; the two CORS-specific tests remain separately.
Six redundant test files were removed, preserving their assertions. Discovery
checks reject uncollected/mixed-style tests, main-only files and shadowed names.

Six requirement-evidence IDs were still pre-package names: corrected them to
`harness.*` and added real loader-ID controls. The XXE smoke now isolates its
intended validator and forbids an unexpected shared collaborator. Canonical
smoke/full commands enforce the evidence gate and use fresh local run IDs.

## Verified here

From the repository root, using `.venv-rationalisation/Scripts/python.exe`:

- `-m harness.suite smoke`: **90 tests OK**, 27.923s, evidence gate passed.
- `-m harness.suite full`: **2,295 unittest tests OK, 2 browser skips**;
  **38 pytest passed**, **13 score/plumbing + 42 evaluation tests OK**;
  evidence gate passed, combined exit 0. Unittest duration: 234.228s.
- Original transport group: 16 tests OK; consolidated group retains all 16
  scenarios. No assertion was removed merely because it was old or mocked.

These are offline/stubbed-model and owned-loopback results. Python 3.12.14 was
used with isolated dependencies and a reported proxy/typing-extensions metadata
conflict; initial dependency/sandbox failures are documented, not hidden as skips.
See [TESTING.md](docs/TESTING.md) and the [audit](reviews/2026-09-19/rationalisation/REVIEW.md)
for commands, old-to-new mapping, runtime limits, log hashes and source binding.
A separate task's Python 3.14 pass is recorded as owner-reported in that audit.

## Other work and remaining verification

Concurrent commits `1b0b1d5` through `506e2e5` added role probing, attack-tree
search, knowledge retrieval and tactical guides. Commits `fe30f64` through
`57bcc02` address the dated implementation review's proof, evaluation, privacy,
coverage, export and integration findings. Current consumers were located in
score/export/coverage paths; this audit does not independently certify every
review requirement or live efficacy. Inspect the specific caller and its tests.
The [review](reviews/2026-09-19/implementation-review/REVIEW.md) describes its base
revision, not an automatically current backlog.

No real-model benchmark, blind-target run, hosted CI or Java build was performed
here. Cached scores and older suite counts remain historical. The earlier live
integrated driver was `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`;
its completion/results and current process state were not checked in this task.
Do not restart unrelated processes based on old notes. Keep future updates in
this rolling file rather than appending session histories.
