# Current state — 2026-09-19

## Checkout

Branch `reconciliation-backlog`, 56+ commits ahead of `main`, 0 behind. HEAD is
this session's commits (below) on top of `249b799`. The working tree still carries
other in-progress edits, so the verification below reflects HEAD plus those edits,
not a clean commit.

## Committed this session (on `reconciliation-backlog`)

- `fix(store)`: `_connect()` retries on SQLite lock during concurrent first-connect
  (see the Verified section for the failure this closes).
- `docs`: corrected the stale `target_transport.py` reference in AGENTS.md and
  docs/ARCHITECTURE.md (the transport is the `TargetTransport` class in
  `run_context.py`; the auditor is `transport_inventory.py`), restored the missing
  `tools/sqlmap.Dockerfile` (referenced by README, config, `ffuf.Dockerfile` and
  the sqlmap validator; lost when `tools/` moved from `harness/tools/`), and
  refreshed this file.

## Still-uncommitted working-tree changes (someone else's WIP — preserved)

The verification below was run on HEAD plus these edits, which are **not** this
session's and were left untouched:

- Agents-subsystem refactor: `harness/agent_manager.py`, `harness/agents/__init__.py`,
  `harness/agents/plugin.py`. Plugin/agent-class discovery is simplified and the
  lazy `_plugin_system` singleton dropped; `get_all_agents(config, ollama)` is
  replaced by argument-free `get_all_agent_classes()`. New untracked
  `harness/test_agent_lifecycle.py`.
- `harness/ollama_client.py` + `harness/test_ollama_client.py` edits.
- `testing/blind-target-2/run_blind_eval.py` edits.

## Verified here (2026-09-19, this dirty tree)

From the repository root, using `.venv-rationalisation/Scripts/python.exe`
(Python 3.12.14, isolated deps; see the Python 3.12 typing-extensions caveat in
[TESTING.md](docs/TESTING.md)):

- `-m harness.suite smoke`: **90 tests OK**, 34.7s, requirement-evidence gate ran
  with a fresh run id, exit 0.
- `-m harness.suite full`: **green.** Unittest **2,301 tests OK, 2 skips**
  (283.2s); pytest-native **38 passed**; score/plumbing **13 OK**; evaluation
  **42 OK**; requirement-evidence gate passed; combined exit 0.

Fixed this session: `test_store.TestConnectConcurrentMigrationIsIdempotent`
reproduced deterministically before the fix — a 16-way concurrent first-connect
raised SQLite `database is locked` (and left the temp DB locked, a Windows
teardown error). `store._connect()`'s WAL switch and check-then-act migrations
take a write lock, and SQLite returns `SQLITE_BUSY` *immediately* (bypassing
`busy_timeout`) when a read-lock holder must upgrade while a peer holds the write
lock. `_connect()` now retries on a lock error, closing between attempts; the setup
is idempotent, so once a caller wins the losers reopen an already-migrated DB. The
test passes 5/5 in isolation and the full run above is clean.

These are offline/stubbed-model, owned-loopback results only. No real-model
benchmark, blind-target run, hosted CI or Java build was performed here.

## Superseded / historical

The prior recorded run (`8325b05` + the ollama edits: smoke 90 OK, full 2,295
unittest OK / 2 browser skips, 38 pytest, 13 + 42) is now **historical** — the
tree has since advanced to `249b799` and grown the uncommitted refactor above.
See the [rationalisation audit](reviews/2026-09-19/rationalisation/REVIEW.md) for
that run's commands, old-to-new mapping, log hashes and source binding.

## Open work and pointers

- Finish and commit the agents-subsystem refactor above; re-run `full` and confirm
  the agent/ollama unit tests and the whole tree are green before claiming so.
- Concurrent branch history: commits `1b0b1d5`..`506e2e5` (role probing,
  attack-tree search, knowledge retrieval, tactical guides) and `fe30f64`..
  `57bcc02` (the dated implementation review's proof/eval/privacy/coverage/export/
  integration findings). These describe their named revisions, not a currently
  certified backlog; inspect the specific caller and its tests.
- The [implementation review](reviews/2026-09-19/implementation-review/REVIEW.md)
  and [prioritised review](reviews/2026-09-19/PRIORITISED_REVIEW.md) are
  revision-bound; the earlier live driver
  `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py` was not re-checked.
  Do not restart unrelated processes based on old notes. Keep future updates in
  this rolling file rather than appending session histories.
