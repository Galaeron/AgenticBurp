# ARTEX borrow plan — 2026-11-26

Source: a read of ARTEX (mirror `acheong08/artex` at `f457a6d`, Go, AGPL-3.0) against this
checkout. Ideas only: no ARTEX code or prompt text is copied (licence). Every batch keeps
`harness/config.yaml` behaviour unchanged by default.

| Batch | Idea taken from ARTEX | Where it lands here | Default |
|---|---|---|---|
| [parallel-drive-20261126](../parallel-drive-20261126/BATCH.md) | Worker pool that claims one unit of work atomically (`server/engine.go` workerLoop, `db/exploration.go` ClaimIntent) | `coverage_tracker.py` drive loops (`:755`, `:865`), sequential today | 1 worker = today's behaviour |
| [click-explore-20261126](../click-explore-20261126/BATCH.md) | Browser exploration by clicking page elements (`skills/playwright-cli`); deletion-label denylist (`db/db.go` seed v3) | `browser_driver.py` / `spa_navigation.py` SPA crawl; open work 0 (review dialog) | off |
| [policy-refusal-20261126](../policy-refusal-20261126/BATCH.md) | A refusal is framed to the model as harness policy, not target defence (`guard/guard.go` systemBlockMessage) | `iterative_agent.py` model-facing history (`:655`, `:657`, `:941`, `:958`, `:984`) | always on (text only) |
| [evidence-integrity-20261126](../evidence-integrity-20261126/BATCH.md) | Evidence re-hashed on every read and export; a saved report goes stale when its evidence changes (`evidence/store.go`, `db/finding_traffic.go`) | `store.py` evidence blobs (`:377`), export and share paths | always on |

Not done: ARTEX's ranked LLM failover pool (`llmpool/pool.go`). `llm_provider.py:47`/`:117`
refuse silent fallback on purpose, and the ledger's provenance rule needs one model per run.
The ARTEX evidence for window-aware skipping was a struct comment, not code that was read.

## Execution
- One subagent per batch, each in its own git worktree, committing on its own branch; none
  pushes. At most 3 run at once (AGENTS.md). Wave 1: parallel-drive, click-explore,
  policy-refusal. Wave 2: evidence-integrity.
- Each batch runs smoke, precondition and its targeted modules. The full suite runs once on
  the merged branch `ccr-66c758a5-7lmduz` (base full run recorded first, same container).
- Environment: `/home/user/.venv-agb` (harness/requirements.lock + playwright 1.63.0, Python
  3.13.18), `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`. No Juice Shop, Ollama or Docker here:
  offline fixtures only, no live-run claims.
- After merge: CURRENT_STATE.md is overwritten once with the result.
