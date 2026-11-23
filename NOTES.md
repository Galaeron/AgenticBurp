# Session handoff (overwrite at the end of each session; 40 lines at most)

## 2026-11-23: principal-audit remediation, batch e1 (docs and project state)
Branch `claude/intelligent-poitras-53161a` on `integrate/audit-fixes-20261120` at `6fe5538c`; not pushed.
Program, rules and every batch HANDOFF: `.test-work/audit-fix-20261120/` (main checkout, untracked).
This batch's detail: `.test-work/audit-fix-20261120/e1-docs-state/HANDOFF.md`.

Done (one commit per ID): DOC-1 (no hard counts in README/LIMITATIONS), DOC-3 (six-step first run),
DOC-4 (what is redacted, USER_MANUAL section 5), DOC-5 (backlog split: open file + archive),
OPS-4 (SECURITY.md, CHANGELOG.md, docs/RELEASING.md), STATE-2 (this file, CURRENT_STATE.md under
100 lines), STATE-4 (`sitecustomize.py` header, TESTING.md), then the README dispatch route and
the `evaluation_integrity` issue label.

Next (owner):
1. Read the e1 HANDOFF's owner decisions; enable GitHub private vulnerability reporting (SECURITY.md).
2. Push `integrate/audit-fixes-20261120` (with e1) and open one PR; CI runs the full suite once.
3. Merge PR #32; decide the local-only files and move the root to `main` (STATE-1).
4. Before checking this branch out in the main checkout, move its untracked `NOTES.md`, and reconcile
   its edited `CLAUDE.md`, `AGENTS.md` and `CURRENT_STATE.md` with these.

Not verified: the clean-machine first-run walk-through (DOC-3), CI's new blocking audit job, the Java
build on this branch (docs only changed), the full suite (CI).

Edit the backlog through `docs/IMPROVEMENT_BACKLOG_ARCHIVE.md`, then `python tools/backlog_index.py --write`.
