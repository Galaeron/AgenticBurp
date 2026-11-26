# Session handoff (overwrite at the end of each session; 40 lines at most)

## 2026-11-26: merge the r11 and principal-audit stack to main
Branch `ccr-eb5addff-9zxd82` (PR #36) on `integrate/audit-fixes-g-20261124` (PR #35's tip `6031d704`).

Done:
- CI was green on #31 to #35 (full suite, Java, advisory pip-audit). The main-only
  `dependency-audit-blocking` job (OPS-1) had never run; pip-audit found 29 known vulnerabilities in
  8 lock packages. #36 bumps them within mitmproxy 12.3.1's caps and allowlists the four tornado ids
  fixed only in 6.6+ (mitmproxy caps tornado<=6.5.10; the harness runs mitmdump, no tornado server).
- Merge order: #31, #32, #33, #34, #35, #36, each retargeted to `main` after the one before merged.
  The pushes for #33 to #35 fail only the blocking audit job; #36's push is the first that passes it.

Next (owner):
1. Check main's CI on #36's merge commit (full suite and `dependency-audit-blocking`).
2. The owner decisions #33, #34 and #35 list (CURRENT_STATE.md open work 0 and 1).
3. Before 2027-01-31: drop or renew the tornado entries in `.github/pip-audit-allowlist.toml`.

Not verified: the full suite on #36 locally (its CI runs it); the clean-machine first run (DOC-3).

Edit the backlog through `docs/IMPROVEMENT_BACKLOG_ARCHIVE.md`, then `python tools/backlog_index.py --write`.
