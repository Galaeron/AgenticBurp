# Current state — 2026-09-28

## Checkout

Branch `reconciliation-backlog`; HEAD `bb421dac` (the full swarm-refresh R1–R7
batch is now committed as seven isolated fix commits, each paired with its own
backlog-closure doc commit). Latest analysis:
[swarm-refresh review](reviews/2026-09-28/swarm-refresh/REVIEW.md) +
[verification](reviews/2026-09-28/swarm-refresh/VERIFICATION.md), which reviewed
this HEAD with a **then-clean** working tree (its own words: "no tracked
production-file modifications were present at the end-of-review source check").
Original [upstream comparison](reviews/2026-09-27/swarm-comparison/REVIEW.md)
uses Pentest-Swarm `661c21828f8a2d0e84ee8b161037d5e9d93942f8`; not refetched.

**Since that review, the working tree has picked up uncommitted production
changes** fixing most of its R1–R7 findings (`git diff --stat`: `cache.py`,
`confirmation_gate.py`, `effort.py`, `models.py`, `orchestrator_chain.py`,
`orchestrator_confirm.py`, `orchestrator_detect.py`,
`validators/{cross_identity,browser_xss,dom_xss,stored_xss}_validator.py`,
plus new/corrected tests). **This is ongoing, concurrent work, not all of it
from this session** — this edit reconciles what's actually on disk right now
against the review's own reproduction script, not just narrates intent.

## Fresh verification (this checkout, current working tree incl. the uncommitted fixes)

`.venv-rationalisation` (Python 3.12.14), repository root, `python -m harness.suite full`:
- **Current (full R1–R7 batch committed, HEAD `bb421dac`):** exit 0 — 2838 unittest
  OK (2 skipped), 38 pytest-native passed, 229 evaluation OK, 42 integrity OK.
  (2838 = the 2829 on-disk baseline + 9 caller tests ADDED this session: R1 +2
  hardening, R2/R3/R4/R5/R6 +1 each, R7 +2 budget-exhaustion; the +8 evaluation vs
  the 221 below is an unrelated untracked file, `testing/test_web_objective_benchmark.py`.)
- **On the R1/R3/R4/R5/R6 fixes (before R7 landed):** exit 0 — 2829 unittest OK
  (2 skipped), 38 pytest-native passed, 221 evaluation OK, 42 integrity OK.
  (2829 vs. the review's 2817 with no test files changed at that point;
  reported as observed, not explained.)
  `smoke` → exit 0, 92 OK. `test_orchestrator_precondition` → 60 OK.
- **After R7 landed, rerun in full a second time (this edit):** exit 0 — same
  2829 unittest OK (2 skipped), 38 pytest-native passed, 221 evaluation OK, 42
  integrity OK. **Clean — no failure.** This directly contradicts a concurrent
  edit to this file that had reported "1 pre-existing, unrelated failure:
  `test_playwright_is_not_installed_here`" for the same post-R7 state; that
  claim did not reproduce against this checkout/venv and should be treated as
  environment-specific to whatever ran it, not a real defect, unless it
  reproduces again.
- Java/wheel/live-model/blind-recall/browser-container/Burp-runtime results are
  unchanged HISTORICAL claims from the swarm-refresh review.

## Reconciled status of the swarm-refresh review's R1–R7

Full evidence, commands and acceptance criteria in
[IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md)'s **Swarm-refresh batch — 2026-09-28**.

| # | Finding | Fix on disk? | Dedicated test? |
|---|---|---|---|
| R1 | Credential-check accepted noise/status jitter as authorization | **Committed `c2fe5c75`** | Yes (2 new + 1 corrected + 2 hardening controls at close, in `test_credential_grant_differential.py`) |
| R2 | RA-7's `control_outcome` lost before final suppression | **Committed `02d21a70`** (both stubs match the real validator; validator audit done) | Yes (`analyze()`-level caller test) |
| R3 | Unknown/anonymous principal wildcarded a resolved principal | **Committed `cd0273cf`** | Yes (4-case `suppression_*` caller test) |
| R4 | Reservation admission arithmetic could exceed a hard budget | **Committed `18cc1ec2`** (arithmetic only; SC-8's "no production caller" gap separate) | Yes (3 tests + 1 corrected in `test_effort.py`) |
| R5 | Cache `clear()`/`size()` ignored the hypothesis-cache table | **Committed `b23ad18c`** | Yes (clear+size caller test) |
| R6 | A failed inference stage was cached and replayed as reusable | **Committed `d66e606a`** | Yes (fail-then-recover caller test) |
| R7 | Browser/DOM/stored-XSS callers omit SC-7's gate/budget objects | **Committed `bb421dac`** | Yes (pass-through + denial-honored + negative control per validator) |

**All of R1–R7 are committed (through `bb421dac`) — the swarm-refresh reconciliation is complete; no R-batch production changes remain uncommitted.** Everything else the swarm-refresh review
reconciled (SC-1 real-oracle-gate fix, SC-4/RA-8 fail-closed workflow
assertions, SC-5 MCP adapter forwarding) is unaffected and stands as that
review described. A5/SC-6 (packaging) and A6 (tool-network egress) remain open.

## Offline loop status — EXHAUSTED (LOOP_DONE)

The swarm-refresh R1–R7 batch is fully committed, and every remaining backlog `[ ]`
item was assessed this session as NOT offline-loop-consumable — so the offline loop is
exhausted again (as at the pre-swarm-refresh `LOOP_DONE`, `ce387cf3`):

- OWNER/LIVE: P1-3's remaining single-command live scorecard, P1-5 (Burp UX), P2-3's
  Burp-tab half, P3-3 (team mode), BM-3, PR-A..E, NC-O1..O5.
- Too large for one clean iteration: P2-1 (a whole new business-reasoning agent),
  SC-10..15 (multi-subsystem "borrows"); SC-9's dep PR-11 is `[~]`.
- Packaging/supply-chain (needs Docker/registry or PyPI egress, not offline): P3-2, SC-6.
- BM-2 is owner-gated in substance: its classes (sqli/xss/idor/path_traversal/command_injection)
  are exactly the ones FR-4 EXCLUDES because a corroboration gate on them collapses recall to
  ~0.05 (`confirmation_gate.py:519–522`); a real control-discriminator is per-validator research
  whose success is corpus-measured, so only a tautology-risking single-twin gate is offline. Left `[ ]`.

**Owner/live follow-ups:** rerun `reviews/2026-09-28/swarm-refresh/probes.py` (needs a scratch patch
for R6's now-3rd pipeline call) as the R-batch capstone; the reservation API still lacks a production
caller; then packaging, tool-egress, BM-2 corpus tuning, and the matched-budget efficacy / blind-recall
runs. A future review can reopen the loop with fresh offline items, as swarm-refresh did.

Existing owner deferrals remain owner decisions; none of the counterexamples
above needs a live model or real target to reproduce. Preserve
`test_pipeline_gate.py` and its defect-injection controls. No blind keys or
blind implementations read. Keep this file under 100 lines.
