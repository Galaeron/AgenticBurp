# Current state — 2026-09-28

## Checkout

Branch `reconciliation-backlog`; HEAD `d66e606a` (R1 + R3 + R5 + R6 landed this
session as isolated commits off the reconciled working tree; R2/R4/R7 still
uncommitted on disk). Latest analysis:
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
- **Current (after R1 `c2fe5c75` + R3 `cd0273cf` + R5 `b23ad18c` + R6 `d66e606a`;
  R2/R4/R7 still on disk):** exit 0 — 2834 unittest OK (2 skipped), 38 pytest-native
  passed, 229 evaluation OK, 42 integrity OK. (2834 = +2 R1 +1 R3 +1 R5 +1 R6 caller
  tests; the +8 evaluation vs the 221 below is an unrelated untracked file,
  `testing/test_web_objective_benchmark.py`.)
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
| R2 | RA-7's `control_outcome` lost before final suppression | Partial — correct when a validator sets it explicitly; real `cross_identity_validator` now does; the one stub that should (`_CrossIdentityBflaReachedUnprovenValidator`) predates the convention and still reproduces the old symptom | No |
| R3 | Unknown/anonymous principal wildcarded a resolved principal | **Committed `cd0273cf`** | Yes (4-case `suppression_*` caller test) |
| R4 | Reservation admission arithmetic could exceed a hard budget | Yes (admission arithmetic only; SC-8's "no production caller" gap is separate and untouched) | Yes (2 new + 1 corrected in `test_effort.py`) |
| R5 | Cache `clear()`/`size()` ignored the hypothesis-cache table | **Committed `b23ad18c`** | Yes (clear+size caller test) |
| R6 | A failed inference stage was cached and replayed as reusable | **Committed `d66e606a`** | Yes (fail-then-recover caller test) |
| R7 | Browser/DOM/stored-XSS callers omit SC-7's gate/budget objects | Yes | Yes (`test_browser_xss_validator.py`, `test_dom_xss_validator.py`, new `test_stored_xss_validator.py`) |

**R1 (`c2fe5c75`), R3 (`cd0273cf`), R5 (`b23ad18c`) and R6 (`d66e606a`) are committed; R2/R4/R7 remain uncommitted on disk.** Everything else the swarm-refresh review
reconciled (SC-1 real-oracle-gate fix, SC-4/RA-8 fail-closed workflow
assertions, SC-5 MCP adapter forwarding) is unaffected and stands as that
review described. A5/SC-6 (packaging) and A6 (tool-network egress) remain open.

## Current priorities

Loop order: **R4 → R2 → R7** (R1 `c2fe5c75`, R3 `cd0273cf`, R5 `b23ad18c`, R6 `d66e606a` done).

1. R4 and R7: fix + caller tests already on disk (as R1's were) — one commit away
   each; commit after re-confirming `full` green on the isolated diff.
2. R2 also needs the stale `_CrossIdentityBflaReachedUnprovenValidator` stub updated
   to `control_outcome="inconclusive"` and an `analyze()`-level caller test (existing
   tests stop at `_validate_findings`); then audit other `not_confirmed`-returning
   validators for the same gap.
3. Once all R-items close, rerun `reviews/2026-09-28/swarm-refresh/probes.py` and fold
   the result into that review dir. Then SC-8 dispatch wiring, A5/SC-6 packaging, A6
   tool-network egress; then governed integrations + matched-budget efficacy (owner-gated).

Existing owner deferrals remain owner decisions; none of the counterexamples
above needs a live model or real target to reproduce. Preserve
`test_pipeline_gate.py` and its defect-injection controls. No blind keys or
blind implementations read. Keep this file under 100 lines.
