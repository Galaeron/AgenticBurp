# BM-2 — same-class secure-vs-vulnerable discriminator (batch 2026-11-02)

Branch `claude/bm2-discriminator-afa402`, base `9b02511`. Item: IMPROVEMENT_BACKLOG.md BM-2.
No corpus labels, answer keys or blind targets read. Own loopback twins only.

## Where a secure-control false positive becomes "confirmed" (finding, before code)

Only a validator leg sets `finding.confirmed` (`orchestrator_confirm.py` ~726, stamped with
proof/leg). The confirmation gate does not accept a model assertion
(`confirmation_gate.active_confirmation_is_unproven` is the backstop). So two separate paths:

1. **Passive tier (what the benchmark counter measures).** `testing/strict_benchmark.py` replays
   captures with no active legs; `fp_on_tested_negative_control` counts *unconfirmed* model
   hypotheses that surface in the report (`eval_adapter.compute_stages`). Those are never
   "confirmed"; their surfacing is governed by the existing OFF-by-default gates
   (`quarantine_unverified_leads`, `gate_low_confidence_generic`, `gate_uncorroborated_catchall`,
   FR-4). Changing those defaults is out of scope (no config default changes).
2. **Active tier (what this batch fixes).** Per leg, does a secure endpoint of the class confirm?
   - **command_injection** — DEFECT. The in-band oracle confirms when the joined nonce marker
     appears in the attack response. A Ticket-6 "control" (marker pieces without shell syntax)
     is computed but explicitly "never a verdict input". A secure endpoint that strips shell
     metacharacters and echoes the rest (`& whoami & echo HVa^b` -> `whoami echo HVab`) contains
     the joined marker and is confirmed as OS command injection.
   - **path_traversal** — DEFECT. Confirms when `/root:.*:0:0:/` or the win.ini marker appears
     in any probe response, with no baseline. A secure endpoint whose ordinary response already
     carries that text (a fixed document/help page, a viewer that ignores the parameter) is
     confirmed as an arbitrary file read.
   - **sqli (boolean preflight / sqlmap reproduction)** — DEFECT. One tautology request then one
     contradiction request; any status or >20B/5% length difference confirms. Order-dependent
     server state (a secure login that adds a captcha / lockout block after the first failure,
     rotating variable-length content) produces a difference unrelated to the predicate.
   - **xss (browser_xss, stored_xss)** — no defect found: confirmation needs the browser to
     produce the product of two fresh random operands, which the payload never contains, so an
     escaping/echoing secure twin cannot confirm. Twin test added as regression coverage only
     (it passes on base).
   - **idor** — not the same mechanism: `idor_read_validator` never confirms (RV-D2 V2); IDOR
     confirmation is `cross_identity` against `authz.owners` (owner decision), a two-identity
     ownership oracle, not a same-endpoint baseline. Documented, not changed.

## Plan
- cmdi: make the per-template plain-pieces control a verdict input (marker in control => not
  execution; try next template). Sent in and out of a run.
- path_traversal: replay the original request once (lazily, on first marker hit); a marker the
  baseline already shows is not a read.
- sqli: on a differential, re-send contradiction then tautology; confirm only when each repeat
  matches its first answer and the repeats still differ from each other.
- Caller tests: `harness/test_bm2_secure_twin_callers.py`, loopback twins per class through
  `Orchestrator._validate_findings`.
