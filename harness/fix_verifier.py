"""
Fix-verifier / regression verdicts (item #10) -- rides on oracle proof capsules.

Re-tests a previously-found bug by re-running its oracle and comparing the fresh
`ProofCapsule` against the one captured when the bug was found. Crucially it tests
the vulnerability CLASS (does the oracle still reproduce?), not the exact payload
string, so a fix that only blocks the literal payload we happened to use -- while
the class stays exploitable by a sibling payload -- is NOT scored as fixed.

Verdicts:

  * CLOSED     -- was reproducible, now the probe EXECUTED and returned a clean
                  negative on every attempt. Only an executed clean negative closes
                  a bug: a timeout, auth failure, out-of-scope, or missing baseline
                  is INCONCLUSIVE, never CLOSED (Q11/Q03).
  * PARTIAL    -- was reproducible N-of-N, now reproduces only intermittently
                  (some runs confirm, not all). Fragile fix or a flaky bug; needs
                  a human look, never reported as closed.
  * NOT_FIXED  -- was reproducible, still reproduces N-of-N. The fix did nothing.
  * REGRESSED  -- was NOT reproducible at retest baseline (a prior CLOSED/candidate),
                  now reproduces. A regression.
  * INCONCLUSIVE -- the oracle could not run (no applicable leg, a probe error, an
                  off-scope/blocked send, or no clean executed negative), so we
                  cannot make any claim. Never silently treated as closed.

`compare_capsules` is pure and hermetically tested. `reverify` runs the live oracle
(scope/safety-gated through the validators) and hands the result to it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from harness.models import Finding, HttpExchange
from harness.oracle_framework import OracleRegistry, ProofCapsule

log = logging.getLogger("harness.fix_verifier")

CLOSED = "CLOSED"
PARTIAL = "PARTIAL"
NOT_FIXED = "NOT_FIXED"
REGRESSED = "REGRESSED"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class FixVerdict:
    verdict: str
    reason: str
    prior_reproduced: bool
    now_reproduced: bool
    now_n_confirmed: int
    now_n_required: int
    current_capsule: Optional[ProofCapsule] = None

    def to_dict(self) -> dict:
        d = {
            "verdict": self.verdict,
            "reason": self.reason,
            "prior_reproduced": self.prior_reproduced,
            "now_reproduced": self.now_reproduced,
            "now_n_confirmed": self.now_n_confirmed,
            "now_n_required": self.now_n_required,
        }
        if self.current_capsule is not None:
            d["current_capsule"] = self.current_capsule.to_dict()
        return d


def compare_capsules(
    prior_reproduced: bool, current: ProofCapsule | None
) -> FixVerdict:
    """Pure verdict from the prior reproduction status and a fresh capsule.

    `prior_reproduced` is whether the bug reproduced when it was found (a verified
    or reproduced capsule). `current` is None when the oracle could not run now."""
    if current is None:
        return FixVerdict(
            verdict=INCONCLUSIVE,
            reason="no oracle could run at retest -- cannot verify the fix",
            prior_reproduced=prior_reproduced,
            now_reproduced=False,
            now_n_confirmed=0,
            now_n_required=0,
            current_capsule=None,
        )

    now_repro = current.reproduced
    n_conf = current.n_confirmed
    n_req = current.n_required

    if not prior_reproduced:
        # Retest baseline did not reproduce; if it does now, that's a regression.
        if now_repro or n_conf > 0:
            verdict, reason = REGRESSED, (
                f"class did not reproduce at baseline but now confirms "
                f"{n_conf}/{n_req} -- regression")
        else:
            verdict, reason = CLOSED, "did not reproduce at baseline and still does not"
        return FixVerdict(verdict, reason, prior_reproduced, now_repro, n_conf, n_req, current)

    # Prior WAS reproducible.
    if now_repro:
        verdict, reason = NOT_FIXED, (
            f"still reproduces N-of-N ({n_conf}/{n_req}) -- fix ineffective")
    elif n_conf > 0:
        verdict, reason = PARTIAL, (
            f"now reproduces only {n_conf}/{n_req} -- fragile/flaky, not fully closed")
    elif current.reproduction_clean_negative:
        verdict, reason = CLOSED, "probe executed a clean negative -- fix holds"
    else:
        # Q11/Q03: did not reproduce, but the probe did NOT execute a clean negative
        # (skipped/errored/blocked/unreachable). That is not evidence of a fix.
        verdict, reason = INCONCLUSIVE, (
            "did not reproduce, but the probe did not execute a clean negative "
            "(skipped/errored/blocked) -- cannot conclude the bug is fixed")
    return FixVerdict(verdict, reason, prior_reproduced, now_repro, n_conf, n_req, current)


async def reverify(
    finding: Finding,
    exchange: HttpExchange,
    oracle_registry: OracleRegistry,
    *,
    prior_reproduced: bool = True,
) -> FixVerdict:
    """Re-run the oracle for `finding` and score the fix against `prior_reproduced`."""
    current = await oracle_registry.verify(finding, exchange)
    verdict = compare_capsules(prior_reproduced, current)
    log.info("fix-verifier: %s (%s) -> %s", finding.vulnerability_class,
             getattr(finding, "url", ""), verdict.verdict)
    return verdict
