"""Hermetic tests for the fix-verifier (item #10). Pure capsule comparison +
an async reverify path driven by a fake oracle registry."""
from __future__ import annotations

import asyncio
import unittest

from harness.models import Finding, HttpExchange
from harness.oracle_framework import ProofCapsule
from harness import fix_verifier
from harness.fix_verifier import (
    compare_capsules, reverify, CLOSED, PARTIAL, NOT_FIXED, REGRESSED, INCONCLUSIVE,
)


def _cap(reproduced, n_confirmed, n_required=3, verified=None, clean_negative=None):
    if verified is None:
        verified = reproduced
    if clean_negative is None:
        # By default a full non-reproduction (0 confirmed) is a clean executed negative.
        clean_negative = (not reproduced and n_confirmed == 0)
    return ProofCapsule("v", "sqli", n_required, n_confirmed, reproduced,
                        True, reproduced, verified,
                        reproduction_clean_negative=clean_negative, reason="r")


class TestCompareCapsules(unittest.TestCase):
    def test_closed_when_no_longer_reproduces(self):
        v = compare_capsules(prior_reproduced=True, current=_cap(False, 0))
        self.assertEqual(v.verdict, CLOSED)

    def test_not_fixed_when_still_reproduces(self):
        v = compare_capsules(prior_reproduced=True, current=_cap(True, 3))
        self.assertEqual(v.verdict, NOT_FIXED)

    def test_partial_when_intermittent(self):
        v = compare_capsules(prior_reproduced=True, current=_cap(False, 1))
        self.assertEqual(v.verdict, PARTIAL)
        self.assertIn("1/3", v.reason)

    def test_regressed_when_baseline_clean_now_reproduces(self):
        v = compare_capsules(prior_reproduced=False, current=_cap(True, 3))
        self.assertEqual(v.verdict, REGRESSED)

    def test_regressed_on_partial_from_clean_baseline(self):
        v = compare_capsules(prior_reproduced=False, current=_cap(False, 1))
        self.assertEqual(v.verdict, REGRESSED)

    def test_closed_stays_closed_from_clean_baseline(self):
        v = compare_capsules(prior_reproduced=False, current=_cap(False, 0))
        self.assertEqual(v.verdict, CLOSED)

    def test_inconclusive_when_no_oracle(self):
        v = compare_capsules(prior_reproduced=True, current=None)
        self.assertEqual(v.verdict, INCONCLUSIVE)

    def test_inconclusive_when_not_reproduced_but_no_clean_negative(self):
        # Q11/Q03: the probe skipped/errored (not a clean negative) -> INCONCLUSIVE,
        # never CLOSED, even though it "did not reproduce".
        v = compare_capsules(prior_reproduced=True,
                             current=_cap(False, 0, clean_negative=False))
        self.assertEqual(v.verdict, INCONCLUSIVE)
        self.assertIn("clean negative", v.reason)

    def test_closed_requires_clean_executed_negative(self):
        v = compare_capsules(prior_reproduced=True,
                             current=_cap(False, 0, clean_negative=True))
        self.assertEqual(v.verdict, CLOSED)

    def test_to_dict_includes_capsule(self):
        v = compare_capsules(prior_reproduced=True, current=_cap(True, 3))
        d = v.to_dict()
        self.assertEqual(d["verdict"], NOT_FIXED)
        self.assertIn("current_capsule", d)


class FakeOracleRegistry:
    def __init__(self, capsule):
        self._capsule = capsule

    async def verify(self, finding, exchange):
        return self._capsule


class TestReverify(unittest.TestCase):
    def _finding(self):
        return Finding(vulnerability_class="sqli", confidence=0.9, summary="s",
                       evidence="e", suggested_test="t", basis="derived")

    def test_reverify_closed(self):
        reg = FakeOracleRegistry(_cap(False, 0))
        v = asyncio.run(reverify(self._finding(), HttpExchange(url="http://127.0.0.1/i?id=1",
                        method="GET"), reg, prior_reproduced=True))
        self.assertEqual(v.verdict, CLOSED)

    def test_reverify_not_fixed(self):
        reg = FakeOracleRegistry(_cap(True, 3))
        v = asyncio.run(reverify(self._finding(), HttpExchange(url="http://127.0.0.1/i?id=1",
                        method="GET"), reg, prior_reproduced=True))
        self.assertEqual(v.verdict, NOT_FIXED)

    def test_reverify_inconclusive_when_registry_returns_none(self):
        reg = FakeOracleRegistry(None)
        v = asyncio.run(reverify(self._finding(), HttpExchange(url="http://127.0.0.1/i?id=1",
                        method="GET"), reg, prior_reproduced=True))
        self.assertEqual(v.verdict, INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
