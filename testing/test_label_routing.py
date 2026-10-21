"""Phase 2.1 -- baseline + regression ratchet for finding-label routing.

Loads the committed baseline (testing/fixtures/crapi_finding_labels.json -- every
label the model emitted across the three crAPI result files, with how many reach
a validator today) and recomputes routing with the CURRENT harness. The miss rate
must never rise above the recorded baseline: Phase 2.2 (constrain the label
vocabulary + route by agent) should DROP it, and any change that re-breaks routing
fails here. Also pins the vocabulary-vs-wording nature of the miss with concrete
examples, so the fixture can't be gamed by a predicate that routes everything.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))

import label_routing as lr  # noqa: E402

_FIXTURE = _HERE / "fixtures" / "crapi_finding_labels.json"


def _load():
    with open(_FIXTURE, encoding="utf-8") as f:
        return json.load(f)


class LabelRoutingBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = _load()
        cls.counts = {row["label"]: row["count"] for row in cls.fx["labels"]}
        cls.summary = lr.classify(cls.counts)

    def test_fixture_is_substantive(self):
        # Guard against an emptied/[]-ed fixture silently passing the ratchet.
        self.assertEqual(len(self.counts), self.fx["distinct_labels"])
        self.assertGreaterEqual(self.fx["distinct_labels"], 100)
        self.assertEqual(sum(self.counts.values()), self.fx["total_findings"])
        self.assertGreaterEqual(self.fx["total_findings"], 500)

    def test_distinct_miss_rate_not_above_baseline(self):
        self.assertLessEqual(
            self.summary["distinct_miss_rate"], self.fx["baseline_distinct_miss_rate"],
            f"label-routing regressed: {self.summary['distinct_missing']} of "
            f"{self.summary['distinct_labels']} labels now miss "
            f"({self.summary['distinct_miss_rate']}) vs baseline "
            f"{self.fx['baseline_distinct_miss_rate']}. Newly missing: "
            f"{sorted(set(self.summary['missing_labels']) - set(self.fx['baseline_missing_labels']))}")

    def test_weighted_miss_rate_not_above_baseline(self):
        self.assertLessEqual(
            self.summary["weighted_miss_rate"], self.fx["baseline_weighted_miss_rate"],
            f"finding-loss regressed: {self.summary['findings_missed']} of "
            f"{self.summary['total_findings']} findings now reach no validator "
            f"({self.summary['weighted_miss_rate']}) vs baseline "
            f"{self.fx['baseline_weighted_miss_rate']}")

    def test_some_labels_route_and_some_miss_at_baseline(self):
        # The baseline is a real measurement, not 0% or 100%: a non-trivial share
        # routes AND a non-trivial share misses (the gap Phase 2.2 closes).
        self.assertGreater(self.fx["baseline_distinct_miss_rate"], 0.0)
        self.assertLess(self.fx["baseline_distinct_miss_rate"], 1.0)

    def test_previously_routable_labels_cannot_regress_in_exchange_for_improvements(self):
        self.assertFalse(set(self.summary["missing_labels"]) - set(self.fx["baseline_missing_labels"]))


class RoutingPredicateTests(unittest.TestCase):
    def test_canonical_classes_route(self):
        for label in ("idor", "sqli", "xss", "ssrf", "open_redirect"):
            self.assertTrue(lr.routes_to_validator(label), label)

    def test_access_control_prose_routes_via_markers(self):
        self.assertTrue(lr.routes_to_validator("Broken Access Control"))

    def test_unknown_vocabulary_misses(self):
        self.assertFalse(lr.routes_to_validator("Totally Made Up Nonsense Class XYZ"))

    def test_historical_wording_gap_is_recorded_without_requiring_it_to_persist(self):
        # The crux the baseline captures: the SAME vulnerability wins or loses on
        # wording. "Mass Assignment" routes; the ALL-CAPS slashed title does not --
        # the exact free-text-label loss Phase 2.2 is meant to remove.
        self.assertTrue(lr.routes_to_validator("Mass Assignment"))
        self.assertIn("MASS ASSIGNMENT / EXCESSIVE DATA BINDING", _load()["baseline_missing_labels"])


if __name__ == "__main__":
    unittest.main()
