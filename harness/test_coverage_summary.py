"""Hermetic tests for coverage_summary.py (P0.6). Builds CoverageMatrix cells
directly -- no discovery/crawl/live target involved."""
from __future__ import annotations

import unittest

from harness.coverage_model import CellResult, CellStatus, CoverageMatrix
from harness.coverage_summary import summarize_coverage, KIND_EXECUTED, KIND_INFERRED, KIND_UNKNOWN


def _matrix(cells: list[tuple[str, str, str, CellResult]]) -> CoverageMatrix:
    m = CoverageMatrix()
    for identity, ep, check, result in cells:
        m.set(identity, ep, check, result)
    return m


class TestSummarizeCoverageMixedMatrix(unittest.TestCase):
    def setUp(self):
        self.matrix = _matrix([
            # Executed conclusive: validator set.
            ("alice", "GET /a", "sqli",
             CellResult(status=CellStatus.CONFIRMED, validator="sqlmap")),
            ("alice", "GET /b", "idor",
             CellResult(status=CellStatus.NOT_DETECTED, validator="cross_identity")),
            # Inferred conclusive: no validator -- an agent asserted it.
            ("alice", "GET /c", "xss",
             CellResult(status=CellStatus.DETECTED)),
            # Not-a-clean-negative bucket.
            ("alice", "GET /d", "ssrf", CellResult(status=CellStatus.SKIPPED)),
            ("alice", "GET /e", "csrf", CellResult(status=CellStatus.ERROR)),
            ("alice", "GET /f", "rate_limit", CellResult(status=CellStatus.INCONCLUSIVE)),
            ("alice", "GET /g", "verb_tamper", CellResult(status=CellStatus.BLOCKED)),
            # Not applicable -- excluded from the denominator entirely.
            ("alice", "GET /h", "file_upload", CellResult(status=CellStatus.NOT_APPLICABLE)),
            # Pending -- counted in applicable, but neither executed nor inferred
            # nor a not-a-clean-negative bucket member.
            ("alice", "GET /i", "ssti", CellResult(status=CellStatus.PENDING)),
        ])

    def test_executed_and_inferred_are_disjoint_counts(self):
        s = summarize_coverage(self.matrix)
        self.assertEqual(s["executed"]["numerator"], 2)
        self.assertEqual(s["inferred"]["numerator"], 1)
        self.assertNotEqual(s["executed"]["numerator"], s["inferred"]["numerator"])

    def test_not_applicable_excluded_from_denominator(self):
        s = summarize_coverage(self.matrix)
        self.assertEqual(s["total_cells"], 9)
        self.assertEqual(s["not_applicable"], 1)
        self.assertEqual(s["applicable"], 8)
        self.assertEqual(s["executed"]["denominator"], 8)

    def test_skip_error_inconclusive_blocked_are_not_clean_negatives(self):
        s = summarize_coverage(self.matrix)
        neg = s["not_a_clean_negative"]
        self.assertEqual(neg["skipped"], 1)
        self.assertEqual(neg["error"], 1)
        self.assertEqual(neg["inconclusive"], 1)
        self.assertEqual(neg["blocked"], 1)
        self.assertEqual(neg["total"], 4)
        # None of these leaked into the conclusive executed/inferred counts.
        self.assertEqual(s["executed"]["numerator"] + s["inferred"]["numerator"], 3)

    def test_percentages_computed_over_named_denominator(self):
        s = summarize_coverage(self.matrix)
        self.assertEqual(s["executed"]["kind"], KIND_EXECUTED)
        self.assertEqual(s["executed"]["pct"], round(100.0 * 2 / 8, 2))
        self.assertEqual(s["inferred"]["kind"], KIND_INFERRED)
        self.assertEqual(s["inferred"]["pct"], round(100.0 * 1 / 8, 2))


class TestSummarizeCoverageAllUnknown(unittest.TestCase):
    def test_all_not_applicable_reports_pct_none_not_fabricated_100(self):
        """Negative control: a matrix where NOTHING is applicable must report
        pct=None for both metrics -- never a fabricated 100% (or 0%) from a
        0/0 division."""
        matrix = _matrix([
            ("alice", "GET /a", "sqli", CellResult(status=CellStatus.NOT_APPLICABLE)),
            ("alice", "GET /b", "idor", CellResult(status=CellStatus.NOT_APPLICABLE)),
        ])
        s = summarize_coverage(matrix)
        self.assertEqual(s["applicable"], 0)
        self.assertEqual(s["executed"]["kind"], KIND_UNKNOWN)
        self.assertIsNone(s["executed"]["pct"])
        self.assertEqual(s["inferred"]["kind"], KIND_UNKNOWN)
        self.assertIsNone(s["inferred"]["pct"])

    def test_empty_matrix_reports_pct_none(self):
        s = summarize_coverage(CoverageMatrix())
        self.assertEqual(s["total_cells"], 0)
        self.assertIsNone(s["executed"]["pct"])
        self.assertIsNone(s["inferred"]["pct"])


if __name__ == "__main__":
    unittest.main()
