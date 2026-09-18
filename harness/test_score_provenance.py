"""Hermetic tests for score_provenance.py (P0.4). No git subprocess, no live
run -- revision/corpus are supplied by the caller."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.score_provenance import (
    ScoreProvenance, freshness_label, compute_inputs_hash,
    LABEL_FRESH, LABEL_HISTORICAL, LABEL_INVALID,
)


def _prov(**overrides):
    base = dict(git_revision="abc123", run_id="run-1", corpus_id="corpus-v1",
                inputs_hash="deadbeef", complete=True)
    base.update(overrides)
    return ScoreProvenance(**base)


class TestFreshnessLabel(unittest.TestCase):
    def test_fresh_when_complete_and_matching(self):
        prov = _prov()
        self.assertEqual(freshness_label(prov, "abc123", "corpus-v1"), LABEL_FRESH)

    def test_historical_when_revision_differs(self):
        prov = _prov()
        self.assertEqual(freshness_label(prov, "def456", "corpus-v1"), LABEL_HISTORICAL)

    def test_historical_when_corpus_differs(self):
        prov = _prov()
        self.assertEqual(freshness_label(prov, "abc123", "corpus-v2"), LABEL_HISTORICAL)

    def test_invalid_when_incomplete_even_if_revision_matches(self):
        """Negative control: an incomplete run must NEVER read as "fresh" or
        even "historical" -- a run that didn't finish is not a trustworthy
        result at all, regardless of revision match."""
        prov = _prov(complete=False)
        self.assertEqual(freshness_label(prov, "abc123", "corpus-v1"), LABEL_INVALID)

    def test_invalid_when_any_id_field_missing(self):
        for field_name in ("git_revision", "run_id", "corpus_id", "inputs_hash"):
            prov = _prov(**{field_name: ""})
            self.assertEqual(
                freshness_label(prov, "abc123", "corpus-v1"), LABEL_INVALID,
                f"missing {field_name} did not classify as invalid")

    def test_to_dict_from_dict_roundtrip(self):
        prov = _prov()
        restored = ScoreProvenance.from_dict(prov.to_dict())
        self.assertEqual(restored, prov)


class TestComputeInputsHash(unittest.TestCase):
    def test_deterministic_for_same_content(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.json"
            b = Path(d) / "b.json"
            a.write_text('{"x": 1}')
            b.write_text('{"y": 2}')
            h1 = compute_inputs_hash([a, b])
            h2 = compute_inputs_hash([b, a])  # order-independent
            self.assertEqual(h1, h2)

    def test_changes_when_content_changes(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.json"
            a.write_text('{"x": 1}')
            h1 = compute_inputs_hash([a])
            a.write_text('{"x": 2}')
            h2 = compute_inputs_hash([a])
            self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
