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

    def test_reviewer_repro_quoted_false_complete_is_invalid(self):
        """R05 reproduction: complete='false' (a quoted string, as a loosely
        typed JSON/YAML round trip could produce) must classify as invalid,
        never coerced by bare bool() into a truthy "fresh"/"historical"."""
        prov = ScoreProvenance.from_dict({
            "git_revision": "abc123", "run_id": "run-1", "corpus_id": "corpus-v1",
            "inputs_hash": "not-a-real-hash", "complete": "false",
        })
        self.assertFalse(prov.complete)
        self.assertEqual(freshness_label(prov, "abc123", "corpus-v1"), LABEL_INVALID)

    def test_non_bool_non_string_complete_is_rejected(self):
        for bad in (1, 0, None, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _prov(complete=bad)

    def test_garbage_string_complete_is_rejected(self):
        with self.assertRaises(ValueError):
            _prov(complete="yes")

    def test_expected_run_id_mismatch_is_invalid_not_historical(self):
        """R05 reproduction: an artifact whose run_id does not match the run
        the caller actually launched must be invalid, not accepted as a real
        historical result just because its run_id field is nonempty."""
        prov = _prov(run_id="some-other-run")
        self.assertEqual(
            freshness_label(prov, "abc123", "corpus-v1", expected_run_id="run-1"),
            LABEL_INVALID)

    def test_expected_inputs_hash_mismatch_is_invalid(self):
        prov = _prov(inputs_hash="not-a-real-hash")
        self.assertEqual(
            freshness_label(prov, "abc123", "corpus-v1", expected_inputs_hash="deadbeef"),
            LABEL_INVALID)

    def test_matching_expected_run_and_inputs_still_freshens(self):
        prov = _prov()
        self.assertEqual(
            freshness_label(prov, "abc123", "corpus-v1",
                            expected_run_id="run-1", expected_inputs_hash="deadbeef"),
            LABEL_FRESH)

    def test_expected_checks_are_optional_and_backward_compatible(self):
        """A caller that doesn't know the expected run/inputs yet (no kwargs
        supplied) keeps getting the original revision/corpus-only behaviour."""
        prov = _prov()
        self.assertEqual(freshness_label(prov, "abc123", "corpus-v1"), LABEL_FRESH)


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

    def test_reviewer_repro_file_boundary_is_unambiguous(self):
        """R05 reproduction: files containing "ab"+"c" and "a"+"bc" must NOT
        hash the same just because their concatenated bytes are identical --
        that was ambiguous encoding (no separator/length prefix), not a
        genuine SHA-256 collision. Same two paths (same sorted order), only
        the content split between them changes."""
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.txt", Path(d) / "b.txt"
            a.write_text("ab")
            b.write_text("c")
            h1 = compute_inputs_hash([a, b])
            a.write_text("a")
            b.write_text("bc")
            h2 = compute_inputs_hash([a, b])
            self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
