"""Tests for the PR-D/BP-5C frozen clustered holdout splitter.

Positive properties (determinism, cluster integrity) each paired with a negative
control (a different seed reshuffles; a hand-crafted leak is refused).
"""
from __future__ import annotations

import unittest

from testing import corpus_holdout as ch


def _pairs(n):
    """n vulnerable/fixed pairs -> 2n cases sharing a pair_id per pair."""
    cases = []
    for i in range(n):
        cases.append({"id": f"c{i}-vuln", "pair_id": f"pair{i}", "expected_vulnerable": True})
        cases.append({"id": f"c{i}-fixed", "pair_id": f"pair{i}", "expected_vulnerable": False})
    return cases


class SplitTests(unittest.TestCase):
    def test_same_seed_is_reproducible(self):  # positive (frozen)
        cases = _pairs(20)
        a = ch.split(cases, seed="s1")
        b = ch.split(cases, seed="s1")
        self.assertEqual(a["train_ids"], b["train_ids"])
        self.assertEqual(a["holdout_ids"], b["holdout_ids"])

    def test_different_seed_reshuffles(self):  # negative control (not a constant split)
        self.assertNotEqual(ch.assign_score("pair0", "s1"),
                            ch.assign_score("pair0", "s2"))

    def test_pairs_never_leak_across_sides(self):  # positive (core guarantee)
        result = ch.split(_pairs(30), seed="s1", holdout_fraction=0.4)
        train_pairs = {c["pair_id"] for c in result["train"]}
        holdout_pairs = {c["pair_id"] for c in result["holdout"]}
        self.assertEqual(train_pairs & holdout_pairs, set())  # no pair straddles
        ch.verify_split(result)  # must not raise

    def test_holdout_and_train_are_disjoint(self):  # positive
        result = ch.split(_pairs(15), seed="x")
        self.assertEqual(set(result["train_ids"]) & set(result["holdout_ids"]), set())

    def test_verify_split_refuses_a_leaked_split(self):  # negative control
        vuln = {"id": "v", "pair_id": "p"}
        fixed = {"id": "f", "pair_id": "p"}
        leaked = {"train": [vuln], "holdout": [fixed]}  # same cluster, both sides
        with self.assertRaises(ch.CorpusSplitError):
            ch.verify_split(leaked)

    def test_singleton_clustering_when_no_group_key(self):
        cases = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        result = ch.split(cases, seed="s1")
        self.assertEqual(result["cluster_count"], 3)  # each its own cluster
        ch.verify_split(result)

    def test_duplicate_ids_refused(self):  # negative control
        with self.assertRaises(ch.CorpusSplitError):
            ch.split([{"id": "dup"}, {"id": "dup"}])

    def test_realized_fraction_tracks_request(self):
        result = ch.split(_pairs(100), seed="s1", holdout_fraction=0.3)
        frac = result["realized_holdout_fraction"]
        self.assertIsNotNone(frac)
        self.assertLess(abs(frac - 0.3), 0.15)  # approximate, cluster-quantized
        self.assertTrue(result["curated_holdout_untouched"])


if __name__ == "__main__":
    unittest.main()
