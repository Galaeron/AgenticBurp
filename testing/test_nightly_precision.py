"""Hermetic test for the P0.10 CPU-only nightly precision-plumbing check.

No network, no GPU, no live model -- nightly_precision.py's own corpus is
fully stubbed. This proves the SCRIPT itself (not just score.py's math,
already covered by test_score.py) runs end to end and writes SCORECARD.md.
The corpus already carries its own negative control: TN-sqli-1/TN-idor-1
force the same agents with the model returning nothing, so a false positive
in either would show up as fp > 0 and fail the run.

Run from the testing/ directory (matches score.py's own test convention):
    cd testing && python -m unittest test_nightly_precision
"""
from __future__ import annotations

import unittest
from pathlib import Path

import nightly_precision


class NightlyPrecisionPlumbingTest(unittest.TestCase):
    def setUp(self):
        self._had_scorecard = nightly_precision.SCORECARD_PATH.exists()
        self._prior_content = (
            nightly_precision.SCORECARD_PATH.read_text(encoding="utf-8")
            if self._had_scorecard else None
        )

    def tearDown(self):
        if self._had_scorecard:
            nightly_precision.SCORECARD_PATH.write_text(self._prior_content, encoding="utf-8")
        else:
            nightly_precision.SCORECARD_PATH.unlink(missing_ok=True)

    def test_main_writes_scorecard_and_exits_zero(self):
        exit_code = nightly_precision.main()
        self.assertEqual(exit_code, 0)
        self.assertTrue(nightly_precision.SCORECARD_PATH.exists())
        content = nightly_precision.SCORECARD_PATH.read_text(encoding="utf-8")
        self.assertIn("tp=2 fp=0 fn=0", content)
        self.assertIn("NOT a measurement of real model detection accuracy", content)

    def test_negative_control_true_negatives_produce_no_false_positive(self):
        """The corpus's TN-sqli-1/TN-idor-1 labels force the SAME agents as the
        TPs but script the model to return nothing -- if the pipeline ever
        fabricated a finding with no model output, fp would be > 0 here."""
        import asyncio
        labeled = asyncio.run(nightly_precision._run_corpus())
        self.assertEqual(labeled["TN-sqli-1"], [])
        self.assertEqual(labeled["TN-idor-1"], [])
        self.assertIn("sql_injection", labeled["TP-sqli-1"])
        self.assertIn("idor", labeled["TP-idor-1"])


if __name__ == "__main__":
    unittest.main()
