"""W-7: explicit CONFIRMED / SUSPECTED / LEAD finding lifecycle state.

The demotion of unconfirmed findings already lives in confirmation_gate
(apply_confirmation_suppression). W-7 adds one canonical state label derived
from (confirmed, review_verdict) and surfaces it through the findings API
(store.all_host_findings) and the report, so "unconfirmed != confirmed" is
visible at a glance instead of hidden behind a raw confidence number.
"""
import tempfile
import unittest
from pathlib import Path

import harness.confirmation_gate as cg
from harness import store
from harness.models import HttpExchange, Finding


class LifecycleStateMappingTests(unittest.TestCase):
    def test_confirmed_is_confirmed(self):
        self.assertEqual(cg.lifecycle_state(True, ""), "CONFIRMED")
        # confirmed wins regardless of any stale verdict
        self.assertEqual(cg.lifecycle_state(True, "unconfirmed_hypothesis"), "CONFIRMED")

    def test_refuted_and_downgraded_verdicts_are_lead(self):
        for verdict in ("unconfirmed_hypothesis", "inconclusive_unverified",
                        "downgraded", "rejected"):
            self.assertEqual(cg.lifecycle_state(False, verdict), "LEAD", verdict)

    def test_open_hypotheses_are_suspected(self):
        for verdict in ("", "survived", "unproven_unverified_leg", "something_else"):
            self.assertEqual(cg.lifecycle_state(False, verdict), "SUSPECTED", verdict)

    def test_finding_lifecycle_state_accepts_object_and_dict(self):
        f = Finding(vulnerability_class="sqli", confidence=0.9, summary="s",
                    evidence="e", suggested_test="t", basis="derived", confirmed=True)
        self.assertEqual(cg.finding_lifecycle_state(f), "CONFIRMED")
        self.assertEqual(
            cg.finding_lifecycle_state({"confirmed": False, "review_verdict": "downgraded"}),
            "LEAD")


class LifecycleStateInFindingsApiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()

    def _persist(self, **kw):
        ex = HttpExchange(url="https://target.test/api/x", method="GET")
        f = Finding(vulnerability_class="sqli", confidence=0.9, summary="s",
                    evidence="e", suggested_test="t", basis="derived", **kw)
        store.persist_findings(ex, "sqli", [f])
        return store.all_host_findings("https://target.test/api/x")[0]

    def test_confirmed_finding_reports_confirmed(self):
        row = self._persist(confirmed=True)
        self.assertEqual(row["lifecycle_state"], "CONFIRMED")
        self.assertIn("review_verdict", row)

    def test_demoted_finding_reports_lead(self):
        row = self._persist(confirmed=False, review_verdict="unconfirmed_hypothesis")
        self.assertEqual(row["lifecycle_state"], "LEAD")

    def test_open_hypothesis_reports_suspected(self):
        row = self._persist(confirmed=False)
        self.assertEqual(row["lifecycle_state"], "SUSPECTED")


class LifecycleStateAfterGateTests(unittest.TestCase):
    """The state must reflect the gate's own demotion: a finding the
    suppression gate demotes is never CONFIRMED and reads as LEAD/SUSPECTED."""

    def test_gate_demotion_yields_non_confirmed_state(self):
        from harness.models import AgentReport
        # A live-verified class (sqli) with a controlled negative -> REFUTED.
        f = Finding(vulnerability_class="sqli", confidence=0.9, severity="high",
                    summary="maybe sqli", evidence="e", suggested_test="t", basis="derived")
        report = AgentReport(agent="sqli", model="stub", findings=[f])

        class _VR:
            status = "not_confirmed"
            confirmed = False
            finding_class = "sqli"

        cg.apply_confirmation_suppression([report], [_VR()])
        self.assertFalse(f.confirmed)
        self.assertEqual(cg.finding_lifecycle_state(f), "LEAD")
        self.assertIn(f.severity, ("info", "low"))  # demoted, not medium+


if __name__ == "__main__":
    unittest.main()
