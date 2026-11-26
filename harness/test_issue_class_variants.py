"""R11-2: agent label variants of one class group as one issue.

r11 filed one metrics exposure as `exposed_metrics_endpoint`, `exposed metrics
endpoint` and `exposed_public_metrics_endpoint`, and `potential_idor` beside `idor`;
issues.issue_class fell back to the raw lowercased label, so each spelling was its own
issue. Callers: issues.group_findings_into_issues (issue_key) for the report's issues,
and assessment_health.confirmed_issue_accounting (what server._attempt_accounting
returns as the job's issue accounting). Controls: the pre-R11-2 issue_class brings the
split back; two different unknown classes on one route stay two issues; the stored
fingerprint and validator routing (canonicalize) do not move.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from harness import assessment_health, issues, store
from harness.assessment_health import confirmed_issue_accounting
from harness.categories import (canonicalize, distinctive_token, grouping_class, is_lead_label,
                                legacy_canonicalize)
from harness.evidence import TestCaseRef

ORIGIN = "https://captured.example"
METRICS = ("exposed_metrics_endpoint", "exposed metrics endpoint", "exposed_public_metrics_endpoint")


def _pre_r11_2_issue_class(vc: str) -> str:
    vc = vc or ""
    return canonicalize(vc) or distinctive_token(vc) or vc.strip().lower()


def _finding(vc: str, n: int, path: str = "/metrics", **extra) -> dict:
    return {"url": f"{ORIGIN}{path}", "method": "GET", "vulnerability_class": vc,
            "finding_id": f"f{n}", "fingerprint": f"fp{n}", **extra}


class IssueClassTests(unittest.TestCase):

    def test_the_metrics_spellings_are_one_class(self):
        self.assertEqual({issues.issue_class(vc) for vc in METRICS}, {"metrics_exposure"})
        self.assertEqual(issues.issue_class("Exposed-Metrics-Endpoint"), "metrics_exposure")

    def test_a_lead_prefix_is_a_flag_not_a_class(self):
        self.assertEqual(issues.issue_class("potential_idor"), "idor")
        self.assertEqual(issues.issue_class("Potential SQL Injection"), "sqli")
        self.assertTrue(is_lead_label("potential_idor"))
        self.assertTrue(is_lead_label("idor lead"))
        self.assertFalse(is_lead_label("idor"))

    def test_control_unknown_and_near_miss_labels_stay_unmapped(self):
        for vc in ("metrics injection", "exposed_debug_console", "potential", "lead"):
            self.assertIsNone(grouping_class(vc), vc)
        self.assertEqual(issues.issue_class("Exposed_Debug_Console"), "exposed_debug_console")
        # a hedge word on an unknown class keeps the raw label
        self.assertEqual(issues.issue_class("potential_foo_bar"), "potential_foo_bar")

    def test_routing_and_the_stored_fingerprint_do_not_move(self):
        for vc in (*METRICS, "potential_idor"):
            self.assertIsNone(canonicalize(vc), vc)
            self.assertIsNone(legacy_canonicalize(vc), vc)
        a = store.finding_fingerprint("captured.example", "GET", f"{ORIGIN}/metrics", METRICS[0])
        b = store.finding_fingerprint("captured.example", "GET", f"{ORIGIN}/metrics", METRICS[2])
        self.assertNotEqual(a, b)


class IssueGroupingTests(unittest.TestCase):

    def test_the_three_metrics_spellings_on_one_route_are_one_issue(self):
        grouped = issues.group_findings_into_issues([_finding(vc, n) for n, vc in enumerate(METRICS)])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].vulnerability_class, "metrics_exposure")
        self.assertEqual(len(grouped[0].members), 3)

    def test_control_the_raw_label_fallback_splits_them(self):
        with patch.object(issues, "issue_class", _pre_r11_2_issue_class):
            grouped = issues.group_findings_into_issues(
                [_finding(vc, n) for n, vc in enumerate(METRICS)])
        self.assertEqual(len(grouped), 3)

    def test_control_two_unknown_classes_on_one_route_stay_two_issues(self):
        grouped = issues.group_findings_into_issues(
            [_finding("exposed_debug_console", 1), _finding("verbose_stack_banner", 2)])
        self.assertEqual(len(grouped), 2)

    def test_a_lead_and_its_confirmation_are_one_issue(self):
        path = "/api/orders/7"
        grouped = issues.group_findings_into_issues(
            [_finding("potential_idor", 1, path), _finding("idor", 2, path, confirmed=True)])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].vulnerability_class, "idor")
        self.assertFalse(grouped[0].lead)
        lead_only = issues.group_findings_into_issues([_finding("potential_idor", 1, path)])
        self.assertTrue(lead_only[0].lead)

    def test_other_routes_stay_apart(self):
        grouped = issues.group_findings_into_issues(
            [_finding(METRICS[0], 1, "/metrics"), _finding(METRICS[1], 2, "/admin/metrics")])
        self.assertEqual(len(grouped), 2)


def _proof_bound(vc: str, n: int) -> tuple[dict, dict]:
    """One structured proof of the /metrics case, labelled `vc` by its finding."""
    case = TestCaseRef.make(run_id="run1", request_template_id="tpl/metrics",
                            check_id="metrics_exposure").to_dict()
    proof = {"proof_id": f"p{n}", "case": case, "validator": "metrics_exposure_validator",
             "verdict": "confirmed", "executed": True, "legacy": False, "created_at": float(n),
             "baseline_artifact_id": f"b{n}", "attack_artifact_id": f"a{n}",
             "control_artifact_ids": [f"c{n}"]}
    finding = {"confirmed": True, "case_id": case["case_id"], "proof_id": proof["proof_id"],
               "url": f"{ORIGIN}/metrics", "vulnerability_class": vc, "finding_id": f"f{n}"}
    return proof, finding


class JobAccountingTests(unittest.TestCase):
    """confirmed_issue_accounting, as server._attempt_accounting calls it."""

    def _counts(self, labels):
        pairs = [_proof_bound(vc, n) for n, vc in enumerate(labels)]
        proofs = [p for p, _ in pairs]
        by_case = {}
        for p in proofs:
            by_case.setdefault(p["case"]["case_id"], []).append(p)
        out = confirmed_issue_accounting([f for _, f in pairs], "run1", lambda c: by_case.get(c, []),
                                         run_proofs=proofs, artifact_resolver=lambda proof: True)
        return out["counts"], out

    def test_the_three_metrics_spellings_are_one_vulnerability(self):
        counts, out = self._counts(METRICS)
        self.assertEqual(counts["vulnerabilities"], 1)
        self.assertEqual(counts["ledger_confirmed_proof_instances"], 3)
        self.assertEqual({g["vulnerability_class"] for g in out["groups"]}, {"metrics_exposure"})

    def test_control_the_raw_label_fallback_makes_three(self):
        with patch.object(assessment_health, "issue_class", _pre_r11_2_issue_class):
            counts, _ = self._counts(METRICS)
        self.assertEqual(counts["vulnerabilities"], 3)

    def test_control_two_unknown_classes_stay_two(self):
        counts, _ = self._counts(("exposed_debug_console", "verbose_stack_banner"))
        self.assertEqual(counts["vulnerabilities"], 2)


if __name__ == "__main__":
    unittest.main()
