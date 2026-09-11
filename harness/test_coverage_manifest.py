"""
Hermetic tests for the requirement-coverage manifest (coverage_manifest.py).

These pin the improving-notes invariants the manifest exists to enforce:

  - report pass / fail / skipped / manual / not_applicable, with not_implemented
    flagged SEPARATELY as a missing implementation;
  - a passing test yields only PARTIAL requirement coverage (never "complete");
  - **missing evidence, a skipped/failed test, or a manual-only check NEVER counts
    as passing coverage**;
  - requirement coverage is kept SEPARATE from the test outcome.

No network, no model. Synthetic specs + a temp evidence dir, plus one reconcile of
the real committed evidence to tie the manifest to the shipped mass-assignment slice.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import coverage_manifest
from coverage_manifest import (
    RequirementStatus, TestSpec, TestStatus, declared_coverage_ok, load_evidence,
    reconcile, render_markdown, write_evidence,
)
from coverage_model import CHECKS_BY_ID


def _req(report, check_id):
    return next(r for r in report["requirements"] if r["check_id"] == check_id)


class WriteLoadRoundTripTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_manifest_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_write_then_load_round_trips(self):
        p = write_evidence(check_id="WSTG-INPV-05", test_id="t.T.test_x",
                           aspect="sqli in a query param", status=TestStatus.PASS,
                           invariant="inv", reason="ok", observed={"a": 1},
                           evidence_dir=self._tmp)
        self.assertTrue(p.exists())
        loaded = load_evidence(self._tmp)
        rec = loaded[("WSTG-INPV-05", "sqli in a query param")]
        self.assertEqual(rec.status, TestStatus.PASS)
        self.assertEqual(rec.observed, {"a": 1})
        # The catalog metadata is folded in for a self-describing artifact.
        self.assertEqual(rec.wstg_version, CHECKS_BY_ID["WSTG-INPV-05"].wstg_version)

    def test_write_is_byte_deterministic(self):
        kw = dict(check_id="WSTG-INPV-05", test_id="t.T.test_x", aspect="asp",
                  status=TestStatus.PASS, observed={"b": 2, "a": 1}, evidence_dir=self._tmp)
        first = write_evidence(**kw).read_bytes()
        second = write_evidence(**kw).read_bytes()
        self.assertEqual(first, second)  # no wall clock, sorted keys -> stable

    def test_unknown_check_id_rejected(self):
        with self.assertRaises(ValueError):
            write_evidence(check_id="WSTG-NOPE-99", test_id="t", aspect="a",
                           status=TestStatus.PASS, evidence_dir=self._tmp)
        with self.assertRaises(ValueError):
            TestSpec(check_id="WSTG-NOPE-99", test_id="t", aspect="a")

    def test_malformed_artifact_is_ignored_never_a_pass(self):
        (self._tmp / "junk.json").write_text("not json{", encoding="utf-8")
        (self._tmp / "nocheck.json").write_text('{"status":"pass"}', encoding="utf-8")
        self.assertEqual(load_evidence(self._tmp), {})


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_reconcile_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _spec(self, check_id, aspect, kind="automated"):
        return TestSpec(check_id=check_id, test_id=f"m.T.test_{check_id}", aspect=aspect,
                        kind=kind,
                        evidence_file=coverage_manifest.evidence_basename(check_id, aspect))

    def test_pass_evidence_yields_partial_coverage_never_complete(self):
        spec = self._spec("WSTG-INPV-05", "sqli in query")
        write_evidence(check_id="WSTG-INPV-05", test_id=spec.test_id, aspect=spec.aspect,
                       status=TestStatus.PASS, evidence_dir=self._tmp)
        rep = reconcile((spec,), evidence_dir=self._tmp)
        r = _req(rep, "WSTG-INPV-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        self.assertEqual(r["covered_aspects"], ["sqli in query"])
        # A pass proves only the aspect -> the report SAYS it is partial, not complete.
        self.assertIn("partial", r["note"])
        self.assertNotIn("complete", r["requirement_status"])

    def test_missing_evidence_never_counts_as_covered(self):
        spec = self._spec("WSTG-INPV-05", "sqli in query")
        # No artifact written.
        rep = reconcile((spec,), evidence_dir=self._tmp)
        r = _req(rep, "WSTG-INPV-05")
        self.assertNotEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        self.assertEqual(r["tests"][0]["status"], TestStatus.NOT_IMPLEMENTED.value)
        ok, problems = declared_coverage_ok(rep)
        self.assertFalse(ok)  # a declared automated test with no evidence fails the gate
        self.assertTrue(any("WSTG-INPV-05" in p for p in problems))

    def test_failed_evidence_never_counts_as_covered(self):
        spec = self._spec("WSTG-INPV-05", "sqli in query")
        write_evidence(check_id="WSTG-INPV-05", test_id=spec.test_id, aspect=spec.aspect,
                       status=TestStatus.FAIL, reason="assertion failed", evidence_dir=self._tmp)
        rep = reconcile((spec,), evidence_dir=self._tmp)
        r = _req(rep, "WSTG-INPV-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.GAP_FAILED.value)
        self.assertFalse(declared_coverage_ok(rep)[0])

    def test_skipped_evidence_never_counts_as_covered(self):
        spec = self._spec("WSTG-INPV-05", "sqli in query")
        write_evidence(check_id="WSTG-INPV-05", test_id=spec.test_id, aspect=spec.aspect,
                       status=TestStatus.SKIPPED, evidence_dir=self._tmp)
        rep = reconcile((spec,), evidence_dir=self._tmp)
        self.assertEqual(_req(rep, "WSTG-INPV-05")["requirement_status"],
                         RequirementStatus.GAP_SKIPPED.value)

    def test_manual_spec_is_a_flagged_gap_not_coverage(self):
        spec = self._spec("WSTG-SESS-05", "CSRF PoC", kind="manual")
        rep = reconcile((spec,), evidence_dir=self._tmp)
        r = _req(rep, "WSTG-SESS-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.GAP_MANUAL.value)
        self.assertIn("WSTG-SESS-05", rep["manual"])
        self.assertEqual(r["tests"][0]["status"], TestStatus.MANUAL.value)
        # Manual is a KNOWN gap, not a regression -> it does not fail the declared gate.
        self.assertTrue(declared_coverage_ok(rep)[0])

    def test_requirement_without_a_spec_is_flagged_unimplemented(self):
        rep = reconcile((), evidence_dir=self._tmp)  # no specs at all
        self.assertEqual(len(rep["requirements"]), len(CHECKS_BY_ID))
        self.assertTrue(rep["unimplemented"])
        self.assertEqual(_req(rep, "WSTG-INPV-05")["requirement_status"],
                         RequirementStatus.GAP_UNIMPLEMENTED.value)
        # An unimplemented requirement is a known gap, not a declared-coverage regression.
        self.assertTrue(declared_coverage_ok(rep)[0])

    def test_stale_test_id_mismatch_downgrades_pass(self):
        spec = self._spec("WSTG-INPV-05", "sqli in query")
        # Evidence says PASS but from a DIFFERENT test id -> stale, must not count.
        write_evidence(check_id="WSTG-INPV-05", test_id="some.other.test", aspect=spec.aspect,
                       status=TestStatus.PASS, evidence_dir=self._tmp)
        rep = reconcile((spec,), evidence_dir=self._tmp)
        r = _req(rep, "WSTG-INPV-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.GAP_FAILED.value)
        self.assertIn("stale", r["tests"][0]["reason"])

    def test_totals_separate_requirement_from_test_status(self):
        specs = (self._spec("WSTG-INPV-05", "sqli"), self._spec("WSTG-INPV-01", "xss"))
        write_evidence(check_id="WSTG-INPV-05", test_id=specs[0].test_id, aspect="sqli",
                       status=TestStatus.PASS, evidence_dir=self._tmp)
        write_evidence(check_id="WSTG-INPV-01", test_id=specs[1].test_id, aspect="xss",
                       status=TestStatus.FAIL, evidence_dir=self._tmp)
        rep = reconcile(specs, evidence_dir=self._tmp)
        t = rep["totals"]
        self.assertEqual(t["test_status_counts"].get("pass"), 1)
        self.assertEqual(t["test_status_counts"].get("fail"), 1)
        self.assertEqual(t["covered_partial"], 1)  # only the passing one
        self.assertEqual(t["requirements"], len(CHECKS_BY_ID))

    def test_render_markdown_is_a_string_with_headers(self):
        rep = reconcile((), evidence_dir=self._tmp)
        md = render_markdown(rep)
        self.assertIsInstance(md, str)
        self.assertIn("WSTG requirement-coverage report", md)
        self.assertIn("SEPARATELY from test outcomes", md)


class CommittedEvidenceTests(unittest.TestCase):
    """Tie the manifest to the shipped mass-assignment slice's committed artifact."""

    def test_committed_mass_assignment_evidence_reconciles_to_covered(self):
        rep = reconcile()  # real REQUIREMENT_TESTS + real committed EVIDENCE_DIR
        r = _req(rep, "WSTG-CONF-09")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        self.assertEqual(r["tests"][0]["status"], TestStatus.PASS.value)
        self.assertTrue(r["tests"][0]["evidence_path"])
        # The shipped declared coverage must be internally consistent.
        ok, problems = declared_coverage_ok(rep)
        self.assertTrue(ok, f"declared coverage inconsistent: {problems}")


class ModelExtensionTests(unittest.TestCase):
    def test_versioned_wstg_ref(self):
        self.assertEqual(CHECKS_BY_ID["WSTG-CONF-09"].wstg_ref(), "WSTG-CONF-09 (WSTG v4.2)")

    def test_mass_assignment_has_academy_url(self):
        self.assertTrue(CHECKS_BY_ID["WSTG-CONF-09"].academy_url.startswith("https://portswigger.net/"))


if __name__ == "__main__":
    unittest.main()
