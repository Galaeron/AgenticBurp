"""
Hermetic tests for the requirement-coverage manifest + evidence runner.

Pins the review fixes:
  - issue 1: the gate checks EVERY declared automated aspect independently -- one
    passing aspect never hides a failing / skipped / missing sibling;
  - issue 2: evidence is bound to the run id (a stale artifact can't satisfy a new
    run) and outcomes are recorded THROUGH the runner (fail/skip are recorded);
  - issue 3: exact non-empty test_id match, schema validation, duplicate rejection;
  - issue 4: the mass-assignment scenario has an internal id + external refs;
  - issue 5: each aspect is a separate labelled artifact;
  - issue 6: applicability with rationale (incl. requirement-level not_applicable),
    and residual aspects are retained in gaps even under partial coverage.

No network, no model. Temp evidence dirs + explicit run ids.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import harness.coverage_manifest as cm
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.coverage_manifest import (
    RequirementStatus, TestSpec, TestStatus, declared_coverage_ok, load_evidence,
    reconcile, render_markdown, write_evidence,
)
from harness.coverage_model import CHECKS_BY_ID

RUN = "RUN_UNDER_TEST"


def _req(report, check_id):
    return next(r for r in report["requirements"] if r["check_id"] == check_id)


def _spec(check_id, aspect, *, mode="automated", label="unit", test_id=None):
    tid = test_id if test_id is not None else f"m.T.test_{cm._slug(aspect)}"
    return TestSpec(check_id=check_id, test_id=tid, aspect=aspect, mode=mode, label=label,
                    evidence_file=cm.evidence_basename(check_id, aspect))


def _write(tmp, check_id, aspect, status, *, test_id="m.T.test_x", run_id=RUN):
    return write_evidence(check_id=check_id, aspect=aspect, status=status, test_id=test_id,
                          run_id=run_id, evidence_dir=tmp)


class WriteLoadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_wl_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def test_round_trip_separates_observation_and_execution(self):
        _write(self._tmp, "WSTG-INPV-05", "sqli in q", TestStatus.PASS, test_id="mod.T.test_x")
        body = json.loads(next(self._tmp.glob("*.json")).read_text())
        self.assertEqual(body["schema_version"], cm.SCHEMA_VERSION)
        self.assertIn("observation", body)
        self.assertIn("execution", body)
        self.assertEqual(body["execution"]["run_id"], RUN)
        loaded = load_evidence(self._tmp, run_id=RUN)
        rec = loaded[("WSTG-INPV-05", "sqli in q")]
        self.assertEqual(rec.status, TestStatus.PASS)
        self.assertEqual(rec.test_id, "mod.T.test_x")

    def test_freshness_stale_run_is_ignored(self):
        _write(self._tmp, "WSTG-INPV-05", "sqli", TestStatus.PASS, run_id="OLD_RUN")
        self.assertEqual(load_evidence(self._tmp, run_id="NEW_RUN"), {})   # stale -> gone
        self.assertIn(("WSTG-INPV-05", "sqli"), load_evidence(self._tmp, run_id="OLD_RUN"))

    def test_unsupported_schema_is_invalid_never_pass(self):
        p = self._tmp / cm.evidence_basename("WSTG-INPV-05", "x")
        p.write_text(json.dumps({"schema_version": 999, "check_id": "WSTG-INPV-05",
                                 "aspect": "x", "execution": {"status": "pass",
                                 "run_id": RUN, "test_id": "m.T.test_x"}}))
        rec = load_evidence(self._tmp, run_id=RUN)[("WSTG-INPV-05", "x")]
        self.assertTrue(rec.conflict)
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_duplicate_artifacts_become_a_conflict(self):
        for name in ("a.json", "b.json"):
            (self._tmp / name).write_text(json.dumps({
                "schema_version": cm.SCHEMA_VERSION, "check_id": "WSTG-INPV-05",
                "aspect": "dup", "execution": {"status": "pass", "run_id": RUN,
                                               "test_id": "m.T.test_x"}}))
        rec = load_evidence(self._tmp, run_id=RUN)[("WSTG-INPV-05", "dup")]
        self.assertTrue(rec.conflict)
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_unknown_check_id_rejected(self):
        with self.assertRaises(ValueError):
            write_evidence(check_id="WSTG-NOPE-99", aspect="a", status=TestStatus.PASS,
                           test_id="t", run_id=RUN, evidence_dir=self._tmp)
        with self.assertRaises(ValueError):
            TestSpec(check_id="WSTG-NOPE-99", test_id="t", aspect="a")
        with self.assertRaises(ValueError):
            TestSpec(check_id="WSTG-INPV-05", test_id="", aspect="a")  # automated needs id


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_rec_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _reconcile(self, specs, **kw):
        return reconcile(tuple(specs), evidence_dir=self._tmp, run_id=RUN, **kw)

    def test_pass_is_partial_never_complete(self):
        spec = _spec("WSTG-INPV-05", "sqli in q", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INPV-05", "sqli in q", TestStatus.PASS, test_id="mod.T.test_x")
        r = _req(self._reconcile([spec]), "WSTG-INPV-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        self.assertIn("partial", r["note"])
        self.assertTrue(declared_coverage_ok(self._reconcile([spec]))[0])

    def test_missing_evidence_never_covered(self):
        spec = _spec("WSTG-INPV-05", "sqli")   # nothing written
        rep = self._reconcile([spec])
        r = _req(rep, "WSTG-INPV-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.NOT_IMPLEMENTED.value)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok)
        self.assertTrue(any("WSTG-INPV-05" in p for p in probs))

    def test_empty_test_id_is_rejected(self):
        # issue 3: an empty evidence test_id must NOT pass.
        spec = _spec("WSTG-INPV-05", "sqli", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INPV-05", "sqli", TestStatus.PASS, test_id="")
        r = _req(self._reconcile([spec]), "WSTG-INPV-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.FAIL.value)
        self.assertFalse(declared_coverage_ok(self._reconcile([spec]))[0])

    def test_mismatched_test_id_is_rejected(self):
        spec = _spec("WSTG-INPV-05", "sqli", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INPV-05", "sqli", TestStatus.PASS, test_id="mod.T.other")
        r = _req(self._reconcile([spec]), "WSTG-INPV-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.FAIL.value)

    # ---- issue 1: one passing aspect must not hide a failing sibling ----

    def _mixed(self, sibling_status, *, write_sibling=True):
        a = _spec("WSTG-INPV-05", "aspect A", test_id="mod.T.test_a")
        b = _spec("WSTG-INPV-05", "aspect B", test_id="mod.T.test_b")
        _write(self._tmp, "WSTG-INPV-05", "aspect A", TestStatus.PASS, test_id="mod.T.test_a")
        if write_sibling:
            _write(self._tmp, "WSTG-INPV-05", "aspect B", sibling_status, test_id="mod.T.test_b")
        return self._reconcile([a, b])

    def test_gate_fails_on_pass_plus_fail(self):
        rep = self._mixed(TestStatus.FAIL)
        r = _req(rep, "WSTG-INPV-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok, "gate passed despite a failing sibling aspect")
        self.assertTrue(any("aspect B" in p for p in probs))
        # issue 6: the failing sibling is retained in gaps under a partial requirement.
        self.assertIn("WSTG-INPV-05", [g["check_id"] for g in rep["gaps"]])

    def test_gate_fails_on_pass_plus_skipped(self):
        rep = self._mixed(TestStatus.SKIPPED)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok)
        self.assertTrue(any("aspect B" in p for p in probs))

    def test_gate_fails_on_pass_plus_missing(self):
        rep = self._mixed(None, write_sibling=False)  # sibling evidence never written
        r = _req(rep, "WSTG-INPV-05")
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok)
        self.assertTrue(any("aspect B" in p for p in probs))
        self.assertTrue(any(t["status"] == TestStatus.NOT_IMPLEMENTED.value
                            for t in r["tests"]))

    # ---- manual / unimplemented / applicability ----

    def test_manual_is_flagged_gap_not_regression(self):
        spec = _spec("WSTG-SESS-05", "CSRF PoC", mode="manual")
        rep = self._reconcile([spec])
        r = _req(rep, "WSTG-SESS-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.GAP_MANUAL.value)
        self.assertIn("WSTG-SESS-05", rep["manual"])
        self.assertTrue(declared_coverage_ok(rep)[0])  # manual is a known gap, not a regression

    def test_unimplemented_flagged_and_not_a_regression(self):
        rep = self._reconcile([])   # no specs at all
        self.assertEqual(len(rep["requirements"]), len(CHECKS_BY_ID))
        self.assertTrue(rep["unimplemented"])
        self.assertTrue(declared_coverage_ok(rep)[0])

    def test_declared_not_applicable_with_rationale(self):
        # issue 6: a requirement-level not_applicable now exists, carrying a rationale,
        # and it is excluded from gaps and from the gate.
        spec = _spec("WSTG-INPV-07", "xxe")   # would be a gap if applicable
        rep = self._reconcile([spec], applicability={"WSTG-INPV-07": (False, "no XML endpoints in scope")})
        r = _req(rep, "WSTG-INPV-07")
        self.assertEqual(r["requirement_status"], RequirementStatus.NOT_APPLICABLE.value)
        self.assertEqual(r["applicability"], {"applicable": False, "rationale": "no XML endpoints in scope"})
        self.assertNotIn("WSTG-INPV-07", [g["check_id"] for g in rep["gaps"]])
        self.assertTrue(declared_coverage_ok(rep)[0])

    def test_every_requirement_carries_applicability_rationale(self):
        rep = self._reconcile([])
        self.assertTrue(all(r["applicability"]["rationale"] for r in rep["requirements"]))

    def test_duplicate_evidence_fails_the_gate(self):
        spec = _spec("WSTG-INPV-05", "dup", test_id="mod.T.test_x")
        for name in ("a.json", "b.json"):
            (self._tmp / name).write_text(json.dumps({
                "schema_version": cm.SCHEMA_VERSION, "check_id": "WSTG-INPV-05",
                "aspect": "dup", "execution": {"status": "pass", "run_id": RUN,
                                               "test_id": "mod.T.test_x"}}))
        self.assertFalse(declared_coverage_ok(self._reconcile([spec]))[0])

    def test_render_markdown_smoke(self):
        md = render_markdown(self._reconcile([]))
        self.assertIn("Requirement-coverage report", md)
        self.assertIn("SEPARATELY from test outcomes", md)


# ---------------------------------------------------------------------------
# The evidence RUNNER records the actual outcome (issue 2)
#
# The dummy EvidenceCase subclasses are built LOCALLY inside each test so the
# unittest loader never collects (and runs) the deliberately-failing one.
# ---------------------------------------------------------------------------

class EvidenceRunnerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_run_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _run_case(self, aspect, body):
        tmp = self._tmp

        @evidence_for(check_id="WSTG-INPV-05", aspect=aspect, label="unit")
        def test_it(self):
            body(self)

        cls = type("DynEvidenceCase", (EvidenceCase,),
                   {"evidence_dir_override": tmp, "test_it": test_it})
        cls("test_it").run(unittest.TestResult())
        return load_evidence(tmp, run_id=cm.current_run_id())

    def test_pass_records_pass(self):
        def body(s):
            s.record_observation({"x": 1})
            s.assertTrue(True)
        rec = self._run_case("runner pass", body)[("WSTG-INPV-05", "runner pass")]
        self.assertEqual(rec.status, TestStatus.PASS)
        self.assertEqual(rec.observation, {"x": 1})
        self.assertTrue(rec.test_id.endswith(".test_it"))

    def test_failure_records_fail_not_pass(self):
        rec = self._run_case("runner fail", lambda s: s.assertEqual(1, 2))[("WSTG-INPV-05", "runner fail")]
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_skip_records_skipped(self):
        rec = self._run_case("runner skip", lambda s: s.skipTest("x"))[("WSTG-INPV-05", "runner skip")]
        self.assertEqual(rec.status, TestStatus.SKIPPED)

    def test_failed_run_cannot_satisfy_gate(self):
        # A failing run's fresh 'fail' artifact must not read as coverage.
        loaded = self._run_case("runner fail2", lambda s: s.assertEqual(1, 2))
        rec = loaded[("WSTG-INPV-05", "runner fail2")]
        spec = _spec("WSTG-INPV-05", "runner fail2", test_id=rec.test_id)
        rep = reconcile((spec,), evidence_dir=self._tmp, run_id=cm.current_run_id())
        self.assertFalse(declared_coverage_ok(rep)[0])


# ---------------------------------------------------------------------------
# Model extension (issue 4): internal id + external refs; WSTG-CONF-09 unbound
# ---------------------------------------------------------------------------

class ModelExtensionTests(unittest.TestCase):
    def test_genuine_wstg_ref_is_versioned(self):
        self.assertEqual(CHECKS_BY_ID["WSTG-INPV-05"].reference_label(), "WSTG-INPV-05 (WSTG v4.2)")
        self.assertTrue(CHECKS_BY_ID["WSTG-INPV-05"].is_wstg())

    def test_mass_assignment_is_internal_with_external_refs(self):
        c = CHECKS_BY_ID["AV-MASSASSIGN-01"]
        self.assertFalse(c.is_wstg())
        self.assertIn("internal", c.reference_label())
        catalogs = {e.catalog for e in c.external_refs}
        self.assertIn("PortSwigger Academy", catalogs)
        self.assertTrue(any("OWASP" in cat for cat in catalogs))
        # It must NOT falsely claim a WSTG id anywhere.
        self.assertTrue(all(e.catalog != "WSTG" for e in c.external_refs))

    def test_wstg_conf_09_is_test_file_permission_not_mass_assignment(self):
        # WSTG-CONF-09 now carries its GENUINE OWASP meaning, not mass assignment.
        self.assertIn("WSTG-CONF-09", CHECKS_BY_ID)
        self.assertEqual(CHECKS_BY_ID["WSTG-CONF-09"].name, "Test File Permission")
        self.assertNotEqual(CHECKS_BY_ID["WSTG-CONF-09"].vulnerability_class, "api_security")


if __name__ == "__main__":
    unittest.main()
