"""
Hermetic tests for the requirement-coverage manifest + evidence runner.

Pins the review fixes:
  - issue 1: the gate checks EVERY declared automated aspect independently -- one
    passing aspect never hides a failing / skipped / missing sibling;
  - issue 2: evidence is bound to the run id (a stale artifact can't satisfy a new
    run) and outcomes are recorded THROUGH the runner (fail/skip are recorded);
  - issue 3: exact non-empty test_id match, schema validation, duplicate rejection;
  - issue 4: the mass-assignment scenario keeps its external refs (WG-1: its id is now
    WSTG-INJT-20, formerly the internal AV-MASSASSIGN-01);
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
        _write(self._tmp, "WSTG-INJT-05", "sqli in q", TestStatus.PASS, test_id="mod.T.test_x")
        body = json.loads(next(self._tmp.glob("*.json")).read_text())
        self.assertEqual(body["schema_version"], cm.SCHEMA_VERSION)
        self.assertIn("observation", body)
        self.assertIn("execution", body)
        self.assertEqual(body["execution"]["run_id"], RUN)
        loaded = load_evidence(self._tmp, run_id=RUN)
        rec = loaded[("WSTG-INJT-05", "sqli in q")]
        self.assertEqual(rec.status, TestStatus.PASS)
        self.assertEqual(rec.test_id, "mod.T.test_x")

    def test_freshness_stale_run_is_ignored(self):
        _write(self._tmp, "WSTG-INJT-05", "sqli", TestStatus.PASS, run_id="OLD_RUN")
        self.assertEqual(load_evidence(self._tmp, run_id="NEW_RUN"), {})   # stale -> gone
        self.assertIn(("WSTG-INJT-05", "sqli"), load_evidence(self._tmp, run_id="OLD_RUN"))

    def test_unsupported_schema_is_invalid_never_pass(self):
        p = self._tmp / cm.evidence_basename("WSTG-INJT-05", "x")
        p.write_text(json.dumps({"schema_version": 999, "check_id": "WSTG-INJT-05",
                                 "aspect": "x", "execution": {"status": "pass",
                                 "run_id": RUN, "test_id": "m.T.test_x"}}))
        rec = load_evidence(self._tmp, run_id=RUN)[("WSTG-INJT-05", "x")]
        self.assertTrue(rec.conflict)
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_duplicate_artifacts_become_a_conflict(self):
        for name in ("a.json", "b.json"):
            (self._tmp / name).write_text(json.dumps({
                "schema_version": cm.SCHEMA_VERSION, "check_id": "WSTG-INJT-05",
                "aspect": "dup", "execution": {"status": "pass", "run_id": RUN,
                                               "test_id": "m.T.test_x"}}))
        rec = load_evidence(self._tmp, run_id=RUN)[("WSTG-INJT-05", "dup")]
        self.assertTrue(rec.conflict)
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_unknown_check_id_rejected(self):
        with self.assertRaises(ValueError):
            write_evidence(check_id="WSTG-NOPE-99", aspect="a", status=TestStatus.PASS,
                           test_id="t", run_id=RUN, evidence_dir=self._tmp)
        with self.assertRaises(ValueError):
            TestSpec(check_id="WSTG-NOPE-99", test_id="t", aspect="a")
        with self.assertRaises(ValueError):
            TestSpec(check_id="WSTG-INJT-05", test_id="", aspect="a")  # automated needs id


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_rec_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _reconcile(self, specs, **kw):
        return reconcile(tuple(specs), evidence_dir=self._tmp, run_id=RUN, **kw)

    def test_pass_is_partial_never_complete(self):
        spec = _spec("WSTG-INJT-05", "sqli in q", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INJT-05", "sqli in q", TestStatus.PASS, test_id="mod.T.test_x")
        r = _req(self._reconcile([spec]), "WSTG-INJT-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        self.assertIn("partial", r["note"])
        self.assertTrue(declared_coverage_ok(self._reconcile([spec]))[0])

    def test_missing_evidence_never_covered(self):
        spec = _spec("WSTG-INJT-05", "sqli")   # nothing written
        rep = self._reconcile([spec])
        r = _req(rep, "WSTG-INJT-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.NOT_IMPLEMENTED.value)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok)
        self.assertTrue(any("WSTG-INJT-05" in p for p in probs))

    def test_empty_test_id_is_rejected(self):
        # issue 3: an empty evidence test_id must NOT pass.
        spec = _spec("WSTG-INJT-05", "sqli", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INJT-05", "sqli", TestStatus.PASS, test_id="")
        r = _req(self._reconcile([spec]), "WSTG-INJT-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.FAIL.value)
        self.assertFalse(declared_coverage_ok(self._reconcile([spec]))[0])

    def test_mismatched_test_id_is_rejected(self):
        spec = _spec("WSTG-INJT-05", "sqli", test_id="mod.T.test_x")
        _write(self._tmp, "WSTG-INJT-05", "sqli", TestStatus.PASS, test_id="mod.T.other")
        r = _req(self._reconcile([spec]), "WSTG-INJT-05")
        self.assertEqual(r["tests"][0]["status"], TestStatus.FAIL.value)

    # ---- issue 1: one passing aspect must not hide a failing sibling ----

    def _mixed(self, sibling_status, *, write_sibling=True):
        a = _spec("WSTG-INJT-05", "aspect A", test_id="mod.T.test_a")
        b = _spec("WSTG-INJT-05", "aspect B", test_id="mod.T.test_b")
        _write(self._tmp, "WSTG-INJT-05", "aspect A", TestStatus.PASS, test_id="mod.T.test_a")
        if write_sibling:
            _write(self._tmp, "WSTG-INJT-05", "aspect B", sibling_status, test_id="mod.T.test_b")
        return self._reconcile([a, b])

    def test_gate_fails_on_pass_plus_fail(self):
        rep = self._mixed(TestStatus.FAIL)
        r = _req(rep, "WSTG-INJT-05")
        self.assertEqual(r["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok, "gate passed despite a failing sibling aspect")
        self.assertTrue(any("aspect B" in p for p in probs))
        # issue 6: the failing sibling is retained in gaps under a partial requirement.
        self.assertIn("WSTG-INJT-05", [g["check_id"] for g in rep["gaps"]])

    def test_gate_fails_on_pass_plus_skipped(self):
        rep = self._mixed(TestStatus.SKIPPED)
        ok, probs = declared_coverage_ok(rep)
        self.assertFalse(ok)
        self.assertTrue(any("aspect B" in p for p in probs))

    def test_gate_fails_on_pass_plus_missing(self):
        rep = self._mixed(None, write_sibling=False)  # sibling evidence never written
        r = _req(rep, "WSTG-INJT-05")
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
        spec = _spec("WSTG-INJT-07", "xxe")   # would be a gap if applicable
        rep = self._reconcile([spec], applicability={"WSTG-INJT-07": (False, "no XML endpoints in scope")})
        r = _req(rep, "WSTG-INJT-07")
        self.assertEqual(r["requirement_status"], RequirementStatus.NOT_APPLICABLE.value)
        self.assertEqual(r["applicability"], {"applicable": False, "rationale": "no XML endpoints in scope"})
        self.assertNotIn("WSTG-INJT-07", [g["check_id"] for g in rep["gaps"]])
        self.assertTrue(declared_coverage_ok(rep)[0])

    def test_every_requirement_carries_applicability_rationale(self):
        rep = self._reconcile([])
        self.assertTrue(all(r["applicability"]["rationale"] for r in rep["requirements"]))

    def test_duplicate_evidence_fails_the_gate(self):
        spec = _spec("WSTG-INJT-05", "dup", test_id="mod.T.test_x")
        for name in ("a.json", "b.json"):
            (self._tmp / name).write_text(json.dumps({
                "schema_version": cm.SCHEMA_VERSION, "check_id": "WSTG-INJT-05",
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

        @evidence_for(check_id="WSTG-INJT-05", aspect=aspect, label="unit")
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
        rec = self._run_case("runner pass", body)[("WSTG-INJT-05", "runner pass")]
        self.assertEqual(rec.status, TestStatus.PASS)
        self.assertEqual(rec.observation, {"x": 1})
        self.assertTrue(rec.test_id.endswith(".test_it"))

    def test_failure_records_fail_not_pass(self):
        rec = self._run_case("runner fail", lambda s: s.assertEqual(1, 2))[("WSTG-INJT-05", "runner fail")]
        self.assertEqual(rec.status, TestStatus.FAIL)

    def test_skip_records_skipped(self):
        rec = self._run_case("runner skip", lambda s: s.skipTest("x"))[("WSTG-INJT-05", "runner skip")]
        self.assertEqual(rec.status, TestStatus.SKIPPED)

    def test_failed_run_cannot_satisfy_gate(self):
        # A failing run's fresh 'fail' artifact must not read as coverage.
        loaded = self._run_case("runner fail2", lambda s: s.assertEqual(1, 2))
        rec = loaded[("WSTG-INJT-05", "runner fail2")]
        spec = _spec("WSTG-INJT-05", "runner fail2", test_id=rec.test_id)
        rep = reconcile((spec,), evidence_dir=self._tmp, run_id=cm.current_run_id())
        self.assertFalse(declared_coverage_ok(rep)[0])


# ---------------------------------------------------------------------------
# Model extension (issue 4): mass assignment + external refs; WSTG-CONF-09 unbound
# ---------------------------------------------------------------------------

class ModelExtensionTests(unittest.TestCase):
    def test_genuine_wstg_ref_is_versioned(self):
        self.assertEqual(CHECKS_BY_ID["WSTG-INJT-05"].reference_label(), "WSTG-INJT-05 (WSTG latest)")
        self.assertTrue(CHECKS_BY_ID["WSTG-INJT-05"].is_wstg())

    def test_mass_assignment_is_wstg_injt_20_with_external_refs(self):
        # WG-1: current WSTG has Mass Assignment (INJT-20), so the row left its
        # internal AV-MASSASSIGN-01 id; the API-layer sources stay attached.
        c = CHECKS_BY_ID["WSTG-INJT-20"]
        self.assertTrue(c.is_wstg())
        self.assertEqual(c.reference_label(), "WSTG-INJT-20 (WSTG latest)")
        catalogs = {e.catalog for e in c.external_refs}
        self.assertIn("PortSwigger Academy", catalogs)
        self.assertTrue(any("OWASP" in cat for cat in catalogs))
        # The external refs stay the non-WSTG sources; the primary id is the WSTG claim.
        self.assertTrue(all(e.catalog != "WSTG" for e in c.external_refs))

    def test_wstg_conf_09_is_test_file_permission_not_mass_assignment(self):
        # WSTG-CONF-09 now carries its GENUINE OWASP meaning, not mass assignment.
        self.assertIn("WSTG-CONF-09", CHECKS_BY_ID)
        self.assertEqual(CHECKS_BY_ID["WSTG-CONF-09"].name, "Test File Permission")
        self.assertNotEqual(CHECKS_BY_ID["WSTG-CONF-09"].vulnerability_class, "api_security")


class SafetyPropertyLedgerTests(unittest.TestCase):
    """GAP-4: the harness safety properties have their own section of the ledger."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_safety_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _pass_all(self, specs):
        for s in specs:
            _write(self._tmp, s.check_id, s.aspect, TestStatus.PASS, test_id=s.test_id)

    def test_every_property_has_an_automated_spec_and_is_not_a_catalog_row(self):
        declared = {s.check_id for s in cm.SAFETY_TESTS if s.mode == "automated"}
        self.assertEqual(declared, set(cm.SAFETY_PROPERTIES_BY_ID))
        for pid in cm.SAFETY_PROPERTIES_BY_ID:
            self.assertTrue(pid.startswith("HS-"), pid)
            self.assertNotIn(pid, CHECKS_BY_ID)
        self.assertFalse({s.check_id for s in cm.REQUIREMENT_TESTS} & set(cm.SAFETY_PROPERTIES_BY_ID))

    def test_properties_report_separately_and_leave_requirement_totals_alone(self):
        empty = reconcile(evidence_dir=self._tmp, run_id=RUN)
        self._pass_all(cm.SAFETY_TESTS)
        rep = reconcile(evidence_dir=self._tmp, run_id=RUN)
        self.assertEqual(rep["totals"]["requirements"], empty["totals"]["requirements"])
        self.assertEqual(rep["totals"]["requirement_status_counts"],
                         empty["totals"]["requirement_status_counts"])
        self.assertFalse({r["check_id"] for r in rep["requirements"]} & set(cm.SAFETY_PROPERTIES_BY_ID))
        props = {p["check_id"]: p for p in rep["safety_properties"]}
        self.assertEqual(set(props), set(cm.SAFETY_PROPERTIES_BY_ID))
        for p in props.values():
            self.assertEqual(p["requirement_status"], RequirementStatus.COVERED_PARTIAL.value)
            self.assertFalse(p["is_wstg"])
        self.assertEqual(rep["totals"]["safety_property_status_counts"],
                         {RequirementStatus.COVERED_PARTIAL.value: len(cm.SAFETY_PROPERTIES)})
        self.assertIn("Harness safety properties", render_markdown(rep))

    def test_gate_blocks_on_a_missing_or_failing_safety_aspect(self):
        first, *rest = cm.SAFETY_TESTS
        self._pass_all(rest)
        ok, problems = declared_coverage_ok(reconcile(evidence_dir=self._tmp, run_id=RUN))
        self.assertFalse(ok)
        self.assertTrue(any(first.check_id in p and "not_implemented" in p for p in problems), problems)
        _write(self._tmp, first.check_id, first.aspect, TestStatus.FAIL, test_id=first.test_id)
        ok, problems = declared_coverage_ok(reconcile(evidence_dir=self._tmp, run_id=RUN))
        self.assertFalse(ok)
        self.assertTrue(any(first.check_id in p and "'fail'" in p for p in problems), problems)
        md = render_markdown(reconcile(evidence_dir=self._tmp, run_id=RUN))
        self.assertIn(f"**{first.check_id}** [harness_safety] fail: {first.aspect}", md)

    def test_safety_ids_are_written_as_is_and_unknown_ids_still_refused(self):
        path = _write(self._tmp, "HS-PIN-01", "an aspect", TestStatus.PASS)
        self.assertTrue(path.name.startswith("HS-PIN-01__"))
        self.assertIn(("HS-PIN-01", "an aspect"), load_evidence(self._tmp, run_id=RUN))
        with self.assertRaises(ValueError):
            _write(self._tmp, "HS-NOPE-99", "x", TestStatus.PASS)
        with self.assertRaises(ValueError):
            TestSpec("HS-NOPE-99", "m.T.test_x", "x")

    def test_custom_specs_reconcile_without_the_declared_safety_specs(self):
        rep = reconcile((), evidence_dir=self._tmp, run_id=RUN)
        self.assertTrue(all(p["requirement_status"] == RequirementStatus.GAP_UNIMPLEMENTED.value
                            for p in rep["safety_properties"]))
        self.assertTrue(declared_coverage_ok(rep)[0])


class DeclaredIdentityTests(unittest.TestCase):
    def test_declared_automated_ids_resolve_to_runner_ids(self):
        for spec in cm.REQUIREMENT_TESTS + cm.SAFETY_TESTS:
            if spec.mode != "automated":
                continue
            with self.subTest(test_id=spec.test_id):
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromName(spec.test_id)
                self.assertEqual(loader.errors, [], "stale declared test identity")
                self.assertEqual(suite.countTestCases(), 1)
                self.assertEqual(next(iter(suite)).id(), spec.test_id)

    def test_declared_specs_are_unique_per_aspect_and_evidence_file(self):
        # Two aspects of one check must never share a (check, aspect) key or an evidence
        # basename (the slug is truncated), or one artifact would overwrite the other.
        automated = [s for s in cm.REQUIREMENT_TESTS + cm.SAFETY_TESTS if s.mode == "automated"]
        keys = [(s.check_id, s.aspect) for s in automated]
        self.assertEqual(len(keys), len(set(keys)), "duplicate (check_id, aspect) declaration")
        files = [(s.check_id, s.evidence_file) for s in automated]
        self.assertEqual(len(files), len(set(files)), "two aspects share one evidence file name")
        tests = [s.test_id for s in automated]
        self.assertEqual(len(tests), len(set(tests)), "one test bound to two aspects")

    def test_declared_specs_match_their_decorators(self):
        # The gate matches evidence by (check_id, aspect) AND exact test_id; a decorator
        # that drifted from its declaration would only surface as a missing aspect at the
        # end of a full run. Pin them statically: each declared test carries exactly the
        # evidence metadata its spec names.
        for spec in cm.REQUIREMENT_TESTS + cm.SAFETY_TESTS:
            if spec.mode != "automated":
                continue
            with self.subTest(test_id=spec.test_id):
                suite = unittest.TestLoader().loadTestsFromName(spec.test_id)
                case = next(iter(suite))
                meta = getattr(getattr(case, case._testMethodName), "__coverage_evidence__", None)
                self.assertIsNotNone(meta, "declared test carries no @evidence_for")
                self.assertEqual((meta["check_id"], meta["aspect"], meta["label"]),
                                 (spec.check_id, spec.aspect, spec.label))

    def test_old_flat_module_identity_does_not_resolve(self):
        # A pre-package flat module id must never be an accepted declared
        # identity. Asserting an outright import error is not robust: it only
        # held when the harness dir was not itself a sys.path entry. Under the
        # full suite (`discover -s harness`) harness IS on sys.path, so the flat
        # name imports -- but it loads as a DISTINCT id (no 'harness.' prefix)
        # that matches no declared test_id, which is the guarantee that matters.
        flat = ("test_mass_assignment_slice.MassAssignmentSliceTest."
                "test_harness_sequence_validator_confirms_vulnerable")
        declared = {s.test_id for s in cm.REQUIREMENT_TESTS}
        self.assertNotIn(flat, declared, "the flat pre-package id must not be a declared identity")
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(flat)
        loaded = set() if loader.errors else {t.id() for t in suite}
        self.assertFalse(loaded & declared,
                         "the flat pre-package id must not resolve to any declared "
                         "(package-qualified) test")


if __name__ == "__main__":
    unittest.main()
