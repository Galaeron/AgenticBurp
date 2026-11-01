"""R17 - scoring contract and evaluation eligibility (synthetic only).

Black-box contract tests for ``testing.web_objective_benchmark.score`` and its
efficacy-orchestrator caller.  Everything here is a benign in-memory manifest or
run record; no target, network, oracle, or answer key is involved.

Each guard has a positive control (a well-formed run that must stay eligible with
exact rates) and negative controls (a defect that must make the run visibly
ineligible or raise, never score as clean).  The negatives assert the *specific*
signal (a named gate, event list, or contract error) rather than just "not
eligible", so removing the guard that produces that signal fails the test.
"""
from __future__ import annotations

import contextlib
import io
import json
import math
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from testing import run_web_objective_efficacy as eff
from testing import web_objective_benchmark as wob


def _case(cid, *, vulnerable, pair=None, cls="sqli", modes=("captured", "autonomous")):
    case = {"id": cid, "expected_class": cls, "expected_vulnerable": vulnerable,
            "modes": list(modes)}
    if pair:
        case["pair_id"] = pair
    return case


def _manifest(cases=None, attempts=3):
    return {"schema_version": "1.0.0", "attempts_per_case": attempts,
            "cases": cases if cases is not None else [
                _case("v", vulnerable=True, pair="p"),
                _case("f", vulnerable=False, pair="p")]}


def _finding(cls, state="confirmed"):
    return {"vulnerability_class": cls, "verification_state": state}


def _rec(case, attempt, findings=None, *, objective=False, status="success", **extra):
    record = {"case_id": case, "attempt": attempt, "status": status,
              "objective_verified": objective, "findings": findings or [],
              "human_interventions": 0,
              "artifact_refs": [f"artifacts/{case}-{attempt}.json"]}
    record.update(extra)
    return record


def _run(mode, records):
    return {"schema_version": "1.0.0", "run_id": "r17", "mode": mode,
            "model": "synthetic-model", "checkout": "synthetic-rev",
            "config_hash": "synthetic-config", "records": records}


def _records(v_findings=None, f_findings=None, *, attempts=(1, 2, 3), objective=False):
    out = []
    for a in attempts:
        out.append(_rec("v", a, [_finding("sqli")] if v_findings is None else v_findings,
                        objective=objective))
        out.append(_rec("f", a, f_findings or []))
    return out


def _score(records, mode="captured", manifest=None, **kw):
    return wob.score(manifest or _manifest(), _run(mode, records), **kw)


def _errors(result):
    return result["cases"]["contract_errors"]


def _make_dir_link(link, target):
    """A directory symlink, or on Windows a junction; False if neither can be made."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True)
        return done.returncode == 0
    return False


def _remove_dir_link(link):
    try:
        os.rmdir(link)
    except OSError:
        os.unlink(link)


class PositiveControlTests(unittest.TestCase):
    def test_correct_expected_class_run_is_eligible_with_exact_rates(self):
        res = _score(_records())
        self.assertTrue(res["eligible"])
        self.assertTrue(res["complete"])
        self.assertEqual(_errors(res), [])
        self.assertTrue(all(res["gates"].values()), res["gates"])
        self.assertEqual(res["controls"]["wrong_class_confirmation_events"], [])
        self.assertEqual(res["controls"]["false_confirmation_events"], [])
        obj = res["objective"]
        self.assertEqual((obj["first_attempt_rate"], obj["pass_at_attempt_budget"],
                          obj["repeatability_rate"]), (1.0, 1.0, 1.0))

    def test_expected_class_success_math_across_two_positives(self):
        manifest = _manifest([
            _case("v1", vulnerable=True, pair="p1"), _case("f1", vulnerable=False, pair="p1"),
            _case("v2", vulnerable=True, pair="p2"), _case("f2", vulnerable=False, pair="p2")])
        records = []
        for a in (1, 2, 3):
            records.append(_rec("v1", a, [_finding("sqli")]))           # 3/3
            records.append(_rec("v2", a, [_finding("sqli")] if a == 2 else []))  # 1/3, not first
            records.append(_rec("f1", a))
            records.append(_rec("f2", a, [_finding("sqli")] if a == 1 else []))
        res = _score(records, manifest=manifest)
        obj = res["objective"]
        self.assertEqual(res["cases"]["positive"], 2)
        self.assertEqual((obj["first_attempt_successes"], obj["first_attempt_rate"]), (1, 0.5))
        self.assertEqual((obj["solved_within_attempt_budget"], obj["pass_at_attempt_budget"]), (2, 1.0))
        self.assertEqual((obj["repeatable_successes"], obj["repeatability_rate"]), (1, 0.5))
        # f2 was falsely confirmed once: 1 of 2 controls, and the run is ineligible.
        self.assertEqual(res["controls"]["false_confirmation_cases"], 1)
        self.assertEqual(res["controls"]["false_confirmation_case_rate"], 0.5)
        self.assertFalse(res["gates"]["zero_false_confirmations"])
        self.assertFalse(res["eligible"])

    def test_rates_are_none_not_zero_when_a_denominator_is_empty(self):
        controls_only = _manifest([_case("f", vulnerable=False)], attempts=1)
        res = _score([_rec("f", 1)], manifest=controls_only)
        self.assertIsNone(res["objective"]["first_attempt_rate"])
        self.assertIsNone(res["objective"]["pass_at_attempt_budget"])
        self.assertIsNone(res["objective"]["repeatability_rate"])
        self.assertEqual(res["controls"]["false_confirmation_case_rate"], 0.0)
        positives_only = _manifest([_case("v", vulnerable=True)], attempts=1)
        res = _score([_rec("v", 1, [_finding("sqli")])], manifest=positives_only)
        self.assertIsNone(res["controls"]["false_confirmation_case_rate"])
        self.assertEqual(res["objective"]["first_attempt_rate"], 1.0)

    def test_resolvable_artifacts_are_eligible_and_reported_as_resolved(self):
        with TemporaryDirectory() as tmp:
            for case in ("v", "f"):
                for a in (1, 2, 3):
                    path = Path(tmp) / "artifacts" / f"{case}-{a}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}", encoding="utf-8")
            res = _score(_records(), artifact_root=tmp)
        self.assertTrue(res["eligible"])
        self.assertEqual(res["artifact_integrity"], "resolved")


class MissingAttemptDenominatorTests(unittest.TestCase):
    def test_missing_attempts_stay_in_the_denominator_and_block_eligibility(self):
        records = [_rec("v", 1, [_finding("sqli")])] + [_rec("f", a) for a in (1, 2, 3)]
        res = _score(records)
        self.assertFalse(res["complete"])
        self.assertFalse(res["eligible"])
        self.assertFalse(res["gates"]["complete_records"])
        self.assertEqual(res["cases"]["missing_records"],
                         [{"case_id": "v", "attempt": 2}, {"case_id": "v", "attempt": 3}])
        self.assertEqual(res["cases"]["positive"], 1)
        # A missing attempt is a failed attempt, never a skipped one.
        self.assertEqual(res["objective"]["repeatability_rate"], 0.0)
        self.assertEqual(res["objective"]["solved_within_attempt_budget"], 1)

    def test_run_where_no_case_applies_to_its_mode_is_not_vacuously_eligible(self):
        manifest = _manifest([_case("v", vulnerable=True, modes=("autonomous",))])
        res = _score([], mode="captured", manifest=manifest)
        self.assertFalse(res["complete"])
        self.assertFalse(res["eligible"])
        self.assertTrue(any("no manifest case applies" in e for e in _errors(res)), _errors(res))


class WrongClassTests(unittest.TestCase):
    def test_unrelated_class_confirmation_is_not_a_tp_is_counted_and_blocks_eligibility(self):
        res = _score(_records(v_findings=[_finding("xss")]))
        self.assertEqual(res["objective"]["first_attempt_rate"], 0.0)
        self.assertEqual(res["objective"]["pass_at_attempt_budget"], 0.0)
        self.assertEqual(res["controls"]["wrong_class_confirmation_events"],
                         [{"case_id": "v", "attempt": a} for a in (1, 2, 3)])
        self.assertFalse(res["gates"]["zero_wrong_class_confirmations"])
        self.assertTrue(res["gates"]["zero_false_confirmations"])  # fixed control stayed quiet
        self.assertTrue(res["complete"])
        self.assertFalse(res["eligible"])

    def test_unrelated_confirmation_next_to_a_correct_one_is_not_silently_dropped(self):
        res = _score(_records(v_findings=[_finding("sqli"), _finding("xss")]))
        self.assertEqual(res["objective"]["first_attempt_rate"], 1.0)  # expected class still a TP
        self.assertEqual(res["controls"]["wrong_class_confirmation_events"],
                         [{"case_id": "v", "attempt": a} for a in (1, 2, 3)])
        self.assertFalse(res["eligible"])

    def test_unconfirmed_unrelated_class_finding_is_not_a_wrong_class_confirmation(self):
        # Boundary control: only *confirmed* unrelated findings count; a candidate does not.
        res = _score(_records(v_findings=[_finding("sqli"), _finding("xss", "unverified")]))
        self.assertEqual(res["controls"]["wrong_class_confirmation_events"], [])
        self.assertTrue(res["gates"]["zero_wrong_class_confirmations"])
        self.assertTrue(res["eligible"])

    def test_unrelated_confirmation_on_a_fixed_control_is_a_false_confirmation(self):
        res = _score(_records(f_findings=[_finding("xss")]))
        self.assertEqual(res["controls"]["false_confirmation_cases"], 1)
        self.assertEqual(res["controls"]["false_confirmation_case_rate"], 1.0)
        self.assertEqual(len(res["controls"]["false_confirmation_events"]), 3)
        self.assertFalse(res["gates"]["zero_false_confirmations"])
        self.assertFalse(res["eligible"])

    def test_oracle_verified_autonomous_attempt_with_wrong_class_noise_is_ineligible(self):
        res = _score(_records(v_findings=[_finding("xss")], objective=True), mode="autonomous")
        self.assertEqual(res["objective"]["pass_at_attempt_budget"], 1.0)  # oracle, not prose
        self.assertEqual(len(res["controls"]["wrong_class_confirmation_events"]), 3)
        self.assertFalse(res["eligible"])


class ArtifactReferenceIntegrityTests(unittest.TestCase):
    MALFORMED = {
        "empty list": [], "whitespace only": ["   "], "empty string": [""],
        "one good one blank": ["artifacts/ok.json", " "], "non-string": [123],
        "parent traversal": ["../outside/secret.json"],
        "embedded traversal": ["artifacts/../../outside.json"],
        "backslash traversal": ["artifacts\\..\\..\\outside.json"],
        "posix absolute": ["/etc/passwd"], "windows drive": ["C:\\Windows\\system.ini"],
        "unc": ["\\\\server\\share\\x.json"], "nul byte": ["artifacts/a\x00.json"],
    }

    def test_malformed_references_make_the_run_incomplete_and_ineligible(self):
        for label, refs in self.MALFORMED.items():
            with self.subTest(label):
                records = _records()
                records[0]["artifact_refs"] = refs
                res = _score(records)
                self.assertFalse(res["complete"])
                self.assertFalse(res["eligible"])
                self.assertFalse(res["gates"]["complete_records"])
                self.assertTrue(any("artifact reference" in e for e in _errors(res)),
                                _errors(res))

    def test_dangling_reference_is_rejected_when_the_artifact_root_is_known(self):
        with TemporaryDirectory() as tmp:
            res = _score(_records(), artifact_root=tmp)  # nothing exists under tmp
        self.assertFalse(res["complete"])
        self.assertFalse(res["eligible"])
        self.assertEqual(res["artifact_integrity"], "resolved")
        self.assertTrue(any("does not resolve to a file" in e for e in _errors(res)), _errors(res))

    def test_one_missing_artifact_among_resolvable_ones_is_caught(self):
        with TemporaryDirectory() as tmp:
            for case in ("v", "f"):
                for a in (1, 2, 3):
                    path = Path(tmp) / "artifacts" / f"{case}-{a}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}", encoding="utf-8")
            (Path(tmp) / "artifacts" / "v-2.json").unlink()
            res = _score(_records(), artifact_root=tmp)
        self.assertFalse(res["eligible"])
        self.assertEqual(len([e for e in _errors(res) if "does not resolve" in e]), 1)
        self.assertTrue(any(e.startswith("v attempt 2:") for e in _errors(res)))

    def test_reference_to_a_directory_is_not_an_artifact(self):
        with TemporaryDirectory() as tmp:
            for case in ("v", "f"):
                for a in (1, 2, 3):
                    path = Path(tmp) / "artifacts" / f"{case}-{a}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}", encoding="utf-8")
            records = _records()
            records[0]["artifact_refs"] = ["artifacts"]
            res = _score(records, artifact_root=tmp)
        self.assertFalse(res["eligible"])
        self.assertTrue(any("does not resolve to a file" in e for e in _errors(res)))

    def test_reference_through_a_link_that_leaves_the_root_is_rejected(self):
        with TemporaryDirectory() as root, TemporaryDirectory() as outside:
            (Path(outside) / "secret.json").write_text("{}", encoding="utf-8")
            link = Path(root) / "linked"
            if not _make_dir_link(link, outside):
                self.skipTest("cannot create a directory link on this platform")
            try:
                records = _records()
                records[0]["artifact_refs"] = ["linked/secret.json"]
                res = _score(records, artifact_root=root)
            finally:
                _remove_dir_link(link)
        self.assertFalse(res["eligible"])
        self.assertTrue(any(e.startswith("v attempt 1:") and "outside the artifact root" in e
                            for e in _errors(res)), _errors(res))

    def test_without_a_root_resolution_is_not_claimed(self):
        res = _score(_records())  # well-formed but unresolvable refs: accepted only as format
        self.assertTrue(res["eligible"])
        self.assertEqual(res["artifact_integrity"], "format_only")

    def test_cli_artifact_root_flag_gates_the_exit_code(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
            (root / "run.json").write_text(json.dumps(_run("captured", _records())),
                                           encoding="utf-8")
            argv = [str(root / "manifest.json"), str(root / "run.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                dangling = wob.main(argv + ["--artifact-root", str(root)])
                format_only = wob.main(argv)
                for case in ("v", "f"):
                    for a in (1, 2, 3):
                        path = root / "artifacts" / f"{case}-{a}.json"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("{}", encoding="utf-8")
                resolved = wob.main(argv + ["--artifact-root", str(root)])
        self.assertEqual((dangling, format_only, resolved), (2, 0, 0))


class CorruptRecordPayloadTests(unittest.TestCase):
    CORRUPT_FINDINGS = {
        "string": "CONFIRMED sqli", "bare object": _finding("sqli"),
        "list of strings": ["CONFIRMED sqli"], "null": None, "list of numbers": [1, 2],
        "object mixed with junk": ["junk", _finding("xss", "unverified")],
    }

    def test_corrupt_findings_on_a_fixed_control_never_score_as_clean(self):
        for label, bad in self.CORRUPT_FINDINGS.items():
            with self.subTest(label):
                records = _records()
                for r in records:
                    if r["case_id"] == "f":
                        r["findings"] = bad
                res = _score(records)
                self.assertFalse(res["complete"])
                self.assertFalse(res["eligible"])
                self.assertTrue(any("findings must be a list of objects" in e
                                    for e in _errors(res)), _errors(res))

    def test_corrupt_findings_on_a_positive_are_flagged_not_read_as_no_finding(self):
        records = _records()
        records[0]["findings"] = "CONFIRMED sqli"
        res = _score(records)
        self.assertFalse(res["eligible"])
        self.assertTrue(any(e.startswith("v attempt 1:") and "findings" in e
                            for e in _errors(res)), _errors(res))

    def test_absent_findings_key_is_an_ordinary_no_finding_record(self):
        records = _records()
        for r in records:
            if r["case_id"] == "f":
                del r["findings"]
        res = _score(records)
        self.assertTrue(res["eligible"])

    def test_corrupt_resource_counts_are_flagged_and_excluded_from_totals(self):
        for label, bad in {"negative": -3, "nan": math.nan, "inf": math.inf,
                           "numeric string": "5", "list": [1]}.items():
            with self.subTest(label):
                records = _records()
                records[0]["requests"] = bad
                records[2]["requests"] = 4
                res = _score(records)
                self.assertFalse(res["complete"])
                self.assertFalse(res["eligible"])
                self.assertTrue(any("requests must be a non-negative number" in e
                                    for e in _errors(res)), _errors(res))
                self.assertEqual(res["resources"].get("requests", 0), 4)

    def test_offsetting_negative_count_cannot_mask_a_human_intervention(self):
        records = _records(objective=True)
        records[0]["human_interventions"] = 1
        records[1]["human_interventions"] = -1
        res = _score(records, mode="autonomous")
        self.assertFalse(res["eligible"])
        self.assertFalse(res["complete"])
        self.assertTrue(any("human_interventions must be a non-negative number" in e
                            for e in _errors(res)), _errors(res))

    def test_genuine_human_intervention_still_fails_the_autonomous_gate(self):
        records = _records(objective=True)
        records[0]["human_interventions"] = 2
        res = _score(records, mode="autonomous")
        self.assertTrue(res["complete"])
        self.assertFalse(res["gates"]["zero_human_interventions"])
        self.assertFalse(res["eligible"])


class UnhealthyIntervalTests(unittest.TestCase):
    def test_error_attempt_is_counted_visible_and_ineligible_not_dropped(self):
        records = _records()
        records[0].update(status="error", requests=5)
        res = _score(records)
        self.assertTrue(res["complete"])  # execution record exists; health is a separate gate
        self.assertFalse(res["gates"]["healthy_execution"])
        self.assertFalse(res["eligible"])
        self.assertEqual(sum(res["failure_stages"].values()), 1)
        self.assertEqual(res["resources"]["requests"], 5)

    def test_infrastructure_failure_stage_is_unhealthy_even_without_error_status(self):
        records = _records()
        records[1].update(status="failure", failure_stage="infrastructure")
        res = _score(records)
        self.assertTrue(res["complete"])
        self.assertFalse(res["gates"]["healthy_execution"])
        self.assertFalse(res["eligible"])
        self.assertEqual(res["failure_stages"], {"infrastructure": 1})

    def test_invalid_status_or_stage_is_a_contract_error_not_a_healthy_attempt(self):
        records = _records()
        records[0]["status"] = "ok"
        records[1]["failure_stage"] = "network"
        res = _score(records)
        self.assertFalse(res["complete"])
        self.assertFalse(res["eligible"])
        self.assertTrue(any("invalid status" in e for e in _errors(res)))
        self.assertTrue(any("invalid failure_stage" in e for e in _errors(res)))

    def test_timeout_is_not_an_infrastructure_fault_but_is_not_a_success_either(self):
        records = _records(v_findings=[], objective=False)
        records[0].update(status="timeout")
        res = _score(records, mode="autonomous")
        self.assertTrue(res["gates"]["healthy_execution"])
        self.assertEqual(res["objective"]["pass_at_attempt_budget"], 0.0)
        self.assertEqual(res["failure_stages"], {"unclassified": 1})


class EfficacyCallerTests(unittest.TestCase):
    """The real consumer path: orchestrate() -> assemble_run() -> score()."""

    MANIFEST = _manifest([_case("lab", vulnerable=True, modes=("autonomous",))], attempts=2)

    @staticmethod
    def _artifact(findings):
        return {"status": "done", "findings": findings, "checkout": "rev",
                "config_hash": "cfg", "model": "m", "requests": 3, "duration_seconds": 1.0}

    def _orchestrate(self, tmp, findings, *, write_artifact=True):
        def fake_runner(*, target, case_id, objective_class, out_dir, run_id,
                        budgets, python, runner):
            artifact = self._artifact(findings)
            if write_artifact:
                Path(out_dir).mkdir(parents=True, exist_ok=True)
                (Path(out_dir) / "attempt.json").write_text(json.dumps(artifact), encoding="utf-8")
            return artifact

        return eff.orchestrate(
            self.MANIFEST, {"lab": "https://lab.invalid/"}, mode="autonomous",
            output_dir=Path(tmp), oracle={"lab": [True, True]}, run_id="r17",
            runner_fn=fake_runner)

    def test_clean_attempts_with_written_artifacts_are_eligible(self):
        with TemporaryDirectory() as tmp:
            card = self._orchestrate(tmp, [_finding("sqli")])["scorecard"]
        self.assertTrue(card["eligible"])
        self.assertEqual(card["artifact_integrity"], "resolved")
        self.assertEqual(card["objective"]["repeatability_rate"], 1.0)

    def test_wrong_class_confirmation_reaches_the_scorecard_and_summary(self):
        with TemporaryDirectory() as tmp:
            card = self._orchestrate(tmp, [_finding("xss")])["scorecard"]
            summary = (Path(tmp) / "summary.md").read_text(encoding="utf-8")
        self.assertFalse(card["eligible"])
        self.assertFalse(card["gates"]["zero_wrong_class_confirmations"])
        self.assertEqual(len(card["controls"]["wrong_class_confirmation_events"]), 2)
        self.assertIn("zero_wrong_class_confirmations=False", summary)
        self.assertIn("Wrong-class confirmations: 2", summary)

    def test_attempt_whose_artifact_was_never_written_is_ineligible(self):
        with TemporaryDirectory() as tmp:
            card = self._orchestrate(tmp, [_finding("sqli")], write_artifact=False)["scorecard"]
        self.assertFalse(card["eligible"])
        self.assertFalse(card["complete"])
        self.assertTrue(any("does not resolve to a file" in e
                            for e in card["cases"]["contract_errors"]))


if __name__ == "__main__":
    unittest.main()
