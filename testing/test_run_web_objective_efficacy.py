"""Tests for the Priority-1 efficacy orchestrator.

Each acceptance property has a positive case AND a negative control. The pure
record-mapping / assembly path is exercised directly; the end-to-end path drives
the REAL scorer (:mod:`testing.web_objective_benchmark`) and, for orchestration,
an injected fake runner so no live target is touched.
"""
from __future__ import annotations

import json
import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

from testing import run_web_objective_efficacy as eff
from testing.web_objective_benchmark import BenchmarkContractError


def _artifact(*, status="done", findings=None, checkout="abc123",
              config_hash="cfg1", model="qwen3:8b", requests=7, duration=1.5):
    return {
        "schema_version": "1.0.0", "kind": "web_objective_smoke_attempt",
        "status": status, "findings": findings or [], "checkout": checkout,
        "config_hash": config_hash, "model": model, "requests": requests,
        "duration_seconds": duration,
    }


def _manifest(cases, attempts=3):
    return {"schema_version": "1.0.0", "attempts_per_case": attempts, "cases": cases}


_VULN = {"id": "ps-sqli-hidden-data", "expected_class": "sqli",
         "expected_vulnerable": True, "modes": ["autonomous"]}
_PAIR_VULN = {"id": "p-vuln", "pair_id": "p", "expected_class": "idor",
              "expected_vulnerable": True, "modes": ["autonomous"]}
_PAIR_FIXED = {"id": "p-fixed", "pair_id": "p", "expected_class": "idor",
               "expected_vulnerable": False, "modes": ["autonomous"]}
_CONFIRMED = [{"vulnerability_class": "idor", "verification_state": "confirmed"}]


class AttemptRecordTests(unittest.TestCase):
    def test_done_attempt_with_oracle_is_verified_success(self):  # positive
        rec = eff.attempt_record(_artifact(status="done"), case_id="c", attempt=1,
                                 artifact_ref="c/a1/attempt.json", oracle_verified=True)
        self.assertEqual(rec["status"], "success")
        self.assertTrue(rec["objective_verified"])
        self.assertIsNone(rec["failure_stage"])

    def test_timeout_is_never_verified_even_if_oracle_says_solved(self):  # negative control
        # CURRENT_STATE attempt-4 discipline: a solved lab behind a timed-out
        # attempt is excluded, not scored as a success.
        rec = eff.attempt_record(_artifact(status="timeout"), case_id="c", attempt=1,
                                 artifact_ref="ref", oracle_verified=True)
        self.assertEqual(rec["status"], "timeout")
        self.assertFalse(rec["objective_verified"])
        self.assertTrue(rec["_excluded_verified"])

    def test_error_attempt_maps_to_infrastructure(self):  # negative control
        rec = eff.attempt_record(_artifact(status="error"), case_id="c", attempt=1,
                                 artifact_ref="ref", oracle_verified=False)
        self.assertEqual(rec["status"], "error")
        self.assertEqual(rec["failure_stage"], "infrastructure")


class AssembleRunTests(unittest.TestCase):
    def _entry(self, artifact, case_id="c", attempt=1, oracle=False):
        return {"case_id": case_id, "attempt": attempt, "artifact": artifact,
                "artifact_ref": f"{case_id}/a{attempt}", "oracle_verified": oracle}

    def test_single_config_assembles(self):  # positive
        run = eff.assemble_run("autonomous", [self._entry(_artifact())], run_id="r1")
        self.assertEqual(run["checkout"], "abc123")
        self.assertEqual(run["config_hash"], "cfg1")
        self.assertEqual(len(run["records"]), 1)

    def test_mixed_checkouts_refused(self):  # negative control (one-checkout discipline)
        entries = [self._entry(_artifact(checkout="abc123"), attempt=1),
                   self._entry(_artifact(checkout="DIFFERENT"), attempt=2)]
        with self.assertRaises(BenchmarkContractError):
            eff.assemble_run("autonomous", entries, run_id="r1")

    def test_mixed_config_hash_refused(self):  # negative control
        entries = [self._entry(_artifact(config_hash="cfg1"), attempt=1),
                   self._entry(_artifact(config_hash="cfg2"), attempt=2)]
        with self.assertRaises(BenchmarkContractError):
            eff.assemble_run("autonomous", entries, run_id="r1")


class ScoringThroughRealScorerTests(unittest.TestCase):
    def test_three_clean_verified_attempts_score_eligible(self):  # positive, end-to-end
        manifest = _manifest([_VULN])
        entries = [{"case_id": _VULN["id"], "attempt": a, "artifact": _artifact(),
                    "artifact_ref": f"a{a}", "oracle_verified": True}
                   for a in (1, 2, 3)]
        run = eff.assemble_run("autonomous", entries, run_id="r1")
        run.pop("_excluded_verified", None)
        from testing import web_objective_benchmark as wob
        card = wob.score(manifest, run)
        self.assertTrue(card["eligible"])
        self.assertEqual(card["objective"]["first_attempt_successes"], 1)
        self.assertEqual(card["objective"]["repeatable_successes"], 1)

    def test_fixed_control_false_confirmation_blocks_eligibility(self):  # negative control
        manifest = _manifest([_PAIR_VULN, _PAIR_FIXED])
        entries = []
        for a in (1, 2, 3):
            entries.append({"case_id": _PAIR_VULN["id"], "attempt": a,
                            "artifact": _artifact(findings=_CONFIRMED),
                            "artifact_ref": f"v{a}", "oracle_verified": True})
            # The FIXED control wrongly emits a confirmed finding -> false confirm.
            entries.append({"case_id": _PAIR_FIXED["id"], "attempt": a,
                            "artifact": _artifact(findings=_CONFIRMED),
                            "artifact_ref": f"f{a}", "oracle_verified": False})
        run = eff.assemble_run("autonomous", entries, run_id="r1")
        run.pop("_excluded_verified", None)
        from testing import web_objective_benchmark as wob
        card = wob.score(manifest, run)
        self.assertFalse(card["eligible"])
        self.assertGreaterEqual(card["controls"]["false_confirmation_cases"], 1)


class OrchestrateWithFakeRunnerTests(unittest.TestCase):
    def test_runner_called_per_case_attempt_and_scorecard_written(self):  # positive, caller-level
        manifest = _manifest([_VULN], attempts=3)
        calls: list[dict] = []

        def fake_runner(*, target, case_id, objective_class, out_dir, run_id,
                        budgets, python, runner):
            calls.append({"target": target, "case_id": case_id, "run_id": run_id})
            out_dir = Path(out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            art = _artifact()
            (out_dir / "attempt.json").write_text(json.dumps(art), encoding="utf-8")
            return art

        with TemporaryDirectory() as tmp:
            result = eff.orchestrate(
                manifest, {_VULN["id"]: "https://lab.example/"}, mode="autonomous",
                output_dir=Path(tmp), oracle={_VULN["id"]: [True, True, True]},
                run_id="rX", runner_fn=fake_runner)
            self.assertEqual(len(calls), 3)  # one per attempt
            self.assertTrue(all(c["target"] == "https://lab.example/" for c in calls))
            self.assertTrue((Path(tmp) / "scorecard.json").exists())
            self.assertTrue((Path(tmp) / "summary.md").exists())
            self.assertTrue(result["scorecard"]["eligible"])

    def test_missing_target_refused_before_any_run(self):  # negative control
        manifest = _manifest([_VULN])
        calls = []

        def fake_runner(**kwargs):
            calls.append(kwargs)
            return _artifact()

        with TemporaryDirectory() as tmp:
            with self.assertRaises(BenchmarkContractError):
                eff.orchestrate(manifest, {}, mode="autonomous",
                                output_dir=Path(tmp), runner_fn=fake_runner)
            self.assertEqual(calls, [])  # refused before launching anything


# --- R46: the subprocess runner's artifact must belong to this invocation ------------------

# Stands in for run_web_objective_smoke.py: the target argument names the scenario. It
# honours --output / --run-id exactly as the real runner does and exits 0 only for "done".
_FAKE_SMOKE_RUNNER = """\
import json, sys
from pathlib import Path
args = sys.argv[1:]
scenario = args[0]
out = Path(args[args.index("--output") + 1])
run_id = args[args.index("--run-id") + 1]
artifact = {"schema_version": "1.0.0", "kind": "web_objective_smoke_attempt",
            "run_id": run_id, "status": "done", "findings": [], "checkout": "abc123",
            "config_hash": "cfg1", "model": "m", "requests": 3, "duration_seconds": 1.0,
            "result": {"degraded": False, "errors": []}, "auth": {"requested": False, "ok": False}}
if scenario == "wrong-run-id":
    artifact["run_id"] = "someone-elses-run"
elif scenario == "timeout-exit2":
    artifact.update(status="timeout", result={"degraded": True, "errors": [{"error": "wall clock"}]})
if scenario == "corrupt":
    (out / "attempt.json").write_text("{not json", encoding="utf-8")
elif scenario not in ("crash", "noop"):
    (out / "attempt.json").write_text(json.dumps(artifact), encoding="utf-8")
sys.exit({"crash": 1, "done-exit1": 1, "timeout-exit2": 2}.get(scenario, 0))
"""

_RUN_ID = "rN"
_ATTEMPT_RUN_ID = f"{_RUN_ID}-{_VULN['id']}-a1"


def _stale_attempt(run_id="old-run"):
    return {**_artifact(), "run_id": run_id, "result": {"degraded": False, "errors": []}}


def _run_default_runner(scenario, *, stale_run_id=None, oracle=True, runner_fn=None):
    """Drive orchestrate() with the REAL default runner against the fake smoke runner."""
    with TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        runner = tmp / "fake_smoke_runner.py"
        runner.write_text(_FAKE_SMOKE_RUNNER, encoding="utf-8")
        out = tmp / "out"
        attempt_dir = out / _VULN["id"] / "attempt-1"
        if stale_run_id is not None:  # a reused directory holding a previous healthy attempt
            attempt_dir.mkdir(parents=True)
            (attempt_dir / "attempt.json").write_text(
                json.dumps(_stale_attempt(stale_run_id)), encoding="utf-8")
        result = eff.orchestrate(
            _manifest([_VULN], attempts=1), {_VULN["id"]: scenario}, mode="autonomous",
            output_dir=out, oracle={_VULN["id"]: [oracle]}, run_id=_RUN_ID, runner=runner,
            runner_fn=runner_fn)
        files = sorted(p.name for p in attempt_dir.iterdir())
        stale_kept = [json.loads(p.read_text(encoding="utf-8")).get("run_id")
                      for p in attempt_dir.glob("attempt.json.superseded-*")]
        return result["scorecard"], result["run"]["records"][0], files, stale_kept


def _pre_fix_default_runner(*, python, runner, target, case_id, objective_class, out_dir,
                            run_id, budgets):
    """The runner as it was before R46: exit status ignored, any attempt.json loaded."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [python, str(runner), target, "--case-id", case_id,
           "--objective-class", objective_class, "--output", str(out_dir), "--run-id", run_id]
    eff.subprocess.run(cmd, cwd=str(eff.ROOT), check=False)
    artifact_path = out_dir / "attempt.json"
    if not artifact_path.exists():
        return {"status": "error", "error": "runner produced no attempt.json",
                "findings": [], "checkout": "unknown", "config_hash": "unknown"}
    return json.loads(artifact_path.read_text(encoding="utf-8"))


class DefaultRunnerFreshnessTests(unittest.TestCase):
    def assertRejected(self, scorecard, record):
        self.assertFalse(scorecard["eligible"])
        self.assertFalse(scorecard["gates"]["healthy_execution"])
        self.assertEqual((record["status"], record["failure_stage"]), ("error", "infrastructure"))
        self.assertFalse(record["objective_verified"])

    def test_failed_runner_cannot_reuse_a_previous_attempt(self):  # R46
        scorecard, record, files, stale_kept = _run_default_runner("crash", stale_run_id="old-run")
        self.assertRejected(scorecard, record)
        self.assertEqual(stale_kept, ["old-run"])  # the old artifact is kept, but set aside
        self.assertNotIn("attempt.json", files)

    def test_previous_attempt_with_the_same_run_id_is_not_fresh(self):  # R46
        scorecard, record, _files, _kept = _run_default_runner("noop", stale_run_id=_ATTEMPT_RUN_ID)
        self.assertRejected(scorecard, record)

    def test_artifact_of_another_invocation_is_rejected(self):  # R46
        self.assertRejected(*_run_default_runner("wrong-run-id")[:2])

    def test_done_artifact_after_a_failed_exit_is_rejected(self):  # R46
        self.assertRejected(*_run_default_runner("done-exit1")[:2])

    def test_corrupt_artifact_is_an_error_not_a_crash(self):  # R46
        self.assertRejected(*_run_default_runner("corrupt")[:2])

    def test_fresh_successful_run_is_eligible_even_in_a_reused_directory(self):  # control
        scorecard, record, files, stale_kept = _run_default_runner("ok", stale_run_id="old-run")
        self.assertTrue(scorecard["eligible"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 1)
        self.assertEqual((record["status"], record["objective_verified"]), ("success", True))
        self.assertIn("attempt.json", files)
        self.assertEqual(stale_kept, ["old-run"])

    def test_timeout_with_the_runners_failure_exit_stays_a_timeout(self):  # control
        scorecard, record, _files, _kept = _run_default_runner("timeout-exit2")
        self.assertEqual((record["status"], record["failure_stage"]), ("timeout", None))
        self.assertTrue(scorecard["gates"]["healthy_execution"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)

    def test_fault_injection_pre_fix_runner_certifies_the_stale_attempt(self):  # defect injection
        with unittest.mock.patch.object(eff, "_default_runner", _pre_fix_default_runner):
            scorecard, _record, _files, _kept = _run_default_runner("crash", stale_run_id="old-run")
        self.assertTrue(scorecard["eligible"])  # the R46 defect, observable once the fix is removed


# --- R47: a "done" attempt must also be healthy ---------------------------------------------

def _writing_runner(artifact):
    def run(*, out_dir, **_kwargs):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "attempt.json").write_text(json.dumps(artifact), encoding="utf-8")
        return artifact
    return run


def _orchestrate_single(artifact=None, *, oracle=True):
    with TemporaryDirectory() as tmp:
        result = eff.orchestrate(
            _manifest([_VULN], attempts=1), {_VULN["id"]: "https://lab.example/"},
            mode="autonomous", output_dir=Path(tmp), oracle={_VULN["id"]: [oracle]},
            run_id=_RUN_ID, runner_fn=_writing_runner(artifact or _artifact()))
        return result["scorecard"], result["run"]["records"][0], (Path(tmp) / "summary.md").read_text(
            encoding="utf-8")


_DEGRADED_DONE = {
    "result.degraded": {"result": {"degraded": True, "errors": []}},
    "result.errors": {"result": {"degraded": False, "errors": [{"phase": "x", "error": "boom"}]}},
    "auth.degraded": {"auth": {"requested": True, "ok": False, "degraded": True,
                               "hard_error": "authentication requested but not established"}},
    "auth requested, not ok": {"auth": {"requested": True, "ok": False}},
    "degraded as a string": {"result": {"degraded": "false", "errors": []}},
    "errors not a list": {"result": {"degraded": False, "errors": "none"}},
    "result not an object": {"result": "ok"},
    "auth not an object": {"auth": "ok"},
}


class DegradedExecutionTests(unittest.TestCase):
    def test_done_attempt_reporting_degraded_execution_is_rejected(self):  # R47
        for name, extra in _DEGRADED_DONE.items():
            with self.subTest(name):
                record = eff.attempt_record({**_artifact(), **extra}, case_id="c", attempt=1,
                                            artifact_ref="ref", oracle_verified=True)
                self.assertEqual((record["status"], record["failure_stage"]), ("error", "infrastructure"))
                self.assertFalse(record["objective_verified"])
                self.assertTrue(record["_excluded_verified"])
                self.assertTrue(record["health_problems"])

    def test_degraded_attempt_makes_the_run_ineligible_and_is_reported(self):  # R47, caller-level
        artifact = {**_artifact(), "result": {"degraded": True, "errors": [{"error": "model unavailable"}]},
                    "auth": {"requested": True, "ok": False, "degraded": True}}
        scorecard, record, summary = _orchestrate_single(artifact)
        self.assertFalse(scorecard["eligible"])
        self.assertFalse(scorecard["gates"]["healthy_execution"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)
        self.assertEqual([d["case_id"] for d in scorecard["degraded_attempts"]], [_VULN["id"]])
        self.assertEqual(scorecard["excluded_verified_attempts"], [{"case_id": _VULN["id"], "attempt": 1}])
        self.assertIn("Degraded attempts", summary)
        self.assertIn("result.degraded is true", summary)

    def test_healthy_done_attempt_with_explicit_health_blocks_succeeds(self):  # control
        artifact = {**_artifact(), "result": {"degraded": False, "errors": []},
                    "auth": {"requested": True, "ok": True, "login_status": 200}}
        scorecard, record, summary = _orchestrate_single(artifact)
        self.assertTrue(scorecard["eligible"])
        self.assertEqual((record["status"], record["objective_verified"]), ("success", True))
        self.assertNotIn("health_problems", record)
        self.assertNotIn("Degraded attempts", summary)

    def test_artifact_without_health_blocks_is_unchanged(self):  # control: older artifacts
        record = eff.attempt_record(_artifact(), case_id="c", attempt=1, artifact_ref="ref",
                                    oracle_verified=True)
        self.assertEqual((record["status"], record["objective_verified"]), ("success", True))

    def test_timeout_keeps_its_own_status_when_degraded(self):  # control
        artifact = {**_artifact(status="timeout"), "result": {"degraded": True, "errors": [{"e": 1}]}}
        record = eff.attempt_record(artifact, case_id="c", attempt=1, artifact_ref="ref")
        self.assertEqual((record["status"], record["failure_stage"]), ("timeout", None))
        self.assertNotIn("health_problems", record)

    def test_fault_injection_ignoring_health_scores_the_degraded_run(self):  # defect injection
        artifact = {**_artifact(), "result": {"degraded": True, "errors": [{"error": "x"}]}}
        with unittest.mock.patch.object(eff, "_degradation", lambda _artifact: []):
            scorecard, _record, _summary = _orchestrate_single(artifact)
        self.assertTrue(scorecard["eligible"])  # the R47 defect, observable once the fix is removed


# --- R48: oracle verdicts are real booleans -------------------------------------------------

def _orchestrate_with_oracle(oracle):
    with TemporaryDirectory() as tmp:
        result = eff.orchestrate(
            _manifest([_VULN], attempts=1), {_VULN["id"]: "https://lab.example/"},
            mode="autonomous", output_dir=Path(tmp), oracle=oracle, run_id=_RUN_ID,
            runner_fn=_writing_runner(_artifact()))
        return result["scorecard"], (Path(tmp) / "summary.md").read_text(encoding="utf-8")


class OracleVerdictTests(unittest.TestCase):
    def test_non_boolean_verdicts_never_count_as_solved(self):  # R48
        for bad in ("false", "true", "False", 1, 0, None, [True]):
            with self.subTest(verdict=bad):
                scorecard, summary = _orchestrate_with_oracle({_VULN["id"]: [bad]})
                self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)
                self.assertEqual(scorecard["objective"]["repeatable_successes"], 0)
                self.assertFalse(scorecard["eligible"])
                self.assertFalse(scorecard["gates"]["valid_oracle_entries"])
                self.assertEqual([e["case_id"] for e in scorecard["invalid_oracle_entries"]], [_VULN["id"]])
                self.assertIn("Invalid oracle entries", summary)

    def test_oracle_that_is_not_a_list_is_reported_not_a_crash(self):  # R48
        for bad in (True, "true", {"1": True}):
            with self.subTest(oracle=bad):
                scorecard, _summary = _orchestrate_with_oracle({_VULN["id"]: bad})
                self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)
                self.assertFalse(scorecard["eligible"])

    def test_boolean_true_scores_one(self):  # control
        scorecard, _summary = _orchestrate_with_oracle({_VULN["id"]: [True]})
        self.assertTrue(scorecard["eligible"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 1)
        self.assertEqual(scorecard["invalid_oracle_entries"], [])

    def test_boolean_false_scores_zero(self):  # control
        scorecard, _summary = _orchestrate_with_oracle({_VULN["id"]: [False]})
        self.assertTrue(scorecard["eligible"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)

    def test_missing_oracle_is_unverified_not_invalid(self):  # control: documented default
        scorecard, _summary = _orchestrate_with_oracle({})
        self.assertTrue(scorecard["eligible"])
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 0)

    def test_record_and_assembly_reject_a_non_boolean_verdict(self):  # R48, library boundary
        for bad in ("false", 1, None):
            with self.subTest(verdict=bad):
                with self.assertRaises(BenchmarkContractError):
                    eff.attempt_record(_artifact(), case_id="c", attempt=1, artifact_ref="r",
                                       oracle_verified=bad)
                with self.assertRaises(BenchmarkContractError):
                    eff.assemble_run("autonomous", [{"case_id": "c", "attempt": 1, "artifact": _artifact(),
                                                     "artifact_ref": "r", "oracle_verified": bad}],
                                     run_id="r1")

    def test_fault_injection_bool_coercion_solves_the_objective(self):  # defect injection
        def pre_fix(case_oracle, attempt):  # bool() of the raw entry: "false" is truthy
            return bool(attempt <= len(case_oracle) and case_oracle[attempt - 1]), None

        with unittest.mock.patch.object(eff, "_oracle_verdict", pre_fix):
            scorecard, _summary = _orchestrate_with_oracle({_VULN["id"]: ["false"]})
        self.assertEqual(scorecard["objective"]["first_attempt_successes"], 1)  # the R48 defect


if __name__ == "__main__":
    unittest.main()
