"""Tests for the Priority-1 efficacy orchestrator.

Each acceptance property has a positive case AND a negative control. The pure
record-mapping / assembly path is exercised directly; the end-to-end path drives
the REAL scorer (:mod:`testing.web_objective_benchmark`) and, for orchestration,
an injected fake runner so no live target is touched.
"""
from __future__ import annotations

import json
import unittest
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


if __name__ == "__main__":
    unittest.main()
