from __future__ import annotations
import json
import tempfile
import unittest
from harness.run_manifest import RunManifest, config_fingerprint, redact


class RunManifestTests(unittest.TestCase):
    def test_serializes_and_redacts_nested_secrets(self):
        cfg = {"server": {"auth_token": "bearer-value"},
               "headers": {"Cookie": "session=live", "X-Mode": "safe"}, "model": "qwen3:8b"}
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="run-redact", target_identifier="fixture:vulnerable",
                                    config=cfg, output_dir=td)
            saved = json.loads(run.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["config"]["server"]["auth_token"], "[REDACTED]")
        self.assertEqual(saved["config"]["headers"]["Cookie"], "[REDACTED]")
        self.assertEqual(saved["config"]["headers"]["X-Mode"], "safe")
        self.assertNotIn("bearer-value", json.dumps(saved))
        self.assertEqual(saved["config_fingerprint"], config_fingerprint(cfg))

    def test_started_run_remains_incomplete_in_manifest_and_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="interrupted", target_identifier="fixture", config={}, output_dir=td)
            saved = json.loads(run.path.read_text(encoding="utf-8"))
            ledger = [json.loads(line) for line in run.ledger_path.read_text().splitlines()]
        self.assertEqual(saved["completion_status"], "running")
        self.assertIsNone(saved["finished_at"])
        self.assertEqual([row["completion_status"] for row in ledger], ["running"])

    def test_unavailable_metrics_and_dependency_error_are_honest(self):
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="degraded", target_identifier="fixture", config={}, output_dir=td)
            run.finish("error", error="RuntimeError: Ollama unavailable")
            saved = json.loads(run.path.read_text(encoding="utf-8"))
        self.assertIsNone(saved["model_metrics"])
        self.assertIsNone(saved["request_count"])
        self.assertIsNone(saved["measurement"]["recall"])
        self.assertTrue(saved["degraded"])
        self.assertIn("Ollama unavailable", saved["operational_errors"][0]["error"])

    def test_reviewer_repro_coverage_audited_survives_into_the_manifest(self):
        """R01/R07: the auditable executed-vs-inferred coverage breakdown
        (CoverageTracker.report()["audited"], via coverage_summary.py) must
        survive into the persisted manifest, so a LATER reader (the MCP
        coverage resource) can see it without the live in-memory job result."""
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="cov-run", target_identifier="fixture", config={}, output_dir=td)
            run.finish("done", result={"coverage": {"audited": {
                "executed": {"numerator": 2, "denominator": 8, "kind": "executed", "pct": 25.0},
                "inferred": {"numerator": 1, "denominator": 8, "kind": "inferred", "pct": 12.5},
            }}})
            saved = json.loads(run.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["coverage_audited"]["executed"]["numerator"], 2)

    def test_missing_coverage_key_leaves_coverage_audited_none(self):
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="no-cov", target_identifier="fixture", config={}, output_dir=td)
            run.finish("done", result={})
            saved = json.loads(run.path.read_text(encoding="utf-8"))
        self.assertIsNone(saved["coverage_audited"])

    def test_redact_does_not_mutate_input(self):
        original = {"password": "live", "nested": [{"token": "t"}]}
        cleaned = redact(original)
        self.assertEqual(original["password"], "live")
        self.assertEqual(cleaned["nested"][0]["token"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()

