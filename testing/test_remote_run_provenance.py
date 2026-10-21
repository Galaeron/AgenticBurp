import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from testing import run_captured_analysis as driver
from testing.remote_run_provenance import checked_provenance

# A structurally healthy /analyze answer. These tests are about provenance
# stamping and drift, so the analysis responses must be valid on their own: the
# driver (R44) no longer treats an empty `{}` body as a valid analysis, and a
# test whose only analysis response is `{}` could not tell drift from a bad payload.
HEALTHY_ANALYSIS = {"degraded": False,
                    "agent_reports": [{"agent": "sqli", "findings": [], "raw_error": None}]}


class RemoteDriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.overlay = self.root / "run.yaml"
        self.controls = {
            "server": {"allowed_hosts": ["crapi.test"]},
            "validators": {"active_enabled": True, "allow_mutating_replay": True, "max_burst_size": 5},
            "ollama": {"seed": 0}, "coordinator": {"temperature": 0, "model": "m"},
            "agent_defaults": {"temperature": 0}, "critique": {"temperature": 0},
        }
        self.overlay.write_text(yaml.safe_dump(self.controls))
        self.state = {"schema_version": 1, "controls": self.controls, "source_matches_disk": True,
                      "harness_commit": "server-commit", "config_hash": "server-config",
                      "source": {"content_id": "server-source"}}
        self.exchanges = self.root / "exchanges.json"
        self.exchanges.write_text(json.dumps([{"method": "GET", "url": "http://crapi.test/object/1"}]))
        self.out = self.root / "out.json"
        self.argv = ["--harness-repo", str(Path(__file__).resolve().parent.parent),
                     "--decisive-config", str(self.overlay), "--exchanges", str(self.exchanges),
                     "--out", str(self.out), "--label", "synthetic"]

    def test_actual_driver_stamps_checkpoint_and_final_result(self):
        seen = []
        def http(method, url, body, timeout):
            seen.append(url)
            if url.endswith("run-provenance"):
                return 200, self.state
            return 200, HEALTHY_ANALYSIS
        with patch.dict(os.environ, {"HARNESS_TOKEN": "synthetic"}), patch.object(driver, "http_json", side_effect=http):
            self.assertEqual(driver.main(self.argv), 0)
        result = json.loads(self.out.read_text())
        self.assertEqual(result["meta"]["provenance"]["config_hash"], "server-config")
        self.assertEqual(result["meta"]["harness_commit"], "server-commit")
        self.assertEqual(result["meta"]["provenance"]["effective_seed"], 0)
        self.assertTrue(result["meta"]["validity"]["valid_run"])
        self.assertTrue(seen[0].endswith("run-provenance"))

    def test_wrong_server_settings_fail_before_cache_clear_or_analysis(self):
        state = copy.deepcopy(self.state)
        state["controls"]["critique"]["temperature"] = 0.1
        with patch.dict(os.environ, {"HARNESS_TOKEN": "synthetic"}), \
             patch.object(driver, "http_json", return_value=(200, state)) as http:
            with self.assertRaises(ValueError):
                driver.main(self.argv)
            self.assertEqual(http.call_count, 1)
        self.assertFalse(self.out.exists())

    def test_source_drift_invalidates_saved_result(self):
        calls = 0
        def http(method, url, body, timeout):
            nonlocal calls
            if url.endswith("run-provenance"):
                calls += 1
                state = copy.deepcopy(self.state)
                if calls > 1:
                    state["source_matches_disk"] = False
                return 200, state
            return 200, HEALTHY_ANALYSIS
        with patch.dict(os.environ, {"HARNESS_TOKEN": "synthetic"}), patch.object(driver, "http_json", side_effect=http):
            self.assertEqual(driver.main(self.argv), 2)
        result = json.loads(self.out.read_text())
        self.assertFalse(result["meta"]["validity"]["valid_run"])
        self.assertFalse(result["meta"]["provenance_valid"])


if __name__ == "__main__":
    unittest.main()
