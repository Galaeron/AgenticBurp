"""Caller-level tests of the captured-analysis driver's run-validity rule (R44).

`run_captured_analysis.main` is driven end to end over a synthetic server
boundary (`http_json` is the only stub; provenance helpers are replaced by
fixed values). No HTTP, model, corpus, target or credential is used.

The rule under test: a run is valid only if every exchange came back as a
structurally real analysis (HTTP 200, an object carrying a non-empty
`agent_reports` list and a boolean `degraded`), no exchange was degraded or
carried agent errors beyond the documented error-rate tolerance, and nothing
timed out. Before R44 only `raw_error` strings were counted, so HTTP 200 `{}`
and `degraded=True` with no reports were both reported as a valid run.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from testing import run_captured_analysis as driver  # noqa: E402

HEALTHY = {"degraded": False,
           "agent_reports": [{"agent": "sqli", "findings": [], "raw_error": None}]}


def _healthy():
    return json.loads(json.dumps(HEALTHY))


def exercise(responses, *, n_exchanges=1):
    """Run the driver over `n_exchanges` synthetic exchanges. `responses` is
    one `(status, body)` pair used for every /analyze call, or a list of such
    pairs (one per exchange). Returns `(rc, meta, records)`."""
    if isinstance(responses, tuple):
        responses = [responses] * n_exchanges
    analyze_calls = iter(responses)
    provenance = types.ModuleType("testing.remote_run_provenance")
    provenance.checked_provenance = lambda *_: {"harness_commit": "synthetic"}
    provenance.assert_unchanged = lambda *_: None
    provenance.driver_identity = lambda *_: "synthetic-driver"

    def http(method, url, body, timeout):
        if url.endswith("/analyze"):
            return next(analyze_calls)
        return 200, {}

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source, out = td / "synthetic.json", td / "result.json"
        source.write_text(json.dumps(
            [{"method": "GET", "url": f"https://example.invalid/x{i}"} for i in range(n_exchanges)]))
        args = ["--exchanges", str(source), "--out", str(out), "--label", "rvc",
                "--harness-repo", str(_ROOT), "--decisive-config", str(td / "unused.yaml")]
        with mock.patch.dict(sys.modules, {"testing.remote_run_provenance": provenance}), \
             mock.patch.dict(os.environ, {"HARNESS_TOKEN": "synthetic-not-a-secret"}), \
             mock.patch.object(driver, "http_json", side_effect=http), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(args)
        saved = json.loads(out.read_text())
    return rc, saved["meta"]["validity"], saved["records"]


class InvalidAnalysisPayloadTests(unittest.TestCase):
    def assert_invalid(self, response, *, n_exchanges=1):
        rc, validity, records = exercise(response, n_exchanges=n_exchanges)
        self.assertNotEqual(rc, 0, validity)
        self.assertFalse(validity["valid_run"], validity)
        return validity, records

    def test_missing_analysis_payload_is_invalid(self):
        validity, records = self.assert_invalid((200, {}))
        self.assertEqual(validity["exchanges_with_invalid_payload"], 1)
        self.assertIn("agent_reports", records[0]["payload_defect"])

    def test_degraded_empty_reports_is_invalid(self):
        validity, _ = self.assert_invalid((200, {"degraded": True, "agent_reports": []}))
        self.assertEqual(validity["exchanges_with_invalid_payload"], 1)

    def test_not_analyzed_effort_budget_shape_is_invalid(self):
        """The server's real 'Not analyzed' response: healthy-looking flags and
        no reports. An exchange that was never analyzed is missing data."""
        self.assert_invalid((200, {"degraded": False, "agent_reports": [],
                                   "dispatched_agents": [], "summary": "Not analyzed: budget"}))

    def test_other_malformed_payloads_are_invalid(self):
        report = {"agent": "sqli", "findings": [], "raw_error": None}
        for label, response in (
                ("empty body with 200", (200, None)),
                ("non-200 success status", (204, _healthy())),
                ("list body", (200, [report])),
                ("agent_reports is not a list", (200, {"degraded": False, "agent_reports": {"a": report}})),
                ("agent report is not an object", (200, {"degraded": False, "agent_reports": ["sqli"]})),
                ("degraded flag absent", (200, {"agent_reports": [report]})),
                ("degraded flag not a bool", (200, {"degraded": "no", "agent_reports": [report]}))):
            with self.subTest(label):
                self.assert_invalid(response)

    def test_one_malformed_exchange_invalidates_a_large_run(self):
        """A missing analysis is not model noise: the documented 10% error
        tolerance does not cover it."""
        responses = [(200, _healthy())] * 19 + [(200, {})]
        validity, _ = self.assert_invalid(responses, n_exchanges=20)
        self.assertEqual(validity["exchanges_with_invalid_payload"], 1)

    def test_degraded_response_with_reports_is_invalid(self):
        response = _healthy()
        response["degraded"] = True
        validity, _ = self.assert_invalid((200, response))
        self.assertEqual(validity["exchanges_degraded_or_with_agent_errors"], 1)

    def test_top_level_agent_errors_and_failed_stage_are_health_failures(self):
        for label, extra in (("agent_errors", {"agent_errors": ["sqli: model unavailable"]}),
                             ("failed stage", {"stage_outcomes": [{"stage": "critique", "status": "failed"}]})):
            with self.subTest(label):
                response = dict(_healthy(), **extra)
                self.assert_invalid((200, response))


class ValidAnalysisControlTests(unittest.TestCase):
    def test_healthy_negative_control(self):
        rc, validity, _ = exercise((200, _healthy()))
        self.assertEqual(rc, 0)
        self.assertTrue(validity["valid_run"])

    def test_healthy_run_reports_no_payload_or_health_defects(self):
        _, validity, records = exercise((200, _healthy()))
        self.assertEqual(validity["exchanges_with_invalid_payload"], 0)
        self.assertEqual(validity["exchanges_degraded_or_with_agent_errors"], 0)
        self.assertIsNone(records[0]["payload_defect"])

    def test_explicit_error_control(self):
        rc, validity, _ = exercise((200, {"degraded": False, "agent_reports": [
            {"agent": "sqli", "raw_error": "model unavailable", "findings": []}]}))
        self.assertEqual(rc, 2)
        self.assertFalse(validity["valid_run"])
        self.assertEqual(validity["exchanges_with_raw_error_or_error"], 1)

    def test_existing_error_rate_tolerance_is_unchanged(self):
        """1 failing exchange in 10 is exactly the documented 10% tolerance."""
        failing = {"degraded": False, "agent_reports": [{"agent": "sqli", "raw_error": "boom", "findings": []}]}
        rc, validity, _ = exercise([(200, _healthy())] * 9 + [(200, failing)], n_exchanges=10)
        self.assertEqual(rc, 0)
        self.assertTrue(validity["valid_run"])
        rc, validity, _ = exercise([(200, _healthy())] * 8 + [(200, failing)] * 2, n_exchanges=10)
        self.assertEqual(rc, 2)

    def test_findings_in_a_healthy_response_do_not_affect_validity(self):
        response = _healthy()
        response["agent_reports"][0]["findings"] = [{"vulnerability_class": "sqli"}]
        rc, validity, _ = exercise((200, response))
        self.assertEqual(rc, 0)
        self.assertTrue(validity["valid_run"])


class PayloadValidatorIsLoadBearingTests(unittest.TestCase):
    """Fault injection inside the suite: with the structural validator
    neutralised the very responses rejected above become a valid run again, so
    the rejection comes from that validator and not from some other rule."""

    def test_neutralised_validator_accepts_the_empty_payload(self):
        with mock.patch.object(driver, "_payload_defect", return_value=None):
            rc, validity, _ = exercise((200, {}))
        self.assertEqual(rc, 0)
        self.assertTrue(validity["valid_run"])


if __name__ == "__main__":
    unittest.main()
