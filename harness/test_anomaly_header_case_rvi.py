"""Code review 02, batch RV-I (I06/I07): anomaly analysis is case-insensitive about header names (R23).

Drives the production caller the way the reviewer's boundary_checks.py did, with
the reviewer's control as the negative control. Nothing leaves the machine:
requests are answered by a patched ``httpx.AsyncClient``.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import cache, safety_gate, store
from harness.agents.anomaly_agent import AnomalyAgent
from harness.anomaly_detector import AnomalyDetector
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange, _RecordingModel


_SECURITY_HEADERS = ["X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
                     "Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy"]


class AnomalyHeaderCaseTests(unittest.TestCase):
    """R23: present mixed-case headers must not be reported missing."""

    def _findings(self, names, transform):
        ex = _exchange("https://shop.invalid/")
        ex.response_headers = {transform(n): "present" for n in names}
        ex.response_body = "ordinary page"
        with patch("harness.agents.anomaly_agent.detector", AnomalyDetector()):
            report = asyncio.run(AnomalyAgent(None, "synthetic").run(ex, 1000, "", None))
        return ex, [f for f in report.findings
                    if f.vulnerability_class in ("missing_security_header", "security_misconfiguration")]

    def test_anomaly_agent_accepts_header_case(self):
        _ex, missing = self._findings(_SECURITY_HEADERS, lambda n: n)
        self.assertFalse([f.model_dump() for f in missing])

    def test_anomaly_lowercase_headers_control(self):
        _ex, missing = self._findings(_SECURITY_HEADERS, str.lower)
        self.assertFalse([f.model_dump() for f in missing])

    def _assert_only_referrer_policy_missing(self, transform):
        present = [n for n in _SECURITY_HEADERS if n != "Referrer-Policy"]
        _ex, missing = self._findings(present, transform)
        text = " ".join(f"{f.summary} {f.evidence}".lower() for f in missing)
        self.assertIn("referrer-policy", text, missing)
        self.assertNotIn("x-frame-options", text, missing)

    def test_really_missing_header_is_still_reported_lowercase(self):
        self._assert_only_referrer_policy_missing(str.lower)

    def test_really_missing_header_is_still_reported_mixed_case(self):
        self._assert_only_referrer_policy_missing(lambda n: n)

    def test_response_without_security_headers_is_still_reported(self):
        for transform in (lambda n: n, str.lower):
            _ex, missing = self._findings([], transform)
            self.assertTrue(missing)

    def test_other_header_lookups_are_case_insensitive_too(self):
        # The same normalised view feeds the detector's content-type checks.
        ex = _exchange("https://shop.invalid/")
        ex.response_headers = {"Content-Type": "text/plain"}
        ex.response_body = '{"id": 1, "total": 10}'
        lower = ex.model_copy(update={"response_headers": {"content-type": "text/plain"}})
        with patch("harness.agents.anomaly_agent.detector", AnomalyDetector()):
            mixed = asyncio.run(AnomalyAgent(None, "synthetic").run(ex, 1000, "", None))
        with patch("harness.agents.anomaly_agent.detector", AnomalyDetector()):
            low = asyncio.run(AnomalyAgent(None, "synthetic").run(lower, 1000, "", None))
        shape = lambda r: sorted((f.vulnerability_class, f.summary.lower()) for f in r.findings)  # noqa: E731
        self.assertEqual(shape(mixed), shape(low))

    def test_callers_exchange_is_not_mutated(self):
        ex, _missing = self._findings(_SECURITY_HEADERS, lambda n: n)
        self.assertEqual(sorted(ex.response_headers), sorted(_SECURITY_HEADERS))


class AnalyzeCallerTests(unittest.TestCase):
    """The same defect through Orchestrator.analyze, the way a Burp capture arrives."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rvi_anomaly_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _anomaly_findings(self, headers):
        orch = Orchestrator(_config())
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        ex = _exchange("https://shop.invalid/")
        ex.response_headers = headers
        with patch("harness.agents.anomaly_agent.detector", AnomalyDetector()):
            response = asyncio.run(orch.analyze(ex, force_agents=["anomaly"]))
        self.assertEqual(response.dispatched_agents, ["anomaly"])
        return [f for rep in response.agent_reports if rep.agent == "anomaly"
                for f in rep.findings
                if f.vulnerability_class in ("missing_security_header", "security_misconfiguration")]

    def test_present_mixed_case_headers_are_not_reported_missing(self):
        self.assertEqual(self._anomaly_findings({n: "present" for n in _SECURITY_HEADERS}), [])

    def test_headers_really_absent_are_still_reported(self):
        self.assertTrue(self._anomaly_findings({"Content-Type": "application/json"}))


if __name__ == "__main__":
    unittest.main()
