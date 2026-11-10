"""r7: on a plain-HTTP loopback target, "Insecure Transmission of Credentials/Data",
"Insecure Transport" and "Token Transmission over HTTP" were filed as
vulnerabilities on every route. The scheme of a local test deployment is not a
flaw of the application: such findings are now environment (hardening)
observations with a stated reason, through the existing header/transport noise
path. Control: the same findings on a public plain-HTTP host stay vulnerabilities.

Caller-level: the real AnalysisPipeline.run_full_analysis (only the agent
dispatch is faked, returning the findings) followed by the real
confirmation-suppression gate and lifecycle/triage mapping.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from harness.analysis_pipeline import AnalysisPipeline
from harness.confirmation_gate import (
    STATE_LEAD, STATE_SUSPECTED, apply_confirmation_suppression, finding_lifecycle_state,
    finding_triage)
from harness.header_noise_gate import ENVIRONMENT_VERDICT, local_plain_http_host
from harness.models import AgentReport, Finding, HttpExchange, StageOutcome

_CLASSES = ("Insecure Transmission of Credentials/Data", "Insecure Transport",
            "Token Transmission over HTTP", "Cleartext Transmission of JWT")


def _findings():
    return [Finding(vulnerability_class=c, confidence=0.8, severity="medium", summary=c,
                    evidence="the login form posts over http://", suggested_test="t",
                    basis="derived") for c in _CLASSES] + [
        Finding(vulnerability_class="sqli", confidence=0.8, severity="high", summary="sqli",
                evidence="e", suggested_test="t", basis="derived")]


def _run(url, *, critique=None):
    manager = MagicMock()
    findings = _findings()
    manager.run_multiple_agents = AsyncMock(
        return_value=[AgentReport(agent="crypto", model="m", findings=findings)])
    pipeline = AnalysisPipeline(manager, effort_budget=None, store=None, ollama_client=MagicMock(),
                                config={"critique": {"enabled": False}})
    exchange = HttpExchange(url=url, method="POST", request_headers={}, request_body="u=a&p=b",
                            response_status=200, response_headers={}, response_body="ok")
    with patch.object(AnalysisPipeline, "_critique", critique) if critique else _noop():
        reports, *_ = asyncio.run(pipeline.run_full_analysis(exchange, ["crypto"], "", 4000))
    apply_confirmation_suppression(reports, [])
    return reports[0].findings


class _noop:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class LocalCleartextEnvironmentTests(unittest.TestCase):
    def test_loopback_http_target_makes_transport_findings_environment_observations(self):
        for url in ("http://127.0.0.1:3000/rest/user/login", "http://localhost/login",
                    "http://[::1]:8080/login", "http://10.0.0.5/login"):
            with self.subTest(url=url):
                *transport, sqli = _run(url)
                for f in transport:
                    self.assertEqual(f.review_verdict, ENVIRONMENT_VERDICT, f.vulnerability_class)
                    self.assertEqual((f.severity, f.original_severity), ("info", "medium"))
                    self.assertIn("plain HTTP on the loopback/private address", f.review_note)
                    self.assertEqual(finding_lifecycle_state(f), STATE_LEAD)
                    self.assertEqual(finding_triage(f)["triage_priority"], "hardening")
                    self.assertFalse(f.summary.startswith("["), f.summary)
                # A real vulnerability on the same target is untouched by this gate.
                self.assertNotEqual(sqli.review_verdict, ENVIRONMENT_VERDICT)
                self.assertNotIn("loopback", sqli.review_note or "")

    def test_control_public_http_host_keeps_them_as_vulnerabilities(self):
        for url in ("http://shop.example.com/login", "http://93.184.216.34/login",
                    "https://127.0.0.1/login"):
            with self.subTest(url=url):
                for f in _run(url)[:3]:
                    self.assertNotEqual(f.review_verdict, ENVIRONMENT_VERDICT)
                    self.assertEqual(f.severity, "medium")
                    self.assertEqual(finding_lifecycle_state(f), STATE_SUSPECTED)

    def test_critique_survival_does_not_overwrite_the_classification(self):
        async def survived(self, exchange, reports):
            for r in reports:
                for f in r.findings:
                    f.review_verdict = "survived"
            return StageOutcome(name="critique", status="completed"), 5, 0
        transport = _run("http://127.0.0.1:3000/login", critique=survived)[:4]
        self.assertTrue(all(f.review_verdict == ENVIRONMENT_VERDICT for f in transport))

    def test_host_predicate(self):
        self.assertEqual(local_plain_http_host("http://127.8.0.1/"), "127.8.0.1")
        self.assertEqual(local_plain_http_host("http://app.localhost:5000/"), "app.localhost")
        for url in ("https://localhost/", "http://example.com/", "http://8.8.8.8/",
                    "http://0.0.0.0/", "", "not a url"):
            self.assertEqual(local_plain_http_host(url), "", url)


if __name__ == "__main__":
    unittest.main()
