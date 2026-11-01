"""R03 synthetic privacy/auth controls; fake providers never send to targets."""
import asyncio
import base64
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from harness import security, store, issues, report_generator, sarif_adapter, test_pairing_contract as pairing_controls
from harness.agents.base_agent import BaseAgent
from harness.agent_families import FamilyRunner
from harness.coordinator import Coordinator
from harness.analysis_pipeline import AnalysisPipeline
from harness.models import HttpExchange, Finding, AgentReport
from harness.ollama_client import OllamaClient, OllamaResult, OllamaError
from harness.llm_provider import OllamaProvider
from harness.openai_provider import OpenAiProvider, ProviderCallError
from harness.anthropic_provider import AnthropicProvider


SENTINELS = ["R03_HEADER_SENTINEL", "R03_URL_SENTINEL", "R03_BODY_SENTINEL",
             "R03_NESTED_SENTINEL", "R03_NOTE_SENTINEL", "R03_CONTEXT_SENTINEL"]


def captured():
    return HttpExchange(url="https://user:R03_URL_SENTINEL@captured.example/ordinary?token=R03_URL_SENTINEL&item=ordinary",
                        method="GET", request_headers={"Authorization": "Bearer R03_HEADER_SENTINEL",
                                                       "X-Custom-Security": "retain-ordinary-structure"},
                        request_body=json.dumps({"password": "R03_BODY_SENTINEL", "rows": [
                            {"next": "https://captured.example?api_key=R03_NESTED_SENTINEL&item=ordinary"}]}),
                        response_status=200, response_body="Ordinary captured response",
                        analyst_note='{"client_secret":"R03_NOTE_SENTINEL","note":"ordinary-note"}')


class PassiveAgent(BaseAgent):
    name = "synthetic-passive"
    @property
    def specialty_prompt(self):
        return "Review ordinary captured response metadata without sending requests."


class RecordingProvider:
    def __init__(self, result=None):
        self.calls = []
        self.result = result if result is not None else {"findings": [], "components": [],
                                                       "dispatch": ["synthetic-passive"], "reviews": []}

    async def chat_json(self, **kwargs):
        self.calls.append(kwargs)
        return self.result

    async def chat_json_metered(self, *args, **kwargs):
        if args:
            kwargs.update(model=args[0], system_prompt=args[1], user_prompt=args[2])
        self.calls.append(kwargs)
        return OllamaResult(self.result, 7, 3)


class PrivacyCallerTests(unittest.TestCase):
    def assert_sanitized(self, text):
        for value in SENTINELS:
            self.assertNotIn(value, text)
        self.assertIn("ordinary", text.lower())

    def test_passive_specialist_and_family_prompt_boundaries(self):
        for family in (False, True):
            provider = RecordingProvider()
            agent = PassiveAgent(provider, "synthetic")
            runner = FamilyRunner("synthetic-family", [agent]) if family else agent
            with patch("harness.knowledge.retrieve", return_value="client_secret=R03_NOTE_SENTINEL\nordinary-methodology"):
                result = asyncio.run(runner.run(captured(), 6000, "password=R03_CONTEXT_SENTINEL\nordinary-context"))
            self.assertEqual(result.findings, [])
            self.assertEqual(len(provider.calls), 1)
            self.assert_sanitized(provider.calls[0]["user_prompt"])
            self.assertIn("X-Custom-Security", provider.calls[0]["user_prompt"])
            self.assertIn("retain-ordinary-structure", provider.calls[0]["user_prompt"])

    def test_real_coordinator_and_critique_callers_are_sanitized(self):
        provider = RecordingProvider()
        coordinator = Coordinator(provider, {"model": "synthetic"})
        asyncio.run(coordinator.choose_agents(captured(), ["synthetic-passive"]))
        self.assert_sanitized(provider.calls[0]["user_prompt"])
        pipeline = AnalysisPipeline.__new__(AnalysisPipeline)
        pipeline.config = {"coordinator": {"model": "synthetic"}, "critique": {"enabled": True}}
        pipeline.ollama_client = provider
        pipeline.effort_budget = None
        pipeline.store = store
        finding = Finding(vulnerability_class="passive_observation", confidence=0.7,
                          summary='{"token":"R03_CONTEXT_SENTINEL","note":"ordinary-observation"}',
                          evidence="api_key=R03_BODY_SENTINEL", suggested_test="", basis="derived")
        asyncio.run(pipeline._critique(captured(), [AgentReport(agent="synthetic-passive", model="synthetic",
                                                               findings=[finding])]))
        self.assertEqual(len(provider.calls), 2)
        self.assert_sanitized(provider.calls[1]["user_prompt"])

    def test_defect_injection_unprotected_coordinator_leaks_sentinel(self):
        provider = RecordingProvider()
        coordinator = Coordinator(provider, {"model": "synthetic"})
        with patch("harness.security.sanitize_for_inference", side_effect=lambda system, user: (system, user)):
            asyncio.run(coordinator.choose_agents(captured(), ["synthetic-passive"]))
        self.assertIn("R03_BODY_SENTINEL", provider.calls[0]["user_prompt"])

    def test_local_adapter_sanitizes_even_with_fake_inner_client(self):
        inner = RecordingProvider()
        asyncio.run(OllamaProvider(inner).chat_json("synthetic", "ordinary", 'password=R03_BODY_SENTINEL\nordinary-context'))
        self.assert_sanitized(inner.calls[0]["user_prompt"])

    def test_local_offline_profile_fake_egress_recorder(self):
        # Real adapter/HTTP serialization, an in-memory transport, and a real
        # offline advisory client. This bounds these callers, not the whole OS.
        from harness.github_advisories import GitHubAdvisoryClient
        from harness.models import ComponentCandidate
        destinations, payloads = [], []
        real_client = httpx.AsyncClient

        def recorder(request):
            destinations.append(str(request.url))
            payloads.append(json.loads(request.content))
            return httpx.Response(200, json={"message": {"content": '{"findings":[]}'},
                                            "prompt_eval_count": 7, "eval_count": 3})

        class OfflineClient(real_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(recorder)
                super().__init__(*args, **kwargs)

        async def callers():
            inner = OllamaClient(base_url="http://localhost:11434")
            await OllamaProvider(inner).chat_json("synthetic", "ordinary", json.dumps(captured().model_dump()))
            return await GitHubAdvisoryClient(offline=True).lookup(
                ComponentCandidate(name="ordinary", version="1.0", ecosystem="npm"))

        audit = MagicMock()
        with patch("httpx.AsyncClient", OfflineClient), patch(
                "harness.audit_logger.get_audit_logger", return_value=audit):
            result = asyncio.run(callers())
        self.assertEqual(destinations, ["http://localhost:11434/api/chat"])
        self.assert_sanitized(json.dumps(payloads))
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, repr(audit.mock_calls))
        self.assertIn(result.status, {"no_known_advisory", "error"})

    def test_known_error_text_is_withheld_from_passive_result(self):
        provider = RecordingProvider()
        provider.chat_json = AsyncMock(side_effect=OllamaError("password=R03_BODY_SENTINEL"))
        result = asyncio.run(PassiveAgent(provider, "synthetic").run(captured(), 6000))
        self.assertEqual(result.findings, [])
        self.assertNotIn("R03_BODY_SENTINEL", result.raw_error)
        self.assertIn("OllamaError", result.raw_error)

    def test_remote_adapter_payloads_errors_and_missing_usage(self):
        for cls, body in (
                (OpenAiProvider, {"choices": [{"message": {"content": "{}"}}]}),
                (AnthropicProvider, {"content": [{"type": "text", "text": "{}"}]})):
            provider = cls(api_key="synthetic-wire-provider-key")
            response = httpx.Response(200, json=body, request=httpx.Request("POST", "https://provider.invalid/ordinary"))
            post = AsyncMock(return_value=response)
            with patch("httpx.AsyncClient.post", post):
                result = asyncio.run(provider.chat_json("synthetic", "ordinary", json.dumps(captured().model_dump())))
            payload = post.call_args.kwargs["json"]
            self.assert_sanitized(json.dumps(payload))
            self.assertIsNone(result.prompt_tokens)
            self.assertIsNone(result.completion_tokens)
            with patch("httpx.AsyncClient.post", AsyncMock(side_effect=httpx.HTTPError("R03_BODY_SENTINEL"))):
                with self.assertRaises(ProviderCallError) as caught:
                    asyncio.run(provider.chat_json("synthetic", "ordinary", "ordinary"))
            self.assertNotIn("R03_BODY_SENTINEL", str(caught.exception))

    def test_remote_unparseable_response_preserves_known_consumption(self):
        bodies = [(OpenAiProvider, {"choices": [{"message": {"content": "R03_BODY_SENTINEL"}}],
                                   "usage": {"prompt_tokens": 7, "completion_tokens": 3}}),
                  (AnthropicProvider, {"content": [{"type": "text", "text": "R03_BODY_SENTINEL"}],
                                       "usage": {"input_tokens": 7, "output_tokens": 3}})]
        for cls, body in bodies:
            response = httpx.Response(200, json=body, request=httpx.Request("POST", "https://provider.invalid/ordinary"))
            with patch("httpx.AsyncClient.post", AsyncMock(return_value=response)):
                with self.assertRaises(ProviderCallError) as caught:
                    asyncio.run(cls(api_key="synthetic-wire-key").chat_json("synthetic", "ordinary", "ordinary"))
            self.assertNotIn("R03_BODY_SENTINEL", str(caught.exception))
            self.assertEqual(caught.exception.inference_usage["prompt_tokens"], 7)
            self.assertEqual(caught.exception.inference_usage["completion_tokens"], 3)
            self.assertFalse(caught.exception.inference_usage["usable"])

    def test_structural_sanitization_is_idempotent_and_preserves_nonsecrets(self):
        text = json.dumps(captured().model_dump())
        clean = security.sanitize_text(text)
        self.assert_sanitized(clean)
        self.assertEqual(security.sanitize_text(clean), clean)
        ordinary = '{ "search": "ordinary%2Bencoded", "rows": [1, 2] }'
        self.assertEqual(security.sanitize_text(ordinary), ordinary)
        self.assertEqual(security.sanitize_text("unlabelled opaque text"), "unlabelled opaque text")
        self.assertNotIn("synthetic-opaque-secret", security.sanitize_text(
            "known value synthetic-opaque-secret", known_values=["synthetic-opaque-secret"]))
        from harness import issues
        self.assert_sanitized(issues.redact(text))
        self.assertNotIn("R03_URL_SENTINEL", issues.redact_url(captured().url + "#access_token=R03_URL_SENTINEL"))

    def test_jwt_header_discloses_only_allowed_metadata(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT",
                                                     "kid": "R03_HEADER_SENTINEL",
                                                     "private_key": "R03_BODY_SENTINEL"}).encode()).decode().rstrip("=")
        clean = security.redact_headers({"Authorization": f"Bearer {header}.synthetic-payload.synthetic-signature"})
        self.assertIn('"alg": "HS256"', clean["Authorization"])
        self.assertNotIn("R03_HEADER_SENTINEL", repr(clean))
        self.assertNotIn("R03_BODY_SENTINEL", repr(clean))
        self.assertNotIn("synthetic-payload", repr(clean))


class SensitiveReadCallerTests(pairing_controls.PairingCallerTests):
    def _seed_secret_finding(self):
        exchange = captured().model_copy(update={
            "url": "https://captured.example/ordinary?token=R03_URL_SENTINEL&item=ordinary"})
        store.persist_findings(exchange, "synthetic-passive", [Finding(
            vulnerability_class="passive_observation", confidence=0.7, severity="info",
            summary='{"password":"R03_BODY_SENTINEL","note":"ordinary-observation"}',
            evidence="Authorization: Bearer R03_HEADER_SENTINEL\n"
                     'nested={"rows":[{"client_secret":"R03_NESTED_SENTINEL"}]}',
            suggested_test="api_key=R03_CONTEXT_SENTINEL\nordinary-review", basis="derived")])
        return exchange

    def test_real_markdown_sarif_and_structured_export_boundaries(self):
        exchange = self._seed_secret_finding()
        original = store.all_host_findings(exchange.url)
        self.assertIn("R03_BODY_SENTINEL", original[0]["summary"])
        exports = report_generator.export_issues_for_host(exchange.url)
        self.assertEqual(len(exports), 1)
        views = [json.dumps(exports)]
        for route in ("/report", "/report/sarif"):
            denied = self.client.get(route, params={"url": exchange.url})
            self.assertEqual(denied.status_code, 401)
            with self.assertLogs("httpx", "INFO") as logs:
                response = self.client.get(route, params={"url": exchange.url}, headers=self.auth)
            self.assertNotIn("R03_URL_SENTINEL", "".join(logs.output))
            self.assertEqual(response.status_code, 200, response.text)
            views.append(response.text)
            if route.endswith("sarif"):
                self.assertEqual(sarif_adapter.validate_sarif_shape(response.json()), [])
                self.assertEqual(len(response.json()["runs"][0]["results"]), 1)
        for view in views:
            for sentinel in SENTINELS:
                self.assertNotIn(sentinel, view)
            self.assertIn("ordinary", view)
        self.assertEqual(store.all_host_findings(exchange.url), original)

    def test_export_metadata_and_markdown_chain_follow_shared_contract(self):
        raw = {"url": "https://captured.example/ordinary", "method": "GET",
               "vulnerability_class": "passive_observation", "severity": "info", "confidence": 0.7,
               "summary": "ordinary", "evidence": "ordinary", "basis": "derived",
               "parameter_location": "query", "parameter_name": "token=R03_CONTEXT_SENTINEL",
               "proof_id": "api_key=R03_NESTED_SENTINEL"}
        issue = issues.group_findings_into_issues([raw])[0]
        for view in (issues.export_issue(issue), issues.replay_view(issue)):
            self.assertNotIn("R03_CONTEXT_SENTINEL", json.dumps(view))
            self.assertNotIn("R03_NESTED_SENTINEL", json.dumps(view))
        raw["vulnerability_class"] = "potential-attack-chain:token=R03_BODY_SENTINEL"
        rendered = report_generator.generate_markdown_report("ordinary", [raw])
        self.assertNotIn("R03_BODY_SENTINEL", rendered)
        self.assertIn("Potential Attack Chains", rendered)

    def test_defect_injection_http_log_filter_leaks_encoded_url_sentinel(self):
        exchange = self._seed_secret_finding()
        logger = security.logging.getLogger("httpx")
        privacy_filters = [item for item in logger.filters if isinstance(item, security.PrivacyLogFilter)]
        self.assertTrue(privacy_filters, "actual HTTP diagnostic logger must have the privacy boundary")
        for item in privacy_filters:
            logger.removeFilter(item)
        try:
            with self.assertLogs("httpx", "INFO") as logs:
                response = self.client.get("/report", params={"url": exchange.url}, headers=self.auth)
            self.assertEqual(response.status_code, 200)
            self.assertIn("R03_URL_SENTINEL", "".join(logs.output))
        finally:
            for item in privacy_filters:
                logger.addFilter(item)

    def test_defect_injection_export_boundary_leaks_metadata_sentinel(self):
        raw = {"url": "https://captured.example/ordinary", "method": "GET",
               "vulnerability_class": "passive_observation", "summary": "ordinary",
               "parameter_location": "query", "parameter_name": "token=R03_CONTEXT_SENTINEL"}
        issue = issues.group_findings_into_issues([raw])[0]
        with patch("harness.security.sanitize_data", side_effect=lambda value, **kwargs: value):
            self.assertIn("R03_CONTEXT_SENTINEL", json.dumps(issues.export_issue(issue)))

    def test_every_registered_sensitive_get_rejects_without_token(self):
        public = {"/health", "/pairing/check", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
        checked = []
        for route in self.server.app.routes:
            if "GET" not in getattr(route, "methods", ()) or route.path in public:
                continue
            path = route.path
            for parameter in getattr(route, "param_convertors", {}):
                path = path.replace("{" + parameter + "}", "synthetic")
            with self.subTest(route=route.path):
                self.assertEqual(self.client.get(path).status_code, 401)
                self.assertEqual(self.client.get(path, headers={"Authorization": "Bearer synthetic-wrong"}).status_code, 401)
            checked.append(route.path)
        self.assertIn("/report", checked)
        self.assertIn("/models", checked)
        self.assertIn("/cache/stats", checked)

    def test_false_legacy_config_and_flag_cannot_disable_reads(self):
        self.server.config["server"]["require_read_auth"] = False
        self.server._READ_AUTH_ENABLED = False
        self.assertEqual(self.client.get("/report", params={"url": "https://captured.example"}).status_code, 401)
        with self.assertRaises(Exception) as denied:
            self.server._require_read_auth(None)
        self.assertEqual(denied.exception.status_code, 401)
        self.server._require_read_auth(self.auth["Authorization"])

    def test_server_error_does_not_echo_sensitive_detail_or_traceback(self):
        self.server.orchestrator.analyze = AsyncMock(side_effect=ValueError("R03_BODY_SENTINEL"))
        with self.assertLogs("harness.server", "ERROR") as log:
            response = self.client.post("/analyze", json=self.request, headers=self.auth)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("R03_BODY_SENTINEL", response.text)
        self.assertNotIn("R03_BODY_SENTINEL", "".join(log.output))
        self.assertIn("ValueError", response.text)


if __name__ == "__main__":
    unittest.main()
