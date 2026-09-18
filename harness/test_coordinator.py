"""
Tests for coordinator.py -- no test file existed for this module before
this one. HANDOVER.md flagged its fail-open behavior (falling back to
ALL available agents when the routing LLM errors or returns nothing
usable) as "never verified under live traffic" -- fast_path.py now
handles the overwhelming majority of real exchanges, so the coordinator
essentially never fires in practice, which also means these code paths
had never run against anything, mocked or real, before this file existed.
"""
import unittest
from unittest.mock import AsyncMock

from harness import coordinator
from harness.coordinator import Coordinator
from harness.models import HttpExchange
from harness.ollama_client import OllamaError, OllamaResult


def _exchange(url="https://example.test/about", method="GET"):
    return HttpExchange(
        url=url, method=method, request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="<html>ok</html>",
    )


class CoordinatorDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ollama = AsyncMock()
        self.coordinator = Coordinator(self.ollama, {"model": "llama3.1:8b"})
        self.available = ["sqli", "xss", "idor", "auth", "misconfig"]

    async def test_valid_dispatch_is_returned_as_is(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor", "auth"], "reason": "numeric id + no auth header"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, ["idor", "auth"])
        self.assertEqual(reason, "numeric id + no auth header")

    async def test_dispatch_is_filtered_to_available_agents_only(self):
        """The routing model can only see the names it was given, but
        nothing stops it hallucinating one anyway -- silently trusting an
        unavailable agent name would crash downstream dispatch."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor", "graphql", "ssti"], "reason": "r"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, _ = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, ["idor"])

    async def test_empty_dispatch_falls_back_to_all_available_agents(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": [], "reason": "nothing plausible"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_dispatch_of_only_unavailable_agents_falls_back(self):
        """Filtering can reduce a non-empty model response to an empty
        one -- that must hit the same fallback as an originally-empty
        dispatch, not silently return an empty list."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["graphql", "ssti"], "reason": "r"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_malformed_json_response_falls_back(self):
        """chat_json_metered raises OllamaError when the model doesn't
        return valid/parseable JSON -- the coordinator must not propagate
        that as an unhandled exception up through analyze()."""
        self.ollama.chat_json_metered.side_effect = OllamaError("not valid JSON")
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)
        self.assertIn("coordinator error", reason)

    async def test_missing_dispatch_key_falls_back(self):
        """A well-formed JSON object that simply doesn't use the
        requested shape (e.g. the model answers conversationally inside
        valid JSON) must be treated the same as an empty dispatch, not
        raise a KeyError."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"answer": "no vulnerabilities here"}, prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_generic_exception_from_ollama_falls_back(self):
        """Any unexpected exception (network error, timeout, circuit
        breaker open) must degrade to fail-open, never propagate."""
        self.ollama.chat_json_metered.side_effect = RuntimeError("connection reset")
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)


class CloudCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    """Cloud-primary routing (handover §7): routes on the anonymized
    projection, uses the cloud model, and never leaks body/header values
    across the off-prem boundary."""

    def setUp(self):
        self.ollama = AsyncMock()
        self.available = ["sqli", "xss", "idor", "auth", "misconfig", "cors"]

    def test_cloud_flags_default_off(self):
        c = Coordinator(self.ollama, {"model": "qwen3:8b"})
        self.assertFalse(c.cloud_primary)
        self.assertEqual(c.cloud_model, "qwen3:8b")  # falls back to local model

    def test_cloud_flags_parsed(self):
        c = Coordinator(self.ollama, {
            "model": "qwen3:8b", "cloud_primary": True, "cloud_model": "gemma4:31b-cloud",
        })
        self.assertTrue(c.cloud_primary)
        self.assertEqual(c.cloud_model, "gemma4:31b-cloud")

    async def test_cloud_routing_uses_cloud_model_and_projection(self):
        c = Coordinator(self.ollama, {
            "model": "qwen3:8b", "cloud_primary": True, "cloud_model": "gemma4:31b-cloud",
        })
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor", "auth"], "reason": "id path, no auth"},
            prompt_tokens=10, completion_tokens=5,
        )
        ex = HttpExchange(
            url="https://shop.test/api/Users/35?token=SECRETVAL",
            method="GET",
            request_headers={"Authorization": "Bearer LEAKEDTOKENVALUE",
                             "Cookie": "session=LEAKEDSESSION"},
            response_status=200,
            response_body="PROPRIETARY_BODY_CONTENT",
        )
        dispatch, reason = await c.choose_agents_cloud(ex, self.available)
        self.assertEqual(dispatch, ["idor", "auth"])

        # The cloud model -- not the local one -- must have been used.
        _, kwargs = self.ollama.chat_json_metered.call_args
        self.assertEqual(kwargs["model"], "gemma4:31b-cloud")

        # Anonymization boundary: no secret value may appear in the prompt.
        sent = kwargs["system_prompt"] + kwargs["user_prompt"]
        for secret in ("SECRETVAL", "LEAKEDTOKENVALUE", "LEAKEDSESSION",
                       "PROPRIETARY_BODY_CONTENT", "35"):
            self.assertNotIn(secret, sent)
        # ...but the routing signal (path shape, resource-id flag) survives.
        self.assertIn("/api/Users/{id}", sent)

    async def test_cloud_routing_fails_open_on_error(self):
        c = Coordinator(self.ollama, {
            "model": "qwen3:8b", "cloud_primary": True, "cloud_model": "gemma4:31b-cloud",
        })
        self.ollama.chat_json_metered.side_effect = RuntimeError("cloud unreachable")
        ex = HttpExchange(url="https://shop.test/x", method="GET", response_status=200)
        dispatch, reason = await c.choose_agents_cloud(ex, self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)


class RespinSuggestionTests(unittest.IsolatedAsyncioTestCase):
    """suggest_followup_agents (adaptive re-spin): excludes already-tried
    agents, returns token counts for the ledger, and -- unlike primary
    routing -- does NOT fail open to all agents (a clean 'nothing further'
    is the safe answer)."""

    def setUp(self):
        self.ollama = AsyncMock()
        self.coordinator = Coordinator(self.ollama, {
            "model": "qwen3:8b", "cloud_primary": True, "cloud_model": "gemma4:31b-cloud",
        })
        self.available = ["sqli", "xss", "idor", "auth", "business_logic"]

    async def test_excludes_already_tried_and_returns_tokens(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["business_logic", "sqli"], "reason": "price field shape"},
            prompt_tokens=42, completion_tokens=7,
        )
        ex = HttpExchange(url="https://shop.test/api/checkout", method="POST", response_status=200)
        new_agents, reason, p, c = await self.coordinator.suggest_followup_agents(
            ex, self.available, already_tried=["sqli", "xss"]
        )
        # sqli was already tried -> excluded; business_logic survives.
        self.assertEqual(new_agents, ["business_logic"])
        self.assertEqual((p, c), (42, 7))

    async def test_empty_suggestion_does_not_fail_open(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": [], "reason": "nothing further"},
            prompt_tokens=30, completion_tokens=3,
        )
        ex = HttpExchange(url="https://shop.test/about", method="GET", response_status=200)
        new_agents, reason, p, c = await self.coordinator.suggest_followup_agents(
            ex, self.available, already_tried=["misconfig"]
        )
        self.assertEqual(new_agents, [])  # NOT self.available

    async def test_error_returns_no_agents_and_zero_tokens(self):
        self.ollama.chat_json_metered.side_effect = RuntimeError("cloud down")
        ex = HttpExchange(url="https://shop.test/x", method="GET", response_status=200)
        new_agents, reason, p, c = await self.coordinator.suggest_followup_agents(
            ex, self.available, already_tried=[]
        )
        self.assertEqual(new_agents, [])
        self.assertEqual((p, c), (0, 0))
        self.assertIn("error", reason)


class FailOpenTelemetryTests(unittest.IsolatedAsyncioTestCase):
    """Phase 1.4: the coordinator fail-open must be OBSERVABLE, not just safe.
    A routing failure that falls back to all agents has to increment the
    process-wide telemetry counters -- otherwise the historically-silent
    "quietly firing all 36 agents on every exchange" state is invisible again."""

    def setUp(self):
        self.ollama = AsyncMock()
        self.coordinator = Coordinator(self.ollama, {
            "model": "qwen3:8b", "cloud_primary": True, "cloud_model": "gemma4:31b-cloud"})
        self.available = ["sqli", "xss", "idor"]
        coordinator.reset_fail_open_stats()

    def tearDown(self):
        coordinator.reset_fail_open_stats()  # counters are process-wide -- don't leak

    async def test_error_fail_open_is_recorded(self):
        self.ollama.chat_json_metered.side_effect = RuntimeError("cloud down")
        ex = HttpExchange(url="https://shop.test/x", method="GET", response_status=200)
        dispatch, _ = await self.coordinator.choose_agents_cloud(ex, self.available)
        self.assertEqual(dispatch, self.available)  # failed open
        stats = coordinator.fail_open_stats()
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["by_reason"].get("cloud:error:RuntimeError"), 1)

    async def test_empty_dispatch_fail_open_is_recorded(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": [], "reason": "nothing"}, prompt_tokens=1, completion_tokens=1)
        ex = HttpExchange(url="https://shop.test/x", method="GET", response_status=200)
        dispatch, _ = await self.coordinator.choose_agents_cloud(ex, self.available)
        self.assertEqual(dispatch, self.available)
        self.assertEqual(coordinator.fail_open_stats()["by_reason"].get("cloud:no-valid-targets"), 1)

    async def test_successful_routing_records_no_fail_open(self):
        # Negative control: a clean route must NOT touch the fail-open counters.
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["sqli"], "reason": "sqli shape"}, prompt_tokens=1, completion_tokens=1)
        ex = HttpExchange(url="https://shop.test/x", method="GET", response_status=200)
        dispatch, _ = await self.coordinator.choose_agents_cloud(ex, self.available)
        self.assertEqual(dispatch, ["sqli"])
        self.assertEqual(coordinator.fail_open_stats()["count"], 0)


class FallbackFlagTests(unittest.IsolatedAsyncioTestCase):
    """P0.9: a fail-open route must be surfaced as a structured flag (not just
    process-wide telemetry) and logged loudly, not silently. is_fallback_reason
    is the pure predicate orchestrator_detect.py stamps AnalysisResponse.
    coordinator_fallback with; tested directly here plus end-to-end via a
    real (mocked-LLM) choose_agents call, per the local and cloud paths."""

    def setUp(self):
        self.ollama = AsyncMock()
        self.coordinator = Coordinator(self.ollama, {"model": "qwen3:8b"})
        self.available = ["sqli", "xss", "idor"]
        coordinator.reset_fail_open_stats()

    def tearDown(self):
        coordinator.reset_fail_open_stats()

    def test_is_fallback_reason_true_for_local_fallback(self):
        self.assertTrue(coordinator.is_fallback_reason(
            "fallback (all): coordinator error (boom)"))

    def test_is_fallback_reason_true_when_nested_in_cloud_primary_reason(self):
        self.assertTrue(coordinator.is_fallback_reason(
            "cloud-coordinator (fallback (curated): cloud coordinator error (boom))"))

    def test_is_fallback_reason_false_for_normal_reason(self):
        # Negative control: a real routing decision must not read as a fallback.
        self.assertFalse(coordinator.is_fallback_reason("numeric id + no auth header"))
        self.assertFalse(coordinator.is_fallback_reason(""))

    async def test_llm_error_sets_flag_true_and_logs_warning(self):
        self.ollama.chat_json_metered.side_effect = RuntimeError("boom")
        with self.assertLogs("harness.coordinator", level="WARNING") as cm:
            dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertTrue(coordinator.is_fallback_reason(reason))
        self.assertTrue(any("FAIL-OPEN" in line for line in cm.output))

    async def test_normal_routing_sets_flag_false(self):
        # Negative control: a healthy route must not read as a fallback.
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor"], "reason": "numeric id + no auth header"},
            prompt_tokens=5, completion_tokens=2,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, ["idor"])
        self.assertFalse(coordinator.is_fallback_reason(reason))


if __name__ == "__main__":
    unittest.main()
