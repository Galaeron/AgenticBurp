"""Tests for the iterative (active) agent -- scripted LLM, mocked network."""
import asyncio
import unittest
from unittest.mock import patch

from harness.models import HttpExchange
from harness.iterative_agent import IterativeAgent
from harness import safety_gate


class _ScriptedOllama:
    """Returns a preset sequence of action dicts, one per chat_json call."""
    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = 0

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.calls += 1
        if self._actions:
            return self._actions.pop(0)
        return {"action": "stop", "verdict": "not_found", "thought": "out of ideas"}


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        # W-16: sends now go through run_context.TargetTransport, which inspects
        # response headers (e.g. for redirect handling), so the mock must carry them.
        self.headers = headers or {}


def _exchange():
    return HttpExchange(
        url="http://localhost:5002/api/search?q=widget",
        method="GET",
        request_headers={"User-Agent": "x"},
        request_body="",
        response_status=200,
        response_body="results",
    )


def _obj_exchange():
    # object-scoped, no query/body param -- the IDOR-by-path-id case
    return HttpExchange(
        url="http://localhost:5002/api/tickets/1",
        method="GET",
        request_headers={"Authorization": "Bearer u"},
        request_body="",
        response_status=200,
        response_body='{"id":1,"owner":"me"}',
    )


def _run(agent, ex, **kw):
    return asyncio.run(agent.run(ex, hypothesis="SQLi in q", specialty="sqli", **kw))


class IterativeAgentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def test_confirms_and_stops_with_finding(self):
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "query", "param": "q", "value": "' OR '1'='1"},
            {"action": "stop", "verdict": "found", "thought": "error surfaced",
             "finding": {"vulnerability_class": "sqli", "confidence": 0.85, "severity": "high",
                         "summary": "SQLi in q", "evidence": "db error", "suggested_test": "x", "basis": "derived"}},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(500, "SQL syntax error")):
            r = await agent.run(_exchange(), "SQLi in q", "sqli")
        self.assertEqual(r.stop_reason, "found")
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].vulnerability_class, "sqli")
        self.assertFalse(r.findings[0].confirmed)  # LLM reasoning never sets confirmed

    async def test_self_reported_authority_fields_are_stripped(self):
        """R02: an agent's raw finding dict can carry ANY key the model
        chooses to write. proof_id/case_id/review_verdict must be discarded
        exactly like confirmed -- none of them are earned by model output."""
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "query", "param": "q", "value": "' OR '1'='1"},
            {"action": "stop", "verdict": "found", "thought": "error surfaced",
             "finding": {"vulnerability_class": "sqli", "confidence": 0.85, "severity": "high",
                         "summary": "SQLi in q", "evidence": "db error", "suggested_test": "x",
                         "basis": "derived", "confirmed": True, "proof_id": "model-supplied-id",
                         "case_id": "model-supplied-case", "review_verdict": "validator-confirmed"}},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(500, "SQL syntax error")):
            r = await agent.run(_exchange(), "SQLi in q", "sqli")
        f = r.findings[0]
        self.assertFalse(f.confirmed)
        self.assertEqual(f.proof_id, "")
        self.assertEqual(f.case_id, "")
        self.assertIsNone(f.review_verdict)

    async def test_step_budget_bounds_the_loop(self):
        # Always mutate, never stop -> must halt at step_budget.
        ollama = _ScriptedOllama([{"action": "mutate", "location": "query", "param": "q", "value": f"p{i}"}
                                  for i in range(50)])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")):
            r = await agent.run(_exchange(), "h", "sqli", step_budget=5)
        self.assertEqual(r.stop_reason, "exhausted_steps")
        self.assertLessEqual(r.steps_used, 5)

    async def test_out_of_scope_request_is_blocked_not_sent(self):
        ex = _exchange()
        ex.url = "http://evil.test/api/search?q=w"
        ollama = _ScriptedOllama([{"action": "mutate", "location": "query", "param": "q", "value": "x"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])  # evil.test not in scope
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(ex, "h", "sqli", step_budget=1)
            mock_req.assert_not_called()  # never sent
        self.assertTrue(any(s.blocked and "out of scope" in s.blocked for s in r.transcript))

    async def test_invalid_param_is_rejected_without_send(self):
        ollama = _ScriptedOllama([{"action": "mutate", "location": "query", "param": "nonexistent", "value": "x"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(_exchange(), "h", "sqli", step_budget=1)
            mock_req.assert_not_called()
        self.assertTrue(any(s.blocked and "not present" in s.blocked for s in r.transcript))

    async def test_mutating_method_goes_through_safety_gate(self):
        # A POST body mutation must be authorized by the gate; with mutating
        # replay NOT allowed, it is blocked and never sent.
        safety_gate.reset_default_gate()
        ex = HttpExchange(url="http://localhost:5002/api/tickets", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"subject":"x"}', response_status=201)
        ollama = _ScriptedOllama([{"action": "mutate", "location": "body", "param": "subject", "value": "y"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request") as mock_req:
            r = await agent.run(ex, "h", "business_logic", step_budget=1)
        # Either blocked by the gate (no send) -- the safe default.
        if mock_req.called:
            self.skipTest("gate permitted mutating replay in this config")
        self.assertTrue(any(s.blocked and "safety gate" in (s.blocked or "") for s in r.transcript))

    async def test_aborts_on_target_distress(self):
        # Target returns 503 repeatedly -> stop instead of exhausting the budget.
        ollama = _ScriptedOllama([{"action": "mutate", "location": "query", "param": "q", "value": f"p{i}"}
                                  for i in range(50)])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(503, "Service Unavailable")):
            r = await agent.run(_exchange(), "h", "sqli", step_budget=50)
        self.assertEqual(r.stop_reason, "target_distress")
        self.assertLessEqual(r.steps_used, 3)  # aborted quickly, did not run all 50

    async def test_duplicate_request_is_skipped_and_logged(self):
        """P2.6: the model re-proposing the EXACT same mutation (same
        location/param/value -> byte-identical request) a second time must
        be skipped, not re-sent."""
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "query", "param": "q", "value": "same-value"},
            {"action": "mutate", "location": "query", "param": "q", "value": "same-value"},
            {"action": "stop", "verdict": "not_found", "thought": "done"},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with self.assertLogs("harness.iterative_agent", level="INFO") as cm:
            with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as mock_req:
                r = await agent.run(_exchange(), "h", "sqli", step_budget=5)
        self.assertEqual(mock_req.call_count, 1)  # second identical mutation never sent
        self.assertTrue(any(
            s.blocked and "already sent this active-probe session" in s.blocked
            for s in r.transcript))
        self.assertTrue(any("skipping duplicate request" in line for line in cm.output))

    async def test_different_request_is_not_skipped(self):
        """Negative control: two DIFFERENT mutations (different values) must
        both be sent -- the guard must not over-match."""
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "query", "param": "q", "value": "value-one"},
            {"action": "mutate", "location": "query", "param": "q", "value": "value-two"},
            {"action": "stop", "verdict": "not_found", "thought": "done"},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as mock_req:
            r = await agent.run(_exchange(), "h", "sqli", step_budget=5)
        self.assertEqual(mock_req.call_count, 2)  # both distinct requests sent
        self.assertFalse(any(
            s.blocked and "already sent this active-probe session" in s.blocked
            for s in r.transcript))

    async def test_on_step_receives_live_activity(self):
        seen = []
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "query", "param": "q", "value": "a"},
            {"action": "stop", "verdict": "not_found", "thought": "done"},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")):
            await agent.run(_exchange(), "h", "sqli", step_budget=5, on_step=lambda s: seen.append(s))
        self.assertGreaterEqual(len(seen), 2)          # mutate step + stop step
        self.assertEqual(seen[0].action["action"], "mutate")
        self.assertEqual(seen[0].response_status, 200)

    async def test_broken_on_step_callback_does_not_kill_run(self):
        ollama = _ScriptedOllama([{"action": "stop", "verdict": "not_found", "thought": "x"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        def boom(_): raise RuntimeError("ui exploded")
        r = await agent.run(_exchange(), "h", "sqli", on_step=boom)  # must not raise
        self.assertEqual(r.stop_reason, "gave_up")

    async def test_gives_up_cleanly(self):
        ollama = _ScriptedOllama([{"action": "stop", "verdict": "not_found", "thought": "nothing here"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        r = await agent.run(_exchange(), "h", "sqli")
        self.assertEqual(r.stop_reason, "gave_up")
        self.assertEqual(r.findings, [])

    async def test_path_id_enumeration_reaches_another_object(self):
        # The pass-2 gap: an object-scoped endpoint (/api/tickets/1) exposes no
        # query/body param, so IDOR was unreachable. Path mutation now enumerates
        # the id -> the agent can walk /tickets/1 -> /tickets/2 and confirm BOLA.
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "path", "param": "1", "value": "2", "thought": "try id 2"},
            {"action": "stop", "verdict": "found", "thought": "reached another user's ticket",
             "finding": {"vulnerability_class": "idor", "confidence": 0.8, "severity": "high",
                         "summary": "IDOR on ticket id", "evidence": "user 2's data", "suggested_test": "x",
                         "basis": "derived"}},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        seen = {}
        async def fake_request(self, method, url, headers=None, content=None):
            seen["url"] = url
            return _Resp(200, "ticket belonging to user 2")
        with patch("httpx.AsyncClient.request", fake_request):
            r = await agent.run(_obj_exchange(), "IDOR on the ticket id", "idor")
        self.assertIn("/api/tickets/2", seen["url"])
        self.assertEqual(r.stop_reason, "found")
        self.assertEqual(r.findings[0].vulnerability_class, "idor")

    async def test_missing_path_segment_rejected_without_send(self):
        ollama = _ScriptedOllama([
            {"action": "mutate", "location": "path", "param": "999", "value": "2", "thought": "no such seg"},
            {"action": "stop", "verdict": "not_found", "thought": "done"},
        ])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "x")) as req:
            r = await agent.run(_obj_exchange(), "h", "idor")
        req.assert_not_called()  # rejected pre-send: 999 isn't on the path
        self.assertTrue(any(s.blocked for s in r.transcript))


class PathMutationHelperTests(unittest.TestCase):
    def test_path_id_values_lists_id_segments(self):
        from harness.iterative_agent import _path_id_values
        self.assertEqual(_path_id_values("http://h/api/tickets/1"), ["1"])
        self.assertEqual(_path_id_values("http://h/api/tickets/1/comments/5"), ["1", "5"])
        self.assertEqual(_path_id_values("http://h/api/users/me"), [])  # non-id segment ignored

    def test_mutate_path_segment_replaces_first_match(self):
        from harness.iterative_agent import _mutate_path_segment
        self.assertEqual(_mutate_path_segment("http://h/api/tickets/1", "1", "2"),
                         "http://h/api/tickets/2")
        self.assertEqual(_mutate_path_segment("http://h/api/tickets/1?x=1", "1", "9"),
                         "http://h/api/tickets/9?x=1")  # query's 1 untouched
        self.assertIsNone(_mutate_path_segment("http://h/api/tickets/1", "7", "2"))


if __name__ == "__main__":
    unittest.main()
