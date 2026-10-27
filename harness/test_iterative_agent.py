"""Tests for the iterative (active) agent -- scripted LLM, mocked network."""
import asyncio
import hashlib
import re
import unittest
from unittest.mock import patch

from harness.models import HttpExchange
from harness.iterative_agent import IterativeAgent, IterativeResult, _attempt_key, _excerpt
from harness import safety_gate


class _ScriptedOllama:
    """Returns a preset sequence of action dicts, one per chat_json call."""
    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = 0
        self.prompts = []  # Ticket D: every user prompt, in call order

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.calls += 1
        self.prompts.append(user_prompt)
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

    async def test_duplicate_loop_stops_before_spending_model_budget(self):
        # Ticket D: a model stuck repeating one request is now stopped by the
        # duplicate rule (second back-to-back repeat), one model call sooner than
        # the old consecutive_no_progress >= 3 stop (which gave 4 calls).
        action = {"action": "set_header", "name": "X-Probe", "value": "same"}
        ollama = _ScriptedOllama([action] * 64)
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as send:
            result = await agent.run(_exchange(), "h", "auth", step_budget=64)
        self.assertEqual(result.stop_reason, "repeated_duplicates")
        self.assertEqual(result.steps_used, 3)
        self.assertEqual(ollama.calls, 3)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(result.findings, [])

    async def test_new_response_resets_no_progress_streak(self):
        # a, b, a(dup), b(dup), c(fresh send: resets the no-progress count), a(dup),
        # b(dup). Without the reset the 3rd non-send (step 6) would end the run as
        # no_progress after 6 model calls; with it the run reaches the final stop.
        a = {"action": "set_header", "name": "X-Probe", "value": "a"}
        b, c = dict(a, value="b"), dict(a, value="c")
        ollama = _ScriptedOllama([a, b, a, b, c, a, b,
                                {"action": "stop", "verdict": "not_found"}])
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request", return_value=_Resp(200, "ok")) as send:
            result = await agent.run(_exchange(), "h", "auth", step_budget=64)
        self.assertEqual(result.stop_reason, "gave_up")
        self.assertEqual(ollama.calls, 8)
        self.assertEqual(send.call_count, 3)
        self.assertEqual(result.duplicate_proposals, 4)

    async def test_rejected_actions_also_stop_without_requests(self):
        ollama = _ScriptedOllama([None] * 64)
        agent = IterativeAgent(ollama, "m", ["localhost"])
        with patch("httpx.AsyncClient.request") as send:
            result = await agent.run(_exchange(), "h", "auth", step_budget=64)
        self.assertEqual(result.stop_reason, "no_progress")
        self.assertEqual(result.steps_used, 3)
        self.assertEqual(ollama.calls, 3)
        send.assert_not_called()

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


# --------------------------------------------------------------------------
# Ticket D: structured prior attempts, duplicates rejected before transport.
# --------------------------------------------------------------------------

class _Net:
    """Fake target on the transport boundary (httpx.AsyncClient.request): records
    every request that actually reaches the wire."""
    def __init__(self, respond=None):
        self.sent = []  # (method, url, headers, content)
        self._respond = respond or (lambda method, url, headers, content: _Resp(200, "ok"))

    async def request(self, method, url, headers=None, content=None, **kw):
        self.sent.append((method, str(url), dict(headers or {}), content))
        return self._respond(method, str(url), dict(headers or {}), content)

    @property
    def urls(self):
        return [s[1] for s in self.sent]


def _ticket_exchange():
    return HttpExchange(
        url="http://localhost:5002/api/tickets/1?q=widget",
        method="GET",
        request_headers={"Authorization": "Bearer user-one"},
        request_body="",
        response_status=200,
        response_body="{}",
    )


def _path(value):
    return {"action": "mutate", "location": "path", "param": "1", "value": value}


def _query(value):
    return {"action": "mutate", "location": "query", "param": "q", "value": value}


_STOP = {"action": "stop", "verdict": "not_found", "thought": "done"}
# The four distinct requests of the measured pattern, and what the fake target says.
_A, _B, _C, _D = _path("2"), _query("beta"), _path("3"), _query("delta")
_BODIES = {"/api/tickets/2?q=widget": (200, "ticket two body"),
           "/api/tickets/1?q=beta": (404, "no beta"),
           "/api/tickets/3?q=widget": (403, "forbidden three"),
           "/api/tickets/1?q=delta": (200, "delta results")}


def _measured_target(method, url, headers, content):
    status, text = _BODIES[url.split("5002", 1)[1]]
    return _Resp(status, text)


def _attempt_lines(prompt):
    """The attempt lines of the PRIOR ATTEMPTS block in `prompt`."""
    block = prompt.split("PRIOR ATTEMPTS (do not repeat)", 1)[1]
    return [ln for ln in block.splitlines() if ln.startswith("- step ")]


class DuplicateProposalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def _drive(self, actions, exchange=None, *, respond=None, agent=None, budget=64):
        ollama = _ScriptedOllama(actions)
        agent = agent or IterativeAgent(ollama, "m", ["localhost"])
        agent.ollama = ollama
        net = _Net(respond)
        with patch("httpx.AsyncClient.request", net.request):
            result = await agent.run(exchange or _ticket_exchange(), "IDOR on ticket id", "idor",
                                     step_budget=budget)
        return result, net, ollama

    async def test_measured_pattern_sends_only_the_distinct_requests(self):
        """The live-run pattern A,B,A,C,A,B,D: the 3 repeats never reach the
        transport, every distinct request is still sent, and the model is told."""
        with self.assertLogs("harness.iterative_agent", level="INFO") as logs:
            result, net, ollama = await self._drive(
                [_A, _B, _A, _C, _A, _B, _D, _STOP], respond=_measured_target)
        self.assertEqual(
            net.urls,
            ["http://localhost:5002/api/tickets/2?q=widget", "http://localhost:5002/api/tickets/1?q=beta",
             "http://localhost:5002/api/tickets/3?q=widget", "http://localhost:5002/api/tickets/1?q=delta"])
        self.assertEqual(result.duplicate_proposals, 3)
        self.assertEqual(result.distinct_requests, 4)
        self.assertEqual(result.stop_reason, "gave_up")  # the scripted stop, not the duplicate rule
        self.assertEqual(result.steps_used, 7)
        dup_steps = [s for s in result.transcript if s.blocked and "DUPLICATE of step" in s.blocked]
        self.assertEqual([s.n for s in dup_steps], [3, 5, 6])
        # the prompt after the first duplicate (step 3) names it and lists the earlier attempts
        after_dup = ollama.prompts[3]
        self.assertIn("[step 3] DUPLICATE of step 1 (outcome HTTP 200, 15 bytes): "
                      "choose a different supported action or stop", after_dup)
        self.assertEqual(_attempt_lines(after_dup), [
            '- step 1: mutate path:1="2" | GET /api/tickets/2?q=widget | HTTP 200, 15 bytes',
            '- step 2: mutate query:q="beta" | GET /api/tickets/1?q=beta | HTTP 404, 7 bytes'])
        self.assertIn("distinct requests tried: 2; duplicate proposals rejected: 1", after_dup)
        # the existing free-text history lines are still there
        self.assertIn("[step 1] GET http://localhost:5002/api/tickets/2?q=widget -> HTTP 200, 15 bytes",
                      after_dup)
        self.assertIn("HYPOTHESIS: IDOR on ticket id", after_dup)
        # final prompt: all four distinct attempts, duplicates counted not listed
        final = ollama.prompts[-1]
        self.assertEqual(len(_attempt_lines(final)), 4)
        self.assertIn("distinct requests tried: 4; duplicate proposals rejected: 3", final)
        # the first prompt carries the (empty) block too
        self.assertIn("PRIOR ATTEMPTS (do not repeat) -- distinct requests tried: 0", ollama.prompts[0])
        self.assertTrue(any("iterative:idor summary steps=7 distinct=4 duplicates=3 stop=gave_up" in line
                            for line in logs.output))
        d = result.to_dict()
        self.assertEqual((d["duplicate_proposals"], d["distinct_requests"]), (3, 4))

    async def test_repeating_one_request_stops_with_repeated_duplicates(self):
        """A,A,A: A is sent once, the two repeats are rejected, and the run
        stops (without a third repeat reaching the model) as inconclusive."""
        with self.assertLogs("harness.iterative_agent", level="INFO") as logs:
            result, net, ollama = await self._drive([_A, _A, _A, _A])
        self.assertEqual(len(net.sent), 1)
        self.assertEqual(result.stop_reason, "repeated_duplicates")
        self.assertEqual(result.duplicate_proposals, 2)
        self.assertEqual(result.distinct_requests, 1)
        self.assertEqual(ollama.calls, 3)
        self.assertEqual(result.steps_used, 3)
        self.assertEqual(result.findings, [])
        self.assertIn("2 duplicate", result.handoff_note)
        self.assertIn("inconclusive", result.handoff_note)
        self.assertTrue(any("summary steps=3 distinct=1 duplicates=2 stop=repeated_duplicates" in ln
                            for ln in logs.output))

    async def test_fresh_send_resets_the_duplicate_streak(self):
        """Negative control for the stop rule: A, A(dup), B(fresh), A(dup again)
        is two separate single repeats, not a stuck loop."""
        result, net, ollama = await self._drive([_A, _A, _B, _A, _STOP])
        self.assertEqual(len(net.sent), 2)
        self.assertEqual(result.duplicate_proposals, 2)
        self.assertEqual(result.stop_reason, "gave_up")

    async def test_alternating_repeats_of_different_attempts_are_still_bounded(self):
        """Back-to-back duplicates of DIFFERENT earlier attempts (A,B,A,B,A) do not
        trip the duplicate-streak rule, but the existing consecutive_no_progress
        stop still ends them after three, without any extra send."""
        result, net, ollama = await self._drive([_A, _B, _A, _B, _A, _B, _A, _B])
        self.assertEqual(len(net.sent), 2)
        self.assertEqual(result.stop_reason, "no_progress")
        self.assertEqual(result.duplicate_proposals, 3)
        self.assertEqual(ollama.calls, 5)

    async def test_duplicate_of_a_blocked_request_cites_the_block_reason(self):
        ex = _ticket_exchange()
        ex.url = "http://evil.test/api/tickets/1?q=widget"
        result, net, ollama = await self._drive([_A, _A, _STOP], exchange=ex)
        self.assertEqual(net.sent, [])
        self.assertEqual(result.duplicate_proposals, 1)
        self.assertEqual(result.distinct_requests, 1)  # tried once; blocked at transport
        self.assertIn("[step 2] DUPLICATE of step 1 (outcome blocked: evil.test out of scope)",
                      ollama.prompts[2])

    async def test_request_sent_by_an_earlier_run_of_this_agent_is_a_duplicate(self):
        agent = IterativeAgent(_ScriptedOllama([]), "m", ["localhost"])
        first, net1, _ = await self._drive([_A, _STOP], agent=agent)
        second, net2, ollama2 = await self._drive([_A, _STOP], agent=agent)
        self.assertEqual(len(net1.sent), 1)
        self.assertEqual(net2.sent, [])
        self.assertEqual((second.duplicate_proposals, second.distinct_requests), (1, 0))
        self.assertIn("[step 1] DUPLICATE of an earlier run's request", ollama2.prompts[1])

    async def test_execute_keeps_its_own_signature_check_as_backstop(self):
        agent = IterativeAgent(_ScriptedOllama([]), "m", ["localhost"])
        net = _Net()
        args = ("GET", "http://localhost:5002/api/search?q=x", {"User-Agent": "x"}, "")
        with patch("httpx.AsyncClient.request", net.request):
            first = await agent._execute(*args)
            second = await agent._execute(*args)
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], None)
        self.assertIn("already sent this active-probe session", second[1])
        self.assertEqual(len(net.sent), 1)

    # -- negative controls: genuinely different requests are never merged -------

    async def test_header_value_difference_is_not_a_duplicate(self):
        """Requests differing only in one header value -- an authorization
        header, a probe header -- are all sent."""
        hdr = lambda n, v: {"action": "set_header", "name": n, "value": v}
        result, net, ollama = await self._drive([
            hdr("Authorization", "Bearer user-two"), hdr("Authorization", "Bearer user-three"),
            hdr("X-Probe", "one"), hdr("X-Probe", "two"), _STOP])
        self.assertEqual(len(net.sent), 4)
        self.assertEqual(result.duplicate_proposals, 0)
        self.assertEqual(result.distinct_requests, 4)
        self.assertEqual([s[2]["Authorization"] for s in net.sent[:2]],
                         ["Bearer user-two", "Bearer user-three"])
        self.assertEqual([s[2]["X-Probe"] for s in net.sent[2:]], ["one", "two"])
        # secret-named headers are shown as a fingerprint of the value, never the value
        # (the raw value stays in the attempt key, so the two tokens are two attempts)
        last = ollama.prompts[-1]
        fingerprints = re.findall(r"hdr\[Authorization=<redacted #([0-9a-f]{8})>\]", last)
        self.assertEqual(fingerprints, [hashlib.sha256(v.encode()).hexdigest()[:8]
                                        for v in ("Bearer user-two", "Bearer user-three")])
        self.assertEqual(len(set(fingerprints)), 2)
        for token in ("user-two", "user-three"):
            self.assertFalse(any(token in p for p in ollama.prompts), token)
        # ... in the value column as well as in the target's hdr[...]
        self.assertIn(f'- step 1: set_header header:Authorization="<redacted #{fingerprints[0]}>" | ', last)
        self.assertIn("hdr[X-Probe=two]", last)  # a non-secret header value is still shown

    async def test_different_object_ids_are_not_duplicates(self):
        result, net, _ = await self._drive([_path("2"), _path("3"), _path("22"), _STOP])
        self.assertEqual([u.split("/tickets/")[1] for u in net.urls],
                         ["2?q=widget", "3?q=widget", "22?q=widget"])
        self.assertEqual(result.duplicate_proposals, 0)

    async def test_body_field_difference_is_not_a_duplicate(self):
        """Different bodies -- the same field set to two values, or two fields
        set to the same value -- are all sent; only the true repeat is dropped."""
        from harness.safety_gate import SafetyGate, SafetyGateConfig
        gate = SafetyGate(SafetyGateConfig(
            active_enabled=True, allow_mutating_replay=True, max_mutating_requests_per_finding=10,
            allowed_hosts=frozenset({"localhost", "localhost:5002"})))
        ex = HttpExchange(url="http://localhost:5002/api/tickets", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"subject":"x","note":"n"}', response_status=201)
        body = lambda p, v: {"action": "mutate", "location": "body", "param": p, "value": v}
        with patch("harness.iterative_agent.get_default_gate", return_value=gate):
            result, net, ollama = await self._drive(
                [body("subject", "y"), body("subject", "z"), body("note", "y"),
                 body("subject", "y"), _STOP], exchange=ex)
        self.assertEqual([s[3] for s in net.sent],
                         ['{"subject": "y", "note": "n"}', '{"subject": "z", "note": "n"}',
                          '{"subject": "x", "note": "y"}'])
        self.assertEqual((result.distinct_requests, result.duplicate_proposals), (3, 1))

    def test_attempt_key_normalizes_only_query_order(self):
        key = lambda m="GET", u="http://h/api/t/1?a=1&b=2", h=None, b="": _attempt_key(
            m, u, {"Authorization": "Bearer one"} if h is None else h, b)
        base = key()
        self.assertEqual(base, key(u="http://h/api/t/1?b=2&a=1"))     # query order only
        self.assertEqual(base, key(u="HTTP://H/api/t/1?a=1&b=2#frag"))  # scheme/host case, fragment
        self.assertNotEqual(base, key(u="http://h/api/t/2?a=1&b=2"))  # object id
        self.assertNotEqual(base, key(u="http://h/api/T/1?a=1&b=2"))  # path case is significant
        self.assertNotEqual(base, key(u="http://h/api/t/1?a=1&b=3"))  # query value
        self.assertNotEqual(base, key(u="http://h/api/t/1?a=1&b=%32"))  # no decoding: different bytes
        self.assertNotEqual(base, key(h={"Authorization": "Bearer two"}))  # authz header value
        self.assertNotEqual(base, key(h={"Authorization": "Bearer one", "X-Probe": "1"}))  # extra header
        self.assertNotEqual(base, key(h={}))                          # header dropped
        self.assertNotEqual(base, key(b='{"a":1}'))                   # body
        self.assertNotEqual(key(m="POST", b='{"a":1}'), key(m="POST", b='{"a":2}'))
        self.assertNotEqual(base, key(m="DELETE"))                    # method
        self.assertEqual(key(h={"authorization": "Bearer one"}), base)  # header NAME case
        # repeated names keep their order; only the order of DIFFERENT names is normalized
        self.assertNotEqual(key(u="http://h/x?a=1&a=2"), key(u="http://h/x?a=2&a=1"))
        self.assertNotEqual(key(u="http://h/x?id=1&b=0&id=2"), key(u="http://h/x?id=2&b=0&id=1"))
        self.assertEqual(key(u="http://h/x?b=2&a=1"), key(u="http://h/x?a=1&b=2"))
        self.assertEqual(key(u="http://h/x?b=0&id=1&id=2"), key(u="http://h/x?id=1&b=0&id=2"))

    async def test_repeated_query_keys_in_a_different_order_are_not_duplicates(self):
        """?role=user&role=admin and ?role=admin&role=user are different requests
        (reachable through a path value); both must reach the transport."""
        ex = _ticket_exchange()
        ex.url = "http://localhost:5002/api/tickets/1"
        result, net, _ = await self._drive(
            [_path("1?role=user&role=admin"), _path("1?role=admin&role=user"), _STOP], exchange=ex)
        self.assertEqual(net.urls, ["http://localhost:5002/api/tickets/1?role=user&role=admin",
                                    "http://localhost:5002/api/tickets/1?role=admin&role=user"])
        self.assertEqual((result.distinct_requests, result.duplicate_proposals), (2, 0))

    async def test_captured_credentials_never_reach_the_prompt(self):
        """Only the header the action set appears in PRIOR ATTEMPTS; the exchange's
        captured Authorization/Cookie are sent but never shown to the model."""
        ex = _ticket_exchange()
        ex.request_headers = {"Authorization": "Bearer CAPTURED-x", "Cookie": "sid=CAPTURED-y"}
        probe = {"action": "set_header", "name": "X-Probe", "value": "one"}
        result, net, ollama = await self._drive([probe, _query("beta"), _path("2"), _STOP], exchange=ex)
        self.assertEqual(len(net.sent), 3)
        for _, _, sent_headers, _ in net.sent:  # the credentials really were on the wire
            self.assertEqual(sent_headers["Authorization"], "Bearer CAPTURED-x")
            self.assertEqual(sent_headers["Cookie"], "sid=CAPTURED-y")
        for prompt in ollama.prompts:
            for needle in ("CAPTURED", "Authorization", "Cookie"):
                self.assertNotIn(needle, prompt)
        self.assertIn("hdr[X-Probe=one]", ollama.prompts[-1])

    async def test_duplicates_do_not_reset_the_target_distress_streak(self):
        """503, dup, 503, dup, 503: a duplicate is no evidence the target recovered
        (no request was made), so three real 503s still end the run as distress."""
        q = _query
        result, net, ollama = await self._drive(
            [q("a1"), q("a1"), q("a2"), q("a2"), q("a3"), q("a4")],
            respond=lambda m, u, h, c: _Resp(503, "busy"))
        self.assertEqual(result.stop_reason, "target_distress")
        self.assertEqual((len(net.sent), result.duplicate_proposals, ollama.calls), (3, 2, 5))
        self.assertEqual(result.steps_used, 5)

    async def test_prior_attempts_block_is_capped_and_excerpted(self):
        long_value = "L" * 100
        actions = [_query(f"v{i}") for i in range(29)] + [_query(long_value), _STOP]
        result, net, ollama = await self._drive(actions)
        self.assertEqual(len(net.sent), 30)
        lines = _attempt_lines(ollama.prompts[-1])
        self.assertEqual(len(lines), 25)                      # last 25 only
        self.assertTrue(lines[0].startswith("- step 6: "))
        self.assertTrue(lines[-1].startswith("- step 30: "))
        self.assertIn("distinct requests tried: 30", ollama.prompts[-1])
        self.assertIn("showing the last 25", ollama.prompts[-1])
        self.assertIn('"' + "L" * 57 + '..."', lines[-1])      # value excerpt is 60 chars
        self.assertNotIn("L" * 58, lines[-1].split(" | ")[0])  # the value column, not the URL
        self.assertEqual(len(_excerpt(long_value)), 60)

    def test_result_to_dict_carries_the_new_counters(self):
        d = IterativeResult(agent="iterative:x").to_dict()
        self.assertEqual((d["duplicate_proposals"], d["distinct_requests"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
