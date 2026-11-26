"""Caller-level tests: a refusal the harness makes is shown to the model as harness
policy, and a response the target sends is not.

Each test drives the production loop (IterativeAgent.run) with a scripted model that
records every prompt it receives, over the real TargetTransport with the network
patched at `httpx.AsyncClient.request` (no socket is opened). The framing is for the
model only: transcript, stop reason, counters and logs keep the raw reasons, which the
last tests prove by running the same script with the framing switched off.
"""
import json
import unittest
from unittest.mock import patch

import httpx

from harness import policy_refusal, safety_gate
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.run_context import standalone_context

MARK = policy_refusal.MARKER


class _Model:
    """Plays a preset list of actions and keeps each user prompt it was sent."""
    def __init__(self, actions):
        self._actions = list(actions)
        self.prompts: list[str] = []
        self.systems: list[str] = []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.prompts.append(user_prompt)
        self.systems.append(system_prompt)
        if self._actions:
            return self._actions.pop(0)
        return {"action": "stop", "verdict": "not_found", "thought": "done"}


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


_STOP = {"action": "stop", "verdict": "not_found", "thought": "done"}


def _q(value):
    return {"action": "mutate", "location": "query", "param": "q", "value": value}


def _get(url="http://localhost:5002/api/search?q=widget"):
    return HttpExchange(url=url, method="GET", request_headers={"User-Agent": "x"},
                        request_body="", response_status=200, response_body="results")


def _post():
    return HttpExchange(url="http://localhost:5002/api/tickets", method="POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body='{"subject":"x"}', response_status=201)


def _step_lines(prompt: str) -> list[str]:
    return [ln for ln in prompt.splitlines() if ln.startswith("[step ")]


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def drive(self, actions, exchange=None, *, respond=None, allowed=("localhost",),
                    run_context=None, step_budget=6, **agent_kw):
        model = _Model(actions)
        agent = IterativeAgent(model, "m", list(allowed), run_context=run_context, **agent_kw)
        side = respond or (lambda *a, **k: _Resp(200, "ok"))
        with patch("httpx.AsyncClient.request", side_effect=side) as net:
            result = await agent.run(exchange or _get(), "h", "sqli", step_budget=step_budget)
        return result, model, net


class HarnessRefusalsAreFramedTests(_Base):
    async def test_scope_block_reaches_the_model_as_policy(self):
        result, model, net = await self.drive(
            [_q("x"), _STOP], _get("http://evil.test/api/search?q=w"))
        net.assert_not_called()
        line = _step_lines(model.prompts[1])[0]
        self.assertIn(f"{MARK} [scope]", line)
        self.assertIn("not a response, error page, WAF block or rate limit from the target", line)
        self.assertIn("Do not retry it or a re-encoded or otherwise varied form of it", line)
        self.assertIn("Harness reason: blocked: evil.test out of scope", line)
        # the PRIOR ATTEMPTS line is marked too
        self.assertIn(f"| {MARK} [scope], not sent: blocked: evil.test out of scope", model.prompts[1])
        # raw everywhere else
        self.assertEqual(result.transcript[0].blocked, "blocked: evil.test out of scope")
        self.assertEqual(result.stop_reason, "gave_up")

    async def test_safety_gate_block_reaches_the_model_as_policy(self):
        result, model, net = await self.drive(
            [{"action": "mutate", "location": "body", "param": "subject", "value": "y"}, _STOP], _post())
        if net.called:
            self.skipTest("gate permitted mutating replay in this config")
        line = _step_lines(model.prompts[1])[0]
        self.assertIn(f"{MARK} [safety_gate]", line)
        self.assertIn("Harness reason: blocked by safety gate:", line)
        self.assertTrue(result.transcript[0].blocked.startswith("blocked by safety gate:"))
        self.assertNotIn(MARK, result.transcript[0].blocked)

    async def test_budget_refusal_reaches_the_model_as_policy(self):
        ctx = standalone_context(["localhost"], max_requests=0)
        result, model, net = await self.drive([_q("x"), _STOP], run_context=ctx)
        net.assert_not_called()
        line = _step_lines(model.prompts[1])[0]
        self.assertIn(f"{MARK} [budget]", line)
        self.assertIn("Harness reason: request failed: budget_exhausted", line)
        self.assertEqual(result.transcript[0].blocked, "request failed: budget_exhausted")

    async def test_duplicate_and_rejected_proposals_are_framed(self):
        result, model, _ = await self.drive(
            [_q("x"), _q("x"), {"action": "mutate", "location": "query", "param": "nope", "value": "1"},
             _STOP])
        dup = _step_lines(model.prompts[2])[-1]
        self.assertTrue(dup.startswith(f"[step 2] {MARK} [duplicate]"), dup)
        rej = _step_lines(model.prompts[3])[-1]
        self.assertTrue(rej.startswith(f"[step 3] action rejected: {MARK} [rejected_proposal]"), rej)
        self.assertIn("Harness reason: query param 'nope' not present on the captured request", rej)
        # transcript keeps the raw texts
        self.assertTrue(result.transcript[1].blocked.startswith("skipped: identical request"))
        self.assertEqual(result.transcript[2].blocked,
                         "query param 'nope' not present on the captured request")

    async def test_mechanism_refusal_is_framed_and_a_completed_one_is_not(self):
        outcomes = [{"status": "rejected", "readiness": "unknown mechanism or hypothesis"},
                    {"status": "completed", "kind": "k", "fresh_attempt_ids": ["req:1"]}]

        async def handoff(action):
            return outcomes.pop(0)
        sel = {"action": "experiment", "kind": "k", "hypothesis": "h"}
        _, model, _ = await self.drive([sel, sel, _STOP], experiment_handoff=handoff,
                                       experiment_catalog=lambda: {"ready": ["k"]})
        first = _step_lines(model.prompts[1])[-1]
        self.assertIn(f"mechanism result: {MARK} [mechanism]", first)
        second = _step_lines(model.prompts[2])[-1]
        self.assertTrue(second.startswith("[step 2] mechanism result: {"), second)
        self.assertNotIn(MARK, second)

    async def test_system_prompt_names_the_marker(self):
        _, model, _ = await self.drive([_STOP])
        self.assertIn(f'A line marked "{MARK}" comes from this testing harness', model.systems[0])


class TargetResponsesAreNotFramedTests(_Base):
    """Negative controls: what the target itself answered stays a target response."""

    async def test_target_403_429_and_waf_page_are_shown_as_http_status(self):
        replies = [_Resp(403, "Forbidden"), _Resp(429, "Too Many Requests", {"Retry-After": "1"}),
                   _Resp(406, "<html>Request blocked by web application firewall</html>")]
        result, model, net = await self.drive(
            [_q("a"), _q("b"), _q("c"), _STOP], respond=lambda *a, **k: replies.pop(0))
        self.assertEqual(net.call_count, 3)
        final = model.prompts[3]
        self.assertNotIn(MARK, "\n".join(_step_lines(final)))
        self.assertNotIn(MARK, final.split("PRIOR ATTEMPTS", 1)[1])
        for status in ("HTTP 403", "HTTP 429", "HTTP 406"):
            self.assertIn(status, final)
        self.assertEqual(result.diagnostics["policy_refusal_repeats"], 0)

    async def test_transport_failure_is_not_policy(self):
        def boom(*a, **k):
            raise httpx.ConnectError("connection reset")
        result, model, _ = await self.drive([_q("a"), _STOP], respond=boom)
        line = _step_lines(model.prompts[1])[0]
        self.assertIn("request failed:", line)
        self.assertNotIn(MARK, model.prompts[1])


class RawValuesUnchangedTests(_Base):
    """The framing changes only the prompt: running the same script with framing
    switched off gives the same stop reason, counters and transcript."""

    async def _both(self, actions, exchange=None, **kw):
        framed = await self.drive(list(actions), exchange, **kw)
        with patch.object(policy_refusal, "frame", lambda c, r: r), \
                patch.object(policy_refusal, "short", lambda c, r: r):
            plain = await self.drive(list(actions), exchange, **kw)
        return framed, plain

    def _assert_same_outside_prompt(self, framed, plain):
        (fr, fm, _), (pr, pm, _) = framed, plain
        self.assertEqual(fr.to_dict(), pr.to_dict())
        self.assertNotIn(MARK, json.dumps(fr.to_dict()))
        self.assertNotEqual(fm.prompts, pm.prompts)  # the framing did reach the model

    async def test_scope_block_run(self):
        framed, plain = await self._both([_q("x"), _q("y"), _q("x"), _q("z")],
                                         _get("http://evil.test/api/search?q=w"))
        self._assert_same_outside_prompt(framed, plain)
        self.assertEqual(framed[0].stop_reason, "no_progress")
        self.assertEqual(framed[0].diagnostics["blocked_attempts"], 2)
        self.assertEqual(framed[0].duplicate_proposals, 1)

    async def test_logs_keep_the_raw_reason(self):
        with self.assertLogs("harness.iterative_agent", level="INFO") as logs:
            framed, plain = await self._both(
                [_q("x"), _q("x"), {"action": "mutate", "location": "query", "param": "no", "value": "1"},
                 _STOP], _get("http://evil.test/api/search?q=w"))
        self._assert_same_outside_prompt(framed, plain)
        self.assertFalse(any(MARK in ln for ln in logs.output))

    async def test_budget_exhausted_stop_reason_is_unchanged(self):
        acts = [_q("x"), _q("y"), _q("z"), _q("w")]
        framed = await self.drive(list(acts), run_context=standalone_context(["localhost"], max_requests=0))
        with patch.object(policy_refusal, "frame", lambda c, r: r), \
                patch.object(policy_refusal, "short", lambda c, r: r):
            plain = await self.drive(list(acts), run_context=standalone_context(["localhost"], max_requests=0))
        self._assert_same_outside_prompt(framed, plain)
        self.assertIn(framed[0].stop_reason, ("no_progress", "target_distress"))


class PolicyRefusalRepeatCountTests(_Base):
    async def test_repeated_scope_blocks_are_counted(self):
        result, _, _ = await self.drive([_q("x"), _q("y"), _STOP], _get("http://evil.test/api/search?q=w"))
        self.assertEqual(result.diagnostics["policy_refusal_repeats"], 1)

    async def test_one_refusal_then_sends_counts_nothing(self):
        result, _, _ = await self.drive(
            [{"action": "mutate", "location": "query", "param": "nope", "value": "1"}, _q("a"), _q("b"),
             _STOP])
        self.assertEqual(result.diagnostics["policy_refusal_repeats"], 0)


if __name__ == "__main__":
    unittest.main()
