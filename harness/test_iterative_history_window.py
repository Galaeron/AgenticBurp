"""TOK-3: the iterative probe's prompt stops growing once the history window is full.

Caller-level: IterativeAgent.run is driven for 100 steps by a scripted model over
a fake wire (`httpx.AsyncClient.request`). The prompt the model receives at each
step is measured with prompt_budget.estimate_tokens, the estimator the prompt
budget itself uses. With the default window the step-100 prompt is within 1.3x
the step-25 prompt; with an unbounded window (the old render-every-step
behaviour) it is not -- the negative control.
"""
import itertools
import unittest
from unittest.mock import patch

from harness import safety_gate
from harness.iterative_agent import (DEFAULT_HISTORY_WINDOW, IterativeAgent, _StepEntry,
                                     _SUMMARY_MAX_ROWS, _render_history)
from harness.models import HttpExchange
from harness.prompt_budget import estimate_tokens

_STEPS = 100


class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": "text/html"}


class _Wire:
    """Answers in a rotating pattern so outcomes vary step to step."""
    def __init__(self):
        self.sent = 0
        self._status = itertools.cycle([200, 404, 500, 403, 200])

    async def request(self, method, url, headers=None, content=None, **kw):
        self.sent += 1
        status = next(self._status)
        return _Resp(status, f"<html>page {self.sent} status {status} " + "lorem ipsum " * 20)


class _Model:
    def __init__(self, actions):
        self._actions = list(actions)
        self.sent_tokens = []          # estimate_tokens(system) + estimate_tokens(user)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.sent_tokens.append(estimate_tokens(system_prompt) + estimate_tokens(user_prompt))
        if self._actions:
            return self._actions.pop(0)
        return {"action": "stop", "verdict": "not_found", "thought": "done"}


def _actions(n):
    """n distinct requests: query payloads and header probes, never a duplicate."""
    out = []
    for i in range(n):
        if i % 3 == 2:
            out.append({"action": "set_header", "name": f"X-Probe-{i % 4}", "value": f"v{i}",
                        "thought": "header knob"})
        else:
            out.append({"action": "mutate", "location": "query", "param": "q",
                        "value": f"' OR {i}={i} -- probe {i}", "thought": "try payload"})
    return out


def _exchange():
    return HttpExchange(url="http://localhost:5002/api/search?q=widget", method="GET",
                        request_headers={"User-Agent": "x"}, request_body="",
                        response_status=200, response_body="results " * 40)


async def _drive(history_window=None):
    model, wire = _Model(_actions(_STEPS)), _Wire()
    agent = IterativeAgent(model, "m", ["localhost"], max_steps=_STEPS + 5,
                           history_window=history_window)
    with patch("httpx.AsyncClient.request", wire.request):
        result = await agent.run(_exchange(), "SQLi in q", "sqli", step_budget=_STEPS)
    return result, model, wire


class HistoryWindowTokenTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def test_step_100_prompt_is_within_1_3x_of_step_25(self):
        result, model, wire = await _drive()
        self.assertEqual(wire.sent, _STEPS)          # every step was a real send
        self.assertEqual(result.duplicate_proposals, 0)
        self.assertGreaterEqual(len(model.sent_tokens), _STEPS)
        at25, at100 = model.sent_tokens[24], model.sent_tokens[99]
        self.assertLessEqual(at100, 1.3 * at25, (at25, at100))

    async def test_negative_control_unbounded_window_breaks_the_ratio(self):
        """W = infinity is the old behaviour (every step's line, forever)."""
        _, model, wire = await _drive(history_window=10**9)
        self.assertEqual(wire.sent, _STEPS)
        at25, at100 = model.sent_tokens[24], model.sent_tokens[99]
        self.assertGreater(at100, 1.3 * at25, (at25, at100))


class RenderHistoryTests(unittest.TestCase):
    def _entries(self, n, outcome=lambda i: f"HTTP {200 + i % 3}"):
        return [_StepEntry(i, f"[step {i}] GET /x?q={i} -> {outcome(i)}",
                           ("mutate", "query:q", outcome(i)), f"v{i}",
                           detail=f"[step {i}] FULL VIEW {i}")
                for i in range(1, n + 1)]

    def test_window_lines_in_full_and_earlier_steps_as_deduplicated_rows(self):
        text = _render_history(["HYPOTHESIS: h"] + self._entries(20), window=8)
        self.assertTrue(text.startswith("HYPOTHESIS: h\nEARLIER STEPS 1-12"))
        for i in range(13, 19):
            self.assertIn(f"[step {i}] GET /x?q={i}", text)
        self.assertIn("[step 19] FULL VIEW 19", text)      # latest _DETAILED_STEPS in full
        self.assertIn("[step 20] FULL VIEW 20", text)
        self.assertNotIn("[step 12] GET", text)              # folded into the table
        # 12 earlier steps, three outcomes -> three rows, counted, last value kept
        self.assertIn("mutate | query:q | HTTP 200 | x4 (step 3-12) | \"v12\"", text)
        self.assertEqual(text.count("mutate | query:q |"), 3)

    def test_summary_rows_are_capped(self):
        text = _render_history(self._entries(60, outcome=lambda i: f"HTTP {i}"), window=8)
        rows = [ln for ln in text.splitlines() if ln.startswith("mutate | query:q |")]
        self.assertEqual(len(rows), _SUMMARY_MAX_ROWS)
        self.assertIn(f"(+{52 - _SUMMARY_MAX_ROWS} older rows covering", text)

    def test_default_window_and_clamp(self):
        self.assertEqual(IterativeAgent(None, "m", []).history_window, DEFAULT_HISTORY_WINDOW)
        self.assertEqual(IterativeAgent(None, "m", [], history_window=0).history_window, 1)
        short = _render_history(self._entries(3), window=8)
        self.assertNotIn("EARLIER STEPS", short)              # nothing has left the window


if __name__ == "__main__":
    unittest.main()
