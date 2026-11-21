"""Caller-level tests for the iterative agent's action language: edits that
accumulate across steps, JSON-typed body values, path-addressed JSON edits and
reset. Each drives IterativeAgent.run with a scripted model against a real
loopback HTTP app, so what is asserted is what reached the wire."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import safety_gate
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.run_context import standalone_context
from harness.safety_gate import SafetyGate, SafetyGateConfig

_STOP = {"action": "stop", "verdict": "not_found", "thought": "done"}
_CAPTURED_BODY = '{"qty": 1, "price": 10, "items": [{"id": 7, "qty": 1}]}'


class _ScriptedOllama:
    def __init__(self, actions):
        self._actions = list(actions)
        self.prompts = []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.prompts.append(user_prompt)
        return self._actions.pop(0) if self._actions else _STOP


class _App:
    """Loopback app: records (method, path, headers, body) of every request."""
    def __init__(self):
        self.seen = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                app.seen.append((self.command, self.path, dict(self.headers), body))
                out = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = _handle

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def bodies(self):
        return [json.loads(s[3]) for s in self.seen]


def _mutate(loc, param, value, **kw):
    return dict({"action": "mutate", "location": loc, "param": param, "value": value}, **kw)


class _LoopBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.app = _App()
        host = f"127.0.0.1:{self.app.server.server_port}"
        self.gate = SafetyGate(SafetyGateConfig(
            active_enabled=True, allow_mutating_replay=True, max_mutating_requests_per_finding=10,
            allowed_hosts=frozenset({"127.0.0.1", host})))

    def tearDown(self):
        self.app.close()

    def _post(self, body=_CAPTURED_BODY, ct="application/json"):
        return HttpExchange(url=self.app.base + "/api/basket", method="POST",
                            request_headers={"Content-Type": ct}, request_body=body,
                            response_status=200, response_body='{"ok": true}')

    def _get(self, path="/api/search?q=widget"):
        return HttpExchange(url=self.app.base + path, method="GET", request_headers={},
                            request_body="", response_status=200, response_body='{"ok": true}')

    async def _drive(self, actions, exchange):
        ollama = _ScriptedOllama(actions + [_STOP])
        # ARC-11: the gate is injected through the run context, not patched in.
        ctx = standalone_context(["127.0.0.1"], gate=self.gate)
        agent = IterativeAgent(ollama, "m", ["127.0.0.1"], run_context=ctx)
        try:
            result = await agent.run(exchange, "price tampering", "business_logic", step_budget=20)
        finally:
            await ctx.aclose()
        return result, ollama


class TypedActionLoopTests(_LoopBase):
    async def test_two_step_typed_edits_compose_with_types_preserved(self):
        result, _ = await self._drive(
            [_mutate("body", "qty", -5), _mutate("body", "price", 0)], self._post())
        self.assertEqual(len(self.app.seen), 2)
        first, second = self.app.bodies
        self.assertEqual(first["qty"], -5)
        self.assertIs(type(first["qty"]), int)          # a number, not "-5"
        self.assertEqual(first["price"], 10)
        self.assertEqual((second["qty"], second["price"]), (-5, 0))  # step 1's edit persisted
        self.assertIs(type(second["price"]), int)
        self.assertEqual(result.distinct_requests, 2)
        self.assertEqual(result.diagnostics["rejected_proposals"], 0)

    async def test_typed_values_of_every_json_kind_keep_their_type(self):
        await self._drive([_mutate("body", "qty", 2.5), _mutate("body", "price", None),
                           _mutate("body", "items", []), _mutate("json", "admin", True),
                           _mutate("json", "meta", {"role": "admin"})], self._post())
        last = self.app.bodies[-1]
        self.assertEqual(last, {"qty": 2.5, "price": None, "items": [], "admin": True,
                                "meta": {"role": "admin"}})

    async def test_json_path_sets_nested_fields_and_creates_missing_keys(self):
        await self._drive([_mutate("json", "items.0.qty", -1),
                           _mutate("json", "coupon.code", "FREE"),
                           _mutate("json", "items.1", {"id": 9, "qty": 3})], self._post())
        self.assertEqual(self.app.bodies[0]["items"], [{"id": 7, "qty": -1}])
        self.assertEqual(self.app.bodies[1]["coupon"], {"code": "FREE"})
        self.assertEqual(self.app.bodies[2]["items"], [{"id": 7, "qty": -1}, {"id": 9, "qty": 3}])

    async def test_json_path_into_a_non_container_is_rejected_and_the_run_continues(self):
        result, ollama = await self._drive(
            [_mutate("json", "qty.x", 1), _mutate("json", "items.5", 1),
             _mutate("body", "qty", 3), _mutate("json", "items.id", 1)], self._post())
        self.assertEqual(self.app.bodies, [{"qty": 3, "price": 10, "items": [{"id": 7, "qty": 1}]}])
        self.assertEqual(result.diagnostics["rejected_proposals"], 3)
        self.assertIn("action rejected: json path cannot index into a number at 'qty'", ollama.prompts[1])
        self.assertIn("json path index 5 out of range at 'items' (array length 1)", ollama.prompts[2])
        self.assertIn("json path segment 'id' must be a list index at 'items'", ollama.prompts[4])

    async def test_json_location_needs_a_json_body(self):
        result, ollama = await self._drive(
            [_mutate("json", "a", "1")],
            self._post(body="a=1&b=2", ct="application/x-www-form-urlencoded"))
        self.assertEqual(self.app.seen, [])
        self.assertIn("location 'json' requires a JSON request body", ollama.prompts[1])

    async def test_non_string_query_value_is_rejected_and_the_run_continues(self):
        result, ollama = await self._drive(
            [_mutate("query", "q", 5), _mutate("query", "q", "5")], self._get())
        self.assertEqual([s[1] for s in self.app.seen], ["/api/search?q=5"])  # only the string send
        self.assertIn("action rejected: location 'query' takes a string value, got number",
                      ollama.prompts[1])
        self.assertEqual(result.diagnostics["rejected_proposals"], 1)
        self.assertEqual(result.distinct_requests, 1)
        self.assertEqual(result.stop_reason, "gave_up")  # the scripted stop, not an error

    async def test_non_string_form_and_path_values_are_rejected(self):
        _, ollama = await self._drive(
            [_mutate("body", "a", 1)], self._post(body="a=1", ct="application/x-www-form-urlencoded"))
        self.assertIn("a form-encoded body takes a string value, got number", ollama.prompts[1])
        _, ollama = await self._drive([_mutate("path", "1", 2)], self._get("/api/tickets/1"))
        self.assertIn("location 'path' takes a string value, got number", ollama.prompts[1])
        self.assertEqual(self.app.seen, [])

    async def test_reset_returns_to_the_captured_request(self):
        result, ollama = await self._drive(
            [_mutate("body", "qty", -5), {"action": "set_header", "name": "X-Probe", "value": "1"},
             {"action": "reset"}, _mutate("body", "price", 0)], self._post())
        self.assertEqual(len(self.app.seen), 3)
        self.assertEqual(self.app.seen[1][2].get("X-Probe"), "1")
        last_headers, last = self.app.seen[2][2], self.app.bodies[2]
        self.assertEqual(last, {"qty": 1, "price": 0, "items": [{"id": 7, "qty": 1}]})
        self.assertNotIn("X-Probe", last_headers)
        self.assertIn("[step 3] reset", ollama.prompts[3])
        self.assertEqual([s.request_summary for s in result.transcript][2], "(reset)")

    async def test_reset_flag_applies_one_action_to_the_capture(self):
        await self._drive([_mutate("body", "qty", -5),
                           _mutate("body", "price", 0, reset=True)], self._post())
        self.assertEqual(self.app.bodies[1], {"qty": 1, "price": 0, "items": [{"id": 7, "qty": 1}]})

    async def test_reset_of_an_unchanged_request_is_a_rejected_no_op(self):
        result, ollama = await self._drive([{"action": "reset"}] * 4, self._post())
        self.assertEqual(self.app.seen, [])
        self.assertEqual(result.stop_reason, "no_progress")  # bounded like any non-send
        self.assertIn("reset: the request is already the captured request", ollama.prompts[1])


class StringOnlyControlTests(_LoopBase):
    """Negative controls: string-only sequences keep the old requests."""

    async def test_string_value_in_a_json_body_stays_a_string(self):
        await self._drive([_mutate("body", "qty", "-5")], self._post())
        self.assertEqual(self.app.bodies[0]["qty"], "-5")
        self.assertEqual(self.app.seen[0][3], '{"qty": "-5", "price": 10, "items": [{"id": 7, "qty": 1}]}')

    async def test_repeated_string_query_edits_send_the_same_requests_as_before(self):
        result, _ = await self._drive(
            [_mutate("query", "q", "a'"), _mutate("query", "q", "b"), _mutate("query", "q", "a'")],
            self._get())
        self.assertEqual([s[1] for s in self.app.seen], ["/api/search?q=a%27", "/api/search?q=b"])
        self.assertEqual(result.duplicate_proposals, 1)

    async def test_path_enumeration_by_the_captured_id_keeps_working(self):
        await self._drive([_mutate("path", "1", "2"), _mutate("path", "1", "3")],
                          self._get("/api/tickets/1"))
        self.assertEqual([s[1] for s in self.app.seen], ["/api/tickets/2", "/api/tickets/3"])

    async def test_path_swap_names_the_captured_segment_after_a_colliding_swap(self):
        """After /users/1/orders/2 -> /users/2/orders/2, a swap of "2" means the
        captured orders id (the prompt's contract), not the users segment that an
        earlier step happened to set to 2. A value only the current path holds
        is still swapped in place."""
        await self._drive([_mutate("path", "1", "2"), _mutate("path", "2", "9"),
                           _mutate("path", "9", "5")],
                          self._get("/api/users/1/orders/2"))
        self.assertEqual([s[1] for s in self.app.seen],
                         ["/api/users/2/orders/2", "/api/users/2/orders/9", "/api/users/2/orders/5"])


if __name__ == "__main__":
    unittest.main()
