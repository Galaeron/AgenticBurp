"""ARC-6: the model may not set the headers the transport or the session manager own.

Caller-level: the production probe (IterativeAgent.run) is driven by a scripted
model; the wire is the fake at `httpx.AsyncClient.request`, so `net.sent` counts
the requests that actually left. A refused set_header is an action error with zero
sends; the transport drops the same names for every other caller unless one call
opts in (the request-smuggling probe), and that opt-in is not on the agent's path.
"""
import asyncio
import inspect
import unittest
from unittest.mock import patch

from harness import run_context as rc
from harness import safety_gate
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.run_context import RunContext, TargetTransport, standalone_context
from harness.validators.http_request_smuggling_validator import HttpRequestSmugglingValidator

_STOP = {"action": "stop", "verdict": "not_found", "thought": "done"}


class _Resp:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text
        self.headers = {}


class _Net:
    """The wire: every request that reached the HTTP client."""
    def __init__(self):
        self.sent = []

    async def request(self, method, url, headers=None, content=None, **kw):
        self.sent.append((method, str(url), dict(headers or {}), content))
        return _Resp()


class _Model:
    def __init__(self, actions):
        self._actions = list(actions)
        self.prompts = []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        self.prompts.append(user_prompt)
        return self._actions.pop(0) if self._actions else dict(_STOP)


def _exchange(headers=None):
    return HttpExchange(url="http://localhost:5002/api/search?q=widget", method="GET",
                        request_headers=dict(headers or {"User-Agent": "x"}),
                        request_body="", response_status=200, response_body="results")


def _hdr(name, value="v"):
    return {"action": "set_header", "name": name, "value": value}


async def _drive(actions, *, exchange=None, ctx=None):
    net, model = _Net(), _Model(actions)
    agent = IterativeAgent(model, "m", ["localhost"], run_context=ctx)
    with patch("httpx.AsyncClient.request", net.request):
        result = await agent.run(exchange or _exchange(), "header probe", "sqli",
                                 step_budget=len(actions) + 1)
    return result, net, model


_DENIED = ["Host", "  host ", "HOST", "Content-Length", "transfer-encoding", "Connection",
           "Keep-Alive", "TE", "Trailer", "Upgrade", "Proxy-Authorization",
           "Proxy-Connection", "Authorization", "cookie", "X-API-Key", "Host:",
           "X-A\r\nHost"]


class SetHeaderDenyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def test_each_denied_header_is_an_action_error_with_zero_sends(self):
        for name in _DENIED:
            with self.subTest(name=name):
                result, net, model = await _drive([_hdr(name), _STOP])
                self.assertEqual(net.sent, [], name)
                self.assertEqual(result.diagnostics["rejected_proposals"], 1)
                step = result.transcript[0]
                self.assertTrue(step.blocked and "set_header" in step.blocked, step.blocked)
                self.assertIn("action rejected: set_header", model.prompts[1])

    async def test_value_with_a_line_break_is_refused(self):
        result, net, _ = await _drive([_hdr("X-Probe", "a\r\nHost: evil"), _STOP])
        self.assertEqual(net.sent, [])
        self.assertIn("CR, LF or NUL", result.transcript[0].blocked)

    async def test_negative_control_removing_the_deny_entry_lets_the_send_happen(self):
        """With "host" taken out of the deny set the very same action is sent, so
        the zero-send result above is the deny entry's doing."""
        with patch.object(rc, "TRANSPORT_CONTROLLED_HEADERS",
                          rc.TRANSPORT_CONTROLLED_HEADERS - {"host"}):
            result, net, _ = await _drive([_hdr("Host", "localhost:5002"), _STOP])
        self.assertEqual(len(net.sent), 1)
        self.assertEqual(result.diagnostics["rejected_proposals"], 0)

    async def test_ordinary_and_request_binding_headers_still_go_out(self):
        result, net, _ = await _drive([_hdr("X-Probe", "1"), _hdr("X-CSRF-Token", "t"), _STOP])
        self.assertEqual(len(net.sent), 2)
        self.assertEqual(net.sent[0][2]["X-Probe"], "1")
        self.assertEqual(net.sent[1][2]["X-CSRF-Token"], "t")

    async def test_header_name_is_replaced_whatever_its_case(self):
        result, net, _ = await _drive([_hdr(" x-probe ", "new"), _STOP],
                                      exchange=_exchange({"X-Probe": "old"}))
        sent = net.sent[0][2]
        self.assertEqual([k for k in sent if k.lower() == "x-probe"], ["x-probe"])
        self.assertEqual(sent["x-probe"], "new")

    async def test_captured_transport_headers_are_not_replayed(self):
        captured = {"Host": "localhost:5002", "Connection": "keep-alive",
                    "Content-Length": "0", "Proxy-Authorization": "Basic cHJveHk=",
                    "X-Captured": "kept"}
        _, net, _ = await _drive([_hdr("X-Probe", "1"), _STOP], exchange=_exchange(captured))
        sent = {k.lower() for k in net.sent[0][2]}
        self.assertIn("x-captured", sent)
        self.assertFalse(sent & {"host", "connection", "content-length", "proxy-authorization"})

    async def test_request_ceiling_still_binds_and_a_refusal_spends_none_of_it(self):
        """b1's ceiling: a refused header costs no budget, the first real send
        takes the only slot, and the next is refused by the budget."""
        ctx = standalone_context(["localhost"], max_requests=1)
        result, net, _ = await _drive(
            [_hdr("Host", "evil"), _hdr("X-Probe", "1"), _hdr("X-Probe", "2"), _STOP], ctx=ctx)
        self.assertEqual(len(net.sent), 1)
        self.assertEqual(ctx.budget.used, 1)
        self.assertTrue(any(s.blocked and "budget_exhausted" in s.blocked
                            for s in result.transcript))


_RAW = {"Host": "evil.test", "Connection": "keep-alive", " Keep-Alive ": "5",
        "Transfer-Encoding": "chunked", "Content-Length": "6", "TE": "trailers",
        "Upgrade": "h2c", "Proxy-Connection": "x", "X-Keep": "1"}


class TransportHeaderFilterTests(unittest.IsolatedAsyncioTestCase):
    async def _send(self, **kw):
        ctx = standalone_context(["localhost"], max_requests=5)
        net = _Net()
        with patch("httpx.AsyncClient.request", net.request):
            outcome = await ctx.target_transport().send(
                "GET", "http://localhost:5002/x", capability="test", headers=dict(_RAW),
                max_redirects=0, **kw)
        await ctx.aclose()
        return outcome, net

    async def test_transport_drops_controlled_headers_by_default(self):
        outcome, net = await self._send()
        self.assertEqual(len(net.sent), 1)
        self.assertEqual(net.sent[0][2], {"X-Keep": "1"})

    async def test_negative_control_without_the_filter_the_headers_go_out(self):
        with patch.object(rc, "_drop_transport_controlled", lambda h, allow_framing: dict(h)):
            _, net = await self._send()
        self.assertIn("Host", net.sent[0][2])

    async def test_per_call_opt_in_keeps_framing_but_never_host_or_proxy(self):
        _, net = await self._send(allow_framing_headers=True)
        sent = {k.strip().lower() for k in net.sent[0][2]}
        self.assertEqual(sent, {"connection", "keep-alive", "transfer-encoding",
                                "content-length", "te", "upgrade", "x-keep"})

    async def test_proxy_credential_bound_as_a_session_header_is_still_dropped(self):
        """send_creds() binds a Proxy-Authorization header into a session; the
        filter runs after the session's headers are merged, so it never leaves."""
        ctx = standalone_context(["localhost"], max_requests=5)
        net = _Net()
        with patch("httpx.AsyncClient.request", net.request):
            await ctx.target_transport().send_creds(
                "GET", "http://localhost:5002/x", capability="test",
                headers={"Proxy-Authorization": "Basic eA==", "X-Keep": "1"})
        await ctx.aclose()
        self.assertEqual(len(net.sent), 1)
        self.assertEqual({k.lower() for k in net.sent[0][2]}, {"x-keep"})

    def test_opt_in_is_not_reachable_from_the_agent_path(self):
        """The agent sends only through send_creds(), which has no opt-in."""
        self.assertNotIn("allow_framing_headers",
                         inspect.signature(TargetTransport.send_creds).parameters)
        self.assertIn("allow_framing_headers",
                      inspect.signature(TargetTransport.execute).parameters)


class SmugglingProbeOptInTests(unittest.TestCase):
    def test_smuggling_probe_still_sends_its_framing_headers(self):
        ctx = RunContext.create(allowed_hosts=["localhost"], max_requests=2,
                                gate_config={"active_enabled": True,
                                             "allow_mutating_replay": True})
        validator = HttpRequestSmugglingValidator(run_context=ctx)
        net = _Net()

        async def scenario():
            with patch("httpx.AsyncClient.request", net.request):
                await validator._send_raw_request(
                    "POST", "http://localhost:5002/probe",
                    headers={"Content-Length": "6", "Transfer-Encoding": "chunked",
                             "Connection": "keep-alive", "Host": "evil.test"},
                    body="0\r\n\r\nG")
            await ctx.aclose()

        asyncio.run(scenario())
        sent = {k.lower(): v for k, v in net.sent[0][2].items()}
        self.assertEqual((sent["content-length"], sent["transfer-encoding"], sent["connection"]),
                         ("6", "chunked", "keep-alive"))
        self.assertNotIn("host", sent)


if __name__ == "__main__":
    unittest.main()
