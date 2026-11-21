"""ARC-11: no shared default gate on the probe paths; the escalation cap holds
under concurrency; an active_enabled toggle during a run is in its manifest.

Caller-level throughout:
  * `_auto_escalate` is driven N times concurrently (asyncio.gather) through the
    production ChainMixin code, with the credential probe and the role crawl
    faked so every escalation is in flight at once. The crawl count must never
    exceed engagement_max_escalations. Negative control: a reserve that only
    checks, with the count taken after the crawl's await (the pre-fix order),
    lets every one of them through.
  * `run_active_probe` (no owning run) is driven twice and the gate each probe
    received is inspected; the probe agent outside any run is driven over a fake
    wire and the process-wide gate's audit log must not move.
  * RunManifest start/finish around ValidatorRegistry.set_active_enabled.
"""
import asyncio
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import global_throttle, safety_gate
from harness.engagement import EngagementState
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.orchestrator_chain import ChainMixin
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_manifest import RunManifest

_HOST = "shop.test"


class _CrawlResult:
    endpoints = []

    def to_dict(self):
        return {"endpoints": [], "idor_findings": [], "auth_bypass_candidates": [],
                "idor_candidates": []}


class _EscalationHost(ChainMixin):
    """Just the orchestrator surface _auto_escalate reads."""
    def __init__(self, cap, *, verifies=True):
        self.allowed_hosts = [_HOST]
        self._escalation_counts = {}
        self.engagement_max_escalations = cap
        self.verifies = verifies
        self.verify_calls = 0

    async def _credential_grants_access(self, url, headers, *, run_context=None):
        self.verify_calls += 1
        await asyncio.sleep(0)          # yield: every escalation is in flight at once
        await asyncio.sleep(0)
        return self.verifies


def _cap(i):
    return {"type": "credential", "kind": "bearer",
            "headers": {"Authorization": f"Bearer learned-{i}"},
            "source_url": f"http://{_HOST}/login{i}", "reason": "r"}


class _Crawl:
    """Fake role crawl: counts the crawls and the most that ran at once."""
    def __init__(self, *, raises=None, block=None, after=None):
        self.calls, self.active, self.peak = 0, 0, 0
        self._raises, self._block, self._after = raises, block, after

    async def __call__(self, *a, **k):
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0)
            if self._block is not None:
                await self._block.wait()
            if self._raises is not None:
                raise self._raises
            if self._after is not None:
                self._after()
            return _CrawlResult()
        finally:
            self.active -= 1


async def _escalate_concurrently(host, n, crawl):
    st = EngagementState(host=_HOST)
    with patch("harness.role_crawl.crawl_roles", crawl):
        await asyncio.gather(*(host._auto_escalate(_HOST, f"http://{_HOST}/login{i}",
                                                   [_cap(i)], st) for i in range(n)))


class EscalationCapConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        global_throttle.configure(0)

    async def test_concurrent_escalations_never_exceed_the_cap(self):
        for n, cap in ((8, 3), (5, 1), (4, 4), (3, 6)):
            with self.subTest(n=n, cap=cap):
                host, crawl = _EscalationHost(cap), _Crawl()
                await _escalate_concurrently(host, n, crawl)
                self.assertEqual(crawl.calls, min(n, cap))
                self.assertEqual(host._escalation_counts[_HOST], min(n, cap))
                self.assertEqual(host.verify_calls, min(n, cap))   # refused before any probe

    async def test_negative_control_counting_after_the_await_lets_all_through(self):
        """The pre-fix order: check the cap, await the probe and the crawl, count
        afterwards. With the check alone at the reservation point every concurrent
        escalation passes it, so the test above would fail."""
        host = _EscalationHost(3)

        def count_after_crawl():
            host._escalation_counts[_HOST] = host._escalation_counts.get(_HOST, 0) + 1

        crawl = _Crawl(after=count_after_crawl)
        with patch.object(_EscalationHost, "_reserve_escalation",
                          lambda self, h: self._escalation_counts.get(h, 0)
                          < self.engagement_max_escalations), \
             patch.object(_EscalationHost, "_release_escalation", lambda self, h: None):
            await _escalate_concurrently(host, 8, crawl)
        self.assertEqual(crawl.calls, 8)
        self.assertGreater(host._escalation_counts[_HOST], host.engagement_max_escalations)


class EscalationSlotReleaseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        global_throttle.configure(0)

    async def test_a_landed_escalation_keeps_its_slot(self):
        host = _EscalationHost(2)
        await _escalate_concurrently(host, 1, _Crawl())
        self.assertEqual(host._escalation_counts[_HOST], 1)

    async def test_unverified_credential_gives_the_slot_back(self):
        host, crawl = _EscalationHost(1, verifies=False), _Crawl()
        await _escalate_concurrently(host, 1, crawl)
        self.assertEqual((crawl.calls, host._escalation_counts[_HOST]), (0, 0))
        host.verifies = True                      # the next learned credential still gets it
        await _escalate_concurrently(host, 1, crawl)
        self.assertEqual((crawl.calls, host._escalation_counts[_HOST]), (1, 1))

    async def test_a_failed_crawl_gives_the_slot_back(self):
        host = _EscalationHost(1)
        await _escalate_concurrently(host, 1, _Crawl(raises=RuntimeError("crawl broke")))
        self.assertEqual(host._escalation_counts[_HOST], 0)

    async def test_a_cancelled_escalation_gives_the_slot_back(self):
        host, block = _EscalationHost(1), asyncio.Event()
        crawl = _Crawl(block=block)
        st = EngagementState(host=_HOST)
        with patch("harness.role_crawl.crawl_roles", crawl):
            task = asyncio.ensure_future(
                host._auto_escalate(_HOST, f"http://{_HOST}/login0", [_cap(0)], st))
            while crawl.active == 0:
                await asyncio.sleep(0)
            self.assertEqual(host._escalation_counts[_HOST], 1)   # held while in flight
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(host._escalation_counts[_HOST], 0)


class _RecordingAgent:
    gates: list = []

    def __init__(self, ollama, model, allowed_hosts, *, run_context=None, **kw):
        type(self).gates.append(run_context.gate)

    async def run(self, *a, **k):
        return SimpleNamespace(to_dict=lambda: {"stop_reason": "gave_up", "findings": []})


class _ProbeHost(ConfirmMixin):
    def __init__(self, config, registry=None):
        self.config = config
        self.allowed_hosts = ["localhost"]
        self.ollama = object()
        self.iterative_agent_enabled = True
        self.iterative_agent_max_steps = 20
        self.effort_budget = None
        if registry is not None:
            self.validator_registry = registry

    def reasoning_model(self):
        return "test-model"


def _exchange():
    return HttpExchange(url="http://localhost:5002/api/search?q=widget", method="GET",
                        request_headers={"User-Agent": "x"}, request_body="",
                        response_status=200, response_body="results")


class StandaloneProbeGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        _RecordingAgent.gates = []

    async def _probe_gates(self, host, times=2):
        with patch("harness.iterative_agent.IterativeAgent", _RecordingAgent), \
             patch("harness.pivot_memory.integrate",
                   new=AsyncMock(return_value=SimpleNamespace(to_dict=lambda: {}))):
            for _ in range(times):
                await host.run_active_probe(_exchange(), "h", "sqli", step_budget=10)
        return list(_RecordingAgent.gates)

    async def test_each_standalone_probe_gets_a_gate_of_its_own(self):
        default = safety_gate.get_default_gate({"active_enabled": True,
                                                "allowed_hosts": ["localhost"]})
        g1, g2 = await self._probe_gates(_ProbeHost({}))
        self.assertIsNot(g1, g2)                       # no shared audit log / counts
        self.assertIsNot(g1, default)
        self.assertIsNot(g2, default)
        self.assertIn("localhost", g1.config.allowed_hosts)

    async def test_the_live_settings_toggle_reaches_the_probe_gate(self):
        """validators.active_enabled from startup config says one thing, the live
        /settings toggle (the registry) the other: the probe gate follows the toggle,
        where the process-wide gate kept the startup value."""
        on = await self._probe_gates(
            _ProbeHost({"validators": {"active_enabled": False}},
                       registry=SimpleNamespace(active_enabled=True)), times=1)
        off = await self._probe_gates(
            _ProbeHost({"validators": {"active_enabled": True}},
                       registry=SimpleNamespace(active_enabled=False)), times=1)
        self.assertTrue(on[0].config.active_enabled)
        self.assertFalse(off[-1].config.active_enabled)


class _Resp:
    def __init__(self):
        self.status_code, self.text, self.headers = 200, "ok", {}


class _Model:
    def __init__(self, actions):
        self._actions = list(actions)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.2):
        return self._actions.pop(0) if self._actions else {"action": "stop",
                                                           "verdict": "not_found"}


class AgentOutsideARunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        safety_gate.reset_default_gate()

    async def _drive(self):
        default = safety_gate.get_default_gate({"allowed_hosts": ["localhost"]})
        before = len(default.audit_log)
        agent = IterativeAgent(_Model([{"action": "mutate", "location": "query", "param": "q",
                                        "value": "1"}]), "m", ["localhost"])
        sent = []

        async def wire(client, method, url, **kw):
            sent.append(url)
            return _Resp()

        with patch("httpx.AsyncClient.request", wire):
            await agent.run(_exchange(), "h", "sqli", step_budget=3)
        return agent, default, before, sent

    async def test_the_process_wide_gate_is_never_touched(self):
        agent, default, before, sent = await self._drive()
        self.assertEqual(len(sent), 1)
        self.assertIsNone(agent.gate)
        self.assertEqual(len(default.audit_log), before)

    async def test_negative_control_falling_back_to_the_default_gate_shares_its_log(self):
        with patch("harness.iterative_agent.ambient_gate", safety_gate.get_default_gate):
            _, default, before, sent = await self._drive()
        self.assertEqual(len(sent), 1)
        self.assertGreater(len(default.audit_log), before)


class ManifestActiveEnabledTests(unittest.TestCase):
    def test_a_toggle_during_the_run_is_in_its_manifest(self):
        from harness.validators.registry import ValidatorRegistry
        registry = ValidatorRegistry({"validators": {"active_enabled": False}})
        registry.set_active_enabled(True, source="before-run")       # not this run's
        before = time.time()
        while time.time() <= before:
            pass
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="arc11", target_identifier="fixture", config={},
                                    output_dir=td)
            self.assertEqual(run.data["active_enabled"]["at_start"]["active_enabled"], True)
            registry.set_active_enabled(False)                       # /settings, mid-run
            registry.set_active_enabled(False)                       # no change: not logged
            run.finish("done", result={})
            record = run.data["active_enabled"]
        self.assertEqual([(c["previous"], c["active_enabled"], c["source"])
                          for c in record["changes"]], [(True, False, "settings")])
        self.assertEqual(record["at_finish"]["active_enabled"], False)
        self.assertEqual(record["at_finish"]["set_by"], "settings")


if __name__ == "__main__":
    unittest.main()
