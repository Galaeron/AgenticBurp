"""ARCH-3 (lifecycle half): a STANDALONE analyze owns its run context -- it creates
ONE context with an explicit request ceiling and closes it on every exit -- while a
context BORROWED from an engagement is never created or closed here.

These exercise the public DetectMixin.analyze wrapper directly (the heavy
_analyze_inner body is stubbed), so the ownership/ceiling/cleanup contract is tested
at the caller without a live model or network.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock, Mock

from harness.orchestrator_detect import DetectMixin
from harness.models import HttpExchange


def _exchange():
    return HttpExchange(url="https://a.test/api/x", method="GET",
                        request_headers={}, request_body="",
                        response_status=200, response_body="ok")


class _Host(DetectMixin):
    """Minimal attribute surface for DetectMixin.analyze's ownership wrapper."""
    def __init__(self, config=None):
        self.allowed_hosts = ["a.test"]
        self.config = {} if config is None else config
        self.validator_registry = None


class StandaloneAnalyzeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.created = {}

        def _fake_create(**kwargs):
            ctx = SimpleNamespace(aclose=AsyncMock(), kwargs=kwargs)
            self.created["kwargs"] = kwargs
            self.created["ctx"] = ctx
            return ctx

        self._p_create = patch("harness.run_context.RunContext.create", side_effect=_fake_create)
        self._p_gate = patch("harness.orchestrator_detect.per_run_gate_config", return_value={})
        self._p_create.start()
        self._p_gate.start()

    def tearDown(self):
        self._p_create.stop()
        self._p_gate.stop()

    async def test_standalone_creates_ceilinged_context_and_closes_it(self):
        host = _Host()
        host._seed_identities_from_store = Mock()
        host._analyze_inner = AsyncMock(return_value="RESP")
        out = await host.analyze(_exchange())
        self.assertEqual(out, "RESP")
        # created exactly one context, with an EXPLICIT request ceiling
        self.assertIn("max_requests", self.created["kwargs"])
        self.assertEqual(self.created["kwargs"]["max_requests"], 1000)
        # and it was closed after the analysis
        self.created["ctx"].aclose.assert_awaited_once()
        # the inner body was told it owns the run, and got the created context
        _, kw = host._analyze_inner.call_args
        self.assertTrue(kw["_owns_run"])
        self.assertIs(kw["run_context"], self.created["ctx"])

    async def test_config_overrides_the_request_ceiling(self):
        host = _Host(config={"analyze": {"max_requests": 42}})
        host._seed_identities_from_store = Mock()
        host._analyze_inner = AsyncMock(return_value="RESP")
        await host.analyze(_exchange())
        self.assertEqual(self.created["kwargs"]["max_requests"], 42)

    async def test_owned_context_is_closed_even_on_error(self):
        host = _Host()
        host._seed_identities_from_store = Mock()
        host._analyze_inner = AsyncMock(side_effect=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            await host.analyze(_exchange())
        # the finally must still close the owned context -- no leak on the error path
        self.created["ctx"].aclose.assert_awaited_once()

    async def test_borrowed_engagement_context_is_neither_created_nor_closed(self):
        host = _Host()
        host._seed_identities_from_store = Mock()
        host._analyze_inner = AsyncMock(return_value="RESP")
        borrowed = SimpleNamespace(aclose=AsyncMock())
        out = await host.analyze(_exchange(), run_context=borrowed)
        self.assertEqual(out, "RESP")
        self.assertEqual(self.created, {})               # no context was created here
        host._seed_identities_from_store.assert_not_called()
        borrowed.aclose.assert_not_awaited()             # the engagement owns its lifetime
        _, kw = host._analyze_inner.call_args
        self.assertFalse(kw["_owns_run"])
        self.assertIs(kw["run_context"], borrowed)


if __name__ == "__main__":
    unittest.main()
