"""I05, owner decision 2026-10-19: a standalone analyze() publishes its own run.

analyze() always created a run with an explicit request ceiling
(analyze.max_requests), but never published it as the enclosing run. Validators that send through
GatedAsyncClient (I03's routing needs an enclosing run) therefore used a private
client: outside the ceiling and outside the run's TLS policy (which, for those
sends, could not be configured at all). Publishing the run puts them on the run's
transport: the ceiling binds them, the run's scope applies, and a self-signed
target can be trusted through the explicit TLS policy (transport.tls.ca_bundle,
or the loopback-fixture exception used here). The model plane stays shared.

Driven through Orchestrator.analyze with no run passed in (the /analyze path),
against an owned loopback target that counts what it receives. The api_security
limit probe is the gated send under test.
"""
from __future__ import annotations

import asyncio
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_engagement_transport_callers import _Target, _config, _install_model
from harness.test_run_escape_callers import _ApiModel, _IsolatedStateBase, _skip_timing_leg


class StandaloneAnalyzeRunTests(_IsolatedStateBase, unittest.TestCase):
    def _target(self, **kw) -> _Target:
        target = _Target(**kw)
        self.addCleanup(target.close)
        return target

    def _tls_target(self) -> _Target:
        from harness.test_remediation_tls import _LEAF_CERT, _LEAF_KEY
        cert, key = Path(self._tmp) / "leaf.pem", Path(self._tmp) / "key.pem"
        cert.write_text(_LEAF_CERT, encoding="ascii")
        key.write_text(_LEAF_KEY, encoding="ascii")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert), str(key))
        return self._target(tls_context=server_context)

    def _analyze(self, target, *, ceiling=200, tls=None, extra_patches=()):
        """One standalone analyze (no run passed in); returns the run it created."""
        url = f"{target.base}/api/items?limit=10"
        cfg = _config(mutating=False)
        cfg["iterative_agent"]["enabled"] = False
        cfg.setdefault("analyze", {})["max_requests"] = ceiling
        if tls is not None:
            cfg.setdefault("transport", {})["tls"] = tls
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _ApiModel(url))
        exchange = HttpExchange(url=url, method="GET", response_status=200,
                                response_headers={"Content-Type": "application/json"},
                                response_body='{"items": [1, 2, 3]}')
        created: list[RunContext] = []
        real_create = RunContext.create.__func__

        def recording_create(cls, *a, **kw):
            run = real_create(cls, *a, **kw)
            created.append(run)
            return run

        patches = [patch.object(RunContext, "create", classmethod(recording_create)),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch("harness.validators.command_injection_validator."
                         "CommandInjectionValidator.validate", _skip_timing_leg),
                   *extra_patches]
        for p in patches:
            p.start()
        try:
            asyncio.run(orch.analyze(exchange, force_agents=["api_security"]))
        finally:
            for p in reversed(patches):
                p.stop()
        return created[0]

    @staticmethod
    def _limit_probes(target):
        return [r for r in target.requests if "limit=999999" in r[1]]

    def test_gated_validator_spends_the_analysis_ceiling(self):
        target = self._target()
        run = self._analyze(target)
        self.assertTrue(self._limit_probes(target), "the gated limit probe never ran")
        self.assertEqual(len(target.requests), run.budget.used, target.requests)

    def test_zero_ceiling_sends_nothing(self):
        target = self._target()
        self._analyze(target, ceiling=0)
        self.assertEqual(target.requests, [])

    def test_untrusted_certificate_is_refused(self):
        target = self._tls_target()
        self._analyze(target)
        self.assertGreater(target.connections, 0, "nothing attempted a connection -- vacuous")
        self.assertEqual(target.requests, [], "a gated send went over an untrusted channel")

    def test_explicit_fixture_trust_restores_access(self):
        target = self._tls_target()
        run = self._analyze(target, tls={"fixture_insecure_origins": [target.base],
                                         "fixture_insecure_reason": "I05 loopback TLS fixture"})
        self.assertTrue(self._limit_probes(target), "trusting the fixture did not restore the probe")
        self.assertEqual(len(target.requests), run.budget.used, target.requests)

    def test_not_publishing_the_run_is_detected(self):
        """Fault injection: analyze() creates its run but does not publish it."""
        target = self._target()
        self._analyze(target, ceiling=0, extra_patches=[
            patch.object(RunContext, "publish", lambda self: self)])
        self.assertTrue(self._limit_probes(target),
                        "not publishing the run no longer leaks -- the control is vacuous")

    def test_shared_model_plane_is_kept(self):
        """Publishing must not install a per-run Ollama breaker (that is `async with`)."""
        target = self._target()
        run = self._analyze(target)
        self.assertIsNone(run._ollama_breaker)


if __name__ == "__main__":
    unittest.main()
