"""Code review 02, batch RV-F (I10), finding R10: a cross-identity request that was
refused or never sent is not authorization evidence, and only an executed, denied
request is a held control.

Drives ``Orchestrator._validate_findings`` (the production caller) with the reviewer's
zero-budget shape on both the function-level and the object-level path; the executed
denial and an executed cross-identity read are the controls, and one fault injection
reinstates the old "status 0 is a denial" reading.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import cache, safety_gate, store
from harness.models import AgentReport, Finding
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _exchange, _RecordingModel

ORIGIN = "http://shop.invalid"


def _finding(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


def _verdicts(reports):
    return [(v.status, v.control_outcome, v.summary) for v in reports]



class _CallerBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rvf_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, cfg=None):
        cfg = cfg or _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        return orch


# ------------------------------------------------------------------ R10
class CrossIdentityUnsentTests(_CallerBase):
    """R10: a cross-identity request that was refused or never sent is not
    authorization evidence. Only an executed, denied request is a held control."""

    BFLA = ORIGIN + "/admin/settings"     # function-level (admin namespace) path
    BOLA = ORIGIN + "/orders/1"           # object-level (object identifier) path

    def _check(self, url, *, max_requests, others=("other",), allow=()):
        """Validate one access-control finding as the production caller does.
        Every identity in ``allow`` receives the owner's response; all else is
        denied (403)."""
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        orch = self._orch()
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {
            "cross_identity": CrossIdentityValidator(allowed_hosts=["shop.invalid"])}
        ex = _exchange(url, {"Authorization": "Bearer source"})
        sent = []

        async def fake_request(client, method, request_url, **kwargs):
            auth = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}.get(
                "authorization", "")
            sent.append((str(request_url), auth))
            request = httpx.Request(method, request_url)
            if auth in allow:
                return httpx.Response(200, text='{"id": 1, "total": 10}', request=request)
            return httpx.Response(403, text="forbidden", request=request)

        async def go():
            async with RunContext.create(allowed_hosts=["shop.invalid"],
                                         max_requests=max_requests,
                                         gate_config={"active_enabled": True}) as run:
                run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[ORIGIN])
                for name in others:
                    run.sessions.register(name, name, {"Authorization": f"Bearer {name}"},
                                          allowed_origins=[ORIGIN], role="user")
                return await orch._validate_findings(
                    ex, [AgentReport(agent="auth", model="fake",
                                     findings=[_finding("broken_access_control")])],
                    run_context=run)
        with patch.object(httpx.AsyncClient, "request", fake_request):
            reports, _proofs = asyncio.run(go())
        return reports, sent

    def _assert_not_held(self, reports, *, status=None):
        self.assertTrue(reports)
        self.assertFalse(any(v.control_outcome == "control_held" for v in reports),
                         _verdicts(reports))
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        if status is not None:
            self.assertEqual([v.status for v in reports], [status], _verdicts(reports))

    # the reviewer's check (admin-namespaced path), and the object-level twin
    def test_budget_blocked_identity_checks_do_not_claim_held_control(self):
        for url in (self.BFLA, self.BOLA):
            with self.subTest(url=url):
                reports, sent = self._check(url, max_requests=0)
                self.assertEqual(sent, [])            # nothing reached the target
                self._assert_not_held(reports, status="blocked")

    def test_budget_that_ends_before_any_identity_probe_is_blocked(self):
        # The anonymous baseline used the only request; the identity probe was refused.
        for url in (self.BFLA, self.BOLA):
            with self.subTest(url=url):
                reports, sent = self._check(url, max_requests=1)
                self.assertEqual(len(sent), 1)
                self._assert_not_held(reports, status="blocked")

    def test_budget_that_ends_mid_way_is_inconclusive_not_held(self):
        # anon + first identity answered (both denied); the second identity was refused.
        for url in (self.BFLA, self.BOLA):
            with self.subTest(url=url):
                reports, sent = self._check(url, max_requests=2, others=("other", "third"))
                self.assertEqual(len(sent), 2)
                self._assert_not_held(reports)
                self.assertEqual([v.control_outcome for v in reports], ["inconclusive"],
                                 _verdicts(reports))

    # controls: an executed, denied request still reports the control held
    def test_executed_denials_still_report_the_control_held(self):
        for url in (self.BFLA, self.BOLA):
            with self.subTest(url=url):
                reports, sent = self._check(url, max_requests=20)
                self.assertEqual(len(sent), 2)        # anon baseline + the other identity
                self.assertEqual([(v.status, v.control_outcome) for v in reports],
                                 [("not_confirmed", "control_held")], _verdicts(reports))

    def test_executed_cross_identity_read_still_confirms(self):
        reports, sent = self._check(self.BOLA, max_requests=20, allow=("Bearer other",))
        self.assertEqual(len(sent), 2)
        self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))

    # fault injection
    def test_reinstating_unsent_probe_as_denial_is_detected(self):
        """Fault injection: if an unsent probe is read as a response again, the zero-
        budget run claims the control held and the guard above would fail."""
        from harness.validators import cross_identity_validator as ci
        with patch.object(ci, "_not_reached", lambda probe: False):
            reports, sent = self._check(self.BFLA, max_requests=0)
        self.assertEqual(sent, [])
        self.assertTrue(any(v.control_outcome == "control_held" for v in reports),
                        "removing the unsent-probe check no longer claims a held control "
                        "-- the guard test is vacuous: " + str(_verdicts(reports)))


if __name__ == "__main__":
    unittest.main()
