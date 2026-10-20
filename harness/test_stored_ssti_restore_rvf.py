"""Code review 02, batch RV-F (I10), finding R12: a stored-SSTI plant whose restore the
mutation ceiling (or the request budget) cannot afford is refused, and a restore that
did not happen is never reported as one.

Drives ``Orchestrator._validate_findings`` (the production caller) with the reviewer's
stored-SSTI shape; a plant whose restore really succeeds is the control, and two fault
injections reinstate the unchecked plant and the unchecked restore outcome.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

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


# ------------------------------------------------------------------ R12
class StoredSstiRestoreTests(_CallerBase):
    """R12: the mutation ceiling allows the plant but refuses the restore, while the
    result claimed restoration succeeded."""

    PAGE = ORIGIN + "/page"

    def _stored(self, *, ceiling=None, restore_status=200, max_requests=None):
        """Drive the stored-SSTI leg through _validate_findings against a fake
        settings page whose value is rendered on /page. Returns (reports, state, sent)."""
        from harness.validators.ssti_validator import SstiValidator
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=True)
        if ceiling is not None:
            cfg["validators"]["mutating_ceiling_by_check"] = {"ssti": ceiling}
        orch = Orchestrator(cfg)
        orch.validator_registry.validators = {
            "ssti": SstiValidator(allowed_hosts=["shop.invalid"], readback_urls=[self.PAGE])}
        ex = _exchange(ORIGIN + "/settings", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "display=original"
        state, sent = {"display": "original"}, []
        posts = []

        async def fake_request(client, method, url, **kwargs):
            sent.append((method, str(url)))
            request = httpx.Request(method, url)
            if method == "POST":
                posts.append(1)
                if len(posts) > 1 and restore_status != 200:
                    return httpx.Response(restore_status, text="rejected", request=request)
                body = kwargs.get("content") or ""
                body = body.decode() if isinstance(body, bytes) else body
                state["display"] = parse_qs(body)["display"][0]
            text = "8633" if method == "GET" and state["display"] == "89*97" else "fixture"
            return httpx.Response(200, text=text, request=request)
        agent_reports = [AgentReport(agent="ssti", model="fake", findings=[_finding("ssti")])]

        async def go():
            if max_requests is None:
                return await orch._validate_findings(ex, agent_reports)
            # an explicit run with a small request budget
            async with RunContext.create(
                    allowed_hosts=["shop.invalid"], max_requests=max_requests,
                    gate_config={"active_enabled": True, "allow_mutating_replay": True,
                                 "mutating_ceiling_by_check": {"ssti": ceiling or 1}}) as run:
                return await orch._validate_findings(ex, agent_reports, run_context=run)
        with patch.object(httpx.AsyncClient, "request", fake_request):
            reports, _proofs = asyncio.run(go())
        return reports, state, sent

    @staticmethod
    def _text(reports):
        return " ".join(f"{v.summary} {v.evidence}" for v in reports)

    # the reviewer's check: no claim of restoration while the plant is still stored
    def test_stored_ssti_does_not_claim_blocked_restore_succeeded(self):
        reports, state, sent = self._stored()      # default ceiling: one mutating send
        self.assertFalse(state["display"] != "original" and "replayed afterward" in self._text(reports),
                         (state, sent, _verdicts(reports)))

    def test_an_unaffordable_restore_refuses_the_plant(self):
        # One mutating send is all the default ceiling allows: plant + restore cannot
        # both be afforded, so nothing is written and the check is blocked, not negative.
        reports, state, sent = self._stored()
        self.assertEqual([m for m, _ in sent if m == "POST"], [])
        self.assertEqual(state["display"], "original")
        self.assertEqual([v.status for v in reports], ["blocked"], _verdicts(reports))
        self.assertFalse(any(v.confirmed for v in reports))
        self.assertIn("restore", self._text(reports))

    def test_request_budget_that_cannot_afford_the_restore_refuses_the_plant(self):
        # The baseline read leaves one request: the plant would be the last send.
        reports, state, sent = self._stored(ceiling=2, max_requests=2)
        self.assertEqual([m for m, _ in sent if m == "POST"], [])
        self.assertEqual(state["display"], "original")
        self.assertEqual([v.status for v in reports], ["blocked"], _verdicts(reports))

    def test_a_budget_that_can_afford_the_restore_still_confirms(self):
        # control for the budget refusal above: the same explicit run with room to spare
        reports, state, sent = self._stored(ceiling=2, max_requests=20)
        self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual(state["display"], "original")
        self.assertIn("replayed afterward", self._text(reports))

    # control: a plant whose restore really succeeds still reports restored
    def test_a_plant_whose_restore_succeeds_still_reports_restored(self):
        reports, state, sent = self._stored(ceiling=2)
        self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual(state["display"], "original")             # really restored
        self.assertEqual([m for m, _ in sent if m == "POST"], ["POST", "POST"])
        self.assertIn("replayed afterward", self._text(reports))
        self.assertNotIn("NOT restored", self._text(reports))

    # a restore the target rejects after the plant was written is disclosed
    def test_a_rejected_restore_is_disclosed_as_residual_state(self):
        reports, state, sent = self._stored(ceiling=2, restore_status=403)
        self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))   # proof stands
        self.assertEqual(state["display"], "89*97")                # the plant is still stored
        text = self._text(reports)
        self.assertNotIn("replayed afterward", text)
        self.assertIn("NOT restored", text)
        self.assertIn("89*97", text)

    # fault injections
    def test_fault_injection_unchecked_affordability_is_detected(self):
        """Fault injection 1: without the affordability check the plant is written and
        the restore is refused. The outcome check still stops a false claim."""
        from harness.validators.ssti_validator import SstiValidator
        with patch.object(SstiValidator, "_cleanup_unaffordable", lambda *a, **k: None):
            reports, state, sent = self._stored()
        self.assertEqual(state["display"], "89*97",
                         "removing the affordability check no longer lets the plant be written "
                         "-- the guard test is vacuous")
        self.assertNotIn("replayed afterward", self._text(reports))
        self.assertIn("NOT restored", self._text(reports))

    def test_fault_injection_unchecked_restore_outcome_is_detected(self):
        """Fault injection 2: without reading the restore send's outcome a refused
        restore is claimed as replayed again (the reviewer's defect)."""
        from harness.validators.ssti_validator import SstiValidator
        with patch.object(SstiValidator, "_cleanup_unaffordable", lambda *a, **k: None), \
                patch("harness.validators.ssti_validator._restore_succeeded",
                      lambda outcome: (True, "HTTP 200")):
            reports, state, sent = self._stored()
        self.assertEqual(state["display"], "89*97")
        self.assertIn("replayed afterward", self._text(reports),
                      "removing the outcome check no longer produces the false claim "
                      "-- the guard test is vacuous")


if __name__ == "__main__":
    unittest.main()
