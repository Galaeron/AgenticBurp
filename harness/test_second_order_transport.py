"""ARCH-2 controls: the second-order PLANT (and read) travel the owning run's ONE
TargetTransport -- scope + gate + request budget + evidence, under the run's TLS
trust -- never a separate verify=False client that bypassed all of it.

The plant/read closures in orchestrator_chain delegate their send to
second_order.send_through_run; these exercise that single send path against a real
RunContext (scope + gate + budget enforced inside send()) with the network patched
at httpx.AsyncClient.request -- so a blocked path never reaches the client, and a
bypass (a raw client) would never touch the run's budget.
"""
import unittest
from unittest.mock import patch

from harness.run_context import RunContext, ExecutionOutcome
from harness import second_order


_PLANT_HEADERS = {"Authorization": "Bearer planter", "Content-Type": "application/json"}


class _Resp:
    def __init__(self, status=200, text="ok", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _ctx(allowed=("a.test",), *, max_requests=None, mutating=True):
    return RunContext.create(
        allowed_hosts=list(allowed), config={},
        gate_config={"active_enabled": mutating, "allow_mutating_replay": mutating},
        max_requests=max_requests)


async def _plant(rc, url):
    return await second_order.send_through_run(
        rc, "POST", url, allowed_hosts=["a.test"], config={},
        capability="second_order_plant", headers=dict(_PLANT_HEADERS),
        body='{"q":"marker"}', case_ref="second_order_sqli:A=>B")


class SecondOrderPlantTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_permitted_write_sends_increments_budget_and_emits_evidence(self):
        rc = _ctx(max_requests=5)
        with patch("httpx.AsyncClient.request", return_value=_Resp(200)) as req:
            out = await _plant(rc, "https://a.test/api/x")
            self.assertEqual(req.call_count, 1)                # the write really went out
        self.assertTrue(out.ok)
        self.assertEqual(out.status, 200)
        self.assertEqual(rc.budget.used, 1)                   # against the SHARED run budget
        self.assertIsNotNone(out.artifact)                    # evidence recorded for the write

    async def test_exhausted_budget_prevents_the_write(self):
        rc = _ctx(max_requests=0)
        with patch("httpx.AsyncClient.request") as req:
            out = await _plant(rc, "https://a.test/api/x")
            req.assert_not_called()                           # never reached the network
        self.assertFalse(out.ok)
        self.assertEqual(out.outcome, "budget_exhausted")

    async def test_out_of_scope_destination_prevents_the_write(self):
        rc = _ctx(allowed=("a.test",), max_requests=5)
        with patch("httpx.AsyncClient.request") as req:
            out = await _plant(rc, "https://evil.test/api/x")
            req.assert_not_called()
        self.assertFalse(out.ok)
        self.assertEqual(out.outcome, "out_of_scope")
        self.assertEqual(rc.budget.used, 0)                   # a blocked attempt costs no budget

    async def test_cancelled_run_prevents_the_write(self):
        rc = _ctx(max_requests=5)
        rc.cancel.cancel()
        with patch("httpx.AsyncClient.request") as req:
            out = await _plant(rc, "https://a.test/api/x")
            req.assert_not_called()
        self.assertFalse(out.ok)
        self.assertEqual(out.outcome, "cancelled")

    async def test_denied_mutating_gate_prevents_the_write(self):
        rc = _ctx(max_requests=5, mutating=False)             # gate forbids the POST
        with patch("httpx.AsyncClient.request") as req:
            out = await _plant(rc, "https://a.test/api/x")
            req.assert_not_called()
        self.assertFalse(out.ok)
        self.assertEqual(out.outcome, "blocked")

    async def test_failed_write_status_is_surfaced_not_reported_as_success(self):
        rc = _ctx(max_requests=5)
        with patch("httpx.AsyncClient.request", return_value=_Resp(500, "err")) as req:
            out = await _plant(rc, "https://a.test/api/x")
            self.assertEqual(req.call_count, 1)               # a response did come back
        # ...but _plant's success test (out.ok and 200<=status<400) must reject it.
        plant_succeeded = out.ok and out.status is not None and 200 <= out.status < 400
        self.assertFalse(plant_succeeded)
        self.assertEqual(out.status, 500)

    async def test_write_uses_the_run_budget_not_a_bypass_client(self):
        """Transport-bypass regression: a permitted write moves the RUN's budget. A
        reintroduced raw/verify=False client would send without ever reserving from
        rc.budget -> used stays 0 -> this fails."""
        rc = _ctx(max_requests=5)
        with patch("httpx.AsyncClient.request", return_value=_Resp(200)):
            await _plant(rc, "https://a.test/api/x")
        self.assertEqual(rc.budget.used, 1)

    async def test_case_ref_is_forwarded_to_the_transport_send(self):
        """Per-case accounting cannot be sidestepped: send_through_run forwards the
        shared case_ref (and capability) onto the real transport send -- the plant
        and read of a pair pass the SAME ref, which keys the evidence ledger."""
        rc = _ctx(max_requests=5)
        captured = {}

        class _FakeTransport:
            async def send_creds(self, method, url, *, capability, headers=None,
                                 body=None, case_ref="", max_redirects=0):
                captured.update(method=method, capability=capability, case_ref=case_ref)
                return ExecutionOutcome(outcome="ok", status=200, body="")

        rc.target_transport = lambda: _FakeTransport()
        await second_order.send_through_run(
            rc, "POST", "https://a.test/api/x", allowed_hosts=["a.test"], config={},
            capability="second_order_plant", headers=dict(_PLANT_HEADERS), body="{}",
            case_ref="second_order_sqli:A=>B")
        self.assertEqual(captured["case_ref"], "second_order_sqli:A=>B")
        self.assertEqual(captured["capability"], "second_order_plant")


if __name__ == "__main__":
    unittest.main()
