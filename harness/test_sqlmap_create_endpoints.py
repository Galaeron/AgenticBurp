"""Create endpoints get a light, capped sqlmap (owner decision, #28).

In the 8h juice-shop run one sqlmap scan sent 4,765 requests to POST /api/Users
and 685 of them created accounts. A create endpoint (a POST/PUT that answered 201
or a new object id, or a POST to a plural collection path) is now scanned at
level 1 / risk 1 with boolean + error techniques only, and the run's tool proxy
stops the scan at validators.sqlmap.create_endpoint_max_requests. The reason and
cap lead the verdict's limitation (the proof reason) and its evidence.

The launched sqlmap is the owned stand-in tool from test_tool_traffic_accounting
(it sends I05D_REQUESTS GETs to its -u URL); the owned target counts what arrives.
"""
from __future__ import annotations

import asyncio
import unittest

from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_tool_traffic_accounting import _FAKE_SQLMAP, _AccountingFixture, _sqli
from harness.validators.base import proof_limitation_of
from harness.validators.sqlmap import (LIGHT_TECHNIQUES, SqlmapValidator,
                                       create_endpoint_reason)


def _ex(method="POST", path="/api/Users", status=201, body='{"status":"success","data":{"id":9}}',
        request_body='{"email":"a@b.c","password":"x"}'):
    return HttpExchange(url=f"http://127.0.0.1:1{path}", method=method,
                        request_headers={"Content-Type": "application/json"},
                        request_body=request_body, response_status=status, response_body=body)


class CreateEndpointDetectionTests(unittest.TestCase):
    def test_creates(self):
        self.assertIn("201", create_endpoint_reason(_ex()))
        self.assertIn("201", create_endpoint_reason(_ex(method="PUT", path="/api/Items/4")))
        self.assertIn("new object id", create_endpoint_reason(
            _ex(path="/api/register", status=200, body='{"id": 12}')))
        self.assertIn("collection", create_endpoint_reason(
            _ex(path="/api/BasketItems/", status=200, body="{}")))

    def test_negative_controls_are_not_creates(self):
        # A read, an update of one object, a login, and an action endpoint.
        self.assertEqual(create_endpoint_reason(_ex(method="GET", status=200)), "")
        self.assertEqual(create_endpoint_reason(
            _ex(method="PUT", path="/api/Users/7", status=200, body='{"id": 7}')), "")
        self.assertEqual(create_endpoint_reason(
            _ex(path="/rest/user/login", status=200, body='{"authentication":{"token":"t"}}',
                request_body='{"email":"a@b.c","password":"x"}')), "")
        self.assertEqual(create_endpoint_reason(
            _ex(path="/api/login", status=200, body='{"id": 1, "token": "t"}')), "")
        self.assertEqual(create_endpoint_reason(
            _ex(path="/rest/basket/1/checkout", status=200, body='{"orderConfirmation":"x"}')), "")


class LightCappedSqlmapTests(_AccountingFixture, unittest.TestCase):
    def _run_create(self, *, cap=5, max_requests=200, exchange=None, **kw):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests,
                                gate_config={"active_enabled": True, "allow_mutating_replay": True})
        exchange = exchange or HttpExchange(
            url=f"{self.target.base}/api/Users", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email":"a@b.c","password":"x"}', response_status=201,
            response_body='{"status":"success","data":{"id":9}}')
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run,
                                    create_endpoint_max_requests=cap, **kw)

        async def go():
            try:
                async with run:
                    return await asyncio.wait_for(validator.validate(_sqli(), exchange), 60)
            finally:
                await run.aclose()
        return asyncio.run(go()), run

    def test_scan_is_light_and_stops_at_the_cap(self):
        self.env["I05D_REQUESTS"] = "40"
        result, run = self._run_create(cap=5, level=2, risk=2)
        self.assertEqual(len(self._tool_requests()), 5, "the cap did not bound the scan")
        self.assertEqual(run.budget.used, 5)
        args = self.launched[0]
        self.assertEqual(args[args.index("--level") + 1], "1")
        self.assertEqual(args[args.index("--risk") + 1], "1")
        self.assertEqual(args[args.index("--technique") + 1], LIGHT_TECHNIQUES)
        self.assertEqual(LIGHT_TECHNIQUES, "BE")   # no stacked/time/union queries
        # A capped scan is incomplete, never a negative; the proof says why.
        self.assertNotEqual(result.status, "not_confirmed")
        reason = proof_limitation_of(result)
        for part in ("light sqlmap", "create endpoint", "201", "at most 5 requests",
                     "5 request(s) sent", "cap reached"):
            self.assertIn(part, reason)
        self.assertTrue(result.evidence.startswith("light sqlmap"), result.evidence[:80])

    def test_scan_under_the_cap_still_records_the_light_coverage(self):
        self.env["I05D_REQUESTS"] = "3"
        result, run = self._run_create(cap=5)
        self.assertEqual(len(self._tool_requests()), 3)
        self.assertIn("light sqlmap", result.limitation)
        self.assertIn("3 request(s) sent", result.limitation)
        self.assertNotIn("cap reached", result.limitation)

    def test_without_a_run_a_create_endpoint_is_not_scanned(self):
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, allowed_hosts=["127.0.0.1"])
        from harness.safety_gate import get_default_gate
        from unittest.mock import patch
        allow = type("D", (), {"allowed": True, "reason": ""})()
        with patch.object(get_default_gate(), "authorize", return_value=allow):
            result = asyncio.run(validator.validate(_sqli(), _ex()))
        self.assertEqual(self.launched, [])
        self.assertEqual(result.status, "skipped")
        self.assertIn("needs a run to enforce the cap", result.summary)
        self.assertIn("light sqlmap", proof_limitation_of(result))

    def test_negative_control_other_endpoints_keep_the_full_scan(self):
        self.env["I05D_REQUESTS"] = "12"
        exchange = HttpExchange(url=f"{self.target.base}/api/Users/7", method="PUT",
                                request_headers={"Content-Type": "application/json"},
                                request_body='{"email":"a@b.c"}', response_status=200,
                                response_body='{"id": 7}')
        result, run = self._run_create(cap=5, exchange=exchange, level=2, risk=2)
        self.assertEqual(len(self._tool_requests()), 12, "an update endpoint was capped")
        args = self.launched[0]
        self.assertEqual(args[args.index("--level") + 1], "2")
        self.assertNotIn("--technique", args)
        self.assertNotIn("light sqlmap", result.limitation)

    def test_removing_the_cap_is_detected(self):
        """Fault injection: a proxy that ignores the cap lets every request through."""
        from unittest.mock import patch
        from harness import tool_proxy
        self.env["I05D_REQUESTS"] = "20"
        real_init = tool_proxy.ToolProxy.__init__

        def no_cap(self, *a, **kw):
            kw.pop("max_forwarded", None)
            real_init(self, *a, **kw)
        with patch.object(tool_proxy.ToolProxy, "__init__", no_cap):
            self._run_create(cap=5)
        self.assertEqual(len(self._tool_requests()), 20,
                         "removing the cap no longer matters -- the control is vacuous")


if __name__ == "__main__":
    unittest.main()
