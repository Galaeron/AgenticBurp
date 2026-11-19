"""R11-3: sqlmap stays off long-polling transport endpoints and is time-shared per family.

Caller level: the real SqlmapValidator.plan()/validate() inside a RunContext, with the
owned stand-in sqlmap from test_tool_traffic_accounting (the swap happens inside
subprocess.Popen, so the real launch path runs) against an owned loopback target.
`self.launched` lists every sqlmap process that started.

The polling fixture is recognised from its response framing only; its path is
deliberately neutral (`/rt/poll/`), so no route or product name can be what matched.
"""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

import yaml

from harness import sqlmap_targeting as st
from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_tool_traffic_accounting import _FAKE_SQLMAP, _AccountingFixture, _sqli
from harness.validators.sqlmap import SqlmapValidator

_OPEN = ('0{"sid":"Zx81kq","upgrades":["websocket"],"pingInterval":25000,'
         '"pingTimeout":20000,"maxPayload":1000000}')


class FramingTests(unittest.TestCase):
    def test_transport_framings_are_recognised(self):
        for body in (_OPEN,                                   # Engine.IO v4 open packet
                     f"{len(_OPEN)}:{_OPEN}2:40",             # v3 length-prefixed payload
                     '40{"sid":"abc"}',                       # socket.io connect ack
                     "42[\"tick\",1]\x1e2",                   # v4 record-separated packets
                     "o\n", "h\n", 'a["hello"]\n', 'c[3000,"Go away!"]\n',
                     '{"websocket":true,"origins":["*:*"],"cookie_needed":false,"entropy":42}'):
            self.assertTrue(st.transport_framing(body), body)

    def test_ordinary_bodies_are_not_transport(self):
        # A bare digit (a count, a ping-looking body) is ambiguous on its own, and a
        # JSON body with a `sid` key is ordinary application data.
        for body in ("2", "3", "6", "42", "0", "o", "ok", "200 OK", '[1,2,3]',
                     '{"sid":"abc","upgrades":[]}', '{"status":"success","data":[]}',
                     "0.5", "<html>o</html>", 'a["x"]', "1:x"):
            self.assertEqual(st.transport_framing(body), "", body)

    def test_endpoint_family_folds_object_ids(self):
        a = st.endpoint_family("GET", "http://h:1/api/Items/12?x=1")
        b = st.endpoint_family("get", "http://H:1/api/Items/987")
        self.assertEqual(a, b)
        self.assertEqual(a, "GET http://h:1/api/Items/{id}")
        self.assertNotEqual(a, st.endpoint_family("POST", "http://h:1/api/Items/12"))
        self.assertNotEqual(a, st.endpoint_family("GET", "http://h:1/api/Users/12"))

    def test_shipped_default_is_a_safe_bound(self):
        cfg = yaml.safe_load(Path(__file__).with_name("config.yaml").read_text(encoding="utf-8"))
        value = cfg["validators"]["sqlmap"]["endpoint_family_seconds"]
        self.assertEqual(float(value), st.DEFAULT_ENDPOINT_FAMILY_SECONDS)
        self.assertGreater(value, cfg["validators"]["sqlmap"]["timeout_seconds"],
                           "the share must allow at least one full scan per family")


class SqlmapTargetingCallerTests(_AccountingFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.env["I05D_REQUESTS"] = "2"

    def _run(self, exchanges, *, family_seconds=None, clock=None):
        """Plan and validate each exchange in order, in one run; returns (plans, results, run)."""
        config = {}
        if family_seconds is not None:
            config = {"validators": {"sqlmap": {"endpoint_family_seconds": family_seconds}}}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=500, config=config,
                                gate_config={"active_enabled": True})
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run)
        if clock is not None:
            validator._targeting().clock = clock
        plans = [validator.plan(_sqli(), ex) for ex in exchanges]

        async def go():
            try:
                async with run:
                    out = []
                    for ex in exchanges:
                        out.append(await asyncio.wait_for(validator.validate(_sqli(), ex), 60))
                    return out
            finally:
                await run.aclose()
        return plans, asyncio.run(go()), run

    def _get(self, path_query, body='{"status":"success","data":[]}'):
        return HttpExchange(url=f"{self.target.base}{path_query}", method="GET",
                            response_status=200, response_body=body)

    def _launched_paths(self):
        from urllib.parse import urlsplit
        return [urlsplit(a[a.index("-u") + 1]).path for a in self.launched]

    def test_polling_route_is_not_queued_and_search_route_is(self):
        handshake = self._get("/rt/poll/?EIO=4&transport=polling&t=PqX1a", body=_OPEN)
        # A later poll answers with a bare ping, ambiguous on its own: the path is
        # already known as a transport endpoint from the handshake capture.
        poll = self._get("/rt/poll/?EIO=4&transport=polling&t=PqX2b&sid=Zx81kq", body="2")
        search = self._get("/rest/products/search?q=apple")
        plans, results, run = self._run([handshake, poll, search])
        self.assertIsNone(plans[0])
        self.assertIsNone(plans[1])
        self.assertIsNotNone(plans[2])
        self.assertEqual(self._launched_paths(), ["/rest/products/search"])
        for r in results[:2]:
            self.assertEqual(r.status, "skipped")
            self.assertIn("long-polling transport endpoint", r.summary)
            self.assertIn("not a negative result", r.limitation)
        self.assertIn("Engine.IO open packet", results[0].summary)
        self.assertIn("another capture of this path", results[1].summary)
        self.assertNotEqual(results[2].status, "skipped")
        # Nothing at all reached the polling route (no boolean preflight either).
        self.assertFalse([r for r in self.target.requests if "/rt/poll" in r[1]])
        report = st.run_report(run)
        self.assertEqual(report["transport_endpoints"][0]["targets_skipped"], 2)

    def test_t_and_sid_on_a_non_transport_route_still_get_sqlmap(self):
        """Negative control: the parameter names alone never mark a transport."""
        plans, results, _ = self._run([self._get("/api/report?t=1700000000&sid=42")])
        self.assertIsNotNone(plans[0])
        self.assertEqual(self._launched_paths(), ["/api/report"])
        self.assertNotIn("transport", results[0].summary)

    def test_past_its_share_the_next_target_on_the_family_is_held(self):
        now = [0.0]

        def clock():
            now[0] += 50.0      # each scan measures 50 s on the fake clock
            return now[0]
        first = self._get("/api/Challenges/1?f=a")
        second = self._get("/api/Challenges/2?f=b")     # same family (object id folded)
        other = self._get("/rest/products/search?q=b")  # a different family
        _, results, run = self._run([first, second, other], family_seconds=40, clock=clock)
        self.assertEqual(self._launched_paths(), ["/api/Challenges/1", "/rest/products/search"])
        held = results[1]
        self.assertEqual(held.status, "inconclusive")
        self.assertIn("sqlmap held", held.summary)
        self.assertIn("endpoint_family_seconds", held.summary)
        self.assertIn("GET " + self.target.base.lower() + "/api/Challenges/{id}", held.summary)
        self.assertIn("not a negative result", held.limitation)
        report = st.run_report(run)
        self.assertEqual([h["targets_held"] for h in report["held"]], [1])

    def test_default_config_does_not_hold_ordinary_targets(self):
        """Control: with the shipped default share, consecutive scans of one family run."""
        exchanges = [self._get(f"/api/Challenges/{i}?f={i}") for i in range(3)]
        _, results, run = self._run(exchanges)
        self.assertEqual(len(self.launched), 3)
        self.assertFalse(any(r.status == "inconclusive" and "held" in r.summary for r in results))
        self.assertEqual(st.run_report(run)["endpoint_family_seconds"],
                         st.DEFAULT_ENDPOINT_FAMILY_SECONDS)

    def test_zero_disables_the_share(self):
        now = [0.0]

        def clock():
            now[0] += 1000.0
            return now[0]
        exchanges = [self._get(f"/api/Challenges/{i}?f={i}") for i in range(3)]
        _, results, _ = self._run(exchanges, family_seconds=0, clock=clock)
        self.assertEqual(len(self.launched), 3)


if __name__ == "__main__":
    unittest.main()
