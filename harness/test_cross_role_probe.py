"""P1.3 -- multi-user role testing (active cross-role object probe).

Uses a REAL loopback HTTP fixture (not a transport mock) with two endpoints:
  /api/tickets/{id} -- VULNERABLE: returns ticket data for any credentialed
                        caller, regardless of who owns the ticket.
  /api/secure/{id}   -- PATCHED: checks the caller's Authorization token
                        against the object's declared owner, 403s otherwise.
This gives one real positive (a genuine cross-role leak) and one real
negative control (the same shape, properly scoped) from the same target.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import role_crawl
from harness.role_crawl import EndpointAccess, RoleCrawlResult, RoleSession

# token -> owning role, shared by both endpoints' object stores below.
_OWNER_BY_TOKEN = {"Bearer alice-token": "alice", "Bearer bob-token": "bob"}
# object id -> owning role, per endpoint.
_TICKETS = {"101": "alice", "102": "bob"}
_SECURE = {"201": "alice", "202": "bob"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self, status, body: bytes):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        parts = path.strip("/").split("/")
        token = self.headers.get("Authorization") or ""
        caller = _OWNER_BY_TOKEN.get(token)

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "tickets":
            obj_id = parts[2]
            owner = _TICKETS.get(obj_id)
            if not caller or not owner:
                self._reply(401, b"")
                return
            # VULNERABLE: no ownership check at all -- any known caller reads
            # any ticket.
            self._reply(200, f'{{"ticket": "{obj_id}", "owner": "{owner}"}}'.encode())
            return

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "secure":
            obj_id = parts[2]
            owner = _SECURE.get(obj_id)
            if not caller or not owner:
                self._reply(401, b"")
                return
            if caller != owner:
                self._reply(403, b"")   # PATCHED: ownership enforced
                return
            self._reply(200, f'{{"secure": "{obj_id}", "owner": "{owner}"}}'.encode())
            return

        self._reply(404, b"")


class _Fixture:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _roles():
    return [
        RoleSession("alice", {"Authorization": "Bearer alice-token"}),
        RoleSession("bob", {"Authorization": "Bearer bob-token"}),
    ]


class ProbeCrossRoleObjectsTests(unittest.TestCase):
    """Direct unit tests of the probe primitive, against the real fixture."""

    def setUp(self):
        self.fixture = _Fixture()
        self.addCleanup(self.fixture.close)

    def test_vulnerable_endpoint_leaks_to_other_role(self):
        outcomes = asyncio.run(role_crawl.probe_cross_role_objects(
            self.fixture.base, _roles(), "GET", "/api/tickets/{id}",
            {"alice": "101", "bob": "102"}, allowed_hosts=["127.0.0.1"]))
        # 2 owners x 1 other requester each = 2 pairs.
        self.assertEqual(len(outcomes), 2)
        by_pair = {(o.owner_role, o.requester_role): o for o in outcomes}
        bob_reads_alice = by_pair[("alice", "bob")]
        self.assertEqual(bob_reads_alice.classification, "leaked")
        self.assertEqual(bob_reads_alice.status, 200)
        self.assertIsNotNone(bob_reads_alice.finding)
        self.assertEqual(bob_reads_alice.finding.vulnerability_class, "idor")
        self.assertTrue(bob_reads_alice.finding.confirmed)
        alice_reads_bob = by_pair[("bob", "alice")]
        self.assertEqual(alice_reads_bob.classification, "leaked")

    def test_patched_endpoint_is_denied_negative_control(self):
        outcomes = asyncio.run(role_crawl.probe_cross_role_objects(
            self.fixture.base, _roles(), "GET", "/api/secure/{id}",
            {"alice": "201", "bob": "202"}, allowed_hosts=["127.0.0.1"]))
        self.assertEqual(len(outcomes), 2)
        for o in outcomes:
            self.assertEqual(o.classification, "denied")
            self.assertEqual(o.status, 403)
            self.assertIsNone(o.finding)

    def test_owner_is_never_probed_against_itself(self):
        outcomes = asyncio.run(role_crawl.probe_cross_role_objects(
            self.fixture.base, _roles(), "GET", "/api/tickets/{id}",
            {"alice": "101", "bob": "102"}, allowed_hosts=["127.0.0.1"]))
        self.assertNotIn(("alice", "alice"), {(o.owner_role, o.requester_role) for o in outcomes})
        self.assertNotIn(("bob", "bob"), {(o.owner_role, o.requester_role) for o in outcomes})

    def test_out_of_scope_host_yields_no_outcomes(self):
        outcomes = asyncio.run(role_crawl.probe_cross_role_objects(
            self.fixture.base, _roles(), "GET", "/api/tickets/{id}",
            {"alice": "101", "bob": "102"}, allowed_hosts=["other.test"]))
        self.assertEqual(outcomes, [])

    def test_missing_owned_id_is_skipped(self):
        outcomes = asyncio.run(role_crawl.probe_cross_role_objects(
            self.fixture.base, _roles(), "GET", "/api/tickets/{id}",
            {"alice": "101", "bob": ""}, allowed_hosts=["127.0.0.1"]))
        # bob has no declared object -> only alice's object is probed (by bob).
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].owner_role, "alice")


class ProbeCrossRoleMatrixTests(unittest.TestCase):
    """The matrix-driving wrapper that folds leaked outcomes into idor_findings."""

    def setUp(self):
        self.fixture = _Fixture()
        self.addCleanup(self.fixture.close)

    def _result(self):
        r = RoleCrawlResult(base_url=self.fixture.base, roles=["alice", "bob"])
        r.endpoints = [
            EndpointAccess(method="GET", path="/api/tickets/{id}"),
            EndpointAccess(method="GET", path="/api/secure/{id}"),
            EndpointAccess(method="GET", path="/api/public"),  # not object-scoped
        ]
        return r

    def test_matrix_probes_every_object_scoped_endpoint_with_known_owners(self):
        result = self._result()
        owned = {
            "alice": {"/api/tickets/{id}": "101", "/api/secure/{id}": "201"},
            "bob": {"/api/tickets/{id}": "102", "/api/secure/{id}": "202"},
        }
        asyncio.run(role_crawl.probe_cross_role_matrix(
            result, _roles(), owned, allowed_hosts=["127.0.0.1"]))
        # 2 object-scoped endpoints x 2 pairs each = 4 outcomes; /api/public skipped.
        self.assertEqual(len(result.cross_role_outcomes), 4)
        leaked = [o for o in result.cross_role_outcomes if o["classification"] == "leaked"]
        denied = [o for o in result.cross_role_outcomes if o["classification"] == "denied"]
        self.assertEqual(len(leaked), 2)   # both tickets pairs leak
        self.assertEqual(len(denied), 2)   # both secure pairs denied
        # leaked outcomes are folded into idor_findings as real Findings.
        self.assertEqual(len(result.idor_findings), 2)
        for f in result.idor_findings:
            self.assertEqual(f["vulnerability_class"], "idor")
            self.assertTrue(f["confirmed"])

    def test_endpoint_with_only_one_declared_owner_is_not_probed(self):
        result = self._result()
        owned = {"alice": {"/api/tickets/{id}": "101"}}  # bob's id unknown
        asyncio.run(role_crawl.probe_cross_role_matrix(
            result, _roles(), owned, allowed_hosts=["127.0.0.1"]))
        self.assertEqual(result.cross_role_outcomes, [])
        self.assertEqual(result.idor_findings, [])

    def test_crawl_roles_wires_owned_object_ids_end_to_end(self):
        from unittest.mock import patch
        from harness.crawler import CrawlResult

        async def fake_crawl(base_url, headers=None, allowed_hosts=None, max_pages=40,
                             max_depth=2, timeout=15.0, **kwargs):
            r = CrawlResult(base_url=base_url)
            r.endpoints = {"/api/tickets/{id}"}
            return r

        owned = {"alice": {"/api/tickets/{id}": "101"}, "bob": {"/api/tickets/{id}": "102"}}
        with patch("harness.crawler.crawl", fake_crawl):
            result = asyncio.run(role_crawl.crawl_roles(
                self.fixture.base, _roles(), allowed_hosts=["127.0.0.1"],
                owned_object_ids=owned))
        self.assertEqual(len(result.cross_role_outcomes), 2)
        self.assertTrue(any(o["classification"] == "leaked" for o in result.cross_role_outcomes))
        self.assertTrue(any(f["vulnerability_class"] == "idor" for f in result.idor_findings))

    def test_crawl_roles_without_owned_object_ids_is_unchanged(self):
        from unittest.mock import patch
        from harness.crawler import CrawlResult

        async def fake_crawl(base_url, headers=None, allowed_hosts=None, max_pages=40,
                             max_depth=2, timeout=15.0, **kwargs):
            r = CrawlResult(base_url=base_url)
            r.endpoints = {"/api/tickets/{id}"}
            return r

        with patch("harness.crawler.crawl", fake_crawl):
            result = asyncio.run(role_crawl.crawl_roles(
                self.fixture.base, _roles(), allowed_hosts=["127.0.0.1"]))
        self.assertEqual(result.cross_role_outcomes, [])


if __name__ == "__main__":
    unittest.main()
