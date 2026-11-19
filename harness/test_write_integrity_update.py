"""R11-5: an update of one object written by someone who should not make it,
read back as its owner or an admin, and written back.

The loopback store is generic: objects under /api/<collection>/<id>, every answer
in a {"status", "data"} envelope, a free read for everyone. Its collections differ
only in how a PUT is checked:

  things   unchecked: anyone, anonymous included, may PUT (the flaw);
  locked   checked: only the object's owner may PUT (401 anonymous, 403 others);
  inert    answers 200 to any PUT and changes nothing (the "200 that changes
           nothing" negative control);
  sticky   the first PUT lands, every later PUT is ignored (a restore that fails).

Each test runs over real HTTP through a RunContext whose gate admits the writes,
and checks what was left behind: the store equals its seed again and the run's
change log records the write as restored.
"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import principals
from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.base import proves_finding_class
from harness.validators.registry import ValidatorRegistry
from harness.validators.write_integrity_validator import UNAUTHORIZED_UPDATE, WriteIntegrityValidator

_OWNERS = {"Bearer a": "alice", "Bearer b": "bob", "Bearer admin": "admin"}


def _seed():
    obj = {"id": 1, "name": "desk", "description": "oak", "price": 10}
    return {c: {1: dict(obj)} for c in ("things", "locked", "inert", "sticky")}


class _Store(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def route(self):
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        if len(parts) != 3 or parts[0] != "api" or parts[1] not in self.server.data:
            return None, None
        return parts[1], int(parts[2]) if parts[2].isdigit() else None

    def do_GET(self):
        coll, oid = self.route()
        self.server.received.append(("GET", self.path, self.headers.get("Authorization") or ""))
        if coll is None or oid not in self.server.data[coll]:
            return self.reply(404, {"error": "not found"})
        return self.reply(200, {"status": "success", "data": self.server.data[coll][oid]})

    def do_PUT(self):
        coll, oid = self.route()
        who = _OWNERS.get(self.headers.get("Authorization") or "", "")
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        self.server.received.append(("PUT", self.path, who))
        if coll is None or oid not in self.server.data[coll]:
            return self.reply(404, {"error": "not found"})
        objs = self.server.data[coll]
        if coll == "locked" and who != "alice":
            return self.reply(401 if not who else 403, {"error": "not yours"})
        if coll == "inert":
            return self.reply(200, {"status": "success", "data": objs[oid]})
        if coll == "sticky":
            self.server.sticky_puts += 1
            if self.server.sticky_puts > 1:
                return self.reply(200, {"status": "success", "data": objs[oid]})
        objs[oid] = {**data, "id": oid}
        return self.reply(200, {"status": "success", "data": objs[oid]})


class _Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Store)
        self.server.data, self.server.received, self.server.sticky_puts = _seed(), [], 0
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.runs = []

    async def asyncTearDown(self):
        for run in self.runs:
            await run.aclose()
        self.server.shutdown()
        self.server.server_close()

    def build(self, *, writes=True, owners=True, admin=True, protected=None, ceiling=4,
              xid=False):
        cfg = {"validators": {"active_enabled": True, "allow_mutating_replay": writes,
                              "write_integrity": {"enabled": True},
                              "cross_identity": {"enabled": xid}},
               "server": {"allowed_hosts": ["127.0.0.1"]}}
        if protected:
            cfg["authz"] = {"protected_paths": {f"127.0.0.1:{self.server.server_port}": protected}}
        gate = {"active_enabled": True, "allow_mutating_replay": writes,
                "mutating_ceiling_by_check": {"write_integrity": ceiling, "cross_identity": ceiling}}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=60, config=cfg,
                                gate_config=gate)
        self.runs.append(run)
        origins = [self.origin]
        run.sessions.register("anonymous", "anonymous", {}, allowed_origins=origins)
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=origins)
        run.sessions.register("b", "bob", {"Authorization": "Bearer b"}, allowed_origins=origins)
        if admin:
            run.sessions.register("adm", "admin", {"Authorization": "Bearer admin"},
                                  allowed_origins=origins, role="admin")
        reg = ValidatorRegistry(cfg)
        ledger = principals.OwnershipLedger()
        if owners:
            for coll in ("things", "locked", "inert", "sticky"):
                ledger.declare(f"{self.origin}/api/{coll}/1", owner="alice")
        reg.set_ownership(ledger)
        return reg, run

    def capture(self, cls, path, *, auth="", body=None):
        finding = Finding(vulnerability_class=cls, confidence=0.6, summary="write check",
                          evidence="capture", suggested_test="read back", basis="derived")
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = auth
        # The role crawler's guessed body (no schema for this write): the check must
        # not depend on it.
        ex = HttpExchange(url=self.origin + path, method="PUT", request_headers=headers,
                          request_body=json.dumps(body if body is not None
                                                  else {"name": "probe", "value": "probe"}))
        return finding, ex

    async def direct(self, path, **kw):
        auth = kw.pop("auth", "")
        reg, run = self.build(**kw)
        finding, ex = self.capture(UNAUTHORIZED_UPDATE, path, auth=auth)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        self.assertTrue(legs, "registry did not route unauthorized_update to write_integrity")
        async with run:
            result = await legs[0].validate(finding, ex)
        return result, run

    def puts(self):
        return [(p, who) for m, p, who in self.server.received if m == "PUT"]

    def assert_restored(self, run):
        self.assertEqual(self.server.data, _seed(), "the store was not returned to its seed state")
        entries = [e for e in run.change_log.entries() if e["method"] == "PUT"
                   and e["restore_status"] != "restore_send"]
        self.assertTrue(entries, "no write was recorded in the change log")
        self.assertEqual({e["restore_status"] for e in entries}, {"restored"}, entries)
        self.assertEqual(run.change_log.failed_restores(), [])


class UnauthorizedUpdateTests(_Fixture):
    async def test_unchecked_owner_only_put_is_confirmed_and_restored(self):
        result, run = await self.direct("/api/things/1")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertTrue(result.confirmed)
        self.assertIn("anonymous changed", result.summary)
        self.assertIn("authz.owners declares the object to 'alice'", result.summary)
        self.assertEqual(result.mechanism_classes, ("broken_access_control", "missing_authentication"))
        self.assertIn("reader=alice (owner)", result.evidence)
        # The field comes from the object, not the guessed body's "value".
        self.assertIn("field=name (from the captured body)", result.evidence)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertTrue(result.baseline_artifact_id and result.attack_artifact_id)
        # The anonymous write, then the owner's write-back.
        self.assertEqual(self.puts(), [("/api/things/1", ""), ("/api/things/1", "alice")])
        self.assert_restored(run)

    async def test_checked_owner_only_put_is_a_held_control(self):
        result, run = await self.direct("/api/locked/1", auth="Bearer b")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("HTTP 401, 403", result.summary)
        # Anonymous, then the capture's own non-owner session; no write-back needed.
        self.assertEqual(self.puts(), [("/api/locked/1", ""), ("/api/locked/1", "bob")])
        self.assertIn("restore=not_needed", result.evidence)
        self.assertEqual(self.server.data, _seed())

    async def test_a_200_that_changes_nothing_is_not_confirmed(self):
        result, run = await self.direct("/api/inert/1")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertIn("HTTP 200", result.summary)
        self.assertIn("unchanged", result.summary)
        self.assertEqual(self.server.data, _seed())

    async def test_off_a_declared_route_a_change_is_a_lead(self):
        result, run = await self.direct("/api/things/1", owners=False)
        self.assertEqual(result.status, "supported", result.summary)
        self.assertFalse(result.confirmed)
        self.assertTrue(result.summary.startswith("LEAD:"), result.summary)
        self.assertIn("reader=admin (admin)", result.evidence)
        self.assertIn("boundary=undeclared", result.evidence)
        self.assert_restored(run)

    async def test_a_protected_path_confirms_an_anonymous_change(self):
        result, run = await self.direct("/api/things/1", owners=False,
                                        protected=["PUT /api/things/*"])
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("declared protected", result.summary)
        self.assert_restored(run)

    async def test_an_engagement_protected_path_confirms_an_anonymous_change(self):
        reg, run = self.build(owners=False)
        run.protected_paths = ["PUT /api/things/*"]
        finding, ex = self.capture(UNAUTHORIZED_UPDATE, "/api/things/1")
        leg = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
               if v.name == "write_integrity"][0]
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("engagement protected_paths", result.summary)
        self.assert_restored(run)

    async def test_a_restore_that_cannot_be_verified_is_a_loud_error(self):
        result, run = await self.direct("/api/sticky/1")
        self.assertEqual(result.status, "error", result.summary)
        self.assertTrue(result.summary.startswith("RESTORE FAILED"), result.summary)
        self.assertTrue(run.change_log.failed_restores())

    async def test_no_owner_or_admin_session_is_skipped_without_a_write(self):
        result, _ = await self.direct("/api/things/1", owners=False, admin=False)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("no admin session", result.summary)
        self.assertEqual(self.puts(), [])

    async def test_mutating_replay_off_writes_nothing(self):
        reg, run = self.build(writes=False)
        finding, ex = self.capture(UNAUTHORIZED_UPDATE, "/api/things/1")
        leg = WriteIntegrityValidator(run_context=run, allow_writes=False)
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("allow_mutating_replay", result.summary)
        self.assertEqual(self.puts(), [])

    async def test_a_ceiling_below_write_and_restore_writes_nothing(self):
        result, _ = await self.direct("/api/things/1", ceiling=1)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn(">= 2", result.summary)
        self.assertEqual(self.puts(), [])


class CrossIdentityCallerTests(_Fixture):
    """The r11 path: an access-control finding on an anonymous PUT capture reached
    cross_identity's write leg, which had no owner session for it and skipped. It now
    runs the update check, and the R11-1 gate binds the confirmation."""

    async def dispatch(self, path, cls="broken_access_control", **kw):
        reg, run = self.build(xid=True, **kw)
        finding, ex = self.capture(cls, path)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "cross_identity"]
        self.assertTrue(legs, "registry did not route the PUT to cross_identity")
        async with run:
            result = await legs[0].validate(finding, ex)
        return legs[0], finding, ex, result, run

    async def test_anonymous_capture_reaches_the_update_check(self):
        leg, finding, ex, result, run = await self.dispatch("/api/things/1")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertTrue(proves_finding_class(leg, result, finding, ex))
        self.assert_restored(run)

    async def test_checked_put_stays_not_confirmed_through_the_caller(self):
        leg, finding, ex, result, run = await self.dispatch("/api/locked/1")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(self.server.data, _seed())

    async def test_without_a_reader_the_write_legs_reason_comes_first(self):
        leg, finding, ex, result, run = await self.dispatch("/api/things/1", owners=False, admin=False)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertTrue(result.summary.startswith("No registered owner/baseline session"), result.summary)
        self.assertEqual(self.puts(), [])


if __name__ == "__main__":
    unittest.main()
