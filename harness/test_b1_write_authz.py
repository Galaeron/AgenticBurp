"""B1-T2: cross_identity write-side authorization leg with mandatory restore.

Every case runs against an owned loopback HTTP fixture (a generic JSON object
store), dispatched through the real registry (for_finding + bind_run_context)
or the real confirmation caller (ConfirmMixin._validate_findings). Only proof
persistence and the evidence ledger are replaced in the caller-level test.
"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

from harness import principals
from harness.models import AgentReport, Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.registry import ValidatorRegistry


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.received.append(("GET", self.headers.get("Authorization")))
        self.reply(200 if self.server.obj else 404, self.server.obj or {})

    def write(self):
        caller = self.headers.get("Authorization")
        self.server.received.append((self.command, caller))
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        writer = caller != self.server.owner_token
        if writer and self.server.mode == "denied":
            return self.reply(403, {})
        if not writer and self.server.mode == "restore_failed":
            return self.reply(500, {})
        if writer and self.server.mode == "unchanged":
            return self.reply(200, self.server.obj)   # accepted, silently ignored
        if self.command == "DELETE":
            self.server.obj = None
        elif self.command == "PATCH":
            self.server.obj.update(data)
        else:
            self.server.obj = data
        self.reply(200, self.server.obj or {})

    do_PUT = do_PATCH = do_DELETE = write


class _Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.obj = {"id": 7, "description": "original", "owner": "alice"}
        self.server.mode, self.server.received = "vulnerable", []
        self.server.owner_token = "Bearer a"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.url = self.origin + "/objects/7"
        self.original = dict(self.server.obj)
        self.runs = []

    async def asyncTearDown(self):
        for run in self.runs:
            await run.aclose()
        self.server.shutdown()
        self.server.server_close()

    def build(self, *, registry_writes=True, run_writes=True, ceiling=2, owner="alice",
              restore_contract="", admin=False):
        cfg = {"validators": {"active_enabled": True, "allow_mutating_replay": registry_writes,
                              "cross_identity": {"enabled": True,
                                                 "delete_restore_method": restore_contract}},
               "server": {"allowed_hosts": ["127.0.0.1"]}}
        gate = {"active_enabled": True, "allow_mutating_replay": run_writes}
        if ceiling is not None:
            gate["mutating_ceiling_by_check"] = {"cross_identity": ceiling}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=20, config=cfg,
                                gate_config=gate)
        self.runs.append(run)
        origins = [self.origin]
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=origins)
        run.sessions.register("b", "bob", {"Authorization": "Bearer b"}, allowed_origins=origins)
        if admin:
            run.sessions.register("z", "root", {"Authorization": "Bearer z"},
                                  allowed_origins=origins, role="admin")
        reg = ValidatorRegistry(cfg)
        ledger = principals.OwnershipLedger()
        if owner:
            ledger.declare(self.url, owner=owner)
        reg.set_ownership(ledger)
        return reg, run

    def capture(self, method="PUT", token="Bearer a"):
        finding = Finding(vulnerability_class="idor", confidence=0.7, summary="write authz",
                          evidence="capture", suggested_test="read back", basis="derived")
        ex = HttpExchange(url=self.url, method=method, request_body='{"description":"captured"}',
                          request_headers={"Authorization": token,
                                           "Content-Type": "application/json"})
        return finding, ex

    async def dispatch(self, method="PUT", token="Bearer a", **kw):
        """Real registry dispatch: for_finding -> bind_run_context -> validate."""
        reg, run = self.build(**kw)
        finding, ex = self.capture(method, token)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "cross_identity"]
        if not legs:
            return None, run
        async with run:
            result = await legs[0].validate(finding, ex)
        return result, run


class WriteAuthorizationTests(_Fixture):
    async def test_cross_owner_put_persists_is_confirmed_and_restored(self):
        result, run = await self.dispatch()
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertTrue(result.confirmed)
        self.assertEqual(self.server.obj, self.original)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(run.budget.used, 5)
        self.assertEqual(self.server.received, [("GET", "Bearer a"), ("PUT", "Bearer b"),
                         ("GET", "Bearer a"), ("PUT", "Bearer a"), ("GET", "Bearer a")])
        # Strict accounting needs executed baseline/attack/control artifacts.
        self.assertTrue(result.baseline_artifact_id)
        self.assertTrue(result.attack_artifact_id)
        self.assertEqual(len(result.control_artifact_ids), 2)

    async def test_patch_persists_is_confirmed_and_restored(self):
        result, _ = await self.dispatch(method="PATCH")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(self.server.obj, self.original)
        self.assertEqual([m for m, _ in self.server.received], ["GET", "PATCH", "GET", "PATCH", "GET"])

    async def test_denied_write_is_not_confirmed_and_restore_still_runs(self):
        self.server.mode = "denied"
        result, _ = await self.dispatch()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn(("PUT", "Bearer a"), self.server.received, "restore did not run")
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.server.obj, self.original)

    async def test_accepted_but_unchanged_read_back_is_not_confirmed(self):
        self.server.mode = "unchanged"
        result, _ = await self.dispatch()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertIn(("PUT", "Bearer a"), self.server.received, "restore did not run")
        self.assertEqual(self.server.obj, self.original)

    async def test_failed_restore_is_a_loud_error(self):
        self.server.mode = "restore_failed"
        with self.assertLogs("harness.validators.cross_identity_validator", level="ERROR") as logs:
            result, _ = await self.dispatch()
        self.assertEqual(result.status, "error")
        self.assertFalse(result.confirmed)
        self.assertIn("RESTORE FAILED", result.summary)
        self.assertIn("restore_succeeded=false", result.evidence)
        self.assertIn("RESTORE FAILED", "\n".join(logs.output))
        self.assertNotEqual(self.server.obj, self.original)   # the fixture really kept the marker

    async def test_undeclared_shared_object_is_only_a_lead(self):
        result, _ = await self.dispatch(owner="")
        self.assertEqual(result.status, "supported", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(self.server.obj, self.original)

    async def test_object_declared_to_admin_is_confirmed_for_a_low_privilege_writer(self):
        self.server.owner_token = "Bearer z"
        result, _ = await self.dispatch(owner="root", admin=True, token="Bearer z")
        self.assertEqual(result.status, "confirmed", result.summary)
        puts = [who for verb, who in self.server.received if verb == "PUT"]
        self.assertEqual(len(puts), 2)
        self.assertIn(puts[0], {"Bearer a", "Bearer b"}, "the attack must come from a non-admin")
        self.assertEqual(puts[1], "Bearer z", "the admin owner restores")
        self.assertEqual(self.server.obj, self.original)

    async def test_delete_needs_restore_contract(self):
        result, _ = await self.dispatch(method="DELETE")
        self.assertIsNone(result, "DELETE armed without a recreation contract")
        self.assertEqual(self.server.received, [])

    async def test_delete_with_declared_recreation_contract(self):
        result, _ = await self.dispatch(method="DELETE", restore_contract="PUT")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(self.server.obj, self.original)
        self.assertEqual([m for m, _ in self.server.received], ["GET", "DELETE", "GET", "PUT", "GET"])


class WriteGateTests(_Fixture):
    async def test_registry_write_gate_off_does_not_arm_the_leg(self):
        result, _ = await self.dispatch(registry_writes=False)
        self.assertIsNone(result, "a write armed cross_identity with mutating replay off")
        self.assertEqual(self.server.received, [])

    async def test_run_gate_off_skips_and_sends_nothing(self):
        result, _ = await self.dispatch(run_writes=False)
        self.assertEqual(result.status, "skipped")
        self.assertEqual(self.server.received, [])

    async def test_default_single_mutation_ceiling_skips_before_writing(self):
        result, _ = await self.dispatch(ceiling=None)
        self.assertEqual(result.status, "skipped")
        self.assertIn("mutating_ceiling_by_check.cross_identity", result.summary)
        self.assertEqual(self.server.received, [])

    async def test_post_is_still_never_armed(self):
        result, _ = await self.dispatch(method="POST")
        self.assertIsNone(result)
        self.assertEqual(self.server.received, [])


class ConfirmationCallerTests(_Fixture):
    """The production confirmation caller reaches the write leg and persists a
    proof naming executed artifacts; with the write gate off it does not."""

    async def run_caller(self, *, registry_writes=True):
        from harness.orchestrator_confirm import ConfirmMixin
        reg, run = self.build(registry_writes=registry_writes)
        caller = ConfirmMixin()
        caller.config = {"validators": {"active_enabled": True}}
        caller.allowed_hosts = ["127.0.0.1"]
        caller.validator_registry = reg
        reg.validators = {"cross_identity": reg.validators["cross_identity"]}
        finding, ex = self.capture()
        persist = AsyncMock(return_value=(True, {"proof_id": "inert"}, ""))
        with patch.object(caller, "_persist_confirmation_proof", persist), \
             patch("harness.evidence_ledger.emit"):
            async with run:
                validations, _ = await caller._validate_findings(
                    ex, [AgentReport(agent="idor", model="synthetic", findings=[finding])],
                    run_context=run)
        return validations, persist, finding

    async def test_caller_confirms_with_executed_artifacts(self):
        validations, persist, finding = await self.run_caller()
        self.assertEqual([(v.validator, v.status) for v in validations],
                         [("cross_identity", "confirmed")])
        self.assertTrue(finding.confirmed)
        artifacts = persist.await_args.kwargs["proof_artifacts"]
        self.assertTrue(artifacts, "confirmation persisted without executed artifacts")
        self.assertTrue(all(artifacts.values()), artifacts)
        self.assertEqual(self.server.obj, self.original)

    async def test_caller_with_write_gate_off_never_dispatches(self):
        validations, persist, finding = await self.run_caller(registry_writes=False)
        self.assertEqual(validations, [])
        self.assertFalse(finding.confirmed)
        self.assertEqual(self.server.received, [])


if __name__ == "__main__":
    unittest.main()
