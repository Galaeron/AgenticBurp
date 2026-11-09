"""B1-T2: cross_identity write-side authorization leg with mandatory restore.

Every case runs against an owned loopback HTTP fixture (a generic JSON object
store), dispatched through the real registry (for_finding + bind_run_context)
or the real confirmation caller (ConfirmMixin._validate_findings). Only proof
persistence and the evidence ledger are replaced in the caller-level test.
"""
import asyncio
import json
import threading
import time
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
        if self.server.slow_marker_reads and "harness_authz_" in json.dumps(self.server.obj):
            time.sleep(0.3)   # widen the window a concurrent case could read in
        self.reply(200 if self.server.obj else 404, self.server.obj or {})

    def write(self):
        caller = self.headers.get("Authorization")
        self.server.received.append((self.command, caller))
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        self.server.bodies.append((self.command, caller, data))
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
        if self.server.obj is not None and self.server.timestamps:
            self.server.clock += 1   # a server-rewritten (volatile) key
            self.server.obj["updatedAt"] = f"2026-01-01T00:00:{self.server.clock:02d}Z"
        if self.server.obj is not None and not writer and self.server.mode == "restore_corrupts":
            self.server.obj["status"] = "reset-by-server"   # a NON-volatile change
        self.reply(200, self.server.obj or {})

    do_PUT = do_PATCH = do_DELETE = write


class _Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.obj = {"id": 7, "description": "original", "owner": "alice"}
        self.server.mode, self.server.received, self.server.bodies = "vulnerable", [], []
        self.server.timestamps, self.server.clock, self.server.slow_marker_reads = False, 0, False
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

    def capture(self, method="PUT", token="Bearer a", finding_id=""):
        finding = Finding(vulnerability_class="idor", confidence=0.7, summary="write authz",
                          evidence="capture", suggested_test="read back", basis="derived",
                          finding_id=finding_id)
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

    async def test_denied_write_is_not_confirmed_and_sends_no_restore(self):
        # Finding 2a: a denied write changed nothing, so no restore is sent (a
        # full-object restore would rewrite the object from a possibly lossy read).
        self.server.mode = "denied"
        result, _ = await self.dispatch()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertEqual(self.server.received, [("GET", "Bearer a"), ("PUT", "Bearer b"),
                                                ("GET", "Bearer a")])
        self.assertIn("restore=not_needed", result.evidence)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.server.obj, self.original)

    async def test_accepted_but_unchanged_read_back_sends_no_restore(self):
        self.server.mode = "unchanged"
        result, _ = await self.dispatch()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertNotIn(("PUT", "Bearer a"), self.server.received, "restore sent for no change")
        self.assertIn("own record may now hold", result.summary)   # session-scoped write note
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


class RestoreSafetyTests(_Fixture):
    """Review findings 2-4: restore only what changed, refuse lossy baselines,
    verify the whole object minus volatile keys, serialize per object."""

    def writes(self):
        return [(m, who) for m, who in self.server.received if m != "GET"]

    async def test_masked_baseline_refuses_a_put_before_any_write(self):
        for masked in ("********", "[REDACTED]", "\u2022\u2022\u2022\u2022"):
            with self.subTest(masked=masked):
                self.server.received.clear()
                self.server.obj = {**self.original, "secret": masked}
                result, _ = await self.dispatch()
                self.assertEqual(result.status, "skipped", result.summary)
                self.assertIn("not safely round-trippable", result.summary)
                self.assertIn("secret", result.summary)
                self.assertEqual(self.server.received, [("GET", "Bearer a")], "a write was sent")
                self.assertEqual(self.server.obj, {**self.original, "secret": masked})

    async def test_masked_other_field_does_not_block_a_minimal_patch(self):
        # Negative control: PATCH sends only the changed field, so a masked value
        # elsewhere is never written back; the restore carries that field alone.
        self.server.obj = {**self.original, "secret": "********"}
        result, _ = await self.dispatch(method="PATCH")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(self.server.obj, {**self.original, "secret": "********"})
        restore = [d for m, who, d in self.server.bodies if who == "Bearer a"]
        self.assertEqual(restore, [{"description": "original"}])

    async def test_restore_verifies_the_whole_object_not_just_the_field(self):
        # The restore puts the field back but the server rewrites another value:
        # previously reported restore_succeeded=true.
        self.server.mode = "restore_corrupts"
        with self.assertLogs("harness.validators.cross_identity_validator", level="ERROR"):
            result, _ = await self.dispatch()
        self.assertEqual(result.status, "error")
        self.assertIn("RESTORE FAILED", result.summary)
        self.assertIn("restore_succeeded=false", result.evidence)

    async def test_volatile_timestamps_do_not_fail_verification(self):
        # Negative control: only server-rewritten keys differ after the restore.
        self.server.timestamps = True
        self.server.obj["updatedAt"] = "2026-01-01T00:00:00Z"
        result, _ = await self.dispatch()
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.server.obj["description"], "original")

    async def test_denied_delete_sends_no_recreation(self):
        # Finding 3: a protected DELETE (403) used to run the recreation PUT,
        # which bumped updatedAt and reported RESTORE FAILED instead of a negative.
        self.server.mode, self.server.timestamps = "denied", True
        self.server.obj["updatedAt"] = "2026-01-01T00:00:00Z"
        before = dict(self.server.obj)
        result, _ = await self.dispatch(method="DELETE", restore_contract="PUT")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertEqual(self.writes(), [("DELETE", "Bearer b")], "recreation sent for a denied DELETE")
        self.assertEqual(self.server.obj, before)

    async def test_accepted_delete_with_timestamps_is_restored_and_verified(self):
        # Negative control: a DELETE that went through is recreated, and the
        # recreated object verifies despite a fresh updatedAt.
        self.server.timestamps = True
        self.server.obj["updatedAt"] = "2026-01-01T00:00:00Z"
        result, _ = await self.dispatch(method="DELETE", restore_contract="PUT")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.writes(), [("DELETE", "Bearer b"), ("PUT", "Bearer a")])
        self.assertEqual(self.server.obj["description"], "original")

    async def race(self):
        """Two write cases on one object; B starts once A's attack landed."""
        self.server.slow_marker_reads = True
        reg, run = self.build()
        fa, ex = self.capture(finding_id="case-a")
        fb, _ = self.capture(finding_id="case-b")
        leg = [v for v in reg.bind_run_context(reg.for_finding(fa, ex), run)
               if v.name == "cross_identity"][0]

        async def later():
            while ("PUT", "Bearer b") not in self.server.received:
                await asyncio.sleep(0.01)
            return await leg.validate(fb, ex)

        async with run:
            return await asyncio.gather(leg.validate(fa, ex), later())

    async def test_concurrent_cases_on_one_object_are_serialized(self):
        # Finding 4: B must read the true original, not A's marker.
        results = await self.race()
        self.assertEqual([r.status for r in results], ["confirmed", "confirmed"],
                         [r.summary for r in results])
        self.assertEqual(self.server.obj, self.original)

    async def test_race_reproduces_without_the_object_lock(self):
        # Defect injection: with a fresh lock per call the race leaves A's marker.
        from harness.validators import cross_identity_validator as civ
        with patch.object(civ, "_object_lock", side_effect=lambda url: asyncio.Lock()):
            await self.race()
        self.assertIn("harness_authz_", json.dumps(self.server.obj))


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


class ChainConstructionTests(_Fixture):
    """Finding 7: the engagement chain builds its own CrossIdentityValidator. It
    must carry the same write policy as the registry, and with
    allow_mutating_replay false nothing it runs may send a write."""

    async def run_chain(self, *, writes):
        from harness import engagement_builder, missing_auth_probe, worklist_investigator
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.test_chain_coverage_rvm import _chain_config
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        from harness.validators.base import ValidationResult
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        from harness.validators.idor_read_validator import IdorReadValidator

        cfg = _chain_config()
        cfg["validators"]["allow_mutating_replay"] = writes
        cfg["validators"].setdefault("cross_identity", {})["delete_restore_method"] = "PUT"
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _, run = self.build(registry_writes=writes)   # run gate permits writes
        path = "/objects/7"
        node = {"method": "PUT", "path": path, "reachable_roles": ["anonymous"],
                "template": {"method": "PUT", "query": "", "body": '{"description":"x"}',
                             "content_type": "application/json", "object_id": "7"}}
        label = {"vulnerability_class": "idor", "confidence": 0.8, "severity": "high",
                 "summary": "write idor", "evidence": "", "suggested_test": "", "basis": "agent"}

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "PUT", "path": path, "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": True,
                "template": node["template"]}]})
            return state, RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            ex = worklist_investigator._seed_exchange(self.origin + "/", node, {}, "1")
            await kwargs["confirm_fn"](label, ex)
            return [{"path": path, "method": "PUT", "findings_detail": [label], "confirmed": False}]

        built, real_init = [], CrossIdentityValidator.__init__

        def spy(validator, *a, **kw):
            built.append(validator)
            return real_init(validator, *a, **kw)

        skip = AsyncMock(return_value=ValidationResult(validator="x", status="skipped",
                                                       finding_class="x", summary="stub"))
        with patch.object(engagement_builder, "build_engagement", new=build), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=AsyncMock(return_value=0)), \
             patch("harness.orchestrator_chain.universal_header_audit", new=AsyncMock(return_value=0)), \
             patch.object(CrossIdentityValidator, "__init__", spy), \
             patch.object(IdorReadValidator, "validate", new=skip), \
             patch.object(AuthSequenceValidator, "validate", new=skip), \
             patch.object(missing_auth_probe, "probe", new=AsyncMock(side_effect=RuntimeError("stub"))), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            async with run:
                await orch.investigate_engagement(
                    self.origin + "/", [RoleSession("anonymous", {})], max_nodes=1,
                    max_chain_rounds=0, discovery_max_probes=1, run_context=run)
                chain = [v for v in built if v.run_context is run]
                self.assertEqual(len(chain), 1, "chain validator not built with this run")
                # The chain's own validator, given a captured PUT directly.
                finding, ex = self.capture()
                direct = await chain[0].validate(finding, ex)
        return chain[0], direct

    async def test_chain_validator_with_mutating_replay_off_sends_no_write(self):
        xval, direct = await self.run_chain(writes=False)
        self.assertFalse(xval.allow_writes)
        self.assertEqual(xval.delete_restore_method, "PUT")
        self.assertFalse(xval.write_admitted("PUT"))
        self.assertEqual(direct.status, "skipped", direct.summary)
        self.assertEqual([m for m, _ in self.server.received if m != "GET"], [],
                         "the chain path sent a write with mutating replay off")
        self.assertEqual(self.server.obj, self.original)

    async def test_chain_validator_with_mutating_replay_on_matches_the_registry(self):
        # Negative control: the same chain validator, permitted, does run the leg.
        xval, direct = await self.run_chain(writes=True)
        self.assertTrue(xval.allow_writes)
        self.assertTrue(xval.write_admitted("PUT") and xval.write_admitted("DELETE"))
        # The chain's own ownership ledger does not carry this test's declaration,
        # so a persisted write is a lead here; the point is that the leg ran.
        self.assertIn(direct.status, {"confirmed", "supported"}, direct.summary)
        self.assertIn(("PUT", "Bearer b"), self.server.received)
        self.assertEqual(self.server.obj, self.original)


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
