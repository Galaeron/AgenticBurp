"""r7 follow-ups to the cross_identity write-authorization leg (B1-T2).

The 8-hour r7 run sent no cross_identity write at all. These tests pin the four
fixes against an owned, generic loopback JSON object store (the fixture of
test_b1_write_authz), each through a real dispatch path with a negative control:

1. the engagement chain's confirmation dispatch refused every non-GET
   access-control finding ("replay GET reads only") before cross_identity saw it;
2. a write whose only eligible fields are numbers/booleans was refused;
3. an owner read wrapped in a {"status": ..., "data": {...}} envelope was refused;
4. the write leg's restore outcome is recorded on the run's change log.
"""
import json
import unittest
from unittest.mock import AsyncMock, patch

from harness import principals
from harness.models import Finding, HttpExchange
from harness.run_handoff import RESTORED, RESTORE_FAILED, RESTORE_SEND
from harness.test_b1_write_authz import _Fixture, _Handler
from harness.validators.cross_identity_validator import (
    _choose_write_field, _protected_field, _unwrap_envelope)


class _EnvelopeHandler(_Handler):
    """The same store, but reads come back inside a response envelope."""

    def reply(self, status, obj):
        if self.command == "GET" and status == 200:
            shape = self.server.envelope
            obj = {"status": "success", "data": [obj] if shape == "list" else obj}
        super().reply(status, obj)


class _Base(_Fixture, unittest.IsolatedAsyncioTestCase):
    # The explicit base lets the static test-discovery guards see these as cases.
    def capture_body(self, body: dict, method="PUT", token="Bearer a"):
        finding = Finding(vulnerability_class="idor", confidence=0.7, summary="write authz",
                          evidence="capture", suggested_test="read back", basis="derived")
        ex = HttpExchange(url=self.url, method=method, request_body=json.dumps(body),
                          request_headers={"Authorization": token,
                                           "Content-Type": "application/json"})
        return finding, ex

    async def dispatch_body(self, body: dict, method="PUT", **kw):
        """Real registry dispatch: for_finding -> bind_run_context -> validate."""
        reg, run = self.build(**kw)
        finding, ex = self.capture_body(body, method)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "cross_identity"]
        self.assertTrue(legs, "cross_identity was not dispatched for the captured write")
        async with run:
            result = await legs[0].validate(finding, ex)
        return result, run

    def set_object(self, obj: dict):
        self.server.obj = dict(obj)
        self.original = dict(obj)

    def writes(self):
        return [(m, who) for m, who in self.server.received if m != "GET"]


class ChainDispatchTests(_Base):
    """Task 1. r7 root cause: orchestrator_chain._access_control_shape_gap returned
    'cross-identity and idor-read replay GET reads only; this is a PUT request' for
    every write, so the chain's confirm_fn recorded no_applicable_leg and never
    called cross_identity, whatever allow_mutating_replay said."""

    async def run_chain_confirm(self, *, writes):
        from harness import engagement_builder, missing_auth_probe, worklist_investigator
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.test_chain_coverage_rvm import _chain_config
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        from harness.validators.base import ValidationResult
        from harness.validators.idor_read_validator import IdorReadValidator

        cfg = _chain_config()
        cfg["validators"]["allow_mutating_replay"] = writes
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _, run = self.build(registry_writes=writes)   # the run gate permits writes
        path = "/objects/7"
        node = {"method": "PUT", "path": path, "reachable_roles": ["anonymous"],
                "template": {"method": "PUT", "query": "", "body": '{"description":"x"}',
                             "content_type": "application/json", "object_id": "7"}}
        label = {"vulnerability_class": "Broken Object Level Authorization (BOLA)",
                 "confidence": 0.8, "severity": "high", "summary": "write bola",
                 "evidence": "", "suggested_test": "", "basis": "agent"}
        sent_by_confirm = []

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "PUT", "path": path, "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": True,
                "template": node["template"]}]})
            return state, RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            # The agent's finding on a write captured as the object's owner.
            ex = worklist_investigator._seed_exchange(
                self.origin + "/", node, {"Authorization": "Bearer a"}, "1")
            before = len(self.server.received)
            await kwargs["confirm_fn"](label, ex)
            sent_by_confirm.extend(self.server.received[before:])
            return [{"path": path, "method": "PUT", "findings_detail": [label], "confirmed": False}]

        skip = AsyncMock(return_value=ValidationResult(validator="x", status="skipped",
                                                       finding_class="x", summary="stub"))
        with patch.object(engagement_builder, "build_engagement", new=build), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=AsyncMock(return_value=0)), \
             patch("harness.orchestrator_chain.universal_header_audit", new=AsyncMock(return_value=0)), \
             patch.object(IdorReadValidator, "validate", new=skip), \
             patch.object(AuthSequenceValidator, "validate", new=skip), \
             patch.object(missing_auth_probe, "probe", new=AsyncMock(side_effect=RuntimeError("stub"))), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            async with run:
                await orch.investigate_engagement(
                    self.origin + "/", [RoleSession("anonymous", {})], max_nodes=1,
                    max_chain_rounds=0, discovery_max_probes=1, run_context=run)
        return label, sent_by_confirm, run

    async def test_write_bola_finding_arms_the_write_leg_through_confirm_fn(self):
        label, sent, run = await self.run_chain_confirm(writes=True)
        self.assertNotEqual(label.get("leg_disposition"), "no_applicable_leg",
                            label.get("leg_disposition_reason"))
        self.assertIn(("PUT", "Bearer b"), sent, "the chain dispatch sent no cross-principal write")
        self.assertIn(("PUT", "Bearer a"), sent, "the owner restore was not sent")
        self.assertEqual(self.server.obj, self.original)
        statuses = [e["restore_status"] for e in run.change_log.entries()
                    if e["capability"] == "cross_identity"]
        self.assertIn(RESTORED, statuses)

    async def test_with_mutating_replay_off_the_chain_sends_no_write(self):
        label, sent, _ = await self.run_chain_confirm(writes=False)
        self.assertEqual([m for m, _ in sent if m != "GET"], [])
        self.assertEqual(self.writes(), [], "a write was sent with mutating replay off")
        self.assertEqual(label.get("leg_disposition"), "no_applicable_leg")
        self.assertIn("allow_mutating_replay", label.get("leg_disposition_reason", ""))
        self.assertEqual(self.server.obj, self.original)

    def test_shape_gap_unit_contract(self):
        from harness.orchestrator_chain import _access_control_shape_gap
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        put = HttpExchange(url=self.url, method="PUT")
        self.assertEqual(_access_control_shape_gap(put, CrossIdentityValidator(allow_writes=True)), "")
        self.assertIn("allow_mutating_replay",
                      _access_control_shape_gap(put, CrossIdentityValidator(allow_writes=False)))
        self.assertIn("allow_mutating_replay", _access_control_shape_gap(put))
        post = HttpExchange(url=self.url, method="POST")
        self.assertIn("GET reads only",
                      _access_control_shape_gap(post, CrossIdentityValidator(allow_writes=True)))


class NumericFieldTests(_Base):
    """Task 2: a number or boolean is a restorable mutation target when no string
    qualifies; identifiers, foreign keys, owner refs, roles and secrets never are."""

    async def test_numeric_only_write_is_confirmed_and_restored(self):
        self.set_object({"id": 7, "quantity": 2, "productId": 3, "basket_id": 4,
                         "owner": "alice"})
        result, run = await self.dispatch_body({"id": 7, "quantity": 5, "productId": 3})
        self.assertEqual(result.status, "confirmed", result.summary)
        attack = [b for m, who, b in self.server.bodies if who == "Bearer b"]
        self.assertEqual(len(attack), 1)
        self.assertEqual(attack[0]["quantity"], 3, "the number was not moved to a distinct value")
        self.assertEqual((attack[0]["id"], attack[0]["productId"], attack[0]["basket_id"]),
                         (7, 3, 4), "an identifier or foreign key was mutated")
        self.assertIn(("PUT", "Bearer a"), self.writes(), "no restore was sent")
        self.assertEqual(self.server.obj, self.original)
        self.assertIn("restore_succeeded=true", result.evidence)

    async def test_boolean_only_patch_is_flipped_and_restored(self):
        self.set_object({"id": 7, "archived": False, "owner": "alice"})
        result, _ = await self.dispatch_body({"archived": True}, method="PATCH")
        self.assertEqual(result.status, "confirmed", result.summary)
        attack = [b for m, who, b in self.server.bodies if who == "Bearer b"]
        self.assertEqual(attack, [{"archived": True}])
        self.assertEqual(self.server.obj, self.original)

    async def test_string_field_is_still_preferred(self):
        self.set_object({"id": 7, "quantity": 2, "note": "hi", "owner": "alice"})
        result, _ = await self.dispatch_body({"quantity": 5, "note": "x"})
        self.assertEqual(result.status, "confirmed", result.summary)
        attack = [b for m, who, b in self.server.bodies if who == "Bearer b"][0]
        self.assertTrue(attack["note"].startswith("harness_authz_"))
        self.assertEqual(attack["quantity"], 2)
        self.assertEqual(self.server.obj, self.original)

    async def test_id_foreign_key_and_role_only_write_is_refused_before_sending(self):
        # Control: nothing outside the fixed denylist -> refused, nothing written.
        self.set_object({"id": 7, "productId": 3, "basket_id": 4, "role": "customer",
                         "isAdmin": False, "userId": 9, "owner": "alice"})
        result, _ = await self.dispatch_body(
            {"id": 7, "productId": 8, "basket_id": 5, "role": "admin", "isAdmin": True, "userId": 1})
        self.assertEqual(result.status, "skipped")
        self.assertIn("No restorable field", result.summary)
        self.assertEqual(self.writes(), [], "a write was sent for a denylisted-only body")
        self.assertEqual(self.server.obj, self.original)

    def test_fixed_denylist(self):
        for key in ("id", "ID", "productId", "basket_id", "BasketId", "userID", "uuid",
                    "owner", "ownerId", "user", "UserId", "createdBy", "role", "roles",
                    "isAdmin", "permissions", "password", "totpSecret", "apiKey",
                    "accessToken", "email", "username", "tenant"):
            self.assertTrue(_protected_field(key), key)
        for key in ("quantity", "price", "description", "archived", "paid", "valid", "rating",
                    "shipping", "keyword"):
            self.assertFalse(_protected_field(key), key)
        self.assertIsNone(_choose_write_field({"id": 1, "role": "x"}, {"id": 1, "role": "y"}))
        self.assertIsNone(_choose_write_field({"meta": {}}, {"meta": {"a": 1}}),
                          "a nested value is not a scalar mutation target")


class OwnerEnvelopeTests(_Base):
    """Task 3. r7: the target answered owner reads as {"status": "success",
    "data": {...}}; the leg only unwrapped one-member dicts, so every such write
    was refused with 'Owner baseline did not return a restorable JSON object'."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server.RequestHandlerClass = _EnvelopeHandler

    async def test_single_object_envelope_is_unwrapped(self):
        self.server.envelope = "object"
        result, run = await self.dispatch_body({"description": "captured"})
        self.assertEqual(result.status, "confirmed", result.summary)
        attack = [b for m, who, b in self.server.bodies if who == "Bearer b"][0]
        self.assertNotIn("status", attack, "the envelope, not the object, was written")
        self.assertEqual(attack["id"], 7)
        self.assertEqual(self.server.obj, self.original)

    async def test_list_envelope_is_still_refused(self):
        self.server.envelope = "list"
        result, _ = await self.dispatch_body({"description": "captured"})
        self.assertEqual(result.status, "skipped")
        self.assertIn("Owner baseline did not return a restorable JSON object", result.summary)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.server.obj, self.original)

    def test_unwrap_contract(self):
        obj = {"id": 1, "name": "n"}
        self.assertEqual(_unwrap_envelope({"status": "success", "data": obj}), obj)
        self.assertEqual(_unwrap_envelope({"data": obj}), obj)
        self.assertIsNone(_unwrap_envelope({"status": "success", "data": [obj]}))
        # A real object with one nested sub-object is not an envelope.
        nested = {"id": 1, "name": "n", "address": {"city": "c"}}
        self.assertEqual(_unwrap_envelope(nested), nested)
        self.assertEqual(_unwrap_envelope({"id": 1, "data": {"x": 1}, "meta": {"y": 2}}),
                         {"id": 1, "data": {"x": 1}, "meta": {"y": 2}})


class RestoreRecordingTests(_Base):
    """Task 4: each write-leg restore is recorded via run_handoff.mark_restore."""

    def leg_entries(self, run):
        return [e for e in run.change_log.entries() if e["capability"] == "cross_identity"]

    async def test_successful_restore_is_recorded_restored(self):
        result, run = await self.dispatch_body({"description": "captured"})
        self.assertEqual(result.status, "confirmed", result.summary)
        by_status = {e["restore_status"] for e in self.leg_entries(run)}
        self.assertIn(RESTORED, by_status)
        self.assertIn(RESTORE_SEND, by_status, "the restore send was not marked as a cleanup")
        self.assertEqual(run.change_log.failed_restores(), [])

    async def test_failed_restore_is_recorded_restore_failed(self):
        # Control: the owner's restore is refused by the server.
        self.server.mode = "restore_failed"
        with self.assertLogs("harness.run_handoff", level="ERROR"):
            result, run = await self.dispatch_body({"description": "captured"})
        self.assertEqual(result.status, "error")
        failed = run.change_log.failed_restores()
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["capability"], "cross_identity")
        self.assertIn("NOT verified", failed[0]["restore_detail"])
        self.assertNotIn(RESTORED, {e["restore_status"] for e in self.leg_entries(run)})

    async def test_denied_write_records_nothing_to_restore(self):
        self.server.mode = "denied"
        result, run = await self.dispatch_body({"description": "captured"})
        self.assertEqual(result.status, "not_confirmed")
        self.assertEqual(self.leg_entries(run), [], "a denied write has no change to record")


if __name__ == "__main__":
    unittest.main()
