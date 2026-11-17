"""write_integrity: the five write-path flaw classes, each against an owned
loopback JSON store.

Every case runs through the real registry (for_finding + bind_run_context) or the
real confirmation caller (ConfirmMixin._validate_findings), over real HTTP, with a
RunContext whose gate admits the writes. The store is generic: collections under
/api/<name>, items under /api/<name>/<id>, every answer in a {"data": ...}
envelope. Each confirmation has its negative control on the same store with the
matching rule switched on (ownership enforced, author bound to the session, range
checked, privileged fields ignored, create validated), and every test checks what
was left behind: the store holds only its seed objects again, and the run's change
log records each create as restored.
"""
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

from harness import principals
from harness.models import AgentReport, Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators.registry import ValidatorRegistry

_EMAIL = {"Bearer a": "alice@example.test", "Bearer b": "bob@example.test"}
_ALLOWED_ACCOUNT_FIELDS = {"email", "password", "name"}


def _seed():
    return {
        "lists": {1: {"id": 1, "name": "alice's list"}, 2: {"id": 2, "name": "bob's list"}},
        "items": {10: {"id": 10, "listId": 1, "name": "seed", "quantity": 3}},
        "notes": {}, "accounts": {},
    }


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
        if len(parts) < 2 or parts[0] != "api" or parts[1] not in self.server.data:
            return None, None
        oid = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        return parts[1], oid

    def caller(self):
        return self.headers.get("Authorization") or ""

    def public(self, coll, obj):
        return {k: v for k, v in obj.items() if k != "password"}

    def do_GET(self):
        coll, oid = self.route()
        self.server.received.append(("GET", self.path, self.caller()))
        if coll is None:
            return self.reply(404, {"error": "no route"})
        objs = self.server.data[coll]
        if oid is None:
            return self.reply(200, {"status": "success",
                                    "data": [self.public(coll, o) for o in objs.values()]})
        if oid not in objs:
            return self.reply(404, {"error": "not found"})
        return self.reply(200, {"status": "success", "data": self.public(coll, objs[oid])})

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")

    def rules(self, coll, data, objs, oid=None):
        """The patched store's checks; None when the write passes."""
        modes, who = self.server.modes, self.caller()
        if "enforce_owner" in modes:
            for key, value in data.items():
                m = re.fullmatch(r"([a-z]+)Id", key)
                ref = self.server.data.get((m.group(1) + "s") if m else "", {})
                if m and ref and self.server.owners.get((m.group(1) + "s", value)) != who:
                    return 403, {"error": "not your " + m.group(1)}
        if "check_range" in modes:
            for key in ("quantity", "rating", "price"):
                if key in data and (not isinstance(data[key], (int, float)) or data[key] <= 0
                                    or (key == "rating" and data[key] > 5)):
                    return 400, {"error": key + " out of range"}
        if "validate" in modes:
            if any(isinstance(v, str) and not v for v in data.values()):
                return 400, {"error": "empty field"}
            if "email" in data and any(o.get("email") == data["email"] and o["id"] != oid
                                       for o in objs.values()):
                return 409, {"error": "duplicate"}
        return None

    def shape(self, coll, data):
        modes, who = self.server.modes, self.caller()
        if coll == "accounts":
            base = {"role": "customer"}
            if "ignore_roles" in modes:
                data = {k: v for k, v in data.items() if k in _ALLOWED_ACCOUNT_FIELDS}
            data = {**base, **data}
        if coll == "notes" and "bind_author" in modes:
            data = {**data, "author": _EMAIL.get(who, "")}
        return data

    def do_POST(self):
        coll, oid = self.route()
        data = self.body()
        self.server.received.append(("POST", self.path, self.caller()))
        self.server.bodies.append(data)
        if coll is None or oid is not None:
            return self.reply(404, {"error": "no route"})
        objs = self.server.data[coll]
        refused = self.rules(coll, data, objs)
        if refused:
            return self.reply(*refused)
        new_id = self.server.next_id
        self.server.next_id += 1
        obj = {**self.shape(coll, data), "id": new_id}
        objs[new_id] = obj
        self.server.owners[(coll, new_id)] = self.caller()
        return self.reply(201, {"status": "success", "data": self.public(coll, obj)})

    def update(self):
        coll, oid = self.route()
        data = self.body()
        self.server.received.append((self.command, self.path, self.caller()))
        if coll is None or oid not in self.server.data.get(coll, {}):
            return self.reply(404, {"error": "not found"})
        objs = self.server.data[coll]
        refused = self.rules(coll, data, objs, oid)
        if refused:
            return self.reply(*refused)
        if self.command == "PUT":
            objs[oid] = {**data, "id": oid}
        else:
            objs[oid].update(data)
        return self.reply(200, {"status": "success", "data": self.public(coll, objs[oid])})

    do_PUT = do_PATCH = update

    def do_DELETE(self):
        coll, oid = self.route()
        self.server.received.append(("DELETE", self.path, self.caller()))
        if coll is None or oid not in self.server.data.get(coll, {}):
            return self.reply(404, {"error": "not found"})
        if "fake_delete" not in self.server.modes:
            del self.server.data[coll][oid]
        return self.reply(200, {"status": "success"})


_RESTORE_ROUTES = ["DELETE /api/items/{id}", "DELETE /api/notes/{id}", "DELETE /api/accounts/{id}"]


class _Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Store)
        self.server.data, self.server.next_id = _seed(), 100
        self.server.owners = {("lists", 1): "Bearer a", ("lists", 2): "Bearer b",
                              ("items", 10): "Bearer a"}
        self.server.modes, self.server.received, self.server.bodies = set(), [], []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.runs = []

    async def asyncTearDown(self):
        for run in self.runs:
            await run.aclose()
        self.server.shutdown()
        self.server.server_close()

    def build(self, *, run_writes=True, registry_writes=True, ceiling=8,
              restore_routes=tuple(_RESTORE_ROUTES)):
        cfg = {"validators": {"active_enabled": True, "allow_mutating_replay": registry_writes,
                              "write_integrity": {"enabled": True,
                                                  "restore_routes": list(restore_routes)}},
               "server": {"allowed_hosts": ["127.0.0.1"]}}
        gate = {"active_enabled": True, "allow_mutating_replay": run_writes}
        if ceiling is not None:
            gate["mutating_ceiling_by_check"] = {"write_integrity": ceiling}
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=80, config=cfg,
                                gate_config=gate)
        self.runs.append(run)
        origins = [self.origin]
        run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=origins)
        run.sessions.register("b", "bob", {"Authorization": "Bearer b"}, allowed_origins=origins)
        reg = ValidatorRegistry(cfg)
        ledger = principals.OwnershipLedger()
        ledger.declare(self.origin + "/api/lists/1", owner="alice")
        ledger.declare(self.origin + "/api/lists/2", owner="bob")
        reg.set_ownership(ledger)
        return reg, run

    def capture(self, cls, path, body, method="POST"):
        finding = Finding(vulnerability_class=cls, confidence=0.7, summary="write check",
                          evidence="capture", suggested_test="read back", basis="derived")
        ex = HttpExchange(url=self.origin + path, method=method, request_body=json.dumps(body),
                          request_headers={"Authorization": "Bearer a",
                                           "Content-Type": "application/json"})
        return finding, ex

    async def dispatch(self, cls, path, body, method="POST", **kw):
        """Real registry dispatch: for_finding -> bind_run_context -> validate."""
        reg, run = self.build(**kw)
        finding, ex = self.capture(cls, path, body, method)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        self.assertTrue(legs, f"registry did not route {cls} to write_integrity")
        async with run:
            result = await legs[0].validate(finding, ex)
        return result, run

    # -- what was left behind ------------------------------------------------------

    def writes(self):
        return [(m, p) for m, p, _ in self.server.received if m != "GET"]

    def assert_store_restored(self):
        self.assertEqual(self.server.data, _seed(), "the store was not returned to its seed state")

    def assert_creates_restored(self, run):
        posts = [e for e in run.change_log.entries()
                 if e["capability"] == "write_integrity" and e["method"] == "POST"]
        self.assertTrue(posts, "no create was recorded in the change log")
        self.assertEqual({e["restore_status"] for e in posts}, {"restored"}, posts)
        self.assertEqual(run.change_log.failed_restores(), [])


# The captured creates (a generic store's shapes; nothing application-specific).
_ITEM = {"listId": 1, "name": "pen", "quantity": 2}
_NOTE = {"author": "alice@example.test", "text": "hello"}
_ACCOUNT = {"email": "new@example.test", "password": "pw-123456", "name": "Newcomer"}


class CrossIdentityWriteTests(_Fixture):
    async def test_reference_to_another_principals_object_is_confirmed_and_deleted(self):
        result, run = await self.dispatch("cross_identity_write", "/api/items", _ITEM)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("listId", result.summary)
        self.assertIn("other=bob", result.evidence)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertTrue(result.baseline_artifact_id and result.attack_artifact_id)
        self.assertTrue(result.control_artifact_ids)
        # The attack really carried bob's list; the control carried alice's own.
        self.assertEqual([b.get("listId") for b in self.server.bodies], [1, 2])
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_ownership_enforced_is_a_held_control(self):
        self.server.modes.add("enforce_owner")
        result, run = await self.dispatch("cross_identity_write", "/api/items", _ITEM)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("HTTP 403", result.summary)
        self.assert_store_restored()
        self.assert_creates_restored(run)


class ForgedAuthorshipTests(_Fixture):
    async def test_client_set_author_is_confirmed_and_deleted(self):
        result, run = await self.dispatch("forged_authorship", "/api/notes", _NOTE)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("author", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_author_bound_to_session_is_a_held_control(self):
        self.server.modes.add("bind_author")
        result, run = await self.dispatch("forged_authorship", "/api/notes", _NOTE)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("alice@example.test", result.summary)
        self.assert_store_restored()
        self.assert_creates_restored(run)


class BusinessRuleTamperTests(_Fixture):
    async def test_negative_quantity_on_create_is_confirmed_and_deleted(self):
        result, run = await self.dispatch("business_rule_tamper", "/api/items", _ITEM)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("quantity=-1", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_range_checked_create_is_a_held_control(self):
        self.server.modes.add("check_range")
        result, run = await self.dispatch("business_rule_tamper", "/api/items", _ITEM)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("HTTP 400", result.summary)
        self.assert_store_restored()

    async def test_negative_quantity_on_update_is_confirmed_and_restored(self):
        result, run = await self.dispatch("business_rule_tamper", "/api/items/10",
                                          {"listId": 1, "name": "seed", "quantity": 3}, method="PUT")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual([m for m, _ in self.writes()], ["PUT", "PUT", "PUT"])
        self.assert_store_restored()
        entries = [e for e in run.change_log.entries() if e["capability"] == "write_integrity"
                   and e["restore_status"] != "restore_send"]
        self.assertEqual({e["restore_status"] for e in entries}, {"restored"}, entries)

    async def test_range_checked_update_is_a_held_control_and_restored(self):
        self.server.modes.add("check_range")
        result, run = await self.dispatch("business_rule_tamper", "/api/items/10",
                                          {"listId": 1, "name": "seed", "quantity": 3}, method="PUT")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assert_store_restored()

    async def test_coupon_only_create_is_skipped_without_a_write(self):
        result, _ = await self.dispatch("business_rule_tamper", "/api/items",
                                        {"listId": 1, "name": "pen", "couponCode": "SPENT10"})
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("discount-code", result.summary)
        self.assertEqual(self.writes(), [])


class MassAssignmentCreateTests(_Fixture):
    async def test_role_on_registration_is_confirmed_by_read_back_and_deleted(self):
        result, run = await self.dispatch("mass_assignment_create", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("role", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_role_field_ignored_is_a_held_control(self):
        self.server.modes.add("ignore_roles")
        result, run = await self.dispatch("mass_assignment_create", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_plain_mass_assignment_class_on_a_create_routes_here(self):
        result, _ = await self.dispatch("mass_assignment", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assert_store_restored()


class CreateValidationTests(_Fixture):
    async def test_duplicate_and_empty_registrations_are_confirmed_and_deleted(self):
        result, run = await self.dispatch("create_validation", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("duplicate", result.summary)
        self.assertIn("empty", result.summary)
        self.assertEqual(len([m for m, _ in self.writes() if m == "POST"]), 4)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_validating_server_is_a_held_control(self):
        self.server.modes.add("validate")
        result, run = await self.dispatch("create_validation", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("duplicate was refused", result.summary)
        self.assert_store_restored()
        self.assert_creates_restored(run)


class RefusalTests(_Fixture):
    """Every refusal happens before the first write, and says why."""

    async def test_no_restore_route_skips_without_a_write(self):
        result, _ = await self.dispatch("mass_assignment_create", "/api/accounts", _ACCOUNT,
                                        restore_routes=())
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("no restore path known", result.summary)
        self.assertIn("DELETE /api/accounts/{id}", result.summary)
        self.assertEqual(self.writes(), [])

    async def test_restore_route_learned_from_the_route_inventory(self):
        # The chain hands the validator its observed routes; no operator declaration.
        reg, run = self.build(restore_routes=())
        finding, ex = self.capture("mass_assignment_create", "/api/accounts", _ACCOUNT)
        leg = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
               if v.name == "write_integrity"][0]
        leg.route_inventory = lambda: ["GET /api/accounts", "DELETE /api/accounts/{id}"]
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assert_store_restored()

    async def test_write_gate_off_skips_without_a_request(self):
        result, _ = await self.dispatch("mass_assignment_create", "/api/accounts", _ACCOUNT,
                                        run_writes=False)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("allow_mutating_replay", result.summary)
        self.assertEqual(self.server.received, [])

    async def test_insufficient_write_ceiling_skips_without_a_write(self):
        # Create validation needs four creates and four verified deletes.
        result, _ = await self.dispatch("create_validation", "/api/accounts", _ACCOUNT, ceiling=4)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("need 8 mutating sends", result.summary)
        self.assertEqual(self.writes(), [])

    async def test_unregistered_credentials_skip_without_a_write(self):
        reg, run = self.build()
        finding, ex = self.capture("mass_assignment_create", "/api/accounts", _ACCOUNT)
        ex = ex.model_copy(update={"request_headers": {"Authorization": "Bearer stranger",
                                                       "Content-Type": "application/json"}})
        leg = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
               if v.name == "write_integrity"][0]
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("no registered session", result.summary)
        self.assertEqual(self.server.received, [])

    async def test_update_class_other_than_tamper_needs_a_create(self):
        result, _ = await self.dispatch("mass_assignment_create", "/api/items/10",
                                        {"listId": 1, "name": "seed", "quantity": 3}, method="PUT")
        # A PUT is not a create: only business-rule tampering has an update path.
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("needs a POST create", result.summary)
        self.assertEqual(self.writes(), [])

    async def test_registry_with_mutating_replay_off_routes_no_write_leg(self):
        reg, run = self.build(registry_writes=False)
        finding, ex = self.capture("mass_assignment_create", "/api/accounts", _ACCOUNT)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        self.assertEqual(legs, [])
        # A direct call on the unpermitted leg refuses too, before any request.
        leg = reg.validators["write_integrity"]
        leg.run_context = run
        async with run:
            result = await leg.validate(finding, ex)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(self.server.received, [])


class RestoreFailureTests(_Fixture):
    async def test_failed_delete_is_a_loud_error_and_no_attack_is_sent(self):
        self.server.modes.add("fake_delete")
        with self.assertLogs("harness.validators.write_integrity_validator", "ERROR") as logs:
            result, run = await self.dispatch("mass_assignment_create", "/api/accounts", _ACCOUNT)
        self.assertEqual(result.status, "error", result.summary)
        self.assertTrue(result.summary.startswith("RESTORE FAILED"), result.summary)
        self.assertIn("remove it manually", result.summary)
        self.assertIn("restore_succeeded=false", result.evidence)
        self.assertTrue(any("RESTORE FAILED" in line for line in logs.output))
        # Only the control was created: a broken restore path stops the attack.
        self.assertEqual(len([m for m, _ in self.writes() if m == "POST"]), 1)
        failed = run.change_log.failed_restores()
        self.assertTrue(failed and all(e["capability"] == "write_integrity" for e in failed), failed)


class CapabilityTests(_Fixture):
    """The coverage drive's readiness for the five write-path cells (no I/O)."""

    def test_cells_are_ready_with_write_permission_and_denied_without(self):
        from harness.coverage_model import CHECKS_BY_ID
        reg, run = self.build()
        _, create = self.capture("x", "/api/accounts", _ACCOUNT)
        _, update = self.capture("x", "/api/items/10", {"quantity": 3}, method="PUT")
        cells = {"AV-WRITE-XID-01": "cross_identity_write", "AV-WRITE-AUTHOR-01": "forged_authorship",
                 "AV-WRITE-BIZ-01": "business_rule_tamper", "AV-MASSASSIGN-02": "mass_assignment_create",
                 "AV-WRITE-VALID-01": "create_validation"}
        for check_id, kind in cells.items():
            check = CHECKS_BY_ID[check_id]
            self.assertEqual(check.confirmation, "write_integrity")
            got = reg.capability_for_check(check, create, run_context=run)
            self.assertEqual((got["status"], got["mechanism_id"]), ("ready", "write_integrity." + kind),
                             check_id)
            on_update = reg.capability_for_check(check, update, run_context=run)
            # Business-rule tampering and forged authorship have an update path
            # (snapshot, write, read back, write the snapshot back).
            self.assertEqual(on_update["status"],
                             "ready" if kind in ("business_rule_tamper", "forged_authorship")
                             else "unsupported", check_id)
        _, denied_run = self.build(run_writes=False)
        denied = reg.capability_for_check(CHECKS_BY_ID["AV-MASSASSIGN-02"], create,
                                          run_context=denied_run)
        self.assertEqual(denied["status"], "policy_denied")


class ChainRoutingTests(unittest.TestCase):
    def ex(self, method, path, body):
        return HttpExchange(url="http://127.0.0.1:1" + path, method=method,
                            request_body=json.dumps(body))

    def test_chain_routes_creates_and_tamperable_business_findings(self):
        from harness.validators.write_integrity_validator import chain_routes
        self.assertTrue(chain_routes("mass_assignment", self.ex("POST", "/api/accounts", _ACCOUNT)))
        self.assertFalse(chain_routes("mass_assignment", self.ex("PUT", "/api/accounts/1", _ACCOUNT)))
        self.assertTrue(chain_routes("business_logic", self.ex("POST", "/api/items", _ITEM)))
        # An integer price the client sends stays with client_trust.
        self.assertFalse(chain_routes("business_logic",
                                      self.ex("POST", "/api/orders", {"price": 1000, "quantity": 1})))
        self.assertTrue(chain_routes("forged_authorship", self.ex("POST", "/api/notes", _NOTE)))
        self.assertFalse(chain_routes("xss", self.ex("POST", "/api/notes", _NOTE)))

    def test_new_classes_are_provisional_until_confirmed(self):
        from harness.confirmation_gate import PROVISIONAL_MARKERS
        for kind in ("cross_identity_write", "forged_authorship", "business_rule_tamper",
                     "mass_assignment_create", "create_validation"):
            self.assertTrue(any(m in kind for m in PROVISIONAL_MARKERS), kind)


class SequenceHandoffTests(_Fixture):
    async def test_sequence_hands_a_collection_create_to_write_integrity_without_writing(self):
        from harness.validators.sequence_validator import SequenceValidator
        finding, ex = self.capture("mass_assignment", "/api/accounts", _ACCOUNT)
        result = await SequenceValidator(allowed_hosts=["127.0.0.1"]).validate(finding, ex)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("handed to write_integrity", result.summary)
        self.assertEqual(self.writes(), [])

    def test_an_object_with_a_list_field_is_not_a_collection(self):
        from harness.validators.sequence_validator import _lists_a_collection
        self.assertTrue(_lists_a_collection({"status": "success", "data": [{"id": 1}]}))
        self.assertTrue(_lists_a_collection({"data": []}))
        self.assertFalse(_lists_a_collection({"id": 1, "items": [{"id": 2}]}))
        self.assertFalse(_lists_a_collection({"data": {"id": 1}, "tags": []}))
        self.assertFalse(_lists_a_collection({"name": "me", "tags": ["a", "b"]}))


class ChainCallerTests(_Fixture):
    """The engagement chain's _confirm hands a write-path finding on a captured
    create to its own write_integrity leg, with the registry's write policy."""

    async def run_chain(self, cls, *, writes):
        from harness import engagement_builder, missing_auth_probe, worklist_investigator
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.test_chain_coverage_rvm import _chain_config
        from harness.validators.write_integrity_validator import WriteIntegrityValidator

        cfg = _chain_config()
        cfg["validators"]["allow_mutating_replay"] = writes
        cfg["validators"]["write_integrity"] = {"enabled": True, "restore_routes": _RESTORE_ROUTES}
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _, run = self.build()   # the run gate permits writes; the chain's policy decides
        path = "/api/accounts"
        template = {"method": "POST", "query": "", "body": json.dumps(_ACCOUNT),
                    "content_type": "application/json", "object_id": None}
        node = {"method": "POST", "path": path, "reachable_roles": ["anonymous"], "template": template}
        label = {"vulnerability_class": cls, "confidence": 0.8, "severity": "high",
                 "summary": "privileged field on registration", "evidence": "",
                 "suggested_test": "", "basis": "agent"}

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "POST", "path": path, "by_role": {"anonymous": 201},
                "reachable_roles": ["anonymous"], "template": template}]})
            return state, RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            ex = worklist_investigator._seed_exchange(self.origin + "/", node, {}, "1")
            await kwargs["confirm_fn"](label, ex)
            return [{"path": path, "method": "POST", "findings_detail": [label], "confirmed": False}]

        seen, real_validate = [], WriteIntegrityValidator.validate

        async def spy(validator, finding, exchange):
            result = await real_validate(validator, finding, exchange)
            seen.append((validator, result))
            return result

        with patch.object(engagement_builder, "build_engagement", new=build), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=AsyncMock(return_value=0)), \
             patch("harness.orchestrator_chain.universal_header_audit", new=AsyncMock(return_value=0)), \
             patch.object(WriteIntegrityValidator, "validate", spy), \
             patch.object(missing_auth_probe, "probe", new=AsyncMock(side_effect=RuntimeError("stub"))), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            async with run:
                await orch.investigate_engagement(
                    self.origin + "/", [RoleSession("anonymous", {})], max_nodes=1,
                    max_chain_rounds=0, discovery_max_probes=1, run_context=run)
        return [(v, r) for v, r in seen if v.run_context is run], run

    async def test_chain_confirms_mass_assignment_at_create_and_deletes(self):
        seen, run = await self.run_chain("mass_assignment_create", writes=True)
        self.assertTrue(seen, "the chain never reached write_integrity")
        validator, result = seen[0]
        self.assertTrue(validator.allow_writes)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual(self.server.data, _seed())
        self.assert_creates_restored(run)

    async def test_chain_with_mutating_replay_off_sends_no_write(self):
        seen, _ = await self.run_chain("mass_assignment_create", writes=False)
        self.assertTrue(seen, "the chain never reached write_integrity")
        for validator, result in seen:
            self.assertFalse(validator.allow_writes)
            self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(self.writes(), [], "the chain path sent a write with mutating replay off")


class ConfirmationCallerTests(_Fixture):
    """The production confirmation caller reaches the write leg, persists a proof
    naming executed artifacts, and leaves the store as it found it."""

    async def run_caller(self, cls, path, body, *, registry_writes=True):
        from harness.orchestrator_confirm import ConfirmMixin
        reg, run = self.build(registry_writes=registry_writes)
        caller = ConfirmMixin()
        caller.config = {"validators": {"active_enabled": True}}
        caller.allowed_hosts = ["127.0.0.1"]
        caller.validator_registry = reg
        reg.validators = {"write_integrity": reg.validators["write_integrity"]}
        finding, ex = self.capture(cls, path, body)
        persist = AsyncMock(return_value=(True, {"proof_id": "inert"}, ""))
        with patch.object(caller, "_persist_confirmation_proof", persist), \
             patch("harness.evidence_ledger.emit"):
            async with run:
                validations, _ = await caller._validate_findings(
                    ex, [AgentReport(agent="api_security", model="synthetic", findings=[finding])],
                    run_context=run)
        return validations, persist, finding, run

    async def test_caller_confirms_mass_assignment_with_artifacts_and_restores(self):
        validations, persist, finding, run = await self.run_caller(
            "mass_assignment_create", "/api/accounts", _ACCOUNT)
        self.assertEqual([(v.validator, v.status) for v in validations],
                         [("write_integrity", "confirmed")])
        self.assertTrue(finding.confirmed)
        artifacts = persist.await_args.kwargs["proof_artifacts"]
        self.assertTrue(artifacts and all(artifacts.values()), artifacts)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_caller_negative_control_does_not_confirm(self):
        self.server.modes.add("ignore_roles")
        validations, _, finding, _ = await self.run_caller(
            "mass_assignment_create", "/api/accounts", _ACCOUNT)
        self.assertEqual([(v.validator, v.status) for v in validations],
                         [("write_integrity", "not_confirmed")])
        self.assertFalse(finding.confirmed)
        self.assert_store_restored()

    async def test_caller_with_write_gate_off_sends_no_write(self):
        validations, _, finding, _ = await self.run_caller(
            "mass_assignment_create", "/api/accounts", _ACCOUNT, registry_writes=False)
        self.assertEqual(validations, [])
        self.assertFalse(finding.confirmed)
        self.assertEqual(self.server.received, [])


if __name__ == "__main__":
    unittest.main()
