"""ARC-4: the Burp plane's dispatch protocol, through the real route module.

A Burp-plane result is accepted only under the single-use nonce
POST /test-plans/{plan_id}/dispatch issued, once, for a plan that holds no
verdict yet. No provider or target traffic: a fake passive orchestrator and a
temporary SQLite store.
"""
import json
import sqlite3
import unittest
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch

from harness import store
from harness.models import TestPlan, ValidationSubmission


def _plan(plan_id="plane-plan-1", *, plane="burp", capability="reflection_context_validation"):
    # category "cors" is not retryable, so no follow-up plan muddies the checks.
    return TestPlan(id=plan_id, capability=capability, finding_class="cors", category="cors",
                    source_exchange_url="https://plane-dispatch.invalid/account",
                    execution_plane=plane, source_exchange_hash="hash-plane")


def _query(sql, params=()):
    with closing(sqlite3.connect(store._DB_PATH)) as conn:
        return conn.execute(sql, params).fetchall()


def _result(plan_id="plane-plan-1", status="rejected", nonce="", **extra):
    body = {"plan_id": plan_id, "status": status, "confirmed": status == "confirmed",
            "confidence": 0.9 if status == "confirmed" else 0.0,
            "executor": "burp:reflection_context_validation",
            "source_exchange_hash": "hash-plane", "dispatch_nonce": nonce}
    body.update(extra)
    return body


class PlaneDispatchRouteTests(unittest.TestCase):
    def setUp(self):
        from harness.test_pairing_contract import PairingCallerTests
        fixture = PairingCallerTests("test_health_is_liveness_and_pairing_requires_credential")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.server = fixture.server
        self.client = fixture.client
        self.client.headers.update(fixture.auth)
        self.registry = SimpleNamespace(active_enabled=False)
        self.server.orchestrator.validator_registry = self.registry
        self.server.orchestrator.config = {"runs": {"max_requests": 7}}
        store.persist_retry_plan(_plan())

    # -- helpers ------------------------------------------------------------
    def _dispatch(self, plan_id="plane-plan-1", binding="hash-plane"):
        return self.client.post(f"/test-plans/{plan_id}/dispatch",
                                json={"source_exchange_hash": binding})

    def _nonce(self, plan_id="plane-plan-1"):
        reply = self._dispatch(plan_id)
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply.json()["dispatch_nonce"]

    def _submit(self, **kwargs):
        return self.client.post("/validation-results", json=_result(**kwargs))

    def _runs(self, plan_id="plane-plan-1"):
        return _query("SELECT status FROM validation_runs WHERE plan_id = ?", (plan_id,))

    def _plan_status(self, plan_id="plane-plan-1"):
        return store.get_test_plan(plan_id)["status"]

    def _ledger(self, plan_id="plane-plan-1"):
        rows = _query("SELECT event_type, data_json FROM ledger_events WHERE finding_ref = ? "
                      "ORDER BY created_at", (f"plan:{plan_id}",))
        return [(kind, json.loads(data)) for kind, data in rows]

    def _check_refused(self, reply, status, reason):
        self.assertEqual(reply.status_code, status, reply.text)
        detail = reply.json()["detail"]
        self.assertIsInstance(detail, dict, reply.text)
        self.assertEqual(detail["reason"], reason, reply.text)
        self.assertTrue(detail["message"], reply.text)

    # -- the protocol -------------------------------------------------------
    def test_dispatch_hands_the_plane_the_live_policy_and_budget(self):
        reply = self._dispatch()
        self.assertEqual(reply.status_code, 200, reply.text)
        body = reply.json()
        self.assertEqual(body["policy"], {"active_enabled": False, "allow_mutating_replay": False})
        self.assertEqual(body["request_budget"], 7)
        self.assertGreaterEqual(len(body["dispatch_nonce"]), 32)
        stored = _query("SELECT nonce_sha256 FROM plane_dispatches")[0][0]
        self.assertNotIn(body["dispatch_nonce"], stored)  # only the digest is kept

        self.registry.active_enabled = True
        self.server.config["validators"] = {"allow_mutating_replay": True}
        self.server.orchestrator.config = {"runs": {}}
        body = self._dispatch().json()
        self.assertEqual(body["policy"], {"active_enabled": True, "allow_mutating_replay": True})
        self.assertIsNone(body["request_budget"])

    def test_a_malformed_ceiling_fails_closed(self):
        for runs in ([], "100", {"max_requests": "100"}, {"max_requests": True}, {"max_requests": -1}):
            self.server.orchestrator.config = {"runs": runs}
            reply = self._dispatch()
            self.assertEqual(reply.status_code, 200, f"{runs!r}: {reply.text}")
            self.assertEqual(reply.json()["request_budget"], 0, repr(runs))

    def test_a_quoted_flag_is_parsed_strictly(self):
        self.registry.active_enabled = True
        self.server.config["validators"] = {"allow_mutating_replay": "false"}
        self.assertFalse(self._dispatch().json()["policy"]["allow_mutating_replay"])

    def test_dispatched_result_is_accepted_once(self):
        nonce = self._nonce()
        self.assertEqual(self._submit(nonce=nonce).status_code, 200)
        self._check_refused(self._submit(nonce=nonce), 409, "duplicate_submission")
        self.assertEqual(self._runs(), [("rejected",)])
        self.assertEqual([(kind, data["decision"]) for kind, data in self._ledger()],
                         [("authorization_decision", "dispatched"),
                          ("validation_decision", "accepted"),
                          ("authorization_decision", "refused")])
        self.assertEqual(self._ledger()[-1][1]["reason"], "duplicate_submission")

    def test_undispatched_result_is_refused(self):
        self._check_refused(self._submit(), 409, "not_dispatched")
        self.assertEqual(self._runs(), [])
        self.assertEqual(self._plan_status(), "proposed")

    def test_unknown_status_is_refused_and_keeps_the_nonce(self):
        nonce = self._nonce()
        reply = self._submit(nonce=nonce, status="pwned")
        self.assertEqual(reply.status_code, 422, reply.text)
        self.assertEqual(self._runs(), [])
        self.assertEqual(self._submit(nonce=nonce).status_code, 200)

    def test_terminal_plan_is_not_overwritten(self):
        nonce = self._nonce()
        ok, _ = store.record_plan_dispatch("plane-plan-1", status="not_confirmed", validator="harness")
        self.assertTrue(ok)
        self._check_refused(self._submit(nonce=nonce, status="confirmed"), 409, "plan_terminal")
        self.assertEqual(self._plan_status(), "not_confirmed")
        self._check_refused(self._dispatch(), 409, "plan_terminal")

    def test_plane_verdict_is_immutable_for_every_writer(self):
        self.assertEqual(self._submit(nonce=self._nonce(), status="confirmed").status_code, 200)
        self._check_refused(self._dispatch(), 409, "plan_terminal")
        ok, reason = store.persist_validation_submission(ValidationSubmission(
            plan_id="plane-plan-1", status="rejected", executor="burp:reflection_context_validation",
            source_exchange_hash="hash-plane"))
        self.assertEqual((ok, reason), (False, "plan already has a plane result"))
        self.assertEqual(self._plan_status(), "confirmed")

    def test_a_superseded_nonce_is_refused(self):
        stale = self._nonce()
        fresh = self._nonce()
        self._check_refused(self._submit(nonce=stale), 409, "dispatch_nonce_mismatch")
        self.assertEqual(self._submit(nonce=fresh).status_code, 200)

    def test_a_result_without_its_nonce_is_refused(self):
        self._nonce()
        self._check_refused(self._submit(), 422, "dispatch_nonce_required")
        self.assertEqual(self._runs(), [])

    def test_an_error_result_leaves_the_plan_runnable(self):
        self.assertEqual(self._submit(nonce=self._nonce(), status="error").status_code, 200)
        self.assertEqual(self._submit(nonce=self._nonce(), status="rejected").status_code, 200)
        self.assertEqual(self._runs(), [("error",), ("rejected",)])

    def test_unknown_plan_and_foreign_plane_are_refused_at_dispatch(self):
        self.assertEqual(self._dispatch("no-such-plan").status_code, 404)
        self.assertEqual(self._submit(plan_id="no-such-plan").status_code, 404)
        self.assertEqual(self._ledger("no-such-plan"), [])
        store.persist_retry_plan(_plan("local-plan", plane="local_tool"))
        self._check_refused(self._dispatch("local-plan"), 422, "wrong_execution_plane")

    def test_wipe_removes_the_plans_dispatches_and_ledger_events(self):
        self.assertEqual(self._submit(nonce=self._nonce()).status_code, 200)
        self.assertTrue(self._ledger())
        store.wipe_engagement("plane-dispatch.invalid")
        self.assertEqual(_query("SELECT COUNT(*) FROM plane_dispatches"), [(0,)])
        self.assertEqual(self._ledger(), [])

    # -- negative control ---------------------------------------------------
    def _check_protocol(self):
        self._check_refused(self._submit(), 409, "not_dispatched")
        nonce = self._nonce()
        self.assertEqual(self._submit(nonce=nonce).status_code, 200)
        self._check_refused(self._submit(nonce=nonce, status="confirmed"), 409, "duplicate_submission")

    def test_control_the_pre_arc4_persist_accepts_undispatched_and_overwrites(self):
        self._check_protocol()
        store.persist_retry_plan(_plan("plane-plan-2"))

        def legacy(submission):  # what /validation-results called before ARC-4
            return store.persist_validation_submission(submission)

        with patch.object(store, "persist_plane_submission", legacy):
            with self.assertRaises(AssertionError):
                self._check_refused(self._submit(plan_id="plane-plan-2"), 409, "not_dispatched")
            with self.assertRaises(AssertionError):
                self._check_refused(self._submit(plan_id="plane-plan-2", status="confirmed"),
                                    409, "duplicate_submission")
        self.assertEqual(self._plan_status("plane-plan-2"), "confirmed")  # the overwrite

    # -- ARC-12: one status per refusal reason -------------------------------
    def _refusals(self):
        """Every refusal code, reached through the routes; each consumes nothing."""
        seen = {}
        seen["unknown_plan"] = self._dispatch("no-such-plan"), self._submit(plan_id="no-such-plan")
        seen["not_dispatched"] = (self._submit(),)
        store.persist_retry_plan(_plan("local-plan", plane="local_tool"))
        seen["wrong_execution_plane"] = (self._dispatch("local-plan"),)
        seen["binding_mismatch"] = (self._dispatch(binding="hash-other"),)
        nonce = self._nonce()
        seen["dispatch_nonce_required"] = (self._submit(),)
        seen["dispatch_nonce_mismatch"] = (self._submit(nonce="not-the-nonce-" + "x" * 30),)
        seen["binding_mismatch"] += (self._submit(nonce=nonce, source_exchange_hash="hash-other"),)
        seen["executor_mismatch"] = (self._submit(nonce=nonce, executor="burp:sql_injection_validation"),)
        seen["confirmed_status_invalid"] = (self._submit(nonce=nonce, status="supported", confirmed=True),)
        store.persist_retry_plan(_plan("csp-plan", capability="csp_clickjacking_validation"))
        seen["capability_cannot_confirm"] = (self._submit(
            plan_id="csp-plan", nonce=self._nonce("csp-plan"), status="confirmed",
            executor="burp:csp_clickjacking_validation"),)
        self.assertEqual(self._submit(nonce=nonce).status_code, 200)  # nothing above consumed it
        seen["duplicate_submission"] = (self._submit(nonce=nonce),)
        seen["plan_terminal"] = (self._dispatch(),)
        return seen

    _EXPECTED_STATUS = {
        "unknown_plan": 404, "not_dispatched": 409, "dispatch_nonce_mismatch": 409,
        "duplicate_submission": 409, "plan_terminal": 409, "dispatch_nonce_required": 422,
        "wrong_execution_plane": 422, "binding_mismatch": 422, "executor_mismatch": 422,
        "capability_cannot_confirm": 422, "confirmed_status_invalid": 422,
    }

    def _check_refusal_statuses(self, seen):
        self.assertEqual(set(seen), set(store.PLANE_REFUSAL_REASONS), "every code is exercised")
        for reason, replies in seen.items():
            for reply in replies:  # no subTest: the control below needs the AssertionError
                self._check_refused(reply, self._EXPECTED_STATUS[reason], reason)

    def test_each_refusal_reason_has_its_own_status(self):
        self._check_refusal_statuses(self._refusals())
        self.assertEqual(self._runs("csp-plan"), [])

    def test_only_an_unknown_plan_is_a_404(self):
        server = self.server
        self.assertEqual(set(server._PLANE_REFUSALS), set(store.PLANE_REFUSAL_REASONS))
        self.assertEqual({r for r, (status, _) in server._PLANE_REFUSALS.items() if status == 404},
                         {"unknown_plan"})
        self.assertEqual(server._plane_refusal("a_future_code").status_code, 409)

    def test_the_burp_client_knows_every_refusal_code(self):
        # HarnessClient surfaces only the codes it lists; a code added here and
        # not there would reach the analyst as a bare HTTP status.
        import re
        from pathlib import Path
        java = (Path(store.__file__).resolve().parent.parent / "burp-extension" / "src" / "main" / "java"
                / "com" / "harness" / "llm" / "HarnessClient.java").read_text(encoding="utf-8")
        block = java.split("PLANE_REFUSALS = java.util.Map.ofEntries(", 1)[1].split(");", 1)[0]
        self.assertEqual(set(re.findall(r'Map\.entry\("([a-z_]+)"', block)), set(store.PLANE_REFUSAL_REASONS))

    def test_the_internal_writer_keeps_its_messages(self):
        ok, reason = store.persist_validation_submission(ValidationSubmission(
            plan_id="plane-plan-1", status="rejected", executor="burp:sql_injection_validation",
            source_exchange_hash="hash-plane"))
        self.assertEqual((ok, reason), (False, "executor does not match the registered capability"))
        self.assertEqual(store.persist_validation_submission(ValidationSubmission(
            plan_id="no-such-plan", status="rejected"))[1], "unknown test plan")

    def test_control_the_pre_arc12_mapping_fails_the_status_checks(self):
        from fastapi import HTTPException
        server = self.server  # the fixture's own copy of the route module

        def legacy(reason):  # ARC-4's mapping: 400 for a binding, 404 for any other content refusal
            status = {"unknown_plan": 404, "not_dispatched": 409, "dispatch_nonce_mismatch": 409,
                      "duplicate_submission": 409, "plan_terminal": 409,
                      "dispatch_nonce_required": 422, "wrong_execution_plane": 422}.get(
                reason, 400 if reason == "binding_mismatch" else 404)
            return HTTPException(status_code=status, detail={"reason": reason, "message": reason})

        with patch.object(server, "_plane_refusal", legacy):
            seen = self._refusals()
        with self.assertRaises(AssertionError):
            self._check_refusal_statuses(seen)

    def test_control_the_shared_model_accepts_any_status(self):
        # The base model the route took before ARC-4 has no status set: an
        # unknown status reached the store and was persisted as given.
        store.persist_retry_plan(_plan("plane-plan-3"))
        ok, _ = store.persist_validation_submission(ValidationSubmission(**{
            k: v for k, v in _result("plane-plan-3", status="pwned").items() if k != "dispatch_nonce"}))
        self.assertTrue(ok)
        self.assertEqual(self._runs("plane-plan-3"), [("pwned",)])


if __name__ == "__main__":
    unittest.main()
