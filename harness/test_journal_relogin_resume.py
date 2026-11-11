"""A resumed run whose roles logged in again skips what the earlier attempt finished (r9).

r9 was resumed twice from its run journal. Each time the run's users logged in again,
so their tokens changed. The worklist's journal key held the capture's identity key
and capture id, both digests of the token value, so no finished authenticated node
matched: 72 of them ran again (the anonymous ones, whose key has no token, resumed).
The capture review's key (observation_key) hashes the token too.

Caller: investigate_engagement over an owned 127.0.0.1 fixture (test_run_journal's),
run 1 with the first login's token, run 2 with a second token for the same named
principal and the same journal. Controls: the r9 keys bring the repeats back, and a
journal written before identities were recorded leaves restored probe templates
under the old identity.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from harness import assessment_health, engagement, run_journal, worklist_investigator
from harness.engagement import capture_identity_key, identity_variants, stable_capture_id
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.run_journal import RunJournal
from harness.test_run_journal import _USER_TOKEN, ROUTES, _Crash, _EngagementBase

SECOND_LOGIN = "Bearer second-login-token-9876543210"


def _roles(token):
    return [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": token}, name="alice")]


FIRST, AGAIN = _roles(_USER_TOKEN), _roles(SECOND_LOGIN)


def _r9_node_key(node) -> str:
    """The worklist key r9 ran with: the identity key and capture id hash the token."""
    capture = node.get("capture") or {}
    principal = getattr(node.get("probe_session"), "principal_id", None)
    return "|".join([str(node.get("method") or "GET").upper(), str(node.get("path") or ""),
                     str(capture.get("identity_key") or ""), str(capture.get("capture_id") or ""),
                     str(principal() if callable(principal) else "")])


class ReloginResumeTests(_EngagementBase):

    def _journal_for(self, roles):
        return RunJournal(self.journal_path, "root-1", "ctx", roles=roles)

    def _run(self, roles, *, orch=None, review=None, extra=()):
        orch = orch or self._orchestrator()
        journal = self._journal_for(roles)

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=5000) as run:
                run.run_journal = journal
                patches = [patch("harness.engagement_builder.build_engagement", new=self._discover)]
                if review is not None:
                    patches.append(patch("harness.orchestrator_chain.review_captured_exchanges",
                                         new=review))
                patches.extend(extra)
                for p in patches:
                    p.start()
                try:
                    return await orch.investigate_engagement(
                        self.site.origin, roles, max_nodes=8, step_budget=2, max_chain_rounds=0,
                        run_context=run)
                finally:
                    for p in reversed(patches):
                        p.stop()
        return asyncio.run(go())

    def _worklist_twice(self, extra=()):
        with self.assertRaises(_Crash):
            self._run(FIRST, review=self._crash_in_review, extra=extra)
        self.assertEqual(len(self.probes), len(ROUTES))
        return self._run(AGAIN, extra=extra)

    def test_finished_worklist_nodes_are_skipped_after_a_relogin(self):
        result = self._worklist_twice()
        self.assertEqual(self.discoveries, 1)
        self.assertEqual(len(self.probes), len(ROUTES))          # nothing probed again
        self.assertEqual(result["resume"]["resumed_units"]["worklist"], len(ROUTES))
        self.assertTrue(all(o["resumed"] for o in result["outcomes"]))

    def test_control_the_r9_key_runs_every_finished_node_again(self):
        result = self._worklist_twice(
            extra=[patch.object(worklist_investigator, "node_key", _r9_node_key)])
        self.assertEqual(len(self.probes), 2 * len(ROUTES))       # the r9 failure
        self.assertEqual(result["resume"]["resumed_units"]["worklist"], 0)

    def _reviews_twice(self, extra=()):
        with patch("harness.chain_linker.link_findings", side_effect=_Crash("died")):
            with self.assertRaises(_Crash):
                self._run(FIRST, extra=extra)
        self.assertEqual(len(self.analyzed), len(ROUTES))
        return self._run(AGAIN, extra=extra)

    def test_finished_capture_reviews_are_skipped_after_a_relogin(self):
        result = self._reviews_twice()
        self.assertEqual(len(self.analyzed), len(ROUTES))        # the model is not asked again
        self.assertEqual(result["resume"]["resumed_units"]["review"], len(ROUTES))

    def test_control_the_observation_key_reviews_every_capture_again(self):
        def r9_key(journal, ex):
            return assessment_health.observation_key(ex)
        self._reviews_twice(extra=[patch.object(RunJournal, "exchange_key", r9_key)])
        self.assertEqual(len(self.analyzed), 2 * len(ROUTES))

    def test_the_resumed_captures_carry_the_second_login(self):
        with self.assertRaises(_Crash):
            self._run(FIRST, review=self._crash_in_review)
        sent = []

        async def review(orch, state, captured, **kwargs):
            sent.extend(c["request_headers"] for c in captured)
            return 0
        self._run(AGAIN, review=review)
        self.assertEqual(sent, [{"Authorization": SECOND_LOGIN}] * len(ROUTES))


class RestoredProbeTemplateTests(unittest.TestCase):
    """restore_discovery moves a principal's captures to its current credentials, so
    an access-matrix probe template (in the state only, never re-captured on resume)
    still replays as that principal."""

    def _payload(self, with_identities=True):
        state = engagement.EngagementState(host="127.0.0.1")
        state.record_identity_probe("http://127.0.0.1/api/orders/7", "GET", {
            "request_headers": {"Authorization": _USER_TOKEN, "Accept": "*/*"},
            "response_status": 200, "response_headers": {"Content-Type": "application/json"},
            "response_body_sha256": "ab" * 32, "response_body_len": 12})
        state.record_template("http://127.0.0.1/api/orders/7", "GET", {
            "url": "http://127.0.0.1/api/orders/7", "method": "GET",
            "request_headers": {"Authorization": _USER_TOKEN}, "request_body": "",
            "response_status": 200, "response_headers": {}, "response_body": '{"id": 7}'})
        rc = type("Rc", (), {"captured": [], "errors": [], "endpoints": []})()
        payload = run_journal.discovery_payload(state, rc, FIRST)
        if not with_identities:
            payload.pop("identities")    # a journal written before this change
        return json.loads(json.dumps(payload))

    def _restored_variants(self, payload):
        state, _rc = run_journal.restore_discovery(payload, AGAIN)
        ep = state.endpoints["GET /api/orders/{id}"]
        return ep, identity_variants(ep, capture_identity_key(AGAIN[1].headers))

    def test_probe_and_capture_move_to_the_second_login(self):
        payload = self._payload()
        self.assertNotIn(_USER_TOKEN, json.dumps(payload["identities"]))
        ep, mine = self._restored_variants(payload)
        self.assertTrue(mine)            # replayable as alice again
        new_key = capture_identity_key(AGAIN[1].headers)
        self.assertEqual({(v.get("source"), v["identity_key"]) for v in ep.capture_variants},
                         {(engagement.ACCESS_MATRIX_SOURCE, new_key), (None, new_key)})
        # the capture id is the one a fresh capture under the second login gets
        state, _rc = run_journal.restore_discovery(payload, AGAIN)
        state.record_template("http://127.0.0.1/api/orders/7", "GET", {
            "url": "http://127.0.0.1/api/orders/7", "method": "GET",
            "request_headers": {"Authorization": SECOND_LOGIN}, "request_body": "",
            "response_status": 200, "response_headers": {}, "response_body": '{"id": 7}'})
        self.assertEqual(len(state.endpoints["GET /api/orders/{id}"].capture_variants), 2)

    def test_control_without_stored_identities_the_templates_stay_with_the_old_login(self):
        _ep, mine = self._restored_variants(self._payload(with_identities=False))
        self.assertEqual(mine, [])

    def test_a_principal_this_run_does_not_have_is_left_alone(self):
        payload = self._payload()
        state, _rc = run_journal.restore_discovery(payload, [RoleSession("anonymous", {})])
        ep = state.endpoints["GET /api/orders/{id}"]
        self.assertEqual({v["identity_key"] for v in ep.capture_variants},
                         {capture_identity_key(FIRST[1].headers)})


class NodeKeyTests(unittest.TestCase):
    """The key drops credential values only: another request, response or principal
    is still another node."""

    def _node(self, token=_USER_TOKEN, body="", principal="alice", status=200):
        variant = engagement.capture_variant({
            "url": "http://h/api/orders", "method": "POST",
            "request_headers": {"Authorization": token}, "request_body": body,
            "response_status": status, "response_headers": {}, "response_body": "{}"})
        role = RoleSession("user", {"Authorization": token}, name=principal)
        return {"method": "POST", "path": "/api/orders", "capture": variant, "probe_session": role}

    def test_same_capture_after_a_relogin_is_the_same_node(self):
        self.assertEqual(worklist_investigator.node_key(self._node()),
                         worklist_investigator.node_key(self._node(token=SECOND_LOGIN)))
        self.assertNotEqual(_r9_node_key(self._node()), _r9_node_key(self._node(token=SECOND_LOGIN)))

    def test_control_another_request_response_or_principal_is_another_node(self):
        base = worklist_investigator.node_key(self._node())
        for other in (self._node(body='{"q": 1}'), self._node(status=403),
                      self._node(principal="bob")):
            self.assertNotEqual(worklist_investigator.node_key(other), base)
        self.assertEqual(stable_capture_id(self._node()["capture"]),
                         stable_capture_id(self._node(token=SECOND_LOGIN)["capture"]))


if __name__ == "__main__":
    unittest.main()
