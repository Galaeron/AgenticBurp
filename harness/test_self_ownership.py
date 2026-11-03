"""Self-observed ownership (self_ownership.py): the harness's own test principals'
objects decide IDOR / cross-identity reads without operator input, below every
operator declaration, and never from a model's claim.

Synthetic A/B: alice and bob are two fresh accounts the harness logged in. Each
`/whoami` binds a principal to its account; alice's login returned her basket id
and her POST created ticket 7. Controls: an object also served without
credentials is never confirmed, a declaration outranks the observation, two
credentials of ONE account are not a crossing, and a model claim is refused."""
import asyncio
import json
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from harness import identity_compare, identity_headers, principals, safety_gate
from harness.models import Finding, HttpExchange
from harness.principals import AuthzDecision, OwnershipFact, Principal
from harness.self_ownership import SelfOwnership, enabled
from harness.validators.cross_identity_validator import CrossIdentityValidator
from harness.validators.idor_read_validator import IdorReadValidator

APP = "http://t.test"
ALICE, BOB = "captured:" + "aa" * 32, "captured:" + "bb" * 32   # credential aliases


def _observed(*, bob_whoami=True, bob_same_account=False) -> SelfOwnership:
    so = SelfOwnership(run_id="r1", persist=False)
    so.observe(source="capture", principal_id="", method="POST", url=f"{APP}/rest/user/login",
               status=200, response_body=json.dumps(
                   {"authentication": {"token": "x", "bid": 6, "umail": "alice@t.test"}}))
    so.observe(source="transport", principal_id=ALICE, method="GET", url=f"{APP}/rest/user/whoami",
               status=200, response_body=json.dumps({"user": {"id": 21, "email": "alice@t.test"}}))
    so.observe(source="transport", principal_id=ALICE, method="POST", url=f"{APP}/api/tickets",
               status=201, response_body=json.dumps({"status": "success", "data": {"id": 7}}))
    if bob_whoami:
        who = {"id": 21, "email": "alice@t.test"} if bob_same_account else {"id": 22, "email": "bob@t.test"}
        so.observe(source="capture", principal_id=BOB, method="GET", url=f"{APP}/rest/user/whoami",
                   status=200, response_body=json.dumps({"user": who}))
    return so


def _ledger(so) -> principals.OwnershipLedger:
    led = principals.OwnershipLedger()
    led.self_observed = so
    return led


def _ref(path):
    return principals.object_reference(APP + path, run_id="r1")


def _alias(pid):
    return Principal(id=pid, provisional=True)


class SelfOwnershipStoreTests(unittest.TestCase):
    def test_other_account_reading_alice_objects_is_unauthorized(self):
        so = _observed()
        for path in ("/rest/basket/6", "/api/tickets/7", "/api/Users/21"):
            with self.subTest(path=path):
                self.assertEqual(so.authorization(_alias(BOB), APP + path)[0], AuthzDecision.UNAUTHORIZED)
                self.assertEqual(so.authorization(_alias(ALICE), APP + path)[0], AuthzDecision.AUTHORIZED)
        self.assertIn("self_observed", so.fact_for(APP + "/rest/basket/6")[1])

    def test_reader_without_an_observed_account_is_unknown(self):
        so = _observed(bob_whoami=False)
        self.assertEqual(so.authorization(_alias(BOB), APP + "/rest/basket/6")[0], AuthzDecision.UNKNOWN)

    def test_second_credential_of_the_same_account_is_not_a_crossing(self):
        so = _observed(bob_same_account=True)
        self.assertEqual(so.authorization(_alias(BOB), APP + "/api/tickets/7")[0], AuthzDecision.AUTHORIZED)

    def test_object_served_as_own_to_two_accounts_is_unknown(self):
        so = _observed()
        so.observe(source="transport", principal_id=BOB, method="POST", url=f"{APP}/api/tickets",
                   status=201, response_body=json.dumps({"data": {"id": 7}}))
        self.assertEqual(so.authorization(_alias(BOB), APP + "/api/tickets/7")[0], AuthzDecision.UNKNOWN)

    def test_anonymous_and_failed_exchanges_record_nothing(self):
        so = SelfOwnership(persist=False)
        self.assertEqual(so.observe(source="transport", principal_id="anonymous", method="POST",
                                    url=f"{APP}/api/Feedbacks", status=201,
                                    response_body=json.dumps({"data": {"id": 3}})), [])
        self.assertEqual(so.observe(source="transport", principal_id=ALICE, method="POST",
                                    url=f"{APP}/api/tickets", status=500,
                                    response_body=json.dumps({"data": {"id": 3}})), [])

    def test_model_asserted_ownership_is_refused(self):
        so = SelfOwnership(persist=False)
        self.assertEqual(so.observe(source="model", principal_id=ALICE, method="POST",
                                    url=f"{APP}/api/tickets", status=201,
                                    response_body=json.dumps({"data": {"id": 9}})), [])
        self.assertEqual(so.rejected, 1)
        self.assertIsNone(so.fact_for(APP + "/api/tickets/9"))
        # Nor can a self_observed fact be slipped into the ledger, where it would
        # outrank the observation rules (and every declaration's priority).
        with self.assertRaises(ValueError):
            principals.OwnershipLedger().record(OwnershipFact(
                object_ref=_ref("/api/tickets/9"), owner_principal_id=ALICE,
                provenance="self_observed; owner=alice (model said so)"))

    def test_config_key_absent_is_off(self):
        self.assertFalse(enabled({}))
        self.assertFalse(enabled({"authz": {"self_observed_ownership": "yes"}}))
        self.assertTrue(enabled({"authz": {"self_observed_ownership": True}}))


class LedgerPriorityTests(unittest.TestCase):
    def test_self_observed_answers_only_when_nothing_is_declared(self):
        led = _ledger(_observed())
        self.assertEqual(led.authorization_source(_alias(BOB), _ref("/api/tickets/7"))[:2],
                         (AuthzDecision.UNAUTHORIZED, "self_observed"))

    def test_operator_declaration_wins(self):
        led = _ledger(_observed())
        led.declare(APP + "/api/tickets/7", public=True)
        self.assertEqual(led.authorization_source(_alias(BOB), _ref("/api/tickets/7"))[:2],
                         (AuthzDecision.AUTHORIZED, "declared"))
        led.declare(APP + "/rest/basket/6", owner="alice", shared_with=[BOB])
        self.assertEqual(led.authorization_source(_alias(BOB), _ref("/rest/basket/6"))[:2],
                         (AuthzDecision.AUTHORIZED, "declared"))

    def test_no_self_store_keeps_unknown(self):
        self.assertEqual(principals.OwnershipLedger().authorization_source(
            _alias(BOB), _ref("/api/tickets/7"))[:2], (AuthzDecision.UNKNOWN, "none"))


def _finding(cls="idor"):
    return Finding(vulnerability_class=cls, confidence=0.5, summary="s", evidence="e",
                   suggested_test="t", basis="derived")


class _R:
    def __init__(self, status, text, headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class IdorReadConsumesSelfOwnershipTests(unittest.TestCase):
    """bob's capture reads his basket 7; the neighbour 6 is alice's (self-observed)."""

    def setUp(self):
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allowed_hosts": ["t.test"]})

    def tearDown(self):
        safety_gate.reset_default_gate()

    def _run(self, ledger, *, anon_served=False):
        bodies = {"6": "basket of alice: apple juice x2 " + "a" * 40,
                  "7": "basket of bob: banana juice x1 " + "b" * 40}

        async def app(_self, method, url, headers=None, content=None):
            bid = urlsplit(url).path.rsplit("/", 1)[-1]
            if "Authorization" not in (headers or {}) and not anon_served:
                return _R(401, "please authenticate")
            return _R(200, bodies[bid]) if bid in bodies else _R(404, "not found")

        ex = HttpExchange(url=f"{APP}/rest/basket/7", method="GET",
                          request_headers={"Authorization": "Bearer bob"}, response_status=200)
        v = IdorReadValidator(allowed_hosts=["t.test"], ownership=ledger)
        with patch("httpx.AsyncClient.request", app), \
                patch("harness.store.captured_principal_id", return_value=BOB):
            return asyncio.run(v.validate(_finding(), ex))

    def test_reading_another_accounts_self_observed_object_confirms(self):
        r = self._run(_ledger(_observed()))
        self.assertEqual(r.status, "confirmed")
        self.assertIn("Self-observed ownership", r.evidence)

    def test_without_a_ledger_it_stays_a_candidate(self):
        r = self._run(None)
        self.assertEqual(r.status, "inconclusive")
        self.assertFalse(r.confirmed)

    def test_object_also_served_anonymously_is_never_confirmed(self):
        # The public-object control keeps its priority over any ownership fact.
        r = self._run(_ledger(_observed()), anon_served=True)
        self.assertEqual(r.status, "inconclusive")
        self.assertIn("without credentials", r.evidence)

    def test_declared_public_outranks_self_observation(self):
        led = _ledger(_observed())
        led.declare(APP + "/rest/basket/6", public=True)
        r = self._run(led)
        self.assertNotEqual(r.status, "confirmed")


class CrossIdentityConsumesSelfOwnershipTests(unittest.TestCase):
    """alice's capture reads her ticket 7; bob (a registered identity known only by
    a credential alias) replays it."""

    def setUp(self):
        identity_headers.clear()
        identity_headers.set_identity("t.test", BOB, {"Authorization": "Bearer bob"})

    def tearDown(self):
        identity_headers.clear()

    def _run(self, ledger, *, anon_served=False):
        class V(CrossIdentityValidator):
            async def _probe(self, url, headers):
                if headers.get("Authorization") == "Bearer bob" or anon_served:
                    return identity_compare.Probe(200, "ALICE-TICKET-7-PRIVATE-NOTES-12345")
                return identity_compare.Probe(403, "Forbidden")
        ex = HttpExchange(url=f"{APP}/api/tickets/7", method="GET", request_headers={},
                          response_status=200, response_body="ALICE-TICKET-7-PRIVATE-NOTES-12345")
        return asyncio.run(V(allowed_hosts=["t.test"], ownership=ledger).validate(
            _finding("insecure_direct_object_reference"), ex))

    def test_bob_reading_alices_self_observed_object_confirms(self):
        r = self._run(_ledger(_observed()))
        self.assertEqual(r.status, "confirmed")
        self.assertIn("Self-observed ownership", r.evidence)

    def test_unbound_reader_stays_a_lead(self):
        r = self._run(_ledger(_observed(bob_whoami=False)))
        self.assertEqual(r.status, "supported")

    def test_anonymous_also_served_is_not_a_bypass(self):
        r = self._run(_ledger(_observed()), anon_served=True)
        self.assertFalse(r.confirmed)

    def test_declared_share_outranks_self_observation(self):
        led = _ledger(_observed())
        led.declare(APP + "/api/tickets/7", owner="alice", shared_with=[BOB])
        r = self._run(led)
        self.assertFalse(r.confirmed)


if __name__ == "__main__":
    unittest.main()
