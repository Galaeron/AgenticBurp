"""Tests for Astra T02 -- explicit principal / session / ownership model (R27).

The handoff's test matrix: Alice & Bob in tenant A, Carol in tenant B, an
explicitly-permitted privileged principal, and anonymous; own-object success,
same-tenant unauthorized, cross-tenant unauthorized, public/shared objects, and
refreshed Alice credentials. Expected permissions are declared by the fixture,
never inferred from role rank.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import principals
import store
from principals import AuthzDecision, OwnershipFact, OwnershipLedger, Principal, Session
from role_crawl import RoleSession

# Principals for the matrix (tenant + declared permissions are operator facts).
ALICE = Principal(id="alice", role="user", trust=1, tenant="A")
BOB = Principal(id="bob", role="user", trust=1, tenant="A")
CAROL = Principal(id="carol", role="user", trust=1, tenant="B")
PRIV = Principal(id="ops", role="admin", trust=3, tenant="A",
                 expected_permissions=frozenset({"item:7"}))   # explicitly permitted to read item 7
ANON = Principal.anonymous()


class AuthorizationMatrixTests(unittest.TestCase):
    def setUp(self):
        self.ledger = OwnershipLedger()
        # item:7 is Alice's private object in tenant A.
        self.ledger.record(OwnershipFact(object_ref="item:7", owner_principal_id="alice",
                                         tenant="A", provenance="created-as:alice"))

    def test_owner_is_authorized(self):
        self.assertEqual(self.ledger.authorization(ALICE, "item:7"), AuthzDecision.AUTHORIZED)

    def test_same_tenant_other_user_unauthorized(self):
        # Bob shares Alice's tenant but does NOT own item 7 -> a real crossing.
        self.assertEqual(self.ledger.authorization(BOB, "item:7"), AuthzDecision.UNAUTHORIZED)

    def test_cross_tenant_unauthorized(self):
        self.assertEqual(self.ledger.authorization(CAROL, "item:7"), AuthzDecision.UNAUTHORIZED)

    def test_anonymous_unauthorized_for_owned_object(self):
        self.assertEqual(self.ledger.authorization(ANON, "item:7"), AuthzDecision.UNAUTHORIZED)

    def test_declared_permission_authorizes(self):
        # Authorized ONLY because the fixture declared the permission -- not role rank.
        self.assertEqual(self.ledger.authorization(PRIV, "item:7"), AuthzDecision.AUTHORIZED)
        # An admin WITHOUT the declared permission is not authorized by rank alone.
        bare_admin = Principal(id="root", role="admin", trust=3, tenant="A")
        self.assertEqual(self.ledger.authorization(bare_admin, "item:7"), AuthzDecision.UNAUTHORIZED)

    def test_public_object_authorized(self):
        self.ledger.record(OwnershipFact(object_ref="doc:pub", public=True, provenance="listed publicly"))
        self.assertEqual(self.ledger.authorization(CAROL, "doc:pub"), AuthzDecision.AUTHORIZED)

    def test_shared_object_authorized(self):
        self.ledger.record(OwnershipFact(object_ref="item:9", owner_principal_id="alice",
                                         tenant="A", shared_with=frozenset({"bob"})))
        self.assertEqual(self.ledger.authorization(BOB, "item:9"), AuthzDecision.AUTHORIZED)
        self.assertEqual(self.ledger.authorization(CAROL, "item:9"), AuthzDecision.UNAUTHORIZED)

    def test_unknown_ownership_stays_unknown(self):
        # No fact at all -> unknown, never a crossing.
        self.assertEqual(self.ledger.authorization(BOB, "item:404"), AuthzDecision.UNKNOWN)
        # A fact with no owner / share / public flag is "known nothing" -> unknown.
        self.ledger.record(OwnershipFact(object_ref="item:blank"))
        self.assertEqual(self.ledger.authorization(BOB, "item:blank"), AuthzDecision.UNKNOWN)

    def test_object_references_are_scoped_and_preserve_query_selection(self):
        a = principals.object_reference("https://shop.test/item?id=1&id=2", run_id="r1")
        b = principals.object_reference("https://shop.test/item?id=2&id=1", run_id="r1")
        other_run = principals.object_reference("https://shop.test/item?id=1&id=2", run_id="r2")
        other_target = principals.object_reference("https://other.test/item?id=1&id=2", run_id="r1")
        self.assertEqual(len({a, b, other_run, other_target}), 4)


class PrincipalAndSessionTests(unittest.TestCase):
    def test_session_renew_keeps_principal_stable(self):
        s = Session(id="s1", principal_id="alice", headers={"Cookie": "old"}, generation=0)
        s2 = s.renew({"Cookie": "new"})
        self.assertEqual(s2.principal_id, "alice")     # SAME principal after refresh
        self.assertEqual(s2.generation, 1)             # new generation
        self.assertEqual(s2.headers["Cookie"], "new")  # new credential

    def test_redacted_session_view_hides_credentials(self):
        s = Session(id="s1", principal_id="alice", headers={"Authorization": "Bearer secret"})
        self.assertNotIn("headers", s.redacted_view())
        self.assertNotIn("secret", str(s.redacted_view()))

    def test_roundtrips(self):
        self.assertEqual(Principal.from_dict(PRIV.to_dict()), PRIV)
        f = OwnershipFact(object_ref="x", owner_principal_id="a", tenant="A",
                          shared_with=frozenset({"b"}), provenance="p")
        self.assertEqual(OwnershipFact.from_dict(f.to_dict()), f)
        s = Session(id="s", principal_id="a", headers={"Cookie": "c"}, generation=2)
        self.assertEqual(Session.from_dict(s.to_dict()), s)


class RoleSessionAdapterTests(unittest.TestCase):
    def test_named_principal_id_stable_across_credential_renewal(self):
        a1 = RoleSession(role="user", name="alice", headers={"Cookie": "sess=1"})
        a2 = RoleSession(role="user", name="alice", headers={"Cookie": "sess=2"})  # refreshed cookie
        self.assertEqual(a1.principal_id(), a2.principal_id())          # still Alice
        self.assertEqual(a1.to_principal().id, a2.to_principal().id)
        self.assertFalse(a1.to_principal().provisional)                # explicit name -> not provisional

    def test_same_role_distinct_users_do_not_collapse(self):
        alice = RoleSession(role="user", name="alice", headers={})
        bob = RoleSession(role="user", name="bob", headers={})
        self.assertNotEqual(alice.principal_id(), bob.principal_id())

    def test_credential_hash_id_is_provisional(self):
        # No explicit name, but has credentials -> id derived from a credential hash.
        p = RoleSession(role="user", headers={"Cookie": "sess=abc"}).to_principal()
        self.assertTrue(p.provisional)
        # Anonymous (no name, no credentials) is a legitimate principal, not provisional.
        self.assertFalse(RoleSession(role="anonymous", headers={}).to_principal().provisional)

    def test_adapter_carries_tenant_permissions_and_trust(self):
        rs = RoleSession(role="admin", name="ops", headers={"Cookie": "x"},
                         tenant="A", expected_permissions=frozenset({"item:7"}))
        p = rs.to_principal()
        self.assertEqual(p.tenant, "A")
        self.assertTrue(p.has_permission("item:7"))
        self.assertEqual(p.trust, principals.TRUST_BY_ROLE["admin"])   # 3, from the explicit table
        self.assertEqual(RoleSession(role="anonymous", headers={}).to_principal().trust, 0)


class OwnershipStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_ownership_fact_roundtrip(self):
        f = OwnershipFact(object_ref="item:7", owner_principal_id="alice", tenant="A",
                          shared_with=frozenset({"bob"}), provenance="created-as:alice")
        store.save_ownership_fact(f)
        got = store.get_ownership_fact("item:7")
        self.assertEqual(OwnershipFact.from_dict(got), f)
        self.assertEqual(len(store.ownership_facts_all()), 1)

    def test_unknown_ownership_absent(self):
        self.assertIsNone(store.get_ownership_fact("item:missing"))

    def test_identity_principal_meta_migration_and_roundtrip(self):
        # save_identity still works with the new additive columns present...
        ident = SimpleNamespace(id="alice", name="Alice", role="user", notes="", created_at=time.time())
        store.save_identity(ident)
        # ...and principal metadata round-trips through the migrated columns.
        store.set_identity_principal_meta("alice", tenant="A", permissions=["item:7"], trust=1)
        meta = store.get_identity_principal_meta("alice")
        self.assertEqual(meta["tenant"], "A")
        self.assertIn("item:7", meta["permissions"])

    def test_resaving_identity_preserves_principal_metadata(self):
        ident = SimpleNamespace(id="alice", name="Alice", role="user", notes="old",
                                created_at=time.time())
        store.save_identity(ident)
        store.set_identity_principal_meta(
            "alice", tenant="A", permissions=["item:7"], trust=3)
        updated = SimpleNamespace(id="alice", name="Alice Updated", role="admin",
                                  notes="new", created_at=ident.created_at)
        store.save_identity(updated)
        meta = store.get_identity_principal_meta("alice")
        self.assertEqual(meta["tenant"], "A")
        self.assertEqual(meta["permissions"], ["item:7"])
        self.assertEqual(meta["trust"], 3)


class CrossIdentityOwnershipWiringTests(unittest.TestCase):
    """T02b production wiring: the cross-identity validator consults ownership
    before confirming, so authorized sharing / a public object is not reported as
    BOLA, while an unknown-ownership crossing still confirms. The response-compare
    is forced to CONFIRMED so the OWNERSHIP gate is what's under test."""

    def setUp(self):
        import identity_compare
        import identity_headers
        self._ih = identity_headers.identities_for_host
        self._ev = identity_compare.evaluate
        # One DISTINCT other identity (bob); the captured source carries no auth.
        identity_headers.identities_for_host = lambda host: [
            {"name": "bob", "role": "user", "headers": {"Cookie": "sess=bob"}}]

        class _Ev:
            verdict = identity_compare.Verdict.CONFIRMED
            confidence = 0.9
            summary = "reached another identity's object"
            detail = "d"

        identity_compare.evaluate = lambda *a, **k: _Ev()

    def tearDown(self):
        import identity_compare
        import identity_headers
        identity_headers.identities_for_host = self._ih
        identity_compare.evaluate = self._ev

    def _validator(self, ownership=None):
        from validators.cross_identity_validator import CrossIdentityValidator
        v = CrossIdentityValidator(allowed_hosts=["t.local"], ownership=ownership)

        async def _fake_probe(url, headers):
            import identity_compare
            return identity_compare.Probe(200, "SECRET owner data 1234567890")  # substantive 2xx

        v._probe = _fake_probe
        return v

    def _run(self, v):
        from models import Finding, HttpExchange
        finding = Finding(vulnerability_class="idor", confidence=0.7, summary="s",
                          evidence="e", suggested_test="t", basis="derived")
        ex = HttpExchange(url="http://t.local/api/items/7", method="GET",
                          response_status=200, response_body="SECRET owner data")
        return asyncio.run(v.validate(finding, ex))

    def test_confirms_without_ownership(self):
        res = self._run(self._validator(ownership=None))
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)

    def test_authorized_sharing_is_not_confirmed(self):
        led = OwnershipLedger()
        led.record(OwnershipFact(object_ref=principals.object_reference(
            "http://t.local/api/items/7"), owner_principal_id="alice",
                                 shared_with=frozenset({"bob"})))
        res = self._run(self._validator(ownership=led))
        self.assertEqual(res.status, "not_confirmed")
        self.assertFalse(res.confirmed)
        self.assertIn("authorized", (res.summary + res.evidence).lower())

    def test_public_object_is_not_confirmed(self):
        led = OwnershipLedger()
        led.record(OwnershipFact(object_ref=principals.object_reference(
            "http://t.local/api/items/7"), public=True))
        self.assertFalse(self._run(self._validator(ownership=led)).confirmed)

    def test_unknown_ownership_still_confirms(self):
        led = OwnershipLedger()  # no fact -> UNKNOWN -> must not suppress a real crossing
        res = self._run(self._validator(ownership=led))
        self.assertEqual(res.status, "confirmed")

    def test_authorized_principal_does_not_suppress_later_unauthorized_case(self):
        from run_context import RunContext
        from validators.cross_identity_validator import CrossIdentityValidator
        ctx = RunContext.create(run_id="ownership-run", allowed_hosts=["t.local"])
        origin = "http://t.local"
        ctx.sessions.register("bob-session", "bob", {"Cookie": "bob"},
                              allowed_origins=[origin], role="user", name="bob",
                              principal=BOB)
        ctx.sessions.register("carol-session", "carol", {"Cookie": "carol"},
                              allowed_origins=[origin], role="user", name="carol",
                              principal=CAROL)
        ctx.sessions.register("anonymous", "anonymous", allowed_origins=[origin],
                              role="anonymous", principal=ANON)
        led = OwnershipLedger()
        ref = principals.object_reference(
            "http://t.local/api/items/7", run_id="ownership-run")
        led.record(OwnershipFact(object_ref=ref, owner_principal_id="alice",
                                 shared_with=frozenset({"bob"})))
        validator = CrossIdentityValidator(run_context=ctx, ownership=led)
        seen = []

        async def _fake_probe(url, headers, session_ref=None):
            import identity_compare
            seen.append(session_ref)
            return identity_compare.Probe(
                401 if session_ref == "anonymous" else 200,
                "denied" if session_ref == "anonymous" else "SECRET owner data 1234567890")

        validator._probe = _fake_probe
        result = self._run(validator)
        self.assertTrue(result.confirmed)
        self.assertIn("bob-session", seen)
        self.assertIn("carol-session", seen)

    def test_authoritative_declared_permission_survives_validator_adapter(self):
        from run_context import RunContext
        from validators.cross_identity_validator import CrossIdentityValidator
        url = "http://t.local/api/items/7"
        ctx = RunContext.create(run_id="permission-run", allowed_hosts=["t.local"])
        permitted = Principal(id="ops", role="admin", trust=3,
                              expected_permissions=frozenset({principals.object_reference(
                                  url, run_id="permission-run")}))
        ctx.sessions.register("ops-session", "ops", {"Cookie": "ops"},
                              allowed_origins=["http://t.local"], role="admin",
                              principal=permitted)
        ctx.sessions.register("anonymous", "anonymous", allowed_origins=["http://t.local"],
                              role="anonymous", principal=ANON)
        led = OwnershipLedger()
        led.record(OwnershipFact(object_ref=principals.object_reference(
            url, run_id="permission-run"), owner_principal_id="alice"))
        validator = CrossIdentityValidator(run_context=ctx, ownership=led)

        async def _fake_probe(url, headers, session_ref=None):
            import identity_compare
            return identity_compare.Probe(
                401 if session_ref == "anonymous" else 200,
                "denied" if session_ref == "anonymous" else "SECRET owner data 1234567890")

        validator._probe = _fake_probe
        result = self._run(validator)
        self.assertFalse(result.confirmed)
        self.assertIn("authorized", result.summary.lower())


if __name__ == "__main__":
    unittest.main()
