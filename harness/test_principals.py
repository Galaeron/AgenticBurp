"""Tests for Astra T02 -- explicit principal / session / ownership model (R27).

The handoff's test matrix: Alice & Bob in tenant A, Carol in tenant B, an
explicitly-permitted privileged principal, and anonymous; own-object success,
same-tenant unauthorized, cross-tenant unauthorized, public/shared objects, and
refreshed Alice credentials. Expected permissions are declared by the fixture,
never inferred from role rank.
"""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
