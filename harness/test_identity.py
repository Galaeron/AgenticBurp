import unittest
import tempfile, os
import harness.identity as identity_mod


class IdentityDataclassTests(unittest.TestCase):
    def test_identity_gets_a_unique_id_and_defaults(self):
        i1 = identity_mod.Identity(name="Alice")
        i2 = identity_mod.Identity(name="Bob")
        self.assertNotEqual(i1.id, i2.id)
        self.assertEqual(i1.role, identity_mod.IdentityRole.USER)

    def test_session_links_identity_to_exchange_not_credential(self):
        i = identity_mod.Identity(name="Alice")
        s = identity_mod.Session(identity_id=i.id, host="a.test", exchange_hash="deadbeef")
        self.assertEqual(s.identity_id, i.id)
        self.assertFalse(hasattr(s, "password"))
        self.assertFalse(hasattr(s, "token"))


class StorePersistenceTests(unittest.TestCase):
    def setUp(self):
        from harness import store
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._orig_path = store._DB_PATH
        store._DB_PATH = self._tmp.name
        self.store = store

    def tearDown(self):
        self.store._DB_PATH = self._orig_path
        os.unlink(self._tmp.name)

    def test_save_and_list_identity(self):
        ident = identity_mod.Identity(name="Alice", role=identity_mod.IdentityRole.ADMIN, notes="test admin")
        self.store.save_identity(ident)
        found = self.store.list_identities()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "Alice")
        self.assertEqual(found[0]["role"], "admin")

    def test_get_identity_by_id(self):
        ident = identity_mod.Identity(name="Bob")
        self.store.save_identity(ident)
        got = self.store.get_identity(ident.id)
        self.assertIsNotNone(got)
        self.assertEqual(got["name"], "Bob")

    def test_get_identity_unknown_id_returns_none(self):
        self.assertIsNone(self.store.get_identity("nonexistent"))

    def test_sessions_for_host_joins_identity_name(self):
        ident = identity_mod.Identity(name="Alice", role=identity_mod.IdentityRole.USER)
        self.store.save_identity(ident)
        sess = identity_mod.Session(identity_id=ident.id, host="a.test", exchange_hash="hash1", label="logged in")
        self.store.save_session(sess)
        rows = self.store.sessions_for_host("a.test")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_name"], "Alice")
        self.assertEqual(rows[0]["exchange_hash"], "hash1")

    def test_sessions_for_host_empty_when_none_captured(self):
        self.assertEqual(self.store.sessions_for_host("nowhere.test"), [])

    def test_multiple_sessions_ordered_most_recent_first(self):
        ident = identity_mod.Identity(name="Alice")
        self.store.save_identity(ident)
        import time
        s1 = identity_mod.Session(identity_id=ident.id, host="a.test", exchange_hash="h1")
        self.store.save_session(s1)
        time.sleep(0.01)
        s2 = identity_mod.Session(identity_id=ident.id, host="a.test", exchange_hash="h2")
        self.store.save_session(s2)
        rows = self.store.sessions_for_host("a.test")
        self.assertEqual(rows[0]["exchange_hash"], "h2")


if __name__ == "__main__":
    unittest.main()
