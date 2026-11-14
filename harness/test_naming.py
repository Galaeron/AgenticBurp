"""r7: one singular rule for object-type names (harness.naming).

r7 named an object 'delivery-statu' (from "status"): three modules each had a
naive `s[:-1]` singulariser. The rule is now shared; these tests check the rule
itself, that the modules that name objects from routes agree on a key, and that
an answer saved under the old key is still found (the negative control is a
different object, whose answer must not match).
"""
from __future__ import annotations

import shutil
import tempfile
import time
import unittest
from pathlib import Path

from harness import access_matrix, business_context_agent, naming, store
from harness.self_ownership import SelfOwnership


class SingularRuleTests(unittest.TestCase):
    def test_words_already_singular_are_kept(self):
        for word in ("status", "address", "addresss", "analysis", "basis", "bonus", "campus",
                     "class", "process"):
            self.assertEqual(naming.singular(word), word, word)

    def test_plurals(self):
        cases = {"statuses": "status", "addresses": "address", "categories": "category",
                 "boxes": "box", "matches": "match", "dishes": "dish", "notes": "note",
                 "Cards": "Card", "houses": "house", "caches": "cache", "responses": "response",
                 "BasketItems": "BasketItem", "QUANTITIES": "QUANTITY"}
        for plural, single in cases.items():
            self.assertEqual(naming.singular(plural), single, plural)

    def test_short_words_unchanged(self):
        self.assertEqual(naming.singular("us"), "us")
        self.assertEqual(naming.singular(""), "")


class CrossModuleAgreementTests(unittest.TestCase):
    """The business-context object name, the access-matrix object key and a
    self-observed ownership fact all key the SAME type for one route."""

    def test_status_route_keys_agree(self):
        noun = business_context_agent._primary_noun("/api/delivery-status/{id}")
        self.assertEqual(noun, "delivery-status")
        shape = access_matrix.object_and_action("GET", "/api/delivery-status/{id}")
        self.assertEqual(access_matrix.object_key(shape[0]), naming.object_key(noun))
        owned = SelfOwnership(persist=False)
        owned.observe(source="transport", principal_id="alice", method="POST",
                      url="http://app.test/api/delivery-status", status=201,
                      response_body='{"id": 5}')
        # The fact is found under the singular route and under the plural one.
        self.assertIsNotNone(owned.fact_for("http://app.test/api/delivery-status/5"))
        self.assertIsNotNone(owned.fact_for("http://app.test/api/delivery-statuses/5"))

    def test_double_s_route_is_not_shortened(self):
        # A route really spelled with a trailing "ss": the object, the matrix key and
        # the ownership fact keep it (the old self_ownership stem dropped one "s").
        noun = business_context_agent._primary_noun("/api/Addresss/{id}")
        self.assertEqual(noun, "addresss")
        owned = SelfOwnership(persist=False)
        owned.observe(source="transport", principal_id="alice", method="POST",
                      url="http://app.test/api/Addresss", status=201,
                      response_body='{"data": {"id": 3}}')
        self.assertIsNotNone(owned.fact_for("http://app.test/api/addresss/3"))
        # control: a different type (the old stem keyed both as "address")
        self.assertIsNone(owned.fact_for("http://app.test/api/address/3"))


class LegacyKeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="naming_")
        self._saved = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _legacy_row(self, key: str, object_type: str):
        conn = store._connect()
        try:
            conn.executescript(access_matrix._SCHEMA)
            with conn:
                conn.execute(
                    "INSERT INTO access_matrix_answers (engagement_id, host, role, object_key, "
                    "object_type, action, answer, operator, source, answered_at) "
                    "VALUES ('', 'app.test', 'user', ?, ?, 'read', 'owner_only', 'op', "
                    "'operator', ?)", (key, object_type, time.time()))
        finally:
            conn.close()

    def test_answer_saved_under_the_old_key_is_found(self):
        self._legacy_row("deliverystatu", "delivery-statu")
        found = access_matrix.expectation_for(None, "app.test", "user", "delivery-status", "read")
        self.assertIsNotNone(found)
        self.assertEqual(found["answer"], "owner_only")

    def test_new_answers_use_the_correct_key(self):
        saved = access_matrix.save_answers("app.test", [
            {"role": "user", "object_type": "Statuses", "action": "read", "answer": "denied"}],
            operator="op")
        self.assertEqual(saved[0]["object_key"], "status")
        self.assertIsNotNone(access_matrix.expectation_for(None, "app.test", "user", "status", "read"))

    def test_control_another_object_does_not_match(self):
        self._legacy_row("deliverystatu", "delivery-statu")
        self.assertIsNone(access_matrix.expectation_for(None, "app.test", "user", "delivery", "read"))


if __name__ == "__main__":
    unittest.main()
