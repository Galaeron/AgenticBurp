"""Tests for the expanded knowledge retrieval (gap 3: Memory Retriever)."""
import tempfile
import unittest
from pathlib import Path

import store
import knowledge
from models import HttpExchange


def _ex(url="https://shop.test/rest/products/search?q=1", body=""):
    return HttpExchange(url=url, method="GET", request_headers={}, request_body=body,
                        response_status=200, response_headers={}, response_body="")


class KnowledgeRagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"

    def tearDown(self):
        store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_builtin_corpus_still_works(self):
        # sqli agent on a search endpoint should still retrieve the sqli note.
        out = knowledge.retrieve("sqli", _ex())
        self.assertTrue(out)

    def test_external_note_retrieved(self):
        store.save_knowledge_note(["graphql", "introspection"],
                                  "This target exposes a GraphQL endpoint at /api/graphql -- try introspection.")
        out = knowledge.retrieve("graphql", _ex(url="https://shop.test/api/graphql"))
        self.assertIn("introspection", out)

    def test_free_text_note_matches_on_body_words(self):
        # A note with NO tags still matches on its own text. Use a distinctive
        # agent so it isn't crowded out of top_k by tied curated corpus entries.
        store.save_knowledge_note([], "The coupon redemption flow is race-condition prone.")
        out = knowledge.retrieve("recon", _ex(url="https://shop.test/api/coupon/redeem"), top_k=3)
        self.assertIn("coupon", out)

    def test_dedup_and_topk(self):
        for i in range(5):
            store.save_knowledge_note(["search"], f"note about search number {i}")
        out = knowledge.retrieve("recon", _ex(url="https://shop.test/search"), top_k=2)
        self.assertLessEqual(out.count("\n") + 1, 2)

    def test_remember_finding_persists_note(self):
        added = knowledge.remember_finding("sqli", "https://shop.test/rest/user/login")
        self.assertTrue(added)
        notes = store.list_knowledge_notes()
        self.assertTrue(any(n["source"] == "finding" for n in notes))
        # and it's retrievable for a similar endpoint
        out = knowledge.retrieve("sqli", _ex(url="https://shop.test/rest/user/login"))
        self.assertIn("CONFIRMED", out)

    def test_no_store_degrades_gracefully(self):
        # even if the store path is broken, retrieve falls back to the corpus.
        store._DB_PATH = Path(self.tmp.name) / "nonexistent" / "x.db"
        out = knowledge.retrieve("sqli", _ex())
        self.assertIsInstance(out, str)  # no crash


class KnowledgeEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"
        import server as server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_add_and_list(self):
        r = self.client.post("/knowledge", json={"note": "always check /actuator", "tags": ["misconfig"]})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["added"])
        notes = self.client.get("/knowledge").json()["notes"]
        self.assertTrue(any("actuator" in n["note"] for n in notes))

    def test_empty_note_is_400(self):
        self.assertEqual(self.client.post("/knowledge", json={"note": "  "}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
