"""Cache-buster query parameters and Engine.IO polling transports (r5/r6 live runs).

Caller level: findings go through the real plan builder (planner.plans_for_findings),
the real validators' plan() and the real store (test_plans rows), and validators are
chosen by the real ValidatorRegistry.for_finding. Negative controls keep real
identifiers (id=1 vs id=2, object ids, words, date-only filters) splitting plans.
No network: nothing here runs a validator."""
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from harness import planner, store
from harness.execution_registry import execution_key
from harness.models import Finding, HttpExchange
from harness.orchestrator_helpers import confirmation_cache_key
from harness.validators.registry import ValidatorRegistry
from harness.volatile_params import is_polling_transport, is_volatile_value, stable_url

BASE = "https://shop.test/rest/products/search"
POLL = "https://shop.test/socket.io/"


def _exchange(url, method="GET", body="", headers=None):
    return HttpExchange(url=url, method=method,
                        request_headers=headers or {"Cookie": "session=abc"},
                        request_body=body, response_status=200, response_headers={},
                        response_body="ok")


def _finding(vc):
    return Finding(vulnerability_class=vc, confidence=0.6, summary="s", evidence="e",
                   suggested_test="t", basis="derived", severity="high")


class _TempDb(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmpdir.cleanup()

    def plan_rows(self):
        conn = store._connect()
        try:
            return conn.execute("SELECT plan_id, capability, url FROM test_plans").fetchall()
        finally:
            conn.close()

    def persist(self, urls, classes=("sqli",)):
        """Each URL as its own capture through the plan builder and the store;
        returns the plans each persist call reported as bound to its capture."""
        bound = []
        for url in urls:
            exchange = _exchange(url)
            plans = planner.plans_for_findings(exchange, [_finding(c) for c in classes])
            bound.append(store.persist_test_plans(exchange, plans))
        return bound


class PlanDedupeTests(_TempDb):
    def test_random_t_token_collapses_to_one_plan(self):
        bound = self.persist([f"{BASE}?q=apple&t=Nq3xYz8", f"{BASE}?q=apple&t=Pk7aBc2"])
        rows = self.plan_rows()
        self.assertEqual(len(rows), 1, rows)
        # The row keeps the first capture's exact URL and binding.
        self.assertTrue(rows[0][2].endswith("t=Nq3xYz8"))
        self.assertEqual(len(bound[0]), 1)
        self.assertEqual(bound[1], [], "the second capture must not claim the first's row")

    def test_epoch_cache_buster_collapses(self):
        self.persist([f"{BASE}?q=apple&_=1762689296123", f"{BASE}?q=apple&_=1762689299456"])
        self.assertEqual(len(self.plan_rows()), 1)

    def test_date_valued_cache_buster_collapses(self):
        d1 = quote("Mon Nov 09 2026 12:34:56 GMT+0100 (Central European Standard Time)")
        d2 = quote("Mon Nov 09 2026 12:35:07 GMT+0100 (Central European Standard Time)")
        self.persist([f"https://shop.test/api/Products?d={d1}",
                      f"https://shop.test/api/Products?d={d2}",
                      "https://shop.test/api/Products?d=2026-11-09T12:36:01.042Z"])
        self.assertEqual(len(self.plan_rows()), 1, self.plan_rows())

    def test_cache_buster_on_one_capture_only_collapses(self):
        self.persist([f"{BASE}?q=apple", f"{BASE}?q=apple&ts=1762689296"])
        self.assertEqual(len(self.plan_rows()), 1)

    def test_real_identifier_still_splits(self):
        """Negative control: ?id=1 vs ?id=2 are two objects, two plans."""
        bound = self.persist([f"{BASE}?id=1", f"{BASE}?id=2"])
        self.assertEqual(len(self.plan_rows()), 2)
        self.assertEqual([len(b) for b in bound], [1, 1])

    def test_object_ids_and_words_still_split(self):
        """Negative control: hex/UUID object ids, search words, date-only filters,
        a five-digit number and a mixed-case code under a long name are kept."""
        urls = [f"{BASE}?oid=5f8d0d55b54764421b7156c3", f"{BASE}?oid=5f8d0d55b54764421b7156c4",
                f"{BASE}?u=3fa85f64-5717-4562-b3fc-2c963f66afa6",
                f"{BASE}?u=3fa85f64-5717-4562-b3fc-2c963f66afa7",
                f"{BASE}?q=Laptop", f"{BASE}?q=Banana",
                f"{BASE}?from=2026-11-01", f"{BASE}?from=2026-11-02",
                f"{BASE}?page=12345", f"{BASE}?page=12346",
                f"{BASE}?coupon=Ab3dE9xY", f"{BASE}?coupon=Qz7kLm2P"]
        self.persist(urls)
        self.assertEqual(len(self.plan_rows()), len(urls))

    def test_opaque_short_named_and_id_named_values_still_split(self):
        """Negative control (review): a short-named parameter carrying an opaque
        mixed-case object id (`v=dQw4w9WgXcQ`, `k=Ab3dE9xY`) and an id-named
        parameter whose value happens to look like an epoch are objects: each
        capture is its own plan, bound to its own capture, and its own
        confirmation case."""
        pairs = [("v=dQw4w9WgXcQ", "v=9bZkp7q19f0"), ("k=Ab3dE9xY", "k=Qz7kLm2P"),
                 ("id=1762689296", "id=1762689297"), ("orderId=1762689296123", "orderId=1762689296124"),
                 ("_id=Nq3xYz8", "_id=Pk7aBc2")]
        urls = [f"{BASE}?{q}" for pair in pairs for q in pair]
        bound = self.persist(urls)
        self.assertEqual(len(self.plan_rows()), len(urls), self.plan_rows())
        self.assertEqual([len(b) for b in bound], [1] * len(urls))
        for a, b in pairs:
            ea, eb = _exchange(f"{BASE}?{a}"), _exchange(f"{BASE}?{b}")
            self.assertNotEqual(confirmation_cache_key("sqlmap", ea),
                                confirmation_cache_key("sqlmap", eb), (a, b))

    def test_different_body_still_splits(self):
        """Negative control: the stable key drops query cache-busters only."""
        a = _exchange(f"{BASE}?t=Nq3xYz8", "POST", '{"q":"a"}')
        b = _exchange(f"{BASE}?t=Pk7aBc2", "POST", '{"q":"b"}')
        ids = {p.id for e in (a, b) for p in planner.plans_for_findings(e, [_finding("sqli")])}
        self.assertEqual(len(ids), 2)

    def test_binding_fingerprint_stays_exact(self):
        a, b = _exchange(f"{BASE}?t=Nq3xYz8"), _exchange(f"{BASE}?t=Pk7aBc2")
        pa = planner.plans_for_findings(a, [_finding("sqli")])[0]
        pb = planner.plans_for_findings(b, [_finding("sqli")])[0]
        self.assertEqual(pa.id, pb.id)
        self.assertNotEqual(pa.source_exchange_hash, pb.source_exchange_hash)
        self.assertEqual(pa.source_exchange_hash, planner.exchange_fingerprint(a))


class ValidatorPlanIdTests(unittest.TestCase):
    def setUp(self):
        self.registry = ValidatorRegistry({"validators": {"active_enabled": True}})

    def test_sqlmap_and_websocket_plan_ids_ignore_cache_buster(self):
        for name, vc, url in (("sqlmap", "sqli", f"{BASE}?q=a&t="),
                              ("websocket_validator", "websocket", f"{POLL}?EIO=4&transport=polling&t=")):
            v = next(v for v in self.registry.validators.values() if v.name == name)
            a, b = _exchange(url + "Nq3xYz8"), _exchange(url + "Pk7aBc2")
            b = b.model_copy(update={"response_body": "different frame"})
            self.assertEqual(v.plan(_finding(vc), a).id, v.plan(_finding(vc), b).id, name)
            c = _exchange(url.replace("q=a", "q=b") + "Nq3xYz8", headers={"Cookie": "session=xyz"})
            self.assertNotEqual(v.plan(_finding(vc), a).id, v.plan(_finding(vc), c).id, name)


class PollingTransportTests(_TempDb):
    POLL_URL = f"{POLL}?EIO=4&transport=polling&t=PxQ9aB&sid=abc123"

    def test_polling_url_gets_no_injection_or_csrf_plan(self):
        exchange = _exchange(self.POLL_URL, "POST", "40")
        findings = [_finding(c) for c in ("sqli", "csrf", "nosql", "ssti", "websocket")]
        plans = planner.plans_for_findings(exchange, findings)
        caps = {p.capability for p in plans}
        self.assertEqual(caps, {"websocket_cswsh_validation"})

    def test_same_findings_on_a_normal_url_are_planned(self):
        """Negative control: the exclusion is the polling transport, not the classes."""
        exchange = _exchange("https://shop.test/api/feedback?x=1", "POST", "a=1")
        findings = [_finding(c) for c in ("sqli", "csrf", "websocket")]
        caps = {p.capability for p in planner.plans_for_findings(exchange, findings)}
        self.assertTrue({"sql_injection_validation", "csrf_validation",
                         "websocket_cswsh_validation"} <= caps, caps)

    def test_websocket_upgrade_transport_is_not_polling(self):
        self.assertFalse(is_polling_transport(f"{POLL}?EIO=4&transport=websocket"))
        self.assertFalse(is_polling_transport(f"{BASE}?transport=polling"))
        self.assertTrue(is_polling_transport(self.POLL_URL))

    def test_registry_drops_injection_and_csrf_validators_on_polling(self):
        registry = ValidatorRegistry({"validators": {"active_enabled": True}})
        poll = _exchange(self.POLL_URL, "POST", "40")
        normal = _exchange("https://shop.test/api/feedback?x=1", "POST", "a=1")
        for vc, name in (("sqli", "sqlmap"), ("csrf", "csrf")):
            on_normal = {v.name for v in registry.for_finding(_finding(vc), normal)}
            on_poll = {v.name for v in registry.for_finding(_finding(vc), poll)}
            if name not in on_normal:
                self.skipTest(f"{name} not registered in this configuration")
            self.assertNotIn(name, on_poll)
        ws = {v.name for v in registry.for_finding(_finding("websocket"), poll)}
        self.assertIn("websocket_validator", ws)

    def test_polling_requests_collapse_for_websocket_plans(self):
        urls = [f"{POLL}?EIO=4&transport=polling&t=PxQ9aB",
                f"{POLL}?EIO=4&transport=polling&t=PxQ9bK"]
        self.persist(urls, classes=("websocket", "sqli", "csrf"))
        rows = self.plan_rows()
        self.assertEqual([r[1] for r in rows], ["websocket_cswsh_validation"])


class KeyTests(unittest.TestCase):
    def test_confirmation_and_execution_keys_ignore_cache_buster(self):
        a, b = _exchange(f"{BASE}?q=a&t=Nq3xYz8"), _exchange(f"{BASE}?q=a&t=Pk7aBc2")
        self.assertEqual(confirmation_cache_key("csrf", a), confirmation_cache_key("csrf", b))
        for name in ("csrf", "sqlmap", "xxe"):
            self.assertEqual(execution_key(name, a), execution_key(name, b), name)
        c = _exchange(f"{BASE}?q=a")
        self.assertEqual(execution_key("xxe", a), execution_key("xxe", c))

    def test_keys_still_split_real_identifiers(self):
        a, b = _exchange(f"{BASE}?id=1"), _exchange(f"{BASE}?id=2")
        self.assertNotEqual(confirmation_cache_key("csrf", a), confirmation_cache_key("csrf", b))
        self.assertNotEqual(execution_key("idor_read", a), execution_key("idor_read", b))

    def test_value_shapes(self):
        volatile = [("t", "Nq3xYz8"), ("_", "1762689296123"), ("ts", "1762689296"),
                    ("d", "2026-11-09T12:34:56Z"), ("d", "Mon, 09 Nov 2026 12:34:56 GMT"),
                    ("r", "0.8394712934")]
        kept = [("id", "1"), ("id", "1234567890"), ("oid", "5f8d0d55b54764421b7156c3"),
                ("q", "Laptop"), ("from", "2026-11-09"), ("coupon", "Ab3dE9xY"),
                ("token", "eyJhbGciOiJIUzI1NiJ9.e30.x"), ("n", "99999999999"),
                ("v", "dQw4w9WgXcQ"), ("k", "Ab3dE9xY"), ("id", "1762689296"),
                ("userId", "2026-11-09T12:34:56Z"), ("_id", "Nq3xYz8")]
        volatile += [("_t", "Nq3xYz8"), ("cb", "Pk7aBc2"), ("r", "Nq3xYz8")]
        for name, value in volatile:
            self.assertTrue(is_volatile_value(name, value), (name, value))
        for name, value in kept:
            self.assertFalse(is_volatile_value(name, value), (name, value))

    def test_stable_url_keeps_raw_spelling(self):
        url = f"{BASE}?q=a%20b&t=Nq3xYz8&page=2"
        self.assertEqual(stable_url(url), f"{BASE}?q=a%20b&page=2")
        self.assertEqual(stable_url(f"{BASE}?q=a"), f"{BASE}?q=a")
        self.assertEqual(stable_url(BASE), BASE)


if __name__ == "__main__":
    unittest.main()
