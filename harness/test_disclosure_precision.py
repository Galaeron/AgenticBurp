"""Disclosure precision: a sensitive field NAME alone is a lead, not a finding.

Caller-level: every case runs through the orchestrator's captured-exchange review
(the same analyze() path the live run takes, with a silent model so only the
deterministic detectors can produce findings) and through the /scan/confidential
endpoint. Negative controls: a password field holding a real bcrypt or hex hash,
and an AWS key inside a label bundle, still reach high confidence.
"""
import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, coordinator, engagement, store
from harness.models import HttpExchange
from harness.orchestrator import review_captured_exchanges
from harness.test_smoke_phase0_capture_review import _build, _disclosure_on

_BCRYPT = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
_MD5_HEX = "0192023a7bbd73250516f069df18b500"

_I18N = json.dumps({
    "LABEL_EMAIL": "Email", "LABEL_PASSWORD": "Password",
    "LABEL_REPEAT_PASSWORD": "Repeat Password", "BTN_LOGIN": "Log in",
    "TITLE_LOGIN": "Login", "MANDATORY_PASSWORD": "Please provide a password.",
    "INVALID_PASSWORD_LENGTH": "Password must be 5-40 characters long.",
})
_TIMESTAMPS = json.dumps({"status": "success", "data": [
    {"id": 1, "name": "Widget", "createdAt": "2026-11-08T10:22:33.123Z",
     "updatedAt": "2026-11-08T10:22:33.123Z"},
    {"id": 2, "name": "Gadget", "createdAt": 1731150000007, "updatedAt": 1731150000007},
]})
_QUESTIONS = json.dumps({"status": "success", "data": [
    {"id": i, "question": q, "createdAt": "2026-11-08 10:22:33.123 +00:00",
     "updatedAt": "2026-11-08 10:22:33.123 +00:00"}
    for i, q in enumerate(["Your eldest sibling's middle name?", "Mother's maiden name?",
                           "Name of your favorite pet?", "Your favorite book?",
                           "Your ZIP/postal code when you were a teenager?"], 1)]})


def _capture(path: str, body: str) -> dict:
    return HttpExchange(
        url=f"http://localhost{path}", method="GET",
        request_headers={"Authorization": "Bearer usertok", "User-Agent": "precision"},
        request_body="", response_status=200,
        response_headers={"Content-Type": "application/json"}, response_body=body,
        analyst_note="role_crawl discovery capture as 'user' (HTTP 200)",
    ).model_dump()


class DisclosurePrecisionThroughReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="disclosure_precision_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        coordinator.reset_fail_open_stats()
        cls.state = engagement.EngagementState(host="localhost")
        captured = [
            _capture("/i18n/en.json", _I18N),
            _capture("/api/items", _TIMESTAMPS),
            _capture("/api/questions", _QUESTIONS),
            _capture("/api/account-export", json.dumps({"id": 1, "email": "a@b.test",
                                                 "password": _BCRYPT})),
            _capture("/api/hash-dump", json.dumps({"id": 2, "email": "c@d.test",
                                                 "password": _MD5_HEX})),
            _capture("/i18n/de.json", _I18N[:-1]
                     + ', "DEBUG_KEY": "AKIAIOSFODNN7EXAMPLE"}'),
        ]
        asyncio.run(review_captured_exchanges(_build(), cls.state, captured))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _max_conf(self, suffix):
        return max((float(f.get("confidence") or 0) for f in _disclosure_on(self.state, suffix)),
                   default=None)

    def test_i18n_bundle_mentioning_password_is_low(self):
        conf = self._max_conf("/i18n/en.json")
        self.assertIsNotNone(conf, "the label match should still surface as a weak lead")
        self.assertLess(conf, 0.5)

    def test_timestamp_fields_only_produce_no_disclosure(self):
        self.assertIsNone(self._max_conf("/api/items"))

    def test_question_catalogue_produces_no_high_disclosure(self):
        conf = self._max_conf("/api/questions")
        self.assertTrue(conf is None or conf < 0.5)

    def test_bcrypt_password_value_stays_high(self):
        self.assertGreaterEqual(self._max_conf("/api/account-export") or 0, 0.9)

    def test_hex_hash_password_value_stays_high(self):
        self.assertGreaterEqual(self._max_conf("/api/hash-dump") or 0, 0.9)

    def test_real_key_inside_label_bundle_stays_high(self):
        self.assertGreaterEqual(self._max_conf("/i18n/de.json") or 0, 0.9)


class DisclosurePrecisionThroughEndpoint(unittest.TestCase):
    def setUp(self):
        import harness.server as server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})

    def _scan(self, body):
        r = self.client.post("/scan/confidential", json={
            "url": "https://t.test/x", "method": "GET", "request_headers": {},
            "request_body": "", "response_status": 200, "response_headers": {},
            "response_body": body})
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_label_match_low_and_hash_match_high(self):
        low = self._scan(_I18N)
        self.assertTrue(low["findings"])
        self.assertTrue(all(f["confidence"] < 0.5 for f in low["findings"]))
        self.assertTrue(all(f["severity"] in ("info", "low") for f in low["findings"]))
        high = self._scan(json.dumps({"password": _BCRYPT}))
        self.assertGreaterEqual(max(f["confidence"] for f in high["findings"]), 0.9)

    def test_plain_password_value_outside_bundle_is_a_low_lead(self):
        out = self._scan(json.dumps({"id": 7, "password": "hunter22"}))
        self.assertTrue(out["findings"])
        self.assertTrue(all(f["confidence"] < 0.5 for f in out["findings"]))

    def test_epoch_timestamp_is_not_a_card_number(self):
        # 1731150000007 passes Luhn; as a createdAt value it is a date, not PII.
        self.assertEqual(self._scan(json.dumps({"createdAt": 1731150000007}))["match_count"], 0)
        # Control: the same digits in a non-timestamp field still match.
        self.assertGreaterEqual(self._scan(json.dumps({"card": "1731150000007"}))["match_count"], 1)


if __name__ == "__main__":
    unittest.main()
