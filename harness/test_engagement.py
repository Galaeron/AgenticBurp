"""Tests for the engagement spine (shared surface model + fused rating)."""
import unittest

from harness import engagement
from harness.engagement import EngagementState, SurfaceEndpoint, normalize_path, template_from_exchange
from harness.models import HttpExchange


class NormalizeTests(unittest.TestCase):
    def test_aligns_concrete_and_templated(self):
        self.assertEqual(normalize_path("https://t.test/api/orders/42?x=1"), "/api/orders/{id}")
        self.assertEqual(normalize_path("/api/orders/{id}"), "/api/orders/{id}")

    def test_strips_host_and_query(self):
        self.assertEqual(normalize_path("http://t.test/a/b?c=d#e"), "/a/b")

    def test_long_hex_collapsed(self):
        self.assertEqual(normalize_path("/reset/a1b2c3d4e5f6a7b8"), "/reset/{id}")


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.st = EngagementState(host="shop.test")

    def test_ingest_endpoints(self):
        self.st.ingest_endpoints(["/api/a", "/api/b"])
        self.assertEqual(len(self.st.endpoints), 2)

    def test_ingest_findings_sets_status(self):
        self.st.ingest_findings("http://shop.test/api/x", "GET",
                                [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.7, "confirmed": False}])
        ep = self.st.endpoints["GET /api/x"]
        self.assertEqual(ep.status, "analyzed")
        self.st.ingest_findings("http://shop.test/api/x", "GET",
                                [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9,
                                  "confirmed": True, "confirmed_by_leg": "browser_xss"}])
        self.assertEqual(self.st.endpoints["GET /api/x"].status, "validated")

    def test_add_finding_dedup_supersede(self):
        ep = SurfaceEndpoint("GET", "/x")
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high", "confidence": 0.5, "confirmed": False})
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high", "confidence": 0.9,
                        "confirmed": True, "confirmed_by_leg": "sqlmap"})
        self.assertEqual(len(ep.findings), 1)
        self.assertTrue(ep.findings[0]["confirmed"])

    def test_confirmed_finding_not_downgraded_by_confident_hypothesis(self):
        """R07 NEGATIVE CONTROL: a confirmed proof must never be replaced by a
        LATER unconfirmed hypothesis, even one with higher model confidence."""
        ep = SurfaceEndpoint("GET", "/x")
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high",
                        "confidence": 0.9, "confirmed": True,
                        "evidence": "sqlmap: injectable param q", "confirmation_method": "sqlmap"})
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high",
                        "confidence": 0.99, "confirmed": False,
                        "summary": "model thinks maybe sqli"})
        self.assertEqual(len(ep.findings), 1)
        f = ep.findings[0]
        self.assertTrue(f["confirmed"])              # still a proof
        self.assertEqual(f["confidence"], 0.9)       # not bumped to 0.99
        self.assertEqual(f["evidence"], "sqlmap: injectable param q")  # proof retained

    def test_add_finding_preserves_proof_and_history(self):
        """Proof fields survive de-dup, and a superseded hypothesis is retained."""
        ep = SurfaceEndpoint("GET", "/x")
        ep.add_finding({"vulnerability_class": "idor", "severity": "medium",
                        "confidence": 0.5, "confirmed": False, "summary": "guess"})
        ep.add_finding({"vulnerability_class": "idor", "severity": "high",
                        "confidence": 0.95, "confirmed": True,
                        "evidence": "read ticket #2 as user A", "confirmation_method": "cross_identity"})
        f = ep.findings[0]
        self.assertTrue(f["confirmed"])
        self.assertEqual(f["evidence"], "read ticket #2 as user A")
        self.assertEqual(f["confirmation_method"], "cross_identity")
        # the earlier hypothesis is preserved in the audit history, not erased
        self.assertTrue(f.get("_superseded"))
        self.assertFalse(f["_superseded"][0]["confirmed"])

    def test_ingest_role_crawl_matrix_and_idor(self):
        result = {
            "endpoints": [{"method": "GET", "path": "/api/orders/{id}", "by_role": {"user": 200},
                           "reachable_roles": ["user"], "object_scoped": True}],
            "idor_findings": [{"vulnerability_class": "idor", "severity": "high", "confidence": 0.65,
                               "confirmed": False, "validation_hints": ["cross_identity_compare:/api/orders/{id}"]}],
        }
        self.st.ingest_role_crawl(result)
        ep = self.st.endpoints["GET /api/orders/{id}"]
        self.assertTrue(ep.object_scoped)
        self.assertIn("user", ep.reachable_roles)
        self.assertTrue(any(f["vulnerability_class"] == "idor" for f in ep.findings))

    def test_ingest_prioritization(self):
        self.st.ingest_endpoints(["/api/x"])
        self.st.ingest_prioritization([{"method": "GET", "url": "http://shop.test/api/x",
                                        "ai_priority": "high", "ai_score": 0.8}])
        self.assertEqual(self.st.endpoints["GET /api/x"].llm_score, 0.8)


class FusionTests(unittest.TestCase):
    def test_anonymous_reaching_admin_ranks_high(self):
        st = EngagementState(host="shop.test")
        st.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": "/rest/admin/config", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False},
            {"method": "GET", "path": "/api/public", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False}]})
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/rest/admin/config")
        self.assertTrue(any("privileged" in r for r in wl[0]["reasons"]))

    def test_confirmed_finding_outranks_bare_endpoint(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/api/plain"])
        st.ingest_findings("http://shop.test/api/hit", "GET",
                           [{"vulnerability_class": "sqli", "severity": "critical", "confidence": 0.9, "confirmed": True}])
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/api/hit")

    def test_validated_is_deprioritized(self):
        st = EngagementState(host="shop.test")
        # two identical-severity findings; one validated, one still a hypothesis
        st.ingest_findings("http://shop.test/api/done", "GET",
                           [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9,
                             "confirmed": True, "confirmed_by_leg": "browser_xss"}])
        st.ingest_findings("http://shop.test/api/open", "GET",
                           [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9, "confirmed": False}])
        scores = {e["path"]: e["score"] for e in st.worklist()}
        self.assertLess(scores["/api/done"], scores["/api/open"])

    def test_llm_score_contributes(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/api/rated", "/api/unrated"])
        st.ingest_prioritization([{"method": "GET", "url": "http://shop.test/api/rated",
                                   "ai_priority": "critical", "ai_score": 0.95}])
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/api/rated")

    def test_roundtrip(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/a"])
        st.ingest_findings("http://shop.test/a", "GET",
                           [{"vulnerability_class": "idor", "severity": "high", "confidence": 0.6, "confirmed": False}])
        st.ingest_identity("admin", "admin", source="seed")
        st2 = EngagementState.from_dict(st.to_dict())
        self.assertEqual(len(st2.endpoints), 1)
        self.assertEqual(st2.identities, st.identities)
        self.assertEqual(st2.endpoints["GET /a"].findings, st.endpoints["GET /a"].findings)


class CapabilityTests(unittest.TestCase):
    def test_extract_jwt_from_body(self):
        cred = engagement._extract_credential({}, 'x eyJhbGciOiJI.eyJzdWIiOiIx.sigABC1234567 y')
        self.assertEqual(cred["kind"], "bearer")
        self.assertIn("Authorization", cred["headers"])

    def test_extract_session_cookie(self):
        cred = engagement._extract_credential({"Set-Cookie": "session=abc123def; Path=/"}, "")
        self.assertEqual(cred["kind"], "cookie")
        self.assertIn("session=abc123def", cred["headers"]["Cookie"])

    def test_extract_json_token(self):
        cred = engagement._extract_credential({}, '{"access_token":"longtokenvalue12345"}')
        self.assertEqual(cred["kind"], "bearer")

    def test_no_credential(self):
        self.assertIsNone(engagement._extract_credential({}, '{"status":"ok"}'))

    def test_credential_capability_from_auth_finding(self):
        f = {"vulnerability_class": "auth", "confidence": 0.8, "confirmed": True}
        caps = engagement.detect_capabilities(f, {"Set-Cookie": "sid=abc123def"}, "", "http://t/login")
        self.assertTrue(any(c["type"] == "credential" for c in caps))

    def test_reachable_area_from_idor(self):
        f = {"vulnerability_class": "idor", "confidence": 0.7, "confirmed": True}
        caps = engagement.detect_capabilities(f, {}, "", "http://t/api/orders/1")
        self.assertTrue(any(c["type"] == "reachable_area" for c in caps))

    def test_apply_credential_registers_identity_and_queues_no_secret(self):
        st = EngagementState(host="t")
        caps = [{"type": "credential", "kind": "bearer",
                 "headers": {"Authorization": "Bearer SECRET"}, "source_url": "http://t/login",
                 "reason": "learned"}]
        cred_caps = st.apply_capabilities(caps, "http://t/login")
        self.assertEqual(len(cred_caps), 1)  # returned for in-process use
        self.assertTrue(any(i["source"] == "finding" for i in st.identities))
        # the queued action + persisted state must NOT contain the secret
        blob = str(st.to_dict())
        self.assertNotIn("SECRET", blob)
        self.assertTrue(any(a["kind"] == "recrawl_as_derived" for a in st.pending()))

    def test_apply_reachable_area_queues_action(self):
        st = EngagementState(host="t")
        caps = [{"type": "reachable_area", "area": "/rest/admin", "source_url": "http://t/rest/admin",
                 "reason": "broken access"}]
        st.apply_capabilities(caps, "http://t/rest/admin")
        self.assertTrue(any(a["kind"] == "recrawl_area" and a["target"] == "/rest/admin"
                            for a in st.pending()))

    def test_enqueue_dedups(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r1")
        st.enqueue_action("recrawl_area", "/x", "r2")
        self.assertEqual(len(st.pending()), 1)

    def test_resolve_action(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r")
        st.resolve_action("recrawl_area", "/x")
        self.assertEqual(st.pending(), [])

    def test_pending_actions_roundtrip(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r")
        st2 = EngagementState.from_dict(st.to_dict())
        self.assertEqual(len(st2.pending()), 1)


class BusinessLogicTests(unittest.TestCase):
    def test_review_by_class(self):
        spec = engagement.business_logic_review("business_logic", "http://t/api/x")
        self.assertIsNotNone(spec)
        self.assertIn("human", spec["needs"])

    def test_review_by_path_shape(self):
        self.assertIsNotNone(engagement.business_logic_review("xss", "http://t/checkout/confirm"))
        self.assertIsNotNone(engagement.business_logic_review("misconfig", "http://t/api/wallet/transfer"))

    def test_no_review_for_plain(self):
        self.assertIsNone(engagement.business_logic_review("xss", "http://t/api/search"))

    def test_flag_adds_blocked_task(self):
        st = EngagementState(host="t")
        added = st.flag_business_logic("business_logic", "http://t/cart/apply-coupon")
        self.assertTrue(added)
        # it's surfaced as BLOCKED (needs human), not a ready action
        self.assertTrue(any(b["needs"] and "human" in b["needs"] for b in st.blocked()))
        self.assertFalse(any(r["kind"] == "review" for r in st.pending()))

    def test_flag_noop_for_plain(self):
        st = EngagementState(host="t")
        self.assertFalse(st.flag_business_logic("xss", "http://t/api/search"))


class StoreAndEndpointTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from harness import store
        from pathlib import Path
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"
        self.store = store

    def tearDown(self):
        self.store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_save_load_roundtrip(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/a", "/b"])
        self.store.save_engagement("shop.test", st.to_dict())
        loaded = self.store.load_engagement("shop.test")
        self.assertEqual(len(loaded["endpoints"]), 2)

    def test_load_missing_is_none(self):
        self.assertIsNone(self.store.load_engagement("nope.test"))

    def test_engagement_endpoint(self):
        import harness.server as server_module
        from fastapi.testclient import TestClient
        client = TestClient(server_module.app, base_url="http://localhost")
        st = EngagementState(host="shop.test")
        st.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": "/rest/admin", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False}]})
        self.store.save_engagement("shop.test", st.to_dict())
        resp = client.get("/engagement/shop.test")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["worklist"])
        self.assertEqual(body["worklist"][0]["path"], "/rest/admin")


class MergeStateTests(unittest.TestCase):
    """R19: derived-identity discoveries must be merged into the primary state."""

    def test_merge_adds_new_endpoints_findings_identities(self):
        primary = EngagementState(host="t")
        primary._ep("GET", "/api/a")
        derived = EngagementState(host="t")
        d_ep = derived._ep("GET", "/api/secret")   # reachable only as the leaked id
        d_ep.reachable_roles = ["derived"]
        d_ep.add_finding({"vulnerability_class": "idor", "confirmed": True, "severity": "high",
                         "confirmed_by_leg": "cross_identity"})
        derived.ingest_identity("leaked-bearer", "derived")
        added = primary.merge_from(derived)
        self.assertEqual(added, 1)
        self.assertIn("GET /api/secret", primary.endpoints)
        self.assertTrue(primary.endpoints["GET /api/secret"].findings[0]["confirmed"])
        self.assertTrue(any(i["name"] == "leaked-bearer" for i in primary.identities))

    def test_merge_is_monotonic_on_shared_endpoint(self):
        primary = EngagementState(host="t")
        primary._ep("GET", "/api/x").add_finding(
            {"vulnerability_class": "idor", "confirmed": True, "severity": "high", "confidence": 0.9,
             "confirmed_by_leg": "cross_identity"})
        derived = EngagementState(host="t")
        derived._ep("GET", "/api/x").add_finding(
            {"vulnerability_class": "idor", "confirmed": False, "severity": "high", "confidence": 0.99})
        primary.merge_from(derived)
        # the confirmed proof survives an unconfirmed higher-confidence merge (R07)
        self.assertTrue(primary.endpoints["GET /api/x"].findings[0]["confirmed"])


class RequestTemplateTests(unittest.TestCase):
    """R05: capture and preserve the real request shape so replay isn't fabricated."""

    def test_record_template_captures_shape(self):
        st = EngagementState(host="t")
        ex = HttpExchange(url="http://t/api/tickets/42?expand=comments", method="POST",
                          request_headers={"Content-Type": "application/xml"},
                          request_body="<ticket/>", response_status=200,
                          response_headers={}, response_body="")
        st.record_template(ex.url, ex.method, ex)
        ep = st.endpoints["POST /api/tickets/{id}"]
        self.assertEqual(ep.template["body"], "<ticket/>")
        self.assertEqual(ep.template["query"], "expand=comments")
        self.assertEqual(ep.template["content_type"], "application/xml")
        self.assertEqual(ep.template["object_id"], "42")   # observed id, not fabricated 1

    def test_record_template_keeps_richest_capture(self):
        st = EngagementState(host="t")
        empty = HttpExchange(url="http://t/api/x", method="POST", request_headers={},
                             request_body="", response_status=200, response_headers={}, response_body="")
        rich = HttpExchange(url="http://t/api/x", method="POST", request_headers={},
                            request_body='{"a":1}', response_status=200, response_headers={}, response_body="")
        st.record_template("http://t/api/x", "POST", empty)
        st.record_template("http://t/api/x", "POST", rich)
        self.assertEqual(st.endpoints["POST /api/x"].template["body"], '{"a":1}')
        # a later empty capture must NOT clobber the richer template
        st.record_template("http://t/api/x", "POST", empty)
        self.assertEqual(st.endpoints["POST /api/x"].template["body"], '{"a":1}')

    def test_template_round_trips_through_dict(self):
        ep = SurfaceEndpoint("POST", "/api/x", template={"method": "POST", "body": "b",
                             "query": "q=1", "content_type": "application/json", "object_id": None})
        ep2 = SurfaceEndpoint.from_dict(ep.to_dict())
        self.assertEqual(ep2.template["body"], "b")
        self.assertEqual(ep2.template["query"], "q=1")

    def test_template_from_exchange_accepts_dict(self):
        t = template_from_exchange({"url": "http://t/a/9f8e7d6c5b4a3210?q=2", "method": "GET",
                                    "request_headers": {}, "request_body": ""})
        self.assertEqual(t["query"], "q=2")
        self.assertEqual(t["object_id"], "9f8e7d6c5b4a3210")


if __name__ == "__main__":
    unittest.main()
