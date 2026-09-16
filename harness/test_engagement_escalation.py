"""Tests for auto_escalate blast-radius guards (dedup / verify / per-host cap)."""
import asyncio
import unittest
from unittest.mock import patch

import global_throttle
import task_graph
from engagement import EngagementState


class _Resp:
    def __init__(self, status):
        self.status_code = status
        self.text = ""
        # W-16: the credential probe now sends via run_context.TargetTransport, which
        # inspects response headers (redirect handling), so the mock must carry them.
        self.headers = {}


def _cred_cap(url="http://shop.test/login"):
    return {"type": "credential", "kind": "bearer",
            "headers": {"Authorization": "Bearer learned"}, "source_url": url, "reason": "r"}


class _FakeCrawlResult:
    endpoints = []
    def to_dict(self):
        return {"endpoints": [], "idor_findings": [], "auth_bypass_candidates": [], "idor_candidates": []}


class AutoEscalateGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server as server_module
        cls.orch = server_module.orchestrator

    def setUp(self):
        global_throttle.configure(0)
        self.orch.allowed_hosts = ["shop.test"]
        self.orch._escalation_counts = {}
        self.orch.engagement_max_escalations = 10

    def _run(self, st, caps, *, verify_status=200, crawl_spy=None):
        async def fake_crawl(*a, **k):
            if crawl_spy is not None:
                crawl_spy.append(True)
            return _FakeCrawlResult()

        async def fake_request(self, method, url, headers=None, **kw):  # W-16: transport uses .request
            return _Resp(verify_status)

        with patch("role_crawl.crawl_roles", fake_crawl), \
             patch("httpx.AsyncClient.request", fake_request):
            asyncio.run(self.orch._auto_escalate("shop.test", "http://shop.test/login", caps, st))

    def test_verified_credential_triggers_crawl(self):
        st = EngagementState(host="shop.test")
        spy = []
        self._run(st, [_cred_cap()], verify_status=200, crawl_spy=spy)
        self.assertEqual(len(spy), 1)
        self.assertEqual(self.orch._escalation_counts["shop.test"], 1)

    def test_unverified_credential_skipped(self):
        st = EngagementState(host="shop.test")
        spy = []
        self._run(st, [_cred_cap()], verify_status=401, crawl_spy=spy)
        self.assertEqual(spy, [])  # 401 -> not crawled
        self.assertEqual(self.orch._escalation_counts.get("shop.test", 0), 0)

    def test_already_escalated_identity_deduped(self):
        st = EngagementState(host="shop.test")
        # pre-create + complete the recrawl task for this identity
        import engagement
        cap = _cred_cap()
        st.apply_capabilities([cap], cap["source_url"])
        tid = task_graph.make_id("recrawl_as_derived",
                                 f"derived:bearer@{engagement.normalize_path(cap['source_url'])}")
        st.graph.mark(tid, task_graph.DONE)
        spy = []
        self._run(st, [cap], verify_status=200, crawl_spy=spy)
        self.assertEqual(spy, [])  # deduped -> no second crawl

    def test_per_host_cap_stops_escalation(self):
        st = EngagementState(host="shop.test")
        self.orch._escalation_counts["shop.test"] = 10  # at cap
        spy = []
        self._run(st, [_cred_cap()], verify_status=200, crawl_spy=spy)
        self.assertEqual(spy, [])  # cap reached -> skip

    def test_out_of_scope_credential_not_verified(self):
        st = EngagementState(host="other.test")
        self.orch.allowed_hosts = ["shop.test"]
        ok = asyncio.run(self.orch._credential_grants_access(
            "http://other.test/x", {"Authorization": "Bearer x"}))
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
