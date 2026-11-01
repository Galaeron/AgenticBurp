"""Capture review is bounded by count and time, and reports what it left unreviewed."""
from __future__ import annotations

import asyncio
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import engagement_builder, role_crawl, worklist_investigator
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import review_captured_exchanges
from harness.role_crawl import RoleSession
from harness.test_deterministic_first import BASE, _config


def exchange(path):
    return HttpExchange(url=f"http://127.0.0.1:3002{path}", method="GET",
                        response_status=200, response_body=path)


def reviewer():
    orch = SimpleNamespace(analyze=AsyncMock(return_value=SimpleNamespace(agent_reports=[])))
    state = SimpleNamespace(record_template=lambda *args: None)
    return orch, state


def reviewed_urls(orch):
    return [call.args[0].url for call in orch.analyze.await_args_list]


class ReviewBounds(unittest.IsolatedAsyncioTestCase):
    async def test_limit_reports_truncation_and_leaves_the_rest_unseen(self):
        orch, state = reviewer()
        captured = [exchange("/a"), exchange("/b"), exchange("/c")]
        seen, errors = set(), []
        await review_captured_exchanges(orch, state, captured, max_reviews=1,
                                        seen=seen, errors=errors)
        self.assertEqual(orch.analyze.await_count, 1)
        self.assertEqual(errors, [{"phase": "capture_review", "error":
                                   "capture review limit reached: 2 captured exchange(s) not reviewed"}])
        # The two left over were never marked seen, so a later pass reviews them.
        await review_captured_exchanges(orch, state, captured, seen=seen, errors=errors)
        self.assertEqual(sorted(reviewed_urls(orch)), sorted(c.url for c in captured))
        self.assertEqual(len(errors), 1)

    async def test_expired_deadline_reviews_nothing_and_says_so(self):
        orch, state = reviewer()
        seen, errors = set(), []
        await review_captured_exchanges(orch, state, [exchange("/a"), exchange("/b")],
                                        seen=seen, errors=errors,
                                        deadline=time.monotonic() - 1)
        orch.analyze.assert_not_awaited()
        self.assertEqual(seen, set())
        self.assertEqual(errors[0]["error"],
                         "capture review time budget reached: 2 captured exchange(s) not reviewed")

    async def test_deadline_reached_mid_review_stops_before_the_next_capture(self):
        orch, state = reviewer()
        clock = SimpleNamespace(now=100.0)
        clock.monotonic = lambda: clock.now

        async def slow_review(*args, **kwargs):
            clock.now += 30
            return SimpleNamespace(agent_reports=[])

        orch.analyze.side_effect = slow_review
        errors = []
        with patch("harness.orchestrator_helpers.time", clock):
            await review_captured_exchanges(
                orch, state, [exchange("/a"), exchange("/b"), exchange("/c")],
                errors=errors, deadline=150.0)
        self.assertEqual(orch.analyze.await_count, 2)
        self.assertIn("time budget reached: 1 captured exchange(s)", errors[0]["error"])

    async def test_exhausted_frontier_within_bounds_is_not_truncation(self):
        orch, state = reviewer()
        errors = []
        await review_captured_exchanges(orch, state, [exchange("/a"), exchange("/b")],
                                        max_reviews=2, errors=errors,
                                        deadline=time.monotonic() + 3600)
        self.assertEqual(orch.analyze.await_count, 2)
        self.assertEqual(errors, [])


async def _build(base_url, roles, **kwargs):
    state = EngagementState(host="shop.test")
    state._ep("GET", "/filter")
    rc = role_crawl.RoleCrawlResult(base_url=base_url)
    rc.captured.extend(HttpExchange(method="GET", url=f"{BASE}{path}", response_status=200,
                                    response_body=path) for path in ("a", "b", "c"))
    return state, rc


async def _no_outcomes(*args, **kwargs):
    return []


class ReviewBoundsCaller(unittest.TestCase):
    def _investigate(self, review_limit, review_seconds, review=None):
        cfg = _config()
        cfg["engagement"].update(capture_review_limit=review_limit,
                                 capture_review_seconds=review_seconds)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["shop.test"]
        analyze = AsyncMock(return_value=SimpleNamespace(agent_reports=[]))
        patches = [patch.object(engagement_builder, "build_engagement", new=_build),
                   patch.object(worklist_investigator, "investigate_worklist", new=_no_outcomes),
                   patch("harness.orchestrator_chain.universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch.object(orch, "analyze", new=analyze)]
        if review is not None:
            patches.append(patch("harness.orchestrator_chain.review_captured_exchanges", new=review))
        for p in patches:
            p.start()
        try:
            started = time.monotonic()
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1,
                max_chain_rounds=0, discovery_max_probes=1))
        finally:
            for p in reversed(patches):
                p.stop()
        return analyze, result, started

    def test_configured_limit_truncates_the_run_and_marks_it_incomplete(self):
        analyze, result, _ = self._investigate(review_limit=1, review_seconds=0)
        self.assertEqual(analyze.await_count, 1)
        self.assertIn({"phase": "capture_review", "error":
                       "capture review limit reached: 2 captured exchange(s) not reviewed"},
                      result["errors"])
        self.assertTrue(result["degraded"])
        self.assertEqual(result["assessment"]["status"], "incomplete")

    def test_configured_time_budget_reaches_the_review_call(self):
        review = AsyncMock(return_value=0)
        _, _, started = self._investigate(review_limit=7, review_seconds=900, review=review)
        kwargs = review.await_args.kwargs
        self.assertEqual(kwargs["max_reviews"], 7)
        self.assertGreaterEqual(kwargs["deadline"], started + 900)
        self.assertLessEqual(kwargs["deadline"], time.monotonic() + 900)

    def test_default_configuration_keeps_the_former_unbounded_time(self):
        review = AsyncMock(return_value=0)
        self._investigate(review_limit=200, review_seconds=0, review=review)
        self.assertEqual(review.await_args.kwargs["max_reviews"], 200)
        self.assertIsNone(review.await_args.kwargs["deadline"])


if __name__ == "__main__":
    unittest.main()
