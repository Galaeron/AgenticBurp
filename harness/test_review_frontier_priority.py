"""E1: capture review order, grouping of identical content, and hardening-agent reuse.

Measured motivation (job 383f0ebff8e8): 225 captures, 70 reviewed in 3,607 s,
alphabetical by path, so the authenticated API captures were never reached; 41 of
69 analyses had a response byte-identical to an earlier one (32 of them the same
SPA shell on different HTML routes); the csp/cors/misconfig/web_cache_poisoning
agents took 47% of the review model-seconds reporting host-wide header facts.

Everything goes through the real callers: `review_captured_exchanges` (with a fake
orchestrator whose `analyze` records its calls) for order and grouping, and the real
`Orchestrator.analyze` (agent pipeline stubbed to record the dispatch) for the
hardening-agent reuse. No network, no model.

Negative controls follow test_model_retry's pattern: the check is written once as a
helper, the real test runs it, and the ``test_control_*`` twin patches the new logic
out IN-PROCESS and asserts the same check now FAILS.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import assessment_health, cache, store
from harness.models import AgentReport, HttpExchange, StageOutcome
from harness.orchestrator import Orchestrator
from harness.orchestrator_helpers import review_captured_exchanges
from harness.run_context import RunContext
from harness.test_smoke_phase0_capture_review import _test_config

_SHELL = "<html><body><app-root></app-root><script src='main.js'></script></body></html>"


def cap(path, *, method="GET", body=None, status=200, ctype="text/html", auth=None, query="",
        headers=None, request_body="", host="localhost") -> HttpExchange:
    url = f"http://{host}{path}" + (f"?{query}" if query else "")
    return HttpExchange(
        url=url, method=method, request_headers={"Authorization": f"Bearer {auth}"} if auth else {},
        request_body=request_body, response_status=status,
        response_headers={"Content-Type": ctype, **(headers or {})},
        response_body=body if body is not None else f"<html>{path}</html>")


def json_cap(path, **kw) -> HttpExchange:
    kw.setdefault("ctype", "application/json")
    kw.setdefault("body", '{"path": "%s"}' % path)
    return cap(path, **kw)


def fake_orch():
    return (SimpleNamespace(analyze=AsyncMock(return_value=SimpleNamespace(agent_reports=[]))),
            SimpleNamespace(record_template=lambda *args: None))


def reviewed_urls(orch) -> list[str]:
    return [call.args[0].url for call in orch.analyze.await_args_list]


async def review(captured, **kwargs):
    orch, state = fake_orch()
    stats: dict = {}
    seen: set = set()
    kwargs.setdefault("stats", stats)
    kwargs.setdefault("seen", seen)
    await review_captured_exchanges(orch, state, captured, **kwargs)
    return orch, kwargs["stats"], kwargs["seen"]


# --------------------------------------------------------------------------
# 1. Priority order
# --------------------------------------------------------------------------
class PriorityOrderTests(unittest.IsolatedAsyncioTestCase):
    async def _check_authenticated_json_goes_first(self):
        shells = [cap(f"/route{i}", body=f"<html>shell {i}</html>") for i in range(6)]
        api = [json_cap("/rest/user/whoami", auth="tok"), json_cap("/rest/order-history", auth="tok"),
               json_cap("/rest/wallet/balance", auth="tok")]
        orch, _, _ = await review([*shells, *api], max_reviews=3)
        self.assertEqual(reviewed_urls(orch), [c.url for c in api])

    async def test_three_authenticated_json_captures_beat_six_html_shells(self):
        await self._check_authenticated_json_goes_first()

    async def test_control_without_the_tiers_the_html_shells_come_first(self):
        with patch.object(assessment_health, "capture_tier", lambda ex: 0):
            with self.assertRaises(AssertionError):
                await self._check_authenticated_json_goes_first()

    async def test_tiers_run_authenticated_anonymous_other_then_html(self):
        html = cap("/page", body="<html>page</html>")
        text = cap("/robots.txt", ctype="text/plain", body="User-agent: *")
        anon_json = json_cap("/api/Products")
        auth_json = json_cap("/rest/basket", auth="tok")
        anon_write = cap("/submit", method="POST", body="<html>done</html>", request_body="a=1")
        auth_write = cap("/profile", method="PUT", auth="tok", body="<html>saved</html>", request_body="a=1")
        orch, stats, _ = await review([html, text, anon_json, anon_write, auth_json, auth_write])
        urls = reviewed_urls(orch)
        self.assertEqual(urls[:2], [auth_json.url, auth_write.url])         # (a) authenticated API / write
        self.assertEqual(urls[2:4], [anon_json.url, anon_write.url])        # (b) anonymous API / write
        self.assertEqual(urls[4:], [text.url, html.url])                    # (c) other non-HTML, (d) HTML
        self.assertEqual(stats["by_tier"], {"authenticated_api": 2, "anonymous_api": 2,
                                            "other_non_html": 1, "html": 1})

    async def test_prioritisation_drops_nothing_and_is_deterministic(self):
        captured = [cap(f"/p{i}", body=f"<html>{i}</html>") for i in range(4)] + [
            json_cap(f"/api/Items{i}", auth="tok") for i in range(4)] + [
            cap("/logo.png", ctype="image/png", body="PNG")]
        first, stats, _ = await review(captured)
        second, _, _ = await review(captured)
        self.assertEqual(sorted(reviewed_urls(first)), sorted(c.url for c in captured))
        self.assertEqual(reviewed_urls(first), reviewed_urls(second))
        self.assertEqual(stats["reviewed"], len(captured))
        self.assertEqual(stats["unreviewed"], 0)

    async def _check_route_families_take_turns(self):
        rest = [json_cap(f"/rest/thing{i}") for i in range(4)]
        api = [json_cap(f"/api/Thing{i}") for i in range(2)]
        orch, _, _ = await review([*rest, *api], max_reviews=2)
        self.assertEqual({url.split("/")[3] for url in reviewed_urls(orch)}, {"rest", "api"})

    async def test_one_route_family_cannot_starve_another_inside_a_tier(self):
        await self._check_route_families_take_turns()

    async def test_control_without_the_family_key_one_family_takes_both_turns(self):
        with patch.object(assessment_health, "_route_family", lambda ex: ("same",)):
            with self.assertRaises(AssertionError):
                await self._check_route_families_take_turns()

    async def test_two_identities_on_one_family_take_turns(self):
        first = [json_cap(f"/rest/a{i}", auth="alice") for i in range(3)]
        second = [json_cap("/rest/b0", auth="bob")]
        orch, _, _ = await review([*first, *second], max_reviews=2)
        self.assertIn(second[0].url, reviewed_urls(orch))

    async def test_an_exact_duplicate_is_still_reviewed_once(self):
        shell = cap("/dup", body="<html>dup</html>")
        orch, stats, _ = await review([shell, shell, shell])
        self.assertEqual(orch.analyze.await_count, 1)
        self.assertEqual(stats["grouped"], [])      # exact observations are dedup, not grouping


# --------------------------------------------------------------------------
# 2. Grouping of identical content
# --------------------------------------------------------------------------
class GroupingTests(unittest.IsolatedAsyncioTestCase):
    async def _check_five_shells_group_to_one(self):
        shells = [cap(f"/{name}", body=_SHELL) for name in ("login", "about", "contact", "search", "help")]
        orch, stats, seen = await review(shells)
        self.assertEqual(orch.analyze.await_count, 1)
        self.assertEqual(reviewed_urls(orch), [shells[0].url])
        self.assertEqual(len(stats["grouped"]), 4)
        for entry, covered in zip(stats["grouped"], shells[1:]):
            self.assertEqual(entry, {"capture": covered.url, "method": "GET", "identity": "anon",
                                     "covered_by": shells[0].url,
                                     "reason": "identical response content, no input"})
        return shells, stats, seen

    async def test_five_html_routes_with_one_body_make_one_analysis_and_four_grouped_entries(self):
        await self._check_five_shells_group_to_one()

    async def test_control_with_grouping_off_all_five_are_analysed(self):
        with self.assertRaises(AssertionError):
            shells = [cap(f"/{name}", body=_SHELL) for name in ("a", "b", "c", "d", "e")]
            orch, stats, _ = await review(shells, group_identical=False)
            self.assertEqual(orch.analyze.await_count, 1)

    async def test_grouped_captures_are_marked_seen_and_not_reviewed_again(self):
        shells, stats, seen = await self._check_five_shells_group_to_one()
        orch, state = fake_orch()
        again = {}
        await review_captured_exchanges(orch, state, shells, seen=seen, stats=again)
        orch.analyze.assert_not_awaited()
        self.assertEqual(again.get("grouped", []), [])

    async def test_a_failed_representative_review_is_flagged_on_its_grouped_entries(self):
        shells = [cap(f"/{name}", body=_SHELL) for name in ("a", "b", "c")]
        orch, state = fake_orch()
        orch.analyze.side_effect = RuntimeError("model down")
        stats, errors = {}, []
        await review_captured_exchanges(orch, state, shells, stats=stats, errors=errors)
        self.assertEqual([e.get("representative_review") for e in stats["grouped"]], ["failed", "failed"])
        self.assertEqual(errors, [{"phase": "capture_review", "error": "RuntimeError"}])

    async def test_grouped_entries_are_not_findings_and_are_not_analysed(self):
        shells = [cap(f"/{name}", body=_SHELL) for name in ("a", "b", "c")]
        orch, state = fake_orch()
        ingest = []
        state.ingest_findings = lambda *args: ingest.append(args)
        await review_captured_exchanges(orch, state, shells, stats={})
        self.assertEqual(ingest, [])

    # -- inputs that must NEVER be grouped ---------------------------------
    async def _check_never_grouped(self, captures):
        orch, stats, _ = await review(captures)
        self.assertEqual(orch.analyze.await_count, len(captures),
                         "a capture with its own identity/input/object id was grouped away")
        self.assertEqual(stats["grouped"], [])

    def _different_identity(self):
        return [cap("/same-a", body=_SHELL), cap("/same-b", body=_SHELL, auth="alice"),
                cap("/same-c", body=_SHELL, auth="bob")]

    def _with_query(self):
        return [cap("/q1", body=_SHELL, query="q=one"), cap("/q2", body=_SHELL, query="q=two"),
                cap("/q3", body=_SHELL, query="q=three")]

    def _with_object_id(self):
        return [json_cap("/api/Items/1", body='{"name": "same"}'),
                json_cap("/api/Items/2", body='{"name": "same"}')]

    def _different_csp(self):
        return [cap("/csp-a", body=_SHELL, headers={"Content-Security-Policy": "default-src 'self'"}),
                cap("/csp-b", body=_SHELL, headers={"Content-Security-Policy": "default-src *"})]

    def _with_request_body(self):
        return [cap("/post-a", method="POST", body=_SHELL, request_body="x=1"),
                cap("/post-b", method="POST", body=_SHELL, request_body="x=2")]

    def _different_method(self):
        return [cap("/m", body=_SHELL), cap("/n", method="POST", body=_SHELL)]

    async def test_the_same_body_under_a_different_identity_is_not_grouped(self):
        await self._check_never_grouped(self._different_identity())

    async def test_the_same_body_with_a_query_parameter_is_not_grouped(self):
        await self._check_never_grouped(self._with_query())

    async def test_items_1_and_items_2_with_one_body_are_not_grouped(self):
        await self._check_never_grouped(self._with_object_id())

    async def test_a_different_csp_header_value_is_not_grouped(self):
        await self._check_never_grouped(self._different_csp())

    async def test_requests_with_a_body_are_not_grouped(self):
        await self._check_never_grouped(self._with_request_body())

    async def test_a_different_method_is_not_grouped(self):
        await self._check_never_grouped(self._different_method())

    async def test_control_a_key_that_ignores_identity_input_ids_and_headers_over_groups(self):
        # Patch the new key out for a constant: every "must not group" case above
        # now collapses, so each of the same checks FAILS.
        with patch.object(assessment_health, "_group_key", lambda ex: ("same",)):
            for make in (self._different_identity, self._with_query, self._with_object_id,
                         self._different_csp, self._with_request_body):
                with self.subTest(make.__name__):
                    with self.assertRaises(AssertionError):
                        await self._check_never_grouped(make())

    async def test_a_set_cookie_value_does_not_split_a_group_but_its_name_does(self):
        same_names = [cap("/c1", body=_SHELL, headers={"Set-Cookie": "sid=111; Path=/"}),
                      cap("/c2", body=_SHELL, headers={"Set-Cookie": "sid=222; Path=/"})]
        orch, stats, _ = await review(same_names)
        self.assertEqual((orch.analyze.await_count, len(stats["grouped"])), (1, 1))
        other_names = [cap("/d1", body=_SHELL, headers={"Set-Cookie": "sid=111"}),
                       cap("/d2", body=_SHELL, headers={"Set-Cookie": "token=111"})]
        await self._check_never_grouped(other_names)

    async def test_identical_authenticated_json_without_input_groups_per_identity(self):
        shared = '{"status": "ok"}'
        alice = [json_cap(f"/rest/ping{i}", body=shared, auth="alice") for i in range(3)]
        bob = [json_cap("/rest/ping9", body=shared, auth="bob")]
        orch, stats, _ = await review([*alice, *bob])
        self.assertEqual(sorted(reviewed_urls(orch)), sorted([alice[0].url, bob[0].url]))
        self.assertEqual({e["identity"] for e in stats["grouped"]}, {"authenticated"})
        self.assertEqual({e["covered_by"] for e in stats["grouped"]}, {alice[0].url})

    async def test_followers_of_an_unreached_representative_stay_unseen_and_unreported(self):
        shells = [cap(f"/s{i}", body=_SHELL) for i in range(3)]
        urgent = json_cap("/rest/whoami", auth="tok")
        orch, state = fake_orch()
        seen, stats, errors = set(), {}, []
        await review_captured_exchanges(orch, state, [*shells, urgent], max_reviews=1,
                                        seen=seen, stats=stats, errors=errors)
        self.assertEqual(reviewed_urls(orch), [urgent.url])
        self.assertEqual(stats["grouped"], [])
        self.assertEqual(stats["unreviewed"], 3)
        self.assertEqual(errors[0]["error"], "capture review limit reached: 3 captured exchange(s) not reviewed")
        # A later pass with room reviews the representative and groups the rest.
        await review_captured_exchanges(orch, state, [*shells, urgent], seen=seen, stats=stats)
        self.assertEqual(reviewed_urls(orch), [urgent.url, shells[0].url])
        self.assertEqual(len(stats["grouped"]), 2)
        self.assertEqual(stats["reviewed"], 2)


# --------------------------------------------------------------------------
# 3. Hardening-agent reuse in the real Orchestrator.analyze dispatch
# --------------------------------------------------------------------------
_ROUTED = ["cors", "csp", "misconfig", "web_cache_poisoning", "xss"]
_CORS_OPEN = {"Access-Control-Allow-Origin": "*"}


class GroupingHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_an_extra_response_header_keeps_a_capture_out_of_the_group(self):
        about = cap("/about", body=_SHELL)
        internal = cap("/internal", body=_SHELL, headers={"X-Debug-Backend": "node-3"})
        orch, stats, _ = await review([about, internal])
        self.assertEqual(reviewed_urls(orch), [about.url, internal.url])
        self.assertEqual(stats["grouped"], [])

    async def test_control_without_the_extra_header_the_two_are_grouped(self):
        about, other = cap("/about", body=_SHELL), cap("/internal", body=_SHELL)
        orch, stats, _ = await review([about, other])
        self.assertEqual(reviewed_urls(orch), [about.url])
        self.assertEqual(len(stats["grouped"]), 1)

    async def test_a_failed_representative_leaves_its_group_for_a_later_round(self):
        shells = [cap(f"/{name}", body=_SHELL) for name in ("a", "b", "c")]
        orch, state = fake_orch()
        orch.analyze.side_effect = RuntimeError("model down")
        seen: set = set()
        await review_captured_exchanges(orch, state, shells, seen=seen, stats={})
        later, _, _ = await review(shells, seen=seen)
        self.assertEqual(reviewed_urls(later), [shells[1].url])

    async def test_control_a_reviewed_representative_leaves_nothing(self):
        shells = [cap(f"/{name}", body=_SHELL) for name in ("a", "b", "c")]
        _, _, seen = await review(shells)
        later, _, _ = await review(shells, seen=seen)
        self.assertEqual(reviewed_urls(later), [])


class HardeningReuseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="e1_reuse_")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        for patcher in (patch.object(store, "_DB_PATH", Path(self._tmp) / "state.db"),
                        patch.object(cache, "_cache", cache._cache)):
            patcher.start()
            self.addCleanup(patcher.stop)
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        self.cfg = _test_config()
        self.orch = Orchestrator(self.cfg)
        self.dispatches: list[tuple[str, list[str]]] = []
        self.fail_agents: set[str] = set()
        self.responses: list = []

        async def pipeline(exchange, dispatch, prior_context, max_body_chars, **kwargs):
            self.dispatches.append((exchange.url, list(dispatch)))
            reports = [AgentReport(agent=name, model="m", findings=[],
                                   raw_error="boom" if name in self.fail_agents else None)
                       for name in dispatch]
            return reports, 0, 0, StageOutcome(name="critique", status="disabled")

        for patcher in (patch.object(self.orch, "_choose_agents", AsyncMock(return_value=(list(_ROUTED), "test"))),
                        patch.object(self.orch.analysis_pipeline, "run_full_analysis", pipeline)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ctx = RunContext.create(run_id="e1-reuse", config=self.cfg,
                                     allowed_hosts=["localhost", "127.0.0.1"])

    async def asyncTearDown(self):
        await self.ctx.aclose()

    async def analyse(self, *exchanges, ctx=None, **kwargs):
        out = []
        for ex in exchanges:
            out.append(await self.orch.analyze(ex, _from_discovery=True,
                                               run_context=ctx or self.ctx, **kwargs))
        self.responses = out
        return out

    def ran(self, agent) -> int:
        return sum(agent in dispatch for _, dispatch in self.dispatches)

    @staticmethod
    def skips(response) -> dict[str, str]:
        return {o.name.removeprefix("agent:"): o.reason for o in response.stage_outcomes
                if o.status == "skipped" and o.name.startswith("agent:")}

    async def _check_cors_runs_once(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), json_cap("/api/b", headers=_CORS_OPEN))
        self.assertEqual(self.ran("cors"), 1, self.dispatches)
        second = self.skips(self.responses[1])
        self.assertIn("cors", second)
        self.assertIn("already analysed", second["cors"])
        # misconfig and web_cache_poisoning read the path and body, which differ here.
        self.assertEqual(self.responses[1].dispatched_agents,
                         ["misconfig", "web_cache_poisoning", "xss"])

    async def test_two_json_captures_with_identical_security_headers_run_cors_once(self):
        await self._check_cors_runs_once()

    async def test_control_without_the_reuse_check_cors_runs_twice(self):
        from harness.orchestrator_detect import DetectMixin
        with patch.object(DetectMixin, "_apply_hardening_reuse",
                          lambda self, exchange, dispatch, run_context, engagement="": (list(dispatch), [], {})):
            with self.assertRaises(AssertionError):
                await self._check_cors_runs_once()

    async def test_different_cors_headers_run_cors_twice(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN),
                           json_cap("/api/b", headers={"Access-Control-Allow-Origin": "https://evil.test",
                                                       "Access-Control-Allow-Credentials": "true"}))
        self.assertEqual(self.ran("cors"), 2)
        self.assertNotIn("cors", self.skips(self.responses[1]))

    async def test_csp_on_json_is_skipped_as_not_applicable(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN))
        self.assertEqual(self.ran("csp"), 0)
        self.assertEqual(self.skips(self.responses[0])["csp"], "not applicable: non-HTML")

    async def test_csp_runs_on_html_then_is_reused_for_the_same_html_headers(self):
        csp = {"Content-Security-Policy": "default-src 'self'"}
        await self.analyse(cap("/one", body="<html>one</html>", headers=csp),
                           cap("/two", body="<html>two</html>", headers=csp))
        self.assertEqual(self.ran("csp"), 1)
        self.assertIn("already analysed", self.skips(self.responses[1])["csp"])

    async def test_a_different_identity_kind_content_family_or_host_runs_the_agents_again(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN),
                           json_cap("/api/b", headers=_CORS_OPEN, auth="tok"),            # identity kind
                           cap("/c", body="<html>c</html>", headers=_CORS_OPEN),          # content family
                           json_cap("/api/d", headers=_CORS_OPEN, host="127.0.0.1"))      # host
        self.assertEqual(self.ran("cors"), 4)

    async def test_another_engagement_partition_in_the_same_run_runs_the_agents_again(self):
        # Findings are stored per engagement partition: a partition that never got
        # the agent's findings must not be served by another partition's run.
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), engagement_id="eng-A")
        await self.analyse(json_cap("/api/b", headers=_CORS_OPEN), engagement_id="eng-B")
        self.assertEqual(self.ran("cors"), 2)

    async def test_content_agents_rerun_on_another_path_and_body_with_the_same_headers(self):
        await self.analyse(json_cap("/rest/products", headers=_CORS_OPEN),
                           json_cap("/rest/admin/application-configuration",
                                    body='{"config": {"server": {"port": 3000}}}', headers=_CORS_OPEN))
        self.assertEqual((self.ran("misconfig"), self.ran("web_cache_poisoning"), self.ran("cors")),
                         (2, 2, 1), self.dispatches)

    async def test_control_same_path_and_body_runs_the_content_agents_once(self):
        await self.analyse(json_cap("/rest/products", query="q=1", body="{}", headers=_CORS_OPEN),
                           json_cap("/rest/products", query="q=2", body="{}", headers=_CORS_OPEN))
        self.assertEqual((self.ran("misconfig"), self.ran("web_cache_poisoning")), (1, 1),
                         self.dispatches)

    async def test_control_header_only_key_skips_misconfig_on_another_path(self):
        from harness import orchestrator_detect
        with patch.object(orchestrator_detect, "_CONTENT_HARDENING_AGENTS", frozenset()):
            await self.analyse(json_cap("/rest/products", headers=_CORS_OPEN),
                               json_cap("/rest/admin/application-configuration",
                                        body='{"config": 1}', headers=_CORS_OPEN))
        self.assertEqual(self.ran("misconfig"), 1, self.dispatches)

    async def test_non_hardening_agents_are_never_skipped(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), json_cap("/api/b", headers=_CORS_OPEN))
        self.assertEqual(self.ran("xss"), 2)

    async def test_a_failed_first_run_does_not_suppress_the_next(self):
        self.fail_agents = {"cors"}
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN))
        self.fail_agents = set()
        await self.analyse(json_cap("/api/b", headers=_CORS_OPEN))
        self.assertEqual(self.ran("cors"), 2)

    async def test_forced_agents_bypass_the_reuse(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), json_cap("/api/b", headers=_CORS_OPEN),
                           force_agents=["cors"])
        self.assertEqual(self.ran("cors"), 2)

    async def test_reuse_is_scoped_to_the_run(self):
        other = RunContext.create(run_id="e1-reuse-2", config=self.cfg, allowed_hosts=["localhost"])
        try:
            await self.analyse(json_cap("/api/a", headers=_CORS_OPEN))
            await self.analyse(json_cap("/api/b", headers=_CORS_OPEN), ctx=other)
        finally:
            await other.aclose()
        self.assertEqual(self.ran("cors"), 2)

    async def test_a_dispatch_emptied_by_the_reuse_still_completes(self):
        self.orch._choose_agents.return_value = (["cors"], "test")
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), json_cap("/api/b", headers=_CORS_OPEN))
        self.assertEqual([dispatch for _, dispatch in self.dispatches], [["cors"], []])
        self.assertEqual(self.responses[1].dispatched_agents, [])
        self.assertIn("cors", self.skips(self.responses[1]))

    async def test_a_skip_is_never_a_failure_or_a_degraded_response(self):
        await self.analyse(json_cap("/api/a", headers=_CORS_OPEN), json_cap("/api/b", headers=_CORS_OPEN))
        self.assertFalse(self.responses[1].degraded)
        self.assertEqual(self.responses[1].stage_outcomes[0].name, "critique")


# --------------------------------------------------------------------------
# 4. The investigate result carries review_stats from both review call sites
# --------------------------------------------------------------------------
class ReviewStatsInResultTests(unittest.TestCase):
    def test_review_stats_aggregate_both_review_calls_in_the_job_result(self):
        from harness import chain_linker, engagement_builder, role_crawl, worklist_investigator
        from harness.engagement import EngagementState
        from harness.role_crawl import RoleSession
        from harness.test_deterministic_first import BASE, _config

        first = [cap("/p1", body="<html>1</html>"), cap("/p2", body="<html>2</html>"),
                 json_cap("/rest/me", auth="tok", host="shop.test")]
        second = [json_cap("/rest/other", auth="derived", host="shop.test")]

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="shop.test")
            state._ep("GET", "/filter")
            rc = role_crawl.RoleCrawlResult(base_url=base_url)
            rc.captured.extend(second if len(roles) > 1 else first)
            return state, rc

        async def no_outcomes(*args, **kwargs):
            return []

        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        orch.analyze = AsyncMock(return_value=SimpleNamespace(agent_reports=[]))
        link = {"chain_findings": [], "credential_caps": [
            {"kind": "bearer", "source_url": BASE, "headers": {"Authorization": "Bearer derived"}}]}
        with patch.object(engagement_builder, "build_engagement", new=build), \
             patch.object(worklist_investigator, "investigate_worklist", new=no_outcomes), \
             patch.object(chain_linker, "link_findings", return_value=link), \
             patch.object(orch, "_credential_grants_access", new=AsyncMock(return_value=True)), \
             patch("harness.orchestrator_chain.universal_header_audit", new=AsyncMock(return_value=0)):
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=1,
                discovery_max_probes=1))
        stats = result["review_stats"]
        self.assertEqual(result["chain_rounds"], 1)
        self.assertEqual(stats["reviewed"], 4)         # three from the first call, one from the chain round
        self.assertEqual(stats["unreviewed"], 0)
        self.assertEqual(stats["grouped"], [])
        self.assertEqual(stats["by_tier"], {"authenticated_api": 2, "anonymous_api": 0,
                                            "other_non_html": 0, "html": 2})
        # The first-call captures were reviewed authenticated-API first.
        self.assertEqual([c.args[0].url for c in orch.analyze.await_args_list][0], first[2].url)


if __name__ == "__main__":
    unittest.main()
