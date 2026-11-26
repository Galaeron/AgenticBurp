"""The capture review runs beside the request-bound phases (harness/review_overlap.py).

Caller level: a real Orchestrator.investigate_engagement against an owned loopback
app, with the real review_captured_exchanges and analyze pipeline and only the model
stubbed -- by a slow model that serves one call at a time, like one local llama.cpp
slot. Discovery hands back real responses from the app as the captures; the coverage
drive is a stand-in that sends real requests to the app for a fixed time, so it is
request-bound and makes no model call, as the real drive is.

r9: once the capture-review slice ran out, the model sat idle while the drive sent
its requests (hours 13-14: 24k and 30k requests, 0 model calls), with 279 of 484
captures unreviewed. With review_overlap the review goes on during the drive and
reviews more captures within the same investigation deadline; with it off (the
negative control) the idle gap comes back.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import yaml

from harness import cache
from harness import coverage_tracker
from harness import engagement_builder
from harness import evidence_ledger
from harness import global_throttle
from harness import orchestrator_review
from harness import role_crawl
from harness import store
from harness import worklist_investigator
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness import review_overlap
from harness.review_overlap import ReviewOverlap
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.run_journal import RunJournal
from harness.chain_stage_patch import chain_patch

_HARNESS = Path(__file__).resolve().parent

CAPTURES = 24
MODEL_SECONDS = 0.04      # one model call; calls are served one at a time
DRIVE_SECONDS = 2.5       # the stand-in drive sends requests for this long
DRIVE_PREFIX = "/drive/"
VALIDATE_PREFIX = "/validate/"   # a validator's request, sent after an analysis


# ---------------------------------------------------------------- the loopback app
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            self.server.received.append((time.monotonic(), self.command, self.path))
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/items/"):
            item = path.rsplit("/", 1)[-1]
            body = json.dumps({"id": item, "name": f"item {item}", "stock": len(item) * 7})
            status, ctype = 200, "application/json"
        elif path.startswith((DRIVE_PREFIX, VALIDATE_PREFIX)):
            body, status, ctype = "ok", 200, "text/plain"
        else:
            body, status, ctype = "not found", 404, "text/plain"
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _Server(ThreadingHTTPServer):
    request_queue_size = 128   # a loaded machine must not refuse the drive's connections
    daemon_threads = True


class _App:
    def __init__(self):
        self.httpd = _Server(("127.0.0.1", 0), _Handler)
        self.httpd.received, self.httpd.lock = [], threading.Lock()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def received(self, prefix: str = "") -> list:
        with self.httpd.lock:
            return [r for r in self.httpd.received if r[2].startswith(prefix)]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(5)


# ---------------------------------------------------------------- the slow model
class _SlowModel:
    """Returns nothing, slowly, one call at a time; records when each call ran."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.calls: list[tuple[float, float]] = []
        self.cancelled = 0
        self._lock: asyncio.Lock | None = None

    async def _serve(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            start = time.monotonic()
            try:
                await asyncio.sleep(self.seconds)
            except asyncio.CancelledError:
                self.cancelled += 1
                raise
            self.calls.append((start, time.monotonic()))

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        await self._serve()
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        await self._serve()
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=1, completion_tokens=1)


def _install(orch, model) -> None:
    orch.ollama = model
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = model


def _config(engagement: dict) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check",
              "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    eng = cfg.setdefault("engagement", {})
    eng.update(auto_escalate=False, feature_crawl=False, coverage_drive_legs=True,
               coverage_drive_cases=False, capture_review_limit=1000)
    eng.update(engagement)
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


class _Run:
    """One investigate_engagement over the app. Returns (result, facts)."""

    def __init__(self, engagement: dict, *, drive_seconds: float = DRIVE_SECONDS,
                 model_seconds: float = MODEL_SECONDS, cancel_mid_drive: bool = False,
                 journal: RunJournal | None = None, max_requests: int | None = None,
                 analysis_sends: bool = False, drive_until_denied: bool = False,
                 drive_requests: int | None = None):
        self.engagement = engagement
        self.drive_seconds = drive_seconds
        self.model = _SlowModel(model_seconds)
        self.cancel_mid_drive = cancel_mid_drive
        self.journal = journal
        self.max_requests = max_requests
        # Each finished analysis then sends one request through the run's transport,
        # as a validator confirming a review finding would.
        self.analysis_sends = analysis_sends
        # The drive stops at its first request the budget denies, or after
        # `drive_requests` sends (drive_seconds is then only a cap): what it sends
        # never depends on the machine's speed.
        self.drive_until_denied = drive_until_denied
        self.drive_requests = drive_requests

    def run(self, app: "_App | None" = None):
        """`app`: an app the caller owns (a resumed run must meet the same target)."""
        tmp = tempfile.mkdtemp(prefix="review_overlap_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(tmp, "cache.db"))
        tstats = global_throttle.throttle.stats()
        prev_rate = tstats["rate_per_second"] if tstats["enabled"] else 0.0
        prev_burst = tstats["burst"] if tstats["enabled"] else None
        global_throttle.configure(0)
        prev_failures = evidence_ledger._PERSISTENCE_FAILURES
        evidence_ledger._PERSISTENCE_FAILURES = 0
        own_app = app is None
        app = app or _App()
        try:
            return self._run(app)
        finally:
            if own_app:
                app.close()
            evidence_ledger._PERSISTENCE_FAILURES = (
                prev_failures + evidence_ledger._PERSISTENCE_FAILURES)
            global_throttle.configure(prev_rate, prev_burst)
            store._DB_PATH, cache._cache = orig_db, orig_cache
            shutil.rmtree(tmp, ignore_errors=True)

    def _run(self, app):
        cfg = _config(self.engagement)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install(orch, self.model)
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                               gate_config={"active_enabled": True},
                               max_requests=self.max_requests)
        if self.journal is not None:
            rc.run_journal = self.journal
        facts: dict = {"drive": None, "leftover_tasks": None, "analyzed": [],
                       "drive_denied": 0, "received_before": len(app.received())}
        real_analyze = orch.analyze

        async def analyze(ex, *args, **kwargs):
            started = time.monotonic()
            resp = await real_analyze(ex, *args, **kwargs)
            if self.analysis_sends:
                await rc.target_transport().send(
                    "GET", f"{app.base}{VALIDATE_PREFIX}{len(facts['analyzed'])}",
                    capability="engagement_execute")
            facts["analyzed"].append((ex.url, started, time.monotonic()))
            return resp

        orch.analyze = analyze

        async def build(base_url, roles, **kwargs):
            # Discovery's product: real responses from the app, one per item.
            state = EngagementState(host="127.0.0.1")
            crawl = role_crawl.RoleCrawlResult(base_url=base_url)
            async with httpx.AsyncClient() as client:
                for n in range(CAPTURES):
                    url = f"{app.base}/api/items/{n}"
                    resp = await client.get(url)
                    state._ep("GET", f"/api/items/{n}")
                    crawl.captured.append(HttpExchange(
                        method="GET", url=url, response_status=resp.status_code,
                        response_headers=dict(resp.headers), response_body=resp.text))
            return state, crawl

        async def drive(state, roles, run_leg, **kwargs):
            # Request-bound: real sends through the run's transport, no model call.
            transport = rc.target_transport()
            started, sent = time.monotonic(), 0
            while time.monotonic() - started < self.drive_seconds:
                outcome = await transport.send("GET", f"{app.base}{DRIVE_PREFIX}{sent}",
                                               capability="engagement_execute")
                denied = getattr(outcome, "outcome", "") == "budget_exhausted"
                facts["drive_denied"] += denied
                sent += 1
                if denied and self.drive_until_denied:
                    break
                if self.drive_requests is not None and sent >= self.drive_requests:
                    break
                # The run is stopped mid-drive once the review has finished two
                # analyses beside it (8 s is only a cap), however slow the machine.
                if self.cancel_mid_drive and (
                        sum(1 for start, _ in self.model.calls if start >= started) >= 2
                        or time.monotonic() - started > 8.0):
                    facts.setdefault("cancelled_at", time.monotonic())
                    facts["engagement"].cancel()   # the run is stopped mid-drive
                await asyncio.sleep(0.01)
            facts["drive"] = (started, time.monotonic(), sent)
            return {"legs_driven": sent}

        async def go():
            try:
                async with rc:
                    facts["engagement"] = asyncio.create_task(orch.investigate_engagement(
                        app.base, [RoleSession("anonymous", {})], max_nodes=1,
                        max_chain_rounds=0, discovery_max_probes=1, run_context=rc))
                    try:
                        return await facts["engagement"]
                    except asyncio.CancelledError:
                        if asyncio.current_task().cancelling():
                            raise
                        return None    # the engagement itself was cancelled
                    finally:
                        facts["engagement_ended_at"] = time.monotonic()
                        facts["leftover_tasks"] = [
                            t.get_name() for t in asyncio.all_tasks()
                            if t is not asyncio.current_task() and not t.done()
                            and t.get_name() == "capture-review-overlap"]
            finally:
                await rc.aclose()

        patches = [patch.object(engagement_builder, "build_engagement", new=build),
                   patch.object(worklist_investigator, "investigate_worklist",
                                new=AsyncMock(return_value=[])),
                   patch.object(coverage_tracker, "build_coverage_driven", new=drive),
                   chain_patch("universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.ffuf_runner.ffuf_available",
                         return_value=(False, "ffuf disabled for this test")),
                   patch("harness.browser_driver.default_driver", return_value=None)]
        for p in patches:
            p.start()
        try:
            facts["started"] = time.monotonic()
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        facts["model_calls"] = list(self.model.calls)
        facts["model_cancelled"] = self.model.cancelled
        # This run's requests only (a shared app also holds an earlier run's).
        facts["received"] = app.received()[facts["received_before"]:]
        facts["drive_requests"] = [r for r in facts["received"] if r[2].startswith(DRIVE_PREFIX)]
        facts["validate_requests"] = [r for r in facts["received"]
                                      if r[2].startswith(VALIDATE_PREFIX)]
        facts["budget_used"] = rc.budget.used
        return result, facts


def _calls_during(calls, window) -> int:
    lo, hi = window
    return sum(1 for start, end in calls if start < hi and end > lo)


# The slice gives the review 1/12 of the time left when it begins (about 1 s of 12);
# the rest is kept for the passes after it. The review's own deadline (12 s) lies
# well past the drive, even on a loaded machine, so the drain is what stops it.
SLICED = {"investigation_seconds": 12,
          "phase_slices": {"capture_review": 1, "final_passes": 11}}


class ReviewBesideTheDriveCallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.on, cls.on_facts = _Run(dict(SLICED)).run()
        cls.off, cls.off_facts = _Run(dict(SLICED, review_overlap=False)).run()

    def _window(self, facts):
        sends = [t for t, _, _ in facts["drive_requests"]]
        self.assertGreater(len(sends), 20, "the drive sent requests to the app")
        return min(sends), max(sends)

    def test_the_model_works_while_the_drive_sends_requests(self):
        window = self._window(self.on_facts)
        self.assertGreater(_calls_during(self.on_facts["model_calls"], window), 5)
        report = self.on["crawl_loop"]["review_overlap"]
        self.assertTrue(report["background"])
        self.assertEqual(report["stopped_by"], "end of the request-bound phases")

    def test_negative_control_the_sequential_order_leaves_the_model_idle(self):
        window = self._window(self.off_facts)
        self.assertEqual(_calls_during(self.off_facts["model_calls"], window), 0)
        self.assertIsNone(self.off["crawl_loop"]["review_overlap"])

    def test_more_captures_are_reviewed_within_the_same_deadline(self):
        on, off = self.on["review_stats"], self.off["review_stats"]
        self.assertGreater(off["unreviewed"], 0, "the slice cut the inline review short")
        self.assertGreater(on["reviewed"], off["reviewed"])
        # Every capture is counted once: reviewed, grouped under another, or left.
        for stats in (on, off):
            self.assertEqual(stats["reviewed"] + len(stats["grouped"]) + stats["unreviewed"],
                             CAPTURES)

    def test_what_the_review_leaves_is_reported_and_no_task_is_left_behind(self):
        self.assertEqual(self.on_facts["leftover_tasks"], [])
        errors = [e["error"] for e in self.on["errors"] if e.get("phase") == "capture_review"]
        left = self.on["review_stats"]["unreviewed"]
        if left:
            self.assertIn(f"end of the request-bound phases reached: {left} captured "
                          "exchange(s) not reviewed", errors)


class ReviewDeadlineCallerTest(unittest.TestCase):
    def test_the_review_is_cancelled_at_its_deadline_and_the_capture_in_flight_stays_unreviewed(self):
        # The drive outlasts the investigation deadline (3 s): the review is stopped
        # there, mid-analysis, while the engagement is still in the drive.
        result, facts = _Run({"investigation_seconds": 3,
                              "phase_slices": {"capture_review": 1, "final_passes": 5}},
                             drive_seconds=4.0, model_seconds=0.15).run()
        deadline = facts["started"] + 3
        # (ReviewOverlapUnitTests shows an analysis in flight at the deadline is cancelled.)
        drive_end = max(t for t, _, _ in facts["drive_requests"])
        self.assertGreater(drive_end, deadline + 0.5, "the drive went on past the deadline")
        # Past the deadline the model is idle while the drive goes on.
        self.assertEqual(_calls_during(facts["model_calls"], (deadline + 0.3, drive_end)), 0)
        report = result["crawl_loop"]["review_overlap"]
        self.assertEqual(report["stopped_by"], "capture review time budget")
        stats = result["review_stats"]
        self.assertEqual(stats["reviewed"] + len(stats["grouped"]) + stats["unreviewed"],
                         CAPTURES)
        self.assertIn(f"capture review time budget reached: {stats['unreviewed']} captured "
                      "exchange(s) not reviewed",
                      [e["error"] for e in result["errors"] if e.get("phase") == "capture_review"])
        self.assertEqual(facts["leftover_tasks"], [])

    def test_an_engagement_cancelled_mid_drive_leaves_no_review_running(self):
        # A long investigation deadline (the slice is still about 1 s): a loaded
        # machine never reaches the review's own deadline before the cancel.
        result, facts = _Run({"investigation_seconds": 20,
                              "phase_slices": {"capture_review": 1, "final_passes": 19}},
                             cancel_mid_drive=True, drive_seconds=10.0).run()
        self.assertIsNone(result)
        self.assertEqual(facts["leftover_tasks"], [])
        drive_start = min(t for t, _, _ in facts["drive_requests"])
        cancelled_at = facts["cancelled_at"]
        calls = facts["model_calls"]
        self.assertGreater(_calls_during(calls, (drive_start, cancelled_at)), 0,
                           "the review was running beside the drive")
        self.assertEqual([c for c in calls if c[1] > facts["engagement_ended_at"]], [],
                         "no analysis finishes once the cancelled engagement has ended")


class ReviewJournalCallerTest(unittest.TestCase):
    """E7 resume: a capture the background review finished is journaled as a
    `review:` unit, and a resumed run takes it from the journal instead of the model."""

    def test_background_reviews_are_journaled_and_skipped_on_resume(self):
        tmp = tempfile.mkdtemp(prefix="review_overlap_journal_")
        self.addCleanup(shutil.rmtree, tmp, True)
        app = _App()
        self.addCleanup(app.close)
        journal = RunJournal(Path(tmp) / "journal.db", "root-1", "same-source")

        first, facts = _Run(dict(SLICED), journal=journal).run(app)
        self.assertTrue(first["crawl_loop"]["review_overlap"]["background"])
        drive_start = min(t for t, _, _ in facts["drive_requests"])
        analyzed = facts["analyzed"]
        self.assertGreater(len([a for a in analyzed if a[2] > drive_start]), 0,
                           "the background review finished captures beside the drive")
        self.assertGreater(first["review_stats"]["unreviewed"], 0, "the first run left some")
        # One unit per finished analysis -- the ones finished in the background too.
        units = journal.units("review:")
        self.assertEqual(len(units), len(analyzed))

        second, facts2 = _Run(dict(SLICED), journal=journal).run(app)
        again = {url for url, _, _ in facts2["analyzed"]} & {url for url, _, _ in analyzed}
        self.assertEqual(again, set(), "a journaled review is not analyzed again")
        self.assertEqual(second["resume"]["resumed_units"]["review"], len(analyzed))
        self.assertGreater(len(facts2["analyzed"]), 0, "the resumed run reviews what was left")


class ReviewBudgetCallerTest(unittest.TestCase):
    """The background review's sends are the run's: every one is reserved from the
    one request budget (runs.max_requests), and its coverage reserve stays the drive's."""

    CEILING = 100
    # The drive sends a fixed count past the ceiling, stopping at the first request the
    # budget denies (60 s is only a cap): a loaded machine sends them more slowly,
    # never fewer.
    DRIVE = {"analysis_sends": True, "drive_until_denied": True,
             "drive_requests": CEILING + 30, "drive_seconds": 60.0}

    def test_the_review_and_the_drive_share_the_one_request_ceiling(self):
        result, facts = _Run(dict(SLICED), max_requests=self.CEILING, **self.DRIVE).run()
        self.assertTrue(result["crawl_loop"]["review_overlap"]["background"])
        window = (min(t for t, _, _ in facts["drive_requests"]),
                  max(t for t, _, _ in facts["drive_requests"]))
        beside = [t for t, _, _ in facts["validate_requests"] if window[0] < t < window[1]]
        self.assertGreater(len(beside), 0, "the review sent requests beside the drive")
        self.assertGreater(facts["drive_denied"], 0, "the ceiling was reached")
        # The app received nothing after discovery's own fetches that the run budget
        # did not reserve (a reserved send can still fail to connect), and the budget
        # stopped at its ceiling.
        self.assertLessEqual(len(facts["received"]) - CAPTURES, facts["budget_used"])
        self.assertEqual(facts["budget_used"], self.CEILING)

    def test_control_without_a_ceiling_the_same_run_sends_more(self):
        # Nothing denies this drive, so it sends its whole count, past the ceiling.
        _, facts = _Run(dict(SLICED), **self.DRIVE).run()
        self.assertEqual(facts["drive_denied"], 0)
        self.assertGreater(facts["budget_used"], self.CEILING)
        self.assertLessEqual(len(facts["received"]) - CAPTURES, facts["budget_used"])

    def test_a_coverage_reserve_stops_the_review_before_the_drive(self):
        reserve = 60
        result, facts = _Run(dict(SLICED, coverage_request_reserve=reserve),
                             max_requests=self.CEILING, **self.DRIVE).run()
        self.assertEqual(result["crawl_loop"]["review_overlap"]["stopped_by"],
                         "coverage request reserve")
        drive_start = min(t for t, _, _ in facts["drive_requests"])
        self.assertEqual([t for t, _, _ in facts["validate_requests"] if t > drive_start], [])
        self.assertGreaterEqual(len(facts["drive_requests"]), reserve,
                                "the drive got the requests held for it")
        self.assertLessEqual(facts["budget_used"], self.CEILING)


class ReviewOverlapDefaultTest(unittest.TestCase):
    """ON by default, yet inert without a capture_review slice: the review then runs
    inline, before the drive, exactly as before."""

    def test_without_a_capture_review_slice_the_review_runs_inline(self):
        result, facts = _Run({"investigation_seconds": 6}).run()
        self.assertIsNone(result["crawl_loop"]["review_overlap"])
        window = (min(t for t, _, _ in facts["drive_requests"]),
                  max(t for t, _, _ in facts["drive_requests"]))
        self.assertGreater(len(facts["model_calls"]), 0, "the review used the model")
        self.assertEqual(_calls_during(facts["model_calls"], window), 0)

    def test_without_a_model_the_review_runs_inline(self):
        with patch("harness.review_overlap.review_uses_model", return_value=False):
            result, _ = _Run(dict(SLICED)).run()
        self.assertIsNone(result["crawl_loop"]["review_overlap"])


# ---------------------------------------------------------------- the review loop
class _FakeReviewOrch:
    """analyze() is a slow model call; review_captured_exchanges is real."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.started: list[str] = []

    async def analyze(self, ex, **kwargs):
        self.started.append(ex.url)
        await asyncio.sleep(self.seconds)

        class _Resp:
            agent_reports, stage_outcomes = [], []
        return _Resp()


def _captures(n):
    return [HttpExchange(method="GET", url=f"http://127.0.0.1:1/api/items/{i}",
                         response_status=200, response_headers={"Content-Type": "application/json"},
                         response_body=json.dumps({"id": i}))
            for i in range(n)]


class ReviewLoopCancelTests(unittest.TestCase):
    def test_a_cancelled_review_puts_the_capture_in_flight_back(self):
        orch, state, seen, stats, errors = _FakeReviewOrch(10), EngagementState(host="h"), set(), {}, []
        caps = _captures(3)

        async def go():
            task = asyncio.create_task(orchestrator_review.review_captured_exchanges(
                orch, state, caps, seen=seen, stats=stats, errors=errors))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(go())
        self.assertEqual(len(orch.started), 1)
        self.assertEqual(seen, set())
        self.assertEqual(stats["reviewed"], 0)
        self.assertEqual(stats["unreviewed"], 3)
        self.assertEqual(sum(stats["by_tier"].values()), 0)
        self.assertEqual(errors[-1]["error"],
                         "cancellation reached: 3 captured exchange(s) not reviewed")

    def test_control_a_finished_review_counts_every_capture(self):
        orch, state, seen, stats = _FakeReviewOrch(0), EngagementState(host="h"), set(), {}
        asyncio.run(orchestrator_review.review_captured_exchanges(
            orch, state, _captures(3), seen=seen, stats=stats))
        self.assertEqual(len(seen), 3)
        self.assertEqual(stats["reviewed"], 3)
        self.assertEqual(stats["unreviewed"], 0)

    def test_should_stop_ends_the_review_before_the_next_capture(self):
        orch, state, stats, out = _FakeReviewOrch(0), EngagementState(host="h"), {}, {}
        asyncio.run(orchestrator_review.review_captured_exchanges(
            orch, state, _captures(4), stats=stats, outcome_out=out,
            should_stop=lambda: "stop requested" if len(orch.started) >= 2 else None))
        self.assertEqual(out, {"stopped_by": "stop requested", "reviewed": 2,
                               "produced": 0, "remaining": 2})


class ReviewOverlapUnitTests(unittest.TestCase):
    def test_the_switch_defaults_on_and_turns_off(self):
        self.assertTrue(review_overlap.enabled({}))
        self.assertTrue(review_overlap.enabled({"engagement": {}}))
        self.assertFalse(review_overlap.enabled({"engagement": {"review_overlap": False}}))

    def test_only_a_review_with_a_model_agent_is_model_bound(self):
        def orch(agents):
            return SimpleNamespace(agent_manager=SimpleNamespace(get_enabled_agents=lambda: agents))
        self.assertTrue(review_overlap.review_uses_model(orch(["sqli"])))
        self.assertFalse(review_overlap.review_uses_model(orch([])))
        self.assertFalse(review_overlap.review_uses_model(SimpleNamespace()))

    def _overlap(self, orch, seen, stats, deadline):
        async def review(captured, **bounds):
            return await orchestrator_review.review_captured_exchanges(
                orch, EngagementState(host="h"), captured, seen=seen, stats=stats, **bounds)
        return ReviewOverlap(review, deadline=deadline)

    def test_hold_returns_at_its_time_and_the_review_goes_on(self):
        orch, seen, stats = _FakeReviewOrch(0.05), set(), {}

        async def go():
            overlap = self._overlap(orch, seen, stats, None).start(_captures(10))
            done = await overlap.hold(time.monotonic() + 0.12)
            at_hold = len(orch.started)
            await asyncio.sleep(0.2)
            during = len(orch.started)
            await overlap.drain()
            return done, at_hold, during, overlap

        done, at_hold, during, overlap = asyncio.run(go())
        self.assertFalse(done)
        self.assertGreater(during, at_hold)
        self.assertEqual(overlap.stopped_by, "end of the request-bound phases")
        self.assertEqual(stats["reviewed"] + stats["unreviewed"], 10)

    def test_extended_captures_are_reviewed_after_the_first_batch(self):
        orch, seen, stats = _FakeReviewOrch(0), set(), {}
        more = [HttpExchange(method="GET", url="http://127.0.0.1:1/api/other/1",
                             response_status=200, response_body='{"other": 1}')]

        async def go():
            overlap = self._overlap(orch, seen, stats, None).start(_captures(2))
            self.assertTrue(await overlap.hold(None))   # nothing left: returns
            self.assertTrue(overlap.extend(more))
            await asyncio.sleep(0.05)
            await overlap.drain()
            self.assertFalse(overlap.extend(more))      # drained: no longer accepting
            return overlap

        overlap = asyncio.run(go())
        self.assertEqual(stats["reviewed"], 3)
        self.assertEqual(overlap.batches, 2)

    def test_a_review_that_raises_is_reported_not_lost(self):
        async def review(captured, **bounds):
            raise RuntimeError("review broke")

        async def go():
            overlap = ReviewOverlap(review, deadline=None).start(_captures(1))
            self.assertTrue(await overlap.hold(None))   # the task ended: nothing to wait for
            self.assertFalse(overlap.accepting)
            await overlap.drain()
            return overlap

        overlap = asyncio.run(go())
        self.assertEqual(overlap.error, "RuntimeError: review broke")
        self.assertEqual(overlap.report()["error"], "RuntimeError: review broke")

    def test_the_deadline_cancels_an_analysis_in_flight(self):
        orch, seen, stats = _FakeReviewOrch(10), set(), {}

        async def go():
            overlap = self._overlap(orch, seen, stats, time.monotonic() + 0.1).start(_captures(2))
            await overlap.hold(None)
            return overlap

        started = time.monotonic()
        overlap = asyncio.run(go())
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(overlap.stopped_by, "capture review time budget")
        self.assertEqual(seen, set())
        self.assertEqual(stats["unreviewed"], 2)


if __name__ == "__main__":
    unittest.main()
