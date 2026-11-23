"""The capture review takes up an idle model before capture_review (IdleReview).

r9 and r10, one local llama.cpp slot: the worklist's model-driven probes were done by
about hour 3.7 of its 7.8 h slice, and the rest of the slice was validator legs that
send requests and make no model call -- model calls stayed at 695 from hour 3.74
while target requests grew by about 24k an hour. engagement.review_on_idle_seconds
starts the capture review beside such a phase once the model has sat idle that long.

Caller level: a real Orchestrator.investigate_engagement against an owned loopback
app, with the real review_captured_exchanges and analyze pipeline and only the model
stubbed by a slow one-slot model that reports its calls to model_activity, as
OllamaClient._chat does. The worklist sweep is a stand-in that makes a few model
calls of its own and then sends real requests through the run's transport for a fixed
time (request-bound, no model call), as the validator legs do.

Negative controls: with the toggle off the review waits for capture_review (the old
sequential order); a model kept busy by the sweep gets no review beside it; and a
capture the idle review finished is not reviewed again by capture_review.
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
from urllib.parse import urlsplit

import httpx

from harness import cache
from harness import coverage_tracker
from harness import engagement_builder
from harness import evidence_ledger
from harness import global_throttle
from harness import model_activity
from harness import orchestrator_review
from harness import review_overlap
from harness import role_crawl
from harness import store
from harness import worklist_investigator
from harness.engagement import EngagementState
from harness.model_activity import ModelActivity
from harness.models import HttpExchange
from harness.ollama_client import OllamaClient
from harness.orchestrator import Orchestrator
from harness.review_overlap import IdleReview
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.test_review_overlap import _SlowModel, _config, _install
from harness.chain_stage_patch import chain_patch

ITEMS = 24                # distinct JSON objects: each is its own review
PAGES = 6                 # one identical page under six paths: one review, five grouped
CAPTURES = ITEMS + PAGES
MODEL_SECONDS = 0.01
IDLE_SECONDS = 0.3
WINDOW = 2.5              # the stand-in sweep sends requests for this long
LONG_WINDOW = 15.0        # ... or, with `until_reviewed`, until the review is done
REVIEWS = ITEMS + 1       # what the whole review analyzes: every item and one page
WORK_PREFIX = "/work/"


# ---------------------------------------------------------------- the loopback app
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            self.server.received.append((time.monotonic(), self.path))
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/items/"):
            item = path.rsplit("/", 1)[-1]
            body = json.dumps({"id": item, "name": f"item {item}", "stock": len(item) * 7})
            status, ctype = 200, "application/json"
        elif path.startswith("/pages/"):
            body, status, ctype = "<html><body>the same page</body></html>", 200, "text/html"
        elif path.startswith(WORK_PREFIX):
            body, status, ctype = "ok", 200, "text/plain"
        else:
            body, status, ctype = "not found", 404, "text/plain"
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _App:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received, self.httpd.lock = [], threading.Lock()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def received(self, prefix: str = "") -> list:
        with self.httpd.lock:
            return [r for r in self.httpd.received if r[1].startswith(prefix)]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(5)


# ---------------------------------------------------------------- the model
class _Model(_SlowModel):
    """The one-slot model, reporting each call to model_activity as OllamaClient._chat
    does (a call waiting for the slot counts as in flight), and recording whose it was."""

    def __init__(self, seconds: float):
        super().__init__(seconds)
        self.owned: list[tuple[float, float, bool]] = []   # (start, end, background)

    async def _serve(self):
        background = model_activity.current_owner() is not None
        with model_activity.ACTIVITY.call():
            start = time.monotonic()
            await super()._serve()
            self.owned.append((start, time.monotonic(), background))


# ---------------------------------------------------------------- one engagement
class _Run:
    """One investigate_engagement over the app, its worklist sweep a stand-in that
    runs `steps`: ("model", n) makes n model calls of its own; ("send", seconds) sends
    requests for that long; ("send", seconds, every) also makes a model call every
    `every` seconds (a model kept busy). With `until_reviewed`, a send step ends a
    second after that many captures were analyzed (the sweep outlasts the review on
    any machine). Returns (result, facts)."""

    def __init__(self, engagement: dict, steps, *, cancel_after: float | None = None,
                 until_reviewed: int | None = None):
        self.engagement = engagement
        self.steps = steps
        self.model = _Model(MODEL_SECONDS)
        self.cancel_after = cancel_after
        self.until_reviewed = until_reviewed

    def run(self):
        tmp = tempfile.mkdtemp(prefix="idle_review_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(tmp, "cache.db"))
        tstats = global_throttle.throttle.stats()
        prev_rate = tstats["rate_per_second"] if tstats["enabled"] else 0.0
        prev_burst = tstats["burst"] if tstats["enabled"] else None
        global_throttle.configure(0)
        prev_failures = evidence_ledger._PERSISTENCE_FAILURES
        evidence_ledger._PERSISTENCE_FAILURES = 0
        app = _App()
        try:
            with patch.object(model_activity, "ACTIVITY", ModelActivity()):
                return self._run(app)
        finally:
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
                               gate_config={"active_enabled": True})
        facts: dict = {"sweep": None, "analyzed": [], "leftover_tasks": None, "sweeps": 0}
        real_analyze = orch.analyze

        async def analyze(ex, *args, **kwargs):
            background = model_activity.current_owner() is not None
            started = time.monotonic()
            resp = await real_analyze(ex, *args, **kwargs)
            facts["analyzed"].append((ex.url, started, time.monotonic(), background))
            return resp

        orch.analyze = analyze

        async def build(base_url, roles, **kwargs):
            # Discovery's product: real responses from the app.
            state = EngagementState(host="127.0.0.1")
            crawl = role_crawl.RoleCrawlResult(base_url=base_url)
            paths = ([f"/api/items/{n}" for n in range(ITEMS)]
                     + [f"/pages/{name}" for name in "abcdef"[:PAGES]])
            async with httpx.AsyncClient() as client:
                for path in paths:
                    resp = await client.get(f"{app.base}{path}")
                    state._ep("GET", path)
                    crawl.captured.append(HttpExchange(
                        method="GET", url=f"{app.base}{path}", response_status=resp.status_code,
                        response_headers=dict(resp.headers), response_body=resp.text))
            return state, crawl

        async def sweep(probe, st, base, roles, **kwargs):
            facts["sweeps"] += 1
            if facts["sweeps"] > 1:
                return []
            started, sent = time.monotonic(), 0
            transport = rc.target_transport()
            for step in self.steps:
                if step[0] == "model":
                    for _ in range(step[1]):
                        await self.model.chat_json("m", "sys", "the sweep's own call")
                    continue
                seconds, every = step[1], (step[2] if len(step) > 2 else None)
                begun = last_call = time.monotonic()
                done_at = None
                while time.monotonic() - begun < seconds:
                    if (self.until_reviewed is not None and done_at is None
                            and len(facts["analyzed"]) >= self.until_reviewed):
                        done_at = time.monotonic()
                    if done_at is not None and time.monotonic() - done_at > 1.0:
                        break
                    await transport.send("GET", f"{app.base}{WORK_PREFIX}{sent}",
                                         capability="engagement_execute")
                    sent += 1
                    if every and time.monotonic() - last_call >= every:
                        await self.model.chat_json("m", "sys", "the sweep's own call")
                        last_call = time.monotonic()
                    await asyncio.sleep(0.01)
            facts["sweep"] = (started, time.monotonic(), sent)
            return []

        async def cancel_later():
            await asyncio.sleep(self.cancel_after)
            facts["cancelled_at"] = time.monotonic()
            facts["engagement"].cancel()

        async def go():
            try:
                async with rc:
                    facts["engagement"] = asyncio.create_task(orch.investigate_engagement(
                        app.base, [RoleSession("anonymous", {})], max_nodes=1,
                        max_chain_rounds=0, discovery_max_probes=1, run_context=rc))
                    canceller = (asyncio.create_task(cancel_later())
                                 if self.cancel_after is not None else None)
                    try:
                        return await facts["engagement"]
                    except asyncio.CancelledError:
                        if asyncio.current_task().cancelling():
                            raise
                        return None    # the engagement itself was cancelled
                    finally:
                        if canceller is not None:
                            canceller.cancel()
                        facts["leftover_tasks"] = [
                            t.get_name() for t in asyncio.all_tasks()
                            if t is not asyncio.current_task() and not t.done()
                            and t.get_name() in ("capture-review-idle",
                                                 "capture-review-overlap")]
            finally:
                await rc.aclose()

        patches = [patch.object(engagement_builder, "build_engagement", new=build),
                   patch.object(worklist_investigator, "investigate_worklist", new=sweep),
                   patch.object(coverage_tracker, "build_coverage_driven",
                                new=AsyncMock(return_value={})),
                   chain_patch("universal_header_audit",
                         new=AsyncMock(return_value=0)),
                   patch("harness.ffuf_runner.ffuf_available",
                         return_value=(False, "ffuf disabled for this test")),
                   patch("harness.browser_driver.default_driver", return_value=None)]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        facts["model_calls"] = list(self.model.owned)
        facts["work_requests"] = app.received(WORK_PREFIX)
        return result, facts


def _path(url: str) -> str:   # each run has its own app, on its own port
    return urlsplit(url).path


def _analyzed_urls(facts) -> list[str]:
    return [_path(url) for url, *_ in facts["analyzed"]]


def _grouped(result) -> set[str]:
    return {_path(g["capture"]) for g in result["review_stats"]["grouped"]}


IDLE = {"review_on_idle_seconds": IDLE_SECONDS}
SWEEP = [("model", 2), ("send", WINDOW)]
LONG_SWEEP = [("model", 2), ("send", LONG_WINDOW)]


class IdleReviewCallerTest(unittest.TestCase):
    """The sweep's own model calls are done early and the rest of it only sends."""

    @classmethod
    def setUpClass(cls):
        cls.on, cls.on_facts = _Run(dict(IDLE), LONG_SWEEP, until_reviewed=REVIEWS).run()
        cls.off, cls.off_facts = _Run({}, SWEEP).run()

    def _window(self, facts):
        sends = [t for t, _ in facts["work_requests"]]
        self.assertGreater(len(sends), 50, "the sweep sent requests to the app")
        return min(sends), max(sends)

    def test_the_review_runs_while_the_sweep_is_still_sending(self):
        lo, hi = self._window(self.on_facts)
        beside = [a for a in self.on_facts["analyzed"] if lo < a[1] < hi]
        self.assertGreater(len(beside), 5, "captures were reviewed while the sweep sent")
        self.assertTrue(all(a[3] for a in beside), "by the idle review, not the sweep")
        calls = [c for c in self.on_facts["model_calls"] if c[2] and lo < c[0] < hi]
        self.assertGreater(len(calls), 5)
        report = self.on["crawl_loop"]["idle_review"]
        self.assertEqual(report["idle_seconds"], IDLE_SECONDS)
        self.assertEqual(report["stopped_by"], "capture review phase")
        self.assertGreaterEqual(report["first_review_after_seconds"], IDLE_SECONDS)

    def test_no_capture_is_reviewed_twice(self):
        urls = _analyzed_urls(self.on_facts)
        self.assertEqual(len(urls), len(set(urls)))
        stats = self.on["review_stats"]
        self.assertEqual(stats["reviewed"], len(urls))
        self.assertEqual(stats["reviewed"] + len(stats["grouped"]) + stats["unreviewed"],
                         CAPTURES)

    def test_the_same_captures_are_reviewed_as_in_the_sequential_order(self):
        self.assertEqual(sorted(_analyzed_urls(self.on_facts)),
                         sorted(_analyzed_urls(self.off_facts)))
        self.assertEqual(_grouped(self.on), _grouped(self.off))
        self.assertEqual(len(_grouped(self.on)), PAGES - 1)
        for result in (self.on, self.off):
            self.assertEqual(result["review_stats"]["unreviewed"], 0)
            self.assertEqual([e for e in result["errors"] if e.get("phase") == "capture_review"],
                             [])

    def test_capture_review_skips_what_the_idle_review_finished(self):
        # The window outlasts the whole review: capture_review is left nothing.
        report = self.on["crawl_loop"]["idle_review"]
        self.assertEqual(report["reviewed"], self.on["review_stats"]["reviewed"])
        self.assertEqual([a for a in self.on_facts["analyzed"] if not a[3]], [],
                         "capture_review made no analysis of its own")
        _, hi = self._window(self.on_facts)
        self.assertEqual([c for c in self.on_facts["model_calls"] if c[0] > hi], [],
                         "and no model call after the sweep")

    def test_negative_control_off_keeps_the_sequential_order(self):
        lo, hi = self._window(self.off_facts)
        self.assertIsNone(self.off["crawl_loop"]["idle_review"])
        self.assertEqual([a for a in self.off_facts["analyzed"] if a[1] < hi], [],
                         "no capture is reviewed before the sweep ends")
        self.assertEqual([c for c in self.off_facts["model_calls"] if lo < c[0] < hi], [],
                         "the model sits idle while the sweep sends")
        self.assertGreater(len(self.off_facts["analyzed"]), 5)
        self.assertEqual(self.off_facts["leftover_tasks"], [])
        self.assertEqual(self.on_facts["leftover_tasks"], [])


class IdleReviewBusyModelCallerTest(unittest.TestCase):
    def test_negative_control_a_busy_model_gets_no_extra_work(self):
        # The sweep calls the model every 0.1 s: it is never idle for 0.3 s.
        result, facts = _Run(dict(IDLE), [("model", 1), ("send", 2.0, 0.1)]).run()
        _, sweep_end, _ = facts["sweep"]
        own = [c for c in facts["model_calls"] if not c[2] and c[0] < sweep_end]
        self.assertGreater(len(own), 10, "the sweep kept the model busy")
        self.assertEqual([a for a in facts["analyzed"] if a[1] < sweep_end], [])
        report = result["crawl_loop"]["idle_review"]
        self.assertEqual((report["reviewed"], report["calls"]), (0, 0))
        # capture_review then reviews everything, as before.
        stats = result["review_stats"]
        self.assertEqual(stats["reviewed"] + len(stats["grouped"]), CAPTURES)
        self.assertEqual(facts["leftover_tasks"], [])

    def test_the_review_pauses_while_the_sweep_uses_the_model_again(self):
        # The sweep's model work comes back mid-way: the review stops before its next
        # capture, lets the sweep's calls through, and resumes once idle again.
        steps = [("model", 2), ("send", 0.8), ("model", 4), ("send", 0.6), ("model", 4),
                 ("send", LONG_WINDOW)]
        result, facts = _Run(dict(IDLE), steps, until_reviewed=REVIEWS).run()
        report = result["crawl_loop"]["idle_review"]
        self.assertGreaterEqual(report["pauses"], 1)
        self.assertGreaterEqual(report["calls"], 2)
        own = [(s, e) for s, e, background in facts["model_calls"] if not background]
        for _, started, _, background in facts["analyzed"]:
            if not background:
                continue
            for s, e in own:
                self.assertFalse(s < started < e, "no capture starts while the sweep calls")
                self.assertFalse(0 <= started - e < IDLE_SECONDS - 1e-3,
                                 "nor within review_on_idle_seconds of its last call")
        urls = _analyzed_urls(facts)
        self.assertEqual(len(urls), len(set(urls)))
        stats = result["review_stats"]
        self.assertEqual(stats["reviewed"] + len(stats["grouped"]) + stats["unreviewed"],
                         CAPTURES)
        self.assertEqual(len(stats["grouped"]), PAGES - 1)


class IdleReviewBoundsCallerTest(unittest.TestCase):
    def test_the_review_limit_is_shared_with_capture_review(self):
        limit = 8
        on, on_facts = _Run(dict(IDLE, capture_review_limit=limit), LONG_SWEEP,
                            until_reviewed=limit).run()
        off, off_facts = _Run({"capture_review_limit": limit}, SWEEP).run()
        self.assertEqual(len(_analyzed_urls(on_facts)), limit)
        self.assertEqual(sorted(_analyzed_urls(on_facts)), sorted(_analyzed_urls(off_facts)))
        self.assertEqual(on["crawl_loop"]["idle_review"]["stopped_by"], "capture review limit")
        for result in (on, off):
            stats = result["review_stats"]
            self.assertEqual(stats["reviewed"], limit)
            self.assertEqual(stats["reviewed"] + len(stats["grouped"]) + stats["unreviewed"],
                             CAPTURES)
        # What the limit left is reported once, by capture_review, as before.
        errors = lambda r: [e["error"] for e in r["errors"] if e.get("phase") == "capture_review"]
        self.assertEqual(errors(on), errors(off))
        self.assertEqual(len(errors(on)), 1)

    def test_an_engagement_cancelled_mid_sweep_leaves_no_review_running(self):
        result, facts = _Run(dict(IDLE), [("model", 2), ("send", 3.0)],
                             cancel_after=1.2).run()
        self.assertIsNone(result)
        self.assertEqual(facts["leftover_tasks"], [])
        cancelled_at = facts["cancelled_at"]
        self.assertGreater(len([a for a in facts["analyzed"] if a[1] < cancelled_at]), 0,
                           "the idle review was running when the engagement was cancelled")
        self.assertEqual([c for c in facts["model_calls"] if c[0] > cancelled_at + 0.1], [],
                         "no model call starts once the engagement is cancelled")


# ---------------------------------------------------------------- unit level
class ModelActivityTests(unittest.TestCase):
    def test_idle_for_excludes_the_owner_and_counts_from_since(self):
        now = [100.0]
        activity = ModelActivity(clock=lambda: now[0])
        mine = object()
        self.assertEqual(activity.idle_for(), float("inf"))
        self.assertEqual(activity.idle_for(since=90.0), 10.0)
        foreground = activity.begin()
        self.assertIsNone(foreground)
        self.assertEqual(activity.in_flight(), 1)
        self.assertEqual(activity.idle_for(exclude=mine), 0.0)
        now[0] = 104.0
        activity.end(foreground)
        now[0] = 105.0
        self.assertEqual(activity.idle_for(exclude=mine), 1.0)
        with model_activity.owned_by(mine):
            owner = activity.begin()
        self.assertIs(owner, mine)
        self.assertEqual(activity.idle_for(exclude=mine), 1.0, "its own call is not counted")
        self.assertEqual(activity.idle_for(), 0.0)
        now[0] = 110.0
        activity.end(owner)
        self.assertEqual(activity.idle_for(exclude=mine), 6.0)
        self.assertEqual(activity.idle_for(), 0.0)
        activity.forget(mine)
        self.assertEqual(activity.idle_for(), 6.0)
        activity.forget(None)   # the foreground's record stays
        self.assertEqual(activity.idle_for(), 6.0)


class OllamaClientActivityTests(unittest.IsolatedAsyncioTestCase):
    async def test_every_model_call_is_in_flight_while_it_runs(self):
        activity = ModelActivity()
        seen = []

        async def chat_impl(*args, **kwargs):
            seen.append((activity.in_flight(), model_activity.current_owner()))
            return {"findings": []}, "{}"

        client = OllamaClient("http://fake-ollama:11434")
        client._chat_impl = chat_impl
        mine = object()
        with patch.object(model_activity, "ACTIVITY", activity):
            await client._chat("m", "sys", "user")
            with model_activity.owned_by(mine):
                await client._chat("m", "sys", "user")
            self.assertEqual(seen, [(1, None), (1, mine)])
            self.assertEqual(activity.in_flight(), 0)
            self.assertLess(activity.idle_for(), 1.0)

            async def failing(*args, **kwargs):
                raise RuntimeError("model down")

            client._chat_impl = failing
            with self.assertRaises(RuntimeError):
                await client._chat("m", "sys", "user")
            self.assertEqual(activity.in_flight(), 0, "a failed call ends too")


class _FakeReview:
    """review_captured_exchanges' contract: asks should_stop before each capture, stops
    at max_reviews and its deadline, and reports through outcome_out."""

    def __init__(self, items: int, seconds: float = 0.02, on_capture=None):
        self.left = list(range(items))
        self.seconds = seconds
        self.on_capture = on_capture
        self.done: list[int] = []
        self.calls = 0

    async def __call__(self, captured, *, max_reviews, deadline, should_stop, outcome_out):
        self.calls += 1
        reviewed, stopped = 0, None
        try:
            while True:
                if reviewed >= max_reviews:
                    stopped = review_overlap.LIMIT
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    stopped = review_overlap.TIME_BUDGET
                    break
                stopped = should_stop()
                if stopped or not self.left:
                    break
                item = self.left.pop(0)
                await asyncio.sleep(self.seconds)
                self.done.append(item)
                reviewed += 1
                if self.on_capture is not None:
                    self.on_capture(item)
        finally:
            outcome_out.update(stopped_by=stopped, reviewed=reviewed, produced=0)
        return 0


class IdleReviewUnitTests(unittest.IsolatedAsyncioTestCase):
    def _review(self, fake, activity, **kwargs):
        kwargs.setdefault("idle_seconds", 0.05)
        kwargs.setdefault("max_reviews", 100)
        return IdleReview(fake, lambda: [object()], activity=activity, **kwargs)

    async def test_it_waits_for_the_model_to_be_idle(self):
        activity = ModelActivity()
        fake = _FakeReview(3)
        foreground = activity.begin()
        idle = self._review(fake, activity).start()
        await asyncio.sleep(0.15)
        self.assertEqual(fake.calls, 0, "nothing while another call is in flight")
        activity.end(foreground)
        await asyncio.sleep(0.25)
        self.assertEqual(fake.done, [0, 1, 2])
        await idle.drain()
        self.assertEqual(idle.stopped_by, review_overlap.REVIEW_PHASE)
        self.assertEqual(idle.reviewed, 3)

    async def test_it_pauses_when_another_call_starts_and_resumes_when_idle(self):
        activity = ModelActivity()
        state = {}

        def on_capture(item):
            if item == 1:   # the sweep calls the model again after the second capture
                with model_activity.owned_by(None):   # the sweep's call, not the review's
                    state["foreground"] = activity.begin()

        fake = _FakeReview(5, on_capture=on_capture)
        idle = self._review(fake, activity).start()
        await asyncio.sleep(0.25)
        self.assertEqual(fake.done, [0, 1], "stopped before the next capture")
        activity.end(state["foreground"])
        await asyncio.sleep(0.3)
        self.assertEqual(fake.done, [0, 1, 2, 3, 4])
        await idle.drain()
        self.assertGreaterEqual(idle.pauses, 1)
        self.assertGreaterEqual(fake.calls, 2)
        self.assertEqual(idle.reviewed, 5)

    async def test_its_own_calls_never_count_as_busy(self):
        activity = ModelActivity()
        captured_owner = []

        def on_capture(item):
            owner = activity.begin()   # the review's own model call
            captured_owner.append(owner)
            activity.end(owner)

        fake = _FakeReview(4, on_capture=on_capture)
        idle = self._review(fake, activity).start()
        await asyncio.sleep(0.4)
        await idle.drain()
        self.assertEqual(fake.done, [0, 1, 2, 3])
        self.assertEqual(idle.pauses, 0)
        self.assertTrue(all(owner is not None for owner in captured_owner))

    async def test_the_limit_and_the_review_seconds_bound_it(self):
        activity = ModelActivity()
        limited = self._review(_FakeReview(10), activity, max_reviews=3).start()
        await asyncio.sleep(0.4)
        self.assertTrue(limited._task.done())
        await limited.drain()
        self.assertEqual((limited.reviewed, limited.stopped_by), (3, review_overlap.LIMIT))

        timed = self._review(_FakeReview(100), activity, review_seconds=0.2).start()
        await asyncio.sleep(0.6)
        self.assertTrue(timed._task.done())
        await timed.drain()
        self.assertEqual(timed.stopped_by, review_overlap.TIME_BUDGET)
        self.assertLess(timed.reviewed, 20)
        self.assertEqual(timed.review_seconds_left, 0.0)

    async def test_the_deadline_is_hard(self):
        activity = ModelActivity()
        fake = _FakeReview(3, seconds=5.0)   # one analysis outlasts the deadline
        idle = self._review(fake, activity, deadline=time.monotonic() + 0.3).start()
        await asyncio.sleep(0.6)
        self.assertTrue(idle._task.done())
        await idle.drain()
        self.assertEqual(idle.stopped_by, review_overlap.TIME_BUDGET)
        self.assertEqual(fake.done, [])

    async def test_drain_lets_the_capture_in_flight_finish(self):
        activity = ModelActivity()
        fake = _FakeReview(3, seconds=0.2)
        idle = self._review(fake, activity).start()
        await asyncio.sleep(0.12)   # the first capture is in flight
        await idle.drain()
        self.assertEqual(fake.done, [0])
        self.assertEqual(idle.stopped_by, review_overlap.REVIEW_PHASE)

    async def test_aclose_cancels_and_an_error_is_kept(self):
        activity = ModelActivity()
        idle = self._review(_FakeReview(3, seconds=5.0), activity).start()
        await asyncio.sleep(0.1)
        await idle.aclose()
        self.assertTrue(idle._task.done())
        self.assertEqual(idle.stopped_by, review_overlap.ENGAGEMENT_END)

        async def broken(captured, **bounds):
            raise ValueError("bad capture")

        failed = IdleReview(broken, lambda: [object()], idle_seconds=0.01, max_reviews=5,
                            activity=activity).start()
        await asyncio.sleep(0.1)
        await failed.drain()
        self.assertEqual(failed.error, "ValueError: bad capture")


def _page(url: str) -> HttpExchange:
    return HttpExchange(method="GET", url=url, response_status=200,
                        response_headers={"Content-Type": "text/html"},
                        response_body="<html>the same page</html>")


class ReviewGroupsAcrossCallsTests(unittest.IsolatedAsyncioTestCase):
    """`groups` carries identical-content grouping from one review call to the next,
    as one call over all the captures would group them."""

    def _orch(self):
        resp = SimpleNamespace(agent_reports=[], stage_outcomes=[])
        return SimpleNamespace(analyze=AsyncMock(return_value=resp))

    def _state(self):
        return SimpleNamespace(record_template=lambda *a: None, ingest_findings=lambda *a: 0)

    async def test_a_later_call_groups_content_an_earlier_call_reviewed(self):
        orch, state, seen, groups = self._orch(), self._state(), set(), {}
        stats = {}
        await orchestrator_review.review_captured_exchanges(
            orch, state, [_page("http://h/pages/a")], seen=seen, stats=stats, groups=groups)
        await orchestrator_review.review_captured_exchanges(
            orch, state, [_page("http://h/pages/a"), _page("http://h/pages/b"),
                          _page("http://h/pages/c")], seen=seen, stats=stats, groups=groups)
        self.assertEqual(orch.analyze.await_count, 1)
        self.assertEqual({g["capture"] for g in stats["grouped"]},
                         {"http://h/pages/b", "http://h/pages/c"})
        self.assertTrue(all(g["covered_by"] == "http://h/pages/a" for g in stats["grouped"]))

    async def test_negative_control_without_groups_the_content_is_reviewed_again(self):
        orch, state, seen = self._orch(), self._state(), set()
        await orchestrator_review.review_captured_exchanges(
            orch, state, [_page("http://h/pages/a")], seen=seen)
        await orchestrator_review.review_captured_exchanges(
            orch, state, [_page("http://h/pages/a"), _page("http://h/pages/b"),
                          _page("http://h/pages/c")], seen=seen)
        self.assertEqual(orch.analyze.await_count, 2)

    async def test_a_capture_already_reviewed_is_not_reviewed_again(self):
        orch, state, seen = self._orch(), self._state(), set()
        items = [HttpExchange(method="GET", url=f"http://h/api/items/{n}", response_status=200,
                              response_headers={"Content-Type": "application/json"},
                              response_body=json.dumps({"id": n})) for n in range(4)]
        await orchestrator_review.review_captured_exchanges(orch, state, items[:2], seen=seen)
        await orchestrator_review.review_captured_exchanges(orch, state, items, seen=seen)
        self.assertEqual([c.args[0].url for c in orch.analyze.await_args_list],
                         [i.url for i in items[:2]] + [i.url for i in items[2:]])

    async def test_a_paused_call_reports_nothing_left(self):
        orch, state, errors, stats, outcome = self._orch(), self._state(), [], {}, {}
        pages = [HttpExchange(method="GET", url=f"http://h/api/items/{n}", response_status=200,
                              response_headers={}, response_body=str(n)) for n in range(3)]
        await orchestrator_review.review_captured_exchanges(
            orch, state, pages, seen=set(), errors=errors, stats=stats,
            should_stop=lambda: review_overlap.MODEL_BUSY, report_left=False,
            outcome_out=outcome)
        self.assertEqual(orch.analyze.await_count, 0)
        self.assertEqual((errors, stats["unreviewed"], outcome["remaining"]), ([], 0, 0))
        self.assertEqual(outcome["stopped_by"], review_overlap.MODEL_BUSY)


if __name__ == "__main__":
    unittest.main()
