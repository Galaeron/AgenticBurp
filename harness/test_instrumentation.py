"""E9: instrumentation for profiling -- model usage by stage, phase walls, the tool
lifecycle and the store's connection cost.

Measured motivation (job 383f0ebff8e8): the manifest `model_metrics` was null,
phase walls had to be rebuilt from log gaps, sqlmap startup and the per-launch
`docker version` could not be measured, and `store._connect()` re-ran ~58 schema
statements on every call.

Everything is no-network: a scripted ``httpx.MockTransport`` stands in for Ollama,
the docker seams are patched, and the engagement test drives the real
``investigate_engagement`` over the same canned discovery the smoke investigate
test uses.

Negative controls follow test_model_retry's pattern: the check is written once as
a helper, the real test runs it, and the ``test_control_*`` twin patches the new
logic out IN-PROCESS and asserts the same check now FAILS. Instrumentation is
observation only, so ``InstrumentationDoesNotChangeBehaviourTests`` also proves a
run with it patched out sends the same requests and reaches the same verdicts.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx

from harness import cache
from harness import circuit_breaker as cb
from harness import instrumentation
from harness import ollama_client as oc
from harness import run_manifest
from harness import store
from harness import test_smoke_investigate as smoke
from harness import tool_runner as tr
from harness.agents.base_agent import BaseAgent
from harness.models import HttpExchange
from harness.ollama_client import OllamaClient, model_stage
from harness.orchestrator import Orchestrator

_REAL_ASYNC_CLIENT = httpx.AsyncClient

_COUNTED_REPLY = {
    "message": {"content": json.dumps({"findings": []})}, "done": True,
    "prompt_eval_count": 10, "eval_count": 4,
    "prompt_eval_duration": 2_000_000, "eval_duration": 5_000_000, "load_duration": 1_000_000,
}


class _Gate:
    """Stands in for the shared token rate limiter."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def record_usage(self, prompt_tokens, completion_tokens):
        pass


class _Agent(BaseAgent):
    name = "instrumented_agent"

    @property
    def specialty_prompt(self):
        return "instrumentation test specialty"


def _fake_ollama(client: OllamaClient, handler) -> contextlib.ExitStack:
    """Point `client` at a scripted wire. The caller keeps the returned stack open."""
    client.rate_limiter = _Gate()
    client.audit_logger = Mock()
    transport = httpx.MockTransport(handler)
    stack = contextlib.ExitStack()
    stack.enter_context(patch("harness.ollama_client.httpx.AsyncClient",
                              side_effect=lambda **kw: _REAL_ASYNC_CLIENT(transport=transport, **kw)))
    return stack


def _counted_reply(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_COUNTED_REPLY)


class _ModelBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        previous = cb._registry
        cb._registry = None           # a fresh shared breaker per test
        self.addCleanup(setattr, cb, "_registry", previous)
        sleep = patch.object(oc, "_backoff_sleep", AsyncMock())
        sleep.start()
        self.addCleanup(sleep.stop)

    def wire(self, handler=_counted_reply, **kwargs) -> OllamaClient:
        client = OllamaClient("http://fake-ollama:11434", **kwargs)
        stack = _fake_ollama(client, handler)
        self.addCleanup(stack.close)
        return client


# --------------------------------------------------------------------------
# 1. Model metrics by stage
# --------------------------------------------------------------------------
class ModelStageTests(_ModelBase):
    async def _check_stage_sums(self):
        client = self.wire()
        with model_stage("critique"):
            await client.chat_json("m", "sys", "user one")
            await client.chat_json("m", "sys", "user two")
        with model_stage("xss"):
            await client.chat_json("m", "sys", "user three")
        stages = client.metrics_snapshot()["stages"]
        self.assertEqual(set(stages), {"critique", "xss"})
        critique, xss = stages["critique"], stages["xss"]
        self.assertEqual((critique["calls"], critique["completed"], critique["failed"]), (2, 2, 0))
        self.assertEqual((critique["prompt_tokens"], critique["completion_tokens"]), (20, 8))
        self.assertEqual((critique["prompt_eval_ms"], critique["eval_ms"], critique["load_ms"]),
                         (4.0, 10.0, 2.0))
        self.assertEqual((xss["calls"], xss["prompt_tokens"], xss["completion_tokens"]), (1, 10, 4))
        self.assertGreaterEqual(critique["wall_ms"], 0.0)
        totals = client.metrics_snapshot()["totals"]
        self.assertEqual((totals["calls"], totals["prompt_tokens"], totals["completion_tokens"]), (3, 30, 12))

    async def test_two_calls_under_critique_and_one_under_xss_sum_per_stage(self):
        await self._check_stage_sums()

    async def test_control_without_stage_bookkeeping_the_sums_fail(self):
        # Patch the new accounting out: every call lands in a throwaway row.
        with patch.object(OllamaClient, "_stage_row", lambda self: {
                **dict.fromkeys(oc._STAGE_COUNT_FIELDS, 0), **dict.fromkeys(oc._STAGE_MS_FIELDS, 0.0),
                **dict.fromkeys(oc._STAGE_MAX_FIELDS, 0)}):
            with self.assertRaises(AssertionError):
                await self._check_stage_sums()

    async def test_unlabelled_calls_land_in_unlabelled(self):
        client = self.wire()
        await client.chat_json("m", "sys", "user")
        self.assertEqual(set(client.metrics_snapshot()["stages"]), {"unlabelled"})
        self.assertEqual(client.metrics_snapshot()["stages"]["unlabelled"]["calls"], 1)

    async def test_label_does_not_leak_out_of_the_block(self):
        client = self.wire()
        with model_stage("planner"):
            pass
        await client.chat_json("m", "sys", "user")
        self.assertEqual(set(client.metrics_snapshot()["stages"]), {"unlabelled"})

    async def test_failed_and_retried_calls_are_counted_per_stage(self):
        steps = iter([500, "ok", 404])

        def wire(request):
            step = next(steps)
            if step == "ok":
                return _counted_reply(request)
            return httpx.Response(step, text="synthetic")

        client = self.wire(wire)
        with model_stage("critique"):
            await client.chat_json("m", "sys", "user")             # 500 then ok: one retry
            with self.assertRaises(oc.OllamaModelNotFoundError):
                await client.chat_json("m", "sys", "user")          # 404: a failed call
        row = client.metrics_snapshot()["stages"]["critique"]
        self.assertEqual((row["calls"], row["completed"], row["failed"], row["retried"]), (2, 1, 1, 1))

    async def test_labelling_does_not_change_the_request_sent(self):
        bodies: list[dict] = []

        def wire(request):
            bodies.append(json.loads(request.content))
            return _counted_reply(request)

        client = self.wire(wire)
        await client.chat_json("m", "sys", "same prompt")
        with model_stage("critique"):
            await client.chat_json("m", "sys", "same prompt")
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0], bodies[1])

    async def _check_base_agent_names_its_stage(self):
        client = self.wire()
        agent = _Agent(ollama=client, model="m")
        report = await agent.run(HttpExchange(url="https://a.test/x", method="GET"), 1000)
        self.assertIsNone(report.raw_error)
        stages = client.metrics_snapshot()["stages"]
        self.assertEqual(set(stages), {"instrumented_agent"})
        self.assertEqual(stages["instrumented_agent"]["completed"], 1)

    async def test_base_agent_run_labels_its_calls_with_the_agent_name(self):
        await self._check_base_agent_names_its_stage()

    async def test_control_base_agent_without_the_label_lands_in_unlabelled(self):
        with patch("harness.agents.base_agent.model_stage", lambda label: contextlib.nullcontext()):
            with self.assertRaises(AssertionError):
                await self._check_base_agent_names_its_stage()

    async def test_snapshot_delta_reports_only_the_run_share(self):
        client = self.wire()
        with model_stage("critique"):
            await client.chat_json("m", "sys", "earlier run")
        before = client.metrics_snapshot()
        with model_stage("critique"):
            await client.chat_json("m", "sys", "this run")
        with model_stage("xss"):
            await client.chat_json("m", "sys", "this run")
        delta = instrumentation.numeric_delta(before, client.metrics_snapshot())
        self.assertEqual(delta["stages"]["critique"]["calls"], 1)
        self.assertEqual(delta["stages"]["xss"]["calls"], 1)
        self.assertEqual(delta["totals"]["prompt_tokens"], 20)
        self.assertEqual(delta["client"]["completed"], 2)


# --------------------------------------------------------------------------
# 2. Store: one-time schema init and timing
# --------------------------------------------------------------------------
class StoreInitTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="instr_store_")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self.db = Path(self._tmp) / "state.db"
        for patcher in (patch.object(store, "_DB_PATH", self.db),
                        patch.dict(store._INITIALISED, {}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _initialisations(self):
        return store.timing_snapshot()["initialisations"]

    def _remove_db_files(self):
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(FileNotFoundError):
                os.remove(str(self.db) + suffix)

    def _check_second_connect_skips_initialisation(self):
        with patch.object(store, "_initialise_connection", wraps=store._initialise_connection) as init:
            first = store._connect()
            first.close()
            second = store._connect()
            try:
                # The skipped connection is a working one: schema present, timeout set.
                second.execute("SELECT count(*) FROM findings").fetchone()
                self.assertEqual(second.execute("PRAGMA busy_timeout").fetchone()[0], 10000)
            finally:
                second.close()
        self.assertEqual(init.call_count, 1, "the schema setup re-ran on the second connection")

    def test_two_connects_in_one_process_initialise_once(self):
        before = store.timing_snapshot()
        self._check_second_connect_skips_initialisation()
        after = store.timing_snapshot()
        self.assertEqual(after["connects"] - before["connects"], 2)
        self.assertEqual(after["initialisations"] - before["initialisations"], 1)
        self.assertEqual(after["skipped_initialisations"] - before["skipped_initialisations"], 1)
        self.assertGreater(after["connect_ms"], before["connect_ms"])

    def test_control_file_identity_that_never_matches_initialises_every_time(self):
        counter = iter(range(10 ** 6))
        real = store._db_identity

        def always_different(conn):
            found = real(conn)
            return None if found is None else (found[0], (next(counter),))

        with patch.object(store, "_db_identity", always_different):
            with self.assertRaises(AssertionError):
                self._check_second_connect_skips_initialisation()

    def _check_recreated_file_is_reinitialised(self):
        store._connect().close()
        self._remove_db_files()
        try:
            conn = store._connect()
            conn.close()
            self.assertTrue(store.save_knowledge_note(["alpha"], "note on the recreated file"))
            notes = store.list_knowledge_notes()
        except sqlite3.OperationalError as exc:
            self.fail(f"a recreated database file was not re-initialised: {exc}")
        self.assertTrue(any("recreated file" in n.get("note", "") for n in notes))

    def test_deleted_and_recreated_file_is_reinitialised_and_usable(self):
        before = self._initialisations()
        self._check_recreated_file_is_reinitialised()
        self.assertEqual(self._initialisations() - before, 2)

    def test_control_a_stale_skip_decision_breaks_the_recreated_file(self):
        real = store._db_identity

        def frozen(conn):
            found = real(conn)
            return None if found is None else (found[0], ("same file",))

        with patch.object(store, "_db_identity", frozen):
            with self.assertRaises(AssertionError):
                self._check_recreated_file_is_reinitialised()

    def _check_dropped_table_is_healed(self):
        conn = store._connect()
        conn.execute("DROP TABLE proof_records")
        conn.commit()
        conn.close()
        conn = store._connect()
        try:
            conn.execute("SELECT count(*) FROM proof_records").fetchone()
        except sqlite3.OperationalError as exc:
            self.fail(f"schema drift was not healed on the next connect: {exc}")
        finally:
            conn.close()

    def test_schema_change_since_the_last_setup_runs_it_again(self):
        # A table dropped under a live process (or migrated by another process)
        # must not be skipped: the schema version is part of the identity.
        self._check_dropped_table_is_healed()

    def test_control_identity_without_the_schema_version_misses_the_drift(self):
        real = store._db_identity

        def file_only(conn):
            found = real(conn)
            return None if found is None else (found[0], ("file",))

        with patch.object(store, "_db_identity", file_only):
            with self.assertRaises(AssertionError):
                self._check_dropped_table_is_healed()

    def test_busy_timeout_is_set_on_every_connection(self):
        for _ in range(3):
            conn = store._connect()
            try:
                self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 10000)
                self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            finally:
                conn.close()

    def _check_save_engagement_records_bytes_and_ms(self):
        before = store.timing_snapshot()["save_engagement"]
        saved = store.save_engagement("instr.example", {"endpoints": {"GET /a": {"n": 1}}})
        after = store.timing_snapshot()["save_engagement"]
        self.assertEqual(after["calls"] - before["calls"], 1)
        self.assertEqual(after["bytes"] - before["bytes"], len(json.dumps(saved)))
        self.assertGreater(after["ms"], before["ms"])
        self.assertGreaterEqual(after["max_bytes"], len(json.dumps(saved)))

    def test_save_engagement_records_bytes_and_ms_per_call(self):
        self._check_save_engagement_records_bytes_and_ms()

    def test_control_without_the_byte_count_the_record_is_wrong(self):
        real = store._write_engagement

        def forget_size(*args, **kwargs):
            out = real(*args, **kwargs)
            store._ENGAGEMENT_WRITE.bytes = 0
            return out

        with patch.object(store, "_write_engagement", forget_size):
            with self.assertRaises(AssertionError):
                self._check_save_engagement_records_bytes_and_ms()


# --------------------------------------------------------------------------
# 3. Tool runner: availability cache and run lifecycle
# --------------------------------------------------------------------------
def _docker_ok(*args, **kwargs):
    return subprocess.CompletedProcess([], 0, "27.0.3\n", "")


def _docker_down(*args, **kwargs):
    return subprocess.CompletedProcess([], 1, "", "cannot connect to the daemon")


class ToolAvailabilityTests(unittest.TestCase):
    def setUp(self):
        tr._reset_available_cache()
        self.addCleanup(tr._reset_available_cache)

    def _check_two_checks_probe_once(self):
        with patch("subprocess.run", side_effect=_docker_ok) as probe:
            first, second = tr.available(), tr.available()
        self.assertEqual((first, second), ((True, "27.0.3"), (True, "27.0.3")))
        self.assertEqual(probe.call_count, 1, "docker was probed again inside the 60 s window")

    def test_two_available_calls_within_60s_run_one_subprocess(self):
        before = tr.lifecycle_snapshot()["availability_checks"]
        self._check_two_checks_probe_once()
        checks = tr.lifecycle_snapshot()["availability_checks"]
        self.assertEqual(checks["checks"] - before["checks"], 2)
        self.assertEqual(checks["cached"] - before["cached"], 1)

    def test_control_without_the_cache_docker_is_probed_every_time(self):
        with patch.object(tr, "AVAILABLE_TTL_SECONDS", 0.0):
            with self.assertRaises(AssertionError):
                self._check_two_checks_probe_once()

    def test_the_cache_expires(self):
        with patch("subprocess.run", side_effect=_docker_ok) as probe:
            tr.available()
            with patch.object(tr.time, "monotonic", return_value=tr.time.monotonic() + 61.0):
                tr.available()
        self.assertEqual(probe.call_count, 2)

    def _check_a_failing_check_is_not_cached(self):
        with patch("subprocess.run", side_effect=_docker_down) as down:
            self.assertFalse(tr.available()[0])
            self.assertFalse(tr.available()[0])
        self.assertEqual(down.call_count, 2, "a failed docker check was served from the cache")
        # Docker Desktop starts: the very next call notices at once.
        with patch("subprocess.run", side_effect=_docker_ok) as up:
            self.assertTrue(tr.available()[0])
            self.assertTrue(tr.available()[0])
        self.assertEqual(up.call_count, 1)

    def test_a_failing_check_is_never_cached(self):
        self._check_a_failing_check_is_not_cached()

    def test_control_caching_a_failure_hides_a_stopped_docker(self):
        def remember_everything(ok, reason):
            tr._available_ok = (tr.DOCKER, tr.time.monotonic(), reason)

        with patch.object(tr, "_remember_available", remember_everything):
            with self.assertRaises(AssertionError):
                self._check_a_failing_check_is_not_cached()


def _finished(returncode=0):
    return tr.ProcessResult(["docker", "run"], returncode, "out", "", "exit", "not_needed", "job")


class ToolLifecycleTests(unittest.TestCase):
    def _check_run_records_a_lifecycle(self):
        receipt: dict = {}
        before = len(tr.lifecycle_snapshot()["runs"])
        with patch.object(tr, "run_process", return_value=_finished(3)):
            returncode, _, _ = tr.run("img:lifecycle", ["--batch"], receipt=receipt)
        self.assertEqual(returncode, 3)
        self.assertGreaterEqual(receipt["duration_ms"], 0.0)
        self.assertLessEqual(receipt["started_at"], receipt["finished_at"])
        runs = tr.lifecycle_snapshot()["runs"]
        self.assertEqual(len(runs), before + 1)
        record = runs[-1]
        self.assertEqual((record["image"], record["outcome"], record["returncode"]),
                         ("img:lifecycle", "exit=3", 3))
        self.assertEqual(record["duration_ms"], receipt["duration_ms"])
        # A record holds counts and timings only: never argv, URLs or output.
        self.assertEqual(set(record), {"image", "outcome", "duration_ms", "returncode", "started_at"})

    def test_run_stamps_the_receipt_and_appends_one_record(self):
        self._check_run_records_a_lifecycle()

    def test_control_without_the_recorder_there_is_no_duration_or_record(self):
        with patch.object(tr, "_record_lifecycle", lambda *args, **kwargs: None):
            with self.assertRaises((AssertionError, KeyError)):
                self._check_run_records_a_lifecycle()

    def test_a_timed_out_run_is_recorded_with_its_outcome(self):
        receipt: dict = {}
        with patch.object(tr, "run_process", side_effect=subprocess.TimeoutExpired("docker", 1)), \
             patch.object(tr, "_force_remove", return_value=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                tr.run("img:timeout", [], timeout=1, receipt=receipt)
        record = tr.lifecycle_snapshot()["runs"][-1]
        self.assertEqual((record["image"], record["outcome"], record["returncode"]),
                         ("img:timeout", "timeout", None))
        self.assertEqual(receipt["outcome"], "timeout")
        self.assertIn("duration_ms", receipt)

    def test_snapshot_has_per_image_counts_and_total_ms(self):
        marker = tr.time.time()
        with patch.object(tr, "run_process", return_value=_finished(0)):
            for _ in range(2):
                tr.run("img:counted", [])
            tr.run("img:other", [])
        snap = tr.lifecycle_snapshot(since=marker)
        self.assertEqual(snap["by_image"]["img:counted"]["runs"], 2)
        self.assertEqual(snap["by_image"]["img:other"]["runs"], 1)
        self.assertAlmostEqual(snap["total_ms"], sum(r["duration_ms"] for r in snap["runs"]), places=2)

    def test_the_record_store_is_bounded(self):
        self.assertEqual(tr._LIFECYCLE.maxlen, 500)
        with patch.object(tr, "run_process", return_value=_finished(0)):
            for _ in range(520):
                tr.run("img:bounded", [])
        self.assertLessEqual(len(tr.lifecycle_snapshot()["runs"]), 500)


# --------------------------------------------------------------------------
# 4. Phase timings
# --------------------------------------------------------------------------
class PhaseRecorderTests(unittest.TestCase):
    def test_sequential_phases_record_walls_and_deltas(self):
        clock = iter([0.0, 0.0, 1.5, 1.5, 4.0])
        used, calls = [0], [0]
        recorder = instrumentation.PhaseRecorder(
            requests=lambda: used[0], model_calls=lambda: calls[0], announce=False,
            clock=lambda: next(clock))
        recorder.begin("discovery")
        used[0], calls[0] = 7, 2
        recorder.begin("worklist")
        used[0], calls[0] = 9, 5
        timings = recorder.timings()
        self.assertEqual([t["phase"] for t in timings], ["discovery", "worklist"])
        self.assertEqual(timings[0], {"phase": "discovery", "started_s": 0.0, "elapsed_s": 1.5,
                                      "requests_used_delta": 7, "model_calls_delta": 2})
        self.assertEqual((timings[1]["requests_used_delta"], timings[1]["model_calls_delta"]), (2, 3))

    def test_context_manager_form_nests_and_orders_by_start(self):
        recorder = instrumentation.PhaseRecorder(announce=False)
        with recorder.phase("outer"):
            with recorder.phase("inner"):
                pass
        self.assertEqual([t["phase"] for t in recorder.timings()], ["outer", "inner"])
        self.assertTrue(all(t["requests_used_delta"] is None and t["model_calls_delta"] is None
                            for t in recorder.timings()))

    def test_a_phase_that_raises_is_still_recorded(self):
        recorder = instrumentation.PhaseRecorder(announce=False)
        with self.assertRaises(RuntimeError):
            with recorder.phase("boom"):
                raise RuntimeError("x")
        self.assertEqual([t["phase"] for t in recorder.timings()], ["boom"])

    def test_each_finished_phase_is_announced_on_the_activity_feed(self):
        from harness import activity_feed
        seen = activity_feed.snapshot(1)["latest_seq"]
        recorder = instrumentation.PhaseRecorder()
        recorder.begin("announced_phase")
        recorder.finish()
        events = [e for e in activity_feed.since(seen)["events"] if e["kind"] == "note"
                  and e["detail"].get("phase") == "announced_phase"]
        self.assertEqual(len(events), 1)
        self.assertRegex(events[0]["message"], r"^phase announced_phase finished in \d+\.\ds$")


_EXPECTED_PHASES = ["discovery", "header_audit", "business_context", "experiments", "worklist",
                    "capture_review", "chain_rounds", "second_order", "coverage_drive", "experiments_final",
                    "finalise"]


class _InvestigateBase(unittest.TestCase):
    """Drives the real `investigate_engagement` like the smoke investigate test,
    with one model call (through BaseAgent.run) made inside the canned discovery."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="instr_investigate_")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        for patcher in (patch.object(store, "_DB_PATH", Path(self._tmp) / "state.db"),
                        patch.dict(store._INITIALISED, {}, clear=True),
                        patch.object(cache, "_cache", cache._cache)):
            patcher.start()
            self.addCleanup(patcher.stop)
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        previous = cb._registry
        cb._registry = None
        self.addCleanup(setattr, cb, "_registry", previous)

    def _investigate(self, *, instrumented=True, run_context=None):
        orch = Orchestrator(smoke._test_config())
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        requests_seen: list[tuple[str, str]] = []
        inner = smoke._responder(True)

        async def recording_get(url, headers=None, **kw):
            requests_seen.append(("GET", str(url)))
            return await inner(url, headers=headers, **kw)

        async def discovery(base_url, roles, **kw):
            # One real model call, labelled by BaseAgent.run, inside the discovery phase.
            with _fake_ollama(orch.ollama, _counted_reply):
                await _Agent(ollama=orch.ollama, model="m").run(
                    HttpExchange(url=base_url + "/seed", method="GET"), 1000)
            return smoke._canned_engagement(base_url, roles, **kw)

        async def drive():
            try:
                return await orch.investigate_engagement(
                    smoke.BASE_URL, smoke.ROLES, max_nodes=4, step_budget=4, max_chain_rounds=0,
                    run_context=run_context)
            finally:
                if run_context is not None:
                    await run_context.aclose()

        patches = [patch("harness.engagement_builder.build_engagement", side_effect=discovery),
                   patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=recording_get)]
        if not instrumented:
            patches.append(patch("harness.instrumentation.RunInstrumentation", _NoInstrumentation))
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            result = asyncio.run(drive())
        return result, requests_seen


class _NoInstrumentation:
    """RunInstrumentation patched out: records nothing, reports nothing."""

    def __init__(self, *args, **kwargs):
        self.phases = SimpleNamespace(begin=lambda name: None, finish=lambda: None)

    def snapshot(self):
        return {}

    def result_blocks(self):
        return {"instrumentation": {}}


class InvestigatePhaseTimingTests(_InvestigateBase):
    def _check_phases_and_model_metrics(self, result):
        block = result["instrumentation"]
        self.assertEqual([t["phase"] for t in block["phase_timings"]], _EXPECTED_PHASES)
        starts = [t["started_s"] for t in block["phase_timings"]]
        self.assertEqual(starts, sorted(starts))
        for timing in block["phase_timings"]:
            self.assertGreaterEqual(timing["elapsed_s"], 0.0)
            self.assertGreaterEqual(timing["started_s"], 0.0)
        discovery = block["phase_timings"][0]
        self.assertEqual(discovery["model_calls_delta"], 1)
        stage = block["model_metrics"]["stages"]["instrumented_agent"]
        self.assertEqual((stage["calls"], stage["prompt_tokens"], stage["completion_tokens"]), (1, 10, 4))
        self.assertEqual(block["model_metrics"]["totals"]["calls"], 1)
        self.assertIn("by_image", block["tool_lifecycle"])
        self.assertIn("connects", block["store_timing"])

    def test_investigate_lists_every_phase_in_order_with_model_metrics(self):
        result, _ = self._investigate()
        self._check_phases_and_model_metrics(result)

    def test_control_without_the_phase_marks_the_list_is_empty(self):
        result, _ = self._investigate()
        with patch.object(instrumentation.PhaseRecorder, "begin", lambda self, name: None):
            other, _ = self._investigate()
        self._check_phases_and_model_metrics(result)
        with self.assertRaises(AssertionError):
            self._check_phases_and_model_metrics(other)

    def test_run_budget_and_health_ride_along_with_a_run_context(self):
        from harness.run_context import RunContext
        cfg = smoke._test_config()
        ctx = RunContext.create(run_id="instr-run", config=cfg, allowed_hosts=["localhost"])
        result, _ = self._investigate(run_context=ctx)
        block = result["instrumentation"]
        self.assertEqual(block["health"]["budget_by_label"], dict(ctx.budget.by_label))
        self.assertIsNotNone(block["health"].get("sessions"))
        # The budget is read, so a phase that sent requests shows them.
        self.assertTrue(all(t["requests_used_delta"] is not None for t in block["phase_timings"]))
        self.assertEqual(sum(t["requests_used_delta"] for t in block["phase_timings"]), ctx.budget.used)

    def _manifest(self, result):
        run = run_manifest.RunManifest.start(run_id="instr", target_identifier="fixture", config={},
                                             output_dir=self._tmp, repo_root=self._tmp)
        run.finish("done", result=result)
        return json.loads(run.path.read_text(encoding="utf-8"))

    def _check_manifest_carries_the_metrics(self, result):
        saved = self._manifest(result)
        self.assertIsNotNone(saved["model_metrics"])
        stage = saved["model_metrics"]["stages"]["instrumented_agent"]
        # Token counts survive the manifest's credential redaction (a count, not a secret).
        self.assertEqual((stage["prompt_tokens"], stage["completion_tokens"]), (10, 4))
        self.assertEqual([t["phase"] for t in saved["phase_timings"]], _EXPECTED_PHASES)

    def test_manifest_model_metrics_is_not_null_after_a_run(self):
        result, _ = self._investigate()
        self._check_manifest_carries_the_metrics(result)

    def test_control_manifest_without_the_copy_keeps_model_metrics_null(self):
        result, _ = self._investigate()
        with patch.object(run_manifest, "_counters", lambda value: None):
            with self.assertRaises(AssertionError):
                self._check_manifest_carries_the_metrics(result)

    def test_a_result_without_instrumentation_leaves_the_manifest_fields_null(self):
        saved = self._manifest({"errors": []})
        self.assertIsNone(saved["model_metrics"])
        self.assertIsNone(saved["phase_timings"])


class InstrumentationDoesNotChangeBehaviourTests(_InvestigateBase):
    @staticmethod
    def _verdicts(result):
        return sorted((o.get("path"), f.get("vulnerability_class"), bool(f.get("confirmed")))
                      for o in result["outcomes"] for f in o.get("findings_detail", []))

    def test_same_requests_and_verdicts_with_and_without_instrumentation(self):
        instrumented, sent_with = self._investigate(instrumented=True)
        plain, sent_without = self._investigate(instrumented=False)
        self.assertTrue(instrumented["instrumentation"]["phase_timings"])
        self.assertEqual(plain["instrumentation"], {})
        self.assertTrue(sent_with, "the run sent no requests, so the comparison proves nothing")
        self.assertEqual(sorted(sent_with), sorted(sent_without))
        self.assertEqual(self._verdicts(instrumented), self._verdicts(plain))
        self.assertTrue(any(confirmed for _, _, confirmed in self._verdicts(instrumented)),
                        "the vulnerable fixture produced no confirmed verdict to compare")
        for key in ("summary", "worklist_summary", "chain_rounds", "errors", "degraded"):
            self.assertEqual(instrumented[key], plain[key], key)


class NumericDeltaTests(unittest.TestCase):
    def test_counters_subtract_and_high_water_marks_keep_their_value(self):
        before = {"a": 2, "nested": {"ms": 1.5}, "max_ms": 9.0}
        after = {"a": 5, "nested": {"ms": 4.0, "new": 3}, "max_ms": 7.0, "label": "x"}
        self.assertEqual(instrumentation.numeric_delta(before, after),
                         {"a": 3, "nested": {"ms": 2.5, "new": 3}, "max_ms": 7.0, "label": "x"})


if __name__ == "__main__":
    unittest.main()
