"""WL-12 (E40): `run_engagement(execute=True)` owns one bounded, cancellable run.

The plan-execute driver behind `/engagement/{host}/run` (double-gated: the request's
`execute` AND `engagement.driver_execute`) fetched each funded GET target through
`transport_for(None, ...)` -- outside a run, a standalone context with no request
ceiling and no reachable cancel token -- and analyzed every fetched page in its own
run (ceiling analyze.max_requests per page). Nothing bounded the call as a whole.

These tests drive `Orchestrator.run_engagement` against an owned loopback target that
counts every request it actually receives, with a test-local config enabling
`engagement.driver_execute` and an engagement state holding several funded GET
targets. Each page analysis makes one send through the run `analyze()` hands it (the
`_analyze_inner` boundary is scripted; `analyze()`'s own run-ownership logic is the
production code), the way a validator inside an analysis would, so the per-page runs
of the old path are visible in the count. One test runs the real analysis path.

  (a) total requests reaching the target <= the configured run ceiling, and equal
      the owned run's budget; page analyses create no run of their own;
  (b) cancelling the owned run stops every further send;
  (c) execute=False (and execute with driver_execute off) sends nothing;
  (d) fault injection: the pre-WL-12 loop (transport_for(None) + per-page analyze
      runs) exceeds the ceiling, so the ceiling test detects it;
  plus: an enclosing run is borrowed (spent, not closed) and the ceiling falls back
  to analyze.max_requests when runs.max_requests is unset.

Caller verification only: loopback, no model accuracy or recall measured.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, urlsplit

import yaml

from harness import cache, engagement, evidence_ledger, global_throttle, safety_gate, store
from harness import scope_discovery
from harness.models import AnalysisResponse, HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext, transport_for

_HARNESS = Path(__file__).resolve().parent
_HOST = "127.0.0.1"
_TARGETS = 6
_PROBE_PATH = "/api/analysis-probe"


class _Target:
    """Loopback target: GET /api/itemN answers JSON; every request is recorded, and
    `on_request` (if set) runs before the response is written."""

    def __init__(self):
        self.requests: list[tuple[str, str]] = []
        self.on_request = None
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                with outer._lock:
                    outer.requests.append((self.command, self.path))
                    count = len(outer.requests)
                if outer.on_request is not None:
                    outer.on_request(count)
                data = json.dumps({"path": self.path, "ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_OPTIONS = do_PUT = do_DELETE = _handle

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        self._server = Server((_HOST, 0), Handler)
        self.base = f"http://{_HOST}:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def page_gets(self):
        return [r for r in self.requests if r[1].startswith("/api/item")]

    def probes(self):
        return [r for r in self.requests if r[1].startswith(_PROBE_PATH)]

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _SilentModel:
    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=await self.chat_json(model, system_prompt, user_prompt),
                            prompt_tokens=1, completion_tokens=1)


def _config(*, runs_max=None, analyze_max=None, driver_execute=True) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    eng = cfg.setdefault("engagement", {})
    eng["driver_execute"] = driver_execute
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = [_HOST]
    if runs_max is not None:
        cfg.setdefault("runs", {})["max_requests"] = runs_max
    if analyze_max is not None:
        cfg.setdefault("analyze", {})["max_requests"] = analyze_max
    return cfg


def _install_model(orch: Orchestrator, model) -> None:
    orch.ollama = model
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coordinator = getattr(orch, "coordinator", None)
    if coordinator is not None and hasattr(coordinator, "ollama"):
        coordinator.ollama = model


def _seed_state() -> None:
    st = engagement.EngagementState(host=_HOST)
    st.ingest_role_crawl({"endpoints": [
        {"method": "GET", "path": f"/api/item{i}", "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False}
        for i in range(_TARGETS)], "idor_findings": []})
    store.save_engagement(_HOST, st.to_dict())


async def _probing_analyze_inner(self, exchange, **kw):
    """Scripted analysis boundary: one send through the run analyze() handed in,
    as a validator inside the analysis would make."""
    run = kw["run_context"]
    page = urlsplit(exchange.url).path
    await run.executor().send("GET", exchange.url.split("/api/", 1)[0] + _PROBE_PATH
                              + "?page=" + quote(page), capability="analysis_probe",
                              max_redirects=0)
    return AnalysisResponse(coordinator_model="scripted", dispatched_agents=[], agent_reports=[],
                            summary="", test_plans=[])


async def _legacy_run_engagement(self, host, base_url, *, max_targets=5, max_rounds=3,
                                 execute=False):
    """The pre-WL-12 execute loop, verbatim in substance (fault injection only):
    a standalone transport_for(None) per round and analyze() without a run."""
    p = urlsplit(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    rounds, seen_urls = [], set()
    for rnd in range(1, max(1, max_rounds) + 1):
        plan = await self.plan_engagement(host, max_targets=max_targets, base_url=base_url)
        funded = [t for t in plan["targets"]
                  if t["action"] != "deferred" and t["method"].upper() == "GET"]
        analyzed = []
        _tt, _owned = transport_for(None, allowed_hosts=self.allowed_hosts, config=self.config)
        try:
            for t in funded:
                url = origin + t["path"].replace("{id}", "1")
                if url in seen_urls or not scope_discovery.is_host_allowed(url, self.allowed_hosts):
                    continue
                seen_urls.add(url)
                out = await _tt.send("GET", url, capability="engagement_execute", max_redirects=0)
                if not out.ok:
                    analyzed.append({"url": url, "error": out.outcome})
                    continue
                exchange = HttpExchange(url=url, method="GET", response_status=out.status,
                                        response_headers=dict(out.headers),
                                        response_body=out.body or "")
                await self.analyze(exchange, retain_observation=False)
                analyzed.append({"url": url, "findings": 0})
        finally:
            if _owned is not None:
                await _owned.aclose()
        rounds.append({"round": rnd, "targets_run": len(analyzed)})
        if not analyzed:
            break
    return {"host": host, "executed": True, "rounds": rounds}


class RunEngagementRunBoundTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="wl12_run_bound_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        stats = global_throttle.throttle.stats()
        self._throttle = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                          stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()
        _seed_state()
        self.target = _Target()
        self.addCleanup(self.target.close)
        # Every RunContext created during a test, in order (spy, not a stub).
        self.created: list[RunContext] = []
        original_create = RunContext.create.__func__
        created = self.created

        def spy(cls, **kw):
            rc = original_create(cls, **kw)
            created.append(rc)
            return rc
        self._spy = patch.object(RunContext, "create", classmethod(spy))

    def tearDown(self):
        global_throttle.configure(*self._throttle)
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _drive(self, cfg, *, execute=True, scripted=True, enclosing=None, extra_patches=(),
               allowed_hosts=(_HOST,)):
        orch = Orchestrator(cfg)
        orch.allowed_hosts = list(allowed_hosts)
        _install_model(orch, _SilentModel())

        async def go():
            if enclosing is None:
                return await orch.run_engagement(_HOST, self.target.base, max_targets=_TARGETS,
                                                 max_rounds=3, execute=execute)
            async with enclosing:
                return await orch.run_engagement(_HOST, self.target.base, max_targets=_TARGETS,
                                                 max_rounds=3, execute=execute)

        patches = [self._spy, patch("harness.browser_driver.default_driver", return_value=None),
                   *extra_patches]
        if scripted:
            patches.append(patch.object(Orchestrator, "_analyze_inner", _probing_analyze_inner))
        for p in patches:
            p.start()
        try:
            return asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()

    def test_requests_reaching_the_target_never_exceed_the_run_ceiling(self):
        ceiling = 5
        result = self._drive(_config(runs_max=ceiling))
        self.assertTrue(result["executed"])
        self.assertLessEqual(len(self.target.requests), ceiling, self.target.requests)
        # The bound binds: without it the call would send 2 x _TARGETS requests.
        self.assertEqual(len(self.target.requests), ceiling)
        self.assertTrue(self.target.probes(), "no page analysis sent through the run")
        self.assertEqual(len(self.created), 1, "a page analysis created a run of its own")
        owned = self.created[0]
        self.assertEqual(owned.budget.used, len(self.target.requests))
        self.assertEqual(result["run"], {"run_id": owned.run_id, "owned": True,
                                         "max_requests": ceiling, "requests_used": ceiling,
                                         "cancelled": False})
        self.assertIn("run request ceiling reached",
                      [r.get("stopped") for r in result["rounds"]])
        # Mutating replay is forced off for the driver's run, as for the RV-G routes.
        self.assertFalse(owned.gate.config.allow_mutating_replay)

    def test_all_targets_run_when_the_ceiling_allows(self):
        result = self._drive(_config(runs_max=100))
        self.assertEqual(len(self.target.page_gets()), _TARGETS)
        self.assertEqual(len(self.target.probes()), _TARGETS)
        self.assertEqual(self.created[0].budget.used, 2 * _TARGETS)
        self.assertEqual(result["run"]["requests_used"], 2 * _TARGETS)

    def test_ceiling_falls_back_to_the_standalone_analysis_ceiling(self):
        result = self._drive(_config(analyze_max=3))
        self.assertEqual(len(self.target.requests), 3)
        self.assertEqual(result["run"]["max_requests"], 3)

    def test_cancelling_the_owned_run_stops_further_sends(self):
        cancel_at = 3

        def cancel(count):
            if count == cancel_at:
                self.created[0].cancel.cancel()
        self.target.on_request = cancel
        result = self._drive(_config(runs_max=100))
        self.assertEqual(len(self.target.requests), cancel_at, self.target.requests)
        self.assertTrue(result["run"]["cancelled"])
        self.assertIn("run cancelled", [r.get("stopped") for r in result["rounds"]])

    def test_plan_only_sends_nothing(self):
        result = self._drive(_config(runs_max=100), execute=False)
        self.assertFalse(result["executed"])
        self.assertEqual(self.target.requests, [])
        self.assertEqual(self.created, [])

    def test_execute_refused_by_config_sends_nothing(self):
        result = self._drive(_config(runs_max=100, driver_execute=False))
        self.assertFalse(result["executed"])
        self.assertIn("refused", result["note"])
        self.assertEqual(self.target.requests, [])
        self.assertEqual(self.created, [])

    def test_an_empty_scope_fails_closed(self):
        """The owned run's scope is fail-closed: with no allowed_hosts nothing is sent
        (the old standalone context admitted an empty scope in passive mode, E41)."""
        result = self._drive(_config(runs_max=100), allowed_hosts=())
        self.assertEqual(self.target.requests, [])
        details = [d for r in result["rounds"] for d in r.get("detail", [])]
        self.assertTrue(details)
        self.assertTrue(all(d.get("error") == "out_of_scope" for d in details), details)

    def test_an_enclosing_run_is_borrowed_not_closed(self):
        enclosing = RunContext.create(allowed_hosts=[_HOST], max_requests=4,
                                      gate_config={"active_enabled": False})
        self.created.clear()
        result = self._drive(_config(runs_max=100), enclosing=enclosing)
        self.assertEqual(self.created, [], "run_engagement created a run inside an enclosing one")
        self.assertEqual(len(self.target.requests), 4)
        self.assertEqual(enclosing.budget.used, 4)
        self.assertEqual(result["run"]["owned"], False)
        self.assertEqual(result["run"]["run_id"], enclosing.run_id)

    def test_real_analysis_path_borrows_the_owned_run(self):
        """No scripted boundary: the production analyze() pipeline runs per page."""
        result = self._drive(_config(runs_max=50), scripted=False)
        details = [d for r in result["rounds"] for d in r.get("detail", [])]
        self.assertTrue(details)
        self.assertFalse([d for d in details if "error" in d], details)
        self.assertEqual(len(self.target.page_gets()), _TARGETS)
        self.assertEqual(len(self.created), 1)
        self.assertEqual(self.created[0].budget.used, len(self.target.requests))
        self.assertLessEqual(len(self.target.requests), 50)

    def test_restoring_the_unbounded_path_is_detected(self):
        """Fault injection (d): the pre-WL-12 loop escapes the ceiling."""
        ceiling = 5
        self._drive(_config(runs_max=ceiling), extra_patches=[
            patch.object(Orchestrator, "run_engagement", _legacy_run_engagement)])
        self.assertGreater(len(self.target.requests), ceiling,
                           "the unbounded path no longer exceeds the ceiling -- the control is vacuous")
        self.assertGreater(len(self.created), 1)   # standalone transports + per-page runs


if __name__ == "__main__":
    unittest.main()
