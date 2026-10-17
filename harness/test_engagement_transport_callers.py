"""I03: budget, cancellation, scope, gate and TLS at the real engagement callers.

The ARCH-1/ARCH-2 tests call `run_active_probe` and `second_order.send_through_run`
directly. These drive `Orchestrator.investigate_engagement` itself -- entered as the
server does, inside `async with run_context` -- into the iterative probe and the
second-order plant/read closures, against an owned loopback target that records
every request it actually receives. Discovery is canned (it sends nothing) and the
model is scripted, so the target's own count is an independent measure of egress:
it must equal the owning run's `budget.used`, and it must be zero whenever the run
is exhausted, cancelled, out of scope, gate-denied or untrusted. Defect injections
that drop the run context must be detected.

Caller verification only: no live target, model accuracy or recall is measured.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from harness import cache, engagement, evidence_ledger, global_throttle, safety_gate, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RunContext

_HARNESS = Path(__file__).resolve().parent
_PROBE_HEADER = "x-i03-probe"
_ROLES = [RoleSession("anonymous", {}),
          RoleSession("alice", {"Authorization": "Bearer alice-token"})]


class _Target:
    """Loopback target that records each request it actually receives.

    GET /api/items/1 is an object route; POST /api/notes stores the body and
    GET /api/notes/view renders it as JSON (a second-order write -> read pair).
    `connections` counts accepted TCP connections, so a TLS rejection shows as a
    connection with no recorded request."""

    def __init__(self, *, tls_context: ssl.SSLContext | None = None, on_request=None):
        self.requests: list[tuple[str, str, dict, str]] = []
        self.connections = 0
        self.note = ""
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _record(self, body: str) -> None:
                with outer._lock:
                    outer.requests.append((self.command, self.path,
                                           {k.lower(): v for k, v in self.headers.items()}, body))
                if on_request is not None:
                    on_request(self.command, self.path, body)

            def _send(self, status: int, payload: str) -> None:
                data = payload.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._record("")
                if self.path.startswith("/api/notes/view"):
                    self._send(200, json.dumps({"notes": [outer.note]}))
                else:
                    self._send(200, json.dumps({"id": 1, "owner": "alice"}))

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                self._record(body)
                outer.note = body
                self._send(201, '{"ok": true}')

            def _other(self):
                # Every method is recorded: the count must match the run's budget.
                self._record(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
                self._send(200, "{}")

            do_OPTIONS = do_PUT = do_PATCH = do_DELETE = do_HEAD = _other

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                sock, addr = self.socket.accept()
                with outer._lock:
                    outer.connections += 1
                if tls_context is not None:
                    # Handshake here; a client that rejects the certificate raises
                    # an OSError that the server loop swallows -- no request recorded.
                    sock = tls_context.wrap_socket(sock, server_side=True)
                return sock, addr

        self._server = Server(("127.0.0.1", 0), Handler)
        scheme = "https" if tls_context is not None else "http"
        self.base = f"{scheme}://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def probe_requests(self):
        return [r for r in self.requests if _PROBE_HEADER in r[2]]

    def plants(self):
        return [r for r in self.requests if _is_plant(r[0], r[1], r[3])]

    def second_order_reads(self):
        # The second-order trigger read is sent AS the planter (alice).
        return [r for r in self.requests if r[0] == "GET" and r[1] == "/api/notes/view"
                and r[2].get("authorization") == "Bearer alice-token"]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _is_plant(method: str, path: str, body: str) -> bool:
    """The second-order plant writes its marker into every _MARK_FIELDS key."""
    return method == "POST" and path == "/api/notes" and '"title"' in body and '"subject"' in body


class _Model:
    """Scripted iterative-agent model; every other model consumer is silent."""

    def __init__(self, actions):
        self._actions = list(actions)
        self.probe_calls = 0

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        if '"action":"mutate"' in (system_prompt or ""):
            self.probe_calls += 1
            if self._actions:
                return self._actions.pop(0)
            return {"action": "stop", "verdict": "not_found", "thought": "done"}
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=await self.chat_json(model, system_prompt, user_prompt),
                            prompt_tokens=1, completion_tokens=1)


def _config(*, mutating: bool) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    v = cfg.setdefault("validators", {})
    v["active_enabled"] = True
    v["allow_mutating_replay"] = mutating
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg["engagement"]["feature_crawl"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


def _install_model(orch: Orchestrator, model: _Model) -> None:
    orch.ollama = model
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coordinator = getattr(orch, "coordinator", None)
    if coordinator is not None and hasattr(coordinator, "ollama"):
        coordinator.ollama = model


def _canned(endpoints, captured):
    """Stand-in for engagement_builder.build_engagement: no discovery traffic."""
    def build(base_url, roles, **kw):
        state = engagement.EngagementState(host="127.0.0.1")
        state.ingest_role_crawl({"endpoints": [dict(e) for e in endpoints], "idor_findings": []})
        for r in roles:
            state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
        rc = SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[],
                             captured=[c(base_url) for c in captured], errors=[],
                             sensitive_file_hits=[], endpoints=[])
        return state, rc
    return build


_OBJECT_NODE = {"method": "GET", "path": "/api/items/{id}", "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": True}


def _write(base):
    return HttpExchange(url=f"{base}/api/notes", method="POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body='{"note": "hello"}', response_status=201,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"ok": true}').model_dump()


def _read(base):
    return HttpExchange(url=f"{base}/api/notes/view", method="GET", response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"notes": []}').model_dump()


class _EngagementCallerBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i03_callers_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        stats = global_throttle.throttle.stats()
        self._throttle = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                          stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

    def tearDown(self):
        global_throttle.configure(*self._throttle)
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, target: _Target, *, max_requests, endpoints=(), captured=(), mutating=False,
             run_hosts=("127.0.0.1",), run_mutating=None, cancel_before=False, model=None,
             wrap_probe=None, extra_patches=(), browser=False, roles=None):
        """One investigate_engagement against `target`, entered as the server does.
        Real Chromium legs run only when `browser` is set (they dominate runtime).
        Returns (result, run_context, model)."""
        cfg = _config(mutating=mutating)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        model = model or _Model([{"action": "set_header", "name": _PROBE_HEADER,
                                  "value": "1", "thought": "probe"}])
        _install_model(orch, model)
        if wrap_probe is not None:
            orch.run_active_probe = wrap_probe(orch.run_active_probe)
        rc = RunContext.create(
            allowed_hosts=list(run_hosts), max_requests=max_requests, config=cfg,
            gate_config={"active_enabled": True,
                         "allow_mutating_replay": mutating if run_mutating is None else run_mutating})
        if cancel_before:
            rc.cancel.cancel()

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        target.base, roles or _ROLES, max_nodes=2, step_budget=2,
                        max_chain_rounds=0, run_context=rc)
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_canned(endpoints, captured)), *extra_patches]
        if not browser:
            patches.append(patch("harness.browser_driver.default_driver", return_value=None))
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return result, rc, model

    def _target(self, **kw) -> _Target:
        target = _Target(**kw)
        self.addCleanup(target.close)
        return target


class EngagementProbeCallerTests(_EngagementCallerBase):
    """ARCH-1 at the engagement caller: investigate_engagement -> worklist -> probe."""

    def test_allowed_probe_send_is_counted_by_the_owning_run(self):
        target = self._target()
        result, rc, model = self._run(target, max_requests=50, endpoints=[_OBJECT_NODE])
        self.assertGreaterEqual(model.probe_calls, 1, "the worklist never reached the probe")
        self.assertTrue(target.probe_requests(), "the probe's send never reached the target")
        # Independent count at the target boundary == the owning run's count: every
        # engagement-phase egress was admitted through this run's transport.
        self.assertEqual(len(target.requests), rc.budget.used, target.requests)

    def test_exhausted_run_budget_sends_nothing_from_any_engagement_leg(self):
        target = self._target()
        result, rc, model = self._run(target, max_requests=0, endpoints=[_OBJECT_NODE])
        self.assertGreaterEqual(model.probe_calls, 1, "the worklist never reached the probe")
        self.assertEqual(target.requests, [])
        self.assertEqual(rc.budget.used, 0)

    def test_cancelled_run_sends_nothing(self):
        target = self._target()
        result, rc, _ = self._run(target, max_requests=50, endpoints=[_OBJECT_NODE],
                                  cancel_before=True)
        self.assertEqual(target.requests, [])
        self.assertEqual(rc.budget.used, 0)

    def test_run_scope_not_orchestrator_scope_governs_engagement_sends(self):
        # The orchestrator allows 127.0.0.1; the run does not. The run must win.
        target = self._target()
        result, rc, model = self._run(target, max_requests=50, endpoints=[_OBJECT_NODE],
                                      run_hosts=("other.test",))
        self.assertGreaterEqual(model.probe_calls, 1, "the worklist never reached the probe")
        self.assertEqual(target.requests, [])
        self.assertEqual(rc.budget.used, 0)

    def test_defect_dropping_probe_context_forwarding_is_detected(self):
        """Fault injection: the engagement calls the probe without its run context
        (the pre-ARCH-1 behaviour). The probe then builds its own context and sends
        past the exhausted run budget -- the invariant above must catch that."""
        def drop_context(original):
            async def probe(exchange, hypothesis, specialty, *a, **kw):
                kw["run_context"] = None
                return await original(exchange, hypothesis, specialty, *a, **kw)
            return probe

        target = self._target()
        self._run(target, max_requests=0, endpoints=[_OBJECT_NODE], wrap_probe=drop_context)
        self.assertTrue(target.probe_requests(),
                        "dropping the run context no longer leaks -- the control is vacuous")


class EngagementSecondOrderCallerTests(_EngagementCallerBase):
    """ARCH-2 at the engagement caller: the real plant/read closures."""

    _PAIR = (_write, _read)

    def _case_ref(self, target):
        return f"second_order_sqli:{target.base}/api/notes=>{target.base}/api/notes/view"

    def test_plant_and_read_spend_the_owning_run_under_one_case_ref(self):
        target = self._target()
        # Generous budget: the shape-driven legs on the same captures run first.
        result, rc, _ = self._run(target, max_requests=500, captured=self._PAIR, mutating=True,
                                  browser=True)
        plants, reads = target.plants(), target.second_order_reads()
        # The gate allows this check two writes per case (TRUE and FALSE plant).
        self.assertEqual(len(plants), 2, [(r[0], r[1], r[3][:60]) for r in target.requests])
        self.assertEqual(len(reads), 2)   # one trigger-read after each plant
        self.assertTrue(all(r[2].get("authorization") == "Bearer alice-token" for r in plants))
        self.assertEqual(len(target.requests), rc.budget.used)
        events = evidence_ledger.get_default_ledger().events_for(self._case_ref(target))
        executed = [e.data.get("request", "") for e in events
                    if e.event_type == evidence_ledger.EventType.EXECUTION]
        self.assertEqual(sum(u.endswith("/api/notes") for u in executed), len(plants), executed)
        self.assertEqual(sum("/api/notes/view" in u for u in executed), len(reads), executed)

    def _run_interrupting_the_plant(self, interrupt):
        """Run the pair, calling interrupt(run) on the target thread as the first
        plant arrives -- before its response returns, so before any read."""
        holder = {}

        def on_request(method, path, body):
            if _is_plant(method, path, body) and "rc" in holder and "hit" not in holder:
                holder["hit"] = True
                interrupt(holder["rc"])

        target = self._target(on_request=on_request)
        real_create = RunContext.create

        def create(*a, **kw):
            holder["rc"] = real_create(*a, **kw)
            return holder["rc"]

        with patch.object(RunContext, "create", side_effect=create):
            result, rc, _ = self._run(target, max_requests=500, captured=self._PAIR, mutating=True,
                                      browser=True)
        plant_at = next((i for i, r in enumerate(target.requests) if _is_plant(r[0], r[1], r[3])), None)
        self.assertIsNotNone(plant_at, "the second-order plant never reached the target")
        return result, rc, target, target.requests[plant_at + 1:]

    def test_budget_exhausted_at_the_plant_sends_no_read_and_confirms_nothing(self):
        def exhaust(run):
            run.budget._max = run.budget.used   # nothing further may be admitted
        result, rc, target, after = self._run_interrupting_the_plant(exhaust)
        self.assertEqual(after, [], "a request was admitted after the run budget ran out")
        self.assertEqual(len(target.requests), rc.budget.used)
        self.assertFalse(_confirmed_second_order(result))

    def test_cancellation_between_plant_and_read_stops_the_read(self):
        result, rc, target, after = self._run_interrupting_the_plant(lambda run: run.cancel.cancel())
        self.assertEqual(after, [], "a request was sent after the run was cancelled")
        self.assertFalse(_confirmed_second_order(result))

    def test_run_gate_denying_mutation_blocks_every_write(self):
        # Mutation is allowed in the orchestrator config but denied by THIS run, so
        # no leg -- the second-order plant included -- may write to the target.
        target = self._target()
        result, rc, _ = self._run(target, max_requests=500, captured=self._PAIR, mutating=True,
                                  run_mutating=False)
        self.assertFalse([r for r in target.requests if r[0] not in ("GET", "HEAD", "OPTIONS")],
                         [(r[0], r[1]) for r in target.requests])
        self.assertEqual(len(target.requests), rc.budget.used)
        self.assertFalse(_confirmed_second_order(result))

    def test_plant_and_read_closures_forward_the_owning_run(self):
        """Negative control for ARCH-2 wiring: every second-order send must be
        handed THIS run. A closure that forwards None (or another context) fails."""
        import harness.second_order as so
        original = so.send_through_run
        seen = []

        async def recording(run_context, *a, **kw):
            seen.append((run_context, kw.get("capability")))
            return await original(run_context, *a, **kw)

        holder = {}
        real_create = RunContext.create

        def create(*a, **kw):
            holder["rc"] = real_create(*a, **kw)
            return holder["rc"]

        target = self._target()
        with patch.object(RunContext, "create", side_effect=create):
            self._run(target, max_requests=500, captured=self._PAIR, mutating=True,
                      extra_patches=[patch.object(so, "send_through_run", side_effect=recording)])
        capabilities = {cap for _, cap in seen}
        self.assertIn("second_order_plant", capabilities, "the plant closure never ran")
        self.assertIn("second_order_read", capabilities, "the read closure never ran")
        self.assertTrue(all(run is holder["rc"] for run, _ in seen),
                        "a second-order send was not given the owning run")


class ConcurrentAdmissionTests(_EngagementCallerBase):
    def test_concurrent_sends_on_the_closure_send_path_never_exceed_the_budget(self):
        import harness.second_order as so
        target = self._target()
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=3, config=_config(mutating=False),
                               gate_config={"active_enabled": True})

        async def go():
            try:
                return await asyncio.gather(*[
                    so.send_through_run(rc, "GET", f"{target.base}/api/notes/view?n={i}",
                                        allowed_hosts=["127.0.0.1"], config={},
                                        capability="second_order_read", case_ref=f"i03:{i}")
                    for i in range(8)])
            finally:
                await rc.aclose()

        outcomes = asyncio.run(go())
        self.assertEqual(sum(o.ok for o in outcomes), 3)
        self.assertEqual(sum(o.outcome == "budget_exhausted" for o in outcomes), 5)
        self.assertEqual(len(target.requests), 3)
        self.assertEqual(rc.budget.used, 3)


class BrowserCancelSignalTests(unittest.TestCase):
    def test_browser_route_guard_honours_the_run_cancel_token(self):
        # Validators and engagement capture pass run_context.CancelToken; the
        # browser guard used to read it as never cancelled.
        from harness.browser_driver import is_cancelled
        from harness.run_context import CancelToken
        token = CancelToken()
        self.assertFalse(is_cancelled(token))
        token.cancel()
        self.assertTrue(is_cancelled(token))


class TlsTrustAtEngagementCallersTests(_EngagementCallerBase):
    def test_untrusted_certificate_is_rejected_for_probe_and_second_order_sends(self):
        from harness.test_remediation_tls import _LEAF_CERT, _LEAF_KEY
        cert, key = Path(self._tmp) / "leaf.pem", Path(self._tmp) / "key.pem"
        cert.write_text(_LEAF_CERT, encoding="ascii")
        key.write_text(_LEAF_KEY, encoding="ascii")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert), str(key))
        target = self._target(tls_context=server_context)
        result, rc, model = self._run(target, max_requests=50, endpoints=[_OBJECT_NODE],
                                      captured=self._pair(), mutating=True, browser=True)
        self.assertGreaterEqual(model.probe_calls, 1, "the worklist never reached the probe")
        self.assertGreater(target.connections, 0, "nothing attempted a connection -- vacuous")
        self.assertEqual(target.requests, [], "a request was sent over an untrusted channel")
        self.assertFalse(_confirmed_second_order(result))

    @staticmethod
    def _pair():
        return (_write, _read)


def _confirmed_second_order(result: dict) -> list[dict]:
    return [f for ep in result.get("worklist", []) for f in ep.get("findings", []) or []
            if f.get("confirmed") and "second_order" in (f.get("vulnerability_class") or "").lower()]


if __name__ == "__main__":
    unittest.main()
