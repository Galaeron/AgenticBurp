"""I05 batch A: target sends that belong to a run must not escape it.

I03 proved the engagement's own legs spend the owning run. Two opt-in production
paths still sent outside their run, through validators or helpers that fall back
to a private client or a throwaway context when no run is handed to them:

  - engagement.coverage_drive_legs: the coverage drive dispatched the registry's
    shared sqlmap validator, never bound to the engagement run, so its boolean
    preflight bypassed the run's budget, cancellation, scope and TLS policy;
  - engagement.auto_escalate inside analyze(): the learned-credential probe and the
    re-crawl as that identity ran outside analyze's request ceiling.

Both are driven here through their real callers against an owned loopback target
that counts what it actually receives. The class-level guards are tested at their
seams: an unbound validator, or transport_for(None), inside an entered run uses
that run. Disabling each guard must be detected.

Caller verification only: no live target, no tool or container launch (the
sqlmap binary is deliberately absent), no recall or accuracy measurement.
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
from urllib.parse import unquote_plus

from harness import cache, evidence_ledger, global_throttle, safety_gate, store
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext, current_run_context, transport_for
from harness.validators.base import ValidationResult
from harness.test_engagement_transport_callers import (
    _ROLES, _Model, _Target, _canned, _config, _install_model)

# Reachable by both identities: anonymous's sqli cell is served from the worklist's
# confirmation cache, so alice's cell is the one the coverage drive actually dispatches.
_ITEM_NODE = {"method": "GET", "path": "/api/items/{id}",
              "by_role": {"anonymous": 200, "alice": 200},
              "reachable_roles": ["anonymous", "alice"], "object_scoped": True}


def _captured_search(base):
    """A captured request whose query becomes the node's replay template."""
    return HttpExchange(url=f"{base}/api/items/7?q=shoes", method="GET", response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"id": 7, "owner": "alice"}').model_dump()
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJpMDUtZXNjYWxhdGUifQ.i05signaturevalue"


async def _skip_timing_leg(self, finding, exchange):
    """The command-injection leg waits on real time-delay probes (~140 s here) and
    is not under test; I03 covers the engagement legs' accounting in general."""
    return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                            summary="stubbed in the I05 caller test")


def _is_sqli_preflight(request) -> bool:
    return "' OR '1'='" in unquote_plus(request[1])


class _IsolatedStateBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i05a_escape_")
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


# --- A1: coverage-drive sqlmap leg -------------------------------------------------
class CoverageDriveSqlmapLegTests(_IsolatedStateBase, unittest.TestCase):
    """investigate_engagement -> coverage drive -> registry sqlmap -> preflight."""

    def _run(self, *, max_requests, cancel_before=False, run_hosts=("127.0.0.1",),
             extra_patches=()):
        target = _Target()
        self.addCleanup(target.close)
        cfg = _config(mutating=False)
        cfg["engagement"]["coverage_drive_legs"] = True
        cfg["engagement"]["coverage_leg_budget"] = 40
        sql = cfg["validators"].setdefault("sqlmap", {})
        sql.update({"enabled": True, "binary": "i05-no-such-sqlmap-binary"})
        sql.pop("container_image", None)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _Model([]))
        rc = RunContext.create(allowed_hosts=list(run_hosts), max_requests=max_requests,
                               config=cfg, gate_config={"active_enabled": True,
                                                        "allow_mutating_replay": False})
        if cancel_before:
            rc.cancel.cancel()

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        target.base, _ROLES, max_nodes=2, step_budget=2,
                        max_chain_rounds=0, run_context=rc)
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_canned([_ITEM_NODE], [_captured_search])),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   patch("harness.validators.command_injection_validator."
                         "CommandInjectionValidator.validate", _skip_timing_leg),
                   *extra_patches]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return target, rc, result

    def test_allowed_preflight_is_counted_by_the_owning_run(self):
        target, rc, result = self._run(max_requests=200)
        self.assertTrue([r for r in target.requests if _is_sqli_preflight(r)],
                        "the coverage drive never reached the sqlmap preflight")
        self.assertEqual(len(target.requests), rc.budget.used, target.requests)

    def test_exhausted_budget_sends_nothing(self):
        target, rc, _ = self._run(max_requests=0)
        self.assertEqual(target.requests, [])
        self.assertEqual(rc.budget.used, 0)

    def test_cancelled_run_sends_nothing(self):
        target, rc, _ = self._run(max_requests=200, cancel_before=True)
        self.assertEqual(target.requests, [])

    def test_run_scope_governs_the_preflight(self):
        target, rc, _ = self._run(max_requests=200, run_hosts=("other.test",))
        self.assertEqual(target.requests, [])

    def test_disabling_the_validator_run_fallback_is_detected(self):
        """Fault injection: without the Validator base's enclosing-run fallback the
        unbound registry sqlmap sends past the exhausted budget again."""
        target, _, _ = self._run(max_requests=0, extra_patches=[
            patch("harness.validators.base._enclosing_run", return_value=None)])
        self.assertTrue([r for r in target.requests if _is_sqli_preflight(r)],
                        "removing the fallback no longer leaks -- the control is vacuous")


# --- A2: auto-escalation inside analyze() ------------------------------------------
class _AuthTarget:
    """Owned loopback target: 200 + a private body for the learned bearer, 401
    otherwise; records every request it receives."""

    def __init__(self):
        self.requests: list[tuple[str, str, dict]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer.requests.append((self.command, self.path,
                                           {k.lower(): v for k, v in self.headers.items()}))
                if self.headers.get("Authorization") == f"Bearer {_JWT}":
                    status, payload = 200, '{"account": "private", "links": ["/api/me"]}'
                else:
                    status, payload = 401, '{"error": "unauthorized"}'
                data = payload.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        self._server = Server(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _EscalationModel:
    """Reports one auth finding for the login exchange; silent otherwise."""

    def __init__(self, url):
        self._url = url

    def _reply(self, user_prompt):
        if f"\nURL: {self._url}\n" not in user_prompt:
            return {"findings": [], "components": []}
        return {"findings": [{"vulnerability_class": "auth", "severity": "high",
                              "confidence": 0.8, "summary": "login returns a bearer token",
                              "evidence": "token in body", "suggested_test": "replay it",
                              "basis": "observed"}], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        from harness.ollama_client import OllamaResult
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)


class AnalyzeAutoEscalationTests(_IsolatedStateBase, unittest.TestCase):
    """Orchestrator.analyze -> _auto_escalate -> credential probe + re-crawl."""

    def _analyze(self, *, ceiling=1000, run=None, extra_patches=()):
        target = _AuthTarget()
        self.addCleanup(target.close)
        url = f"{target.base}/api/login"
        cfg = _config(mutating=False)
        cfg["validators"]["active_enabled"] = False      # passive: only escalation may send
        cfg["iterative_agent"]["enabled"] = False
        cfg["engagement"]["auto_escalate"] = True
        cfg.setdefault("analyze", {})["max_requests"] = ceiling
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _EscalationModel(url))
        exchange = HttpExchange(url=url, method="POST",
                                request_headers={"Content-Type": "application/json"},
                                request_body='{"user": "i05", "password": "fixture"}',
                                response_status=200,
                                response_headers={"Content-Type": "application/json"},
                                response_body=json.dumps({"token": _JWT}))
        for p in extra_patches:
            p.start()
        try:
            asyncio.run(orch.analyze(exchange, force_agents=["auth"], run_context=run))
        finally:
            for p in reversed(extra_patches):
                p.stop()
        return target

    def test_escalation_is_counted_by_the_analysis_run(self):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                gate_config={"active_enabled": True})
        target = self._analyze(run=run)
        bearer = [r for r in target.requests if r[2].get("authorization") == f"Bearer {_JWT}"]
        self.assertTrue(bearer, "auto-escalation never probed the learned credential")
        self.assertEqual(len(target.requests), run.budget.used, target.requests)
        self.assertEqual([s.session_id for s in run.sessions.all()
                          if s.session_id.startswith("auto-escalate:")], [],
                         "the learned identity outlived its re-crawl inside the run")
        asyncio.run(run.aclose())

    def test_standalone_analyze_ceiling_bounds_the_escalation(self):
        target = self._analyze(ceiling=0)
        self.assertEqual(target.requests, [])

    def test_cancelled_analysis_run_sends_no_escalation(self):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                gate_config={"active_enabled": True})
        run.cancel.cancel()
        target = self._analyze(run=run)
        self.assertEqual(target.requests, [])
        asyncio.run(run.aclose())

    def test_dropping_the_run_from_the_escalation_is_detected(self):
        """Fault injection: the escalation is called without analyze's run. Uses a
        borrowed run that is not entered, where the explicit run argument is the only
        thing binding the escalation (a standalone analyze also enters its own run,
        which the enclosing-run fallback would catch)."""
        original = Orchestrator._auto_escalate

        async def unbound(self, host, source_url, credential_caps, st, run_context=None):
            return await original(self, host, source_url, credential_caps, st, run_context=None)

        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=0,
                                gate_config={"active_enabled": True})
        target = self._analyze(run=run, extra_patches=[
            patch.object(Orchestrator, "_auto_escalate", unbound)])
        asyncio.run(run.aclose())
        self.assertTrue(target.requests,
                        "dropping the run no longer leaks -- the control is vacuous")


# --- A4: a validator probe with no run path at all ---------------------------------
class _ApiModel:
    """Reports one api_security finding for the listing exchange; silent otherwise."""

    def __init__(self, url):
        self._url = url

    def _reply(self, user_prompt):
        if f"\nURL: {self._url}\n" not in user_prompt:
            return {"findings": [], "components": []}
        return {"findings": [{"vulnerability_class": "api_security", "severity": "medium",
                              "confidence": 0.6, "summary": "listing honours any page size",
                              "evidence": "limit parameter", "suggested_test": "raise limit",
                              "basis": "derived"}], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        from harness.ollama_client import OllamaResult
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)


class ApiSecurityLimitProbeTests(_IsolatedStateBase, unittest.TestCase):
    """analyze() inside an entered run (as the engagement reviews captured exchanges)
    -> api_security validator -> unbounded-limit probe."""

    def _analyze(self, *, max_requests, cancel_before=False):
        target = _Target()
        self.addCleanup(target.close)
        url = f"{target.base}/api/items?limit=10"
        cfg = _config(mutating=False)
        cfg["iterative_agent"]["enabled"] = False
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _ApiModel(url))
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests, config=cfg,
                               gate_config={"active_enabled": True})
        if cancel_before:
            rc.cancel.cancel()
        exchange = HttpExchange(url=url, method="GET", response_status=200,
                                response_headers={"Content-Type": "application/json"},
                                response_body='{"items": [1, 2, 3]}')

        async def go():
            try:
                async with rc:
                    await orch.analyze(exchange, force_agents=["api_security"], run_context=rc)
            finally:
                await rc.aclose()

        with patch("harness.browser_driver.default_driver", return_value=None),                 patch("harness.validators.command_injection_validator."
                      "CommandInjectionValidator.validate", _skip_timing_leg):
            asyncio.run(go())
        return target, rc

    @staticmethod
    def _limit_probes(target):
        return [r for r in target.requests if "limit=999999" in r[1]]

    def test_limit_probe_is_counted_by_the_run(self):
        target, rc = self._analyze(max_requests=200)
        self.assertTrue(self._limit_probes(target), "the api_security limit probe never ran")
        self.assertEqual(len(target.requests), rc.budget.used, target.requests)

    def test_exhausted_budget_sends_no_limit_probe(self):
        target, rc = self._analyze(max_requests=0)
        self.assertEqual(target.requests, [])

    def test_cancelled_run_sends_no_limit_probe(self):
        target, rc = self._analyze(max_requests=200, cancel_before=True)
        self.assertEqual(target.requests, [])


# --- A3: the class-level guards at their seams --------------------------------------
class EnclosingRunSeamTests(unittest.TestCase):
    def _registry_validators(self):
        cfg = _config(mutating=False)
        orch = Orchestrator(cfg)
        return list(orch.validator_registry.validators.values())

    def test_unbound_validators_resolve_to_the_enclosing_run(self):
        validators = self._registry_validators()
        self.assertGreater(len(validators), 10)
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1)
        other = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1)

        async def go():
            outside = {v.name: v.run_context for v in validators}
            async with rc:
                inside = {v.name: v.run_context for v in validators}
                bound = validators[0]
                bound.run_context = other
                explicit = bound.run_context
                bound.run_context = None
            await other.aclose()
            return outside, inside, explicit

        outside, inside, explicit = asyncio.run(go())
        self.assertEqual({k for k, v in outside.items() if v is not None}, set())
        self.assertEqual({k for k, v in inside.items() if v is not rc}, set())
        self.assertIs(explicit, other, "an explicitly bound run must win")

    def test_transport_for_without_a_run_uses_the_enclosing_run(self):
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=1)

        async def go():
            async with rc:
                inside = transport_for(None, allowed_hosts=["127.0.0.1"])
                self.assertIs(current_run_context(), rc)
            outside = transport_for(None, allowed_hosts=["127.0.0.1"])
            await outside[1].aclose()
            return inside, outside

        (tt_in, owned_in), (tt_out, owned_out) = asyncio.run(go())
        self.assertIsNone(owned_in, "inside a run nothing may build a throwaway context")
        self.assertIs(tt_in.ctx, rc)
        self.assertIsNotNone(owned_out, "outside any run the standalone context remains")


if __name__ == "__main__":
    unittest.main()
