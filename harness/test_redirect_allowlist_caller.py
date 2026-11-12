"""Open redirect behind a host allowlist, through investigate_engagement's coverage
case drive (the production caller of the open-redirect leg).

An allowlisted redirect endpoint answers every off-origin sentinel shape with a
refusal and redirects only to the targets it allows. The leg now learns an allowed
external target the run saw the endpoint redirect to (here: one of the run's own
GETs, whose off-scope follow the transport refuses) and adds the textbook
allowlist-bypass shapes: the allowed URL in the query, fragment or path of the
sentinel URL, and the allowed host as its userinfo. The loopback target is generic:
a GET endpoint whose `to` parameter is checked against one allowed URL.

- substring allowlist (the allowed URL anywhere in the value): a bypass shape is
  accepted and the leg confirms on the Location's parsed host, the sentinel.
- control, parsed-host allowlist (the value's parsed host must be allowed): the
  same bypass shapes are sent and refused; the case concludes clean.
- control, nothing observed: no bypass shape is sent (today's four shapes only),
  so a substring allowlist stays undetected; learning is what adds them.
- every request the target saw is a GET.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

from harness import cache, engagement, store
from harness.coverage_model import CellStatus, CoverageMatrix
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.test_param_dispatch_caller import REDIRECT, ROLES, _config

_ALLOWED = "https://partner.example/landing"
_SENTINEL = "oob-openredirect.example"


class _AllowlistHandler(BaseHTTPRequestHandler):
    """GET /goto?to=<url>: 302 to <url> when the allowlist accepts it, else 406.
    server.mode "substring" accepts a value that contains an allowed URL;
    "parsed" accepts only a value whose parsed host is an allowed URL's host."""

    def do_GET(self):
        self.server.seen.append(("GET", self.path))
        parts = urlsplit(self.path)
        if parts.path != "/goto":
            return self._reply(200, b"<html>ok</html>")
        target = dict(parse_qsl(parts.query, keep_blank_values=True)).get("to", "")
        if self.server.mode == "substring":
            ok = _ALLOWED in target
        else:
            try:
                dest = urlsplit(target)
                ok = dest.scheme in ("http", "https") and dest.hostname == urlsplit(_ALLOWED).hostname
            except ValueError:
                ok = False
        if not ok:
            return self._reply(406, b"Unrecognized target URL for redirect")
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.server.seen.append(("POST", self.path))
        self._reply(405, b"")

    do_PUT = do_PATCH = do_DELETE = do_POST

    def _reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RedirectAllowlistCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="redirect_allowlist_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))

        def restore():
            store._DB_PATH, cache._cache = orig_db, orig_cache
            shutil.rmtree(self._tmp, ignore_errors=True)
        self.addCleanup(restore)

    def _server(self, mode):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _AllowlistHandler)
        server.mode, server.seen = mode, []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def _run(self, mode, *, observed=True):
        server, base = self._server(mode)

        def canned(base_url, roles, **kw):
            state = engagement.EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": "/goto", "by_role": {"anonymous": 406},
                "reachable_roles": ["anonymous"], "object_scoped": False}], "idor_findings": []})
            # The template a crawler kept: an on-origin value, no redirect seen.
            state.record_template(f"{base}/goto?to=/home", "GET", HttpExchange(
                method="GET", url=f"{base}/goto?to=/home", request_headers={},
                response_status=406, response_headers={"Content-Type": "text/html"},
                response_body="Unrecognized target URL for redirect"))
            for r in roles:
                state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
            return state, SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[],
                                          idor_findings=[])

        cfg = _config()
        cfg["validators"]["allow_mutating_replay"] = False
        cfg["validators"].setdefault("ssti", {})["enabled"] = False
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.coverage_case_budget = 8
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})

        async def investigate():
            from harness.orchestrator_helpers import per_run_gate_config
            from harness.run_context import RunContext, TypedRequest
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"], config=cfg,
                    gate_config=per_run_gate_config(cfg, orch.validator_registry)) as ctx:
                if observed:
                    # One of the run's own GETs (a crawl follow): the endpoint 302s to
                    # the allowed external target, whose follow is out of scope.
                    outcome = await ctx.executor().execute(
                        TypedRequest("GET", f"{base}/goto?to={_ALLOWED}"), capability="crawl")
                    self.assertNotEqual(outcome.outcome, "ok", "the off-scope follow was sent")
                self.observations = ctx.observations.redirect_targets(f"{base}/goto", "to")
                return await orch.investigate_engagement(
                    base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0, run_context=ctx)

        with patch("harness.engagement_builder.build_engagement", side_effect=canned), \
                patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]):
            result = asyncio.run(investigate())
        coverage = result.get("coverage") or {}
        self.assertIn("cases_driven", coverage, "the case-driven coverage path did not run")
        matrix = CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"])
        cases = {ck.parameter_name: r for ck, r in
                 matrix.cases_for_cell("anonymous", "GET /goto", REDIRECT)}
        return cases, server.seen

    @staticmethod
    def _bypass_sends(seen):
        # A bypass shape carries the allowed URL (or host) beside the sentinel.
        return [p for _m, p in seen if _SENTINEL in p and "partner.example" in p]

    def test_substring_allowlist_is_confirmed_through_a_bypass_shape(self):
        cases, seen = self._run("substring")
        self.assertEqual(self.observations, [_ALLOWED])
        self.assertEqual(cases["to"].status, CellStatus.CONFIRMED, cases["to"].reason)
        self.assertTrue(cases["to"].executed)
        self.assertTrue(self._bypass_sends(seen))
        self.assertEqual({m for m, _p in seen}, {"GET"})

    def test_control_parsed_host_allowlist_refuses_every_bypass_shape(self):
        cases, seen = self._run("parsed")
        self.assertEqual(self.observations, [_ALLOWED])
        # The shapes were sent, so the clean verdict rests on them.
        self.assertGreaterEqual(len(self._bypass_sends(seen)), 4)
        self.assertEqual(cases["to"].status, CellStatus.NOT_DETECTED, cases["to"].reason)
        self.assertEqual({m for m, _p in seen}, {"GET"})

    def test_control_nothing_observed_sends_no_bypass_shape(self):
        cases, seen = self._run("substring", observed=False)
        self.assertEqual(self.observations, [])
        self.assertEqual(self._bypass_sends(seen), [])
        self.assertNotEqual(cases["to"].status, CellStatus.CONFIRMED, cases["to"].reason)


if __name__ == "__main__":
    unittest.main()
