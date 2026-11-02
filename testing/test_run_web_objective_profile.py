"""LB-6 caller-level tests: the web-objective smoke runner's typed objective
profile reaches `objective_completion` through `RunContext` and the safety gate.

Each test runs `run_web_objective_smoke._run` against an owned in-process
loopback fixture (vulnerable or fixed), never a live lab. Discovery, the model
review passes and the worklist are stubbed so the run goes straight to the
objective-mode confirmation and completion stages; every request those stages
make is a real HTTP request to the fixture. SSTI confirmation is the real
`SstiValidator`; the IDOR cross-identity proof is stubbed because it needs a
second identity the fixture does not model, so the read-only objective's
completion still depends only on the fixture's own independent oracle.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import re
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

from harness import cache, engagement_builder, role_crawl, store, worklist_investigator
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.objective_completion import COMPLETED, NOT_ATTEMPTED, NOT_COMPLETED
from harness.objective_profiles import ObjectiveDeclaration
from harness.run_context import RunContext
from harness.validators.base import ValidationResult
from harness.validators.cross_identity_validator import CrossIdentityValidator
from testing import run_web_objective_smoke as smoke


ROOT = Path(__file__).resolve().parents[1]
MARKER = "ADMIN-PANEL-7f3a"
DISPOSABLE = "/srv/disposable.txt"
_ARITH = re.compile(r"<%=\s*(\d+)\*(\d+)\s*%>")
_DELETE = re.compile(r"<%=\s*File\.delete\('([^']+)'\)\s*rescue\s*nil;\s*'deleted'\s*%>")


class _Fixture:
    """A loopback app in one of three modes:
    - "vulnerable": ERB evaluates arithmetic and File.delete; /admin/secret is
      readable without authorization.
    - "arithmetic": ERB evaluates arithmetic only (File.delete is not available),
      /admin/secret is forbidden.
    - "fixed": nothing is evaluated and /admin/secret is forbidden."""

    def __init__(self, mode: str):
        self.mode = mode
        self.files = {DISPOSABLE}
        self.requests: list[str] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fixture.requests.append(self.path)
                status, body = fixture.respond(self.path)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def respond(self, raw_path: str) -> tuple[int, str]:
        parts = urlsplit(raw_path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/render":
            message = query.get("message", "")
            if self.mode == "vulnerable":
                def _delete(m):
                    self.files.discard(m.group(1))
                    return "deleted"
                message = _DELETE.sub(_delete, message)
            if self.mode in ("vulnerable", "arithmetic"):
                message = _ARITH.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), message)
            else:
                message = message.replace("<", "&lt;").replace(">", "&gt;")
            return 200, f"<html>{message}</html>"
        if parts.path == "/status":
            return 200, "present" if query.get("file") in self.files else "absent"
        if parts.path == "/account":
            return 200, f"<html>account {query.get('id', '')}</html>"
        if parts.path == "/admin/secret":
            if self.mode == "vulnerable":
                return 200, f"<html>{MARKER}</html>"
            return 403, "<html>Forbidden</html>"
        return 404, "not found"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def _ssti_profile(base: str) -> dict:
    return {"profile": "ssti_file_delete", "action_class": "file_delete",
            "mutation_level": "destructive", "oracle": "file_absent",
            "required_end_state": {"target_path": DISPOSABLE,
                                   "oracle_url": f"{base}status?file={DISPOSABLE}"},
            "ceilings": {"max_completion_requests": 2}}


def _admin_profile(base: str) -> dict:
    return {"profile": "access_admin_read", "action_class": "http_get",
            "mutation_level": "read_only", "oracle": "content_present",
            "required_end_state": {"target_path": f"{base}admin/secret",
                                   "oracle_url": f"{base}admin/secret",
                                   "oracle_marker": MARKER},
            "ceilings": {"max_completion_requests": 2}}


class RunnerObjectiveProfileTest(unittest.TestCase):
    def setUp(self):
        work = ROOT / ".test-work"
        work.mkdir(exist_ok=True)
        self.out = Path(tempfile.mkdtemp(prefix="lb6-runner-", dir=work))
        self._db_path = store._DB_PATH
        self._cache = cache._cache

    def tearDown(self):
        store._DB_PATH = self._db_path
        cache._cache = self._cache
        shutil.rmtree(self.out, ignore_errors=True)

    def _args(self, base: str, *, profile: dict | None, objective_class=None,
              allow_destructive=False) -> argparse.Namespace:
        return argparse.Namespace(
            target=base, case_id="lb6-fixture", output=str(self.out), run_id="lb6-test",
            max_nodes=1, step_budget=1, discovery_max_probes=1, discovery_max_endpoints=1,
            discovery_max_pages=1, active_discovery=False, feature_crawl=False,
            max_requests=60, request_timeout=5.0, wall_timeout=60.0,
            objective_class=objective_class,
            objective_profile=json.dumps(profile) if profile else None,
            allow_destructive_objective=allow_destructive, auth=None, login_path="/login",
            idor_candidates=None, race_target_email=None, race_mailbox_url=None)

    def _run(self, fixture: _Fixture, captured_path: str, args: argparse.Namespace,
             *, idor_confirms: bool = False) -> dict:
        path, _, _ = captured_path.partition("?")
        exchange = HttpExchange(method="GET", url=f"{fixture.base}{captured_path.lstrip('/')}",
                                request_headers={}, response_status=200,
                                response_headers={"Content-Type": "text/html"},
                                response_body="hello")

        async def _build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state._ep("GET", path)
            rc = role_crawl.RoleCrawlResult(base_url=base_url)
            rc.captured.append(exchange)
            return state, rc

        xid = ValidationResult(validator="cross_identity", status="confirmed",
                               finding_class="idor", confidence=0.9, confirmed=True,
                               summary="second identity read the object")
        with patch.object(engagement_builder, "build_engagement", new=_build), \
             patch.object(worklist_investigator, "investigate_worklist",
                          new=AsyncMock(return_value=[])), \
             patch("harness.orchestrator_chain.review_captured_exchanges",
                   new=AsyncMock(return_value=0)), \
             patch("harness.orchestrator_chain.universal_header_audit",
                   new=AsyncMock(return_value=0)), \
             patch.object(CrossIdentityValidator, "validate",
                          new=AsyncMock(return_value=xid if idor_confirms else
                                        ValidationResult(validator="cross_identity",
                                                         status="not_confirmed",
                                                         finding_class="idor"))), \
             contextlib.redirect_stdout(io.StringIO()):
            code = asyncio.run(smoke._run(args))
        self.assertEqual(code, 0)
        return json.loads((self.out / "attempt.json").read_text(encoding="utf-8"))

    # --- default: nothing declared ---------------------------------------
    def test_no_profile_defaults_to_not_attempted(self):
        with _Fixture("vulnerable") as fx:
            art = self._run(fx, "/render?message=hello",
                            self._args(fx.base, profile=None, objective_class="ssti"))
        self.assertEqual(art["objective"]["status"], NOT_ATTEMPTED)
        self.assertIsNone(art["objective"]["declared"])
        self.assertIn(DISPOSABLE, fx.files)
        self.assertFalse(any("File.delete" in r for r in fx.requests))

    # --- non-destructive objective: vulnerable completes, fixed does not ---
    def test_read_only_objective_completes_on_vulnerable_fixture(self):
        with _Fixture("vulnerable") as fx:
            art = self._run(fx, "/account?id=wiener",
                            self._args(fx.base, profile=_admin_profile(fx.base)),
                            idor_confirms=True)
        self.assertEqual(art["objective"]["status"], COMPLETED, art["objective"])
        self.assertEqual(art["objective"]["declared"]["mutation_level"], "read_only")
        self.assertEqual(art["objective"]["requests_used"], 2)
        self.assertGreaterEqual(fx.requests.count("/admin/secret"), 2)

    def test_read_only_objective_does_not_complete_on_fixed_control(self):
        with _Fixture("fixed") as fx:
            art = self._run(fx, "/account?id=wiener",
                            self._args(fx.base, profile=_admin_profile(fx.base)),
                            idor_confirms=True)
        self.assertEqual(art["objective"]["status"], NOT_COMPLETED, art["objective"])

    # --- destructive objective -------------------------------------------
    def test_destructive_objective_without_opt_in_is_not_attempted(self):
        with _Fixture("vulnerable") as fx:
            art = self._run(fx, "/render?message=hello",
                            self._args(fx.base, profile=_ssti_profile(fx.base)))
        # The SSTI itself is confirmed by the real validator ...
        self.assertTrue(any(f.get("confirmed") for f in art["findings"]), art["findings"])
        # ... but the destructive objective is never attempted or sent.
        self.assertEqual(art["objective"]["status"], NOT_ATTEMPTED, art["objective"])
        self.assertFalse(art["objective"]["destructive_opt_in"])
        self.assertIn("opt-in", art["objective"]["summary"])
        self.assertIn(DISPOSABLE, fx.files)
        self.assertFalse(any("File.delete" in r for r in fx.requests))

    def test_destructive_objective_with_opt_in_completes_on_vulnerable_fixture(self):
        with _Fixture("vulnerable") as fx:
            art = self._run(fx, "/render?message=hello",
                            self._args(fx.base, profile=_ssti_profile(fx.base),
                                       allow_destructive=True))
        self.assertEqual(art["objective"]["status"], COMPLETED, art["objective"])
        self.assertNotIn(DISPOSABLE, fx.files)

    def test_arithmetic_only_ssti_stays_confirmed_and_not_completed(self):
        with _Fixture("arithmetic") as fx:
            art = self._run(fx, "/render?message=hello",
                            self._args(fx.base, profile=_ssti_profile(fx.base),
                                       allow_destructive=True))
        self.assertTrue(any(f.get("confirmed") for f in art["findings"]), art["findings"])
        self.assertEqual(art["objective"]["status"], NOT_COMPLETED, art["objective"])
        self.assertIn(DISPOSABLE, fx.files)

    def test_fixed_ssti_control_is_not_confirmed_or_attempted(self):
        with _Fixture("fixed") as fx:
            art = self._run(fx, "/render?message=hello",
                            self._args(fx.base, profile=_ssti_profile(fx.base),
                                       allow_destructive=True))
        self.assertFalse(any(f.get("confirmed") for f in art["findings"]))
        self.assertEqual(art["objective"]["status"], NOT_ATTEMPTED)
        self.assertIn(DISPOSABLE, fx.files)

    # --- negative control: the result depends on the RunContext route -----
    def test_completion_depends_on_the_run_context_route(self):
        """Defect-injection control: drop the declared task on its way into the
        RunContext and the vulnerable fixture no longer completes."""
        real_create = RunContext.create.__func__

        def _dropping_create(cls, **kwargs):
            kwargs.pop("objective_task", None)
            return real_create(cls, **kwargs)

        with _Fixture("vulnerable") as fx, \
             patch.object(RunContext, "create", new=classmethod(_dropping_create)):
            art = self._run(fx, "/account?id=wiener",
                            self._args(fx.base, profile=_admin_profile(fx.base)),
                            idor_confirms=True)
        self.assertEqual(art["objective"]["status"], NOT_ATTEMPTED)
        self.assertNotIn("/admin/secret", fx.requests)


class ObjectiveDeclarationTest(unittest.TestCase):
    def test_declaration_cannot_widen_its_profile(self):
        base = "http://127.0.0.1:1/"
        for key, value in (("action_class", "file_delete"), ("mutation_level", "read_only"),
                           ("oracle", "")):
            bad = dict(_ssti_profile(base) if key != "action_class" else _admin_profile(base))
            bad[key] = value
            with self.assertRaises(ValueError, msg=key):
                ObjectiveDeclaration.from_mapping(bad)
        over = _admin_profile(base)
        over["ceilings"] = {"max_completion_requests": 50}
        with self.assertRaises(ValueError):
            ObjectiveDeclaration.from_mapping(over)

    def test_opt_in_only_applies_to_destructive_profiles(self):
        base = "http://127.0.0.1:1/"
        ssti = ObjectiveDeclaration.from_mapping(_ssti_profile(base))
        self.assertFalse(ssti.to_task().destructive_opt_in)
        self.assertTrue(ssti.to_task(allow_destructive=True).destructive_opt_in)
        admin = ObjectiveDeclaration.from_mapping(_admin_profile(base))
        self.assertFalse(admin.to_task(allow_destructive=True).destructive_opt_in)

    def test_runner_rejects_unknown_or_mismatched_profiles(self):
        decl = smoke._objective_declaration(json.dumps(_admin_profile("http://x/")))
        self.assertEqual(decl.profile.vulnerability_class, "idor")
        with self.assertRaises(SystemExit):
            smoke._objective_declaration('{"profile": "nope"}')
        args = argparse.Namespace(target="http://127.0.0.1:1/", output="unused",
                                  run_id="x", objective_class="sqli",
                                  objective_profile=json.dumps(_admin_profile("http://x/")),
                                  allow_destructive_objective=False)
        with self.assertRaises(SystemExit):
            asyncio.run(smoke._run(args))


if __name__ == "__main__":
    unittest.main()
