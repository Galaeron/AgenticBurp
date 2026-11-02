"""Per-parameter dispatch, through investigate_engagement's real coverage case drive.

A leg that can test one input (SSTI here) is driven once per parameter case, so
each parameter gets its own verdict: the evaluating parameter is confirmed and
the literal one beside it concludes clean. Controls: a case-budget-truncated
parameter stays open (never a clean negative), and a request-level-only leg
(open redirect) is still driven once with its parameter cases left inconclusive.

Only discovery is canned (one endpoint with a captured form template), the agent
probe is stubbed, and the worklist's shape-driven legs are switched off (they
would confirm the endpoint before the coverage drive reaches it); the legs send
real requests to a loopback server.
"""
import asyncio
import os
import re
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

import yaml

from harness import cache, engagement, store
from harness.coverage_model import CellStatus, CoverageMatrix
from harness.models import HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession

_HARNESS = Path(__file__).resolve().parent
_JINJA_MUL = re.compile(r"\{\{(\d+)\*(\d+)\}\}")
SSTI, REDIRECT = "WSTG-INPV-18", "WSTG-INPV-17"
ROLES = [RoleSession("anonymous", {})]
# Every coverage leg but the two this file is about stays off, so the loopback
# server only sees SSTI and open-redirect traffic.
_OTHER_LEGS = ("sqlmap", "browser_xss", "stored_xss", "dom_xss", "command_injection", "xxe",
               "ssrf", "nosql", "jwt_forge", "deserialization_oob", "path_traversal",
               "sequence", "auth_sequence", "verb_tamper", "csrf", "file_upload", "rate_limit",
               "reset_token", "toctou", "race_condition", "csp", "cors", "header_injection",
               "http_request_smuggling")


class _Handler(BaseHTTPRequestHandler):
    """POST /render evaluates `{{a*b}}` in `tpl` only; every other value (and every
    value on /echo) is reflected literally."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        params = parse_qsl(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        path = urlsplit(self.path).path
        out = []
        for name, value in params:
            if path == "/render" and name == "tpl":
                value = _JINJA_MUL.sub(lambda m: str(int(m[1]) * int(m[2])), value)
            out.append(f"{name}={value}")
        self._reply(("<html>" + " ".join(out) + "</html>").encode())

    def do_GET(self):
        self._reply(b"<html>ok</html>")

    def _reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = True
    validators["allow_mutating_replay"] = True   # the fixture's form endpoint is a POST
    for name in _OTHER_LEGS:
        validators.setdefault(name, {})["enabled"] = False
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


class PerParameterDispatchCallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="param_dispatch_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, path, body, case_budget=8):
        base = self.base

        def canned(base_url, roles, **kw):
            state = engagement.EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "POST", "path": path, "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False}], "idor_findings": []})
            state.record_template(f"{base}{path}", "POST", HttpExchange(
                method="POST", url=f"{base}{path}",
                request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                request_body=body, response_status=200, response_headers={},
                response_body="<html></html>"))
            for r in roles:
                state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
            return state, SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[],
                                          idor_findings=[])

        orch = Orchestrator(_config())
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.coverage_case_budget = case_budget
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        with patch("harness.engagement_builder.build_engagement", side_effect=canned),                 patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]):
            result = asyncio.run(orch.investigate_engagement(
                base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0))
        coverage = result.get("coverage") or {}
        self.assertIn("cases_driven", coverage, "the case-driven coverage path did not run")
        matrix = CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"])
        key = lambda check: ("anonymous", f"POST {path}", check)  # noqa: E731
        cases = lambda check: {ck.parameter_name: r for ck, r in  # noqa: E731
                               matrix.cases_for_cell(*key(check))}
        return matrix, key, cases

    def test_vulnerable_parameter_confirmed_beside_clean_one(self):
        matrix, key, cases = self._run("/render", "tpl=hello&name=bob")
        ssti = cases(SSTI)
        self.assertEqual(ssti["tpl"].status, CellStatus.CONFIRMED, ssti["tpl"].reason)
        self.assertTrue(ssti["tpl"].executed)
        # The literal parameter beside it is concluded clean on its own send.
        self.assertEqual(ssti["name"].status, CellStatus.NOT_DETECTED, ssti["name"].reason)
        self.assertTrue(ssti["name"].executed)
        self.assertEqual(matrix.get(*key(SSTI)).status, CellStatus.CONFIRMED)

    def test_clean_endpoint_concludes_every_parameter(self):
        matrix, key, cases = self._run("/echo", "a=1&b=2")
        ssti = cases(SSTI)
        self.assertEqual(ssti["a"].status, CellStatus.NOT_DETECTED, ssti["a"].reason)
        self.assertEqual(ssti["b"].status, CellStatus.NOT_DETECTED, ssti["b"].reason)
        self.assertEqual(matrix.get(*key(SSTI)).status, CellStatus.NOT_DETECTED)

    def test_budget_truncated_parameter_stays_open(self):
        matrix, key, cases = self._run("/echo", "a=1&b=2", case_budget=1)
        ssti = cases(SSTI)
        self.assertEqual(ssti["a"].status, CellStatus.NOT_DETECTED, ssti["a"].reason)
        self.assertEqual(ssti["b"].status, CellStatus.SKIPPED)       # never a clean negative
        self.assertFalse(ssti["b"].executed)
        self.assertNotIn(matrix.get(*key(SSTI)).status,
                         (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE))

    def test_request_level_leg_is_unchanged(self):
        # Open redirect is not dispatched per parameter: one request-level attempt,
        # and both inputs stay inconclusive, exactly as before.
        _matrix, _key, cases = self._run("/redirect", "a=1&b=2")
        redirect = cases(REDIRECT)
        self.assertEqual(set(redirect), {"", "a", "b"})
        for name in ("a", "b"):
            self.assertEqual(redirect[name].status, CellStatus.INCONCLUSIVE)
            self.assertIn("request level", redirect[name].reason)
            self.assertFalse(redirect[name].executed)
        # SSTI on the same endpoint is per parameter.
        self.assertEqual(cases(SSTI)["a"].status, CellStatus.NOT_DETECTED)


class SqlmapParameterOnlyTest(unittest.TestCase):
    """sqlmap's per-parameter dispatch: `-p <name>` and probes on that input only.
    The sqlmap process itself is replaced by a canned result (it runs only from
    the Docker image); the boolean preflight sends real requests."""

    class _Handler(BaseHTTPRequestHandler):
        queries = []

        def do_GET(self):
            type(self).queries.append(dict(parse_qsl(urlsplit(self.path).query)))
            body = b"<html>ok</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls._Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/items?a=1&b=2"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _validate(self, name, sqlmap_output):
        from harness import tool_runner
        from harness.models import Finding
        from harness.validators.sqlmap import SqlmapValidator
        argv = []

        def fake_run(cmd, **kw):
            argv.extend(cmd)
            return tool_runner.ProcessResult(list(cmd), 0, sqlmap_output, "", "exit", "not_needed", "job")

        self._Handler.queries.clear()
        finding = Finding(vulnerability_class="sqli", confidence=0.5, summary="s", evidence="",
                          suggested_test="t", basis="derived", parameter_location="query", parameter_name=name, parameter_only=True)
        exchange = HttpExchange(method="GET", url=self.url, request_headers={}, request_body="",
                                response_status=200, response_headers={}, response_body="")
        with patch.object(tool_runner, "run_process", side_effect=fake_run):
            res = asyncio.run(SqlmapValidator(allowed_hosts=["127.0.0.1"]).validate(finding, exchange))
        return res, argv

    def test_named_parameter_only(self):
        res, argv = self._validate("b", "all tested parameters do not appear to be injectable")
        self.assertEqual(res.status, "not_confirmed")
        self.assertEqual(res.control_outcome, "")
        self.assertEqual(argv[argv.index("-p") + 1], "b")
        self.assertTrue(self._Handler.queries)                       # the preflight ran
        self.assertTrue(all(q.get("a") == "1" for q in self._Handler.queries))  # `a` untouched

    def test_parameter_sqlmap_did_not_find_is_not_a_negative(self):
        res, _ = self._validate("b", "[CRITICAL] all testable parameters you provided are not "
                                     "present within the given request data")
        self.assertEqual(res.status, "inconclusive")
        self.assertEqual(res.control_outcome, "named_parameter_untested")

    def test_absent_parameter_is_not_tested(self):
        res, argv = self._validate("zzz", "")
        self.assertEqual(res.status, "skipped")
        self.assertEqual(argv, [])
        self.assertEqual(self._Handler.queries, [])


if __name__ == "__main__":
    unittest.main()
