"""Per-parameter dispatch, through investigate_engagement's real coverage case drive.

A leg that can test one input (SSTI and open redirect here) is driven once per
parameter case, so each parameter gets its own verdict: the evaluating (or
redirecting) parameter is confirmed and the literal one beside it concludes
clean. The verdict binds only because the leg reports the input it tested.
Controls: a case-budget-truncated parameter stays open (never a clean negative),
an input the leg cannot target alone (a repeated name) stays inconclusive, and a
leg that does not report its input leaves every parameter case inconclusive.
The per-finding mutating ceiling counts per parameter case: a parameter the
ceiling cuts off stays open, and one ceiling shared by every parameter (the
defect control) would cut the later one. Request-level legs (path traversal,
and the request-level attempt of SSTI and command injection) count the ceiling
on their own case too: a leg the ceiling cuts off is never a clean negative, and
one under it still concludes.

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
SSTI, REDIRECT, CMDI, TRAVERSAL = "WSTG-INPV-18", "WSTG-INPV-17", "WSTG-INPV-12", "WSTG-ATHZ-01"
ROLES = [RoleSession("anonymous", {})]
# Every coverage leg but the two this file is about stays off, so the loopback
# server only sees SSTI and open-redirect traffic.
_OTHER_LEGS = ("sqlmap", "browser_xss", "stored_xss", "dom_xss", "command_injection", "xxe",
               "ssrf", "nosql", "jwt_forge", "deserialization_oob", "path_traversal",
               "sequence", "auth_sequence", "verb_tamper", "csrf", "file_upload", "rate_limit",
               "reset_token", "toctou", "race_condition", "csp", "cors", "header_injection",
               "http_request_smuggling")


class _Handler(BaseHTTPRequestHandler):
    """POST /render evaluates `{{a*b}}` in `tpl` only; POST /goto redirects to its
    `next` value; every other value (and every value on /echo) is reflected
    literally."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        params = parse_qsl(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        path = urlsplit(self.path).path
        if path == "/goto":
            self.send_response(302)
            self.send_header("Location", dict(params).get("next", "/"))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
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


class _LoopbackDrive(unittest.TestCase):
    """The loopback target and one investigate_engagement run over a canned
    endpoint (no tests of its own)."""

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

    def _run(self, path, body, case_budget=8, engagement_cfg=None, disable=(), validators_cfg=None,
             live_context=False):
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

        cfg = _config()
        cfg["engagement"].update(engagement_cfg or {})
        cfg["validators"].update(validators_cfg or {})
        for name in disable:
            cfg["validators"].setdefault(name, {})["enabled"] = False
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.coverage_case_budget = case_budget
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        async def investigate():
            if not live_context:
                return await orch.investigate_engagement(
                    base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0)
            # As the server's engagement job: the run's own context and gate, so the
            # legs send through the run executor and its per-finding ceiling.
            from harness.orchestrator_helpers import per_run_gate_config
            from harness.run_context import RunContext
            async with RunContext.create(
                    allowed_hosts=["127.0.0.1"], config=cfg,
                    gate_config=per_run_gate_config(cfg, orch.validator_registry)) as ctx:
                return await orch.investigate_engagement(
                    base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0, run_context=ctx)

        with patch("harness.engagement_builder.build_engagement", side_effect=canned),                 patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]):
            result = asyncio.run(investigate())
        coverage = result.get("coverage") or {}
        self.assertIn("cases_driven", coverage, "the case-driven coverage path did not run")
        matrix = CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"])
        key = lambda check: ("anonymous", f"POST {path}", check)  # noqa: E731
        cases = lambda check: {ck.parameter_name: r for ck, r in  # noqa: E731
                               matrix.cases_for_cell(*key(check))}
        self.coverage = coverage
        return matrix, key, cases


class PerParameterDispatchCallerTest(_LoopbackDrive):
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

    def test_open_redirect_concludes_each_parameter(self):
        # Open redirect is dispatched per parameter too: each clean input is
        # concluded on its own send, so the cell concludes clean.
        matrix, key, cases = self._run("/redirect", "a=1&b=2")
        redirect = cases(REDIRECT)
        self.assertEqual(set(redirect), {"", "a", "b"})
        for name in ("a", "b"):
            self.assertEqual(redirect[name].status, CellStatus.NOT_DETECTED, redirect[name].reason)
            self.assertTrue(redirect[name].executed)
        self.assertEqual(matrix.get(*key(REDIRECT)).status, CellStatus.NOT_DETECTED)

    def _redirect_cases(self):
        matrix, key, _cases = self._run("/goto", "next=/home&a=1&a=2")
        cases = {(ck.parameter_name, ck.occurrence): r
                 for ck, r in matrix.cases_for_cell(*key(REDIRECT))}
        return matrix.get(*key(REDIRECT)), cases

    def test_redirecting_parameter_confirmed_untargetable_sibling_stays_open(self):
        cell, cases = self._redirect_cases()
        self.assertEqual(cases[("next", 0)].status, CellStatus.CONFIRMED, cases[("next", 0)].reason)
        self.assertTrue(cases[("next", 0)].executed)
        self.assertEqual(cases[("a", 0)].status, CellStatus.NOT_DETECTED, cases[("a", 0)].reason)
        self.assertTrue(cases[("a", 0)].executed)
        # Control: the second `a` cannot be targeted alone, so the leg never
        # tested it; it stays inconclusive behind the request-level attempt.
        self.assertEqual(cases[("a", 1)].status, CellStatus.INCONCLUSIVE)
        self.assertFalse(cases[("a", 1)].executed)
        self.assertTrue(cases[("", 0)].executed)
        self.assertEqual(cell.status, CellStatus.CONFIRMED)

    def test_control_a_leg_that_does_not_report_its_input_attributes_nothing(self):
        """Defect injection: the same sends, but the leg reports no tested input,
        so no parameter case is concluded; the confirmation stays on the request."""
        from harness.validators import open_redirect_validator
        with patch.object(open_redirect_validator, "tested_inputs", return_value=()):
            cell, cases = self._redirect_cases()
        for case in (("next", 0), ("a", 0), ("a", 1)):
            self.assertEqual(cases[case].status, CellStatus.INCONCLUSIVE, case)
            self.assertFalse(cases[case].executed, case)
        self.assertEqual(cases[("", 0)].status, CellStatus.CONFIRMED)
        self.assertEqual(cell.status, CellStatus.CONFIRMED)

    # -- engagement.coverage_parameter_field_cap, read from the config
    def _field_cap_run(self):
        return self._run("/echo", "a=1&b=2", engagement_cfg={"coverage_parameter_field_cap": 1},
                         disable=("open_redirect",))

    def test_configured_field_cap_bounds_the_parameters_dispatched(self):
        matrix, key, cases = self._field_cap_run()
        ssti = cases(SSTI)
        self.assertEqual(ssti["a"].status, CellStatus.NOT_DETECTED, ssti["a"].reason)
        # Over the configured cap: not dispatched alone, never a clean negative;
        # the request-level attempt covers it and leaves it inconclusive.
        self.assertEqual(ssti["b"].status, CellStatus.INCONCLUSIVE)
        self.assertFalse(ssti["b"].executed)
        self.assertTrue(ssti[""].executed)
        self.assertEqual(self.coverage["cases_driven"], 2)    # `a`, then request level
        self.assertNotEqual(matrix.get(*key(SSTI)).status, CellStatus.NOT_DETECTED)

    def test_control_a_drive_ignoring_the_configured_cap_concludes_both(self):
        """Defect injection: a caller that drops the configured cap (the former
        constant of 6 applies) dispatches `b` too, so the test above sees it."""
        from harness import coverage_tracker
        original = coverage_tracker.build_coverage_cases_driven

        async def ignores_cap(*args, parameter_field_cap=None, **kwargs):
            return await original(*args, **kwargs)

        with patch.object(coverage_tracker, "build_coverage_cases_driven", ignores_cap):
            _matrix, _key, cases = self._field_cap_run()
        self.assertEqual(cases(SSTI)["b"].status, CellStatus.NOT_DETECTED)

    # -- engagement.coverage_leg_budget counts per dispatch
    def _leg_budget_run(self):
        return self._run("/echo", "a=1&b=2", engagement_cfg={"coverage_leg_budget": 1},
                         disable=("open_redirect",))

    def test_leg_budget_counts_each_parameter_dispatch(self):
        matrix, key, cases = self._leg_budget_run()
        ssti = cases(SSTI)
        self.assertEqual(self.coverage["cases_driven"], 1)
        self.assertEqual(self.coverage["drive_stopped_by"], "leg budget")
        self.assertEqual(ssti["a"].status, CellStatus.NOT_DETECTED, ssti["a"].reason)
        # The one unit went to `a`: `b` and the request-level attempt are not sent.
        self.assertEqual(ssti["b"].status, CellStatus.INCONCLUSIVE)
        self.assertIn("leg budget", ssti["b"].reason)
        self.assertFalse(ssti["b"].executed)
        self.assertFalse(ssti[""].executed)
        self.assertNotEqual(matrix.get(*key(SSTI)).status, CellStatus.NOT_DETECTED)

    def test_control_a_budget_counted_per_cell_dispatches_both(self):
        """Defect injection: counting one unit per cell lets a budget of 1 dispatch
        every parameter of the cell, so the test above sees it."""
        from harness.coverage_tracker import CoverageTracker
        original = CoverageTracker._drive_parameter_cases

        async def per_cell(self, run_case, ident, ep_key, check, cks, rep, targets, deadline,
                           remaining, field_cap):
            await original(self, run_case, ident, ep_key, check, cks, rep, targets, deadline,
                           10**6, field_cap)
            return 1

        with patch.object(CoverageTracker, "_drive_parameter_cases", per_cell):
            _matrix, _key, cases = self._leg_budget_run()
        self.assertEqual(cases(SSTI)["b"].status, CellStatus.NOT_DETECTED)
        self.assertEqual(self.coverage["cases_driven"], 1)

    # -- the per-finding mutating ceiling (R16) counts per parameter case
    def _ceiling_run(self, path, body, ceiling):
        return self._run(path, body, disable=("open_redirect",), live_context=True,
                         validators_cfg={"mutating_ceiling_by_check": {"ssti": ceiling}})

    def test_parameter_cut_off_by_the_mutating_ceiling_is_never_a_clean_negative(self):
        # A ceiling of 3: `tpl` confirms in 3 POSTs (probe, control, baseline);
        # the clean `name` needs one per syntax, so its fourth is refused.
        matrix, key, cases = self._ceiling_run("/render", "tpl=hello&name=bob", 3)
        ssti = cases(SSTI)
        self.assertEqual(ssti["tpl"].status, CellStatus.CONFIRMED, ssti["tpl"].reason)
        self.assertTrue(ssti["tpl"].executed)
        self.assertEqual(ssti["name"].status, CellStatus.INCONCLUSIVE, ssti["name"].reason)
        self.assertIn("mutating-request ceiling", ssti["name"].reason)
        self.assertFalse(ssti["name"].executed)
        self.assertEqual(matrix.get(*key(SSTI)).status, CellStatus.CONFIRMED)

    def test_mutating_ceiling_counts_per_parameter_case(self):
        # A ceiling of 6 is exactly one clean input's sends: under it, each
        # parameter concludes on its own account.
        matrix, key, cases = self._ceiling_run("/echo", "a=1&b=2", 6)
        ssti = cases(SSTI)
        for name in ("a", "b"):
            self.assertEqual(ssti[name].status, CellStatus.NOT_DETECTED, ssti[name].reason)
            self.assertTrue(ssti[name].executed)
        self.assertEqual(matrix.get(*key(SSTI)).status, CellStatus.NOT_DETECTED)

    def test_control_a_ceiling_shared_by_the_parameters_cuts_the_later_one(self):
        """Defect injection: one account for every parameter (per finding, not per
        case). `a` spends the ceiling, so `b` is refused before its first send and
        stays open, never a clean negative."""
        from harness.safety_gate import SafetyGate
        original = SafetyGate._reserve_mutating

        def shared(self, finding_id, n, validator_name=None):
            return original(self, "shared" if finding_id else finding_id, n, validator_name)

        with patch.object(SafetyGate, "_reserve_mutating", shared):
            matrix, key, cases = self._ceiling_run("/echo", "a=1&b=2", 6)
        ssti = cases(SSTI)
        self.assertEqual(ssti["a"].status, CellStatus.NOT_DETECTED, ssti["a"].reason)
        self.assertNotIn(ssti["b"].status, (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE))
        self.assertIn("mutating-request ceiling", ssti["b"].reason)
        self.assertFalse(ssti["b"].executed)
        self.assertNotEqual(matrix.get(*key(SSTI)).status, CellStatus.NOT_DETECTED)


_NEGATIVES = (CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE)


class RequestLevelCeilingCallerTest(_LoopbackDrive):
    """The per-finding mutating ceiling (R16) on request-level coverage legs, each
    keyed on its own case. Lowered per check in the test's own config only."""

    @staticmethod
    def _answered(leg) -> int:
        """Answered sends the case's attempts recorded (a cut-off inconclusive leg
        is not `executed`, but its answered probes are on its attempt)."""
        return sum(a.get("sent", 0) for a in leg.attempts if isinstance(a, dict))

    # -- path traversal: a clean POST file route, injected in its path segment
    #    only (no form parameter): 16 POSTs, one per encoding and system file.
    def _traversal_run(self, ceiling):
        return self._run("/files/view", "{}", disable=("ssti", "open_redirect"), live_context=True,
                         validators_cfg={"path_traversal": {"enabled": True},
                                         "mutating_ceiling_by_check": {"path_traversal": ceiling}})

    def test_traversal_cut_off_by_the_ceiling_is_never_a_clean_negative(self):
        matrix, key, cases = self._traversal_run(4)
        leg = cases(TRAVERSAL)[""]
        self.assertEqual(leg.status, CellStatus.INCONCLUSIVE, leg.reason)
        self.assertIn("mutating-request ceiling", leg.reason)
        self.assertEqual(self._answered(leg), 4)           # the case's own account
        self.assertNotIn(matrix.get(*key(TRAVERSAL)).status, _NEGATIVES)

    def test_traversal_under_the_ceiling_concludes(self):
        # Negative control: the hard cap (20) covers every probe, so the clean
        # route concludes on its own account.
        matrix, key, cases = self._traversal_run(20)
        leg = cases(TRAVERSAL)[""]
        self.assertEqual(leg.status, CellStatus.NOT_DETECTED, leg.reason)
        self.assertTrue(leg.executed)
        self.assertEqual(matrix.get(*key(TRAVERSAL)).status, CellStatus.NOT_DETECTED)

    def test_control_a_ceiling_refusal_read_as_one_unsendable_payload_reads_clean(self):
        """Defect injection: the leg files each ceiling refusal as one unsendable
        payload (the former behaviour), so the cut leg ends not_confirmed and the
        cell reads clean. The cut-off test above sees it."""
        from harness.validators.path_traversal_validator import PathTraversalValidator
        with patch.object(PathTraversalValidator, "_ceiling_spent", return_value=False):
            matrix, key, cases = self._traversal_run(4)
        self.assertEqual(cases(TRAVERSAL)[""].status, CellStatus.NOT_DETECTED)
        self.assertEqual(matrix.get(*key(TRAVERSAL)).status, CellStatus.NOT_DETECTED)

    def test_control_an_unkeyed_request_level_leg_escapes_the_ceiling(self):
        """Defect injection: the request-level leg carries no ceiling key (the
        former drive), so the ceiling never counts it and every probe is sent.
        The cut-off test above sees it."""
        from harness.validators.path_traversal_validator import PathTraversalValidator
        original = PathTraversalValidator.validate

        async def unkeyed(self, finding, exchange):
            return await original(self, finding.model_copy(update={"finding_id": ""}), exchange)

        with patch.object(PathTraversalValidator, "validate", unkeyed):
            _matrix, _key, cases = self._traversal_run(4)
        leg = cases(TRAVERSAL)[""]
        self.assertEqual(leg.status, CellStatus.NOT_DETECTED, leg.reason)
        self.assertGreater(self._answered(leg), 4)

    # -- the request-level attempt of SSTI and command injection: a field cap of
    #    0 keeps the cell request-level, so one leg tests both inputs.
    def _request_level_run(self, check, ceiling, **validators_cfg):
        disable = tuple(n for n in ("ssti", "open_redirect", "command_injection") if n != check)
        return self._run("/echo", "a=1&b=2", engagement_cfg={"coverage_parameter_field_cap": 0},
                         disable=disable, live_context=True,
                         validators_cfg={**validators_cfg, check: {"enabled": True},
                                         "mutating_ceiling_by_check": {check: ceiling}})

    def test_ssti_request_level_cut_off_is_never_a_clean_negative(self):
        # Six POSTs per clean input: the twelve this leg needs are cut at six.
        matrix, key, cases = self._request_level_run("ssti", 6)
        leg = cases(SSTI)[""]
        self.assertEqual(leg.status, CellStatus.INCONCLUSIVE, leg.reason)
        self.assertIn("mutating-request ceiling", leg.reason)
        self.assertEqual(self._answered(leg), 6)
        self.assertNotIn(matrix.get(*key(SSTI)).status, _NEGATIVES)

    def test_ssti_request_level_under_the_ceiling_concludes(self):
        matrix, key, cases = self._request_level_run("ssti", 12)
        leg = cases(SSTI)[""]
        self.assertEqual(leg.status, CellStatus.NOT_DETECTED, leg.reason)
        self.assertTrue(leg.executed)

    def test_command_injection_request_level_cut_off_is_never_a_clean_negative(self):
        # Three in-band POSTs per input (callbacks off): the third is refused.
        matrix, key, cases = self._request_level_run(
            "command_injection", 2, oob_callbacks_enabled=False)
        leg = cases(CMDI)[""]
        self.assertIn(leg.status, (CellStatus.INCONCLUSIVE, CellStatus.BLOCKED), leg.reason)
        self.assertIn("mutating-request ceiling", leg.reason)
        self.assertEqual(self._answered(leg), 2)
        self.assertNotIn(matrix.get(*key(CMDI)).status, _NEGATIVES)

    def test_command_injection_request_level_under_the_ceiling_runs_every_probe(self):
        # Control: under the ceiling every in-band probe of both inputs is
        # answered; with callbacks off the leg ends on its own reason, not on
        # the ceiling (it never concludes in-band alone).
        matrix, key, cases = self._request_level_run(
            "command_injection", 6, oob_callbacks_enabled=False)
        leg = cases(CMDI)[""]
        self.assertEqual(self._answered(leg), 6)
        self.assertNotIn("ceiling", leg.reason)
        self.assertIn("callback probes disabled", leg.reason)


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
