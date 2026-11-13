"""dom_xss reads a captured page's own query parameters as location.search sources.

The fixture is a loopback server with four HTML pages that take `?term=` and one
JSON API:
  - `/search` writes `term`, read from location.search, into `innerHTML` (a DOM
    sink); the server never reflects it.
  - `/echo` has the server reflect `term` raw into the HTML (reflected XSS, which
    is browser_xss's verdict, not dom_xss's).
  - `/safe` writes `term` with `textContent` (rendered safely).
  - `/hash` writes `term` safely, and the raw fragment into `innerHTML`.
  - `/api/find` answers JSON.

Covered here:
  - the leg: a per-parameter `query` dispatch places the payload in that one
    parameter, confirms DOM-based XSS only when the served document did not carry
    the payload, and binds its verdict to the parameter; a JSON answer is not
    loaded; the request-level attempt adds the query only for a captured HTML
    page; the coverage remainder (`fragment`) leaves the query alone;
  - the caller: investigate_engagement's case drive dispatches each query case to
    dom_xss and still runs the raw-fragment test once every case was tested alone,
    with a defect-injection control (no remainder: the raw-hash sink reads clean).
"""
import asyncio
import json
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

from harness import cache, engagement, global_throttle, store
from harness.coverage_model import CoverageMatrix, CellStatus
from harness.models import Finding, HttpExchange
from harness.role_crawl import RoleSession
from harness.test_spa_route_xss import _CHROMIUM, _config
from harness.validators.dom_xss_validator import DomXssValidator
from harness.validators.injection_targets import (NAMED_PARAMETER_UNTESTED, PER_PARAMETER_LOCATIONS,
                                                  REQUEST_LEVEL_INPUTS, case_target)
from harness.coverage_model import CaseKey

ROLES = [RoleSession("anonymous", {})]
REFLECTED, DOM = "WSTG-INPV-01", "WSTG-CLNT-01"
HTML = {"Content-Type": "text/html; charset=utf-8"}
JSON_TYPE = {"Content-Type": "application/json"}

_SEARCH = """<!doctype html><html><body><div id="o"></div><script>
document.getElementById("o").innerHTML =
  "Results for " + (new URLSearchParams(location.search).get("term") || "");
</script></body></html>"""

_SAFE = _SEARCH.replace("innerHTML", "textContent")

_HASH = """<!doctype html><html><body><p id="t"></p><div id="o"></div><script>
document.getElementById("t").textContent = new URLSearchParams(location.search).get("term") || "";
document.getElementById("o").innerHTML = decodeURIComponent(location.hash.slice(1));
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        term = dict(parse_qsl(parts.query, keep_blank_values=True)).get("term", "")
        if parts.path == "/search":
            self._reply(_SEARCH, "text/html")
        elif parts.path == "/safe":
            self._reply(_SAFE, "text/html")
        elif parts.path == "/hash":
            self._reply(_HASH, "text/html")
        elif parts.path == "/echo":
            self._reply(f"<!doctype html><html><body><h2>{term}</h2></body></html>", "text/html")
        elif parts.path == "/api/find":
            self._reply(json.dumps({"term": term, "items": []}), "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _reply(self, text, ctype):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _QueryServer(unittest.TestCase):
    """The query fixture on loopback, with a store and cache of its own."""
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="dom_xss_query_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.qserver = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.qbase = f"http://127.0.0.1:{cls.qserver.server_address[1]}"
        threading.Thread(target=cls.qserver.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.qserver.shutdown()
        cls.qserver.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        global_throttle.configure(0)


class _Recorder:
    """A browser that executes nothing and records what it was asked to load."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500, headers=None, **_kw):
        from harness.browser_driver import ExecutionObservation
        self.visited.append(url)
        return ExecutionObservation(url=url)


def _finding(**kw):
    return Finding(vulnerability_class="dom_xss", confidence=0.5, summary="dom xss candidate",
                   evidence="", suggested_test="load it in a browser", basis="assumed",
                   severity="high", **kw)


def _query(name):
    return dict(parameter_location="query", parameter_name=name, parameter_only=True)


_REMAINDER = dict(parameter_location="fragment", parameter_name="", parameter_only=True)


def _validate(url, *, headers=None, driver=None, max_visits=4, **finding_kw):
    v = DomXssValidator(driver=driver, allowed_hosts=["127.0.0.1"], max_visits=max_visits,
                        wait_ms=600)
    ex = HttpExchange(url=url, method="GET", response_status=200,
                      response_headers=dict(headers or {}))
    return asyncio.run(v.validate(_finding(**finding_kw), ex))


def _term(url):
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)).get("term")


class QueryDispatchTargetTest(unittest.TestCase):
    def test_dom_xss_tests_a_query_case_alone_and_keeps_a_fragment_remainder(self):
        self.assertIn("query", PER_PARAMETER_LOCATIONS["dom_xss"])
        self.assertEqual(case_target("dom_xss", CaseKey("query", "term", 0, "", "term")),
                         ("query", "term"))
        self.assertEqual(REQUEST_LEVEL_INPUTS["dom_xss"], "fragment")
        # path traversal keeps its own remainder input
        self.assertEqual(REQUEST_LEVEL_INPUTS["path_traversal"], "path")


class QueryCandidateTest(_QueryServer):
    """What the leg loads, recorded by a browser that runs nothing."""

    def test_a_query_case_puts_the_payload_in_that_parameter_alone(self):
        d = _Recorder()
        res = _validate(f"{self.qbase}/search?term=lamp&page=2", headers=HTML, driver=d,
                        **_query("term"))
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertEqual(res.tested_parameters, (("query", "term"),))
        self.assertTrue(d.visited)
        for u in d.visited:
            self.assertNotEqual(_term(u), "lamp", u)
            self.assertEqual(dict(parse_qsl(urlsplit(u).query))["page"], "2", u)
            self.assertEqual(urlsplit(u).fragment, "", u)

    def test_a_json_answer_is_not_loaded_for_its_query(self):
        d = _Recorder()
        res = _validate(f"{self.qbase}/api/find?term=lamp", headers=JSON_TYPE, driver=d,
                        **_query("term"))
        self.assertEqual((res.status, res.control_outcome, d.visited),
                         ("skipped", NAMED_PARAMETER_UNTESTED, []))
        self.assertEqual(res.tested_parameters, ())

    def test_a_name_the_url_lacks_is_not_tested(self):
        d = _Recorder()
        res = _validate(f"{self.qbase}/search?term=lamp", headers=HTML, driver=d, **_query("q"))
        self.assertEqual((res.status, res.control_outcome, d.visited),
                         ("skipped", NAMED_PARAMETER_UNTESTED, []))
        self.assertIn("not a query parameter", res.summary)

    def test_the_request_level_attempt_adds_the_query_of_an_html_page_only(self):
        url = f"{self.qbase}/search?term=lamp"
        d = _Recorder()
        _validate(url, headers=HTML, driver=d)
        changed = [u for u in d.visited if _term(u) != "lamp"]
        self.assertTrue(changed, d.visited)
        self.assertTrue(any(urlsplit(u).fragment for u in d.visited), "raw fragment dropped")
        self.assertLessEqual(len(d.visited), 8)
        # Control: a capture with no content type (or a JSON one) keeps today's
        # candidates, the raw fragment only.
        for headers in (None, JSON_TYPE):
            d = _Recorder()
            _validate(url, headers=headers, driver=d)
            self.assertTrue(d.visited)
            self.assertTrue(all(_term(u) == "lamp" for u in d.visited), d.visited)

    def test_the_remainder_tests_the_raw_fragment_and_leaves_the_query_alone(self):
        d = _Recorder()
        res = _validate(f"{self.qbase}/search?term=lamp", headers=HTML, driver=d, **_REMAINDER)
        self.assertEqual(res.status, "not_confirmed", res.summary)
        self.assertTrue(d.visited)
        for u in d.visited:
            self.assertEqual(_term(u), "lamp", u)
            self.assertTrue(urlsplit(u).fragment, u)


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class RealBrowserQuerySourceTest(_QueryServer):
    def test_a_location_search_sink_is_confirmed_on_its_query_parameter(self):
        res = _validate(f"{self.qbase}/search?term=lamp", headers=HTML, **_query("term"))
        self.assertEqual(res.status, "confirmed", res.evidence)
        self.assertEqual(res.tested_parameters, (("query", "term"),))
        self.assertIn("query parameter 'term'", res.summary)
        self.assertIn("location.search", res.evidence)

    def test_a_server_reflection_is_not_dom_xss(self):
        res = _validate(f"{self.qbase}/echo?term=lamp", headers=HTML, **_query("term"))
        self.assertEqual(res.status, "inconclusive", res.evidence)
        self.assertFalse(res.confirmed)
        self.assertIn("reflected XSS", res.summary)

    def test_a_safely_rendered_query_is_not_confirmed(self):
        res = _validate(f"{self.qbase}/safe?term=lamp", headers=HTML, **_query("term"))
        self.assertEqual(res.status, "not_confirmed", res.evidence)
        self.assertEqual(res.tested_parameters, (("query", "term"),))

    def test_the_request_level_attempt_finds_the_query_sink_of_an_html_page(self):
        res = _validate(f"{self.qbase}/search?term=lamp", headers=HTML)
        self.assertEqual(res.status, "confirmed", res.evidence)
        # Control: with no content type the old candidates run, which never
        # reach location.search.
        res = _validate(f"{self.qbase}/search?term=lamp")
        self.assertEqual(res.status, "not_confirmed", res.evidence)

    def test_the_remainder_finds_a_raw_hash_sink_the_query_case_misses(self):
        url = f"{self.qbase}/hash?term=lamp"
        res = _validate(url, headers=HTML, **_query("term"))
        self.assertEqual(res.status, "not_confirmed", res.evidence)
        res = _validate(url, headers=HTML, **_REMAINDER)
        self.assertEqual(res.status, "confirmed", res.evidence)
        self.assertIn("FRAGMENT", res.evidence)


def _drive(base, paths):
    """investigate_engagement's case drive over the captured `paths` (each with
    `?term=lamp`), every leg but the two browser XSS legs off, the agent probe
    stubbed."""
    from harness.orchestrator import Orchestrator
    from harness.orchestrator_helpers import per_run_gate_config
    from harness.run_context import RunContext

    def canned(base_url, roles, **kw):
        state = engagement.EngagementState(host="127.0.0.1")
        for path in paths:
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": path, "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False}],
                "idor_findings": []})
            url = f"{base}{path}?term=lamp"
            state.record_template(url, "GET", HttpExchange(
                method="GET", url=url, request_headers={}, response_status=200,
                response_headers=JSON_TYPE if path.startswith("/api/") else HTML,
                response_body="{}" if path.startswith("/api/") else "<html></html>"))
        for r in roles:
            state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
        return state, SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[],
                                      idor_findings=[])

    cfg = _config()
    for leg in ("browser_xss", "dom_xss"):
        # Fewer, shorter visits: the first payload of each kind reaches these sinks.
        cfg["validators"][leg].update(wait_ms=500, max_visits=4)
    orch = Orchestrator(cfg)
    orch.engagement_coverage_drive = True
    orch.engagement_coverage_case_drive = True
    orch.run_active_probe = AsyncMock(return_value={
        "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})

    async def investigate():
        async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                     gate_config=per_run_gate_config(
                                         cfg, orch.validator_registry)) as ctx:
            return await orch.investigate_engagement(
                base, ROLES, max_nodes=0, step_budget=4, max_chain_rounds=0, run_context=ctx)

    with patch("harness.engagement_builder.build_engagement", side_effect=canned), \
            patch("harness.orchestrator_chain.shape_precondition_legs", return_value=[]):
        result = asyncio.run(investigate())
    coverage = result.get("coverage") or {}
    assert "cases_driven" in coverage, "the case-driven coverage path did not run"
    return CoverageMatrix.from_dict(coverage["checkpoint"]["matrix"]), result


def _case(test, matrix, ep_key, check, location="", name=""):
    for ck, r in matrix.cases_for_cell("anonymous", ep_key, check):
        if (ck.parameter_location, ck.parameter_name) == (location, name):
            return r
    test.fail(f"no {location}:{name} case under {ep_key} {check}: "
              f"{[c.label() for c, _ in matrix.cases_for_cell('anonymous', ep_key, check)]}")


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class QuerySourceCoverageCallerTest(_QueryServer):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.matrix, cls.result = _drive(cls.qbase, ("/search", "/echo", "/safe", "/hash",
                                                    "/api/find"))

    def _case(self, *a):
        return _case(self, self.matrix, *a)

    def test_the_location_search_sink_is_confirmed_on_its_query_case(self):
        r = self._case("GET /search", DOM, "query", "term")
        self.assertEqual(r.status, CellStatus.CONFIRMED, r.reason)
        self.assertIn("query parameter 'term'", r.reason)

    def test_a_server_reflection_is_browser_xss_not_dom_xss(self):
        self.assertEqual(self._case("GET /echo", REFLECTED, "query", "term").status,
                         CellStatus.CONFIRMED)
        r = self._case("GET /echo", DOM, "query", "term")
        self.assertEqual(r.status, CellStatus.INCONCLUSIVE, r.reason)

    def test_the_safely_rendered_page_concludes_clean(self):
        self.assertEqual(self._case("GET /safe", DOM, "query", "term").status,
                         CellStatus.NOT_DETECTED)
        # The request as a whole is concluded by the remainder's own attempt (the
        # raw fragment), not inferred from the query case alone.
        r = self._case("GET /safe", DOM)
        self.assertEqual(r.status, CellStatus.NOT_DETECTED, r.reason)
        self.assertNotIn("every input", r.reason)

    def test_the_raw_hash_sink_is_still_found_once_the_query_was_tested_alone(self):
        self.assertEqual(self._case("GET /hash", DOM, "query", "term").status,
                         CellStatus.NOT_DETECTED)
        r = self._case("GET /hash", DOM)
        self.assertEqual(r.status, CellStatus.CONFIRMED, r.reason)

    def test_a_json_api_query_is_not_loaded_as_a_page(self):
        r = self._case("GET /api/find", DOM, "query", "term")
        self.assertNotIn(r.status, (CellStatus.NOT_DETECTED, CellStatus.CONFIRMED), r.reason)
        self.assertIn("location.search", r.reason)

    def test_the_query_dom_xss_enters_the_finding_pipeline(self):
        confirmed = {(f.get("vulnerability_class"), urlsplit(f.get("url") or "").path)
                     for f in self.result.get("findings") or [] if f.get("confirmed")}
        self.assertIn(("dom_xss", "/search"), confirmed)
        self.assertNotIn(("dom_xss", "/safe"), confirmed)
        self.assertNotIn(("dom_xss", "/echo"), confirmed)


@unittest.skipUnless(_CHROMIUM, "headless Chromium is not installed")
class NoRemainderControlTest(_QueryServer):
    def test_without_the_remainder_the_raw_hash_sink_reads_clean(self):
        """Defect injection: no request-level attempt once the query case was
        tested alone, so the raw fragment is never loaded and the page reads
        NOT_DETECTED. The caller test above sees the sink."""
        with patch("harness.coverage_tracker.REQUEST_LEVEL_INPUTS", {"path_traversal": "path"}):
            matrix, _result = _drive(self.qbase, ("/hash",))
        self.assertEqual(_case(self, matrix, "GET /hash", DOM).status, CellStatus.NOT_DETECTED)


if __name__ == "__main__":
    unittest.main()
