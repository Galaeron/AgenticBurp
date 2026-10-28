"""Ticket 2B: a sqlmap confirmation carries its injection points and, where the
harness can reproduce one, a harness-sent true/false differential.

sqlmap is never run: its launch (tool_runner.run_process) returns recorded output.
The target is an owned 127.0.0.1 fixture that counts, per parameter, the requests
that carried a boolean payload. Each behaviour has a negative control that patches
the parser out (the old path: sqlmap's claim only, no points, no differential).
"""
import asyncio
import json
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

import httpx

from harness import store
from harness.assessment_health import stored_proof_artifacts_resolve
from harness.models import HttpExchange
from harness.safety_gate import get_default_gate, reset_default_gate
from harness.test_confirmation_soundness_rve import _finding, _verdicts
from harness.test_proof_artifacts import _execution_event, _ProofCallerBase, _Target
from harness.validators.base import ValidationResult, observed_result_of
from harness.validators.sqlmap import SqlmapValidator, parse_injection_points

_BANNER = """\
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-10-28/
"""

GET_BOOLEAN = _BANNER + """
[12:00:01] [INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

---
[12:00:05] [INFO] the back-end DBMS is SQLite
[12:00:05] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others?
"""

JSON_BOOLEAN_AND_TIME = _BANNER + """
sqlmap identified the following injection point(s) with a total of 90 HTTP(s) requests:
---
Parameter: JSON email ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"email":"a@b.c' OR 5432=5432-- xYzq","password":"x"}

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: {"email":"a@b.c' AND 3333=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- Qwer","password":"x"}
---
[12:00:09] [INFO] (custom) POST parameter 'JSON email' is vulnerable.
"""

# q is boolean-blind in JSON; the only other point sqlmap names is time-based.
_JSON_Q_BOOLEAN = _BANNER + """
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: JSON q ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"q":"x' AND 1234=1234-- abcd","r":"y"}
---
[12:00:09] [INFO] (custom) POST parameter 'JSON q' is vulnerable.
"""
_JSON_R_BOOLEAN = _JSON_Q_BOOLEAN.replace("JSON q", "JSON r")
_JSON_Q_TIME_ONLY = _JSON_Q_BOOLEAN.replace("boolean-based blind", "time-based blind")
_GET_Q_BOOLEAN = _BANNER + """
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: a=1&b=2&c=3&d=4&e=5&q=x AND 1234=1234
---
[12:00:09] [INFO] GET parameter 'q' is vulnerable.
"""


class _Proc:
    def __init__(self, stdout, returncode=0):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


def _sqlmap_says(output):
    return patch("harness.tool_runner.run_process", return_value=_Proc(output))


class ParseInjectionPointsTests(unittest.TestCase):
    def test_get_boolean_point(self):
        points = parse_injection_points(GET_BOOLEAN)
        self.assertEqual(points, [{
            "place": "query", "parameter": "id", "type": "boolean-based blind",
            "title": "AND boolean-based blind - WHERE or HAVING clause",
            "payload": "id=1 AND 1234=1234"}])

    def test_json_post_point_with_two_types_is_two_entries(self):
        points = parse_injection_points(JSON_BOOLEAN_AND_TIME)
        self.assertEqual([(p["place"], p["parameter"], p["type"]) for p in points],
                         [("body_json", "email", "boolean-based blind"),
                          ("body_json", "email", "time-based blind")])
        self.assertIn("5432=5432", points[0]["payload"])
        self.assertIn("RANDOMBLOB", points[1]["payload"])

    def test_windows_line_endings(self):
        crlf = JSON_BOOLEAN_AND_TIME.replace("\n", "\r\n")
        self.assertEqual(parse_injection_points(crlf), parse_injection_points(JSON_BOOLEAN_AND_TIME))

    def test_output_without_a_block_has_no_points(self):
        self.assertEqual(parse_injection_points(_BANNER + "\n[INFO] parameter 'id' is vulnerable\n"), [])
        self.assertEqual(parse_injection_points(""), [])

    def test_places_map_to_harness_locations(self):
        text = ("sqlmap resumed the following injection point(s) from stored session:\n---\n"
                "Parameter: #1* (URI)\n    Type: boolean-based blind\n\n"
                "Parameter: sid (Cookie)\n    Type: boolean-based blind\n\n"
                "Parameter: User-Agent (User-Agent)\n    Type: boolean-based blind\n\n"
                "Parameter: user (POST)\n    Type: boolean-based blind\n---\n")
        self.assertEqual([(p["place"], p["parameter"]) for p in parse_injection_points(text)],
                         [("path", "#1*"), ("cookie", "sid"), ("header", "User-Agent"),
                          ("body_form", "user")])

    def test_missing_title_and_payload_lines_are_tolerated(self):
        text = ("sqlmap identified the following injection point(s) with a total of 9 HTTP(s) requests:\n"
                "---\nParameter: id (GET)\n    Type: boolean-based blind\n"
                "    Type: stacked queries\n    Payload: id=1;SELECT 1\n---\n")
        points = parse_injection_points(text)
        self.assertEqual([(p["type"], p["title"], p["payload"]) for p in points],
                         [("boolean-based blind", "", ""), ("stacked queries", "", "id=1;SELECT 1")])


class EvidenceOrderTests(unittest.IsolatedAsyncioTestCase):
    """The first 1000 characters callers keep must hold the points, not the banner."""

    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                          "allowed_hosts": ["127.0.0.1"]})
        self.exchange = HttpExchange(url="http://127.0.0.1:5000/item?id=1", method="GET",
                                     request_headers={}, response_status=200)
        self.same = httpx.Response(200, content=b"same body", request=httpx.Request("GET", self.exchange.url))

    def tearDown(self):
        reset_default_gate()

    async def _validate(self, output):
        with _sqlmap_says(output), \
                patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=self.same):
            return await SqlmapValidator(binary="sqlmap").validate(_finding("sqli"), self.exchange)

    async def test_points_lead_the_evidence_and_the_banner_trails(self):
        result = await self._validate(GET_BOOLEAN)
        self.assertEqual(result.status, "confirmed")
        head = result.evidence[:1000]
        self.assertTrue(head.startswith("injection point: query:id — boolean-based blind"), head)
        self.assertIn("payload (query:id): id=1 AND 1234=1234", head)
        self.assertIn("--- sqlmap output (tail) ---", head)
        self.assertGreater(result.evidence.index("https://sqlmap.org"), result.evidence.index("--- sqlmap"))
        self.assertEqual([(p["place"], p["parameter"]) for p in result.injection_points], [("query", "id")])

    async def test_control_without_the_parser_keeps_the_banner_first(self):
        with patch("harness.validators.sqlmap.parse_injection_points", return_value=[]):
            result = await self._validate(GET_BOOLEAN)
        self.assertTrue(result.evidence.lstrip().startswith("___"), result.evidence[:80])
        self.assertNotIn("injection point: query:id", result.evidence[:1000])
        self.assertEqual(result.injection_points, ())

    async def test_confirmation_without_a_block_keeps_the_output_as_evidence(self):
        result = await self._validate(_BANNER + "\n[INFO] parameter 'id' is vulnerable\n")
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.injection_points, ())
        self.assertTrue(result.evidence.lstrip().startswith("___"))
        self.assertTrue(result.summary.startswith("tool-reported, not reproduced"))


def _search_app(blind=()):
    """POST/GET search whose `blind` parameters are boolean-blind: the true predicate
    lists 40 rows, the false one none. Counts, per parameter, the requests that
    carried a boolean payload (app.payload_hits) and every request (app.requests)."""
    def app(method, path, headers, body):
        fields = json.loads(body) if body else dict(parse_qsl(urlsplit(path).query))
        app.requests += 1
        rows = 1
        for name, value in fields.items():
            if "' OR '1'=" in str(value):
                app.payload_hits[name] += 1
            if name in blind and "'1'='1'" in str(value):
                rows = 40
            elif name in blind and "'1'='2'" in str(value):
                rows = 0
        return 200, json.dumps({"rows": [{"id": i} for i in range(rows)]})
    app.requests, app.payload_hits = 0, Counter()
    return app


class SqlmapPointsCallerTests(_ProofCallerBase, unittest.TestCase):
    """Through Orchestrator._validate_findings inside an entered run, as production."""

    def _post(self, target, body='{"q": "x", "r": "y"}'):
        return HttpExchange(
            url=target.origin + "/search", method="POST",
            request_headers={"Content-Type": "application/json"}, request_body=body,
            response_status=200, response_body='{"rows": []}')

    def _run(self, app, exchange_for, sqlmap_output, *, parser_out=False):
        target = _Target(app)
        self.addCleanup(target.close)
        exchange = exchange_for(target)
        validator = SqlmapValidator(allowed_hosts=list(self.HOSTS))
        stack = [_sqlmap_says(sqlmap_output)]
        if parser_out:
            stack.append(patch("harness.validators.sqlmap.parse_injection_points", return_value=[]))
        for cm in stack:
            cm.start()
            self.addCleanup(cm.stop)
        run_id, reports, proofs = self._confirm("sqlmap", validator, _finding("sqli"), exchange)
        return target, exchange, run_id, reports, self._stored_proof(proofs)

    def test_reproduced_point_names_distinct_resolving_artifacts(self):
        app = _search_app(blind={"q"})
        target, exchange, run_id, reports, proof = self._run(app, self._post, _JSON_Q_BOOLEAN)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertIn("sqlmap reported injection at body_json:q (boolean-based blind)", reports[0].summary)
        self.assertIn("reproduced a true/false differential on the same parameter", reports[0].summary)
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        rows = {role: len(json.loads(json.loads(store.get_evidence_blob(
            _execution_event(proof, aid)["data"]["response_blob"]))["body"])["rows"])
            for role, aid in (("baseline", proof["baseline_artifact_id"]),
                              ("attack", proof["attack_artifact_id"]),
                              ("control", proof["control_artifact_ids"][0]))}
        self.assertEqual(rows, {"baseline": 1, "attack": 40, "control": 0})
        self.assertEqual(dict(app.payload_hits), {"q": 2})            # 1 true + 1 false, +1 baseline
        self.assertEqual(app.requests, 3)

    def test_proof_observed_result_lists_the_points(self):
        _, _, _, _, proof = self._run(_search_app(blind={"q"}), self._post, _JSON_Q_BOOLEAN)
        self.assertIn("body_json:q boolean-based blind", proof["observed_result"])

    def test_not_reproduced_stays_confirmed_without_artifacts(self):
        app = _search_app(blind=())                                    # the fixture ignores q
        target, exchange, run_id, reports, proof = self._run(app, self._post, _JSON_Q_BOOLEAN)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].summary.startswith("tool-reported, not reproduced by the harness: "),
                        reports[0].summary)
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual((proof["baseline_artifact_id"], proof["attack_artifact_id"],
                          tuple(proof["control_artifact_ids"])), ("", "", ()))
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self.assertIn("body_json:q boolean-based blind", proof["observed_result"])
        self.assertEqual(dict(app.payload_hits), {"q": 2})            # it tried, and saw no change

    def test_only_the_reported_parameter_is_replayed(self):
        app = _search_app(blind={"q", "r"})
        _, _, _, reports, proof = self._run(app, self._post, _JSON_R_BOOLEAN)
        self.assertIn("body_json:r", reports[0].summary)
        self.assertEqual(dict(app.payload_hits), {"r": 2})            # q is never mutated

    def test_control_without_the_restriction_probes_the_other_parameter(self):
        original = SqlmapValidator._boolean_probe_fallback

        async def unrestricted(self, finding, exchange, only_params=None):
            return await original(self, finding, exchange)
        app = _search_app(blind={"q", "r"})
        with patch.object(SqlmapValidator, "_boolean_probe_fallback", unrestricted):
            self._run(app, self._post, _JSON_R_BOOLEAN)
        self.assertEqual(dict(app.payload_hits), {"q": 2})            # the first candidate, not r

    def test_time_based_only_point_sends_no_differential(self):
        app = _search_app(blind={"q"})
        target, _, _, reports, proof = self._run(app, self._post, _JSON_Q_TIME_ONLY)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].summary.startswith("tool-reported, not reproduced"))
        self.assertEqual(app.requests, 0)
        self.assertEqual(proof["attack_artifact_id"], "")
        self.assertIn("body_json:q time-based blind", proof["observed_result"])

    def test_get_point_past_the_preflight_cap_is_reproduced(self):
        # The preflight probes the first five parameters; sqlmap reports the sixth.
        app = _search_app(blind={"q"})
        make = lambda t: HttpExchange(                                  # noqa: E731
            url=t.origin + "/search?a=1&b=2&c=3&d=4&e=5&q=x", method="GET",
            request_headers={}, response_status=200, response_body='{"rows": []}')
        _, exchange, run_id, reports, proof = self._run(app, make, _GET_Q_BOOLEAN)
        self.assertIn("sqlmap reported injection at query:q", reports[0].summary)
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        self.assertEqual(dict(app.payload_hits), {"a": 2, "b": 2, "c": 2, "d": 2, "e": 2, "q": 2})

    def test_control_without_the_parser_sends_no_differential_and_names_no_artifacts(self):
        app = _search_app(blind={"q"})                                 # the same blind fixture
        _, _, run_id, reports, proof = self._run(app, self._post, _JSON_Q_BOOLEAN, parser_out=True)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertEqual(app.requests, 0)
        self.assertEqual(proof["attack_artifact_id"], "")
        self.assertFalse(stored_proof_artifacts_resolve(proof))
        self.assertNotIn("body_json:q", proof["observed_result"])


class CoverageCellEvidenceTests(unittest.TestCase):
    """The coverage cell keeps the first 200 characters of a driven leg's evidence."""

    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                          "allowed_hosts": ["127.0.0.1"]})
        self.addCleanup(reset_default_gate)

    def _cell_evidence(self):
        from harness.coverage_tracker import CoverageTracker, endpoint_view
        state = SimpleNamespace(endpoints={"POST /search": SimpleNamespace(
            path="/search", method="POST", access={}, reachable_roles=[], object_scoped=False,
            findings=[], template=None)})
        tracker = CoverageTracker()
        tracker.build(endpoint_view(state), ["anonymous"], {})
        exchange = HttpExchange(url="http://127.0.0.1:5000/search", method="POST",
                                request_headers={"Content-Type": "application/json"},
                                request_body='{"q": "x", "r": "y"}', response_status=200)
        same = httpx.Response(200, content=b"same", request=httpx.Request("POST", exchange.url))

        async def run_leg(*args):
            return await SqlmapValidator(binary="sqlmap").validate(_finding("sqli"), exchange)
        with _sqlmap_says(_JSON_Q_BOOLEAN), \
                patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=same):
            asyncio.run(tracker.drive_coverage_legs(run_leg, driveable={"sqlmap"}, budget=1))
        cells = [c for c in tracker.matrix.cells().values() if c.validator == "sqlmap"]
        self.assertEqual(len(cells), 1)
        return cells[0].evidence

    def test_cell_evidence_starts_with_the_injection_point(self):
        ev = self._cell_evidence(); self.assertTrue(ev.startswith("injection point: body_json:q"), repr(ev))

    def test_control_without_the_parser_keeps_only_the_banner_in_the_cell(self):
        with patch("harness.validators.sqlmap.parse_injection_points", return_value=[]):
            evidence = self._cell_evidence()
        self.assertNotIn("injection point", evidence)


class ObservedResultTests(unittest.TestCase):
    def test_points_are_listed_and_the_cap_is_kept(self):
        result = ValidationResult("sqlmap", "confirmed", "sqli", summary="s" * 900,
                                  injection_points=({"place": "query", "parameter": "id",
                                                     "type": "boolean-based blind"},))
        text = observed_result_of(result)
        self.assertLessEqual(len(text), 500)
        self.assertTrue(text.endswith("[injection points: query:id boolean-based blind]"))

    def test_a_result_without_points_is_unchanged(self):
        self.assertEqual(observed_result_of(ValidationResult("x", "confirmed", "c", summary="a" * 700)),
                         "a" * 500)


if __name__ == "__main__":
    unittest.main()
