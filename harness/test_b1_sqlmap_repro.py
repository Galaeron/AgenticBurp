"""B1-T4: technique-aware sqlmap reproduction, and the write-endpoint guard.

Reproduction. When sqlmap reports an error-based or UNION point, the harness
reproduces it itself, on that parameter alone, through the run's transport and with
its own payloads (sqlmap's payload is read for context, never sent):
  - error-based: a breaking value and a well-formed, non-original control (the quote
    doubled; 5-0 in a numeric context), each sent twice; confirmed only when a DB
    syntax error answers the breaking value and no DB error the control. A generic
    500, or an ORM/driver type-conversion message, is no signature.
  - UNION: a fresh marker in one projected column; confirmed when it comes back as
    a column value and an echo control does not return it.
An unreproduced detection stays "tool-reported" (evidence_source TOOL_REPORTED), a
candidate proof, never a counted vulnerability and never not_confirmed.

Guard. PUT/PATCH get a light sqlmap (level 1, risk 1, techniques BE) stopped by the
run's tool proxy at WRITE_ENDPOINT_MAX_REQUESTS, each proxied write counted against
the case's mutating ceiling, and their hits are never replayed. DELETE is never
scanned (no restore). A POST reproduction's sends count against the case's ceiling
too. "Could not connect" is an error, not a negative.

sqlmap is never run: its launch returns recorded output (tool_runner.run_process)
or is swapped for the owned stand-in tool of test_tool_traffic_accounting. Every
harness-side send hits a real loopback endpoint; the reproduction targets are backed
by a real SQLite database. Each behaviour has a negative control.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import threading
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate
from harness.test_confirmation_soundness_rve import _finding, _verdicts
from harness.test_proof_artifacts import _ProofCallerBase, _Target
from harness.test_sqlmap_points import _BANNER, _Proc, _sqlmap_says
from harness.test_tool_traffic_accounting import _FAKE_SQLMAP, _AccountingFixture, _sqli
from harness.validators.base import TOOL_REPORTED, proof_limitation_of
from harness.validators.sqlmap import (LIGHT_TECHNIQUES, WRITE_ENDPOINT_MAX_REQUESTS,
                                       SqlmapValidator, _payload_boundary, _union_column_count)

_ERROR_GET = _BANNER + """
sqlmap identified the following injection point(s) with a total of 31 HTTP(s) requests:
---
Parameter: name (GET)
    Type: error-based
    Title: AND error-based - WHERE or HAVING clause (CAST)
    Payload: name=widget' AND 4821=CAST((SELECT 'qzvkq'||'1'||'qpjxq') AS NUMERIC) AND 'aBcD'='aBcD
---
[12:00:05] [INFO] the back-end DBMS is SQLite
[12:00:05] [INFO] GET parameter 'name' is vulnerable. Do you want to keep testing the others?
"""

_UNION_JSON = _BANNER + """
sqlmap identified the following injection point(s) with a total of 52 HTTP(s) requests:
---
Parameter: JSON name ((custom) POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: {"name":"widget' UNION ALL SELECT NULL,'qzvkq'||'AbCdEf'||'qpjxq'-- vXyZ"}
---
[12:00:09] [INFO] (custom) POST parameter 'JSON name' is vulnerable.
"""

_UNREACHABLE = _BANNER + """
[12:00:01] [INFO] testing connection to the target URL
[12:00:11] [CRITICAL] unable to connect to the target URL ('Network is unreachable'). sqlmap is going to retry the request(s)
[12:00:21] [CRITICAL] unable to connect to the target URL ('Network is unreachable')
"""

_ANSWERED_WITH_A_RETRY = _BANNER + """
[12:00:01] [INFO] testing connection to the target URL
[12:00:11] [WARNING] connection timed out to the target URL. sqlmap is going to retry the request(s)
[12:00:15] [INFO] testing if GET parameter 'name' is dynamic
[12:00:30] [WARNING] GET parameter 'name' does not seem to be injectable
[12:00:30] [CRITICAL] all tested parameters do not appear to be injectable.
"""


_ERROR_NUMERIC = _BANNER + """
sqlmap identified the following injection point(s) with a total of 29 HTTP(s) requests:
---
Parameter: id (GET)
    Type: error-based
    Title: AND error-based - WHERE or HAVING clause (CAST)
    Payload: id=5 AND 4821=CAST((SELECT 'qzvkq'||'1'||'qpjxq') AS NUMERIC)
---
[12:00:05] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others?
"""


def _numeric_sqlite_app():
    """GET /item?id=: the id concatenated into SQLite SQL text (no quotes)."""
    db, lock = _sqlite_items()

    def app(method, path, headers, body):
        value = dict(parse_qsl(urlsplit(path).query)).get("id", "")
        app.values[value] += 1
        try:
            with lock:
                db.execute(f"SELECT id, name FROM items WHERE id = {value}").fetchall()
        except sqlite3.Error as exc:
            return 500, json.dumps({"error": f"sqlite3.{type(exc).__name__}: {exc}"})
        return 200, '{"ok": true}'
    app.values = Counter()
    return app


def _parameterized_numeric_app(kind):
    """GET /item?id=: a bound integer parameter -- no SQL text is built from the value.
    "type": any non-integer answers a generic ORM/driver type-conversion error (what a
      Sequelize/Postgres stack says for a bound integer given "5'").
    "quote": only a value with a quote answers a generic ORM error; the value is
      otherwise read as its leading integer ("5-0" -> 5), so a numeric control passes.
    "syntax": any non-integer answers a syntax-shaped message (an input validator), so
      only a non-original control tells it apart from SQL."""
    def app(method, path, headers, body):
        value = dict(parse_qsl(urlsplit(path).query)).get("id", "")
        app.values[value] += 1
        if kind == "quote":
            if "'" in value:
                return 500, ('{"error": "SequelizeDatabaseError: SQLSTATE[HY000]: '
                             'General error: invalid value for a bound parameter"}')
            return 200, '{"ok": true}'
        if value.isdigit():
            return 200, '{"ok": true}'
        if kind == "type":
            return 500, json.dumps({"error": "SequelizeDatabaseError: SQLSTATE[22P02]: invalid "
                                             f"input syntax for type integer: {value!r}"})
        return 500, json.dumps({"error": f"id: syntax error in {value!r}"})
    app.values = Counter()
    return app


def _sqlite_items():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"
                     "INSERT INTO items (name) VALUES ('widget'), ('gadget');")
    return db, threading.Lock()


def _error_app():
    """GET /item?name=: a string-concatenated SQLite query. It answers the same
    {"ok": true} whatever the query matched (so no boolean differential exists) and
    the driver's error text when the query does not parse."""
    db, lock = _sqlite_items()

    def app(method, path, headers, body):
        name = dict(parse_qsl(urlsplit(path).query)).get("name", "")
        app.values[name] += 1
        try:
            with lock:
                db.execute(f"SELECT id, name FROM items WHERE name = '{name}'").fetchall()
        except sqlite3.Error as exc:
            return 500, json.dumps({"error": f"sqlite3.{type(exc).__name__}: {exc}"})
        return 200, '{"ok": true}'
    app.values = Counter()
    return app


def _quote_500_app(*, signature=False):
    """Any quote in the value answers 500 -- a generic page, or (signature=True) a
    DB-error-shaped one for the balanced control too. No SQL behind it either way."""
    def app(method, path, headers, body):
        name = dict(parse_qsl(urlsplit(path).query)).get("name", "")
        app.values[name] += 1
        if "'" in name:
            return 500, ('{"error": "sqlite3.OperationalError: near quote"}' if signature
                         else '{"error": "Internal Server Error"}')
        return 200, '{"ok": true}'
    app.values = Counter()
    return app


def _union_app(*, echo=False):
    """POST /lookup {"name": ...}: string-concatenated SQLite query returning its rows
    as JSON arrays. A failure is a generic 500. echo=True: no SQL at all; the
    endpoint echoes the value it was sent and lists nothing."""
    db, lock = _sqlite_items()

    def app(method, path, headers, body):
        name = json.loads(body or "{}").get("name", "")
        app.requests += 1
        if echo:
            return 200, json.dumps({"query": name, "rows": []})
        try:
            with lock:
                rows = db.execute(f"SELECT id, name FROM items WHERE name = '{name}'").fetchall()
        except sqlite3.Error:
            return 500, '{"error": "Internal Server Error"}'
        return 200, json.dumps({"rows": [list(r) for r in rows]})
    app.requests = 0
    return app


class _ReproCallerBase(_ProofCallerBase, unittest.TestCase):
    """Through Orchestrator._validate_findings inside an entered run, as production."""

    def _get(self, target):
        return HttpExchange(url=target.origin + "/item?name=widget", method="GET",
                            request_headers={}, response_status=200, response_body='{"ok": true}')

    def _get_id(self, target):
        return HttpExchange(url=target.origin + "/item?id=5", method="GET",
                            request_headers={}, response_status=200, response_body='{"ok": true}')

    def _post(self, target):
        return HttpExchange(url=target.origin + "/lookup", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"name": "widget"}', response_status=200,
                            response_body='{"rows": [[1, "widget"]]}')

    def _run(self, app, exchange_for, sqlmap_output, *, extra=(), probe_ceiling=5):
        """probe_ceiling: the case's mutating ceiling for the harness reproduction
        (validators.mutating_ceiling_by_check.sqlmap_technique_probe); None leaves
        the gate's default (max_mutating_requests_per_finding, 1)."""
        target = _Target(app)
        self.addCleanup(target.close)
        exchange = exchange_for(target)
        create = RunContext.create

        def with_ceiling(*a, gate_config=None, **kw):
            gate_config = dict(gate_config or {})
            if probe_ceiling is not None:
                gate_config["mutating_ceiling_by_check"] = {
                    "sqlmap_technique_probe": probe_ceiling}
            return create(*a, gate_config=gate_config, **kw)
        for cm in (_sqlmap_says(sqlmap_output), patch.object(RunContext, "create", with_ceiling),
                   *extra):
            cm.start()
            self.addCleanup(cm.stop)
        run_id, reports, proofs = self._confirm(
            "sqlmap", SqlmapValidator(allowed_hosts=list(self.HOSTS)), _finding("sqli"), exchange)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        return exchange, run_id, reports[0], self._stored_proof(proofs)

    def _assert_tool_reported(self, exchange, run_id, report, proof):
        self.assertTrue(report.summary.startswith("tool-reported, not reproduced"), report.summary)
        self.assertEqual(proof.get("evidence_source"), TOOL_REPORTED)
        self.assertEqual((proof["baseline_artifact_id"], proof["attack_artifact_id"],
                          tuple(proof["control_artifact_ids"])), ("", "", ()))
        # Its own outcome: neither a counted vulnerability nor a negative.
        accounting = self._accounting(run_id, proof, exchange.url, "sqli")
        self.assertEqual(accounting["counts"]["vulnerabilities"], 0, accounting)
        self.assertEqual(accounting["counts"]["tool_reported_cases"], 1, accounting)
        self.assertEqual([i["kind"] for i in accounting["proof_instances"]], ["tool_reported"])


class ErrorBasedReproductionTests(_ReproCallerBase):
    def test_sqlite_error_point_is_reproduced_with_artifacts(self):
        app = _error_app()
        exchange, run_id, report, proof = self._run(app, self._get, _ERROR_GET)
        self.assertIn("sqlmap reported injection at query:name (error-based)", report.summary)
        self.assertIn("a DB error for a breaking value that a balanced control did not produce",
                      report.summary)
        self.assertNotEqual(proof.get("evidence_source"), TOOL_REPORTED)
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        # The harness's own values, never sqlmap's payload: breaking and balanced, twice each.
        self.assertEqual(app.values["widget'"], 2)
        self.assertEqual(app.values["widget''"], 2)
        self.assertFalse(any("CAST" in v for v in app.values), app.values)

    def test_generic_500_for_any_quote_is_not_reproduced(self):
        app = _quote_500_app()
        exchange, run_id, report, proof = self._run(app, self._get, _ERROR_GET)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.values["widget'"], 2, "the breaking value was not sent")

    def test_error_on_the_balanced_control_too_is_not_reproduced(self):
        app = _quote_500_app(signature=True)
        exchange, run_id, report, proof = self._run(app, self._get, _ERROR_GET)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertGreaterEqual(app.values["widget''"], 1, "the balanced control was not sent")

    def test_control_without_the_technique_probe_the_sqlite_point_stays_tool_reported(self):
        """Defect injection: the old path (boolean-only reproduction) on the same
        SQLite endpoint leaves the detection tool-reported."""
        async def none(*a, **kw):
            return None
        app = _error_app()
        exchange, run_id, report, proof = self._run(
            app, self._get, _ERROR_GET,
            extra=[patch.object(SqlmapValidator, "_technique_probe", none)])
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.values["widget'"], 0)


class NumericErrorBasedReproductionTests(_ReproCallerBase):
    """A numeric context's control is a well-formed non-original value (5-0), and only
    a DB syntax error confirms (r-5: the original value as control plus any
    sequelize/sqlstate text confirmed a parameterized endpoint)."""

    def test_sqlite_numeric_point_is_reproduced_with_a_non_original_control(self):
        app = _numeric_sqlite_app()
        exchange, run_id, report, proof = self._run(app, self._get_id, _ERROR_NUMERIC)
        self.assertIn("sqlmap reported injection at query:id (error-based)", report.summary)
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        self.assertEqual(app.values["5'"], 2)
        self.assertEqual(app.values["5-0"], 2)

    def test_parameterized_endpoint_with_a_generic_type_error_is_not_confirmed(self):
        app = _parameterized_numeric_app("type")
        exchange, run_id, report, proof = self._run(app, self._get_id, _ERROR_NUMERIC)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.values["5'"], 2, "the breaking value was not sent")

    def test_generic_orm_error_on_the_breaking_value_alone_is_not_confirmed(self):
        """The control passes here, so only the syntax-signature rule rejects it."""
        app = _parameterized_numeric_app("quote")
        exchange, run_id, report, proof = self._run(app, self._get_id, _ERROR_NUMERIC)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.values["5-0"], 2, "the control was not sent")

    def test_syntax_shaped_error_for_any_non_integer_is_not_confirmed(self):
        """Only the non-original control (5-0, which errors too) rejects it: with the
        original value as the control this endpoint confirmed."""
        app = _parameterized_numeric_app("syntax")
        exchange, run_id, report, proof = self._run(app, self._get_id, _ERROR_NUMERIC)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertGreaterEqual(app.values["5-0"], 1, "the control was not sent")


class UnionReproductionTests(_ReproCallerBase):
    def test_sqlite_union_point_is_reproduced_with_artifacts(self):
        app = _union_app()
        exchange, run_id, report, proof = self._run(app, self._post, _UNION_JSON)
        self.assertIn("sqlmap reported injection at body_json:name (UNION query)", report.summary)
        self.assertIn("a fresh UNION marker returned as a column value", report.summary)
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        # baseline, echo control, the first column's UNION, its repeat
        self.assertEqual(app.requests, 4)

    def test_endpoint_echoing_its_input_is_not_reproduced(self):
        app = _union_app(echo=True)
        exchange, run_id, report, proof = self._run(app, self._post, _UNION_JSON)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.requests, 2)      # baseline and the echo control only


class ReproductionMutatingCeilingTests(_ReproCallerBase):
    """A POST reproduction is a mutating send: each one is counted against the case's
    mutating ceiling under sqlmap_technique_probe, and refused once it is spent."""

    def _reservations(self):
        seen = []
        reserve = SafetyGate._reserve_mutating

        def spy(gate, finding_id, n, validator_name=None):
            ok = reserve(gate, finding_id, n, validator_name)
            if validator_name == "sqlmap_technique_probe":
                seen.append((finding_id, ok[0]))
            return ok
        return seen, patch.object(SafetyGate, "_reserve_mutating", spy)

    def test_each_post_reproduction_send_is_counted_against_the_case(self):
        seen, spy = self._reservations()
        app = _union_app()
        exchange, run_id, report, proof = self._run(app, self._post, _UNION_JSON, extra=[spy])
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        self.assertEqual(len(seen), 4, seen)
        self.assertTrue(all(fid and ok for fid, ok in seen), seen)
        self.assertEqual(len({fid for fid, _ in seen}), 1, "not one case's ceiling")

    def test_without_headroom_for_the_sequence_nothing_is_sent(self):
        """The default ceiling (max_mutating_requests_per_finding: 1)."""
        app = _union_app()
        exchange, run_id, report, proof = self._run(app, self._post, _UNION_JSON,
                                                    probe_ceiling=None)
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.requests, 0)

    def test_a_send_past_the_spent_ceiling_is_refused_by_the_run(self):
        """Defect injection: without the headroom pre-check the run's gate itself
        refuses the fourth send (the ceiling is 3), so the case stays tool-reported."""
        seen, spy = self._reservations()
        app = _union_app()
        roomy = patch.object(SafetyGate, "mutating_headroom", lambda *a, **kw: (99, 0, 99))
        exchange, run_id, report, proof = self._run(app, self._post, _UNION_JSON,
                                                    probe_ceiling=3, extra=[spy, roomy])
        self._assert_tool_reported(exchange, run_id, report, proof)
        self.assertEqual(app.requests, 3)
        self.assertEqual([ok for _, ok in seen], [True, True, True, False])

    def test_negative_control_a_get_reproduction_is_not_a_mutating_send(self):
        seen, spy = self._reservations()
        app = _error_app()
        exchange, run_id, report, proof = self._run(app, self._get, _ERROR_GET,
                                                    probe_ceiling=None, extra=[spy])
        self._assert_counted(run_id, proof, exchange.url, "sqli")
        self.assertEqual(seen, [])


class PayloadContextTests(unittest.TestCase):
    def test_boundary_and_columns_are_read_from_the_reported_payload(self):
        self.assertEqual(_payload_boundary("id=1 AND 1=CAST(x AS INT)"), "")
        self.assertEqual(_payload_boundary("q=x' AND 1=1"), "'")
        self.assertEqual(_payload_boundary("q=x%') AND 1=1"), "%')")
        self.assertEqual(_payload_boundary('{"name":"x\' UNION ALL SELECT NULL-- a"}'), "'")
        self.assertIsNone(_payload_boundary("no keyword"))
        self.assertIsNone(_payload_boundary("q=x`; AND 1=1"))
        self.assertEqual(_union_column_count(
            "q=-1 UNION ALL SELECT NULL,CONCAT(0x71,0x72,0x73),NULL-- -"), 3)
        self.assertEqual(_union_column_count("q=x' UNION ALL SELECT " + ",".join(["NULL"] * 11)), 0)
        self.assertEqual(_union_column_count("q=x' AND 1=1"), 0)


def _put(base):
    return HttpExchange(url=f"{base}/api/records/7", method="PUT",
                        request_headers={"Content-Type": "application/json"},
                        request_body='{"name":"x"}', response_status=200, response_body='{"id": 7}')


_CASE = "case-write-1"
_WRITES_ON = {"active_enabled": True, "allow_mutating_replay": True,
              "mutating_ceiling_by_check": {"sqlmap_tool": WRITE_ENDPOINT_MAX_REQUESTS}}


class WriteEndpointGuardTests(_AccountingFixture, unittest.TestCase):
    """The owned stand-in sqlmap sends I05D_REQUESTS requests through the run's proxy.
    Its writes are counted against the case's mutating ceiling (here raised to the
    write cap for sqlmap_tool), so the case carries a finding id. The stand-in sends
    with the --method it was launched with, so a write scan's sends are writes."""

    def setUp(self):
        super().setUp()
        tool = Path(self.tool).read_text(encoding="utf-8")
        method_aware = tool.replace(
            'req = urllib.request.Request(f"{url}{sep}i05d={i}", headers=headers)',
            'req = urllib.request.Request(f"{url}{sep}i05d={i}", headers=headers, '
            'method=args[args.index("--method") + 1] if "--method" in args else "GET")')
        self.assertNotEqual(method_aware, tool, "the stand-in tool changed shape")
        Path(self.tool).write_text(method_aware, encoding="utf-8")

    def _run_write(self, exchange, *, gate=None, spent=0, finding_id=_CASE, **kw):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=500,
                                gate_config=gate or _WRITES_ON)
        if spent:
            run.gate._reserve_mutating(_CASE, spent, "sqlmap_tool")
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run, **kw)
        finding = _sqli()
        finding.finding_id = finding_id

        async def go():
            try:
                async with run:
                    return await asyncio.wait_for(validator.validate(finding, exchange), 60)
            finally:
                await run.aclose()
        return asyncio.run(go()), run

    def test_put_scan_is_light_and_stops_at_the_write_cap(self):
        self.env["I05D_REQUESTS"] = "60"
        result, run = self._run_write(_put(self.target.base), level=2, risk=2)
        args = self.launched[0]
        self.assertEqual(args[args.index("--level") + 1], "1")
        self.assertEqual(args[args.index("--risk") + 1], "1")
        self.assertEqual(args[args.index("--technique") + 1], LIGHT_TECHNIQUES)
        self.assertEqual(args[args.index("--method") + 1], "PUT")
        self.assertEqual(len(self._tool_requests()), WRITE_ENDPOINT_MAX_REQUESTS)
        self.assertEqual(run.budget.used, WRITE_ENDPOINT_MAX_REQUESTS)
        self.assertNotEqual(result.status, "not_confirmed")    # a capped scan is incomplete
        reason = proof_limitation_of(result)
        for part in ("light sqlmap (write endpoint: PUT /api/records/7)",
                     f"at most {WRITE_ENDPOINT_MAX_REQUESTS} requests", "cap reached"):
            self.assertIn(part, reason)

    def test_patch_is_a_write_endpoint_too(self):
        self.env["I05D_REQUESTS"] = "30"
        exchange = _put(self.target.base)
        exchange.method = "PATCH"
        self._run_write(exchange)
        self.assertEqual(len(self._tool_requests()), WRITE_ENDPOINT_MAX_REQUESTS)

    def test_delete_is_never_scanned(self):
        """No restore exists for a deletion: sqlmap is not launched, nothing is sent,
        and the verdict says why (skipped, not a negative)."""
        self.env["I05D_REQUESTS"] = "30"
        exchange = _put(self.target.base)
        exchange.method = "DELETE"
        result, run = self._run_write(exchange)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("DELETE /api/records/7 is not scanned", result.summary)
        self.assertIn("no restore", result.summary)
        self.assertIn("not a negative result", result.limitation)
        self.assertEqual(self.launched, [])
        self.assertEqual(self.target.requests, [])
        self.assertEqual(run.budget.used, 0)

    def test_each_proxied_write_is_counted_against_the_case(self):
        self.env["I05D_REQUESTS"] = "60"
        _, run = self._run_write(_put(self.target.base))
        self.assertEqual({r[0] for r in self._tool_requests()}, {"PUT"})
        self.assertEqual(run.gate.mutating_headroom(_CASE, "sqlmap_tool")[1],
                         WRITE_ENDPOINT_MAX_REQUESTS)

    def test_a_partly_spent_ceiling_caps_the_scan_at_what_is_left(self):
        self.env["I05D_REQUESTS"] = "60"
        result, run = self._run_write(_put(self.target.base), spent=15)
        self.assertEqual(len(self._tool_requests()), 5)
        self.assertIn("at most 5 requests", proof_limitation_of(result))
        self.assertNotEqual(result.status, "not_confirmed")

    def test_a_spent_ceiling_never_launches_sqlmap(self):
        result, _ = self._run_write(_put(self.target.base), spent=WRITE_ENDPOINT_MAX_REQUESTS)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("mutating-request ceiling is spent", result.summary)
        self.assertEqual(self.launched, [])
        self.assertEqual(self.target.requests, [])

    def test_the_default_ceiling_bounds_the_write_scan(self):
        """No per-check allowance: max_mutating_requests_per_finding (1) applies."""
        self.env["I05D_REQUESTS"] = "60"
        result, _ = self._run_write(_put(self.target.base), gate={
            "active_enabled": True, "allow_mutating_replay": True})
        self.assertEqual(len(self._tool_requests()), 1)
        self.assertNotEqual(result.status, "not_confirmed")

    def test_without_a_case_reference_a_write_is_not_scanned(self):
        result, _ = self._run_write(_put(self.target.base), finding_id="")
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("no case reference", result.summary)
        self.assertEqual(self.launched, [])

    def test_the_proxy_refuses_a_write_past_the_spent_ceiling(self):
        """Defect injection: with the validator's own cap taken off (it sees the whole
        write cap free), the run's proxy still stops the scan once the case's ceiling
        is spent -- its sends carry the case reference."""
        self.env["I05D_REQUESTS"] = "60"
        real = SafetyGate.mutating_headroom
        calls = {"n": 0}

        def first_call_roomy(gate, finding_id, validator_name=None):
            calls["n"] += 1
            return (WRITE_ENDPOINT_MAX_REQUESTS, 0, WRITE_ENDPOINT_MAX_REQUESTS) \
                if calls["n"] == 1 else real(gate, finding_id, validator_name)
        with patch.object(SafetyGate, "mutating_headroom", first_call_roomy):
            result, run = self._run_write(_put(self.target.base), spent=15)
        self.assertEqual(len(self._tool_requests()), 5)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("mutating-request ceiling was reached", result.summary)
        self.assertEqual(run.gate.mutating_headroom(_CASE, "sqlmap_tool")[0], 0)

    def test_negative_control_a_get_scan_is_not_counted_against_the_case(self):
        self.env["I05D_REQUESTS"] = "30"
        exchange = HttpExchange(url=f"{self.target.base}/api/records/7", method="GET",
                                request_headers={}, response_status=200, response_body='{"id": 7}')
        _, run = self._run_write(exchange)
        self.assertEqual(len(self._tool_requests()), 30)
        self.assertEqual(run.gate.mutating_headroom(_CASE, "sqlmap_tool")[1], 0)

    def test_negative_control_a_get_keeps_the_full_scan(self):
        self.env["I05D_REQUESTS"] = "60"
        exchange = HttpExchange(url=f"{self.target.base}/api/records/7", method="GET",
                                request_headers={}, response_status=200, response_body='{"id": 7}')
        result, _ = self._run_write(exchange, level=2, risk=2)
        args = self.launched[0]
        self.assertEqual(args[args.index("--level") + 1], "2")
        self.assertNotIn("--technique", args)
        self.assertEqual(len(self._tool_requests()), 60)
        self.assertNotIn("light sqlmap", result.limitation or "")

    def test_writes_disabled_never_launches_sqlmap(self):
        result, run = self._run_write(_put(self.target.base), gate={"active_enabled": True})
        self.assertEqual(result.status, "blocked", result.summary)
        self.assertEqual(self.launched, [])
        self.assertEqual(self.target.requests, [])

    def test_a_reported_write_hit_is_not_replayed(self):
        output = _ERROR_GET.replace("Parameter: name (GET)", "Parameter: JSON name ((custom) POST)")
        sent = []

        async def spy(*a, **kw):
            sent.append(a)
            return None
        with patch("harness.tool_runner.run_process", return_value=_Proc(output)), \
                patch.object(SqlmapValidator, "_technique_probe", spy), \
                patch.object(SqlmapValidator, "_boolean_probe_fallback", spy):
            result, _ = self._run_write(_put(self.target.base))
            self.assertEqual(sent, [])
            self.assertEqual(result.evidence_source, TOOL_REPORTED)
            self.assertIn("write endpoints are not replayed", result.limitation)
            # Negative control: the same hit on a POST is reproduced (the spy is asked).
            post = _put(self.target.base)
            post.method = "POST"
            self._run_write(post)
            self.assertEqual(len(sent), 1)


class ConnectionFailureTests(_AccountingFixture, unittest.TestCase):
    def _run_get(self, url, **patches):
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=100)
        exchange = HttpExchange(url=url, method="GET", request_headers={},
                                response_status=200, response_body='{"id": 7}')
        validator = SqlmapValidator(binary=_FAKE_SQLMAP, timeout_seconds=30,
                                    allowed_hosts=["127.0.0.1"], run_context=run)

        async def go():
            try:
                async with run:
                    return await asyncio.wait_for(validator.validate(_sqli(), exchange), 60)
            finally:
                await run.aclose()
        return asyncio.run(go())

    def test_sqlmap_unable_to_connect_is_an_error(self):
        with patch("harness.tool_runner.run_process", return_value=_Proc(_UNREACHABLE, 1)):
            result = self._run_get(f"{self.target.base}/api/records/7")
        self.assertEqual(result.status, "error", result.summary)
        self.assertIn("unable to connect", result.summary)
        self.assertIn("not a negative result", result.limitation)

    def test_every_proxied_request_failing_at_the_transport_is_an_error(self):
        """A real closed loopback port: the proxy answers sqlmap 502 for each send."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        self.env["I05D_REQUESTS"] = "3"
        result = self._run_get(f"http://127.0.0.1:{closed}/api/records/7")
        self.assertEqual(len(self.launched), 1, "sqlmap was not launched")
        self.assertEqual(result.status, "error", result.summary)
        self.assertIn("failed at the transport", result.summary)

    def test_negative_control_an_answered_scan_with_one_retry_is_not_confirmed(self):
        with patch("harness.tool_runner.run_process", return_value=_Proc(_ANSWERED_WITH_A_RETRY)):
            result = self._run_get(f"{self.target.base}/api/records/7")
        self.assertEqual(result.status, "not_confirmed", result.summary)

    def test_negative_control_an_answering_target_is_not_an_error(self):
        self.env["I05D_REQUESTS"] = "3"
        result = self._run_get(f"{self.target.base}/api/records/7")
        self.assertEqual(result.status, "not_confirmed", result.summary)


if __name__ == "__main__":
    unittest.main()
