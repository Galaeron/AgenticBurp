"""One request shape gets one sqlmap scan per identity (r9 review).

In r9's longest attempt 65% of sqlmap's requests (90.8k of 139.9k) were the second
or later scan of a shape the run had already scanned. Three causes, all in the
shared execution registry:
- the key carried the finding's class, and the model filed one shape under
  several ('sqli', 'sql_injection', an access-control class);
- with per-parameter coverage cases on, each case ran `sqlmap -p <name>` although
  the worklist's full scan of the same request had tested that parameter (on a
  one-parameter request, the very same scan again);
- an incomplete scan was run again although the target had answered it ~1.5-2k
  times: what stopped it (the timeout) stopped the retry too.

Callers: investigate_engagement over a loopback app with the coverage drive and its
per-parameter cases on (sqlmap's host launch stubbed), and _ConfirmationCache, the
worklist's and the drive's entry into the registry, with a leg that sends through
the run's transport. Each fix has a control that removes it.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from harness import execution_registry
from harness.execution_registry import ExecutionRegistry
from harness.orchestrator_chain import _ConfirmationCache
from harness.run_context import RunContext, TypedRequest
from harness import test_execution_registry as registry_tests
from harness.test_engagement_transport_callers import _EngagementCallerBase, _config
from harness.test_execution_registry import _Counting, _ex, _finding_of, _Target
from harness.validators.base import ValidationResult, Validator
from harness.validators.sqlmap import SqlmapValidator


def _drive_config(*, mutating):
    cfg = _config(mutating=mutating)
    cfg["engagement"]["coverage_drive_legs"] = True
    cfg["engagement"]["coverage_drive_cases"] = True
    return cfg


class PerParameterCaseTests(_EngagementCallerBase, unittest.TestCase):
    """The worklist scans the capture in full; the drive's per-parameter case for its
    query parameter is covered by that scan instead of launching `sqlmap -p`."""

    ROLES = registry_tests.EngagementCallerTests.ROLES
    _investigate = registry_tests.EngagementCallerTests._investigate
    _items = staticmethod(registry_tests.EngagementCallerTests._items)

    def _drive(self, *paths_queries, extra=()):
        # The orchestrator is built from this config before any run patch starts.
        with patch("harness.test_engagement_transport_callers._config", _drive_config):
            return self._investigate([self._items(p, q) for p, q in paths_queries],
                                     extra=extra)

    def test_the_parameter_case_is_covered_by_the_full_scan(self):
        result, _rc, _model, launches, _ = self._drive(("/api/items/1", "q=a"))
        scans = launches.on("/api/items/")
        self.assertEqual(len(scans), 1, scans)
        self.assertNotIn("-p", scans[0])
        stats = result["execution_registry"]["by_validator"]["sqlmap"]
        self.assertGreaterEqual(stats["full_scan_covers"], 1, stats)

    def test_control_without_the_cover_the_case_launches_sqlmap_again(self):
        result, _rc, _model, launches, _ = self._drive(
            ("/api/items/1", "q=a"),
            extra=[patch.object(SqlmapValidator, "full_scan_covers", lambda *a: None)])
        scans = launches.on("/api/items/")
        self.assertEqual(len(scans), 2, scans)                 # the r9 repeat
        self.assertEqual([c[c.index("-p") + 1] for c in scans if "-p" in c], ["q"])


class FullScanCoverPredicateTests(unittest.TestCase):
    """full_scan_covers names only an input a full scan reaches as `-p` would."""

    def _finding(self, loc, name, only=True):
        finding = _finding_of("sqli")
        finding.parameter_location, finding.parameter_name = loc, name
        finding.parameter_only = only
        return finding

    def test_query_and_form_parameters_present_in_the_request(self):
        v = SqlmapValidator()
        query = _ex("http://127.0.0.1/a?q=1&page=2")
        form = _ex("http://127.0.0.1/a", "POST",
                   {"Content-Type": "application/x-www-form-urlencoded"}, "user=x&pw=y")
        self.assertEqual(v.full_scan_covers(self._finding("query", "page"), query), ("query", "page"))
        self.assertEqual(v.full_scan_covers(self._finding("body_form", "pw"), form), ("body_form", "pw"))

    def test_control_absent_json_path_and_unbound_inputs_are_not_covered(self):
        v = SqlmapValidator()
        query = _ex("http://127.0.0.1/a/7?q=1")
        json_body = _ex("http://127.0.0.1/a", "POST", {"Content-Type": "application/json"},
                        '{"q": 1}')
        for finding, exchange in ((self._finding("query", "missing"), query),
                                  (self._finding("path", "id"), query),
                                  (self._finding("body_json", "q"), json_body),
                                  (self._finding("body_form", "q"), json_body),
                                  (self._finding("query", "q", only=False), query)):
            self.assertIsNone(v.full_scan_covers(finding, exchange))

    def test_a_full_scan_that_detected_something_covers_no_case(self):
        registry, validator = ExecutionRegistry(), _Counting()      # confirmed scans
        validator.full_scan_covers = lambda finding, exchange: ("query", "q")
        exchange = _ex("http://127.0.0.1/a?q=1")

        async def go():
            full = _finding_of("sqli")
            await registry.run(validator, full, exchange, case_ref="worklist",
                               call=lambda: validator.validate(full, exchange))
            case = self._finding("query", "q")
            return await registry.run(validator, case, exchange, case_ref="case-q",
                                      call=lambda: validator.validate(case, exchange))
        result = asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)      # the case runs to bind the detection
        self.assertTrue(result.confirmed)


class ClassFreeKeyTests(unittest.TestCase):
    """Findings filing one shape under different classes share one scan."""

    CLASSES = ("sqli", "sql_injection", "insecure_direct_object_reference")

    def _validate_each(self):
        registry, validator = ExecutionRegistry(), _Counting(status="not_confirmed",
                                                             confirmed=False)
        cache = _ConfirmationCache(None, lambda *a: "unused", registry=registry)
        exchange = _ex("http://127.0.0.1/api/items/1?q=a")

        async def go():
            return [await cache.validate(validator, _finding_of(cls), exchange,
                                         case_ref=f"case-{n}")
                    for n, cls in enumerate(self.CLASSES)]
        return asyncio.run(go()), validator

    def test_one_scan_for_every_class_the_shape_was_filed_under(self):
        results, validator = self._validate_each()
        self.assertEqual(len(validator.calls), 1)
        self.assertEqual([r.covered_by for r in results[1:]], ["case-0", "case-0"])

    def test_control_the_r9_key_scans_once_per_class(self):
        with patch.object(execution_registry, "TOOL_SCAN_KEYED", frozenset()):
            _results, validator = self._validate_each()
        # "sql_injection" now reads as sqli (categories), so the class-keyed control
        # scans once per class: sqli and the access-control class.
        self.assertEqual(len(validator.calls), 2)

    def test_other_shape_keyed_legs_still_split_on_the_class(self):
        a = execution_registry.execution_key("ssti", _ex("http://127.0.0.1/a?q=1"), "ssti")
        b = execution_registry.execution_key("ssti", _ex("http://127.0.0.1/a?q=1"), "xss")
        self.assertNotEqual(a, b)


class _Sending(Validator):
    """A tool-scan leg that sends `sends` requests through the run's transport and
    then stops short (its timeout), as sqlmap did on r9's slow routes."""
    finding_classes = {"sqli"}
    active = True

    def __init__(self, ctx, sends, *, name="sqlmap", transient=False):
        self.name, self.ctx, self.sends, self.transient = name, ctx, sends, transient
        self.calls = 0

    async def validate(self, finding, exchange):
        self.calls += 1
        ex = self.ctx.executor()
        for i in range(self.sends):
            await ex.execute(TypedRequest("GET", f"{exchange.url}&n={i}"), capability="sqlmap")
        return ValidationResult(self.name, "error", "sqli",
                                summary=f"{self.name} timed out after 1800s",
                                transient_stop=self.transient)


class AnsweredRetryTests(unittest.TestCase):

    def _three_cases(self, sends, **kw):
        target = _Target()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=2000,
                                gate_config={"active_enabled": True})
        cache = _ConfirmationCache(ctx, lambda *a: "unused",
                                   registry=ExecutionRegistry(ctx.budget, answered_floor=40))
        validator = _Sending(ctx, sends, **kw)

        async def go():
            try:
                return [await cache.validate(validator, _finding_of("sqli"),
                                             _ex(target.base + "/api/slow?q=a"),
                                             case_ref=f"case-{n}") for n in range(3)]
            finally:
                await ctx.aclose()
        try:
            return asyncio.run(go()), validator, target.server.requests
        finally:
            target.close()

    def test_an_answered_scan_that_stopped_short_is_not_run_again(self):
        results, validator, requests = self._three_cases(45)
        self.assertEqual(validator.calls, 1)
        self.assertEqual(requests, 45)
        self.assertEqual(results[0].observed_sends, 45)
        for ref in results[1:]:
            self.assertEqual(ref.sent_count, 0)
            self.assertIn("answered 45 times", ref.summary)

    def test_control_a_scan_with_few_answers_keeps_its_retry(self):
        _results, validator, _ = self._three_cases(5)
        self.assertEqual(validator.calls, 2)               # retry_limit 2, then a reference

    def test_control_a_transient_stop_keeps_its_retry(self):
        _results, validator, _ = self._three_cases(45, transient=True)
        self.assertEqual(validator.calls, 2)

    def test_control_a_leg_that_is_not_a_tool_scan_keeps_its_retry(self):
        _results, validator, _ = self._three_cases(45, name="ssti")
        self.assertEqual(validator.calls, 2)

    def test_control_without_the_floor_the_answered_scan_runs_twice(self):
        with patch.object(ExecutionRegistry, "_answered", staticmethod(lambda *a: 0)):
            _results, validator, requests = self._three_cases(45)
        self.assertEqual((validator.calls, requests), (2, 90))   # the r9 repeat


if __name__ == "__main__":
    unittest.main()
