"""sqlmap tests a path object-id case through its custom injection marker (r9 review).

r9: coverage derives a `path` case (CaseKey("path", "object_id")) for every route
with an object id in its path, but sqlmap's per-parameter dispatch reached only
query and form parameters, so SQL injection in a path segment was never tested
and those cases stayed inconclusive. The case driver now hands the path case to
sqlmap, which marks the object id segment with its custom injection marker (`*`)
and tests that point only (`--param-filter URI`; a marked URL leaves the query
string unparsed).

Caller: the coverage case drive (Orchestrator.investigate_engagement in a run
context) on the loopback fixture of test_param_dispatch_caller; only the sqlmap
process is replaced by a canned result (it runs from the Docker image). Controls:
the path location removed from sqlmap's dispatch (the r9 behaviour), a path input
the request has no object id for, and the validator on a GET with a query string.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch
from urllib.parse import urlsplit

from harness import tool_runner
from harness.coverage_model import CellStatus
from harness.models import Finding, HttpExchange
from harness.test_param_dispatch_caller import _LoopbackDrive
from harness.validators import injection_targets
from harness.validators.sqlmap import SqlmapValidator

SQLI = "WSTG-INPV-05"
_CLEAN = "all tested parameters do not appear to be injectable"


def _fake_sqlmap(argvs):
    def run(cmd, **kw):
        argvs.append(list(cmd))
        return tool_runner.ProcessResult(list(cmd), 0, _CLEAN, "", "exit", "not_needed", "job")
    return run


def _arg(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


class SqlmapPathCaseDriveTest(_LoopbackDrive):

    def _drive(self):
        argvs = []
        with patch.object(tool_runner, "run_process", side_effect=_fake_sqlmap(argvs)):
            matrix, _key, _cases = self._run(
                "/items/7", "note=x", disable=("ssti", "open_redirect"),
                validators_cfg={"sqlmap": {"enabled": True}}, live_context=True)
        cases = {(ck.parameter_location, ck.parameter_name): r
                 for (_identity, _endpoint, check) in matrix.cells() if check == SQLI
                 for ck, r in matrix.cases_for_cell(_identity, _endpoint, check)}
        return cases, argvs

    def test_the_path_case_is_scanned_at_the_marked_object_id_only(self):
        cases, argvs = self._drive()
        marked = [a for a in argvs if urlsplit(_arg(a, "-u") or "").path.endswith("/items/7*")]
        self.assertEqual(len(marked), 1, [_arg(a, "-u") for a in argvs])
        self.assertEqual(_arg(marked[0], "--param-filter"), "URI")
        self.assertNotIn("-p", marked[0])
        path_case = cases[("path", "object_id")]
        self.assertEqual(path_case.status, CellStatus.NOT_DETECTED, path_case.reason)
        # the form parameter keeps its own `-p` dispatch, never marked
        named = [a for a in argvs if _arg(a, "-p") == "note"]
        self.assertEqual(len(named), 1)
        self.assertNotIn("*", _arg(named[0], "-u"))

    def test_control_without_path_dispatch_the_path_case_is_never_scanned(self):
        locations = {**injection_targets.PER_PARAMETER_LOCATIONS,
                     "sqlmap": frozenset({"query", "body_form"})}
        with patch.dict(injection_targets.PER_PARAMETER_LOCATIONS, locations):
            cases, argvs = self._drive()
        self.assertFalse([a for a in argvs if "*" in (_arg(a, "-u") or "")])
        self.assertNotEqual(cases[("path", "object_id")].status, CellStatus.NOT_DETECTED)


class SqlmapPathInputValidatorTest(_LoopbackDrive):
    """The validator on its own, for a GET with a query string."""

    def _validate(self, url, name="object_id", **kw):
        argvs = []
        finding = Finding(vulnerability_class="sqli", confidence=0.5, summary="s", evidence="",
                          suggested_test="t", basis="derived", parameter_location="path",
                          parameter_name=name, parameter_only=True)
        exchange = HttpExchange(method="GET", url=url, request_headers={}, request_body="",
                                response_status=200, response_headers={}, response_body="")
        with patch.object(tool_runner, "run_process", side_effect=_fake_sqlmap(argvs)):
            res = asyncio.run(SqlmapValidator(allowed_hosts=["127.0.0.1"], **kw).validate(finding, exchange))
        return res, argvs

    def test_a_marked_url_keeps_the_query_and_tests_the_segment_only(self):
        res, argvs = self._validate(f"{self.base}/orders/42/lines?sort=asc")
        self.assertEqual(len(argvs), 1)
        self.assertEqual(_arg(argvs[0], "-u"), f"{self.base}/orders/42*/lines?sort=asc")
        self.assertEqual(_arg(argvs[0], "--param-filter"), "URI")
        self.assertEqual(res.status, "not_confirmed")
        self.assertEqual(res.tested_parameters, (("path", "object_id"),))

    def test_control_a_path_without_an_object_id_is_not_tested(self):
        res, argvs = self._validate(f"{self.base}/orders/latest?sort=asc")
        self.assertEqual(argvs, [])
        self.assertEqual(res.status, "skipped")
        self.assertEqual(res.control_outcome, injection_targets.NAMED_PARAMETER_UNTESTED)

    def test_control_a_path_input_other_than_the_object_id_is_not_tested(self):
        res, argvs = self._validate(f"{self.base}/orders/42", name="slug")
        self.assertEqual(argvs, [])
        self.assertEqual(res.control_outcome, injection_targets.NAMED_PARAMETER_UNTESTED)

    def test_control_quick_only_leaves_a_path_input_untested_not_negative(self):
        res, argvs = self._validate(f"{self.base}/orders/42", quick_only=True)
        self.assertEqual(argvs, [])
        self.assertEqual(res.status, "skipped")
        self.assertEqual(res.control_outcome, injection_targets.NAMED_PARAMETER_UNTESTED)


if __name__ == "__main__":
    import unittest
    unittest.main()
