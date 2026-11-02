"""Slice A of the detect -> deterministic -> iterative -> replay loop: a parameter
leg's negative may only refute the finding whose parameter it actually tested.

Before this, the SSTI/command-injection/path-traversal legs tested the first six
top-level parameters and every not_confirmed was a class-level negative, so a
finding about the seventh parameter was demoted as a likely false positive by a
leg that never touched it. The caller tests run the real confirmation caller and
the real suppression gate over a loopback HTTP fixture; only persistence is
stubbed. Each positive has a negative control on a non-evaluating endpoint.
"""
import asyncio
import re
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

from harness import global_throttle
from harness.confirmation_gate import apply_confirmation_suppression
from harness.models import AgentReport, Finding, HttpExchange, sanitize_agent_finding
from harness.orchestrator_confirm import ConfirmMixin
from harness.orchestrator_helpers import confirmation_cache_key
from harness.run_context import RunContext
from harness.validators.injection_targets import (
    NAMED_PARAMETER_UNTESTED, PARTIAL_COVERAGE, select_targets)
from harness.validators.base import ValidationResult
from harness.validators.registry import ValidatorRegistry

_JINJA_MUL = re.compile(r"\{\{(\d+)\*(\d+)\}\}")


class _Handler(BaseHTTPRequestHandler):
    """/render evaluates `{{a*b}}` in `tpl` only; /echo reflects every value literally."""
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        parts = urlsplit(self.path)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        out = []
        for name, value in params.items():
            if parts.path == "/render" and name == "tpl":
                value = _JINJA_MUL.sub(lambda m: str(int(m[1]) * int(m[2])), value)
            out.append(f"{name}={value}")
        body = ("<html>" + " ".join(out) + "</html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _finding(name="", location=""):
    return Finding(vulnerability_class="ssti", confidence=0.85, severity="high",
                   summary="template expression evaluated", evidence="synthetic",
                   suggested_test="tpl={{7*7}}", basis="derived", finding_id="f-1",
                   parameter_location=location, parameter_name=name)


class SelectTargetsTests(unittest.TestCase):
    PARAMS = [("query", c) for c in "abcdef"] + [("query", "tpl")]

    def test_named_parameter_beyond_cap_is_tested_first(self):
        targets, coverage = select_targets(_finding("tpl", "query"), self.PARAMS, 6)
        self.assertEqual(targets[0], ("query", "tpl"))
        self.assertEqual(len(targets), 6)
        self.assertEqual(coverage, "")

    def test_named_parameter_absent_is_untested(self):
        targets, coverage = select_targets(_finding("bio", "body"), self.PARAMS, 6)
        self.assertEqual(targets, self.PARAMS[:6])
        self.assertEqual(coverage, NAMED_PARAMETER_UNTESTED)

    def test_location_mismatch_is_untested(self):
        _, coverage = select_targets(_finding("tpl", "header"), self.PARAMS, 6)
        self.assertEqual(coverage, NAMED_PARAMETER_UNTESTED)

    def test_unnamed_truncated_is_partial(self):
        _, coverage = select_targets(_finding(), self.PARAMS, 6)
        self.assertEqual(coverage, PARTIAL_COVERAGE)

    def test_unnamed_within_cap_is_complete(self):
        targets, coverage = select_targets(_finding(), self.PARAMS[:3], 6)
        self.assertEqual((targets, coverage), (self.PARAMS[:3], ""))

    def test_named_parameter_outside_leg_shape_uses_available(self):
        targets, coverage = select_targets(_finding("tpl"), [("query", "file")], 2,
                                           available=[("query", "file"), ("query", "tpl")])
        self.assertEqual((targets, coverage), ([("query", "tpl"), ("query", "file")], ""))


class AgentParameterFieldTests(unittest.TestCase):
    def test_null_parameter_fields_do_not_fail_the_finding(self):
        raw = {"vulnerability_class": "ssti", "confidence": 0.5, "summary": "s", "evidence": "e",
               "suggested_test": "t", "basis": "derived",
               "parameter_location": None, "parameter_name": None}
        f = Finding(**sanitize_agent_finding(raw))
        self.assertEqual((f.parameter_location, f.parameter_name), ("", ""))

    def test_parameter_is_part_of_the_confirmation_cache_key(self):
        ex = HttpExchange(url="http://t.test/r?a=1&b=2", method="GET")
        self.assertNotEqual(confirmation_cache_key("ssti", ex, "ssti", ("query", "a")),
                            confirmation_cache_key("ssti", ex, "ssti", ("query", "b")))

    def test_run_registry_runs_each_named_parameter_once(self):
        """The run's ExecutionRegistry (the cache every confirmation path shares)
        keys on the named parameter: another parameter is a miss, the same one a hit,
        and an unnamed finding keeps its legacy key."""
        from types import SimpleNamespace
        from harness.execution_registry import ExecutionRegistry, execution_key
        ex = HttpExchange(url="http://t.test/r?a=1&b=2", method="GET")
        calls = []

        def finding(name):
            return Finding(vulnerability_class="ssti", confidence=0.5, summary="s", evidence="e",
                           suggested_test="t", basis="derived",
                           parameter_location="query" if name else "", parameter_name=name)

        async def drive():
            registry = ExecutionRegistry()
            validator = SimpleNamespace(name="ssti")
            for f in (finding("a"), finding("b"), finding("a"), finding(""), finding("")):
                async def call(f=f):
                    calls.append(f.parameter_name)
                    return ValidationResult("ssti", "not_confirmed", "ssti")
                await registry.run(validator, f, ex, case_ref="", call=call)
        asyncio.run(drive())
        self.assertEqual(calls, ["a", "b", ""])
        self.assertEqual(execution_key("ssti", ex, "ssti"),
                         execution_key("ssti", ex, "ssti", parameter=("", "")))


class ParameterBindingCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global_throttle.configure(0)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def run_caller(self, path, finding):
        """Real _validate_findings -> real suppression gate; returns (validation, finding, sent)."""
        async def run():
            hosts = ["127.0.0.1"]
            config = {"server": {"allowed_hosts": hosts},
                      "validators": {"enabled": True, "active_enabled": True}}
            caller = ConfirmMixin()
            caller.config = config
            caller.allowed_hosts = hosts
            caller.validator_registry = ValidatorRegistry(config)
            caller.validator_registry.validators = {
                "ssti": caller.validator_registry.validators["ssti"]}
            exchange = HttpExchange(url=self.base + path, method="GET", response_status=200,
                                    response_body="<html>tpl=hi</html>")
            report = AgentReport(agent="ssti", model="synthetic", findings=[finding])
            context = RunContext.create(allowed_hosts=hosts, config=config,
                                        gate_config={"active_enabled": True})
            before = _Handler.hits
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(caller, "_persist_confirmation_proof", AsyncMock(
                        return_value=(True, {"proof_id": "synthetic"}, ""))))
                    stack.enter_context(patch("harness.store.persist_test_plans"))
                    stack.enter_context(patch("harness.store.persist_validation_submission",
                                              return_value=(True, "")))
                    stack.enter_context(patch("harness.evidence_ledger.emit"))
                    validations, _ = await caller._validate_findings(
                        exchange, [report], run_context=context)
            finally:
                await context.aclose()
            apply_confirmation_suppression([report], validations)
            self.assertEqual(len(validations), 1, validations)
            return validations[0], finding, _Handler.hits - before
        return asyncio.run(run())

    SEVEN = "?a=1&b=2&c=3&d=4&e=5&f=6&tpl=hi"

    def test_named_seventh_parameter_is_confirmed(self):
        v, f, sent = self.run_caller("/render" + self.SEVEN, _finding("tpl", "query"))
        self.assertGreater(sent, 0)
        self.assertEqual(v.status, "confirmed")
        self.assertTrue(f.confirmed)
        self.assertEqual(f.severity, "high")

    def test_unnamed_seventh_parameter_is_inconclusive_not_refuted(self):
        # The leg still only reaches six parameters, so it cannot confirm -- but it
        # must not call the finding a likely false positive either.
        v, f, sent = self.run_caller("/render" + self.SEVEN, _finding())
        self.assertGreater(sent, 0)
        self.assertEqual((v.status, v.control_outcome), ("not_confirmed", PARTIAL_COVERAGE))
        self.assertEqual(f.review_verdict, "inconclusive_unverified")

    def test_named_parameter_not_in_request_is_inconclusive(self):
        v, f, _ = self.run_caller("/render" + self.SEVEN, _finding("bio", "body"))
        self.assertEqual((v.status, v.control_outcome), ("not_confirmed", NAMED_PARAMETER_UNTESTED))
        self.assertEqual(f.review_verdict, "inconclusive_unverified")

    def test_control_named_parameter_tested_and_clean_is_refuted(self):
        # Negative control: the named parameter really was tested and only echoes,
        # so the negative is bound to it and the gate refutes as before.
        v, f, sent = self.run_caller("/echo" + self.SEVEN, _finding("tpl", "query"))
        self.assertGreater(sent, 0)
        self.assertEqual((v.status, v.control_outcome, v.parameter), ("not_confirmed", "", "tpl"))
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")
        self.assertEqual(f.severity, "low")

    def test_control_unnamed_within_cap_and_clean_is_refuted(self):
        v, f, _ = self.run_caller("/echo?a=1&tpl=hi", _finding())
        self.assertEqual((v.status, v.control_outcome), ("not_confirmed", ""))
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")


if __name__ == "__main__":
    unittest.main()
