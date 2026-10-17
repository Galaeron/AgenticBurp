"""Offline real confirmation-caller regression; execution/persistence stubbed only."""
import asyncio
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_confirm import ConfirmMixin
from harness.run_context import RunContext
from harness.validators.registry import ValidatorRegistry

class AgentRoutingCallerTests(unittest.TestCase):
    def exercise(self, label, agent, active=True, scoped=True, method="GET", validator_name="sqlmap"):
        async def run():
            config = {"server": {"allowed_hosts": ["routing.invalid"]},
                      "validators": {"enabled": True, "active_enabled": active}}
            caller = ConfirmMixin()
            caller.config = config
            caller.allowed_hosts = ["routing.invalid"] if scoped else ["outside.invalid"]
            caller.validator_registry = ValidatorRegistry(config)
            caller.validator_registry.validators = {validator_name: caller.validator_registry.validators[validator_name]}
            # No query/body inputs: real preflight has nothing to probe, then
            # real validate reaches the subprocess boundary. No method is mocked.
            exchange = HttpExchange(url="https://routing.invalid/items", method=method,
                                    response_status=200, response_body="ordinary listing")
            finding = Finding(vulnerability_class=label, confidence=0.6, severity="medium",
                              summary="synthetic hypothesis", evidence="synthetic",
                              suggested_test="bounded validation", basis="derived", finding_id="original-id")
            report = AgentReport(agent=agent, model="synthetic", findings=[finding])
            context = RunContext.create(allowed_hosts=caller.allowed_hosts, config=config)
            commands = []
            def fake_run(command, **kwargs):
                self.assertEqual(command[0], "sqlmap")
                self.assertEqual(command[command.index("-u") + 1], exchange.url)
                commands.append(command)
                return subprocess.CompletedProcess(command, 0, "[INFO] no injectable parameter identified", "")
            try:
                with ExitStack() as stack:
                    for target in ("subprocess.Popen", "socket.create_connection",
                                   "httpx.AsyncClient.send", "httpx.Client.send"):
                        stack.enter_context(patch(target, side_effect=AssertionError("unexpected external execution")))
                    stack.enter_context(patch("subprocess.run", side_effect=fake_run))
                    stack.enter_context(patch.object(caller, "_persist_confirmation_proof", AsyncMock(
                        return_value=(True, {"proof_id": "synthetic-negative"}, ""))))
                    plans = stack.enter_context(patch("harness.store.persist_test_plans"))
                    stack.enter_context(patch("harness.store.persist_validation_submission", return_value=(True, "")))
                    stack.enter_context(patch("harness.evidence_ledger.emit"))
                    validations, _ = await caller._validate_findings(exchange, [report], run_context=context)
                    for validation in validations:
                        self.assertEqual(validation.finding_class, label)
                    for call in plans.call_args_list:
                        self.assertEqual(call.args[1][0].finding_class, label)
                    self.assertEqual(finding.vulnerability_class, label)
                    self.assertEqual(finding.finding_id, "original-id")
                    return commands, validations, plans.call_count, finding
            finally:
                await context.aclose()
        return asyncio.run(run())

    def test_canonical_label_reaches_real_sqlmap_execution_boundary(self):
        commands, validations, plans, finding = self.exercise("sqli", "sqli")
        self.assertEqual(len(commands), 1)
        self.assertEqual([v.status for v in validations], ["not_confirmed"])
        self.assertEqual(plans, 1)
        self.assertFalse(finding.confirmed)

    def test_mislabelled_fallback_survives_real_plan_and_validate(self):
        commands, validations, plans, finding = self.exercise("sql_injection", "sqli")
        self.assertEqual(len(commands), 1, "agent fallback must survive plan/validate applies rechecks")
        self.assertEqual([v.status for v in validations], ["not_confirmed"])
        self.assertEqual(plans, 1)
        self.assertFalse(finding.confirmed)

    def test_unknown_agent_does_not_recover_mislabelled_finding(self):
        commands, validations, plans, finding = self.exercise("sql_injection", "unknown")
        self.assertEqual((commands, validations, plans), ([], [], 0))
        self.assertFalse(finding.confirmed)

    def test_active_and_scope_controls_prevent_execution(self):
        for active, scoped in ((False, True), (True, False)):
            with self.subTest(active=active, scoped=scoped):
                commands, validations, plans, finding = self.exercise("sql_injection", "sqli", active, scoped)
                self.assertEqual((commands, validations, plans), ([], [], 0))
                self.assertFalse(finding.confirmed)


    def test_agent_fallback_retains_request_shape_gate(self):
        commands, validations, plans, _ = self.exercise("unmapped_xml_hypothesis", "xxe", validator_name="xxe")
        self.assertEqual(commands, [])
        self.assertEqual([v.status for v in validations], ["skipped"])
        self.assertIn("does not take XML", validations[0].summary)

class RoutingIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_per_validator_label_preference_and_confirmed_identity(self):
        from harness.validators.base import ValidationResult
        observed = []
        class SyntheticValidator:
            active = False
            run_context = None
            version = "test"
            def __init__(self, name, label):
                self.name, self.label = name, label
            def applies(self, finding, exchange):
                return finding.vulnerability_class == self.label
            def plan(self, finding, exchange):
                assert self.applies(finding, exchange)
                return None
            async def validate(self, finding, exchange):
                await asyncio.sleep(0)
                assert self.applies(finding, exchange)
                observed.append((self.name, finding, self.run_context))
                return ValidationResult(self.name, "confirmed", finding.vulnerability_class,
                                        confirmed=True, confidence=0.9, summary="synthetic proof")
        config = {"validators": {"enabled": True}}
        caller = ConfirmMixin()
        caller.config, caller.allowed_hosts = config, ["routing.invalid"]
        caller.validator_registry = ValidatorRegistry(config)
        original_leg = SyntheticValidator("original", "sql_injection")
        fallback_leg = SyntheticValidator("fallback", "sqli")
        caller.validator_registry.validators = {"original": original_leg, "fallback": fallback_leg}
        finding = Finding(vulnerability_class="sql_injection", confidence=0.6, severity="medium",
                          summary="hypothesis", evidence="original evidence", suggested_test="test", basis="derived",
                          finding_id="original-id", parameter_name="id", principal_id="principal")
        report = AgentReport(agent="sqli", model="synthetic", findings=[finding])
        exchange = HttpExchange(url="https://routing.invalid/items", method="GET")
        context = RunContext.create(allowed_hosts=caller.allowed_hosts, config=config)
        proof = AsyncMock(return_value=(True, {"proof_id": "proof"}, ""))
        try:
            with patch.object(caller, "_persist_confirmation_proof", proof), \
                 patch.object(caller, "_oracle_gate", AsyncMock()) as oracle, \
                 patch("harness.store.persist_validation_submission", return_value=(True, "")):
                validations, _ = await caller._validate_findings(exchange, [report], run_context=context)
            self.assertEqual([v.finding_class for v in validations], ["sql_injection"] * 2)
            self.assertIs(observed[0][1], finding)
            routed = observed[1][1]
            self.assertIsNot(routed, finding)
            self.assertEqual(routed.vulnerability_class, "sqli")
            self.assertEqual((routed.finding_id, routed.parameter_name, routed.principal_id),
                             ("original-id", "id", "principal"))
            self.assertTrue(all(item[2] is context for item in observed))
            self.assertIsNone(original_leg.run_context)
            self.assertIsNone(fallback_leg.run_context)
            self.assertTrue(finding.confirmed)
            self.assertEqual((finding.vulnerability_class, finding.evidence),
                             ("sql_injection", "original evidence"))
            self.assertEqual(oracle.call_args.kwargs["routing_finding"], routed)
            self.assertIs(oracle.call_args.args[0], finding)
            self.assertTrue(all(call.kwargs["finding_ref"] == "original-id" for call in proof.call_args_list))
        finally:
            await context.aclose()

    async def test_fallback_validator_mismatched_class_does_not_confirm(self):
        # REPORT_2026-10-15_decisive_reproducibility.md: a validator reached
        # ONLY via the agent-fallback (its own declared classes matched
        # nothing on the finding directly) must never be allowed to confirm
        # the finding by returning confirmed=True for some OTHER, hardcoded
        # claim unrelated to what it was actually asked about -- as
        # auth_sequence did (it ran a username-enumeration check and
        # confirmed an unrelated cleartext_transmission finding with it).
        # This is the general backstop: a SYNTHETIC validator standing in for
        # ANY future validator with the same bug (returns a class that does
        # not match what it was handed) must never confirm.
        from harness.validators.base import ValidationResult
        class MismatchedValidator:
            active = False
            run_context = None
            version = "test"
            name = "mismatched"
            def applies(self, finding, exchange):
                return finding.vulnerability_class == "auth"
            def plan(self, finding, exchange):
                return None
            async def validate(self, finding, exchange):
                await asyncio.sleep(0)
                # Hands back a confirmed result for a DIFFERENT, hardcoded
                # claim ("username_enumeration") regardless of what it was
                # asked about ("auth", the bare agent-fallback sentinel) --
                # exactly auth_sequence's pre-fix shape.
                return ValidationResult(self.name, "confirmed", "username_enumeration",
                                        confirmed=True, confidence=0.9,
                                        summary="unrelated enum proof")
        config = {"validators": {"enabled": True}}
        caller = ConfirmMixin()
        caller.config, caller.allowed_hosts = config, ["routing.invalid"]
        caller.validator_registry = ValidatorRegistry(config)
        caller.validator_registry.validators = {"mismatched": MismatchedValidator()}
        finding = Finding(vulnerability_class="cleartext_transmission", confidence=0.6, severity="medium",
                          summary="hypothesis", evidence="original evidence", suggested_test="test",
                          basis="derived", finding_id="original-id")
        report = AgentReport(agent="auth", model="synthetic", findings=[finding])
        exchange = HttpExchange(url="https://routing.invalid/items", method="GET")
        context = RunContext.create(allowed_hosts=caller.allowed_hosts, config=config)
        proof = AsyncMock(return_value=(True, {"proof_id": "proof"}, ""))
        try:
            with patch.object(caller, "_persist_confirmation_proof", proof), \
                 patch.object(caller, "_oracle_gate", AsyncMock()), \
                 patch("harness.store.persist_validation_submission", return_value=(True, "")):
                validations, _ = await caller._validate_findings(exchange, [report], run_context=context)
            self.assertFalse(finding.confirmed)
            self.assertEqual(len(validations), 1)
            self.assertFalse(validations[0].confirmed)
            self.assertEqual(validations[0].status, "skipped")
            self.assertEqual(validations[0].finding_class, "cleartext_transmission")
        finally:
            await context.aclose()

    async def test_oracle_uses_routed_category_and_stamps_original_passively(self):
        caller = ConfirmMixin()
        caller.config = {}
        caller.validator_registry = ValidatorRegistry({})
        finding = Finding(vulnerability_class="sql_injection", confidence=0.6, severity="medium",
                          summary="hypothesis", evidence="original", suggested_test="test", basis="derived", finding_id="id")
        routed = finding.model_copy(update={"vulnerability_class": "sqli"})
        exchange = HttpExchange(url="https://routing.invalid/items", method="GET")
        with patch("harness.oracle_framework.OracleRegistry.oracle_for", return_value=None) as select, \
             patch("harness.oracle_framework.OracleRegistry.verify", AsyncMock()) as active, \
             patch("harness.oracle_framework.stamp_finding") as stamp:
            await caller._oracle_gate(finding, exchange, routing_finding=routed)
        select.assert_called_once_with(routed, exchange, passive_only=True)
        active.assert_not_called()
        stamp.assert_called_once_with(finding, None)
        self.assertEqual(finding.vulnerability_class, "sql_injection")


class AgentForwardingMutationTests(unittest.TestCase):
    def test_removing_agent_forwarding_is_detected_by_caller_regression(self):
        import inspect
        import io
        import textwrap
        import harness.orchestrator_confirm as confirmation
        source = textwrap.dedent(inspect.getsource(ConfirmMixin._validate_findings))
        mutations = [
            ("finding, exchange, agent=report.agent)", "finding, exchange)"),
            ("self._maybe_replay(validator, routed, exchange)",
             "self._maybe_replay(validator, finding, exchange)"),
            ("validator.plan(routed, exchange)", "validator.plan(finding, exchange)"),
        ]
        for needle, replacement in mutations:
            with self.subTest(mutation=needle):
                self.assertEqual(source.count(needle), 1)
                namespace = dict(vars(confirmation))
                exec(compile(source.replace(needle, replacement), "<routing-mutant>", "exec"), namespace)
                case = AgentRoutingCallerTests("test_mislabelled_fallback_survives_real_plan_and_validate")
                with patch.object(ConfirmMixin, "_validate_findings", namespace["_validate_findings"]):
                    result = unittest.TextTestRunner(stream=io.StringIO()).run(case)
                self.assertEqual(len(result.failures), 1)
                self.assertEqual(result.errors, [])



if __name__ == '__main__':
    unittest.main()
