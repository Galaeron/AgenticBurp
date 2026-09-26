"""P0-1: caller-level tests that the EvidenceLedger is actually wired into the
live detection/confirmation path, not just a self-contained module (see
evidence_ledger.py's own docstring / harness.test_evidence_ledger for the
ledger's own unit tests -- these are the integration seam).

Drives ONE exchange through the REAL pipeline pieces:
  - agents/base_agent.py's BaseAgent.run() (emits HYPOTHESIS)
  - run_context.py's TargetTransport.execute() (emits PLANNED_ACTION /
    AUTHORIZATION_DECISION / EXECUTION) against a mocked HTTP transport, so no
    real network traffic occurs
  - orchestrator_confirm.ConfirmMixin._validate_findings() (emits
    VALIDATION_DECISION), via a minimal validator that itself sends through the
    real TargetTransport with case_ref=finding.finding_id

and asserts the resulting evidence_ledger.reconstruct(finding_ref) answers the
five audit questions, both from the in-memory default ledger and from the
durable store.py-backed replay (evidence_ledger.reconstruct_persisted).

INSTRUMENTATION-ONLY invariant under test: nothing here asserts on a finding's
verdict/severity/scope being CHANGED by the ledger -- only that the ledger now
RECORDS what already happened.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from harness import store
from harness import evidence_ledger
from harness.agents.base_agent import BaseAgent
from harness.models import HttpExchange, AgentReport, Finding
from harness.run_context import RunContext, TypedRequest
from harness.orchestrator_confirm import ConfirmMixin
from harness.validators.base import Validator, ValidationResult
from harness import confirmation_gate


class _DummyAgent(BaseAgent):
    name = "dummy_p0_1"

    @property
    def specialty_prompt(self) -> str:
        return "dummy specialty for P0-1 wiring test"


class _EchoValidator(Validator):
    """A minimal real validator: it does not fake evidence -- it sends the
    exchange's own URL through the REAL TargetTransport (case_ref=the
    finding's finding_id, exactly the seam the confirmation path is supposed
    to thread through) and confirms iff the mocked target's response says so.
    """
    name = "echo_p0_1"
    finding_classes = {"idor"}
    active = True

    def __init__(self, run_context: RunContext):
        self.run_context = run_context

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        outcome = await self.run_context.target_transport().execute(
            TypedRequest(method="GET", url=exchange.url),
            capability=self.name, case_ref=finding.finding_id)
        confirmed = outcome.ok and "other-users-data" in (outcome.body or "")
        return ValidationResult(
            validator=self.name,
            status="confirmed" if confirmed else "not_confirmed",
            finding_class=finding.vulnerability_class,
            confidence=0.9 if confirmed else 0.1,
            confirmed=confirmed,
            summary="echo probe reached the target and inspected its response",
            evidence=(outcome.body or "")[:200],
        )


class _NoopRegistry:
    """A validator_registry stand-in: returns one validator for 'idor', none
    for anything else (so the negative-control finding's class genuinely has
    no applicable leg -- the exact "validator never ran" scenario)."""
    active_enabled = True

    def __init__(self, validator):
        self._validator = validator

    def for_finding(self, finding, exchange):
        if finding.vulnerability_class == "idor":
            return [self._validator]
        return []


class _FakeOrchestrator(ConfirmMixin):
    """Just enough of Orchestrator's attribute surface for
    ConfirmMixin._validate_findings to run for real."""

    def __init__(self, config, allowed_hosts, validator_registry):
        self.config = config
        self.allowed_hosts = allowed_hosts
        self.validator_registry = validator_registry
        self.max_concurrent_validations = 4


def _mock_transport(body: bytes, status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body)
    return httpx.MockTransport(handler)


class EvidenceLedgerWiringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "ledger_wiring_t.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def _run_pipeline(self, *, confirming_body: bytes):
        """Drives one exchange through base_agent -> TargetTransport ->
        _validate_findings -> confirmation_gate, all real code, and returns
        the finding produced."""
        exchange = HttpExchange(
            url="https://a.test/api/tickets/1", method="GET",
            request_headers={}, response_headers={},
            response_body="", response_status=200,
        )

        # 1. HYPOTHESIS: a real agent, real BaseAgent.run(), a mocked model call.
        agent = _DummyAgent(ollama=AsyncMock(), model="test-model")
        agent.ollama.chat_json = AsyncMock(return_value={
            "findings": [{
                "vulnerability_class": "idor",
                "confidence": 0.6,
                "severity": "medium",
                "summary": "ticket 1 may be readable cross-tenant",
                "evidence": "response included another user's ticket fields",
                "suggested_test": "request /api/tickets/1 as a different principal",
                "basis": "derived",
            }],
        })
        report = await agent.run(exchange, max_body_chars=2000)
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertTrue(finding.finding_id, "base_agent must stamp a finding_id so HYPOTHESIS has a ref")

        # 2 + 3. PLANNED_ACTION / AUTHORIZATION_DECISION / EXECUTION (via
        # TargetTransport) and VALIDATION_DECISION (via _validate_findings),
        # against a mocked HTTP transport -- no real network traffic.
        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=_mock_transport(confirming_body))
        validator = _EchoValidator(run_context)
        orch = _FakeOrchestrator(config={}, allowed_hosts=["a.test"],
                                 validator_registry=_NoopRegistry(validator))
        try:
            await orch._validate_findings(exchange, [report], run_context=run_context)
        finally:
            await run_context.aclose()

        # 4. FINDING_REVISION seam: real confirmation_gate call (a no-op here
        # since the finding is confirmed=True, exactly as it should be --
        # exercised for realism, not because this scenario demotes anything).
        confirmation_gate.apply_confirmation_suppression([report], config={})

        return finding

    async def test_positive_end_to_end_reconstruction_is_complete(self):
        finding = await self._run_pipeline(confirming_body=b"leaked other-users-data field")
        self.assertTrue(finding.confirmed, "the mocked target's response should have confirmed this leg")

        ledger = evidence_ledger.get_default_ledger()
        recon = ledger.reconstruct(finding.finding_id)
        self.assertTrue(recon["complete"], recon)
        self.assertTrue(recon["what_sent"], "PLANNED_ACTION/EXECUTION request refs must be recorded")
        self.assertTrue(recon["what_came_back"], "EXECUTION response refs must be recorded")
        self.assertTrue(recon["why_concluded"], "VALIDATION_DECISION must be recorded")
        self.assertTrue(recon["why_tested"], "HYPOTHESIS must be recorded")

        recipe = ledger.reproduction_recipe(finding.finding_id)
        self.assertTrue(recipe["steps"], "reproduction_recipe must return runnable steps")
        self.assertTrue(recipe["config_fingerprint"] or recipe["code_version"],
                        "reproduction_recipe must carry provenance to reproduce against")

        # Same reconstruction must also be recoverable purely from the durable
        # store (store.py), independent of the in-memory singleton -- this is
        # what report_generator.py / server.py's /findings/{ref}/evidence
        # endpoint actually read.
        persisted_recon = evidence_ledger.reconstruct_persisted(finding.finding_id)
        self.assertTrue(persisted_recon["complete"], persisted_recon)
        self.assertTrue(persisted_recon["what_sent"])
        self.assertTrue(persisted_recon["what_came_back"])
        self.assertTrue(persisted_recon["why_concluded"])

        persisted_recipe = evidence_ledger.reproduction_recipe_persisted(finding.finding_id)
        self.assertTrue(persisted_recipe["steps"])

    async def test_negative_control_untested_finding_is_not_complete(self):
        """A finding whose validator never ran (no applicable leg for its
        class) must be honest: complete=False, with a what_was_never_tested
        entry -- never silently collapsed into the positive/complete shape."""
        exchange = HttpExchange(url="https://a.test/api/widgets", method="GET")
        agent = _DummyAgent(ollama=AsyncMock(), model="test-model")
        agent.ollama.chat_json = AsyncMock(return_value={
            "findings": [{
                "vulnerability_class": "some_untested_class",
                "confidence": 0.4,
                "severity": "low",
                "summary": "a class with no confirmation leg registered",
                "evidence": "e",
                "suggested_test": "t",
                "basis": "assumed",
            }],
        })
        report = await agent.run(exchange, max_body_chars=2000)
        finding = report.findings[0]
        self.assertTrue(finding.finding_id)

        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        # A validator IS registered (for "idor"), but not for this finding's
        # class -- the registry legitimately returns no validators for it.
        validator = _EchoValidator(run_context)
        orch = _FakeOrchestrator(config={}, allowed_hosts=["a.test"],
                                 validator_registry=_NoopRegistry(validator))
        try:
            await orch._validate_findings(exchange, [report], run_context=run_context)
        finally:
            await run_context.aclose()

        self.assertFalse(finding.confirmed)

        ledger = evidence_ledger.get_default_ledger()
        recon = ledger.reconstruct(finding.finding_id)
        self.assertFalse(recon["complete"], recon)
        self.assertTrue(recon["what_was_never_tested"], "must honestly record what was never tested")
        self.assertTrue(recon["why_tested"], "the HYPOTHESIS itself must still be recorded")
        self.assertFalse(recon["why_concluded"], "no VALIDATION_DECISION/FINDING_REVISION was ever reached")

        persisted_recon = evidence_ledger.reconstruct_persisted(finding.finding_id)
        self.assertFalse(persisted_recon["complete"], persisted_recon)
        self.assertTrue(persisted_recon["what_was_never_tested"])

    async def test_events_carry_provenance(self):
        finding = await self._run_pipeline(confirming_body=b"leaked other-users-data field")
        ledger = evidence_ledger.get_default_ledger()
        events = ledger.events_for(finding.finding_id)
        self.assertTrue(events)
        hypothesis_events = [e for e in events if e.event_type == evidence_ledger.EventType.HYPOTHESIS]
        self.assertTrue(hypothesis_events)
        for e in events:
            prov = e.provenance
            self.assertTrue(prov.code_version, f"{e.event_type} missing code_version provenance")
            self.assertTrue(prov.evidence_schema_version)
        # The agent-produced event specifically must carry model + prompt_version
        # (the two provenance fields only an LLM call can supply).
        hyp = hypothesis_events[0]
        self.assertEqual(hyp.provenance.model, "test-model")
        self.assertTrue(hyp.provenance.prompt_version)

    async def test_durable_reconstruction_survives_in_memory_ledger_rotation(self):
        """Negative control / regression for P3-4: bounding the in-memory
        default ledger must never harm the durable read path. Runs the real
        pipeline (as in the positive test above), then floods the in-memory
        default ledger with far more events than its cap so the finding's
        own events get evicted from memory -- and asserts reconstruct_persisted
        (the store.py-backed path server.py / report_generator.py actually
        use) is still complete regardless."""
        finding = await self._run_pipeline(confirming_body=b"leaked other-users-data field")
        self.assertTrue(finding.confirmed)

        default_ledger = evidence_ledger.get_default_ledger()
        cap = default_ledger.max_events
        for i in range(cap * 2):
            default_ledger.record(evidence_ledger.EventType.OBSERVATION,
                                  f"unrelated-rotation-filler-{i}", "filler event")
        self.assertLessEqual(len(default_ledger), cap,
                             "in-memory default ledger must stay bounded after rotation")

        persisted_recon = evidence_ledger.reconstruct_persisted(finding.finding_id)
        self.assertTrue(persisted_recon["complete"], persisted_recon)
        self.assertTrue(persisted_recon["what_sent"])
        self.assertTrue(persisted_recon["what_came_back"])
        self.assertTrue(persisted_recon["why_concluded"])

    async def test_execute_without_case_ref_does_not_pollute_the_ledger(self):
        """A send with no case_ref (the vast majority of harness traffic --
        discovery, scripts, non-finding-linked reads) must not create any
        ledger event: emit()'s empty-finding_ref guard must actually be
        reached from the transport, not just exist in evidence_ledger.py."""
        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=_mock_transport(b"ok"))
        try:
            before = len(evidence_ledger.get_default_ledger())
            outcome = await run_context.target_transport().execute(
                TypedRequest(method="GET", url="https://a.test/unrelated"),
                capability="probe")  # no case_ref
            after = len(evidence_ledger.get_default_ledger())
        finally:
            await run_context.aclose()
        self.assertTrue(outcome.ok)
        self.assertEqual(before, after, "an unlinked send must not add any ledger event")


class EvidenceBlobProducerWiringTests(unittest.IsolatedAsyncioTestCase):
    """FR-2 (F03): _artifact's blob-store wiring at the successful-send call
    site. A good send must durably store a hash-verified request+response
    blob (so the P0-6 resolver can honestly call it resolvable); a blob-store
    failure must NEVER turn that good send into a transport failure -- it must
    instead mark the EXECUTION event's evidence degraded so evidence health,
    not the send outcome, reflects the gap."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "blob_wiring_t.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_successful_send_stores_hash_verified_blobs(self):
        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=_mock_transport(b"a real response body"))
        case_ref = "blob-wiring-finding-1"
        try:
            outcome = await run_context.target_transport().execute(
                TypedRequest(method="GET", url="https://a.test/x"),
                capability="probe", case_ref=case_ref)
        finally:
            await run_context.aclose()
        self.assertTrue(outcome.ok)

        comp = evidence_ledger.reconstruct_persisted(case_ref)["completeness"]
        self.assertTrue(comp["resolvable"], comp)
        self.assertTrue(comp["has_request_blob"] and comp["has_response_blob"], comp)

    async def test_blob_store_failure_never_breaks_the_send_and_marks_degraded(self):
        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=_mock_transport(b"a real response body"))
        case_ref = "blob-wiring-finding-2"
        with patch("harness.store.put_evidence_blob", side_effect=RuntimeError("disk full")):
            try:
                outcome = await run_context.target_transport().execute(
                    TypedRequest(method="GET", url="https://a.test/x"),
                    capability="probe", case_ref=case_ref)
            finally:
                await run_context.aclose()
        # The send itself must succeed regardless of the blob-store failure.
        self.assertTrue(outcome.ok,
                        "a blob-store failure must never turn a good send into a transport failure")

        events = store.ledger_events_for(case_ref)
        executions = [e for e in events if e["event_type"] == "execution"]
        self.assertTrue(executions)
        self.assertTrue(executions[0]["data"].get("evidence_blob_degraded"))
        self.assertNotIn("request_blob", executions[0]["data"])
        self.assertNotIn("response_blob", executions[0]["data"])

        comp = evidence_ledger.reconstruct_persisted(case_ref)["completeness"]
        self.assertFalse(comp["resolvable"], "a degraded/failed blob write must not be reported resolvable")
        self.assertTrue(any("degraded" in m for m in comp["missing"]), comp["missing"])


if __name__ == "__main__":
    unittest.main()
