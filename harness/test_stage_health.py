"""Caller-level coverage for AnalysisPipeline._critique's typed StageOutcome (R08/PR-7).

Before this change, `_critique` returned a bare `(0, 0)` tuple on THREE different
situations -- critique disabled by config, a genuinely healthy pass that reviewed 0
candidates (none met the confidence threshold), and a FAILED pass where the model
call raised (OllamaError or any other Exception), so every candidate finding shipped
UNREVIEWED. All three looked identical to a caller, and a circuit breaker that had
not tripped was not enough to tell them apart -- see harness/analysis_pipeline.py's
old `_critique` and harness/models.py's `StageOutcome`/`AnalysisResponse.degraded`.

This drives the REAL `analyze()` pipeline (harness.orchestrator.Orchestrator; real
routing via force_agents, real deterministic gates, real critique application logic)
through all three modes plus the mandatory negative control. Only the ollama model
boundary is stubbed -- the same idiom as test_pipeline_gate.py's
_SilentModel/_install_silent_model and test_smoke_detection.py's _StubOllama/_build,
whose `_sqli_exchange`/`_SQLI_FINDING`/`_SQLI_ANCHOR`/`_SQLI_CLASS`/`_test_config`
this module reuses directly rather than re-deriving its own prompt anchors.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.confirmation_gate import CONFIRMABLE_CLASS_MARKERS
from harness.ollama_client import OllamaError, OllamaResult
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import (
    _test_config, _sqli_exchange, _SQLI_FINDING, _SQLI_ANCHOR,
)

# The stub answers with the sqli agent's own anchor (below) so real fast-path-free
# force_agents=["sqli"] dispatch gets a real finding, BUT the finding's own class is
# overridden to something outside confirmation_gate.CONFIRMABLE_CLASS_MARKERS ("sql_
# injection" is IN that set). That marker set drives an unrelated, pre-existing
# post-critique relabeling pass (the suppression gate demotes any unconfirmed finding
# of a class with a live-verified leg, stamping its OWN review_verdict/confidence --
# e.g. "inconclusive_unverified" -- regardless of what critique itself did). Using a
# class outside that set keeps this module's assertions about what CRITIQUE itself
# set on review_verdict/confidence unambiguous, without touching or weakening that
# other (unrelated) gate.
_TEST_VULN_CLASS = "business_logic_abuse"
assert not any(marker in _TEST_VULN_CLASS for marker in CONFIRMABLE_CLASS_MARKERS), (
    "test fixture class collides with a confirmation_gate marker; pick another"
)


def _finding_payload() -> dict:
    payload = dict(_SQLI_FINDING)
    payload["vulnerability_class"] = _TEST_VULN_CLASS
    return payload


# Distinct host per test so each run's findings/engagement state can never be
# confused with another test method's, even though the whole class shares one
# class-scoped temp DB (see setUpClass/tearDownClass below).
_HOSTS = [
    "stage-health-disabled.smoke-test.local",
    "stage-health-nocandidates.smoke-test.local",
    "stage-health-failed.smoke-test.local",
    "stage-health-healthy.smoke-test.local",
    "stage-health-distinct-a.smoke-test.local",
    "stage-health-distinct-b.smoke-test.local",
    "stage-health-distinct-c.smoke-test.local",
]


class _CritiqueModeStub:
    """Answers the sqli specialist with a real finding (so critique has a candidate
    to review, unless `detect=False`) and controls the critique pass's OWN model
    call to exercise every StageOutcome mode:
      - `critique_mode="ok"`    -- critique reviews normally (verdict "survived").
      - `critique_mode="raise"` -- critique's model call raises OllamaError, the
        exact failure mode `_critique` is supposed to surface as a FAILED
        StageOutcome instead of silently returning (0, 0).
    Matches on `"adversarial reviewer"`, the anchor unique to
    analysis_pipeline.py's `_CRITIQUE_SYSTEM_PROMPT` (verified: it appears nowhere
    else in the harness's own prompts), and on `_SQLI_ANCHOR`, the sqli agent's own
    unique anchor already used by test_smoke_detection.py's `_StubOllama`.
    """

    def __init__(self, critique_mode: str = "ok", detect: bool = True):
        self.critique_mode = critique_mode
        self.detect = detect

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        if "adversarial reviewer" in system_prompt:
            if self.critique_mode == "raise":
                raise OllamaError("synthetic critique failure injected by test_stage_health")
            return OllamaResult(
                data={"reviews": [{
                    "index": 0, "verdict": "survived",
                    "note": "independent read matches the stated finding",
                    "adjusted_confidence": 0.85,
                }]},
                prompt_tokens=1, completion_tokens=1,
            )
        if self.detect and _SQLI_ANCHOR in system_prompt:
            return OllamaResult(data={"findings": [_finding_payload()], "components": []},
                                 prompt_tokens=1, completion_tokens=1)
        return OllamaResult(data={"findings": [], "components": []},
                             prompt_tokens=1, completion_tokens=1)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        result = await self.chat_json_metered(model, system_prompt, user_prompt, temperature)
        return result.data


def _build(critique_enabled: bool, critique_mode: str = "ok", detect: bool = True) -> Orchestrator:
    cfg = _test_config()
    cfg.setdefault("critique", {})["enabled"] = critique_enabled
    cfg["server"]["allowed_hosts"] = list(cfg["server"].get("allowed_hosts", [])) + _HOSTS
    orch = Orchestrator(cfg)
    stub = _CritiqueModeStub(critique_mode=critique_mode, detect=detect)
    # Replace the LLM client everywhere it is held, same as test_smoke_detection.py
    # / test_degraded_circuit.py / test_pipeline_gate.py's install helpers.
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub
    return orch


def _findings(resp):
    return [f for report in resp.agent_reports for f in report.findings]


def _test_findings(resp):
    return [f for f in _findings(resp) if f.vulnerability_class == _TEST_VULN_CLASS]


class StageHealthTests(unittest.TestCase):
    """R08/PR-7 acceptance: the critique stage's three modes are DISTINCT and
    inspectable, a failed critique degrades the response without dropping
    findings, and a healthy run is never falsely flagged degraded."""

    @classmethod
    def setUpClass(cls):
        # Isolated store/cache for the lifetime of this class only -- restored in
        # tearDownClass, same pattern as test_smoke_detection.py/test_pipeline_gate.py,
        # so this module can never pollute (or be polluted by) the shared dev DB or
        # another test module running in the same process.
        cls._tmp = tempfile.mkdtemp(prefix="stage_health_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        # The shared ollama circuit breaker is a process-wide singleton; a stray
        # OPEN state from another test module must never leak in here, and (the
        # whole point of this module) this stub's synthetic OllamaErrors are
        # raised directly by the stub, never through the real breaker-wrapped
        # OllamaClient.call() -- so they must never be mistaken for a breaker trip.
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        get_ollama_circuit_breaker("ollama").reset()

    def test_critique_disabled_is_completed_but_not_reviewed(self):
        orch = _build(critique_enabled=False)
        resp = asyncio.run(orch.analyze(
            _sqli_exchange(_HOSTS[0]), force_agents=["sqli"], bypass_cache=True))

        self.assertTrue(resp.stage_outcomes, "no StageOutcome recorded for a dispatched exchange")
        for outcome in resp.stage_outcomes:
            self.assertEqual(outcome.name, "critique")
            self.assertEqual(outcome.status, "disabled")
            self.assertEqual(outcome.attempted, 0)
            self.assertEqual(outcome.completed, 0)
            self.assertEqual(outcome.failed, 0)
        self.assertFalse(resp.degraded, "critique being turned OFF by config must not read as degraded")
        self.assertFalse(resp.agents_circuit_open)

        findings = _test_findings(resp)
        self.assertEqual(len(findings), 1, "a disabled critique must still ship the finding")
        self.assertIsNone(findings[0].review_verdict, "an unreviewed finding must carry no verdict")

    def test_critique_with_no_candidates_is_completed_not_disabled(self):
        # critique is ENABLED, but the model produces no findings at all, so
        # _critique's own candidate list is empty. Pre-R08/PR-7 this returned the
        # exact same (0, 0) as the disabled-critique case above; `status` must now
        # tell the two apart even though every count is still 0 in both.
        orch = _build(critique_enabled=True, detect=False)
        resp = asyncio.run(orch.analyze(
            _sqli_exchange(_HOSTS[1]), force_agents=["sqli"], bypass_cache=True))

        self.assertTrue(resp.stage_outcomes)
        for outcome in resp.stage_outcomes:
            self.assertEqual(outcome.name, "critique")
            self.assertEqual(outcome.status, "completed")
            self.assertEqual(outcome.attempted, 0)
            self.assertEqual(outcome.completed, 0)
            self.assertEqual(outcome.failed, 0)
        self.assertFalse(resp.degraded, "0 legitimate candidates to review is healthy, not degraded")
        self.assertFalse(resp.agents_circuit_open)
        self.assertEqual(_test_findings(resp), [])

    def test_critique_failure_is_degraded_and_keeps_the_finding(self):
        orch = _build(critique_enabled=True, critique_mode="raise", detect=True)
        resp = asyncio.run(orch.analyze(
            _sqli_exchange(_HOSTS[2]), force_agents=["sqli"], bypass_cache=True))

        failed = [o for o in resp.stage_outcomes if o.status == "failed"]
        self.assertTrue(failed, f"no FAILED stage outcome recorded: {resp.stage_outcomes}")
        outcome = failed[0]
        self.assertEqual(outcome.name, "critique")
        self.assertEqual(outcome.attempted, 1)
        self.assertEqual(outcome.completed, 0)
        self.assertEqual(outcome.failed, 1)
        self.assertTrue(outcome.reason, "a failed stage must record WHY it failed")
        self.assertEqual(len(outcome.affected_finding_ids), 1)
        self.assertTrue(outcome.affected_finding_ids[0], "affected finding id must be non-empty")

        self.assertTrue(
            resp.degraded,
            "a critique pass that raised and shipped its finding unreviewed must "
            "mark the response degraded",
        )
        # R08's own point: a circuit breaker NOT opening is an insufficient health
        # predicate. This test's synthetic failure is raised directly by the stub,
        # bypassing the real breaker-wrapped OllamaClient entirely -- proving
        # `degraded` comes from the stage outcome, not from the breaker tripping.
        self.assertFalse(
            resp.agents_circuit_open,
            "precondition: this test's synthetic failure must not go through the "
            "real circuit breaker, so `degraded` here must come from the stage "
            "outcome alone, not a breaker trip",
        )

        # The finding must still be PRESENT -- shipped, just unreviewed/flagged --
        # never silently dropped because critique failed.
        findings = _test_findings(resp)
        self.assertEqual(len(findings), 1, "a FAILED critique must not drop the finding it couldn't review")
        self.assertIsNone(findings[0].review_verdict, "an unreviewed finding must carry no review verdict")
        self.assertEqual(findings[0].confidence, _SQLI_FINDING["confidence"],
                          "an unreviewed finding's confidence must be untouched")
        self.assertEqual(resp.findings_reviewed, 0)
        self.assertEqual(resp.findings_rejected, 0)

    def test_three_modes_are_pairwise_distinct(self):
        """The acceptance criterion itself: disabled / no-candidates / failed must
        produce DISTINCT, inspectable outcomes -- not the same ambiguous (0, 0)."""
        disabled = asyncio.run(_build(critique_enabled=False).analyze(
            _sqli_exchange(_HOSTS[4]), force_agents=["sqli"], bypass_cache=True))
        no_candidates = asyncio.run(_build(critique_enabled=True, detect=False).analyze(
            _sqli_exchange(_HOSTS[5]), force_agents=["sqli"], bypass_cache=True))
        failed = asyncio.run(_build(critique_enabled=True, critique_mode="raise").analyze(
            _sqli_exchange(_HOSTS[6]), force_agents=["sqli"], bypass_cache=True))

        statuses = {
            disabled.stage_outcomes[0].status,
            no_candidates.stage_outcomes[0].status,
            failed.stage_outcomes[0].status,
        }
        self.assertEqual(
            statuses, {"disabled", "completed", "failed"},
            f"the three critique modes must produce three distinct statuses, got {statuses}",
        )
        self.assertFalse(disabled.degraded)
        self.assertFalse(no_candidates.degraded)
        self.assertTrue(failed.degraded)

    def test_negative_control_healthy_run_is_not_degraded_and_keeps_findings(self):
        """Mandatory negative control (R08/PR-7 acceptance): a HEALTHY full run --
        critique enabled, reviews its one candidate successfully -- reports
        degraded == False and returns the same finding it always did. No
        false-degraded, no finding loss from this change."""
        orch = _build(critique_enabled=True, critique_mode="ok", detect=True)
        resp = asyncio.run(orch.analyze(
            _sqli_exchange(_HOSTS[3]), force_agents=["sqli"], bypass_cache=True))

        self.assertFalse(resp.degraded, "a healthy critique pass must never read as degraded")
        self.assertFalse(resp.agents_circuit_open)
        self.assertTrue(resp.stage_outcomes)
        for outcome in resp.stage_outcomes:
            self.assertEqual(outcome.status, "completed")
            self.assertEqual(outcome.failed, 0)

        findings = _test_findings(resp)
        self.assertEqual(len(findings), 1, "healthy critique pass lost/duplicated the finding")
        finding = findings[0]
        # The critique pass DID run and touch this finding (proves the healthy
        # path is genuinely exercised here, not accidentally short-circuited) --
        # this is exactly the review-application logic this change did not touch.
        self.assertEqual(finding.review_verdict, "survived")
        self.assertAlmostEqual(finding.confidence, 0.85)
        self.assertEqual(resp.findings_reviewed, 1)
        self.assertEqual(resp.findings_rejected, 0)
        # Everything else about the finding is exactly what the agent originally
        # reported -- unchanged by this PR's typed-outcome plumbing.
        self.assertEqual(finding.vulnerability_class, _TEST_VULN_CLASS)
        self.assertEqual(finding.summary, _SQLI_FINDING["summary"])
        self.assertEqual(finding.evidence, _SQLI_FINDING["evidence"])
        self.assertEqual(finding.severity, _SQLI_FINDING["severity"])


if __name__ == "__main__":
    unittest.main()
