"""Cross-request prior context through the public analyze() caller.

Ported from the 2026-10-17 dual-mode audit probe
(reviews/2026-10-17-dual-mode-audit-opus55/evidence/cross_request_probe.py).
Exchange A produces a finding; a later exchange C on the same host must see A's
finding in its agent prompt when the SAME principal analyzes it, and must not
when the principal or the engagement differs.

Only the model boundary is stubbed (a recording stub that emits one finding when
A's marker is in the prompt). State and cache DBs are temporary. Active
validators, discovery and external lookups are off, so no request leaves the
process. The explicit-engagement case is the positive control that the
retrieval path works at all; the other-principal and other-engagement cases are
the negative controls (cross-principal exclusion is a privacy decision, X02).

The standalone same-principal cases are X02. On 1715022a findings from a
standalone call are persisted with captured_principal_id='' (store.persist_findings)
but read back filtered by the real principal (orchestrator_detect ->
store.prior_findings_summary), so the prior context is always empty.
"""
import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import _test_config

_MARK_A = "OBS-A-7731"
_MARK_C = "OBS-C-4410"
_FINDING_SUMMARY = "FINDING-TEXT-A-5521 order object returned with owner field"
_PRIOR_BLOCK = "PRIOR FINDINGS ON THIS HOST"

_FINDING = {
    "vulnerability_class": "idor", "confidence": 0.5, "severity": "medium",
    "owasp_category": "A01:2021-Broken Access Control",
    "summary": _FINDING_SUMMARY, "evidence": "owner_email present in body",
    "suggested_test": "compare the same object as a second principal", "basis": "derived",
    "validation_hints": [],
}


class _RecordingModel:
    """Records every user prompt; emits the finding only for exchange A."""

    def __init__(self):
        self.prompts: list[str] = []

    def _answer(self, user_prompt: str) -> dict:
        self.prompts.append(user_prompt)
        if _MARK_A in user_prompt:
            return {"findings": [dict(_FINDING)], "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        return self._answer(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        return OllamaResult(data=self._answer(user_prompt), prompt_tokens=1, completion_tokens=1)


def _build(model) -> Orchestrator:
    orch = Orchestrator(_test_config())
    orch.ollama = model
    for agent in orch.agent_manager.agents.values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = model
    return orch


def _exchange(path: str, token: str | None, marker: str) -> HttpExchange:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"order_id": int(path.rsplit("/", 1)[-1]), "owner_email": "alice@fixture.test",
                       "status": "delivered", "marker": marker})
    return HttpExchange(url=f"http://localhost{path}", method="GET", request_headers=headers,
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body=body)


class _IsolatedStateCase(unittest.TestCase):
    """Fresh state/cache DBs per test, restored afterwards (store/cache read
    module globals, so leaking them would affect every later test)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="xreq_ctx_")
        self._orig_store_db = store._DB_PATH
        self._orig_cache = cache._cache
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        get_ollama_circuit_breaker("ollama").reset()
        store._DB_PATH = self._orig_store_db
        cache._cache = self._orig_cache
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _second_prompts(self, first: HttpExchange, second: HttpExchange, *,
                        engagement_first: str = "", engagement_second: str = "") -> str:
        """Analyze `first` then `second` through Orchestrator.analyze; return the
        prompts the model saw for `second` only."""
        model = _RecordingModel()
        orch = _build(model)
        r1 = asyncio.run(orch.analyze(first, force_agents=["idor"], bypass_cache=True,
                                      engagement_id=engagement_first))
        self.assertEqual(
            sum(len(r.findings) for r in r1.agent_reports if r.agent == "idor"), 1,
            "precondition: exchange A must produce the stubbed finding")
        seen = len(model.prompts)
        asyncio.run(orch.analyze(second, force_agents=["idor"], bypass_cache=True,
                                 engagement_id=engagement_second))
        prompts = model.prompts[seen:]
        self.assertTrue(prompts, "precondition: the second analysis made no model call")
        return "\n".join(prompts)


class ExplicitEngagementPriorContextTests(_IsolatedStateCase):
    def test_same_principal_same_engagement_sees_prior_finding(self):
        # Positive control (probe case 3): the retrieval path itself works.
        a = _exchange("/api/v1/orders/101", "fixture-alice-token", _MARK_A)
        c = _exchange("/api/v1/orders/202", "fixture-alice-token", _MARK_C)
        joined = self._second_prompts(a, c, engagement_first="eng-probe",
                                      engagement_second="eng-probe")
        self.assertTrue(_PRIOR_BLOCK in joined, "no prior-findings block in the second prompt")
        self.assertTrue(_FINDING_SUMMARY in joined, "A's finding missing from the second prompt")

    def test_other_principal_does_not_see_prior_finding(self):
        # Negative control (probe case 4): cross-principal exclusion holds.
        a = _exchange("/api/v1/orders/101", "fixture-alice-token", _MARK_A)
        c = _exchange("/api/v1/orders/202", "fixture-bob-token", _MARK_C)
        joined = self._second_prompts(a, c, engagement_first="eng-probe",
                                      engagement_second="eng-probe")
        self.assertFalse(_FINDING_SUMMARY in joined, "A's finding leaked into the second prompt")

    def test_other_engagement_never_sees_prior_finding(self):
        # Negative control: a different engagement partition is isolated.
        a = _exchange("/api/v1/orders/101", "fixture-alice-token", _MARK_A)
        c = _exchange("/api/v1/orders/202", "fixture-alice-token", _MARK_C)
        joined = self._second_prompts(a, c, engagement_first="eng-one",
                                      engagement_second="eng-two")
        self.assertFalse(_FINDING_SUMMARY in joined, "A's finding leaked into the second prompt")


class StandalonePriorContextTests(_IsolatedStateCase):
    """Standalone /analyze (no engagement_id) -- the only path the committed
    Burp client uses."""

    def test_standalone_other_principal_does_not_see_prior_finding(self):
        # Negative control: an X02 fix must keep cross-principal exclusion.
        a = _exchange("/api/v1/orders/101", "fixture-alice-token", _MARK_A)
        c = _exchange("/api/v1/orders/202", "fixture-bob-token", _MARK_C)
        self.assertFalse(_FINDING_SUMMARY in self._second_prompts(a, c),
                         "A's finding leaked into another principal's prompt")

    def test_standalone_same_principal_sees_prior_finding(self):
        # X02 (probe case 2).
        a = _exchange("/api/v1/orders/101", "fixture-alice-token", _MARK_A)
        c = _exchange("/api/v1/orders/202", "fixture-alice-token", _MARK_C)
        joined = self._second_prompts(a, c)
        self.assertTrue(_PRIOR_BLOCK in joined,
                        "standalone analyze gave the same principal no prior-findings block")
        self.assertTrue(_FINDING_SUMMARY in joined, "A's finding missing from C's prompt")

    def test_standalone_anonymous_sees_prior_finding(self):
        # X02 (probe case 5): the anonymous principal is one principal too.
        a = _exchange("/api/v1/orders/101", None, _MARK_A)
        c = _exchange("/api/v1/orders/202", None, _MARK_C)
        joined = self._second_prompts(a, c)
        self.assertTrue(_PRIOR_BLOCK in joined,
                        "standalone anonymous analyze gave no prior-findings block")
        self.assertTrue(_FINDING_SUMMARY in joined, "A's finding missing from C's prompt")


if __name__ == "__main__":
    unittest.main()
