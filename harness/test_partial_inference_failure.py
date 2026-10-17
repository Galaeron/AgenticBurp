"""Partial inference failure must not look like a clean miss (X08).

Drives the public Orchestrator.analyze caller with per-agent stub models (no
Ollama call), temporary state/cache DBs and the smoke config (active validators,
discovery and external lookups off). Covers the 2026-10-17 dual-mode audit's
X08 acceptance:

- one of two dispatched model agents raising -> degraded + partial_inference;
- every model agent failing while a deterministic detector still hits ->
  degraded with the all-agents-failed warning (deterministic reports are not
  model agents and must not mask the outage);
- a JSON reply without a `findings` key -> a schema error on that agent, not a
  clean empty report;
- negative control: a healthy run (every agent answers `{"findings": []}`) is
  unchanged -- not degraded, not partial, no agent errors, no warning.

test_silent_model_failure.py keeps the plain all-agents-down case.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.circuit_breaker import get_ollama_circuit_breaker
from harness.models import HttpExchange
from harness.ollama_client import OllamaError, OllamaResult
from harness.orchestrator import Orchestrator
from harness.test_smoke_detection import _test_config

_AGENTS = ["sqli", "xss"]


class _Model:
    """`reply` is returned for every call; `fail` raises like an unreachable backend."""

    def __init__(self, reply=None, fail=False):
        self.reply = {"findings": [], "components": []} if reply is None else reply
        self.fail = fail
        self.calls = 0

    def _answer(self):
        self.calls += 1
        if self.fail:
            raise OllamaError("synthetic: model backend unreachable (injected by test)")
        return dict(self.reply)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        return self._answer()

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1, **kw):
        return OllamaResult(data=self._answer(), prompt_tokens=1, completion_tokens=1)


def _build(per_agent: dict, default=None) -> Orchestrator:
    orch = Orchestrator(_test_config())
    default = default or _Model()
    orch.ollama = default
    for name, agent in orch.agent_manager.agents.items():
        agent.ollama = per_agent.get(name, default)
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = default
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = default
    return orch


def _exchange(body: str = '{"items": [{"id": 1, "name": "widget"}]}') -> HttpExchange:
    return HttpExchange(url="http://localhost/api/items?id=1", method="GET",
                        request_headers={"User-Agent": "x08-test"}, request_body="",
                        response_status=200, response_headers={"Content-Type": "application/json"},
                        response_body=body)


# A response the deterministic confidential-info scan flags (AWS access key id).
_SECRET_BODY = '{"aws_access_key_id": "AKIAQX4Z7RT2PLM9K3WD"}'


class PartialInferenceFailureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="x08_partial_")
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

    def _analyze(self, orch, exchange=None, agents=_AGENTS):
        return asyncio.run(orch.analyze(exchange or _exchange(), force_agents=list(agents),
                                        bypass_cache=True))

    @staticmethod
    def _model_reports(resp, agents=_AGENTS):
        return [r for r in resp.agent_reports if r.agent in agents]

    def test_one_of_two_model_agents_failing_is_partial_and_degraded(self):
        dead, healthy = _Model(fail=True), _Model()
        resp = self._analyze(_build({"sqli": dead, "xss": healthy}))
        reports = {r.agent: r for r in self._model_reports(resp)}
        self.assertEqual(set(reports), set(_AGENTS), "precondition: both agents dispatched")
        self.assertTrue(reports["sqli"].raw_error)
        self.assertFalse(reports["xss"].raw_error)
        self.assertEqual(len(resp.agent_errors), 1)
        self.assertTrue(resp.agent_errors[0].startswith("sqli:"), resp.agent_errors)
        self.assertTrue(resp.degraded, "a run where a dispatched model agent errored reported degraded=False")
        self.assertTrue(resp.partial_inference)
        self.assertIn("WARNING: 1 of 2 LLM agent(s) failed", resp.summary)

    def test_all_model_agents_failed_with_deterministic_hit_is_still_degraded(self):
        dead = _Model(fail=True)
        resp = self._analyze(_build({"sqli": dead}, default=dead), _exchange(_SECRET_BODY),
                             agents=["sqli"])
        deterministic = [r for r in resp.agent_reports if r.model == "deterministic" and r.findings]
        self.assertTrue(deterministic, "precondition: the deterministic secret scan must hit")
        self.assertTrue(all(r.raw_error for r in self._model_reports(resp, ["sqli"])))
        self.assertTrue(resp.degraded,
                        "a deterministic hit masked the model outage (degraded=False)")
        self.assertIn("WARNING: all 1 LLM agent(s) failed", resp.summary)
        self.assertFalse(resp.partial_inference, "every model agent failed: not partial")
        self.assertTrue(any(f.vulnerability_class == "info_disclosure"
                            for r in deterministic for f in r.findings),
                        "deterministic findings must still ship")

    def test_reply_without_findings_key_is_a_schema_error(self):
        empty_object = _Model(reply={})
        resp = self._analyze(_build({"sqli": empty_object, "xss": empty_object}))
        self.assertEqual(empty_object.calls, 2, "precondition: both agents called the model")
        reports = self._model_reports(resp)
        self.assertTrue(reports and all(r.raw_error for r in reports),
                        "a reply with no 'findings' key became a clean empty report")
        self.assertTrue(all("findings" in r.raw_error for r in reports),
                        [r.raw_error for r in reports])
        self.assertTrue(resp.degraded)
        self.assertEqual(len(resp.agent_errors), 2)

    def test_components_only_reply_is_a_schema_error(self):
        components_only = _Model(reply={"components": []})
        resp = self._analyze(_build({"sqli": components_only}), agents=["sqli"])
        (report,) = self._model_reports(resp, ["sqli"])
        self.assertTrue(report.raw_error)
        self.assertTrue(resp.degraded)

    def test_negative_control_healthy_run_is_unchanged(self):
        healthy = _Model(reply={"findings": [], "components": []})
        resp = self._analyze(_build({}, default=healthy))
        reports = self._model_reports(resp)
        self.assertEqual(len(reports), 2)
        self.assertFalse(any(r.raw_error for r in reports))
        self.assertFalse(resp.degraded)
        self.assertFalse(getattr(resp, "partial_inference", False))
        self.assertEqual(resp.agent_errors, [])
        self.assertNotIn("WARNING", resp.summary)

    def test_negative_control_healthy_run_with_deterministic_hit_is_not_degraded(self):
        healthy = _Model(reply={"findings": [], "components": []})
        resp = self._analyze(_build({}, default=healthy), _exchange(_SECRET_BODY))
        self.assertTrue([r for r in resp.agent_reports if r.model == "deterministic" and r.findings])
        self.assertFalse(resp.degraded)
        self.assertFalse(getattr(resp, "partial_inference", False))
        self.assertNotIn("WARNING", resp.summary)


if __name__ == "__main__":
    unittest.main()
