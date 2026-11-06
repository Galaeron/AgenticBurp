"""Capture-review prompts fit a configured model context window (harness/prompt_budget.py).

Measured motivation (r3, job 0574e29a0799, gemma4:latest at `ollama.num_ctx` 4096):
capture review sent 2,391 agent prompts whose system prompts ran 6-10.6k characters
and user prompts up to 10.9k, about 20k characters in all. Ollama keeps the END of
an oversized prompt and drops its start, which is where the agent's instructions
are: the run logged 88 context truncations and 151 empty model responses.

With a budget (`ollama.num_ctx`, else `prompt_budget.model_context_tokens`, minus
`prompt_budget.answer_tokens`), an oversized prompt is fitted: parts that do not
apply are dropped first, then bodies and specialty text are cut, each cut marked in
the prompt and recorded. Without one (a cloud model) prompts are unchanged.

Hermetic: prompts are built from fixtures, never from run data; no model, no network.
Negative controls follow test_review_frontier_priority's pattern: each check is a
helper, and a ``test_control_*`` twin patches the fitting out in-process and asserts
the same check now fails.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from harness import cache, coordinator, engagement, prompt_budget, security, store
from harness.agents.base_agent import BaseAgent
from harness.agents.plugin import get_plugin_system
from harness.analysis_pipeline import AnalysisPipeline
from harness.models import AgentReport, Finding, HttpExchange
from harness.ollama_client import OllamaResult, _MODEL_STAGE

_HARNESS = Path(__file__).resolve().parent
_MARK = "omitted to fit the model context window"
_FIXED_NONCE = "0123456789abcdef"

# A Juice-Shop-shaped user listing: ~72k characters of JSON in one line, so the
# 6000-character body cap, not the line cap, decides what reaches the prompt.
_LARGE_BODY = json.dumps({"status": "success", "data": [
    {"id": i, "email": f"user{i}@juice-sh.op", "role": "customer", "deluxeToken": "",
     "profileImage": "/assets/public/images/uploads/default.svg", "totpSecret": ""}
    for i in range(400)]})
_LARGE = HttpExchange(
    method="POST", url="http://localhost/api/Users?include=profile",
    request_headers={"Host": "localhost", "User-Agent": "Mozilla/5.0 " + "x" * 80,
                     "Accept": "application/json", "Content-Type": "application/json",
                     "Cookie": "language=en; welcomebanner_status=dismiss",
                     "Authorization": "Bearer usertok"},
    request_body=json.dumps({"email": "new@juice-sh.op", "role": "customer",
                             "comment": "lorem ipsum dolor " * 150}),
    response_status=200,
    response_headers={"Content-Type": "application/json; charset=utf-8",
                      "X-Frame-Options": "SAMEORIGIN", "Access-Control-Allow-Origin": "*",
                      "ETag": 'W/"11a-abc"', "X-Powered-By": "Express"},
    response_body=_LARGE_BODY,
    analyst_note="role_crawl discovery capture as 'user' (HTTP 200)",
)
_SMALL = HttpExchange(
    method="GET", url="http://localhost/rest/products/search?q=apple",
    request_headers={"Host": "localhost", "Authorization": "Bearer usertok"},
    request_body="", response_status=200,
    response_headers={"Content-Type": "application/json; charset=utf-8"},
    response_body='{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","price":1.99}]}',
    analyst_note="role_crawl discovery capture as 'user' (HTTP 200)",
)
_PRIOR = "\n".join(f"- [xss] http://localhost/path{i}: reflected parameter q, finding {i}"
                   for i in range(8))
# The response body as the prompt cuts it (sanitized, secrets redacted): the length
# a record's original_chars and the prompt's "N more characters" marker refer to.
_LARGE_PROMPT_BODY = len(security.redact_secrets_in_body(security.sanitized_exchange(_LARGE).response_body))
# Agents named in the r3 evidence plus a spread of others; the 4096 test runs all.
_NAMED = ("info_disclosure", "http_request_smuggling", "auth", "sqli", "idor", "cors")

# The marker each recorded part leaves in the prompt it was cut from.
_PART_MARKERS = {
    "methodology_notes": ("user", "this prompt leaves out: methodology notes"),
    "shared_rules": ("system", "[Omitted as not applicable to this exchange, to fit the model context window"),
    "specialty_sections": ("system", "[Sections omitted to fit the model context window"),
    "prior_findings": ("user", "prior findings on this host"),
    "request_body": ("user", "more characters " + _MARK),
    "response_body": ("user", "more characters " + _MARK),
    "specialty_text": ("system", "more characters of this guidance " + _MARK),
}


def _budget(num_ctx: int) -> prompt_budget.PromptBudget:
    budget = prompt_budget.from_config({"ollama": {"num_ctx": num_ctx}})
    assert budget is not None
    return budget


def _agents(names=None) -> list[BaseAgent]:
    """Instances of the agents that make a model call (AnomalyAgent overrides run)."""
    ps = get_plugin_system()
    out = []
    for name in (names or ps.list_agents()):
        cls = ps.load_agent_class(name)
        if cls.run is BaseAgent.run:
            out.append(cls(ollama=None, model="m"))
    return out


def _sent(system: str, user: str) -> int:
    return prompt_budget._sent_tokens(system, user)


class _RecordingOllama:
    """Silent model that records every prompt it is sent, with its model_stage."""

    def __init__(self):
        self.calls: list[dict] = []

    def _record(self, kwargs):
        self.calls.append({"stage": _MODEL_STAGE.get(), "system": kwargs["system_prompt"],
                           "user": kwargs["user_prompt"]})

    async def chat_json(self, **kwargs):
        self._record(kwargs)
        return {"findings": [], "components": []}

    async def chat_json_metered(self, **kwargs):
        self._record(kwargs)
        return OllamaResult(data={"findings": [], "components": [], "reviews": []},
                            prompt_tokens=1, completion_tokens=1)


_TMP = None
_ORIG = None


def setUpModule():
    # knowledge.retrieve and prior findings read the store: keep them on an empty one.
    global _TMP, _ORIG
    _TMP = tempfile.mkdtemp(prefix="prompt_budget_")
    _ORIG = (store._DB_PATH, cache._cache)
    store._DB_PATH = Path(_TMP) / "state.db"


def tearDownModule():
    store._DB_PATH, cache._cache = _ORIG
    shutil.rmtree(_TMP, ignore_errors=True)


class BudgetSourceTest(unittest.TestCase):
    def test_no_context_configured_means_no_budget(self):
        self.assertIsNone(prompt_budget.from_config({}))
        self.assertIsNone(prompt_budget.from_config({"ollama": {"base_url": "x"}}))
        with open(_HARNESS / "config.yaml") as f:
            shipped = yaml.safe_load(f)
        self.assertIsNone(prompt_budget.from_config(shipped),
                          "the shipped config must leave prompts unchanged (cloud default)")

    def test_num_ctx_then_model_context_then_answer_room(self):
        b = prompt_budget.from_config({"ollama": {"num_ctx": 4096}})
        self.assertEqual((b.context_tokens, b.source), (4096, "ollama.num_ctx"))
        self.assertEqual(b.prompt_tokens, 4096 - prompt_budget.DEFAULT_ANSWER_TOKENS - 32)
        b = prompt_budget.from_config({"prompt_budget": {"model_context_tokens": 8192,
                                                         "answer_tokens": 2048}})
        self.assertEqual((b.context_tokens, b.source, b.answer_tokens),
                         (8192, "prompt_budget.model_context_tokens", 2048))
        b = prompt_budget.from_config({"ollama": {"num_ctx": 4096},
                                       "prompt_budget": {"model_context_tokens": 32768}})
        self.assertEqual(b.source, "ollama.num_ctx")

    def test_fence_nonce_does_not_move_the_estimate(self):
        # A per-call random nonce must not let a fitted prompt land over budget.
        a = "x <<<UNTRUSTED-DATA-a1b2c3d4e5f6a7b8>>> y"
        b = "x <<<UNTRUSTED-DATA-ffffffffffffffff>>> y"
        self.assertEqual(prompt_budget.estimate_tokens(a), prompt_budget.estimate_tokens(b))


class AgentPromptFitTest(unittest.TestCase):
    def _assert_fitted(self, agent, system, user, record, budget, body_chars):
        name = agent.name
        self.assertIsNotNone(record, f"{name}: an oversized prompt was not fitted")
        self.assertTrue(record["fits"], f"{name}: {record}")
        self.assertLessEqual(_sent(system, user), budget.prompt_tokens, name)
        self.assertEqual(record["budget_tokens"], budget.prompt_tokens)
        self.assertGreater(record["original_tokens"], budget.prompt_tokens)
        parts = {e["part"]: e for e in record["elided"]}
        body = parts.get("response_body")
        self.assertIsNotNone(body, f"{name}: the 72k response body was not reported cut")
        self.assertEqual(body["original_chars"], _LARGE_PROMPT_BODY)
        self.assertLess(body["kept_chars"], min(body_chars, _LARGE_PROMPT_BODY))
        self.assertIn(f"{_LARGE_PROMPT_BODY - body['kept_chars']} more characters {_MARK}", user)
        self._assert_marked(name, system, user, record)

    def _assert_marked(self, name, system, user, record):
        """Never cut silently: each recorded part left its marker in the prompt."""
        prompts = {"system": system, "user": user}
        for entry in record["elided"]:
            where, marker = _PART_MARKERS[entry["part"]]
            self.assertIn(marker, prompts[where], f"{name}: {entry['part']} cut without a marker")
        if record["elided"]:
            self.assertIn(_MARK, system + user)

    def test_large_exchange_fits_at_num_ctx_4096(self):
        budget = _budget(4096)
        agents = _agents()
        self.assertGreater(len(agents), 20)
        for agent in agents:
            body_chars = agent._body_budget(6000)
            with self.subTest(agent=agent.name):
                system, user, record = prompt_budget.fit_agent_prompts(
                    agent, _LARGE, body_chars, _PRIOR, budget)
                self._assert_fitted(agent, system, user, record, budget, body_chars)

    def test_large_exchange_fits_at_num_ctx_8192(self):
        # The 6000-character cap already fits 8192 (r3's ~20k-character prompts fit
        # untouched there), so a larger configured cap makes the fitting engage.
        budget = _budget(8192)
        for agent in _agents():
            body_chars = agent._body_budget(30000)
            with self.subTest(agent=agent.name):
                system, user, record = prompt_budget.fit_agent_prompts(
                    agent, _LARGE, body_chars, _PRIOR, budget)
                if body_chars < 30000 and record is None:
                    continue   # a header-only agent's own body cap already fits
                self._assert_fitted(agent, system, user, record, budget, body_chars)
                # At 8192 the bodies give way before the agent's instructions do.
                self.assertNotIn("specialty_text", {e["part"] for e in record["elided"]})

    def test_named_agents_unfitted_prompt_is_over_budget(self):
        """The fixture is meaningful: unfitted, it overflows both windows."""
        for agent in _agents(_NAMED):
            full = _sent(agent._system_prompt(), agent._user_prompt(_LARGE, agent._body_budget(6000), _PRIOR))
            self.assertGreater(full, _budget(4096).prompt_tokens, agent.name)
            full = _sent(agent._system_prompt(), agent._user_prompt(_LARGE, agent._body_budget(30000), _PRIOR))
            if agent.input_body_chars is None:
                self.assertGreater(full, _budget(8192).prompt_tokens, agent.name)

    def test_small_exchange_prompt_is_unchanged(self):
        # 8192: at 4096 some agents' instructions alone exceed the budget
        # (info_disclosure's ~3.2k estimated tokens), so even a small exchange is fitted.
        budget = _budget(8192)
        with patch("harness.agents.base_agent.secrets.token_hex", return_value=_FIXED_NONCE):
            for agent in _agents(_NAMED):
                body_chars = agent._body_budget(6000)
                system, user, record = prompt_budget.fit_agent_prompts(
                    agent, _SMALL, body_chars, "", budget)
                self.assertIsNone(record, agent.name)
                self.assertEqual(system, agent._system_prompt(), agent.name)
                self.assertEqual(user, agent._user_prompt(_SMALL, body_chars, ""), agent.name)
                self.assertNotIn(_MARK, system + user)

    def _run_prompts(self, agent, exchange, max_body_chars=6000, prior=""):
        stub = _RecordingOllama()
        agent.ollama = stub
        report = asyncio.run(agent.run(exchange, max_body_chars, prior))
        self.assertEqual(len(stub.calls), 1)
        return stub.calls[0], report

    def test_no_budget_sends_prompts_unchanged(self):
        from harness.security import sanitize_for_inference
        with patch("harness.agents.base_agent.secrets.token_hex", return_value=_FIXED_NONCE):
            for agent in _agents(_NAMED):
                agent.prompt_budget = None
                call, report = self._run_prompts(agent, _LARGE, prior=_PRIOR)
                expected = sanitize_for_inference(
                    agent._system_prompt(),
                    agent._user_prompt(_LARGE, agent._body_budget(6000), _PRIOR))
                self.assertEqual((call["system"], call["user"]), expected, agent.name)
                self.assertIsNone(report.prompt_fit)

    def test_run_sends_the_fitted_prompt_and_reports_the_fit(self):
        budget = _budget(4096)
        for agent in _agents(_NAMED):
            agent.prompt_budget = budget
            call, report = self._run_prompts(agent, _LARGE, prior=_PRIOR)
            self.assertLessEqual(_sent(call["system"], call["user"]), budget.prompt_tokens, agent.name)
            self.assertIsNotNone(report.prompt_fit, agent.name)
            self.assertTrue(report.prompt_fit["fits"])
            self._assert_marked(agent.name, call["system"], call["user"], report.prompt_fit)


_EVIDENCE = "the listing returns every account email and role field " * 60


class FitFaultTest(unittest.TestCase):
    def test_a_fitting_fault_sends_the_prompt_unfitted_and_says_so(self):
        agent = _agents(["sqli"])[0]
        agent.prompt_budget = _budget(4096)
        stub = _RecordingOllama()
        agent.ollama = stub
        with patch.object(prompt_budget, "fit_agent_prompts", side_effect=RuntimeError("boom")), \
             patch("harness.agents.base_agent.secrets.token_hex", return_value=_FIXED_NONCE), \
             self.assertLogs("harness.prompt_budget", "WARNING"):
            report = asyncio.run(agent.run(_LARGE, 6000, ""))
            expected_user = agent._user_prompt(_LARGE, 6000, "")
        self.assertIsNone(report.raw_error)
        self.assertEqual(report.prompt_fit, {"fits": False, "error": "RuntimeError", "elided": []})
        self.assertEqual(len(stub.calls), 1)
        from harness.security import sanitize_for_inference
        self.assertEqual(stub.calls[0]["user"], sanitize_for_inference("", expected_user)[1])


class CritiquePromptFitTest(unittest.TestCase):
    def _critique(self, config):
        stub = _RecordingOllama()
        pipeline = AnalysisPipeline(agent_manager=None, effort_budget=None, store=store,
                                    config=config, ollama_client=stub)
        findings = [Finding(vulnerability_class="info_disclosure", confidence=0.9,
                            summary=f"user listing exposes emails ({i})",
                            evidence=f"finding {i}: " + _EVIDENCE[: 2500 + i],
                            suggested_test="GET /api/Users as another user", basis="derived")
                    for i in range(12)]
        report = AgentReport(agent="info_disclosure", model="m", findings=findings)
        outcome, _, _ = asyncio.run(pipeline._critique(_LARGE, [report]))
        calls = [c for c in stub.calls if c["stage"] == "critique"]
        self.assertEqual(len(calls), 1)
        return calls[0], outcome

    def test_oversized_critique_listing_fits_with_marked_evidence(self):
        config = {"critique": {"enabled": True}, "ollama": {"num_ctx": 4096}}
        call, outcome = self._critique(config)
        budget = _budget(4096)
        self.assertEqual(outcome.status, "completed")
        self.assertLessEqual(_sent(call["system"], call["user"]), budget.prompt_tokens)
        self.assertIn(_MARK, call["user"])
        self.assertIsNotNone(outcome.prompt_fit)
        self.assertTrue(outcome.prompt_fit["fits"])
        self.assertEqual(outcome.prompt_fit["elided"][0]["part"], "finding_evidence")
        self.assertEqual(outcome.prompt_fit["elided"][0]["findings"], 12)

    def test_without_budget_critique_listing_is_whole(self):
        call, outcome = self._critique({"critique": {"enabled": True}})
        self.assertNotIn(_MARK, call["user"])
        self.assertIn("finding 11: " + _EVIDENCE[:2511], call["user"])
        self.assertIsNone(outcome.prompt_fit)


def _review_config(num_ctx=None, max_body_chars=None) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["localhost", "127.0.0.1"]
    if num_ctx:
        cfg.setdefault("ollama", {})["num_ctx"] = num_ctx
    if max_body_chars:
        cfg["server"]["max_body_chars"] = max_body_chars
    return cfg


class CaptureReviewElisionTest(unittest.TestCase):
    """Through the real caller: review_captured_exchanges -> Orchestrator.analyze."""

    def setUp(self):
        # A fresh response cache per test: a cached analysis would skip the agents.
        self._dir = tempfile.mkdtemp(prefix="prompt_budget_review_", dir=_TMP)
        cache.init_cache(db_path=os.path.join(self._dir, "cache.db"))

    def _review(self, num_ctx, max_body_chars=None):
        from harness.orchestrator import Orchestrator, review_captured_exchanges
        coordinator.reset_fail_open_stats()
        orch = Orchestrator(_review_config(num_ctx, max_body_chars))
        stub = _RecordingOllama()
        orch.ollama = stub
        for agent in orch.agent_manager.agents.values():
            agent.ollama = stub
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = stub
        coord = getattr(orch, "coordinator", None)
        if coord is not None and hasattr(coord, "ollama"):
            coord.ollama = stub
        state = engagement.EngagementState(host="localhost")
        stats: dict = {}
        asyncio.run(review_captured_exchanges(
            orch, state, [_LARGE.model_dump(), _SMALL.model_dump()], stats=stats))
        agent_calls = [c for c in stub.calls if c["stage"] in orch.agent_manager.agents]
        return orch, stats, agent_calls

    def _check_elided(self, stats, agent_calls, budget, *, small_whole):
        self.assertEqual(stats["reviewed"], 2)
        self.assertTrue(agent_calls, "no agent prompt reached the model")
        over = [c["stage"] for c in agent_calls if _sent(c["system"], c["user"]) > budget.prompt_tokens]
        self.assertEqual(over, [], "agent prompts sent over the context budget")
        captures = {e["capture"]: e for e in stats["elided"]}
        self.assertIn(_LARGE.url, captures, "the large capture's cuts were not reported")
        entry = captures[_LARGE.url]
        self.assertEqual(entry["method"], "POST")
        self.assertTrue(entry["prompts"])
        for prompt in entry["prompts"]:
            self.assertTrue(prompt["fits"], prompt)
            body = [e for e in prompt["elided"] if e["part"] == "response_body"]
            self.assertTrue(body, prompt)
            self.assertEqual(body[0]["original_chars"], _LARGE_PROMPT_BODY)
        small = captures.get(_SMALL.url)
        if small_whole:
            self.assertIsNone(small, "the small capture was reported as cut")
        else:   # instructions may be trimmed, but nothing of its bodies is cut
            for prompt in (small or {}).get("prompts", []):
                self.assertFalse({"request_body", "response_body"} & {e["part"] for e in prompt["elided"]})

    def test_large_capture_is_fitted_and_reported_elided_at_4096(self):
        orch, stats, agent_calls = self._review(4096)
        budget = _budget(4096)
        self.assertTrue(all(a.prompt_budget == budget for a in orch.agent_manager.agents.values()))
        self._check_elided(stats, agent_calls, budget, small_whole=False)
        self.assertTrue(any(_MARK in c["user"] for c in agent_calls))

    def test_large_capture_is_fitted_and_small_left_whole_at_8192(self):
        _, stats, agent_calls = self._review(8192, max_body_chars=30000)
        self._check_elided(stats, agent_calls, _budget(8192), small_whole=True)

    def test_control_without_fitting_the_check_fails(self):
        def unfitted(agent, exchange, body_chars, prior_context, budget):
            return agent._system_prompt(), agent._user_prompt(exchange, body_chars, prior_context), None

        with patch.object(prompt_budget, "fit_agent_prompts", side_effect=unfitted):
            _, stats, agent_calls = self._review(4096)
        with self.assertRaises(AssertionError):
            self._check_elided(stats, agent_calls, _budget(4096), small_whole=False)
        self.assertEqual(stats["elided"], [])

    def test_control_no_budget_reports_nothing_and_sends_whole_prompts(self):
        orch, stats, agent_calls = self._review(None)
        self.assertTrue(all(a.prompt_budget is None for a in orch.agent_manager.agents.values()))
        self.assertEqual(stats["reviewed"], 2)
        self.assertEqual(stats["elided"], [])
        self.assertFalse(any(_MARK in c["system"] + c["user"] for c in agent_calls))


if __name__ == "__main__":
    unittest.main()
