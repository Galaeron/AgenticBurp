"""
End-to-end smoke test for Phase 0.1: substantive 2xx responses encountered
during discovery reach full content-level review.

The gap this guards (HARNESS_IMPROVEMENT_NOTES §2 / roadmap Phase 0.1): role_crawl
fetches every probe's response body, but the access-matrix lens only asks "does
this differ across identities?". A response correctly scoped to its authorized
identity that ITSELF leaks (a secret, PII, an internal path) produced no signal
there and was dropped -- it never became an analyzable HttpExchange, so no agent
or deterministic detector ever saw its content. role_crawl now RETAINS those
substantive 2xx responses (`RoleCrawlResult.captured`) and
`orchestrator.review_captured_exchanges` routes each through the full analyze()
pipeline, folding findings into the engagement state.

This runs the REAL analyze() with the model SILENT, so any finding can only come
from the deterministic path -- here the confidential-info response scan (A4),
which matches an AWS key shape with certainty. Two paired captures differing in
exactly one property:

  - leaky:  a 2xx whose body carries an AWS access-key id  -> info_disclosure
  - benign: a structurally identical 2xx with an inert body -> nothing

The benign capture is the negative control: it proves review actually inspects
content rather than flagging every 2xx it is handed. If this goes red, Phase 0.1
is dead even when the role_crawl capture unit tests are green -- the "green
tests, dead pipeline" failure mode, on the recall axis.

Hermetic: no GPU, no model, no network. Captures are supplied as data.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

_HARNESS = Path(__file__).resolve().parent

from harness import store
from harness import cache
from harness import coordinator
from harness import engagement
from harness.orchestrator import Orchestrator, review_captured_exchanges
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult


# An AWS access-key id shape (confidential_info_detector matches \bAKIA[0-9A-Z]{16}\b
# with certainty) embedded in an otherwise ordinary, correctly-scoped 2xx body.
_LEAKY = HttpExchange(
    url="http://localhost/export/backup",
    method="GET",
    request_headers={"Authorization": "Bearer usertok", "User-Agent": "smoke"},
    request_body="",
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"note":"nightly backup","aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}',
    analyst_note="role_crawl discovery capture as 'user' (HTTP 200)",
).model_dump()

_BENIGN = HttpExchange(
    url="http://localhost/health/status",
    method="GET",
    request_headers={"Authorization": "Bearer usertok", "User-Agent": "smoke"},
    request_body="",
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"ok","uptime_seconds":123456}',
    analyst_note="role_crawl discovery capture as 'user' (HTTP 200)",
).model_dump()


class _SilentOllama:
    """Model that returns nothing for every agent, so any finding can only come
    from a deterministic detector -- never from an agent label."""

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"findings": [], "components": []}, prompt_tokens=1, completion_tokens=1)


def _test_config() -> dict:
    """Shipped config with network/GPU/nondeterminism silenced. Active legs stay
    OFF (safe default) -- Phase 0.1 review leans on the deterministic
    confidential-info scan, which runs regardless of the active-mode gate."""
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
    return cfg


def _build() -> Orchestrator:
    orch = Orchestrator(_test_config())
    stub = _SilentOllama()
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub
    return orch


def _disclosure_on(state, path_suffix: str) -> list[dict]:
    """info_disclosure findings the engagement state holds for an endpoint whose
    path ends with `path_suffix`."""
    out: list[dict] = []
    for ep in state.endpoints.values():
        if ep.path.endswith(path_suffix):
            out.extend(f for f in ep.findings if f.get("vulnerability_class") == "info_disclosure")
    return out


class SmokePhase0CaptureReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="smoke_phase0_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _review(self, captured):
        coordinator.reset_fail_open_stats()
        orch = _build()
        state = engagement.EngagementState(host="localhost")
        produced = asyncio.run(review_captured_exchanges(orch, state, captured))
        return state, produced

    def test_leaky_capture_yields_disclosure_finding(self):
        state, produced = self._review([_LEAKY, _BENIGN])
        leaky = _disclosure_on(state, "/export/backup")
        self.assertTrue(
            leaky,
            "PHASE 0.1 REVIEW IS DEAD: a substantive 2xx captured during discovery whose body "
            "carries a live secret produced no info_disclosure finding. Either the capture never "
            "reached analyze(), or its findings never folded back into the engagement state.",
        )
        self.assertGreaterEqual(produced, 1)

    def test_benign_capture_is_negative_control(self):
        state, _ = self._review([_LEAKY, _BENIGN])
        self.assertEqual(
            _disclosure_on(state, "/health/status"), [],
            "Review is not inspecting CONTENT: a benign 2xx with no secret produced an "
            "info_disclosure finding. The capture path must not flag every 2xx it is handed.",
        )


if __name__ == "__main__":
    unittest.main()
