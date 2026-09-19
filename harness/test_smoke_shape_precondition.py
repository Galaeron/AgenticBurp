"""
End-to-end smoke test for analyze()'s PROACTIVE, shape-driven confirmation legs.

Companion to test_smoke_detection.py (the analyze() detection spine) and
test_smoke_investigate.py (the graph path's proactive legs). It closes the gap
those left: the captured-exchange (analyze) path used to run a confirmation leg
ONLY for a class an agent had already flagged -- so an XML-accepting endpoint
that no agent labelled "xxe" never got its external-entity leg run at all. That
is the exact detection->confirmation coupling documented against the
/api/tickets/import XXE (session 8: "the analyze() path still confirms
per-agent-finding").

This runs the REAL analyze() pipeline against an XML-accepting exchange with the
model SILENT (no agent produces any finding), and asserts the shape-driven XXE
leg still runs and its CONFIRMED result surfaces. The negative control -- a
server whose parser does NOT resolve external entities (no OOB callback) --
proves the test guards CONFIRMATION, and that an unconfirmed shape guess is
dropped rather than left standing as noise.

Hermetic: no GPU, no model, no network. The mutating XML POST is stubbed at
httpx.AsyncClient.request; the OOB collaborator is a stub whose wait_for_hit is
the vulnerable/secure switch. If this goes red, the analyze() proactive leg is
dead even if every unit test of shape_precondition_findings is green.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import httpx
import yaml

_HARNESS = Path(__file__).resolve().parent

from harness import store
from harness import cache
from harness import coordinator
from harness.orchestrator import Orchestrator
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult


# An XML-accepting request with NO query string and NO url-shaped param, so the
# shape router raises the XXE leg and NOT the SSRF one -- keeps the assertion
# unambiguous about which leg confirmed.
_XML_EXCHANGE = HttpExchange(
    url="http://localhost/api/tickets/import",
    method="POST",
    request_headers={"Content-Type": "application/xml", "User-Agent": "smoke-test"},
    request_body='<?xml version="1.0"?><ticket><title>hi</title></ticket>',
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status": "imported"}',
)


class _SilentOllama:
    """Model that returns nothing for every agent, so any XXE finding can only
    come from the shape-driven leg -- never from an agent label."""

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"findings": [], "components": []}, prompt_tokens=1, completion_tokens=1)


class _StubCollaborator:
    """OOB collaborator stand-in. ``hit`` is the vulnerable/secure switch: True
    means the target's parser called back (XXE confirmed), False means it did
    not (entities disabled -- the negative control)."""

    def __init__(self, hit: bool):
        self._hit = hit

    def token(self) -> str:
        return "tok-smoke-0123456789"

    def url(self, token: str) -> str:
        return f"http://collab.invalid/{token}"

    async def wait_for_hit(self, token: str, timeout: float = 6.0) -> bool:
        return self._hit


def _test_config() -> dict:
    """Shipped config with network/GPU/nondeterminism silenced, but the active
    XXE leg deliberately ARMED (active_enabled + allow_mutating_replay) -- this
    test is about the active confirmation path, not detection."""
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = True             # arm active legs
    validators["allow_mutating_replay"] = True      # the XML POST is mutating
    validators.setdefault("xxe", {})["enabled"] = True
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["localhost", "127.0.0.1"]
    return cfg


def _build(hit: bool) -> Orchestrator:
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
    # Inject the OOB switch into the registry's XXE validator (it otherwise uses
    # the shared, network-bound collaborator).
    xxe = orch.validator_registry.validators.get("xxe")
    assert xxe is not None, "xxe validator not registered -- config gate changed?"
    xxe._collab = _StubCollaborator(hit=hit)
    # This is an XXE caller slice, not a sweep of every enabled validator.
    # Unrelated default legs otherwise open real collaborator listeners and wait
    # on their own callbacks despite the test's claimed no-network boundary.
    orch.validator_registry.validators = {"xxe": xxe}
    return orch


class SmokeShapePreconditionTest(unittest.TestCase):
    # Redirect the global state/cache DBs to a temp dir for this class only, then
    # restore -- same discipline as test_smoke_detection (doing it at import time
    # leaks temp paths into the rest of the suite).
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="smoke_shape_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    @staticmethod
    def _xxe_findings(resp):
        return [f for report in resp.agent_reports for f in report.findings
                if f.vulnerability_class == "xxe"]

    def _run(self, hit: bool):
        coordinator.reset_fail_open_stats()
        orch = _build(hit=hit)
        # Stub the mutating XML POST so nothing hits the network; the validator
        # ignores the HTTP response and decides purely on the OOB callback.
        fake_resp = SimpleNamespace(status_code=200, text="", headers={})
        class UnexpectedCollaborator(BaseException):
            """Must escape the production pipeline's recoverable-error handling."""

        with patch.object(httpx.AsyncClient, "request", new=AsyncMock(return_value=fake_resp)), \
             patch("harness.collaborator.shared", side_effect=UnexpectedCollaborator):
            return asyncio.run(orch.analyze(_XML_EXCHANGE, bypass_cache=True))

    def test_shape_driven_xxe_confirms_with_no_agent_label(self):
        resp = self._run(hit=True)
        xxe = self._xxe_findings(resp)
        self.assertTrue(
            xxe,
            "SHAPE-DRIVEN CONFIRMATION IS DEAD: an XML-accepting exchange that no agent "
            "labelled 'xxe' produced no XXE finding even though the OOB callback fired. The "
            "proactive shape leg is not reaching the validator in analyze().",
        )
        self.assertTrue(
            all(f.confirmed for f in xxe),
            "the shape-driven XXE finding surfaced UNCONFIRMED -- it must carry a real "
            "validator confirmation, not a bare shape guess.",
        )

    def test_negative_control_no_callback_drops_the_guess(self):
        resp = self._run(hit=False)
        self.assertEqual(
            self._xxe_findings(resp), [],
            "Smoke test is not guarding CONFIRMATION: an XXE finding survived even though the "
            "external-entity payload produced no out-of-band callback. The unconfirmed shape "
            "leg must be dropped, not left standing as noise.",
        )


if __name__ == "__main__":
    unittest.main()
