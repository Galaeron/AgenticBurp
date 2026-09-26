"""RB-5/INV-3: investigate_engagement must re-link chains after the second-order
and coverage phases, not only from the pre-those-phases snapshot the 741/771
links compute.

The bug: `chains` was linked from `all_findings` BEFORE the second-order
auto-confirm phase and the coverage-driven phase append their own NEW confirmed
findings into `all_findings`/`state`. A chain whose second constituent only
confirms in one of those later phases was silently absent from the returned
`chains` -- the SCORECARD "0 chains ... did not reproduce" gap. The fix adds one
final best-effort re-link, exposed as the `Orchestrator._relink_chains` seam
(harness/orchestrator_chain.py), after the coverage phase and before the return.

This is a caller-level test of the real `investigate_engagement` control flow.
Offline only: the model boundary is stubbed (following test_pipeline_gate.py's
_SilentModel/_install_silent_model pattern), `engagement_builder.build_engagement`
(real discovery) and `worklist_investigator.investigate_worklist` (the real
per-node agent/network investigation loop) are replaced with synthetic in-memory
fixtures, and the second-order phase's real plant/read HTTP legs
(harness.second_order.auto_confirm_candidates) are replaced with a canned
confirmation -- so a finding "confirmed in the second-order phase" is injected at
exactly the boundary RB-5 describes, with no live Ollama, no network target and
no answer-key read anywhere in the run.

Positive: with the real `_relink_chains` in place, the chain composed from a
pre-existing finding plus the second-order-phase finding IS present in
`result["chains"]`.

Negative control (defect injection): with `_relink_chains` patched to fail (the
seam RB-5 added specifically so this could be disabled), the exact same chain is
ABSENT -- proving the assertion depends on the final re-link, not a tautology.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import yaml

from pathlib import Path

from harness import engagement_builder
from harness import role_crawl
from harness import safety_gate
from harness import worklist_investigator
from harness.engagement import EngagementState
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession

_HARNESS = Path(__file__).resolve().parent

BASE_URL = "http://shop.test/"
HOST = "shop.test"

# The pre-existing finding: present BEFORE the second-order phase runs, so it is
# part of the 741/771 snapshot. Tagged "admin_exposure" (harness.chaining
# _CLASS_TAGS) so it supplies one half of the "admin_exposure+access_control"
# chain rule.
FINDING_A = {
    "url": f"{BASE_URL}admin/config",
    "vulnerability_class": "admin_exposure",
    "severity": "medium",
    "confidence": 0.8,
    "summary": "exposed admin config endpoint",
    "evidence": "GET /admin/config returned 200 without authentication",
    "confirmed": True,
    "basis": "observed",
}

# The later-phase finding: only appears once the (stubbed) second-order
# auto-confirm phase runs, well after the 741/771 links were computed. Tagged
# "idor" -> "access_control", the other half of the same chain rule.
FINDING_B = {
    "url": f"{BASE_URL}api/notes/2",
    "vulnerability_class": "idor",
    "severity": "high",
    "confidence": 0.9,
    "summary": "second-order-confirmed cross-identity object read",
    "evidence": "second-order plant/trigger differential confirmed the read",
    "confirmed": True,
    "basis": "observed",
    "confirmation_method": "second_order",
}

CHAIN_SIGNATURE = "potential-attack-chain:admin_exposure+access_control"


class _SilentModel:
    """Stand-in for OllamaClient that returns nothing -- the only stubbed model
    boundary, mirroring test_pipeline_gate.py. Not expected to be called on the
    synthetic path this test drives, but installed anyway per the offline-only
    requirement."""

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=1, completion_tokens=1)


def _install_silent_model(orch: Orchestrator) -> None:
    stub = _SilentModel()
    orch.ollama = stub
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    v = cfg.setdefault("validators", {})
    v["allow_mutating_replay"] = True  # gates the second-order block below
    for k in ("autonomous_discovery", "github_advisories", "kev_check",
              "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    eng_cfg = cfg.setdefault("engagement", {})
    eng_cfg["auto_escalate"] = False
    eng_cfg["feature_crawl"] = False
    eng_cfg["coverage_drive_legs"] = False  # exercise the non-driven coverage path
    cfg.setdefault("server", {})["allowed_hosts"] = [HOST]
    return cfg


async def _fake_build_engagement(base_url, roles, **kw):
    """Replaces the real discovery pipeline (engagement_builder.build_engagement)
    with a minimal, already-built EngagementState + an empty RoleCrawlResult --
    no network, no loopback server needed at all. FINDING_A is seeded onto the
    state's worklist-investigation output instead (see
    _fake_investigate_worklist), matching what a real discovered-then-confirmed
    finding looks like by the time the 741/771 links run."""
    state = EngagementState(host=HOST)
    rc = role_crawl.RoleCrawlResult(base_url=base_url)
    return state, rc


async def _fake_investigate_worklist(*args, **kwargs):
    """Replaces worklist_investigator.investigate_worklist (the real per-node
    agent/network investigation loop) with a canned single outcome carrying
    FINDING_A -- this is what `all_findings` holds BEFORE the second-order phase
    runs, i.e. exactly what the 741/771 links see."""
    return [{"path": "/admin/config", "method": "GET", "findings_detail": [dict(FINDING_A)]}]


class _EngagementRelinkRun:
    """One investigate_engagement call with the discovery/worklist/model
    boundaries stubbed and the second-order phase's real plant/read HTTP legs
    replaced by a canned confirmation of FINDING_B. `disable_relink=True` patches
    out the RB-5 seam (Orchestrator._relink_chains) to prove the negative
    control."""

    def __init__(self, *, disable_relink: bool = False):
        self.disable_relink = disable_relink

    def run(self) -> dict:
        orch = Orchestrator(_config())
        orch.allowed_hosts = [HOST]
        _install_silent_model(orch)

        stack = [
            patch.object(engagement_builder, "build_engagement",
                        new=_fake_build_engagement),
            patch.object(worklist_investigator, "investigate_worklist",
                        new=_fake_investigate_worklist),
            # The second-order phase's real network plant/read legs are never
            # reached here -- this replaces harness.second_order.auto_confirm_
            # candidates itself, injecting FINDING_B exactly at the "confirmed
            # in the second-order phase" boundary RB-5 describes.
            patch("harness.second_order.auto_confirm_candidates",
                 new=AsyncMock(return_value=[dict(FINDING_B)])),
        ]
        if self.disable_relink:
            stack.append(patch.object(
                Orchestrator, "_relink_chains",
                side_effect=RuntimeError("defect-injection: re-link disabled")))

        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"allow_mutating_replay": True})
        try:
            with _nest(stack):
                return asyncio.run(orch.investigate_engagement(
                    BASE_URL, ROLES, max_nodes=8, step_budget=4,
                    max_chain_rounds=1, discovery_max_probes=10))
        finally:
            safety_gate.reset_default_gate()


class _nest:
    """Enter a list of context managers together (py<3.10-friendly, explicit;
    matches harness/test_pipeline_gate.py's helper of the same shape)."""
    def __init__(self, mgrs):
        self._mgrs = mgrs
        self._entered = []

    def __enter__(self):
        for m in self._mgrs:
            m.__enter__()
            self._entered.append(m)
        return self

    def __exit__(self, *exc):
        for m in reversed(self._entered):
            m.__exit__(*exc)
        return False


ROLES = [
    RoleSession("anonymous", {}),
    RoleSession("alice", {"Authorization": "Bearer alice-token"}),
]


def _chain_signatures(result: dict) -> set[str]:
    return {cf.get("vulnerability_class") for cf in result.get("chains", []) or []}


class ChainRelinkAfterLaterPhasesTest(unittest.TestCase):
    """Positive: the chain composed from FINDING_A (present before the
    second-order phase) and FINDING_B (confirmed only inside it) must be present
    in the final result -- proving the RB-5 re-link picked up a later-phase
    confirmation the 741/771 snapshot could not have seen."""

    def test_chain_composed_across_second_order_phase_is_present(self):
        result = _EngagementRelinkRun().run()
        self.assertIn(
            CHAIN_SIGNATURE, _chain_signatures(result),
            f"INV-3 REGRESSION: the {CHAIN_SIGNATURE} chain (admin_exposure from "
            f"the initial pass + idor confirmed only in the second-order phase) "
            f"is absent from result['chains']={result.get('chains')!r} -- the "
            f"final re-link did not pick up the later-phase confirmation")
        self.assertFalse(result.get("degraded"), f"unexpected errors: {result.get('errors')}")

    def test_negative_control_disabled_relink_loses_the_chain(self):
        """Defect injection: with Orchestrator._relink_chains patched to raise --
        the exact seam RB-5 added -- the same chain must NOT appear (only the
        stale pre-second-order `chains` snapshot survives), and the run must
        surface a 'final_chain_relink' error rather than silently degrading.
        This proves the positive assertion above actually depends on the final
        re-link and is not a tautology."""
        result = _EngagementRelinkRun(disable_relink=True).run()
        self.assertNotIn(
            CHAIN_SIGNATURE, _chain_signatures(result),
            "defect-injection is inert: the chain survived even with "
            "Orchestrator._relink_chains disabled, so the positive test above "
            "does not actually depend on the final re-link")
        self.assertTrue(result.get("degraded"), "a failed final re-link must mark the run degraded")
        phases = {e.get("phase") for e in result.get("errors", [])}
        self.assertIn("final_chain_relink", phases,
                     f"expected a 'final_chain_relink' error, got {result.get('errors')!r}")


if __name__ == "__main__":
    unittest.main()
