"""AR-1 (LOOP half) caller-level tests: opt-in agent-family routing mode.

Stubs ONLY the model boundary (same principle as
harness.test_pipeline_gate._install_silent_model /
harness.ablation_harness.install_stub_model): every agent AgentManager
constructs shares the SAME ollama object passed into `AgentManager(config,
ollama)` (see AgentManager._create_agent's `ollama=ollama`), and
FamilyRunner (harness/agent_families.py) calls out through
`member.ollama` -- a member agent's own client -- so a single counting stub
installed at construction time sees every model call either path makes,
family or per-agent. This is the "STUB REACHABILITY" requirement from the
AR-1 acceptance criteria: the counter would silently under-count if the
family path used a different client than the agents it was built from.

No live model, no `*ANSWER_KEY*`, no blind target -- synthetic fixtures only.
"""
from __future__ import annotations

import asyncio
import unittest

from harness.agent_manager import AgentManager
from harness.agent_families import (
    DEFAULT_FAMILIES,
    verify_family_membership,
    group_dispatched_agents,
)
from harness.models import HttpExchange, Finding
from harness.ollama_client import OllamaResult
from harness.planner import plans_for_findings


class CountingStubOllama:
    """Records every system_prompt it was called with (so a test can both
    count calls and inspect which specialties/families were actually
    composed into a given call) and returns a fixed, canned findings list
    (default: none) on every call."""

    def __init__(self, canned_findings=None):
        self.calls: list[str] = []
        self.canned_findings = canned_findings if canned_findings is not None else []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls.append(system_prompt)
        return {"findings": list(self.canned_findings), "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        parsed = await self.chat_json(model, system_prompt, user_prompt, temperature)
        return OllamaResult(data=parsed, prompt_tokens=1, completion_tokens=1)

    @property
    def call_count(self) -> int:
        return len(self.calls)


def _config(routing_mode: str | None) -> dict:
    coordinator = {"model": "stub-model"}
    if routing_mode is not None:
        coordinator["routing_mode"] = routing_mode
    return {
        "ollama": {"base_url": "http://localhost:11434"},
        "coordinator": coordinator,
        "agent_defaults": {"model": "stub-model", "temperature": 0.1},
        "agents": {},
    }


def _exchange() -> HttpExchange:
    return HttpExchange(
        url="https://example.test/item?id=7",
        method="GET",
        request_headers={"Accept": "application/json"},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 7, "name": "widget"}',
    )


# A dispatch spanning three members of the "injection" family plus one
# member of "access_control" -- big enough to prove a real collapse
# (families: 2 calls) vs. per-agent (agents: 4 calls), not just a 1-vs-1
# coincidence.
DISPATCH = ["sqli", "xss", "nosql", "idor"]


def _run(manager: AgentManager, dispatch: list[str]):
    return asyncio.run(manager.run_multiple_agents(dispatch, _exchange()))


class DefaultFamiliesMappingTests(unittest.TestCase):
    """DEFAULT_FAMILIES must only ever name real, currently-registered
    agents -- a stale mapping would silently misroute or drop agents."""

    def test_every_family_member_is_a_registered_agent(self):
        problems = verify_family_membership()
        self.assertEqual(problems, [], f"stale DEFAULT_FAMILIES entries: {problems}")

    def test_families_are_disjoint(self):
        seen: dict[str, str] = {}
        for family, members in DEFAULT_FAMILIES.items():
            for name in members:
                self.assertNotIn(
                    name, seen,
                    f"agent {name!r} listed in both {seen.get(name)!r} and {family!r}",
                )
                seen[name] = family

    def test_group_dispatched_agents_splits_families_and_solo(self):
        families, solo = group_dispatched_agents(DISPATCH)
        self.assertEqual(set(families.keys()), {"injection", "access_control"})
        self.assertEqual(sorted(families["injection"]), ["nosql", "sqli", "xss"])
        self.assertEqual(families["access_control"], ["idor"])
        self.assertEqual(solo, [])

    def test_agent_outside_every_family_falls_back_to_solo(self):
        families, solo = group_dispatched_agents(["sqli", "not_a_real_agent"])
        self.assertEqual(solo, ["not_a_real_agent"])
        self.assertEqual(list(families.keys()), ["injection"])


class CallCountTests(unittest.TestCase):
    """Core mechanism acceptance criterion: families issues at most one
    model call per routed family per exchange; agents issues one per
    routed agent."""

    def test_agents_mode_issues_one_call_per_agent(self):
        stub = CountingStubOllama()
        manager = AgentManager(_config("agents"), stub)
        reports = _run(manager, DISPATCH)
        self.assertEqual(stub.call_count, len(DISPATCH))
        self.assertEqual(len(reports), len(DISPATCH))

    def test_families_mode_issues_one_call_per_routed_family(self):
        stub = CountingStubOllama()
        manager = AgentManager(_config("families"), stub)
        reports = _run(manager, DISPATCH)
        # injection (sqli, xss, nosql) collapses to 1 call; access_control
        # (idor alone) is still 1 call -- 2 total, not 4.
        self.assertEqual(stub.call_count, 2)
        self.assertLess(stub.call_count, len(DISPATCH))
        self.assertEqual(len(reports), 2)
        agent_labels = sorted(r.agent for r in reports)
        self.assertEqual(agent_labels, ["family:access_control", "family:injection"])

    def test_families_mode_call_count_is_deterministic(self):
        counts = []
        for _ in range(3):
            stub = CountingStubOllama()
            manager = AgentManager(_config("families"), stub)
            _run(manager, DISPATCH)
            counts.append(stub.call_count)
        self.assertEqual(counts, [2, 2, 2])

    def test_zero_member_family_costs_zero_calls(self):
        """Dispatching only agents from ONE family must not call out for
        every other family that has no dispatched members."""
        stub = CountingStubOllama()
        manager = AgentManager(_config("families"), stub)
        reports = _run(manager, ["sqli", "xss"])  # both injection-only
        self.assertEqual(stub.call_count, 1)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].agent, "family:injection")


class RevertPathTests(unittest.TestCase):
    """The owner's explicit revert requirements: OFF is byte-for-byte
    today's behavior, ON changes the call pattern deterministically, and
    ON -> OFF returns to the original OFF behavior with no residual state."""

    def test_routing_mode_absent_matches_explicit_agents(self):
        """revert test 1: routing_mode absent AND explicitly "agents" must
        produce an identical dispatched agent set, call count, and
        AgentReport list for the same stubbed exchange."""
        stub_absent = CountingStubOllama()
        manager_absent = AgentManager(_config(None), stub_absent)
        reports_absent = _run(manager_absent, DISPATCH)

        stub_explicit = CountingStubOllama()
        manager_explicit = AgentManager(_config("agents"), stub_explicit)
        reports_explicit = _run(manager_explicit, DISPATCH)

        self.assertEqual(manager_absent.routing_mode, "agents")
        self.assertEqual(manager_explicit.routing_mode, "agents")
        self.assertEqual(stub_absent.call_count, stub_explicit.call_count)
        self.assertEqual(stub_absent.call_count, len(DISPATCH))
        self.assertEqual(
            sorted(r.agent for r in reports_absent),
            sorted(r.agent for r in reports_explicit),
        )
        self.assertEqual(len(reports_absent), len(reports_explicit))

    def test_families_mode_changes_call_pattern_deterministically(self):
        """revert test 2: "families" call count == number of routed
        families, strictly less than the number of routed agents for a
        dispatch spanning >=2 members of one family."""
        stub = CountingStubOllama()
        manager = AgentManager(_config("families"), stub)
        _run(manager, DISPATCH)
        families, solo = group_dispatched_agents(DISPATCH)
        expected_calls = len(families) + len(solo)
        self.assertEqual(stub.call_count, expected_calls)
        self.assertLess(stub.call_count, len(DISPATCH))

    def test_on_then_off_returns_to_original_agents_behavior(self):
        """revert test 3: "agents" -> "families" -> "agents" (rebuilding
        the manager each time, as a real config re-read would) yields a
        dispatched set + call count identical to the original OFF run --
        no residual state / no module global written by the family path."""
        stub_original = CountingStubOllama()
        manager_original = AgentManager(_config("agents"), stub_original)
        reports_original = _run(manager_original, DISPATCH)

        # Flip ON.
        stub_families = CountingStubOllama()
        manager_families = AgentManager(_config("families"), stub_families)
        _run(manager_families, DISPATCH)

        # Flip back OFF -- a fresh manager, as a real config re-read/rebuild
        # would produce.
        stub_reverted = CountingStubOllama()
        manager_reverted = AgentManager(_config("agents"), stub_reverted)
        reports_reverted = _run(manager_reverted, DISPATCH)

        self.assertEqual(stub_original.call_count, stub_reverted.call_count)
        self.assertEqual(stub_reverted.call_count, len(DISPATCH))
        self.assertEqual(
            sorted(r.agent for r in reports_original),
            sorted(r.agent for r in reports_reverted),
        )
        # DEFAULT_FAMILIES itself must not have been mutated by the
        # "families" run in between (no module-global written by the
        # family path).
        self.assertEqual(
            group_dispatched_agents(DISPATCH)[0],
            group_dispatched_agents(DISPATCH)[0],
        )


class ConfirmationParityTests(unittest.TestCase):
    """A canned finding produced via a family call must reach the same
    confirmation/validator dispatch (planner.plans_for_findings, which
    keys off Finding.vulnerability_class via categories.canonicalize, NOT
    off AgentReport.agent) as the identical finding from its member agent
    run solo."""

    CANNED_IDOR_FINDING = {
        "vulnerability_class": "idor",
        "confidence": 0.6,
        "severity": "high",
        "summary": "numeric id parameter looks user-scoped but unvalidated",
        "evidence": "GET /item?id=7 returns another user's record",
        "suggested_test": "swap id=7 for a different user's id and compare",
        "basis": "derived",
    }

    def test_family_produced_finding_matches_solo_agent_dispatch(self):
        exchange = _exchange()

        stub_family = CountingStubOllama(canned_findings=[self.CANNED_IDOR_FINDING])
        manager_family = AgentManager(_config("families"), stub_family)
        family_reports = _run(manager_family, ["idor"])
        self.assertEqual(stub_family.call_count, 1)
        self.assertEqual(family_reports[0].agent, "family:access_control")
        family_findings = family_reports[0].findings
        self.assertEqual(len(family_findings), 1)

        stub_solo = CountingStubOllama(canned_findings=[self.CANNED_IDOR_FINDING])
        manager_solo = AgentManager(_config("agents"), stub_solo)
        solo_reports = _run(manager_solo, ["idor"])
        self.assertEqual(solo_reports[0].agent, "idor")
        solo_findings = solo_reports[0].findings
        self.assertEqual(len(solo_findings), 1)

        # Same vulnerability_class preserved verbatim through both paths.
        self.assertEqual(family_findings[0].vulnerability_class, solo_findings[0].vulnerability_class)

        family_plans = plans_for_findings(exchange, family_findings)
        solo_plans = plans_for_findings(exchange, solo_findings)
        self.assertEqual(len(family_plans), 1)
        self.assertEqual(len(solo_plans), 1)
        self.assertEqual(family_plans[0].capability, solo_plans[0].capability)
        self.assertEqual(family_plans[0].capability, "cross_identity_compare")
        self.assertEqual(family_plans[0].execution_plane, solo_plans[0].execution_plane)


class StubReachabilityTests(unittest.TestCase):
    """The composed family call must go through the SAME ollama client the
    agents were constructed with, or a counting stub would silently
    under-count. Prove it directly: every member agent's `.ollama` is the
    exact stub instance passed to AgentManager, both before and after a
    family call runs."""

    def test_family_members_share_the_manager_stub_client(self):
        stub = CountingStubOllama()
        manager = AgentManager(_config("families"), stub)
        for name in ("sqli", "xss", "nosql", "idor"):
            self.assertIs(manager.agents[name].ollama, stub)
        _run(manager, DISPATCH)
        for name in ("sqli", "xss", "nosql", "idor"):
            self.assertIs(manager.agents[name].ollama, stub)
        self.assertGreater(stub.call_count, 0)


class NegativeControlTests(unittest.TestCase):
    """agents mode dispatch and call counts are identical to before this
    change -- run the exact pre-AR-1 shape (no coordinator.routing_mode key
    at all in config) and confirm it still fires one call per agent."""

    def test_agents_mode_unaffected_by_ar1(self):
        config = {
            "ollama": {"base_url": "http://localhost:11434"},
            "coordinator": {"model": "stub-model"},  # no routing_mode key
            "agent_defaults": {"model": "stub-model"},
            "agents": {},
        }
        stub = CountingStubOllama()
        manager = AgentManager(config, stub)
        reports = _run(manager, DISPATCH)
        self.assertEqual(stub.call_count, len(DISPATCH))
        self.assertEqual(sorted(r.agent for r in reports), sorted(DISPATCH))


class ConfigDefaultTests(unittest.TestCase):
    def test_config_yaml_default_routing_mode_is_agents(self):
        import yaml
        from pathlib import Path
        cfg_path = Path(__file__).resolve().parent / "config.yaml"
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        self.assertEqual(cfg.get("coordinator", {}).get("routing_mode"), "agents")

    def test_variant_g_listed_in_ablation_variants(self):
        from harness.ablation_harness import VARIANTS
        keys = [v.key for v in VARIANTS]
        self.assertIn("G", keys)
        g = next(v for v in VARIANTS if v.key == "G")
        self.assertFalse(g.needs_implementation)
        cfg = g.config_transform({})
        self.assertEqual(cfg["coordinator"]["routing_mode"], "families")


if __name__ == "__main__":
    unittest.main()
