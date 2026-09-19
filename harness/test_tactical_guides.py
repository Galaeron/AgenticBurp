"""P1.14 -- per-agent tactical guide.

Covers: the base class carries no guide (never fabricated), a concrete agent's
guide is folded into the system prompt and versioned independently of the
broader prompt_version, the coordinator's own dispatch entrypoint (`run()`)
propagates that version onto the AgentReport, and every real specialist agent
in harness/agents/ actually carries a non-empty guide (the completeness check
that keeps this "content-heavy" requirement from silently regressing as new
agents are added).
"""
from __future__ import annotations

import asyncio
import importlib
import pkgutil
import unittest
from unittest.mock import AsyncMock

import harness.agents as agents_pkg
from harness.agents.base_agent import BaseAgent
from harness.models import HttpExchange


class _NoGuideAgent(BaseAgent):
    name = "no_guide"

    @property
    def specialty_prompt(self) -> str:
        return "no-guide specialty"


class _GuideAgent(BaseAgent):
    name = "with_guide"
    tactical_guide = "1. Do the concrete thing.\n2. Then the other concrete thing."

    @property
    def specialty_prompt(self) -> str:
        return "guided specialty"


class _OtherGuideAgent(BaseAgent):
    name = "with_other_guide"
    tactical_guide = "1. A totally different set of steps."

    @property
    def specialty_prompt(self) -> str:
        return "guided specialty"


class BaseClassHasNoGuideTests(unittest.TestCase):
    def test_base_agent_default_is_empty(self):
        self.assertEqual(BaseAgent.tactical_guide, "")

    def test_unspecialized_subclass_inherits_empty_guide(self):
        agent = _NoGuideAgent(ollama=None, model="m")
        self.assertEqual(agent.tactical_guide, "")
        self.assertEqual(agent._guide_version(), "")

    def test_no_guide_block_in_prompt_when_empty(self):
        agent = _NoGuideAgent(ollama=None, model="m")
        self.assertNotIn("Tactical guide", agent._system_prompt())


class GuideFoldedIntoPromptTests(unittest.TestCase):
    def test_guide_text_present_in_system_prompt(self):
        agent = _GuideAgent(ollama=None, model="m")
        prompt = agent._system_prompt()
        self.assertIn("Tactical guide", prompt)
        self.assertIn("Do the concrete thing", prompt)

    def test_guide_version_is_stable_12char_hash(self):
        agent = _GuideAgent(ollama=None, model="m")
        v1 = agent._guide_version()
        v2 = agent._guide_version()
        self.assertEqual(v1, v2)
        self.assertEqual(len(v1), 12)

    def test_different_guides_produce_different_versions(self):
        a = _GuideAgent(ollama=None, model="m")
        b = _OtherGuideAgent(ollama=None, model="m")
        self.assertNotEqual(a._guide_version(), b._guide_version())

    def test_guide_version_independent_of_prompt_version(self):
        # same guide text, different specialty_prompt -> prompt_version
        # differs but guide_version (hash of JUST the guide) stays equal.
        class SameGuideDifferentSpecialty(BaseAgent):
            name = "variant"
            tactical_guide = _GuideAgent.tactical_guide

            @property
            def specialty_prompt(self) -> str:
                return "a completely different specialty text"

        a = _GuideAgent(ollama=None, model="m")
        b = SameGuideDifferentSpecialty(ollama=None, model="m")
        self.assertNotEqual(a._prompt_version(), b._prompt_version())
        self.assertEqual(a._guide_version(), b._guide_version())

    def test_guide_edit_bumps_prompt_version_too(self):
        # the guide is part of _system_prompt, so prompt_version (which
        # traces "exactly which prompt produced this finding") must move too.
        a = _GuideAgent(ollama=None, model="m")
        b = _OtherGuideAgent(ollama=None, model="m")
        self.assertNotEqual(a._prompt_version(), b._prompt_version())


class DispatchLoadsGuideVersionTests(unittest.TestCase):
    """'the coordinator loads it on dispatch' -- run() IS the dispatch
    entrypoint every coordinator/agent_manager path calls; its AgentReport
    must carry the guide version that was actually used for this call."""

    def _run(self, agent):
        agent.ollama = AsyncMock()
        agent.ollama.chat_json = AsyncMock(return_value={"findings": [], "components": []})
        exchange = HttpExchange(url="https://a.test/x", method="GET")
        return asyncio.run(agent.run(exchange, max_body_chars=1000))

    def test_report_carries_guide_version_when_agent_has_one(self):
        agent = _GuideAgent(ollama=None, model="m")
        report = self._run(agent)
        self.assertEqual(report.guide_version, agent._guide_version())
        self.assertNotEqual(report.guide_version, "")

    def test_report_guide_version_empty_when_agent_has_no_guide(self):
        # negative control: an agent with no tactical_guide must never end up
        # with a fabricated non-empty guide_version on its report.
        agent = _NoGuideAgent(ollama=None, model="m")
        report = self._run(agent)
        self.assertEqual(report.guide_version, "")


def _all_concrete_agent_classes():
    classes = []
    for m in pkgutil.iter_modules(agents_pkg.__path__):
        if m.name in ("base_agent", "plugin"):
            continue
        mod = importlib.import_module(f"harness.agents.{m.name}")
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (isinstance(obj, type) and issubclass(obj, BaseAgent)
                    and obj is not BaseAgent and obj.__module__ == mod.__name__):
                classes.append(obj)
    return classes


class EveryRealAgentHasATacticalGuideTests(unittest.TestCase):
    """The completeness check: P1.14 is only real if every specialist agent
    actually got one, not just the base class plumbing. Fails loudly (naming
    the offending class) if a future agent is added without one."""

    def test_every_concrete_agent_has_a_nonempty_guide(self):
        classes = _all_concrete_agent_classes()
        self.assertGreaterEqual(len(classes), 30, "sanity: agent discovery found too few classes")
        missing = [c.__name__ for c in classes if not c.tactical_guide.strip()]
        self.assertEqual(missing, [], f"agent classes with no tactical_guide: {missing}")

    def test_every_concrete_agent_guide_has_a_stable_version(self):
        for cls in _all_concrete_agent_classes():
            agent = cls(ollama=None, model="m")
            v = agent._guide_version()
            self.assertEqual(len(v), 12, f"{cls.__name__} guide_version is not a 12-char hash")

    def test_guides_are_distinct_across_agents(self):
        # a copy-pasted, unedited guide across two different vulnerability
        # classes would be a real content bug -- catch exact duplicates.
        classes = _all_concrete_agent_classes()
        by_guide: dict[str, list[str]] = {}
        for cls in classes:
            by_guide.setdefault(cls.tactical_guide.strip(), []).append(cls.__name__)
        dupes = {g: names for g, names in by_guide.items() if len(names) > 1}
        self.assertEqual(dupes, {}, f"identical tactical_guide reused across agents: {dupes}")


if __name__ == "__main__":
    unittest.main()
