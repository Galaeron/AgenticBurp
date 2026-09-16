"""
Regression tests for agent model resolution in AgentManager.

Covers the fix that decoupled unconfigured agents' model choice from the
coordinator's model: previously, any agent without an explicit "model" in
config.yaml silently inherited whatever model the coordinator was set to,
coupling agent compute cost to a routing-quality decision that has nothing
to do with it. Agents now fall back to a dedicated `agent_defaults.model`
(default: a small model like Gemma 2 9B) instead.
"""
import unittest

from harness.agent_manager import AgentManager


class DummyOllama:
    """Stand-in ollama client -- these tests only check model resolution,
    they never actually call out to Ollama."""
    pass


class TestAgentModelResolution(unittest.TestCase):
    def _config(self, agents=None, agent_defaults=None, coordinator_model="llama3.1:8b"):
        return {
            "ollama": {"base_url": "http://localhost:11434"},
            "coordinator": {"model": coordinator_model},
            "agent_defaults": agent_defaults or {},
            "agents": agents or {},
        }

    def test_unconfigured_agent_uses_agent_defaults_model(self):
        """An agent with no entry in config['agents'] should get the
        model from agent_defaults, not the coordinator's model."""
        config = self._config(
            agent_defaults={"model": "gemma2:9b", "temperature": 0.2},
        )
        manager = AgentManager(config, DummyOllama())

        self.assertGreater(len(manager.agents), 0)
        for name, agent in manager.agents.items():
            self.assertEqual(agent.model, "gemma2:9b", f"agent {name} did not use agent_defaults model")
            self.assertEqual(agent.temperature, 0.2, f"agent {name} did not use agent_defaults temperature")

    def test_explicit_agent_config_overrides_agent_defaults(self):
        """An agent with an explicit model in config['agents'] must keep
        that model, not the agent_defaults fallback."""
        config = self._config(
            agent_defaults={"model": "gemma2:9b"},
            agents={"sqli": {"enabled": True, "model": "llama3.1:8b", "temperature": 0.1}},
        )
        manager = AgentManager(config, DummyOllama())

        self.assertEqual(manager.agents["sqli"].model, "llama3.1:8b")
        # A different, unconfigured agent should still get the default.
        other = [n for n in manager.agents if n != "sqli"][0]
        self.assertEqual(manager.agents[other].model, "gemma2:9b")

    def test_missing_agent_defaults_section_falls_back_to_hardcoded_default(self):
        """If agent_defaults is omitted from config entirely (e.g. an
        older config file), unconfigured agents must still get a sane
        small-model default rather than erroring or silently reverting
        to the coordinator's model."""
        config = {
            "ollama": {"base_url": "http://localhost:11434"},
            "coordinator": {"model": "llama3.1:8b"},
            "agents": {},
        }
        manager = AgentManager(config, DummyOllama())

        self.assertGreater(len(manager.agents), 0)
        for name, agent in manager.agents.items():
            self.assertNotEqual(
                agent.model, "llama3.1:8b",
                f"agent {name} incorrectly inherited the coordinator's model "
                "instead of falling back to the hardcoded agent default",
            )

    def test_unconfigured_agent_model_is_independent_of_coordinator_model(self):
        """Changing the coordinator's model (e.g. to tune routing
        quality) must not change what model unconfigured agents use --
        this is the specific coupling the fix removes."""
        config_a = self._config(agent_defaults={"model": "gemma2:9b"}, coordinator_model="llama3.1:8b")
        config_b = self._config(agent_defaults={"model": "gemma2:9b"}, coordinator_model="llama3.1:70b")

        manager_a = AgentManager(config_a, DummyOllama())
        manager_b = AgentManager(config_b, DummyOllama())

        for name in manager_a.agents:
            self.assertEqual(manager_a.agents[name].model, manager_b.agents[name].model)
            self.assertEqual(manager_a.agents[name].model, "gemma2:9b")


if __name__ == "__main__":
    unittest.main()
