"""Plugin discovery and agent lifecycle through real packaged classes."""
import unittest
from importlib.metadata import EntryPoint, EntryPoints
from unittest.mock import patch

from harness.agent_manager import AgentManager
from harness.agents.plugin import AgentPluginSystem, PluginSource, ENTRY_POINT_GROUP
from harness.agents.sqli_agent import SqliAgent


class AgentLifecycleTests(unittest.TestCase):
    def test_entry_point_metadata_reaches_manager_and_rejects_non_agent(self):
        entries = EntryPoints([
            EntryPoint(name='installed-sqli', value='harness.agents.sqli_agent:SqliAgent', group=ENTRY_POINT_GROUP),
            EntryPoint(name='not-an-agent', value='json:JSONDecoder', group=ENTRY_POINT_GROUP),
        ])
        plugins = AgentPluginSystem()
        plugins._sources = [PluginSource('installed', plugins._load_from_entry_points)]
        with patch('importlib.metadata.entry_points', return_value=entries) as read, \
             patch('harness.agents.plugin.get_plugin_system', return_value=plugins):
            manager = AgentManager({'agent_defaults': {'model': 'chosen-model', 'temperature': .3}}, object())
        read.assert_called_once_with(group=ENTRY_POINT_GROUP)
        self.assertIsInstance(manager.get_agent('installed-sqli'), SqliAgent)
        self.assertEqual(manager.get_agent('installed-sqli').model, 'chosen-model')
        self.assertNotIn('not-an-agent', manager.get_enabled_agents())

    def test_malformed_entry_does_not_hide_a_valid_sibling(self):
        plugins = AgentPluginSystem()
        entries = EntryPoints([
            EntryPoint(name='missing-class', value='json', group=ENTRY_POINT_GROUP),
            EntryPoint(name='valid', value='harness.agents.sqli_agent:SqliAgent', group=ENTRY_POINT_GROUP),
        ])
        with patch('importlib.metadata.entry_points', return_value=entries):
            self.assertEqual([m.name for m in plugins._load_from_entry_points()], ['valid'])

    def test_no_discovery_fails_loudly_instead_of_using_stale_roster(self):
        plugins = AgentPluginSystem()
        plugins._sources = []
        with patch('harness.agents.plugin.get_plugin_system', return_value=plugins):
            with self.assertRaisesRegex(RuntimeError, 'No agents discovered'):
                AgentManager({}, object())

    def test_package_facade_observes_registry_reset(self):
        from harness import agents
        from harness.agents import plugin
        original = plugin._plugin_system
        self.addCleanup(setattr, plugin, '_plugin_system', original)
        plugin.reset_plugin_system()
        first = agents.get_plugin_system()
        plugin.reset_plugin_system()
        second = agents.get_plugin_system()
        self.assertIsNot(first, second)
        self.assertIs(second, plugin.get_plugin_system())
        self.assertIs(agents.get_all_agent_classes()['sqli'], SqliAgent)

    def test_dynamic_and_recreated_agents_follow_initial_configuration(self):
        config = {'agent_defaults': {'model': 'specialists', 'temperature': .25},
                  'coordinator': {'model': 'routing-only'}}
        manager = AgentManager(config, object())
        self.assertTrue(manager.register_agent('custom', SqliAgent))
        original = manager.get_agent('custom')
        self.assertEqual((original.model, original.temperature), ('specialists', .25))
        self.assertTrue(manager.reload_agent('custom'))
        self.assertIsNot(original, manager.get_agent('custom'))
        self.assertEqual(manager.get_agent('custom').model, 'specialists')
        self.assertTrue(manager.register_agent('override', SqliAgent, {'model': 'explicit', 'temperature': .4}))
        self.assertTrue(manager.reload_agent('override'))
        self.assertEqual((manager.get_agent('override').model, manager.get_agent('override').temperature), ('explicit', .4))

    def test_failed_registration_does_not_publish_config_or_instance(self):
        manager = AgentManager({}, object())
        class BrokenAgent:
            def __init__(self, **kwargs):
                raise ValueError('broken factory')
        self.assertFalse(manager.register_agent('broken', BrokenAgent, {'model': 'invalid'}))
        self.assertNotIn('broken', manager.agents)
        self.assertNotIn('broken', manager._agent_configs)
        original = manager.get_agent('sqli')
        with patch.object(manager, '_create_agent', side_effect=ValueError('broken factory')):
            self.assertFalse(manager.reload_agent('sqli'))
        self.assertIs(manager.get_agent('sqli'), original)


if __name__ == '__main__':
    unittest.main()
