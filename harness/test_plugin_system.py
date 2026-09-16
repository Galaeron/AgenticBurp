"""
Tests for the agent plugin system.

This test suite verifies that the plugin system correctly:
1. Discovers built-in agents
2. Loads agent classes dynamically
3. Supports manual registration
4. Handles agent metadata
5. Works with the agent manager
"""
import pytest

from harness.agents.plugin import (
    AgentPluginSystem,
    AgentMetadata,
    PluginSource,
    get_plugin_system,
    reset_plugin_system,
    ENTRY_POINT_GROUP,
)
from harness.agents.base_agent import BaseAgent


@pytest.fixture
def plugin_system():
    """Create a fresh plugin system for each test."""
    reset_plugin_system()
    return AgentPluginSystem()


@pytest.fixture
def mock_ollama():
    """Create a mock Ollama client."""
    class MockOllama:
        pass
    return MockOllama()


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    return {
        "ollama": {"base_url": "http://localhost:11434"},
        "coordinator": {"model": "llama3.2"},
        "agents": {},
    }


class TestAgentMetadata:
    """Tests for AgentMetadata dataclass."""

    def test_metadata_creation(self):
        """Test creating agent metadata."""
        metadata = AgentMetadata(
            name="test_agent",
            module_path="agents.test_agent",
            class_name="TestAgent",
            display_name="Test Agent",
            description="A test agent",
            version="1.0.0",
            author="Test Author",
            tags=["test", "demo"],
        )
        
        assert metadata.name == "test_agent"
        assert metadata.module_path == "agents.test_agent"
        assert metadata.class_name == "TestAgent"
        assert metadata.display_name == "Test Agent"
        assert metadata.description == "A test agent"
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"
        assert metadata.tags == ["test", "demo"]
        assert metadata.enabled_by_default is True
        assert metadata.full_class_path == "agents.test_agent.TestAgent"

    def test_metadata_defaults(self):
        """Test metadata with default values."""
        metadata = AgentMetadata(
            name="test_agent",
            module_path="agents.test_agent",
            class_name="TestAgent",
        )
        
        assert metadata.display_name == ""
        assert metadata.description == ""
        assert metadata.version == "1.0.0"
        assert metadata.author == ""
        assert metadata.tags == []
        assert metadata.enabled_by_default is True


class TestPluginSource:
    """Tests for PluginSource dataclass."""

    def test_plugin_source_creation(self):
        """Test creating a plugin source."""
        def mock_loader():
            return []
        
        source = PluginSource(
            name="test_source",
            priority=10,
            loader=mock_loader,
        )
        
        assert source.name == "test_source"
        assert source.priority == 10
        assert callable(source.loader)

    def test_plugin_source_default_priority(self):
        """Test plugin source with default priority."""
        def mock_loader():
            return []
        
        source = PluginSource(
            name="test_source",
            loader=mock_loader,
        )
        
        assert source.priority == 0


class TestAgentPluginSystem:
    """Tests for AgentPluginSystem class."""

    def test_initialization(self, plugin_system):
        """Test plugin system initialization."""
        assert plugin_system._sources is not None
        assert len(plugin_system._sources) == 2  # entry_points and file_scan
        assert plugin_system._registry == {}
        assert plugin_system._loaded == {}
        assert plugin_system._initialized is False

    def test_register_source(self, plugin_system):
        """Test registering a new plugin source."""
        def mock_loader():
            return []
        
        source = PluginSource(
            name="custom_source",
            priority=200,
            loader=mock_loader,
        )
        
        plugin_system.register_source(source)
        
        # Check that source was added
        assert len(plugin_system._sources) == 3
        # Check that sources are sorted by priority
        priorities = [s.priority for s in plugin_system._sources]
        assert priorities == sorted(priorities, reverse=True)

    def test_manual_registration(self, plugin_system):
        """Test manually registering an agent."""
        plugin_system.register_agent(
            name="manual_agent",
            module_path="agents.manual_agent",
            class_name="ManualAgent",
            display_name="Manual Agent",
            description="Manually registered agent",
        )
        
        # Check that agent is in registry
        assert "manual_agent" in plugin_system._registry
        metadata = plugin_system._registry["manual_agent"]
        assert metadata.name == "manual_agent"
        assert metadata.module_path == "agents.manual_agent"
        assert metadata.class_name == "ManualAgent"

    def test_discover_agents(self, plugin_system):
        """Test discovering agents."""
        # Manually register an agent first
        plugin_system.register_agent(
            name="discoverable_agent",
            module_path="agents.discoverable_agent",
            class_name="DiscoverableAgent",
        )
        
        # Discover agents
        registry = plugin_system.discover_agents()
        
        # Check that our manually registered agent is in the registry
        assert "discoverable_agent" in registry
        assert isinstance(registry, dict)

    def test_list_agents(self, plugin_system):
        """Test listing all agents."""
        # Manually register some agents
        plugin_system.register_agent(
            name="agent1",
            module_path="agents.agent1",
            class_name="Agent1",
        )
        plugin_system.register_agent(
            name="agent2",
            module_path="agents.agent2",
            class_name="Agent2",
        )
        
        # List agents
        agents = plugin_system.list_agents()
        
        assert isinstance(agents, list)
        assert "agent1" in agents
        assert "agent2" in agents

    def test_get_agent_metadata(self, plugin_system):
        """Test getting metadata for a specific agent."""
        # Manually register an agent
        plugin_system.register_agent(
            name="metadata_agent",
            module_path="agents.metadata_agent",
            class_name="MetadataAgent",
            display_name="Metadata Agent",
            description="Agent with metadata",
            version="2.0.0",
        )
        
        # Get metadata
        metadata = plugin_system.get_agent_metadata("metadata_agent")
        
        assert metadata is not None
        assert metadata.name == "metadata_agent"
        assert metadata.display_name == "Metadata Agent"
        assert metadata.description == "Agent with metadata"
        assert metadata.version == "2.0.0"

    def test_get_nonexistent_agent_metadata(self, plugin_system):
        """Test getting metadata for a non-existent agent."""
        metadata = plugin_system.get_agent_metadata("nonexistent")
        assert metadata is None

    def test_get_all_metadata(self, plugin_system):
        """Test getting metadata for all agents."""
        # Manually register some agents
        plugin_system.register_agent(
            name="all_meta1",
            module_path="agents.all_meta1",
            class_name="AllMeta1",
        )
        plugin_system.register_agent(
            name="all_meta2",
            module_path="agents.all_meta2",
            class_name="AllMeta2",
        )
        
        # Get all metadata
        all_metadata = plugin_system.get_all_metadata()
        
        assert isinstance(all_metadata, dict)
        assert "all_meta1" in all_metadata
        assert "all_meta2" in all_metadata

    def test_load_builtin_agent_class(self, plugin_system):
        """Test loading a built-in agent class."""
        # First, manually register the sqli agent
        plugin_system.register_agent(
            name="sqli",
            module_path="agents.sqli_agent",
            class_name="SqliAgent",
        )
        
        # Try to load the agent class
        agent_class = plugin_system.load_agent_class("sqli")
        
        assert agent_class is not None
        assert hasattr(agent_class, 'name')
        assert agent_class.name == "sqli"
        assert issubclass(agent_class, BaseAgent)

    def test_load_nonexistent_agent_class(self, plugin_system):
        """Test loading a non-existent agent class."""
        agent_class = plugin_system.load_agent_class("nonexistent")
        assert agent_class is None


class TestGlobalPluginSystem:
    """Tests for global plugin system functions."""

    def test_get_plugin_system(self):
        """Test getting the global plugin system."""
        reset_plugin_system()
        
        plugin_system = get_plugin_system()
        
        assert plugin_system is not None
        assert isinstance(plugin_system, AgentPluginSystem)

    def test_get_plugin_system_singleton(self):
        """Test that get_plugin_system returns the same instance."""
        reset_plugin_system()
        
        plugin_system1 = get_plugin_system()
        plugin_system2 = get_plugin_system()
        
        assert plugin_system1 is plugin_system2

    def test_reset_plugin_system(self):
        """Test resetting the plugin system."""
        reset_plugin_system()
        
        plugin_system1 = get_plugin_system()
        plugin_system1.register_agent(
            name="test",
            module_path="test",
            class_name="Test",
        )
        
        reset_plugin_system()
        
        plugin_system2 = get_plugin_system()
        
        # The new instance should not have the registered agent
        assert "test" not in plugin_system2._registry


class TestAgentManagerIntegration:
    """Tests for AgentManager integration with plugin system."""

    def test_agent_manager_initialization(self, mock_ollama, mock_config):
        """Test that AgentManager uses the plugin system."""
        from harness.agent_manager import AgentManager
        
        # Create agent manager
        manager = AgentManager(mock_config, mock_ollama)
        
        # Check that it has agents
        enabled_agents = manager.get_enabled_agents()
        assert isinstance(enabled_agents, list)
        # Should have built-in agents
        assert len(enabled_agents) > 0

    def test_agent_manager_list_all_agents(self, mock_ollama, mock_config):
        """Test listing all agents through AgentManager."""
        from harness.agent_manager import AgentManager
        
        manager = AgentManager(mock_config, mock_ollama)
        
        all_agents = manager.list_all_agents()
        
        assert isinstance(all_agents, list)
        # Each agent should have metadata
        for agent in all_agents:
            assert isinstance(agent, dict)
            assert "name" in agent
            assert "enabled" in agent

    def test_agent_manager_get_agent_metadata(self, mock_ollama, mock_config):
        """Test getting agent metadata through AgentManager."""
        from harness.agent_manager import AgentManager
        
        manager = AgentManager(mock_config, mock_ollama)
        
        # Try to get metadata for sqli agent
        metadata = manager.get_agent_metadata("sqli")
        
        if metadata:
            assert isinstance(metadata, dict)
            assert "name" in metadata


class TestFileScanning:
    """Tests for file scanning plugin discovery."""

    def test_file_scan_discovers_agents(self, plugin_system):
        """Test that file scanning discovers agents in the agents directory."""
        # Trigger file scanning
        agents = plugin_system._load_from_file_scan()
        
        # Should find at least the built-in agents
        assert isinstance(agents, list)
        # Check that we found some agents
        assert len(agents) > 0

    def test_file_scan_skips_special_modules(self, plugin_system):
        """Test that file scanning skips special modules."""
        agents = plugin_system._load_from_file_scan()
        
        # Should not include base_agent or plugin
        agent_names = [a.name for a in agents]
        assert "base_agent" not in agent_names
        assert "plugin" not in agent_names


class TestEntryPoints:
    """Tests for entry point plugin discovery."""

    def test_entry_point_group_constant(self):
        """Test that the entry point group constant is defined."""
        assert ENTRY_POINT_GROUP == "agenticburp.agents"

    def test_entry_points_loading(self, plugin_system):
        """Test loading agents from entry points."""
        # This will return empty list if no entry points are registered
        agents = plugin_system._load_from_entry_points()
        
        assert isinstance(agents, list)
        # May be empty if no plugins are installed
        # This is expected behavior


class TestPluginSystemCaching:
    """Tests for plugin system caching."""

    def test_agent_class_caching(self, plugin_system):
        """Test that loaded agent classes are cached."""
        # Register and load an agent
        plugin_system.register_agent(
            name="cached_agent",
            module_path="agents.sqli_agent",
            class_name="SqliAgent",
        )
        
        # Load the agent class
        agent_class1 = plugin_system.load_agent_class("cached_agent")
        
        # Load again - should return cached version
        agent_class2 = plugin_system.load_agent_class("cached_agent")
        
        assert agent_class1 is agent_class2

    def test_discovery_caching(self, plugin_system):
        """Test that agent discovery results are cached."""
        # First discovery
        registry1 = plugin_system.discover_agents()
        
        # Second discovery - should return cached results
        registry2 = plugin_system.discover_agents()
        
        # Both should be the same object
        assert registry1 is registry2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
