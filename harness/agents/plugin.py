"""
Agent Plugin System

This module provides a plugin system for security testing agents.
It allows agents to be discovered and loaded dynamically without hardcoded imports.

Plugin Discovery Methods:
1. Entry points (preferred): Agents register via setuptools entry_points
2. File scanning: Automatically discover agent modules in the agents directory
3. Manual registration: Explicitly register agent classes

Usage:
    # For plugin authors - register your agent via entry points in setup.py:
    entry_points={
        'agenticburp.agents': [
            'my_agent = my_package.agents.my_agent:MyAgent',
        ]
    }
    
    # For the harness - load all agents:
    from harness.agents.plugin import AgentPluginSystem
    plugin_system = AgentPluginSystem()
    agents = {name: plugin_system.load_agent_class(name)
              for name in plugin_system.list_agents()}
"""

from __future__ import annotations
import importlib
import logging
import pkgutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Type

if TYPE_CHECKING:
    from harness.ollama_client import OllamaClient
    from .base_agent import BaseAgent

log = logging.getLogger("harness.agents.plugin")

# Entry point group for agent plugins
ENTRY_POINT_GROUP = "agenticburp.agents"


@dataclass
class AgentMetadata:
    """Metadata about a registered agent."""
    name: str
    module_path: str
    class_name: str
    display_name: str = ""
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    tags: list[str] = field(default_factory=list)
    enabled_by_default: bool = True
    
    @property
    def full_class_path(self) -> str:
        """Get the full import path for the agent class."""
        return f"{self.module_path}.{self.class_name}"


@dataclass
class PluginSource:
    """Represents a source of agent plugins."""
    name: str
    loader: Callable[[], list[AgentMetadata]]
    priority: int = 0  # Higher priority sources are loaded first


class AgentPluginSystem:
    """
    Plugin system for managing security testing agents.
    
    This class provides multiple ways to discover and load agent plugins:
    - Entry points (standard Python plugin mechanism)
    - File scanning (auto-discover in agents directory)
    - Manual registration
    
    The system maintains a registry of available agents and their metadata.
    """
    
    def __init__(self):
        """Initialize the plugin system."""
        self._sources: list[PluginSource] = []
        self._registry: dict[str, AgentMetadata] = {}
        self._loaded: dict[str, Type[BaseAgent]] = {}
        self._initialized = False
        
        # Register default sources
        self.register_source(PluginSource(
            name="entry_points",
            priority=100,
            loader=self._load_from_entry_points
        ))
        self.register_source(PluginSource(
            name="file_scan",
            priority=50,
            loader=self._load_from_file_scan
        ))
    
    def register_source(self, source: PluginSource) -> None:
        """Register a new plugin source."""
        self._sources.append(source)
        # Sort by priority (descending)
        self._sources.sort(key=lambda s: s.priority, reverse=True)
    
    def register_agent(
        self,
        name: str,
        module_path: str,
        class_name: str,
        display_name: str = "",
        description: str = "",
        version: str = "1.0.0",
        author: str = "",
        tags: list[str] = None,
        enabled_by_default: bool = True
    ) -> None:
        """Manually register an agent."""
        metadata = AgentMetadata(
            name=name,
            module_path=module_path,
            class_name=class_name,
            display_name=display_name,
            description=description,
            version=version,
            author=author,
            tags=tags or [],
            enabled_by_default=enabled_by_default
        )
        self._registry[name] = metadata
        log.debug(f"Manually registered agent: {name}")
    
    def discover_agents(self) -> dict[str, AgentMetadata]:
        """
        Discover all available agents from all registered sources.
        
        Returns:
            Dictionary mapping agent names to their metadata
        """
        if self._initialized:
            return self._registry
        
        # Load from all sources
        for source in self._sources:
            try:
                agents = source.loader()
                for metadata in agents:
                    if metadata.name not in self._registry:
                        self._registry[metadata.name] = metadata
                        log.debug(f"Discovered agent {metadata.name} from {source.name}")
                    else:
                        log.debug(f"Agent {metadata.name} already registered, skipping")
            except Exception as e:
                log.warning(f"Failed to load agents from {source.name}: {e}")
        
        self._initialized = True
        return self._registry
    
    def _load_from_entry_points(self) -> list[AgentMetadata]:
        """Read the structured entry-point API supported by Python >=3.11."""
        from importlib.metadata import entry_points

        agents = []
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                if not ep.attr:
                    raise ValueError("agent entry point must name a class")
                agents.append(AgentMetadata(
                    name=ep.name, module_path=ep.module, class_name=ep.attr))
            except (AttributeError, ValueError) as exc:
                log.warning("Invalid agent entry point %r: %s", ep.name, exc)
        return agents
    
    def _load_from_file_scan(self) -> list[AgentMetadata]:
        """Load agents by scanning the agents directory."""
        agents = []
        
        # Get the agents directory
        agents_dir = Path(__file__).parent
        
        # Look for modules that look like agent files
        for finder, name, ispkg in pkgutil.iter_modules([str(agents_dir)]):
            # Skip __init__ and base_agent
            if name.startswith('_') or name in ('base_agent', 'plugin'):
                continue
            
            # Skip packages (directories)
            if ispkg:
                continue
            
            # Try to import and check for Agent classes
            try:
                module = importlib.import_module(f"{__package__}.{name}")  # harness.agents.<name>
                
                # Look for classes that inherit from BaseAgent
                from .base_agent import BaseAgent
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type) and
                        issubclass(attr, BaseAgent) and
                        attr is not BaseAgent
                    ):
                        # Check if it has a name attribute
                        agent_name = getattr(attr, 'name', None)
                        if agent_name and not agent_name.startswith('_'):
                            agents.append(AgentMetadata(
                                name=agent_name,
                                module_path=f"{__package__}.{name}",  # harness.agents.<name>
                                class_name=attr_name
                            ))
            except Exception as e:
                log.debug(f"Failed to scan agent module {name}: {e}")
        
        return agents
    
    def load_agent_class(self, name: str) -> Type[BaseAgent] | None:
        """
        Load the agent class for a given agent name.
        
        Args:
            name: The name of the agent to load
            
        Returns:
            The agent class, or None if not found
        """
        if name in self._loaded:
            return self._loaded[name]
        
        # Ensure agents are discovered
        self.discover_agents()
        
        if name not in self._registry:
            log.warning(f"Agent {name} not found in registry")
            return None
        
        metadata = self._registry[name]
        
        try:
            # Import the module
            module = importlib.import_module(metadata.module_path)
            
            # Get the class
            agent_class = module
            for part in metadata.class_name.split("."):
                agent_class = getattr(agent_class, part)
            
            # Verify it's a BaseAgent subclass
            from .base_agent import BaseAgent
            if not (isinstance(agent_class, type) and issubclass(agent_class, BaseAgent)):
                log.warning(f"Agent {name} is not a subclass of BaseAgent")
                return None
            
            self._loaded[name] = agent_class
            log.debug(f"Loaded agent class: {name}")
            return agent_class
            
        except ImportError as e:
            log.warning(f"Failed to import agent {name}: {e}")
            return None
        except AttributeError as e:
            log.warning(f"Failed to get agent class {metadata.class_name} from module {metadata.module_path}: {e}")
            return None
        except Exception as e:
            log.warning(f"Unexpected error loading agent {name}: {e}")
            return None
    
    def get_agent_metadata(self, name: str) -> AgentMetadata | None:
        """Get metadata for a specific agent."""
        self.discover_agents()
        return self._registry.get(name)
    
    def list_agents(self) -> list[str]:
        """Get a list of all discovered agent names."""
        self.discover_agents()
        return list(self._registry.keys())
    
    def get_all_metadata(self) -> dict[str, AgentMetadata]:
        """Get metadata for all discovered agents."""
        self.discover_agents()
        return self._registry.copy()


# Global plugin system instance
_plugin_system: AgentPluginSystem | None = None


def get_plugin_system() -> AgentPluginSystem:
    """Get the global plugin system instance."""
    global _plugin_system
    if _plugin_system is None:
        _plugin_system = AgentPluginSystem()
    return _plugin_system


def reset_plugin_system() -> None:
    """Reset the global plugin system (useful for testing)."""
    global _plugin_system
    _plugin_system = None


class AgentPlugin(ABC):
    """
    Base class for agent plugins.
    
    This is an alternative base class that agents can inherit from
    to provide additional plugin-specific functionality.
    
    To create a plugin agent:
    
    1. Inherit from both BaseAgent and AgentPlugin
    2. Implement the required methods
    3. Register via entry points or file placement
    
    Example:
        class MyAgent(BaseAgent, AgentPlugin):
            name = "my_agent"
            
            @property
            def specialty_prompt(self) -> str:
                return "..."
            
            @classmethod
            def get_metadata(cls) -> AgentMetadata:
                return AgentMetadata(
                    name="my_agent",
                    module_path="my_module.my_agent",
                    class_name="MyAgent",
                    display_name="My Custom Agent",
                    description="Does custom security checks"
                )
    """
    
    @classmethod
    @abstractmethod
    def get_metadata(cls) -> AgentMetadata:
        """Get metadata about this plugin agent."""
        raise NotImplementedError
    
    @classmethod
    def register(cls) -> None:
        """Register this plugin agent with the plugin system."""
        plugin_system = get_plugin_system()
        metadata = cls.get_metadata()
        plugin_system.register_agent(
            name=metadata.name,
            module_path=metadata.module_path,
            class_name=metadata.class_name,
            display_name=metadata.display_name,
            description=metadata.description,
            version=metadata.version,
            author=metadata.author,
            tags=metadata.tags,
            enabled_by_default=metadata.enabled_by_default
        )
        log.info(f"Registered plugin agent: {metadata.name}")
