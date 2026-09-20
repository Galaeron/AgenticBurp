"""
Agents package initialization.

This package contains all security testing agents for the AgenticBurp harness.

Agent Discovery:
- Agents are automatically discovered via the plugin system
- Built-in agents are in this directory (sqli_agent.py, xss_agent.py, etc.)
- Custom agents can be added as plugins via entry points or file placement

Usage:
    from harness.agents import get_all_agent_classes, get_agent_class
    
    # Get all available agent classes
    agents = get_all_agent_classes()
    
    # Get a specific agent class
    agent_class = get_agent_class("sqli")
"""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from harness.ollama_client import OllamaClient
    from .base_agent import BaseAgent

log = logging.getLogger("harness.agents")

def _get_plugin_system():
    """Use the canonical registry, including after reset_plugin_system()."""
    from .plugin import get_plugin_system
    return get_plugin_system()


def get_all_agent_classes(config: dict | None = None, ollama: OllamaClient | None = None) -> dict[str, Type[BaseAgent]]:
    """Return discovered classes. Optional legacy arguments are unused.

    Class discovery has no model or configuration dependency; instantiate enabled
    agents through AgentManager. Built-ins use the registry's file-scan source.
    """
    plugins = _get_plugin_system()
    return {name: cls for name in plugins.list_agents()
            if (cls := plugins.load_agent_class(name)) is not None}




def get_agent_class(name: str) -> Type[BaseAgent] | None:
    """
    Get a specific agent class by name.
    
    Args:
        name: The name of the agent
        
    Returns:
        The agent class, or None if not found
    """
    plugin_system = _get_plugin_system()
    return plugin_system.load_agent_class(name)


def get_agent_metadata(name: str) -> dict | None:
    """
    Get metadata for a specific agent.
    
    Args:
        name: The name of the agent
        
    Returns:
        Agent metadata dictionary, or None if not found
    """
    plugin_system = _get_plugin_system()
    metadata = plugin_system.get_agent_metadata(name)
    if metadata:
        return {
            'name': metadata.name,
            'display_name': metadata.display_name or metadata.name,
            'description': metadata.description,
            'version': metadata.version,
            'author': metadata.author,
            'tags': metadata.tags,
            'enabled_by_default': metadata.enabled_by_default,
            'module_path': metadata.module_path,
            'class_name': metadata.class_name,
        }
    return None


def list_agents() -> list[str]:
    """Get a list of all available agent names."""
    plugin_system = _get_plugin_system()
    return plugin_system.list_agents()


def get_plugin_system():
    """Get the plugin system instance."""
    return _get_plugin_system()
