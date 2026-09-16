"""
Agents package initialization.

This package contains all security testing agents for the AgenticBurp harness.

Agent Discovery:
- Agents are automatically discovered via the plugin system
- Built-in agents are in this directory (sqli_agent.py, xss_agent.py, etc.)
- Custom agents can be added as plugins via entry points or file placement

Usage:
    from agents import get_all_agents, get_agent_class
    
    # Get all available agent classes
    agents = get_all_agents(config, ollama)
    
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

# Lazy loading of plugin system
_plugin_system = None


def _get_plugin_system():
    """Get or create the plugin system instance."""
    global _plugin_system
    if _plugin_system is None:
        from .plugin import get_plugin_system
        _plugin_system = get_plugin_system()
    return _plugin_system


def get_all_agent_classes(config: dict, ollama: OllamaClient) -> dict[str, Type[BaseAgent]]:
    """
    Get all available agent classes.
    
    This function discovers all agents (both built-in and plugin) and
    returns a dictionary mapping agent names to their classes.
    
    Args:
        config: Application configuration
        ollama: Ollama client instance
        
    Returns:
        Dictionary mapping agent names to agent classes
    """
    plugin_system = _get_plugin_system()
    
    # Discover all agents
    agent_names = plugin_system.list_agents()
    
    # Load all agent classes
    agents = {}
    for name in agent_names:
        agent_class = plugin_system.load_agent_class(name)
        if agent_class is not None:
            agents[name] = agent_class
    
    # If no agents found via plugin system, fall back to built-in agents
    if not agents:
        log.warning("No agents found via plugin system, falling back to built-in agents")
        agents = _load_builtin_agents()
    
    return agents


def _load_builtin_agents() -> dict[str, Type[BaseAgent]]:
    """Load built-in agent classes directly."""
    from .base_agent import BaseAgent
    
    agents = {}
    builtin_agents = [
        ('sqli', 'SqliAgent'),
        ('xss', 'XssAgent'),
        ('idor', 'IdorAgent'),
        ('ssrf', 'SsrfAgent'),
        ('auth', 'AuthAgent'),
        ('business_logic', 'BusinessLogicAgent'),
        ('business_logic_enhanced', 'BusinessLogicEnhancedAgent'),
        ('misconfig', 'MisconfigAgent'),
        ('ai_llm', 'AiLlmAgent'),
        ('ai_security', 'AiSecurityAgent'),
        ('supply_chain', 'SupplyChainAgent'),
        ('rate_limit', 'RateLimitAgent'),
        ('graphql', 'GraphqlAgent'),
        ('jwt', 'JwtAgent'),
        ('xxe', 'XxeAgent'),
        ('csrf', 'CsrfAgent'),
        ('file_upload', 'FileUploadAgent'),
        ('nosql', 'NosqlAgent'),
        ('command_injection', 'CommandInjectionAgent'),
        ('ssti', 'SstiAgent'),
        ('open_redirect', 'OpenRedirectAgent'),
        ('info_disclosure', 'InfoDisclosureAgent'),
        ('anomaly', 'AnomalyAgent'),
    ]
    
    for name, class_name in builtin_agents:
        try:
            module = __import__(f'agents.{name}_agent', fromlist=[class_name])
            agent_class = getattr(module, class_name)
            if isinstance(agent_class, type) and issubclass(agent_class, BaseAgent):
                agents[name] = agent_class
        except Exception as e:
            log.warning(f"Failed to load built-in agent {name}: {e}")
    
    return agents


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
