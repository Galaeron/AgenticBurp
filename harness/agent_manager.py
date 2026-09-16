"""
Agent management module.

This module handles agent lifecycle, registration, and dispatching.
It separates agent-related concerns from the main orchestrator.

The AgentManager uses the plugin system to discover and load agents dynamically.
"""
from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from harness.ollama_client import OllamaClient
    from harness.models import HttpExchange, AgentReport
    from harness.agents.base_agent import BaseAgent

log = logging.getLogger("harness.agent_manager")


class AgentManager:
    """
    Manages the lifecycle of security testing agents.
    
    Responsibilities:
    - Discover and load agents via the plugin system
    - Initialize agents with proper configuration
    - Dispatch agents to analyze exchanges
    - Track agent health and performance
    - Provide agent metadata and capabilities
    - Support dynamic agent registration
    """
    
    def __init__(self, config: dict, ollama: OllamaClient):
        """
        Initialize the agent manager.
        
        Args:
            config: Full application configuration
            ollama: Ollama client for LLM access
        """
        self.config = config
        self.ollama = ollama
        self.agents: dict[str, BaseAgent] = {}
        self._agent_configs = config.get("agents", {})
        self._plugin_system = None

        # Bound how many agents run concurrently against Ollama through THIS
        # AgentManager instance.  The application orchestrator owns one manager,
        # so its semaphore is shared by overlapping exchanges/jobs routed through
        # that orchestrator.  Separately constructed managers have independent
        # ceilings: this is not a process-global or Ollama-server-wide guarantee.
        # Unbounded concurrency (the old behavior) means every dispatched
        # agent -- up to all 36 if the coordinator fails open -- fires an
        # inference request simultaneously. On memory-constrained GPUs
        # this can exceed available VRAM for concurrent KV-cache
        # allocations, forcing Ollama/the OS to fall back to slow CPU or
        # disk-backed memory rather than actually running in parallel.
        # None or 0 means unbounded (the old behavior), for anyone who
        # knows their hardware can genuinely handle it.
        max_parallel = config.get("concurrency", {}).get("max_parallel_agents")
        self._agent_semaphore = (
            asyncio.Semaphore(max_parallel) if max_parallel and max_parallel > 0 else None
        )

        # Initialize agents
        self._initialize_agents()
    
    def _get_plugin_system(self):
        """Get the plugin system instance."""
        if self._plugin_system is None:
            from harness.agents.plugin import get_plugin_system
            self._plugin_system = get_plugin_system()
        return self._plugin_system
    
    def _initialize_agents(self) -> None:
        """Initialize all enabled agents using the plugin system."""
        plugin_system = self._get_plugin_system()
        
        # Discover all available agents
        agent_names = plugin_system.list_agents()
        
        if not agent_names:
            log.warning("No agents discovered via plugin system, falling back to built-in agents")
            agent_names = self._get_builtin_agent_names()
        
        # Initialize enabled agents
        for name in agent_names:
            # Check if agent is enabled in config
            acfg = self._agent_configs.get(name, {})
            if not acfg.get("enabled", True):
                log.debug(f"Agent {name} is disabled in configuration")
                continue
            
            # Load the agent class
            agent_class = plugin_system.load_agent_class(name)
            if agent_class is None:
                log.warning(f"Failed to load agent class for {name}")
                continue
            
            # Initialize the agent
            try:
                agent_defaults = self.config.get("agent_defaults", {})
                default_model = agent_defaults.get("model", "gemma2:9b")
                default_temperature = agent_defaults.get("temperature", 0.1)
                resolved_model = acfg.get("model", default_model)
                self.agents[name] = agent_class(
                    ollama=self.ollama,
                    model=resolved_model,
                    temperature=acfg.get("temperature", default_temperature),
                )
                log.info(f"Initialized agent: {name} (model: {resolved_model})")
            except Exception as e:
                log.error(f"Failed to initialize agent {name}: {e}")
                raise
    
    def _get_builtin_agent_names(self) -> list[str]:
        """Get list of built-in agent names."""
        return [
            "sqli",
            "xss", 
            "idor",
            "ssrf",
            "auth",
            "business_logic",
            "misconfig",
            "ai_llm",
            "supply_chain",
            "rate_limit",
        ]
    
    def get_agent(self, name: str) -> BaseAgent | None:
        """
        Get an initialized agent by name.
        
        Args:
            name: The name of the agent
            
        Returns:
            The agent instance, or None if not found
        """
        return self.agents.get(name)
    
    def get_agent_class(self, name: str) -> Type[BaseAgent] | None:
        """
        Get the agent class for a given agent name.
        
        Args:
            name: The name of the agent
            
        Returns:
            The agent class, or None if not found
        """
        plugin_system = self._get_plugin_system()
        return plugin_system.load_agent_class(name)
    
    def get_enabled_agents(self) -> list[str]:
        """
        Get list of enabled agent names.
        
        Returns:
            List of names of enabled agents
        """
        return list(self.agents.keys())
    
    def get_agent_config(self, name: str) -> dict:
        """
        Get configuration for a specific agent.
        
        Args:
            name: The name of the agent
            
        Returns:
            Configuration dictionary for the agent
        """
        return self._agent_configs.get(name, {})
    
    def is_agent_enabled(self, name: str) -> bool:
        """
        Check if an agent is enabled.
        
        Args:
            name: The name of the agent
            
        Returns:
            True if the agent is enabled, False otherwise
        """
        return name in self.agents
    
    def register_agent(self, name: str, agent_class: Type[BaseAgent], config: dict = None) -> bool:
        """
        Dynamically register and initialize a new agent.
        
        This allows for runtime agent registration, useful for
        hot-reloading or adding custom agents programmatically.
        
        Args:
            name: The name to register the agent under
            agent_class: The agent class to register
            config: Optional configuration for the agent
            
        Returns:
            True if registration succeeded, False otherwise
        """
        if name in self.agents:
            log.warning(f"Agent {name} already registered")
            return False
        
        try:
            # Store config
            if config:
                self._agent_configs[name] = config
            
            # Initialize the agent
            acfg = self._agent_configs.get(name, {})
            self.agents[name] = agent_class(
                ollama=self.ollama,
                model=acfg.get("model", self.config.get("coordinator", {}).get("model", "llama3.2")),
                temperature=acfg.get("temperature", 0.1),
            )
            log.info(f"Dynamically registered agent: {name}")
            return True
            
        except Exception as e:
            log.error(f"Failed to register agent {name}: {e}")
            return False
    
    def unregister_agent(self, name: str) -> bool:
        """
        Unregister an agent.
        
        Args:
            name: The name of the agent to unregister
            
        Returns:
            True if unregistration succeeded, False otherwise
        """
        if name not in self.agents:
            log.warning(f"Agent {name} not found")
            return False
        
        del self.agents[name]
        log.info(f"Unregistered agent: {name}")
        return True
    
    def reload_agent(self, name: str) -> bool:
        """
        Reload an agent (useful for development/hot-reloading).
        
        Args:
            name: The name of the agent to reload
            
        Returns:
            True if reload succeeded, False otherwise
        """
        if name not in self.agents:
            log.warning(f"Agent {name} not found")
            return False
        
        # Get the agent class
        agent_class = self.get_agent_class(name)
        if agent_class is None:
            log.error(f"Failed to get agent class for {name}")
            return False
        
        # Get the config
        acfg = self._agent_configs.get(name, {})
        
        # Reinitialize the agent
        try:
            self.agents[name] = agent_class(
                ollama=self.ollama,
                model=acfg.get("model", self.config.get("coordinator", {}).get("model", "llama3.2")),
                temperature=acfg.get("temperature", 0.1),
            )
            log.info(f"Reloaded agent: {name}")
            return True
            
        except Exception as e:
            log.error(f"Failed to reload agent {name}: {e}")
            return False
    
    def get_agent_metadata(self, name: str) -> dict | None:
        """
        Get metadata for a specific agent.
        
        Args:
            name: The name of the agent
            
        Returns:
            Metadata dictionary, or None if not found
        """
        plugin_system = self._get_plugin_system()
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
            }
        return None
    
    def list_all_agents(self) -> list[dict]:
        """
        Get metadata for all available agents (including disabled ones).
        
        Returns:
            List of metadata dictionaries for all agents
        """
        plugin_system = self._get_plugin_system()
        all_metadata = plugin_system.get_all_metadata()
        
        result = []
        for name, metadata in all_metadata.items():
            is_enabled = name in self.agents
            result.append({
                'name': name,
                'display_name': metadata.display_name or name,
                'description': metadata.description,
                'version': metadata.version,
                'author': metadata.author,
                'tags': metadata.tags,
                'enabled': is_enabled,
                'enabled_by_default': metadata.enabled_by_default,
            })
        
        return result
    
    def get_agents_by_tag(self, tag: str) -> list[str]:
        """
        Get all enabled agents with a specific tag.
        
        Args:
            tag: The tag to filter by
            
        Returns:
            List of agent names with the specified tag
        """
        result = []
        for name in self.agents:
            metadata = self.get_agent_metadata(name)
            if metadata and tag in metadata.get('tags', []):
                result.append(name)
        return result
    
    def get_agents_by_capability(self, capability: str) -> list[str]:
        """
        Get all enabled agents that support a specific capability.
        
        This is a placeholder for future capability-based filtering.
        
        Args:
            capability: The capability to filter by
            
        Returns:
            List of agent names supporting the capability
        """
        # For now, return all agents
        # This can be enhanced with capability metadata in the future
        return list(self.agents.keys())
    
    def run_agent(self, name: str, exchange, max_body_chars: int = 6000, prior_context: str = "") -> AgentReport:
        """
        Run a specific agent on an exchange.
        
        Args:
            name: The name of the agent to run
            exchange: The HTTP exchange to analyze
            max_body_chars: Maximum number of characters to include from request/response bodies
            prior_context: Prior findings context
            
        Returns:
            AgentReport with findings
        """
        agent = self.get_agent(name)
        if agent is None:
            log.warning(f"Agent {name} not found")
            from harness.models import AgentReport
            return AgentReport(
                agent=name,
                model="unknown",
                findings=[],
                raw_error=f"Agent {name} not found"
            )
        
        # Get effort budget if available
        effort_budget = getattr(self, '_effort_budget', None)
        
        # Run the agent
        import asyncio
        if asyncio.iscoroutinefunction(agent.run):
            # Agent.run is async
            import asyncio
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(
                agent.run(exchange, max_body_chars, prior_context, effort_budget)
            )
        else:
            # Agent.run is sync (shouldn't happen with current BaseAgent)
            return agent.run(exchange, max_body_chars, prior_context, effort_budget)
    
    async def run_agent_async(self, name: str, exchange, max_body_chars: int = 6000, prior_context: str = "") -> AgentReport:
        """
        Async version of run_agent.
        
        Args:
            name: The name of the agent to run
            exchange: The HTTP exchange to analyze
            max_body_chars: Maximum number of characters to include from request/response bodies
            prior_context: Prior findings context
            
        Returns:
            AgentReport with findings
        """
        agent = self.get_agent(name)
        if agent is None:
            log.warning(f"Agent {name} not found")
            from harness.models import AgentReport
            return AgentReport(
                agent=name,
                model="unknown",
                findings=[],
                raw_error=f"Agent {name} not found"
            )
        
        # Get effort budget if available
        effort_budget = getattr(self, '_effort_budget', None)
        
        # Run the agent
        return await agent.run(exchange, max_body_chars, prior_context, effort_budget)

    async def run_multiple_agents(self, agent_names: list[str], exchange,
                                  max_body_chars: int = 6000, prior_context: str = "",
                                  effort_budget=None) -> list:
        """
        Run multiple agents on an exchange concurrently, bounded by
        `concurrency.max_parallel_agents` in config (see __init__) so a
        large dispatch doesn't fire every agent's inference request at
        once and exhaust GPU memory. The bound is manager-scoped and therefore
        also covers simultaneous calls for different exchanges when they share
        this manager; it does not coordinate separate manager instances.

        Args:
            agent_names: List of agent names to run
            exchange: The HTTP exchange to analyze
            max_body_chars: Maximum number of characters to include from request/response bodies
            prior_context: Prior findings context
            effort_budget: Optional effort budget to track token usage

        Returns:
            List of AgentReport objects
        """
        reports = []
        tasks = []

        async def _run_bounded(name: str):
            if self._agent_semaphore is not None:
                async with self._agent_semaphore:
                    return await self.run_agent_async(name, exchange, max_body_chars, prior_context)
            return await self.run_agent_async(name, exchange, max_body_chars, prior_context)

        for name in agent_names:
            if name in self.agents:
                task = asyncio.create_task(_run_bounded(name))
                tasks.append(task)
            else:
                log.warning(f"Agent {name} not found, skipping")

        # Wait for all agents to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    log.error(f"Agent failed with exception: {result}")
                    # Create error report
                    from harness.models import AgentReport
                    reports.append(AgentReport(
                        agent="unknown",
                        model="unknown",
                        findings=[],
                        raw_error=str(result)
                    ))
                else:
                    reports.append(result)

        return reports
