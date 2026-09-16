"""orchestrator_report.py -- ReportMixin mixin for Orchestrator (W-15 decomposition).

Allocation planning, cost estimation, and the model/agent/effort management
surface (list_models, set_*_model, effort_status, list/register agents).

Split out of orchestrator.py verbatim; `self` state is initialised in
Orchestrator.__init__ and resolved across mixins via the MRO.
"""
from __future__ import annotations

from orchestrator_helpers import *  # noqa: F401,F403  (shared imports/helpers/constants)


class ReportMixin:
    def plan_allocation(
        self,
        candidates: list[dict],
        *,
        policy_overrides: dict | None = None,
        avg_agents_per_round: float = 1.0,
    ) -> dict:
        """F5 prioritizer: given competing vulnerabilities and the REMAINING
        global token budget, decide which get the full retry policy, which get a
        reduced one, and which are deferred -- with guidance. This is what turns
        "I have 2M tokens" into an actual spend plan; with no budget cap set,
        everyone gets full policy. Round cost is calibrated from the ledger's
        real observed averages (falls back to labeled priors before any real
        call). `candidates` are dicts: {id, vulnerability_class, url, severity,
        confidence, priority?}."""
        import resource_governor
        policy = self.retry_budget_policy.merged_with(policy_overrides)
        cands = self._build_alloc_candidates(candidates)
        round_cost = resource_governor.estimate_round_cost(
            self.effort_budget.ledger, avg_agents_per_round=avg_agents_per_round)
        plan = resource_governor.plan_allocation(
            cands, self.effort_budget.remaining, policy, round_cost)
        return plan.to_dict()

    def _build_alloc_candidates(self, candidates: list[dict]) -> list:
        import resource_governor
        return [
            resource_governor.AllocationCandidate(
                id=str(c.get("id") or c.get("url") or i),
                vulnerability_class=str(c.get("vulnerability_class", "unknown")),
                url=str(c.get("url", "")),
                severity=str(c.get("severity", "info")),
                confidence=float(c.get("confidence", 0.0) or 0.0),
                priority=c.get("priority"),
            )
            for i, c in enumerate(candidates)
        ]

    async def plan_allocation_ranked(
        self,
        candidates: list[dict],
        *,
        policy_overrides: dict | None = None,
        avg_agents_per_round: float = 1.0,
        model: str = "",
    ) -> dict:
        """Like plan_allocation, but first asks a large model (the cloud
        coordinator by default) to RANK the candidates for this app, feeding its
        scores in as each candidate's priority before the deterministic governor
        allocates. The model ranks; the governor still does the auditable
        budget arithmetic and enforcement. Fails safe: any candidate the model
        doesn't score keeps its static severity-based priority, and a model
        failure degrades the whole call to the static ranking. A candidate that
        already carries an explicit priority is left untouched (operator ordering
        wins over the model)."""
        import resource_governor
        import allocation_prioritizer
        policy = self.retry_budget_policy.merged_with(policy_overrides)
        cands = self._build_alloc_candidates(candidates)

        to_rank = [c for c in cands if c.priority is None]
        ranking_model = model or getattr(self.coordinator, "cloud_model", "") or self.coordinator_model
        scores = await allocation_prioritizer.rank(to_rank, self.ollama, ranking_model)
        llm_scored = 0
        for c in cands:
            if c.priority is None and c.id in scores:
                c.priority = scores[c.id]
                llm_scored += 1

        round_cost = resource_governor.estimate_round_cost(
            self.effort_budget.ledger, avg_agents_per_round=avg_agents_per_round)
        plan = resource_governor.plan_allocation(
            cands, self.effort_budget.remaining, policy, round_cost)
        out = plan.to_dict()
        out["ranking"] = {
            "model": ranking_model,
            "llm_scored": llm_scored,
            "static_fallback": len(cands) - llm_scored,
        }
        return out

    def estimate_for_urls(self, urls: list[UrlEstimateItem]) -> dict:
        """
        Projects total token cost for running the full assessment across
        `urls` -- meant to be called once the analyst has spidered the
        target and sent at least one real exchange through /analyze, so
        this calibrates against self.effort_budget.ledger's real observed
        averages rather than the unmeasured priors in effort.py.
        """
        inputs = [
            effort.UrlEstimateInput(
                url=u.url,
                risk_score=u.risk_score,
                category=u.category,
            )
            for u in urls
        ]
        return effort.estimate_for_urls(inputs, self.effort_budget.ledger)

    async def list_models(self) -> dict:
        """The model choices a UI picker offers: Ollama's own tags plus the
        cloud models config declares (which /api/tags does NOT list), and the
        models currently selected for the coordinator and the agents. Feeds the
        tester's model dropdowns."""
        local = await self.ollama.list_models()
        cloud = list((self.config.get("models", {}) or {}).get("cloud", []) or [])
        agent_models = sorted({getattr(a, "model", "") for a in self.agent_manager.agents.values()
                               if getattr(a, "model", "")})
        return {
            "local": local,
            "cloud": cloud,
            "all": sorted(set(local) | set(cloud) | set(agent_models) | {self.coordinator_model}),
            "coordinator_model": self.coordinator_model,
            "agent_models": agent_models,
        }

    def set_coordinator_model(self, model: str) -> dict:
        """Point the coordinator (routing, critique, allocation ranking) at a
        different model -- the tester's 'orchestrator/governor model' dropdown.
        Takes effect on the next call; does not re-validate the tag exists (a
        bad tag surfaces as an OllamaModelNotFoundError on use, not here)."""
        if not model:
            raise ValueError("model must be non-empty")
        self.coordinator_model = model
        if getattr(self, "coordinator", None) is not None:
            self.coordinator.model = model
        log.info("Coordinator model set to %s", model)
        return {"coordinator_model": self.coordinator_model}

    def reasoning_model(self) -> str:
        """Model for reasoning-heavy work (iterative agent + critique) -- the cloud
        model when the cloud-coordinator seam is toggled on, else local. See
        coordinator.reasoning_model. Reads self.config live so /settings takes
        effect without a restart."""
        return coordinator.reasoning_model(self.config)

    def set_cloud_reasoning(self, enabled: bool) -> dict:
        """Toggle the cloud-coordinator seam (Phase 4). When ON, the iterative
        agent and critique run on coordinator.cloud_model -- which means REAL
        exchange content leaves the host, so this is default-off and flipped
        knowingly. In-memory (mutates self.config, shared with the analysis
        pipeline); not persisted -- gone on restart, like the validator toggles."""
        self.config.setdefault("coordinator", {})["cloud_reasoning"] = bool(enabled)
        log.info("Cloud-reasoning seam %s (reasoning model -> %s)",
                 "ENABLED" if enabled else "disabled", self.reasoning_model())
        return self.cloud_reasoning_state()

    def cloud_reasoning_state(self) -> dict:
        coord = self.config.get("coordinator", {}) or {}
        return {"cloud_reasoning": bool(coord.get("cloud_reasoning", False)),
                "cloud_model": coord.get("cloud_model", ""),
                "reasoning_model": self.reasoning_model()}

    def set_agents_model(self, model: str, agent: str | None = None) -> dict:
        """Point specialist agents at a different model -- the tester's 'agent
        model' dropdown. With `agent` set, only that one changes; otherwise every
        agent flips (the 'run everything on gemma 31b to debug' switch). Returns
        which agents changed."""
        if not model:
            raise ValueError("model must be non-empty")
        if agent is not None:
            if agent not in self.agent_manager.agents:
                raise ValueError(f"unknown agent {agent!r}")
            targets = [agent]
        else:
            targets = list(self.agent_manager.agents.keys())
        for name in targets:
            self.agent_manager.agents[name].model = model
        log.info("Set model=%s for %d agent(s)", model, len(targets))
        return {"model": model, "agents_changed": targets}

    def effort_status(self) -> EffortStatus:
        """Get current effort budget status."""
        return EffortStatus(
            mode=self.effort_budget.mode.value,
            total_tokens=self.effort_budget.total_tokens,
            spent_tokens=self.effort_budget.spent,
            remaining_tokens=self.effort_budget.remaining,
            exhausted=self.effort_budget.exhausted(),
            breakdown=self.effort_budget.ledger.breakdown(),
        )
    
    def list_agents(self) -> list[dict]:
        """
        Get metadata for all available agents.
        
        Returns:
            List of agent metadata dictionaries
        """
        return self.agent_manager.list_all_agents()
    
    def register_agent(self, name: str, agent_class, config: dict = None) -> bool:
        """
        Dynamically register a new agent at runtime.
        
        Args:
            name: The name to register the agent under
            agent_class: The agent class to register
            config: Optional configuration for the agent
            
        Returns:
            True if registration succeeded, False otherwise
        """
        return self.agent_manager.register_agent(name, agent_class, config)
    
    def get_agent_metadata(self, name: str) -> dict | None:
        """
        Get metadata for a specific agent.
        
        Args:
            name: The name of the agent
            
        Returns:
            Agent metadata dictionary, or None if not found
        """
        return self.agent_manager.get_agent_metadata(name)
