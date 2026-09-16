"""
Orchestrator - Main analysis coordinator.

This is the central module that coordinates all security testing activities.
It delegates to specialized modules for:
- Agent management (agent_manager.py)
- Agent coordination (coordinator.py)
- Analysis pipeline (analysis_pipeline.py)
- Caching (cache.py)
- Fast-path selection (fast_path.py)

The orchestrator is responsible for:
1. Receiving HTTP exchanges from the server
2. Determining which agents to dispatch (via coordinator or fast-path)
3. Running the analysis pipeline
4. Collecting and processing results
5. Returning comprehensive analysis responses

Architecture:
- Uses plugin system for dynamic agent discovery and loading
- Delegates agent management to AgentManager
- Uses Coordinator for intelligent agent dispatch decisions
- Uses AnalysisPipeline for streamlined analysis workflow

W-15 decomposition: the ~2,500-line Orchestrator class was split by concern into
mixins, each in its own module, so this file is now just the shared-state __init__
plus the assembly. Behavior is unchanged -- the methods moved verbatim and every
`self.` call still resolves across the mixins via the MRO:
- orchestrator_helpers.py -- shared imports, constants, and the free helper
  functions (leaf module; re-exported here so `from orchestrator import <helper>`
  and `orchestrator.<helper>` keep working).
- orchestrator_detect.py  (DetectMixin)  -- agent selection, adaptive re-spin,
  known-vuln resolution/rediscovery, and analyze().
- orchestrator_confirm.py (ConfirmMixin) -- coverage-proof binding, _validate_findings,
  active-probe and retry-agent entry points.
- orchestrator_chain.py   (ChainMixin)   -- the graph-driven engagement loop
  (plan/run_engagement, auto-escalation, investigate_engagement).
- orchestrator_report.py  (ReportMixin)  -- allocation planning, cost estimation,
  and the model/agent/effort management surface.
"""
from __future__ import annotations

from harness.orchestrator_helpers import *  # noqa: F401,F403  (re-export shared namespace)
from harness.orchestrator_detect import DetectMixin
from harness.orchestrator_confirm import ConfirmMixin
from harness.orchestrator_chain import ChainMixin
from harness.orchestrator_report import ReportMixin


class Orchestrator(DetectMixin, ConfirmMixin, ChainMixin, ReportMixin):
    """
    Main orchestrator for security testing.
    
    This class coordinates all aspects of analyzing HTTP exchanges,
    including agent dispatching, finding collection, validation, and
    result delivery.
    
    The orchestrator uses a modular architecture:
    - AgentManager: Manages agent lifecycle and discovery via plugin system
    - Coordinator: Makes intelligent decisions about which agents to dispatch
    - AnalysisPipeline: Handles the actual analysis workflow
    - FastPathSelector: Provides deterministic pre-LLM agent routing
    """
    
    def __init__(self, config: dict):
        """
        Initialize the orchestrator.
        
        Args:
            config: Full application configuration
        """
        self.config = config
        
        # Initialize Ollama client
        self.ollama = OllamaClient(
            base_url=config["ollama"]["base_url"],
            timeout_seconds=config["ollama"].get("timeout_seconds", 120),
        )
        
        # Configuration
        self.coordinator_model = config["coordinator"]["model"]
        self.coordinator_temp = config["coordinator"].get("temperature", 0.1)
        self.max_body_chars = config["server"].get("max_body_chars", 6000)
        self.allowed_hosts = config["server"].get("allowed_hosts", [])

        # W-13: concurrency caps read from ONE config block instead of magic
        # numbers scattered through the dispatch code. max_concurrent_validations
        # bounds the per-exchange validator fan-out (was a getattr-default of 6,
        # ignoring config); early_termination_batch_size is the first-agent batch
        # size the early-termination check runs against (was a hardcoded 3).
        _conc = config.get("concurrency", {}) or {}
        self.max_concurrent_validations = max(1, int(_conc.get("max_concurrent_validations", 6)))
        self.early_termination_batch_size = max(1, int(_conc.get("early_termination_batch_size", 3)))

        # Initialize GitHub Advisories client
        gha_cfg = config.get("github_advisories", {})
        self.gha_enabled = gha_cfg.get("enabled", True)
        self.gha_max_lookups = gha_cfg.get("max_lookups_per_exchange", 6)
        # Offline advisory snapshot (Phase 3.3): a file-backed fallback so a
        # token-less / air-gapped run still gets known-vuln matches instead of
        # only "error: rate_limited". snapshot_path loads it; offline makes it the
        # sole source. Absent/unreadable snapshot degrades to the live lookup.
        _snapshot = None
        _snap_path = gha_cfg.get("snapshot_path")
        if _snap_path:
            try:
                from harness.advisory_snapshot import AdvisorySnapshot
                _snapshot = AdvisorySnapshot.from_file(_snap_path)
                log.info("Loaded offline advisory snapshot from %s (%d advisories)",
                         _snap_path, len(_snapshot))
            except Exception as e:
                log.warning("Could not load advisory snapshot %s: %s", _snap_path, e)
        self.gha_client = GitHubAdvisoryClient(
            token=gha_cfg.get("token"), snapshot=_snapshot,
            offline=bool(gha_cfg.get("offline", False)))

        # Initialize registry checks
        registry_cfg = config.get("package_registry_checks", {})
        self.registry_checks_enabled = registry_cfg.get("enabled", True)
        self.registry_client = PackageRegistryClient(
            minimum_age_days=registry_cfg.get("minimum_age_days", 2.0)
        )

        # Session-scoped de-dup: a real, GHSA-verified advisory match for a
        # given host must not be reported again on every subsequent exchange
        # just because the same version banner appears in every response.
        # Found live via fp_benchmark.py: the SAME handful of Werkzeug/Flask
        # CVEs were reported 20-60 times for one target across its exchanges.
        # Keyed by (host, advisory id) so a genuinely different host, or a
        # different disclosed advisory for the same host, still reports.
        self._reported_advisories: set[tuple[str, str]] = set()
        self._reported_banner_components: set[tuple[str, str]] = set()

        # Initialize KEV client
        kev_cfg = config.get("kev_check", {})
        self.kev_enabled = kev_cfg.get("enabled", True)
        self.kev_client = KevClient(
            local_file=kev_cfg.get("local_file"),
            cache_ttl_hours=kev_cfg.get("cache_ttl_hours", 24.0),
        )

        # Configure the global outbound-request throttle (global_throttle.py)
        # from config. Default 0 = unlimited, so this is a no-op unless the
        # tester set a ceiling (via config or the Burp setting). Governs the
        # aggregate request rate every active path sends at the target.
        from harness import global_throttle
        _throttle_cfg = config.get("throttle", {}) or {}
        global_throttle.configure(_throttle_cfg.get("max_requests_per_second", 0))

        # Initialize validator registry
        self.validator_registry = ValidatorRegistry(config)

        # Initialize effort budget
        effort_cfg = config.get("effort_budget", {})
        mode_str = str(effort_cfg.get("mode", "soft")).lower()
        try:
            budget_mode = BudgetMode(mode_str)
        except ValueError:
            log.warning("Unknown effort_budget.mode %r; defaulting to soft.", mode_str)
            budget_mode = BudgetMode.SOFT
        self.effort_budget = EffortBudget(mode=budget_mode, total_tokens=effort_cfg.get("total_tokens"))
        
        # Initialize agent manager (uses plugin system for discovery)
        self.agent_manager = AgentManager(config, self.ollama)
        
        # Initialize coordinator
        self.coordinator = Coordinator(self.ollama, config["coordinator"])
        
        # Initialize analysis pipeline
        self.analysis_pipeline = AnalysisPipeline(
            self.agent_manager,
            self.effort_budget,
            store,
            config,
            ollama_client=self.ollama,
        )
        
        # Initialize fast-path selector
        self.fast_path_selector = fast_path.FastPathSelector(
            set(self.agent_manager.get_enabled_agents())
        )

        # Adaptive re-spin loop (SESSION_HANDOVER.md §7). DEFAULT OFF, and
        # additionally a no-op unless coordinator.cloud_primary is also on --
        # the loop is driven by the cloud coordinator. When enabled, after a
        # first agent pass returns nothing actionable, the coordinator is
        # asked (on the anonymized projection) whether a DIFFERENT specialist
        # is worth a second look, bounded by max_rounds AND the effort budget.
        respin_cfg = config.get("adaptive_respin", {}) or {}
        self.adaptive_respin_enabled = bool(respin_cfg.get("enabled", False))
        self.adaptive_respin_max_rounds = int(respin_cfg.get("max_rounds", 1))
        # A finding is "actionable" (so no re-spin is needed) at or above this
        # confidence -- deliberately low: the loop exists for exchanges the
        # first pass returned essentially nothing on, not to second-guess a
        # weak-but-present hit.
        self.adaptive_respin_min_confidence = float(
            respin_cfg.get("min_actionable_confidence", 0.4)
        )

        # Iterative (active) agent -- F4 + F2. DEFAULT OFF. A send->observe->
        # adapt loop that drives the target, then hands its result to F2's
        # pause->validate->remember integration (pivot_memory). Gated here
        # (enabled flag) AND, for any mutating step, by the safety gate.
        iter_cfg = config.get("iterative_agent", {}) or {}
        self.iterative_agent_enabled = bool(iter_cfg.get("enabled", False))
        self.iterative_agent_max_steps = int(iter_cfg.get("max_steps", 250))

        # Per-vulnerability resource governance -- F5. The default policy for
        # how much one vulnerability may consume (retries/agents/tokens); a
        # /retry-agents request can tighten or loosen it per call.
        from harness import resource_governor
        self.retry_budget_policy = resource_governor.VulnBudgetPolicy.from_dict(
            config.get("retry_budget", {}))

        # Engagement closed-loop auto-escalation (engagement.py, slice 2). When a
        # finding yields a replayable credential, re-crawl the origin as that new
        # identity in-process and fold the new surface back into the worklist.
        # DEFAULT OFF: it sends active traffic (a role crawl) as a side effect of
        # analysis. Scope-gated to allowed_hosts and throttled regardless.
        self.engagement_auto_escalate = bool(
            (config.get("engagement", {}) or {}).get("auto_escalate", False))
        # Whether the engagement driver may EXECUTE (fetch + analyze) the planned
        # targets, vs. only ever returning the plan. DEFAULT OFF: even when a
        # /run request asks to execute, this must also be true -- so the driver
        # never dispatches active testing automatically without a deliberate opt-in.
        self.engagement_driver_execute = bool(
            (config.get("engagement", {}) or {}).get("driver_execute", False))
        # Auto-escalation blast-radius guard: a hard ceiling on how many
        # credential-triggered re-crawls fire per host in this process lifetime,
        # on top of the per-identity dedup + credential verification below.
        self.engagement_max_escalations = int(
            (config.get("engagement", {}) or {}).get("max_auto_escalations", 10))
        self._escalation_counts: dict[str, int] = {}
        # Stateful agent-role feature crawling (feature_workflow.py). When on,
        # investigate_engagement drives each distinct role through the app's real
        # workflows (GET a page -> submit its forms -> follow) and folds the
        # captured, credential-bearing exchanges into content review + the surface
        # -- reaching what route-guessing can't. DEFAULT OFF: it sends active
        # traffic, and its form submits are additionally gated by
        # allow_mutating_replay inside the client. Scope-gated + throttled.
        self.engagement_feature_crawl = bool(
            (config.get("engagement", {}) or {}).get("feature_crawl", False))
        # Coverage matrix as a DRIVER (I1): actively fire every applicable
        # deterministic leg per (identity x endpoint x check) cell, regardless of
        # whether an agent labelled it -- so the matrix proves "every applicable
        # check was attempted", not merely inferred, and detection no longer hinges
        # on LLM label variance. DEFAULT OFF (sends the extra leg traffic); bounded
        # by coverage_leg_budget. Legs are still gated by active_enabled + scope.
        _eng_cfg = config.get("engagement", {}) or {}
        self.engagement_coverage_drive = bool(_eng_cfg.get("coverage_drive_legs", False))
        self.coverage_leg_budget = int(_eng_cfg.get("coverage_leg_budget", 80))
        # T05/R26: drive coverage at CONCRETE-INPUT granularity -- fan each parameter
        # leg over the endpoint template's real inputs (query/body/object-id) so a
        # confirmation binds to the exact parameter case, and un-run inputs stay
        # visibly pending instead of a coarse endpoint-wide verdict. DEFAULT OFF
        # (finer fan-out = more leg traffic); bounded per cell by coverage_case_budget.
        self.engagement_coverage_case_drive = bool(_eng_cfg.get("coverage_drive_cases", False))
        self.coverage_case_budget = int(_eng_cfg.get("coverage_case_budget", 8))

        log.info(f"Orchestrator initialized with {len(self.agent_manager.get_enabled_agents())} agents")
