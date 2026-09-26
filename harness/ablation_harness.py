"""A-F architecture ablation harness (W-22, wired by RB-7).

The 36-agent design is currently an unproven assumption -- no specialist-vs-
single-model evidence exists, and "lane discipline" once made precision WORSE.
This harness runs the same held-out corpus, budgets, and credentials across
architecture variants, repeats each run, and produces one comparison table
(precision/recall/FP/tokens/wall-clock, plus TP/FN/confirmed-TP/FP/discovery
coverage/time-to-first-finding) -- enough to decide which specialists survive.

Design: the per-run work is an INJECTABLE callable (`variant_runner`), so the
harness logic (variant definitions, repeated runs, metric aggregation with
variance, table rendering) is reproducible and testable WITHOUT a live model.
`orchestrator_variant_runner()` below builds exactly that callable: it drives
each variant through the REAL `harness.orchestrator.Orchestrator.analyze()`
entry point (never a parallel reimplementation of routing), scoring findings
against corpus ground truth via `testing/score.py`'s `score()` (reused, not
reinvented).

Variant mechanism (RB-7 seam findings; see each `_*` config_transform below
and `variant_analyze_kwargs` for the exact code path each rides):
  A  current            -- baseline; zero overrides, zero call kwargs.
  B  general-model      -- `Orchestrator.analyze(exchange, force_agents=[x])`
                            per-call kwarg forces dispatch to exactly one
                            agent, bypassing fast_path/coordinator routing.
  C  deterministic-only -- every agent disabled BY NAME in the runtime config
                            (force_agents=[] is falsy and does NOT force an
                            empty dispatch -- see `_deterministic_only`),
                            emptying `AgentManager`/`FastPathSelector`/
                            `Coordinator` availability so `dispatched_agents`
                            is always `[]`; deterministic non-LLM legs
                            (shape/validator/known-vuln resolution) still run.
  D  minus-critique     -- pure config: `critique.enabled = False` ->
                            `AnalysisPipeline._critique` short-circuits to
                            `(0, 0)`, so `findings_reviewed`/`_rejected` stay 0.
  E  minus-graph-loop   -- RESIDUAL (NOT wired): the graph is
                            `investigate_engagement`/orchestrator_chain.py,
                            reached only via a separate entry point
                            (`/engagement/{host}/investigate`), never through
                            `analyze()` -- the path every other variant here
                            runs through. See `NO_GRAPH_RESIDUAL`.
  F  strong-single      -- config: `coordinator.fail_open_mode = "curated"`.
                            The closest available runtime seam to "a single,
                            more selective policy" is forcing the fail-open
                            branch (empty/invalid coordinator output) to
                            `Coordinator._curated_fallback`'s high-value
                            shape-keyed subset instead of firing every
                            available agent.
  G  agent-families      -- pure config: `coordinator.routing_mode =
                            "families"` (AR-1, harness/agent_families.py).
                            AgentManager.run_multiple_agents collapses the
                            SAME dispatched agent set into one composed
                            model call per routed family instead of one
                            call per agent; agent SELECTION is untouched.
                            MECHANISM/revertibility only here -- whether
                            the collapse retains recall (P2-2) is owner-
                            reported, not measured by this harness.

Only A/E are pure passthrough; B/D/F/G are runtime config and/or call-kwarg
overrides applied to a DEEP-COPIED base config (`copy.deepcopy`, never
`harness/config.yaml` on disk and never a dict the caller still holds a
reference to) -- the same "load once, override at runtime" shape as
`run_blind_eval.build_eval_config` / `test_pipeline_gate._gate_config`.
"""
from __future__ import annotations

import asyncio
import copy
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable

MARKER = "_ablation_variant"

# Stands in for "one generalist model + tools" (variant B). Any agent name
# enabled in the base config works; `sqli` is enabled by default in the
# shipped `harness/config.yaml` and exists independent of which OTHER agents
# an operator has toggled, so it is a safe, stable default. Callers may pass
# a different `single_agent` to `variant_analyze_kwargs`/`run_variant_async`.
DEFAULT_SINGLE_AGENT = "sqli"

# E (no-graph) has no clean existing runtime toggle -- documented as a
# residual rather than forcing a risky change, per the RB-7 seam findings.
NO_GRAPH_RESIDUAL = (
    "RESIDUAL (documented, not forced): E (minus-graph-loop) has no per-call "
    "or per-config knob. The 'graph' is investigate_engagement's multi-node "
    "build (orchestrator_chain.py), reached only through a SEPARATE entry "
    "point (POST /engagement/{host}/investigate -> Orchestrator.investigate_"
    "engagement) -- analyze() (the path every other variant here is driven "
    "through) never touches it. Every engagement.* auto-drive toggle "
    "(auto_escalate, driver_execute, feature_crawl, coverage_drive_legs, "
    "coverage_drive_cases) is ALREADY False by default in harness/config.yaml "
    "and EngagementPolicy.from_config, so there is no graph running during "
    "analyze() to turn off in an analyze()-only dry-run in the first place. "
    "The real ablation for this variant is an ENTRY-POINT choice -- call "
    "analyze() per captured exchange (every other variant) vs. drive "
    "investigate_engagement over a multi-exchange corpus -- not a config "
    "flag; distinguishing A from E needs an OWNER-run, multi-exchange "
    "engagement corpus through /investigate. E's config_transform returns "
    "the config unchanged (byte-for-byte the same as A) so a caller can "
    "still select 'E' without erroring, but a runner MUST NOT call "
    "investigate_engagement if it wants to honor this variant; this module "
    "does not implement that entry-point switch itself, and VARIANTS keeps "
    "E's `needs_implementation` flag set so the table never pretends it was "
    "measured."
)


def _tag(cfg: dict, key: str) -> dict:
    c = copy.deepcopy(cfg or {})
    c[MARKER] = key
    return c


def _identity(cfg):
    return _tag(cfg, "A")


def _general_model(cfg):
    # No config override: B's mechanism is the `force_agents` per-call kwarg
    # (see `variant_analyze_kwargs`), applied at analyze()-call time, not here.
    return _tag(cfg, "B")


def _deterministic_only(cfg):
    # No config-driven "force empty dispatch" seam exists (`force_agents=[]`
    # is falsy at orchestrator_detect.py's `if force_agents:`, so it falls
    # through to normal routing instead of forcing zero) -- disable every
    # agent BY NAME instead, exactly as an operator would in config.yaml's
    # `agents:` block, just applied at runtime on the deep-copied config.
    c = _tag(cfg, "C")
    agents_cfg = c.setdefault("agents", {})
    agent_names = set(agents_cfg.keys())
    # Cover agents that exist only as plugin-discovered defaults with no
    # explicit `agents:` entry in config.yaml -- agent_manager.py treats a
    # MISSING entry as enabled=True, so those must be named explicitly too
    # or they would stay enabled and defeat this variant.
    try:
        from harness.agents.plugin import get_plugin_system
        agent_names |= set(get_plugin_system().list_agents())
    except Exception:
        pass  # best-effort discovery; explicit config.yaml entries still covered
    for name in agent_names:
        agents_cfg.setdefault(name, {})["enabled"] = False
    return c


def _minus_critique(cfg):
    c = _tag(cfg, "D")
    c.setdefault("critique", {})["enabled"] = False  # pure-config ablation
    return c


def _minus_graph_loop(cfg):
    # RESIDUAL: unchanged config, see NO_GRAPH_RESIDUAL. Distinguishing E
    # from A needs an entry-point choice (investigate_engagement) a runner
    # makes, not a config/call-kwarg override this transform can express.
    return _tag(cfg, "E")


def _strong_single(cfg):
    # Seam finding: no distinct "stronger single model" runtime knob exists;
    # the closest real seam is forcing fail-open routing to the curated
    # high-value subset (Coordinator._fail_open_agents / _curated_fallback)
    # instead of firing every available agent whenever routing fails open.
    c = _tag(cfg, "F")
    c.setdefault("coordinator", {})["fail_open_mode"] = "curated"
    return c


def _family_routing(cfg):
    # AR-1's P2-2 collapse candidate: pure config, same shape as D/F --
    # AgentManager.run_multiple_agents reads coordinator.routing_mode
    # (see harness/agent_families.py) and collapses the SAME dispatched
    # agent set into per-family composed calls. Agent SELECTION
    # (_choose_agents/dispatch) is untouched by this transform or by the
    # mode it sets; only the model-call fan-out changes.
    c = _tag(cfg, "G")
    c.setdefault("coordinator", {})["routing_mode"] = "families"
    return c


@dataclass(frozen=True)
class Variant:
    key: str
    name: str
    description: str
    config_transform: Callable[[dict], dict]
    # Honest: a variant that is not pure config needs a runner code path; the
    # table flags it so an unbuilt variant is never reported as measured.
    needs_implementation: bool = False


VARIANTS: tuple[Variant, ...] = (
    Variant("A", "current", "36 specialists + graph loop + critique (baseline)", _identity),
    Variant("B", "general-model", "one general model + tools, no specialists "
            "(force_agents=[single_agent] bypasses routing)", _general_model),
    Variant("C", "deterministic-only", "deterministic detectors/validators, no LLM agents "
            "(every agent disabled at runtime)", _deterministic_only),
    Variant("D", "minus-critique", "baseline minus the adversarial critique pass", _minus_critique),
    Variant("E", "minus-graph-loop", "captured-exchange analyze() only, no investigate_engagement "
            "(RESIDUAL -- see NO_GRAPH_RESIDUAL, needs an owner-run engagement corpus)",
            _minus_graph_loop, True),
    Variant("F", "strong-single", "baseline routing forced to the curated fail-open subset "
            "(closest available seam to a single, more selective policy)", _strong_single),
    Variant("G", "agent-families", "baseline routing collapsed to per-family composed model "
            "calls (coordinator.routing_mode='families') -- AR-1's P2-2 collapse candidate; "
            "MECHANISM/revertibility only, efficacy is owner-reported", _family_routing),
)


@dataclass
class RunMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    confirmed_tp: int = 0
    confirmed_fp: int = 0
    class_recall: dict = field(default_factory=dict)   # canonical class -> recall
    discovery_coverage: float = 0.0                    # fraction of the surface reached
    time_to_first_finding_s: float | None = None
    cost_tokens: int = 0
    wall_time_s: float = 0.0


@dataclass
class VariantResult:
    variant: Variant
    runs: list[RunMetrics]


def _agg(values) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "stdev": None, "n": 0}
    return {
        "mean": round(statistics.fmean(vals), 3),
        "stdev": round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0,
        "n": len(vals),
    }


def _precision(r: RunMetrics) -> float | None:
    denom = r.tp + r.fp
    return r.tp / denom if denom else None


def _recall(r: RunMetrics) -> float | None:
    denom = r.tp + r.fn
    return r.tp / denom if denom else None


def aggregate(result: VariantResult) -> dict:
    """Per-variant means +/- stdev, INCLUDING precision/recall derived from
    tp/fp/fn (RB-7's required schema: precision/recall/FP/tokens/wall-clock,
    all present here -- fp as `fp`, tokens as `cost_tokens`, wall-clock as
    `wall_time_s`). No second/parallel metrics schema: everything below is
    read off or derived from RunMetrics's own fields."""
    runs = result.runs
    return {
        "variant": result.variant.key,
        "name": result.variant.name,
        "repeats": len(runs),
        "precision": _agg([_precision(r) for r in runs]),
        "recall": _agg([_recall(r) for r in runs]),
        "tp": _agg([r.tp for r in runs]),
        "fp": _agg([r.fp for r in runs]),
        "fn": _agg([r.fn for r in runs]),
        "confirmed_tp": _agg([r.confirmed_tp for r in runs]),
        "confirmed_fp": _agg([r.confirmed_fp for r in runs]),
        "discovery_coverage": _agg([r.discovery_coverage for r in runs]),
        "time_to_first_finding_s": _agg([r.time_to_first_finding_s for r in runs]),
        "cost_tokens": _agg([r.cost_tokens for r in runs]),
        "wall_time_s": _agg([r.wall_time_s for r in runs]),
        "needs_implementation": result.variant.needs_implementation,
    }


def run_ablation(corpus, variant_runner: Callable[[Variant, dict, object], RunMetrics], *,
                 variants=VARIANTS, base_config: dict | None = None,
                 repeats: int = 5) -> list[VariantResult]:
    """Run each variant `repeats` times over `corpus`.

    `variant_runner(variant, config, corpus) -> RunMetrics` does the per-run
    work; injecting it keeps the harness reproducible and testable without a
    live model. Use `orchestrator_variant_runner()` below for a real,
    analyze()-backed runner, or a hand-written stub for pure harness-logic
    tests. Repeating each variant is required (a single run's recall swings
    8/13 -> 7/13 on variance alone), so the table reports mean +/- stdev.
    """
    base_config = base_config or {}
    results: list[VariantResult] = []
    for v in variants:
        cfg = v.config_transform(base_config)
        runs = [variant_runner(v, cfg, corpus) for _ in range(repeats)]
        results.append(VariantResult(variant=v, runs=runs))
    return results


def render_table(results: list[VariantResult]) -> str:
    """One markdown table. Columns lead with RB-7's required schema
    (precision/recall/FP/tokens/wall-clock -- NO accuracy claim implied by
    their presence, they are whatever the runner measured), followed by the
    scaffold's original diagnostic columns."""
    rows = [aggregate(r) for r in results]

    def cell(a):
        if a["mean"] is None:
            return "-"
        return f"{a['mean']}±{a['stdev']}" if a["n"] > 1 else f"{a['mean']}"

    lines = [
        "| variant | precision | recall | FP | tokens | wall(s) | TP | FN "
        "| conf TP | conf FP | disc cov | ttff(s) | notes |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        note = "needs runner impl" if r["needs_implementation"] else ""
        lines.append(
            f"| {r['variant']} {r['name']} | {cell(r['precision'])} | {cell(r['recall'])} "
            f"| {cell(r['fp'])} | {cell(r['cost_tokens'])} | {cell(r['wall_time_s'])} "
            f"| {cell(r['tp'])} | {cell(r['fn'])} | {cell(r['confirmed_tp'])} "
            f"| {cell(r['confirmed_fp'])} | {cell(r['discovery_coverage'])} "
            f"| {cell(r['time_to_first_finding_s'])} | {note} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator-backed variant_runner: drives each variant through the REAL
# analyze() entry point, offline (stubbed model), reusing testing/score.py.
# ---------------------------------------------------------------------------

def variant_analyze_kwargs(key: str, *, single_agent: str = DEFAULT_SINGLE_AGENT) -> dict:
    """Per-call kwargs to pass to `Orchestrator.analyze()` for variant `key`.

    Only B has one: `force_agents` is a per-CALL kwarg (orchestrator_detect.
    py:391), not a config key -- `if force_agents:` (orchestrator_detect.py:
    492) forces `dispatch` to exactly that (filtered-valid) list, bypassing
    fast_path/coordinator routing entirely and deterministically, regardless
    of what a stubbed model would otherwise route. `force_agents=[]` is
    FALSY at that same check (see `_deterministic_only`'s docstring for why C
    uses a config override instead), so every other variant gets no kwargs.
    """
    if key == "B":
        return {"force_agents": [single_agent]}
    return {}


def build_variant_orchestrator(
    variant: Variant,
    base_config: dict,
    *,
    orchestrator_factory: Callable[[dict], Any] | None = None,
):
    """Construct an Orchestrator (or whatever `orchestrator_factory` returns)
    for `variant`, with that variant's runtime config overrides applied via
    its own `config_transform`. Does not touch the model boundary -- callers
    stub `orch.ollama`/agents/coordinator via `install_stub_model` below
    (mirrors `harness.test_pipeline_gate._install_silent_model`, the
    canonical pattern every caller-level test in this repo uses)."""
    cfg = variant.config_transform(base_config)
    cfg = {k: v for k, v in cfg.items() if k != MARKER}  # MARKER is harness-internal bookkeeping
    factory = orchestrator_factory
    if factory is None:
        from harness.orchestrator import Orchestrator
        factory = Orchestrator
    return factory(cfg)


def install_stub_model(orch, stub) -> None:
    """Install `stub` in place of the real OllamaClient at every boundary
    `analyze()` touches -- the orchestrator, each constructed agent, the
    analysis pipeline, and the coordinator. Same shape as
    `harness.test_pipeline_gate._install_silent_model`."""
    orch.ollama = stub
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub


def _exchange_from_dict(e: dict):
    from harness.models import HttpExchange
    return HttpExchange(
        url=e["url"], method=e.get("method", "GET"),
        request_headers=e.get("request_headers", {}) or {},
        request_body=e.get("request_body", "") or "",
        response_status=e.get("response_status", 200),
        response_headers=e.get("response_headers", {}) or {},
        response_body=e.get("response_body", "") or "",
    )


async def run_variant_async(
    variant: Variant,
    exchanges: list[dict],
    orch,
    *,
    single_agent: str = DEFAULT_SINGLE_AGENT,
    label_category: dict[str, str] | None = None,
) -> RunMetrics:
    """Run every synthetic exchange in `exchanges` through `orch.analyze()`
    with `variant`'s call-site kwargs, sequentially (later exchanges' prior
    context can legitimately depend on earlier ones having persisted). `orch`
    must already have been built with `build_variant_orchestrator(variant,
    ...)` (or equivalent) so its CONFIG matches `variant`; this function only
    supplies the per-call kwargs half of the variant's mechanism.

    `exchanges` items: {"url", "method", "request_headers", "request_body",
    "response_status", "response_headers", "response_body", "label"
    (optional, defaults to "ex<i>"), "ground_truth_category" (optional)}.
    `label_category` maps each label to the ground-truth OWASP category
    string testing.score.classify() would produce -- omit a label to mark it
    a benign/negative-control exchange.

    tp/fp/fn come straight from `testing.score.score()`'s micro-averaged
    overall (reused, not reimplemented); confirmed_tp/confirmed_fp and
    discovery_coverage are NOT populated here (this is a dry-run over
    analyze() only, no confirmation pipeline or discovery instrumentation),
    so they stay at RunMetrics' defaults rather than a fabricated number.
    """
    kwargs = variant_analyze_kwargs(variant.key, single_agent=single_agent)
    labeled_findings: dict[str, list[str]] = {}
    tokens_total = 0
    prev_tokens = 0
    first_finding_s: float | None = None

    t0 = time.perf_counter()
    for idx, e in enumerate(exchanges):
        label = e.get("label") or f"ex{idx}"
        ex = _exchange_from_dict(e)
        resp = await orch.analyze(ex, **kwargs)
        spent = max(resp.effort_spent_tokens - prev_tokens, 0)
        tokens_total += spent
        prev_tokens = resp.effort_spent_tokens
        classes = [f.vulnerability_class for rep in resp.agent_reports for f in rep.findings]
        labeled_findings[label] = classes
        if classes and first_finding_s is None:
            first_finding_s = round(time.perf_counter() - t0, 4)
    wall_time_s = time.perf_counter() - t0

    truth = label_category
    if truth is None:
        truth = {
            e.get("label") or f"ex{i}": e["ground_truth_category"]
            for i, e in enumerate(exchanges) if e.get("ground_truth_category")
        }

    from testing.score import score as _score
    report = _score(labeled_findings, label_category=truth or {})
    overall = report["overall"]

    return RunMetrics(
        tp=overall["tp"], fp=overall["fp"], fn=overall["fn"],
        time_to_first_finding_s=first_finding_s,
        cost_tokens=tokens_total,
        wall_time_s=round(wall_time_s, 4),
    )


def orchestrator_variant_runner(
    *,
    orchestrator_factory: Callable[[dict], Any] | None = None,
    model_stub_factory: Callable[[], Any] | None = None,
    single_agent: str = DEFAULT_SINGLE_AGENT,
    label_category: dict[str, str] | None = None,
) -> Callable[[Variant, dict, object], RunMetrics]:
    """Build a `variant_runner` for `run_ablation` that drives each variant
    through the REAL `Orchestrator.analyze()` path: constructs an Orchestrator
    from the variant's already-transformed config (stripping the harness-
    internal MARKER key), optionally installs a stubbed model (pass a
    zero-arg factory, e.g. `_StubOllama`, so each of the `repeats` runs gets
    its own fresh stub/orchestrator instance), and runs `corpus` (a list of
    exchange dicts, see `run_variant_async`) through it.

    E's config_transform is a no-op (identity, see NO_GRAPH_RESIDUAL), so
    this runner exercises E exactly like A over `corpus` -- it does NOT call
    `investigate_engagement`. E's row is therefore still not a real
    ablation of the graph loop; `VARIANTS` keeps its `needs_implementation`
    flag set so `render_table` flags it, and callers must not read E's row
    as a distinct measurement from A's.
    """
    def _runner(variant: Variant, config: dict, corpus) -> RunMetrics:
        cfg = {k: v for k, v in (config or {}).items() if k != MARKER}
        factory = orchestrator_factory
        if factory is None:
            from harness.orchestrator import Orchestrator
            factory = Orchestrator
        orch = factory(cfg)
        if model_stub_factory is not None:
            install_stub_model(orch, model_stub_factory())
        return asyncio.run(run_variant_async(
            variant, list(corpus or []), orch,
            single_agent=single_agent, label_category=label_category))
    return _runner


# No `if __name__ == "__main__":` entrypoint: this module is instrument-only.
# An OWNER live run plugs a real (unstubbed) model in via
# `orchestrator_variant_runner(model_stub_factory=None)` against a real,
# multi-exchange corpus with real ground truth -- analogous to how
# testing/blind-target-2/run_blind_eval.py's own `if __name__ == "__main__":`
# block plugs its importable functions into a live run. Importing this
# module runs nothing.
