"""W-22/RB-7: the A-F ablation harness runs variants reproducibly and
tabulates mean +/- variance across repeats -- verified without a live model
via a stub runner (VariantDefinitionTests/RunAndAggregateTests), AND, since
RB-7, wired to the REAL `harness.orchestrator.Orchestrator.analyze()` entry
point for variants B/C/D/F (never a parallel reimplementation of routing):
  - VariantConfigOverrideTests: each variant's config_transform/
    variant_analyze_kwargs produces the right runtime override, pure config,
    no orchestrator needed.
  - VariantDispatchTests: B's `force_agents` kwarg dispatches EXACTLY ONE
    agent; C's "every agent disabled" config dispatches ZERO -- even for an
    exchange shaped to obviously fast-path under A, and regardless of what
    the stubbed model "returns" for routing. A, on the SAME exchange shape,
    dispatches >=1 agent -- the negative control proving C's zero is the
    override actually taking effect, not an inert/signal-free exchange.
  - VariantCritiqueTests: D's `critique.enabled=False` override actually
    stops the critique pass (findings_reviewed stays 0) versus A on the same
    forced dispatch -- the second negative-control flavor.
  - MetricsTableTests: `orchestrator_variant_runner()` + `run_ablation` +
    `render_table` emit RB-7's required schema (precision/recall/FP/tokens/
    wall-clock) through the completed scaffold, reusing testing.score.score()
    for precision/recall/fp rather than reinventing scoring.

E stays a documented residual throughout (NO_GRAPH_RESIDUAL) -- it is never
asserted to dispatch/score any differently from A, because its runner path
IS A's (see orchestrator_variant_runner's own docstring); only its
`needs_implementation` flag is asserted.

Only the model boundary is stubbed (harness.test_pipeline_gate._SilentModel
pattern); store/cache are redirected to a temp dir for the relevant test
classes' lifetime and restored after. No live Ollama/network, no
*ANSWER_KEY*/blind-target content -- every exchange below is synthetic,
invented for this test.
"""
from __future__ import annotations

import copy
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

import harness.ablation_harness as ah
from harness.ablation_harness import RunMetrics, Variant, run_ablation

_HARNESS_DIR = Path(__file__).resolve().parent

# A bare hostname entry in server.allowed_hosts matches itself AND every
# subdomain (scope_discovery.is_host_allowed) -- so per-test unique
# subdomains keep each test's findings out of the others' prior_findings_
# summary/store reads within the class-scoped temp DB, the same rationale
# test_smoke_detection.py documents for its own host parametrization.
_ROOT_HOST = "ablation-harness-test.local"


def _base_config() -> dict:
    """Shipped config.yaml, with everything that would call out (network/GPU)
    or add nondeterminism silenced -- same shape as harness.test_smoke_
    detection._test_config / harness.test_pipeline_gate._gate_config."""
    with open(_HARNESS_DIR / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    v = cfg.setdefault("validators", {})
    v["active_enabled"] = False
    v["allow_mutating_replay"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = [_ROOT_HOST]
    return cfg


# A strong SQLi shape (query-param quote + a MySQL error body) so variant A's
# deterministic fast_path routes it WITHOUT needing any LLM call at all --
# the same anchor/rationale test_smoke_detection._sqli_exchange uses. This
# is also the exchange variant C must still force to zero dispatched agents,
# and variant A's negative control that it does NOT force to zero.
def _sqli_exchange(host: str) -> dict:
    return {
        "url": f"http://{host}/api/items?id=1'",
        "method": "GET",
        "request_headers": {},
        "request_body": "",
        "response_status": 500,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": (
            '{"error": "You have an error in your SQL syntax; check the manual '
            "that corresponds to your MySQL server version for the right syntax "
            "near '1''\"}"
        ),
        "label": "sqli_shape",
        "ground_truth_category": "A03:Injection",
    }


def _benign_exchange(host: str) -> dict:
    """Signal-free: no query params, plain body -- fast_path finds nothing."""
    return {
        "url": f"http://{host}/hello",
        "method": "GET",
        "request_headers": {},
        "request_body": "",
        "response_status": 200,
        "response_headers": {},
        "response_body": "ok",
        "label": "benign",
    }


# Unique anchors from each prompt's own specialty text -- keys the stub's
# canned finding to the sqli specialist's OWN prompt only (nosql_agent's
# prompt also contains "SQL injection", so a looser match would misfire).
_SQLI_ANCHOR = "SQL injection. Look at parameters"
_COORDINATOR_ANCHOR = "coordinator in a security-testing harness"
_CRITIQUE_ANCHOR = "adversarial reviewer in this security-testing harness"

_SQLI_FINDING = {
    "vulnerability_class": "sql_injection",
    "confidence": 0.9,
    "severity": "high",
    "owasp_category": "A03:2021-Injection",
    "summary": "Error-based SQL injection in the id parameter.",
    "evidence": "Response returns a MySQL syntax error reflecting the injected quote.",
    "suggested_test": "Append a single quote to id and compare the error response.",
    "basis": "derived",
    "validation_hints": [],
}


class _StubOllama:
    """Returns the canned SQLi finding for the sqli specialist's own prompt,
    a fixed ['sqli'] routing decision for the coordinator's own prompt, and a
    "survived" verdict for the adversarial-critique prompt (so a baseline
    variant's critique pass actually REVIEWS the candidate, not just runs and
    finds nothing to say -- otherwise variant A's findings_reviewed would
    read 0 for the same reason variant D's does, defeating the negative
    control). Every other agent prompt gets no findings. Variants B/C never
    reach the coordinator/agent boundary for ROUTING (B forces the agent
    directly, C empties available_agents before any model call could matter
    for routing), so this stub's coordinator answer only matters for the
    variant A/D baselines below."""

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        from harness.ollama_client import OllamaResult
        if _SQLI_ANCHOR in system_prompt:
            return OllamaResult(data={"findings": [dict(_SQLI_FINDING)], "components": []},
                                 prompt_tokens=5, completion_tokens=5)
        if _COORDINATOR_ANCHOR in system_prompt:
            return OllamaResult(data={"dispatch": ["sqli"], "reason": "stub routing"},
                                 prompt_tokens=1, completion_tokens=1)
        if _CRITIQUE_ANCHOR in system_prompt:
            return OllamaResult(
                data={"reviews": [{"index": 0, "verdict": "survived",
                                    "note": "stub critique: independent read matches evidence",
                                    "adjusted_confidence": 0.9}]},
                prompt_tokens=2, completion_tokens=2)
        return OllamaResult(data={"findings": [], "components": []},
                             prompt_tokens=1, completion_tokens=1)

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        result = await self.chat_json_metered(model, system_prompt, user_prompt, temperature)
        return result.data


def _variant(key: str) -> Variant:
    return next(v for v in ah.VARIANTS if v.key == key)


def _build(key: str, base_config: dict):
    orch = ah.build_variant_orchestrator(_variant(key), base_config)
    ah.install_stub_model(orch, _StubOllama())
    return orch


class _TempStoreCase(unittest.IsolatedAsyncioTestCase):
    """Redirects the global state/cache DBs to a temp dir for THIS class only,
    then restores them -- doing this at import time would leak the temp
    paths into every other test module (store._connect/cache._cache read
    module globals); see test_smoke_detection.SmokeDetectionTest's own
    comment for the same rationale."""

    @classmethod
    def setUpClass(cls):
        from harness import cache, store
        cls._tmp = tempfile.mkdtemp(prefix="ablation_harness_test_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        from harness import cache, store
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Original W-22 coverage: harness logic, verified without a live model.
# ---------------------------------------------------------------------------

class VariantDefinitionTests(unittest.TestCase):
    def test_all_six_variants_present_and_tagged(self):
        keys = [v.key for v in ah.VARIANTS]
        self.assertEqual(keys, ["A", "B", "C", "D", "E", "F"])

    def test_config_transforms_tag_and_do_not_mutate_base(self):
        base = {"critique": {"enabled": True}}
        for v in ah.VARIANTS:
            cfg = v.config_transform(base)
            self.assertEqual(cfg[ah.MARKER], v.key)
        # base untouched (deepcopy)
        self.assertTrue(base["critique"]["enabled"])

    def test_minus_critique_is_pure_config(self):
        d = _variant("D")
        cfg = d.config_transform({"critique": {"enabled": True}})
        self.assertFalse(cfg["critique"]["enabled"])
        self.assertFalse(d.needs_implementation)

    def test_seam_variants_no_longer_flagged(self):
        """RB-7: B/C/F now have a real runtime seam wired below (per-call
        kwarg for B, agent-disable config for C, curated fail-open for F),
        so the table must not flag them as unmeasured any more."""
        for key in ("B", "C", "F"):
            self.assertFalse(_variant(key).needs_implementation, key)

    def test_e_still_flagged_needs_implementation(self):
        """E (no-graph) stays a documented residual -- analyze() never
        touches investigate_engagement, so there is no seam to wire here."""
        self.assertTrue(_variant("E").needs_implementation)


class RunAndAggregateTests(unittest.TestCase):
    def _stub_runner(self):
        # Deterministic per-variant metrics with a little per-run spread so
        # variance is non-zero and testable.
        calls = {"n": 0}

        def runner(variant: Variant, config: dict, corpus) -> RunMetrics:
            calls["n"] += 1
            base_tp = {"A": 10, "B": 8, "C": 5, "D": 9, "E": 6, "F": 9}[variant.key]
            spread = calls["n"] % 2  # 0 or 1
            return RunMetrics(tp=base_tp + spread, fp=2, fn=13 - base_tp,
                              confirmed_tp=base_tp - 2, confirmed_fp=1,
                              discovery_coverage=0.5, time_to_first_finding_s=1.0 + spread,
                              cost_tokens=1000 * (1 if variant.key != "A" else 3),
                              wall_time_s=10.0)
        return runner

    def test_run_ablation_runs_every_variant_repeatedly(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=3)
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertEqual(len(r.runs), 3)

    def test_aggregate_reports_mean_and_variance(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=4)
        a = ah.aggregate(results[0])  # variant A
        self.assertEqual(a["tp"]["n"], 4)
        self.assertIsNotNone(a["tp"]["mean"])
        # the +0/+1 spread makes stdev strictly positive (variance is reported)
        self.assertGreater(a["tp"]["stdev"], 0.0)

    def test_aggregate_derives_precision_and_recall(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=2)
        a = ah.aggregate(results[0])  # variant A: tp=10 or 11, fp=2, fn=3
        self.assertIsNotNone(a["precision"]["mean"])
        self.assertIsNotNone(a["recall"]["mean"])
        # precision = tp/(tp+fp); with tp in {10,11}, fp=2 -> in (0.8, 0.85]
        self.assertGreater(a["precision"]["mean"], 0.8)
        self.assertLessEqual(a["precision"]["mean"], 0.85)

    def test_render_table_covers_all_variants_and_flags_unbuilt(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=2)
        table = ah.render_table(results)
        for v in ah.VARIANTS:
            self.assertIn(v.name, table)
        self.assertIn("needs runner impl", table)  # E flagged honestly
        self.assertIn("conf TP", table)            # confirmed-TP column present
        # RB-7 required schema columns are present in the header.
        self.assertIn("| precision |", table)
        self.assertIn("| recall |", table)
        self.assertIn("| FP |", table)
        self.assertIn("| tokens |", table)
        self.assertIn("| wall(s) |", table)

    def test_render_table_only_flags_e_as_unbuilt(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=1)
        table = ah.render_table(results)
        lines = {r["variant"]: r for r in (ah.aggregate(x) for x in results)}
        for key in ("A", "B", "C", "D", "F"):
            self.assertFalse(lines[key]["needs_implementation"], key)
        self.assertTrue(lines["E"]["needs_implementation"])

    def test_variant_runner_receives_the_transformed_config(self):
        seen = {}

        def runner(variant, config, corpus):
            seen[variant.key] = config.get(ah.MARKER)
            return RunMetrics()

        run_ablation("corpus", runner, repeats=1)
        self.assertEqual(seen, {k: k for k in ("A", "B", "C", "D", "E", "F")})


# ---------------------------------------------------------------------------
# RB-7: pure config/kwarg seam checks (no orchestrator, no store/cache needed)
# ---------------------------------------------------------------------------

class VariantConfigOverrideTests(unittest.TestCase):
    def test_base_config_never_mutated(self):
        base = _base_config()
        snapshot = copy.deepcopy(base)
        for v in ah.VARIANTS:
            v.config_transform(base)
        self.assertEqual(base, snapshot)

    def test_variant_d_disables_critique_only(self):
        cfg = _variant("D").config_transform(_base_config())
        self.assertFalse(cfg["critique"]["enabled"])

    def test_variant_f_sets_curated_fail_open(self):
        cfg = _variant("F").config_transform(_base_config())
        self.assertEqual(cfg["coordinator"]["fail_open_mode"], "curated")

    def test_variant_c_disables_every_known_agent(self):
        base = _base_config()
        cfg = _variant("C").config_transform(base)
        self.assertTrue(cfg["agents"])  # sanity: there is something to disable
        for name in base.get("agents", {}):
            self.assertFalse(cfg["agents"][name]["enabled"], name)

    def test_variant_c_uses_config_not_force_agents_empty_list(self):
        self.assertEqual(ah.variant_analyze_kwargs("C"), {})

    def test_variant_a_and_e_leave_config_unchanged_besides_marker(self):
        base = _base_config()
        for key in ("A", "E"):
            cfg = _variant(key).config_transform(base)
            stripped = {k: v for k, v in cfg.items() if k != ah.MARKER}
            self.assertEqual(stripped, base, key)

    def test_variant_b_kwargs_force_single_agent(self):
        self.assertEqual(ah.variant_analyze_kwargs("B"),
                          {"force_agents": [ah.DEFAULT_SINGLE_AGENT]})
        self.assertEqual(ah.variant_analyze_kwargs("B", single_agent="xss"),
                          {"force_agents": ["xss"]})

    def test_other_variants_have_no_call_kwargs(self):
        for key in ("A", "C", "D", "E", "F"):
            self.assertEqual(ah.variant_analyze_kwargs(key), {}, key)

    def test_no_graph_residual_is_documented(self):
        self.assertIn("investigate_engagement", ah.NO_GRAPH_RESIDUAL)
        self.assertIn("residual", ah.NO_GRAPH_RESIDUAL.lower())


# ---------------------------------------------------------------------------
# The core deterministic proof: B -> 1 dispatched agent, C -> 0, through the
# REAL Orchestrator.analyze() path.
# ---------------------------------------------------------------------------

class VariantDispatchTests(_TempStoreCase):

    async def test_variant_b_dispatches_exactly_one_agent(self):
        orch = _build("B", _base_config())
        exchange = ah._exchange_from_dict(_sqli_exchange(f"var-b.{_ROOT_HOST}"))
        resp = await orch.analyze(exchange, **ah.variant_analyze_kwargs("B"))
        self.assertEqual(resp.dispatched_agents, [ah.DEFAULT_SINGLE_AGENT])
        self.assertEqual(len(resp.dispatched_agents), 1)

    async def test_variant_b_forces_whichever_single_agent_is_named(self):
        orch = _build("B", _base_config())
        exchange = ah._exchange_from_dict(_sqli_exchange(f"var-b2.{_ROOT_HOST}"))
        resp = await orch.analyze(
            exchange, **ah.variant_analyze_kwargs("B", single_agent="xss"))
        self.assertEqual(resp.dispatched_agents, ["xss"])
        self.assertEqual(len(resp.dispatched_agents), 1)

    async def test_variant_c_dispatches_zero_agents_on_a_strong_signal_exchange(self):
        orch = _build("C", _base_config())
        exchange = ah._exchange_from_dict(_sqli_exchange(f"var-c.{_ROOT_HOST}"))
        resp = await orch.analyze(exchange, **ah.variant_analyze_kwargs("C"))
        self.assertEqual(resp.dispatched_agents, [])
        self.assertEqual(len(resp.dispatched_agents), 0)

    async def test_variant_c_dispatches_zero_agents_on_a_signal_free_exchange(self):
        orch = _build("C", _base_config())
        exchange = ah._exchange_from_dict(_benign_exchange(f"var-c-b.{_ROOT_HOST}"))
        resp = await orch.analyze(exchange)
        self.assertEqual(resp.dispatched_agents, [])

    async def test_force_agents_empty_list_does_not_force_zero_dispatch(self):
        """Documents WHY variant C's seam is a config override, not
        `force_agents=[]`: an empty list is falsy at orchestrator_detect.py's
        `if force_agents:`, so it falls through to NORMAL routing instead of
        forcing an empty dispatch -- on variant A's unmodified config (agents
        still enabled), that normal routing dispatches >=1 agent, not 0."""
        orch = _build("A", _base_config())
        exchange = ah._exchange_from_dict(_benign_exchange(f"force-empty.{_ROOT_HOST}"))
        resp = await orch.analyze(exchange, force_agents=[])
        self.assertGreaterEqual(len(resp.dispatched_agents), 1)

    async def test_variant_a_baseline_negative_control_dispatches_something(self):
        """Negative control for the C=0 proof: the SAME exchange SHAPE, under
        the unmodified baseline variant, dispatches >=1 agent -- so variant
        C's zero is the override actually taking effect, not an inert
        exchange that would have dispatched nothing under any variant."""
        orch = _build("A", _base_config())
        exchange = ah._exchange_from_dict(_sqli_exchange(f"var-a.{_ROOT_HOST}"))
        resp = await orch.analyze(exchange)
        self.assertGreaterEqual(len(resp.dispatched_agents), 1)


# ---------------------------------------------------------------------------
# Second negative-control flavor: D's critique toggle actually bites.
# ---------------------------------------------------------------------------

class VariantCritiqueTests(_TempStoreCase):

    async def test_variant_d_disables_critique_versus_variant_a_baseline(self):
        base = _base_config()

        orch_a = _build("A", base)
        resp_a = await orch_a.analyze(
            ah._exchange_from_dict(_sqli_exchange(f"var-crit-a.{_ROOT_HOST}")),
            force_agents=["sqli"])
        self.assertGreaterEqual(
            resp_a.findings_reviewed, 1,
            "sanity: baseline variant A must actually run critique on >=1 "
            "finding for variant D's override to be a real (non-vacuous) "
            "negative control")

        orch_d = _build("D", base)
        resp_d = await orch_d.analyze(
            ah._exchange_from_dict(_sqli_exchange(f"var-crit-d.{_ROOT_HOST}")),
            force_agents=["sqli"])
        self.assertEqual(resp_d.findings_reviewed, 0)
        self.assertEqual(resp_d.findings_rejected, 0)


# ---------------------------------------------------------------------------
# The completed scaffold's orchestrator-backed variant_runner + run_ablation
# + render_table, end to end, emitting RB-7's required schema.
# ---------------------------------------------------------------------------

class MetricsTableTests(_TempStoreCase):

    async def test_run_variant_async_emits_schema_fields_on_run_metrics(self):
        orch = _build("A", _base_config())
        exchanges = [
            _sqli_exchange(f"metrics-a.{_ROOT_HOST}"),
            _benign_exchange(f"metrics-b.{_ROOT_HOST}"),
        ]
        metrics = await ah.run_variant_async(
            _variant("A"), exchanges, orch,
            label_category={"sqli_shape": "A03:Injection"})
        self.assertIsInstance(metrics, RunMetrics)
        self.assertGreaterEqual(metrics.tp, 1)
        self.assertGreaterEqual(metrics.cost_tokens, 0)
        self.assertGreaterEqual(metrics.wall_time_s, 0.0)

    def test_orchestrator_variant_runner_through_run_ablation_and_table(self):
        """P3: all six variants selectable through `run_ablation`, each
        producing a schema-complete row, rendered as one table -- the
        completed scaffold's own runner and table, not a parallel module."""
        base = _base_config()
        runner_inner = ah.orchestrator_variant_runner(model_stub_factory=_StubOllama)

        def variant_runner(variant: Variant, config: dict, corpus_arg):
            # run_ablation passes the same opaque `corpus` object through to
            # every call; here each variant instead gets its own exchange on
            # a variant-unique host (store isolation, see _ROOT_HOST's
            # docstring above -- reusing one host/url across variants would
            # let a later variant's analyze() read an earlier variant's
            # cached response instead of exercising its own dispatch).
            exchanges = [_benign_exchange(f"table-{variant.key.lower()}.{_ROOT_HOST}")]
            return runner_inner(variant, config, exchanges)

        results = run_ablation(None, variant_runner, base_config=base, repeats=1)
        self.assertEqual([r.variant.key for r in results], list("ABCDEF"))

        table = ah.render_table(results)
        for v in ah.VARIANTS:
            self.assertIn(v.name, table)
        self.assertIn("| precision |", table)
        self.assertIn("| recall |", table)
        self.assertIn("| FP |", table)
        self.assertIn("| tokens |", table)
        self.assertIn("| wall(s) |", table)
        self.assertIn("needs runner impl", table)  # E, and only E


if __name__ == "__main__":
    unittest.main()
