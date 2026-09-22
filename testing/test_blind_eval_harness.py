"""RB-8 (INV-1 fix): offline regression coverage for
testing/blind-target-2/run_blind_eval.py.

INV-1 (verified problem): the blind-eval driver ran the real orchestrator
over curated exchanges and dumped raw findings, but never called
harness.report_generator.generate_markdown_report -- the SOLE caller of
harness.confirmation_gate.should_quarantine_as_lead -- so the
`quarantine_unverified_leads` knob was a no-op on its output. The driver
also mutated harness.store._DB_PATH at module level with no
`if __name__ == "__main__":` guard, so it could not be imported for testing
without running live (live Ollama, C:\\tmp DB paths).

This module proves, entirely offline:
  1. The refactored driver is now import-safe (no live run on import).
  2. Its scorecard-building code actually INVOKES the quarantine gate: a
     lead-eligible finding (basis=assumed/recalled, a live-verified class,
     unconfirmed, not oracle-verified) is quarantined -- routed to leads,
     not reported.
  3. A synthetic secure/true-negative control whose own (simulated)
     false-positive guess is quarantined stays `controls_clean`; a control
     whose finding is NOT quarantine-eligible is correctly flagged dirty --
     proving the controls_clean metric discriminates rather than always
     reading True by construction.
  4. The scorecard carries timing + token-cost aggregates.
  5. Multi-run variance aggregation (P3) works and its shape is stable.
  6. The P4 cross-identity-REJECT knob is injected by the runner at
     runtime, default OFF, never baked into the committed config.

HARD SAFEGUARDS observed here: no answer-key/app.py file is read; the only
blind-target-2 file touched is run_blind_eval.py itself (loaded by file
path below, since "blind-target-2" is not a valid dotted package name).
The only stubbed boundary is the model (harness/test_pipeline_gate.py's
_SilentModel pattern) -- dispatch, confirmation-suppression and report
generation all run for real, against synthetic HttpExchange fixtures built
in this file. No live Ollama, no network target, no Docker.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TESTING_DIR = Path(__file__).resolve().parent
_ROOT = _TESTING_DIR.parent
_RUNNER_PATH = _ROOT / "testing" / "blind-target-2" / "run_blind_eval.py"


def _load_runner_module():
    """Load run_blind_eval.py by file path (its directory, blind-target-2,
    is not a valid dotted package name). Registered in sys.modules under a
    fixed name before exec -- required for its `from __future__ import
    annotations` + dataclass fields to resolve (dataclass looks the
    defining module up via sys.modules[cls.__module__]) -- so repeated
    calls intentionally reuse/refresh the same module object rather than
    each producing a distinct, mutually-`isinstance`-incompatible class."""
    import sys as _sys
    spec = importlib.util.spec_from_file_location("rb8_blind_eval_runner", _RUNNER_PATH)
    mod = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Synthetic fixtures -- no real blind-target-2 exchange or answer-key data.
# ---------------------------------------------------------------------------

_HOST = "eval-fixture.invalid"
_VULN_URL = f"http://{_HOST}/api/tickets/5"
_CLEAN_CONTROL_URL = f"http://{_HOST}/api/tickets/99"
_DIRTY_CONTROL_URL = f"http://{_HOST}/api/tickets/7"


def _exchange(url: str, ground_truth: str, label: str) -> dict:
    return {
        "url": url,
        "method": "GET",
        "request_headers": {"Authorization": "Bearer bob-token"},
        "request_body": "",
        "response_status": 200,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": json.dumps({"id": 5, "subject": "billing question", "owner": "alice"}),
        "ground_truth": ground_truth,
        "label": label,
    }


def _idor_finding(basis: str) -> dict:
    return {
        "vulnerability_class": "idor",
        "confidence": 0.6,
        "summary": "Ticket referenced by a sequential id; ownership not verified in this single exchange",
        "evidence": "single-exchange heuristic only -- not a confirmed exploit",
        "suggested_test": "Re-request the same id with a different identity's token",
        "basis": basis,
        "severity": "high",
    }


class _CannedFindingModel:
    """Stand-in for OllamaClient -- the ONLY stubbed boundary, matching
    harness/test_pipeline_gate.py's _SilentModel pattern (stub the model,
    keep dispatch/confirmation/report-generation real). Unlike
    _SilentModel, this stub is exchange-aware: base_agent._user_prompt
    embeds the exchange's URL into the rendered user_prompt, so this class
    keys its canned response off which fixture URL appears in it, letting
    one orchestrator run exercise several distinct synthetic scenarios
    (a lead-eligible guess, a control's matching false-positive guess, a
    control's NON-lead-eligible guess) without needing a real model.
    `assumed_urls` get a basis='assumed' IDOR guess (lead-eligible);
    `derived_urls` get a basis='derived' IDOR claim (NOT lead-eligible --
    used only to prove should_quarantine_as_lead discriminates). Every
    other exchange gets empty findings, like _SilentModel.
    """

    def __init__(self, assumed_urls: frozenset[str] = frozenset(), derived_urls: frozenset[str] = frozenset()):
        self._assumed_urls = set(assumed_urls)
        self._derived_urls = set(derived_urls)

    def _canned(self, user_prompt: str) -> dict:
        for url in self._assumed_urls:
            if url in user_prompt:
                return {"findings": [_idor_finding("assumed")], "components": []}
        for url in self._derived_urls:
            if url in user_prompt:
                return {"findings": [_idor_finding("derived")], "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._canned(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        from harness.ollama_client import OllamaResult
        return OllamaResult(data=self._canned(user_prompt), prompt_tokens=42, completion_tokens=17)


def _install_stub_model(orch, stub) -> None:
    orch.ollama = stub
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub


def _stub_orchestrator_factory(stub: _CannedFindingModel):
    def factory(config):
        from harness.orchestrator import Orchestrator
        orch = Orchestrator(config)
        _install_stub_model(orch, stub)
        return orch
    return factory


@contextlib.contextmanager
def _isolated_store():
    """Save/restore harness.store._DB_PATH and harness.cache._cache around a
    run -- run_once() deliberately mutates these module globals (that is
    the point: it is what makes findings persist -> all_host_findings ->
    generate_markdown_report work), but this test process also runs OTHER
    test modules in the same `unittest discover` process, so the shared dev
    DB reference must be restored afterward (same discipline as
    harness/test_pipeline_gate.py's run_live())."""
    from harness import store, cache
    orig_db, orig_cache = store._DB_PATH, cache._cache
    tmp = tempfile.mkdtemp(prefix="rb8_blind_eval_test_")
    try:
        yield Path(tmp)
    finally:
        store._DB_PATH = orig_db
        cache._cache = orig_cache
        shutil.rmtree(tmp, ignore_errors=True)


def _test_config(runner, *, quarantine_leads=True, **overrides):
    cfg = runner.build_eval_config(fail_open_mode="curated", quarantine_leads=quarantine_leads, **overrides)
    # Determinism / offline-safety knobs beyond RB-8's own three injected
    # measurement knobs -- same reasoning as test_pipeline_gate.py's
    # _gate_config(): no critique pass (a second, differently-shaped
    # chat_json call the canned stub doesn't model), no cloud coordinator,
    # no network-touching advisory/registry/KEV lookups. validators.active_
    # enabled stays at config.yaml's committed default (False) unless the
    # caller explicitly asked for cross_identity_reject.
    cfg["critique"]["enabled"] = False
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    return cfg


class ImportSafetyTests(unittest.TestCase):
    """P1: importing the refactored driver must run nothing."""

    def test_import_does_not_call_asyncio_run(self):
        with mock.patch("asyncio.run") as m:
            _load_runner_module()
            m.assert_not_called()

    def test_import_does_not_touch_store_or_cache(self):
        from harness import store, cache
        orig_db, orig_cache = store._DB_PATH, cache._cache
        try:
            _load_runner_module()
            self.assertEqual(store._DB_PATH, orig_db, "import must not mutate harness.store._DB_PATH")
            self.assertIs(cache._cache, orig_cache, "import must not mutate harness.cache._cache")
        finally:
            store._DB_PATH = orig_db
            cache._cache = orig_cache

    def test_live_entrypoint_is_guarded(self):
        source = _RUNNER_PATH.read_text()
        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn("_live_main()", source)


class ConfigInjectionTests(unittest.TestCase):
    """The three measurement knobs are injected at runtime, never baked
    into the committed harness/config.yaml."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_quarantine_and_fail_open_mode_injected(self):
        cfg = self.runner.build_eval_config(fail_open_mode="curated", quarantine_leads=True)
        self.assertEqual(cfg["coordinator"]["fail_open_mode"], "curated")
        self.assertTrue(cfg["reporting"]["quarantine_unverified_leads"])

    def test_committed_config_defaults_stay_safe(self):
        # The runner's default call (quarantine off/on aside) must not have
        # silently flipped any active/mutating/discovery/oracle default --
        # only the three RB-8 knobs this module owns are touched.
        with open(self.runner.HARNESS_DIR / "config.yaml") as f:
            import yaml
            committed = yaml.safe_load(f)
        self.assertFalse(committed.get("validators", {}).get("active_enabled", False))
        self.assertFalse(committed.get("validators", {}).get("cross_identity", {}).get("enabled", False))
        self.assertFalse(committed.get("oracle", {}).get("enabled", False))

    def test_cross_identity_reject_off_by_default(self):
        cfg = self.runner.build_eval_config()
        self.assertFalse((cfg.get("validators") or {}).get("active_enabled", False))
        self.assertFalse((cfg.get("validators") or {}).get("cross_identity", {}).get("enabled", False))

    def test_cross_identity_reject_knob_injects_when_requested(self):
        # P4: proves the injection wiring works. Never exercised with a real
        # orchestrator run in this offline suite -- cross_identity sends live
        # requests, which HARD SAFEGUARDS forbid here.
        cfg = self.runner.build_eval_config(cross_identity_reject=True)
        self.assertTrue(cfg["validators"]["active_enabled"])
        self.assertTrue(cfg["validators"]["cross_identity"]["enabled"])

    def test_build_eval_config_does_not_mutate_base_config(self):
        base = {"coordinator": {"fail_open_mode": "all"}, "reporting": {}}
        self.runner.build_eval_config(fail_open_mode="curated", quarantine_leads=True, base_config=base)
        self.assertEqual(base["coordinator"]["fail_open_mode"], "all")
        self.assertEqual(base["reporting"], {})


class QuarantinePathInvokedTests(unittest.TestCase):
    """P1's core claim: the scorecard-building code actually invokes
    should_quarantine_as_lead / generate_markdown_report over what the
    orchestrator persisted -- not a no-op."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_lead_eligible_finding_is_quarantined_not_reported(self):
        exchanges = [_exchange(_VULN_URL, "idor_lead", "assumed IDOR guess on a real ticket endpoint")]
        stub = _CannedFindingModel(assumed_urls=frozenset({_VULN_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_findings_total"], 1, sc["results"])
        self.assertEqual(sc["n_quarantined_leads"], 1)
        self.assertEqual(sc["n_surfaced_findings"], 0)
        report = sc["markdown_reports"][self.runner_host()]
        self.assertIn("Test Suggestions", report)
        self.assertNotIn("## Unconfirmed Findings", report)

    def runner_host(self):
        from harness import store
        return store.host_of(_VULN_URL)

    def test_quarantine_off_leaves_lead_eligible_finding_reported(self):
        # Same fixture, quarantine_leads=False: negative control on the KNOB
        # itself -- proves the harness's behavior actually depends on it,
        # not that generate_markdown_report is called unconditionally.
        exchanges = [_exchange(_VULN_URL, "idor_lead", "assumed IDOR guess on a real ticket endpoint")]
        stub = _CannedFindingModel(assumed_urls=frozenset({_VULN_URL}))
        cfg = _test_config(self.runner, quarantine_leads=False)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_quarantined_leads"], 0)
        self.assertEqual(sc["n_surfaced_findings"], 1)


class ControlsCleanMetricTests(unittest.TestCase):
    """controls_clean must discriminate, not just always read True."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_clean_control_whose_false_positive_is_quarantined_stays_clean(self):
        # A secure endpoint the model ALSO guesses "idor" on (the realistic
        # false-positive pattern the 2026-09-21 reconciliation review
        # describes) must be quarantined like any other lead-eligible
        # finding, keeping the control clean.
        exchanges = [
            _exchange(_VULN_URL, "idor_lead", "positive"),
            _exchange(_CLEAN_CONTROL_URL, "control", "secure ticket, model still guesses idor"),
        ]
        stub = _CannedFindingModel(assumed_urls=frozenset({_VULN_URL, _CLEAN_CONTROL_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls"], 1)
        self.assertTrue(sc["controls_clean"], sc["dirty_controls"])
        self.assertEqual(sc["n_quarantined_leads"], 2)
        self.assertEqual(sc["n_surfaced_findings"], 0)

    def test_dirty_control_is_detected_not_quarantined(self):
        # Discrimination check: a control finding with basis='derived' is
        # NOT lead-eligible (should_quarantine_as_lead requires assumed/
        # recalled), so it surfaces -- and must be flagged as a dirty
        # control. Proves controls_clean is computed, not hardcoded True.
        exchanges = [_exchange(_DIRTY_CONTROL_URL, "control", "secure ticket, but claim is basis=derived")]
        stub = _CannedFindingModel(derived_urls=frozenset({_DIRTY_CONTROL_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertFalse(sc["controls_clean"], sc["dirty_controls"])
        self.assertEqual(len(sc["dirty_controls"]), 1)
        self.assertEqual(sc["dirty_controls"][0]["url"], _DIRTY_CONTROL_URL)
        self.assertEqual(sc["n_surfaced_findings"], 1)
        self.assertEqual(sc["n_quarantined_leads"], 0)


class ScorecardShapeTests(unittest.TestCase):
    """P2: timing + token-cost aggregates are present and well-typed."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_timing_and_token_fields_present(self):
        exchanges = [
            _exchange(_VULN_URL, "idor_lead", "positive"),
            _exchange(_CLEAN_CONTROL_URL, "control", "secure"),
        ]
        stub = _CannedFindingModel(assumed_urls=frozenset({_VULN_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        timing = sc["timing"]
        for key in ("total_elapsed_seconds", "mean_elapsed_seconds", "max_elapsed_seconds", "total_tokens_spent"):
            self.assertIn(key, timing)
        self.assertGreaterEqual(timing["total_elapsed_seconds"], 0.0)
        self.assertGreaterEqual(timing["total_tokens_spent"], 0)
        self.assertEqual(len(sc["results"]), 2)
        self.assertIn("config_fingerprint", sc)
        self.assertTrue(sc["config_fingerprint"])
        self.assertEqual(sc["n_errors"], 0)


class MultiRunVarianceTests(unittest.TestCase):
    """P3: N>=5 stubbed runs, aggregated per-metric mean/variance."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_five_run_variance_aggregation(self):
        exchanges = [
            _exchange(_VULN_URL, "idor_lead", "positive"),
            _exchange(_CLEAN_CONTROL_URL, "control", "secure"),
        ]
        stub = _CannedFindingModel(assumed_urls=frozenset({_VULN_URL, _CLEAN_CONTROL_URL}))

        def config_builder():
            return _test_config(self.runner, quarantine_leads=True)

        with _isolated_store() as tmp:
            agg = self.runner.run_eval_n_times(
                exchanges, config_builder=config_builder, db_dir=tmp, n_runs=5,
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(agg["n_runs"], 5)
        self.assertEqual(len(agg["runs"]), 5)
        variance = agg["variance"]
        for key in ("n_findings_total", "n_quarantined_leads", "n_surfaced_findings",
                    "controls_clean", "total_elapsed_seconds", "total_tokens_spent"):
            self.assertIn(key, variance)
            self.assertIn("mean", variance[key])
            self.assertIn("variance", variance[key])
            self.assertEqual(len(variance[key]["values"]), 5)
        # Deterministic stub -> every run agrees: controls_clean always
        # True, variance ~0. The point of this field is that the
        # aggregation runs correctly, not that a deterministic stub
        # disagrees with itself.
        self.assertEqual(variance["controls_clean"]["mean"], 1.0)
        self.assertAlmostEqual(variance["controls_clean"]["variance"], 0.0)
        self.assertAlmostEqual(variance["n_quarantined_leads"]["variance"], 0.0)


if __name__ == "__main__":
    unittest.main()
