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


def _exchange(url: str, ground_truth: str, label: str, method: str = "GET") -> dict:
    return {
        "url": url,
        "method": method,
        "request_headers": {"Authorization": "Bearer bob-token"},
        "request_body": "",
        "response_status": 200 if method == "GET" else 405,
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


def _dependency_finding() -> dict:
    """A host-level dependency/banner-class finding (B2-3's dedup test):
    `known-vulnerable-dependency:*` has no confirmation leg (leg_tier ==
    "none"), so should_quarantine_as_lead never quarantines it regardless
    of basis -- it always surfaces, like the real GHA-sourced advisories
    orchestrator_detect.py produces (see harness/issues.py's
    _is_dependency_class exemption, which groups these by host+class only,
    dropping the endpoint/url, so the SAME advisory independently observed
    on several urls collapses to ONE issue)."""
    return {
        "vulnerability_class": "known-vulnerable-dependency:libfoo",
        "confidence": 0.9,
        "summary": "libfoo has a disclosed advisory",
        "evidence": "Seen via response header banner",
        "suggested_test": "Confirm the exact deployed version falls within the affected range",
        "basis": "derived",
        "severity": "medium",
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
    used only to prove should_quarantine_as_lead discriminates).
    `dependency_urls` get a host-level dependency/banner finding (see
    _dependency_finding), used to prove issue-level dedup of the same
    advisory independently observed on several urls.
    `assumed_pairs`/`derived_pairs` are (method, url) tuples, matched
    against the rendered prompt's "METHOD: <m>" line as well as the url --
    used where two exchanges share a url but differ by method (B2-3
    CORRECTIONS items 2/3), so only the intended exchange gets a finding.
    Checked before the url-only sets above. Every other exchange gets empty
    findings, like _SilentModel.
    """

    def __init__(self, assumed_urls: frozenset[str] = frozenset(), derived_urls: frozenset[str] = frozenset(),
                 dependency_urls: frozenset[str] = frozenset(),
                 assumed_pairs: frozenset[tuple[str, str]] = frozenset(),
                 derived_pairs: frozenset[tuple[str, str]] = frozenset()):
        self._assumed_urls = set(assumed_urls)
        self._derived_urls = set(derived_urls)
        self._dependency_urls = set(dependency_urls)
        self._assumed_pairs = set(assumed_pairs)
        self._derived_pairs = set(derived_pairs)

    def _canned(self, user_prompt: str) -> dict:
        for method, url in self._assumed_pairs:
            if f"METHOD: {method}" in user_prompt and url in user_prompt:
                return {"findings": [_idor_finding("assumed")], "components": []}
        for method, url in self._derived_pairs:
            if f"METHOD: {method}" in user_prompt and url in user_prompt:
                return {"findings": [_idor_finding("derived")], "components": []}
        for url in self._assumed_urls:
            if url in user_prompt:
                return {"findings": [_idor_finding("assumed")], "components": []}
        for url in self._derived_urls:
            if url in user_prompt:
                return {"findings": [_idor_finding("derived")], "components": []}
        for url in self._dependency_urls:
            if url in user_prompt:
                return {"findings": [_dependency_finding()], "components": []}
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


class IssueLevelControlsCleanTests(unittest.TestCase):
    """B2-3 (+CORRECTIONS): issue-level controls_clean must (a) dedup
    duplicate findings sharing an issue key into a single issue, (b) key
    control/vuln attribution on (method, url) -- not url alone -- so a
    write-method control sharing a url with a read-method vuln is neither
    dropped from the denominator nor falsely cleared, (c) use a fixed
    vuln-label allow-set (inconclusive must not exclude a control), (d)
    still discriminate a genuinely dirty control, (e) keep host-wide
    dependency/banner findings out of the per-control dirty/clean decision,
    and (f) the scorecard must emit the raw fields, the issue-level fields,
    the per-control driver list, and the host-level list."""

    def setUp(self):
        self.runner = _load_runner_module()

    def test_same_dependency_advisory_across_two_control_urls_collapses_to_one_issue(self):
        # (item 10, renamed/re-documented) NOT a "duplicate findings on one
        # control" case -- this proves the fingerprint MERGES the same
        # host-wide dependency/banner advisory when it is independently
        # observed on two DIFFERENT control urls (harness.issues groups
        # dependency-class findings by host+class only, per
        # _is_dependency_class -- endpoint/method dropped from the key).
        exchanges = [
            _exchange(_CLEAN_CONTROL_URL, "control", "dependency banner on control #1"),
            _exchange(_DIRTY_CONTROL_URL, "control", "dependency banner on control #2"),
        ]
        stub = _CannedFindingModel(dependency_urls=frozenset({_CLEAN_CONTROL_URL, _DIRTY_CONTROL_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        # Raw metric counts every dirty url separately.
        self.assertEqual(len(sc["dirty_controls"]), 2, sc["dirty_controls"])
        self.assertFalse(sc["controls_clean"])
        # Item 12: a host-wide dependency/banner finding never dirties a
        # specific control -- both controls stay clean at the issue level,
        # and the merged advisory shows up in host_level_issues_on_controls.
        self.assertTrue(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(sc["per_control_drivers"], [])
        self.assertEqual(sc["n_controls_clean_issue_level"], 2)
        self.assertEqual(len(sc["host_level_issues_on_controls"]), 1, sc["host_level_issues_on_controls"])
        self.assertEqual(sc["host_level_issues_on_controls"][0]["finding_count"], 2)
        self.assertCountEqual(sc["host_level_issues_on_controls"][0]["affected_instances"],
                               [_CLEAN_CONTROL_URL, _DIRTY_CONTROL_URL])

    def test_delete_control_sharing_url_with_get_vuln_stays_clean_when_only_vuln_has_finding(self):
        # (item 2, rewritten) GET vuln vs DELETE control on the SAME url --
        # not GET/GET, which would bake the old url-only bug into the test.
        # The DELETE control IS counted in the fair denominator (its
        # (method, url) pair differs from the vuln's), and stays CLEAN
        # because only the GET vuln exchange's own finding surfaced.
        shared_url = _VULN_URL
        exchanges = [
            _exchange(shared_url, "confirmed_vuln", "the real vuln, GET", method="GET"),
            _exchange(shared_url, "control", "write-method control on the same url", method="DELETE"),
        ]
        stub = _CannedFindingModel(assumed_pairs=frozenset({("GET", shared_url)}))
        cfg = _test_config(self.runner, quarantine_leads=False)  # keep the vuln finding surfaced
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        # Raw metric (url-only, kept for comparability) is still dirtied.
        self.assertFalse(sc["controls_clean"], sc["dirty_controls"])
        # Issue-level: (DELETE, url) != (GET, url) -> not ambiguous, IS
        # counted in the fair denominator, and stays clean.
        self.assertEqual(sc["n_controls_excluded_ambiguous"], 0)
        self.assertEqual(sc["n_controls_issue_level"], 1)
        self.assertTrue(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(sc["n_controls_clean_issue_level"], 1)
        self.assertEqual(sc["per_control_drivers"], [])

    def test_delete_control_with_own_finding_on_shared_url_is_caught_not_hidden(self):
        # (item 3, NEW -- hidden-FP regression guard) GET vuln exchange PLUS
        # a DELETE control that has its OWN surfaced finding on the SAME
        # url. The old url-only logic treated the shared url as "ambiguous"
        # and excluded it from the denominator entirely, silently hiding a
        # real false positive on the control. This must go RED against that
        # logic and GREEN after the (method, url) fix.
        shared_url = _VULN_URL
        exchanges = [
            _exchange(shared_url, "confirmed_vuln", "the real vuln, GET", method="GET"),
            _exchange(shared_url, "control", "write-method control, but its OWN guess is a false positive",
                      method="DELETE"),
        ]
        # Only the DELETE exchange gets a (non-lead-eligible, so surfaced)
        # finding -- the GET vuln exchange gets none, isolating the DELETE
        # control's own false positive as the sole surfaced finding.
        stub = _CannedFindingModel(derived_pairs=frozenset({("DELETE", shared_url)}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls_excluded_ambiguous"], 0)
        self.assertEqual(sc["n_controls_issue_level"], 1)
        self.assertFalse(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(sc["n_controls_clean_issue_level"], 0)
        self.assertEqual(len(sc["per_control_drivers"]), 1)
        self.assertEqual(sc["per_control_drivers"][0]["method"], "DELETE")
        self.assertEqual(sc["per_control_drivers"][0]["url"], shared_url)

    def test_scorecard_emits_raw_and_issue_level_fields_and_driver_list(self):
        # POSITIVE (shape): all metrics and both list fields are present.
        exchanges = [_exchange(_CLEAN_CONTROL_URL, "control", "clean control")]
        stub = _CannedFindingModel()
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        for key in ("controls_clean", "dirty_controls",
                    "controls_clean_issue_level", "per_control_drivers",
                    "host_level_issues_on_controls", "n_controls_issue_level",
                    "n_controls_clean_issue_level", "n_controls_excluded_ambiguous"):
            self.assertIn(key, sc)
        self.assertNotIn("dirty_controls_issue_level", sc)  # item 9: duplicate key removed
        self.assertIsInstance(sc["per_control_drivers"], list)
        self.assertIsInstance(sc["host_level_issues_on_controls"], list)
        self.assertTrue(sc["controls_clean"])
        self.assertTrue(sc["controls_clean_issue_level"])

    def test_genuinely_dirty_control_still_flagged_by_issue_level_metric(self):
        # NEGATIVE CONTROL: mirrors test_dirty_control_is_detected_not_
        # quarantined -- a surfaced, non-lead-eligible finding actually
        # attributable to a control exchange (no url-sharing, no
        # duplication) must still be flagged dirty by the issue-level
        # metric. The new metric must not read clean by construction.
        exchanges = [_exchange(_DIRTY_CONTROL_URL, "control", "secure ticket, but claim is basis=derived")]
        stub = _CannedFindingModel(derived_urls=frozenset({_DIRTY_CONTROL_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertFalse(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(len(sc["per_control_drivers"]), 1)
        self.assertEqual(sc["per_control_drivers"][0]["url"], _DIRTY_CONTROL_URL)
        self.assertIn("idor", [vc.lower() for vc in sc["per_control_drivers"][0]["vulnerability_classes"]][0])

    def test_host_wide_finding_on_control_excluded_endpoint_scoped_finding_still_dirties(self):
        # (item 12, NEW) A host-wide dependency/banner finding on a control
        # url must NOT mark that control dirty -- it goes into
        # host_level_issues_on_controls instead -- while an endpoint-scoped
        # finding on a (different) control url DOES dirty it, in the same run.
        exchanges = [
            _exchange(_CLEAN_CONTROL_URL, "control", "banner-only control"),
            _exchange(_DIRTY_CONTROL_URL, "control", "secure ticket, but claim is basis=derived"),
        ]
        stub = _CannedFindingModel(
            derived_urls=frozenset({_DIRTY_CONTROL_URL}),
            dependency_urls=frozenset({_CLEAN_CONTROL_URL}),
        )
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls_issue_level"], 2)
        self.assertEqual(sc["n_controls_clean_issue_level"], 1)
        self.assertFalse(sc["controls_clean_issue_level"])
        driver_urls = {d["url"] for d in sc["per_control_drivers"]}
        self.assertIn(_DIRTY_CONTROL_URL, driver_urls)
        self.assertNotIn(_CLEAN_CONTROL_URL, driver_urls)
        self.assertEqual(len(sc["host_level_issues_on_controls"]), 1)
        self.assertEqual(sc["host_level_issues_on_controls"][0]["affected_instances"], [_CLEAN_CONTROL_URL])

    def test_mixed_case_method_still_detected_as_ambiguous_and_excluded(self):
        # (B2-3b review fix, NEW -- case-normalization regression guard) A
        # control record method="delete" (lowercase) vs a confirmed_vuln
        # method="DELETE" (uppercase) on the SAME url -- the SAME underlying
        # HTTP method, just recorded with inconsistent casing (the exact
        # scenario the review's blocker names). Correct behavior: this pair
        # is genuinely ambiguous and must be excluded from the fair
        # denominator entirely, case-insensitively, exactly like the
        # same-case ambiguity test above.
        #
        # If method were compared in its RAW (un-normalized) case only at
        # set-construction time -- normalizing only later, downstream, for
        # finding attribution -- ("delete", url) and ("DELETE", url) fail to
        # intersect: the control wrongly stays in the (raw) fair set, but
        # the vuln's OWN surfaced finding, uppercased by the downstream
        # attribution step, then matches the (separately uppercased) fair
        # set and gets wrongly counted as dirtying "the control" -- the
        # exact hidden-FP bug B2-3b exists to prevent, reintroduced via case
        # mismatch. Verified empirically to go RED against that
        # raw-case-then-downstream-uppercase construction and GREEN once
        # method is normalized to uppercase AT CONSTRUCTION for every set.
        shared_url = _VULN_URL
        exchanges = [
            _exchange(shared_url, "control", "control record, lowercase delete", method="delete"),
            _exchange(shared_url, "confirmed_vuln", "the real vuln, uppercase DELETE", method="DELETE"),
        ]
        # Only the vuln's own (lead-eligible, so surfaced when quarantine is
        # off) finding fires -- isolating whether it gets wrongly attributed
        # to the "control" bucket instead of being excluded as ambiguous.
        stub = _CannedFindingModel(assumed_pairs=frozenset({("DELETE", shared_url)}))
        cfg = _test_config(self.runner, quarantine_leads=False)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls_excluded_ambiguous"], 1)
        self.assertEqual(sc["n_controls_issue_level"], 0)
        self.assertTrue(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(sc["per_control_drivers"], [])

    def test_mixed_case_delete_control_with_own_finding_still_dirties_it(self):
        # Companion positive case: once the SAME-method-mixed-case pair
        # above is correctly excluded as ambiguous, a genuinely DIFFERENT
        # control (its own url) whose ground-truth method is lowercase must
        # still be dirtied by its own surfaced finding -- lowercasing a
        # control's method must not accidentally make it invisible to
        # attribution either.
        exchanges = [_exchange(_DIRTY_CONTROL_URL, "control", "lowercase-method control, real FP",
                                method="delete")]
        # The stub matches the prompt's literal "METHOD: <m>" line, which
        # carries the exchange's own (here lowercase) method verbatim --
        # base_agent._user_prompt does not normalize it.
        stub = _CannedFindingModel(derived_pairs=frozenset({("delete", _DIRTY_CONTROL_URL)}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls_excluded_ambiguous"], 0)
        self.assertEqual(sc["n_controls_issue_level"], 1)
        self.assertFalse(sc["controls_clean_issue_level"], sc["per_control_drivers"])
        self.assertEqual(len(sc["per_control_drivers"]), 1)
        self.assertEqual(sc["per_control_drivers"][0]["method"], "DELETE")
        self.assertEqual(sc["per_control_drivers"][0]["url"], _DIRTY_CONTROL_URL)

    def test_inconclusive_exchange_sharing_pair_with_control_does_not_exclude_it(self):
        # (item 4, NEW) An 'inconclusive'-labeled exchange sharing the SAME
        # (method, url) as a control must NOT remove that control from the
        # fair denominator -- only the fixed _VULN_LABELS allow-set does.
        exchanges = [
            _exchange(_DIRTY_CONTROL_URL, "control", "secure ticket, but claim is basis=derived"),
            _exchange(_DIRTY_CONTROL_URL, "inconclusive", "same (method,url), inconclusive-labeled"),
        ]
        stub = _CannedFindingModel(derived_urls=frozenset({_DIRTY_CONTROL_URL}))
        cfg = _test_config(self.runner, quarantine_leads=True)
        with _isolated_store() as tmp:
            sc = self.runner.run_once(
                exchanges, config=cfg, state_db=tmp / "state.db", cache_db=tmp / "cache.db",
                orchestrator_factory=_stub_orchestrator_factory(stub), force_agents=["idor"],
            )
        self.assertEqual(sc["n_controls_excluded_ambiguous"], 0)
        self.assertEqual(sc["n_controls_issue_level"], 1)
        self.assertFalse(sc["controls_clean_issue_level"])
        self.assertEqual(len(sc["per_control_drivers"]), 1)
        self.assertEqual(sc["per_control_drivers"][0]["url"], _DIRTY_CONTROL_URL)


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
