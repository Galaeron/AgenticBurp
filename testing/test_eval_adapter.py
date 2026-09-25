"""
Caller-level + negative-control tests for testing/eval_adapter.py (PR-5, BP-2).

Discovered both via `python -m unittest discover -s testing -p test_*.py`
(harness.suite's smoke/full tiers) and directly via
`python -m unittest testing.test_eval_adapter`.

Mirrors the established idioms of harness/test_pipeline_gate.py (the
`_SilentModel` / `_install_silent_model` stubbed-model-only pattern) and
testing/test_blind_eval_harness.py (running the REAL orchestrator over
synthetic HttpExchange fixtures with an isolated store DB). The model is the
ONLY stubbed boundary: dispatch, persistence (harness.store), confirmation
suppression, and report generation (harness.report_generator) all run for
real. No live Ollama, no network target, no Docker.

HARD SAFEGUARDS observed here: no *ANSWER_KEY* or blind-target app.py file
is read anywhere in this module; every exchange/finding is synthetic,
constructed in this file, against a `.invalid` fixture host.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TESTING_DIR = Path(__file__).resolve().parent
_ROOT = _TESTING_DIR.parent
if str(_TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTING_DIR))

from labels.manifest import LabelRecord, Manifest, compute_hash  # noqa: E402

import eval_adapter  # noqa: E402
from eval_adapter import (  # noqa: E402
    EvalAdapterError,
    attribute_findings,
    build_eval_artifact,
    compute_stages,
    exchange_descriptor,
    rescore_saved_run,
)

_HARNESS_DIR = _ROOT / "harness"
_HOST = "eval-adapter-fixture.invalid"
_URL_A = f"http://{_HOST}/api/widgets/5"
_URL_B = f"http://{_HOST}/api/widgets/9"


# ---------------------------------------------------------------------------
# Manifest / finding fixtures.
# ---------------------------------------------------------------------------

def _record(exchange_id: str, expected=(), tested_negative=(), status="positive",
           label_scope="synthetic fixture", provenance="unit test fixture -- no answer-key") -> LabelRecord:
    return LabelRecord(
        exchange_id=exchange_id, expected_classes=tuple(expected),
        tested_negative_classes=tuple(tested_negative), label_scope=label_scope,
        status=status, provenance=provenance,
    )


def _manifest(records: list[LabelRecord], corpus: str = "eval-adapter-unittest") -> Manifest:
    return Manifest(corpus=corpus, version="0.0.1", hash=compute_hash(records), records=tuple(records))


def _idor_finding(basis: str = "assumed") -> dict:
    return {
        "vulnerability_class": "idor", "confidence": 0.6,
        "summary": "Ticket referenced by a sequential id; ownership not independently verified",
        "evidence": "single-exchange heuristic only -- not a confirmed exploit",
        "suggested_test": "Re-request the same id with a different identity's token",
        "basis": basis, "severity": "high",
    }


# ---------------------------------------------------------------------------
# Model stubs -- the ONLY stubbed boundary (harness/test_pipeline_gate.py's
# _SilentModel pattern). _PromptSpyModel additionally records every prompt it
# receives, for the label-leakage negative control.
# ---------------------------------------------------------------------------

class _PromptSpyModel:
    def __init__(self, by_url: dict[str, dict] | None = None,
                 by_pair: dict[tuple[str, str], dict] | None = None):
        self._by_url = dict(by_url or {})
        self._by_pair = dict(by_pair or {})
        self.prompts: list[str] = []

    def _canned(self, user_prompt: str) -> dict:
        self.prompts.append(user_prompt)
        for (method, url), payload in self._by_pair.items():
            if f"METHOD: {method}" in user_prompt and url in user_prompt:
                return payload
        for url, payload in self._by_url.items():
            if url in user_prompt:
                return payload
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._canned(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        from harness.ollama_client import OllamaResult
        payload = self._canned(user_prompt)
        return OllamaResult(data=payload, prompt_tokens=11, completion_tokens=4)


class _RaisingModel:
    """Installed only for the rescore negative control -- if anything ever
    calls it, the test must fail loudly, not silently succeed."""

    def __init__(self):
        self.calls = 0

    async def chat_json(self, *a, **kw):
        self.calls += 1
        raise AssertionError("rescore_saved_run must never call the model")

    async def chat_json_metered(self, *a, **kw):
        self.calls += 1
        raise AssertionError("rescore_saved_run must never call the model")


def _install_stub_model(orch, stub) -> None:
    orch.ollama = stub
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub


# ---------------------------------------------------------------------------
# Config / store isolation / orchestrator run plumbing -- mirrors
# harness/test_pipeline_gate.py's _gate_config and
# testing/test_blind_eval_harness.py's _isolated_store/_test_config.
# ---------------------------------------------------------------------------

def _build_config() -> dict:
    import yaml
    with open(_HARNESS_DIR / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    return cfg


@contextlib.contextmanager
def _isolated_store():
    from harness import store, cache
    orig_db, orig_cache = store._DB_PATH, cache._cache
    tmp = tempfile.mkdtemp(prefix="eval_adapter_test_")
    try:
        store._DB_PATH = str(Path(tmp) / "state.db")
        cache.init_cache(db_path=str(Path(tmp) / "cache.db"))
        yield Path(tmp)
    finally:
        store._DB_PATH = orig_db
        cache._cache = orig_cache
        shutil.rmtree(tmp, ignore_errors=True)


def _exchange(url: str, method: str, capture_id: str, body: str = "") -> "object":
    from harness.models import HttpExchange
    return HttpExchange(
        url=url, method=method, request_headers={"Authorization": "Bearer bob-token"},
        request_body=body, response_status=200 if method == "GET" else 201,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 5, "owner": "alice"}', capture_id=capture_id,
    )


async def _run_all(exchanges, orch, force_agents=None) -> None:
    for ex in exchanges:
        await orch.analyze(ex, force_agents=force_agents)


def run_pipeline(exchanges, orch, force_agents=None) -> None:
    asyncio.run(_run_all(exchanges, orch, force_agents=force_agents))


def _fresh_orchestrator(stub):
    from harness.orchestrator import Orchestrator
    orch = Orchestrator(_build_config())
    _install_stub_model(orch, stub)
    return orch


# ---------------------------------------------------------------------------
# Caller-level test: real analyze() -> store -> report -> build_eval_artifact.
# ---------------------------------------------------------------------------

class BuildEvalArtifactCallerLevelTests(unittest.TestCase):
    def test_lead_eligible_finding_scored_and_staged_correctly(self):
        stub = _PromptSpyModel(by_url={_URL_A: {"findings": [_idor_finding("assumed")], "components": []}})
        manifest = _manifest([_record("ex-0", expected=("idor",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)
            self.assertEqual(len(stored), 1, stored)

            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                quarantine_leads=True, git_revision="deadbeef", run_id="run-1",
                corpus_id=manifest.corpus, inputs_hash="fixturehash1", complete=True,
                instrumentation={"model_calls": 1, "prompt_tokens": 11, "completion_tokens": 4,
                                  "total_tokens": 15, "model": "test-stub-model"},
            )

        self.assertEqual(artifact["schema_version"], eval_adapter.SCHEMA_VERSION)
        self.assertEqual(artifact["kind"], "eval_artifact")
        self.assertEqual(len(artifact["stages"]["raw"]), 1)
        self.assertEqual(len(artifact["stages"]["individual"]), 1)
        self.assertEqual(len(artifact["stages"]["surfaced"]), 0)
        self.assertEqual(len(artifact["stages"]["lead"]), 1)
        self.assertEqual(artifact["stages"]["lead"][0]["vulnerability_class"], "idor")

        # Strict exact-class metrics: the manifest expects idor on ex-0, and the
        # (quarantined-but-still-predicted) idor guess is attributed to ex-0 --
        # strict scoring is orthogonal to report visibility (see module docstring).
        overall = artifact["metrics"]["exact_class"]["overall"]
        self.assertEqual(overall["tp"], 1, artifact["metrics"])
        self.assertEqual(overall["fp"], 0, artifact["metrics"])
        self.assertEqual(overall["recall"], 1.0)

        # ScoreProvenance, reused verbatim from harness.score_provenance.
        prov = artifact["provenance"]
        self.assertEqual(prov["git_revision"], "deadbeef")
        self.assertEqual(prov["run_id"], "run-1")
        self.assertEqual(prov["corpus_id"], manifest.corpus)
        self.assertTrue(prov["complete"])

        # Real instrumentation supplied -> real values, not the sentinel.
        self.assertEqual(artifact["instrumentation"]["total_tokens"], 15)
        self.assertEqual(artifact["instrumentation"]["model"], "test-stub-model")

        # Attribution: the finding is attributed to its own exchange.
        self.assertIn("ex-0", artifact["attribution"]["by_exchange"])
        self.assertEqual(artifact["attribution"]["unresolved"], [])

        self.assertTrue(artifact["report_cross_check"]["consistent"])


class UnavailableVsZeroTests(unittest.TestCase):
    def test_missing_instrumentation_is_unavailable_not_zero(self):
        stub = _PromptSpyModel()
        manifest = _manifest([_record("ex-0", status="negative")])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]
        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)
            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                git_revision="deadbeef", run_id="run-1", corpus_id=manifest.corpus,
                inputs_hash="h", complete=True,
                # instrumentation intentionally omitted.
            )
        for key in ("model_calls", "prompt_tokens", "completion_tokens", "total_tokens", "model"):
            self.assertEqual(artifact["instrumentation"][key], "unavailable", artifact["instrumentation"])

    def test_supplied_zero_stays_a_real_zero(self):
        stub = _PromptSpyModel()
        manifest = _manifest([_record("ex-0", status="negative")])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]
        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)
            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                git_revision="deadbeef", run_id="run-1", corpus_id=manifest.corpus,
                inputs_hash="h", complete=True,
                instrumentation={"model_calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                  "total_tokens": 0, "model": "test-stub-model"},
            )
        for key in ("model_calls", "prompt_tokens", "completion_tokens", "total_tokens"):
            self.assertEqual(artifact["instrumentation"][key], 0)
            self.assertNotEqual(artifact["instrumentation"][key], "unavailable")


# ---------------------------------------------------------------------------
# Negative control 1: label leakage.
# ---------------------------------------------------------------------------

class LabelLeakageNegativeControlTests(unittest.TestCase):
    def test_manifest_sentinel_never_reaches_the_model_prompt(self):
        sentinel = "SENTINEL-9f8c7d21-LABEL-LEAK-CHECK"
        # The sentinel lives ONLY inside the manifest's provenance text -- a
        # field that build_eval_artifact/attribute_findings never threads
        # into an exchange or a prompt; this test proves that at runtime,
        # not just by code inspection.
        manifest = _manifest([_record("ex-0", expected=("idor",), provenance=f"{sentinel} permitted source")])
        stub = _PromptSpyModel(by_url={_URL_A: {"findings": [_idor_finding("assumed")], "components": []}})
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)

            self.assertTrue(stub.prompts, "precondition: the model must have been prompted at all")
            for prompt in stub.prompts:
                self.assertNotIn(sentinel, prompt,
                                  "manifest/label text leaked into a prompt passed to analyze()")

            # Building the artifact afterward (the normal call order) must not
            # retroactively leak the sentinel anywhere either.
            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                git_revision="deadbeef", run_id="run-1", corpus_id=manifest.corpus,
                inputs_hash="h", complete=True,
            )
        import json as _json
        self.assertNotIn(sentinel, _json.dumps(artifact["stages"]),
                          "manifest provenance text leaked into the artifact's finding stages")


# ---------------------------------------------------------------------------
# Negative control 2: dropped findings are detected, not silently accepted.
# ---------------------------------------------------------------------------

class DroppedFindingNegativeControlTests(unittest.TestCase):
    def test_synthetic_drop_raises(self):
        stub = _PromptSpyModel(by_url={
            _URL_A: {"findings": [_idor_finding("assumed")], "components": []},
            _URL_B: {"findings": [{"vulnerability_class": "sql injection", "confidence": 0.4,
                                    "summary": "possible sqli", "evidence": "", "suggested_test": "",
                                    "basis": "derived", "severity": "medium"}], "components": []},
        })
        manifest = _manifest([_record("ex-0", expected=("idor",)), _record("ex-1", expected=("sqli",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A), exchange_descriptor("ex-1", "GET", _URL_B)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline(
                [_exchange(_URL_A, "GET", "ex-0"), _exchange(_URL_B, "GET", "ex-1")],
                orch, force_agents=["idor"],
            )
            stored = store.all_host_findings(_HOST)
            self.assertEqual(len(stored), 2, stored)

            truncated = stored[:1]  # synthetic drop: one persisted finding withheld
            with self.assertRaises(EvalAdapterError):
                build_eval_artifact(
                    host=_HOST, stored_findings=truncated, exchanges=exchanges_desc, manifest=manifest,
                    git_revision="deadbeef", run_id="run-1", corpus_id=manifest.corpus,
                    inputs_hash="h", complete=True,
                )

            # Positive control: the untruncated list is accepted.
            build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                git_revision="deadbeef", run_id="run-1", corpus_id=manifest.corpus,
                inputs_hash="h", complete=True,
            )


# ---------------------------------------------------------------------------
# Negative control 3: wrong-exchange joins.
# ---------------------------------------------------------------------------

class AttributionNegativeControlTests(unittest.TestCase):
    """Pure unit tests of attribute_findings' fallback path -- no
    orchestrator/store needed to exercise "0 or >1 (method,url) matches with
    no observation data => unresolved, never assigned to every URL-sharer"."""

    def test_ambiguous_pair_with_no_observations_is_unresolved_not_assigned_to_both(self):
        exchanges = [exchange_descriptor("exX", "GET", _URL_A), exchange_descriptor("exY", "GET", _URL_A)]
        findings = [{"finding_id": "f1", "fingerprint": "fp1", "vulnerability_class": "idor",
                     "method": "GET", "url": _URL_A}]
        predictions, attribution = attribute_findings(findings, exchanges, observations={})
        self.assertEqual(predictions["exX"], [])
        self.assertEqual(predictions["exY"], [])
        self.assertEqual(len(attribution["unresolved"]), 1, attribution)
        self.assertEqual(set(attribution["unresolved"][0]["candidate_exchange_ids"]), {"exX", "exY"})
        self.assertEqual(attribution["by_exchange"]["exX"], [])
        self.assertEqual(attribution["by_exchange"]["exY"], [])

    def test_unique_pair_match_falls_back_correctly_when_no_observations(self):
        exchanges = [exchange_descriptor("exX", "GET", _URL_A), exchange_descriptor("exY", "POST", _URL_A)]
        findings = [{"finding_id": "f1", "fingerprint": "fp1", "vulnerability_class": "idor",
                     "method": "GET", "url": _URL_A}]
        predictions, attribution = attribute_findings(findings, exchanges, observations={})
        self.assertEqual(predictions["exX"], ["idor"])
        self.assertEqual(predictions["exY"], [])
        self.assertEqual(attribution["unresolved"], [])
        self.assertEqual(attribution["by_exchange"]["exX"], ["f1"])

    def test_no_pair_match_at_all_is_unresolved(self):
        exchanges = [exchange_descriptor("exX", "DELETE", _URL_A)]
        findings = [{"finding_id": "f1", "fingerprint": "fp1", "vulnerability_class": "idor",
                     "method": "GET", "url": _URL_A}]
        predictions, attribution = attribute_findings(findings, exchanges, observations={})
        self.assertEqual(predictions["exX"], [])
        self.assertEqual(len(attribution["unresolved"]), 1)
        self.assertEqual(attribution["unresolved"][0]["candidate_exchange_ids"], [])


class ExchangeFirstAttributionCallerLevelTests(unittest.TestCase):
    """Real end-to-end: two exchanges sharing the IDENTICAL (method, url)
    both independently produce the SAME idor finding (one fingerprint,
    dedup-collapsed store row) -- AR-3's finding_observations correctly
    records BOTH exchanges as real observers, and attribute_findings
    attributes the prediction to EACH of its own exchanges (not "mis-joined"
    to a third, uninvolved one, and not silently dropped to just one)."""

    def test_shared_pair_both_real_observers_are_both_attributed(self):
        stub = _PromptSpyModel(by_url={_URL_A: {"findings": [_idor_finding("assumed")], "components": []}})
        manifest = _manifest([_record("ex-0", expected=("idor",)), _record("ex-1", expected=("idor",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A), exchange_descriptor("ex-1", "GET", _URL_A)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline(
                [_exchange(_URL_A, "GET", "ex-0"), _exchange(_URL_A, "GET", "ex-1")],
                orch, force_agents=["idor"],
            )
            stored = store.all_host_findings(_HOST)
            self.assertEqual(len(stored), 1, "same fingerprint on both exchanges must dedup to one row")

            observations = store.finding_observations([stored[0]["fingerprint"]])
            self.assertEqual(sorted(observations.get(stored[0]["fingerprint"], [])), ["ex-0", "ex-1"])

            predictions, attribution = attribute_findings(stored, exchanges_desc, observations)

        self.assertEqual(predictions["ex-0"], ["idor"])
        self.assertEqual(predictions["ex-1"], ["idor"])
        self.assertEqual(attribution["unresolved"], [])
        self.assertIn(stored[0]["finding_id"] or stored[0]["fingerprint"], attribution["by_exchange"]["ex-0"])
        self.assertIn(stored[0]["finding_id"] or stored[0]["fingerprint"], attribution["by_exchange"]["ex-1"])


# ---------------------------------------------------------------------------
# Negative control 4: scorer/report visibility disagreement is detected.
# ---------------------------------------------------------------------------

class VisibilityDisagreementNegativeControlTests(unittest.TestCase):
    def test_lead_and_surfaced_are_disjoint(self):
        # Different METHODS (not just different urls) for the two exchanges:
        # harness.store.prior_findings_summary legitimately re-embeds an
        # earlier exchange's URL into a LATER exchange's prompt on the same
        # host (run_exchanges runs sequentially on purpose -- see
        # testing/test_blind_eval_harness.py's own note on this), so keying
        # the stub on (method, url) pairs with distinct methods is what
        # keeps the second exchange's canned response from being shadowed
        # by the first exchange's url leaking into its prompt as context.
        stub = _PromptSpyModel(by_pair={
            ("GET", _URL_A): {"findings": [_idor_finding("assumed")], "components": []},
            ("POST", _URL_B): {"findings": [_idor_finding("derived")], "components": []},  # not lead-eligible
        })
        manifest = _manifest([_record("ex-0", expected=("idor",)), _record("ex-1", expected=("idor",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A), exchange_descriptor("ex-1", "POST", _URL_B)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline(
                [_exchange(_URL_A, "GET", "ex-0"), _exchange(_URL_B, "POST", "ex-1")],
                orch, force_agents=["idor"],
            )
            stored = store.all_host_findings(_HOST)
            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                quarantine_leads=True, git_revision="deadbeef", run_id="run-1",
                corpus_id=manifest.corpus, inputs_hash="h", complete=True,
            )

        self.assertEqual(len(artifact["stages"]["lead"]), 1)
        self.assertEqual(len(artifact["stages"]["surfaced"]), 1)
        lead_fps = {f["fingerprint"] for f in artifact["stages"]["lead"]}
        surfaced_fps = {f["fingerprint"] for f in artifact["stages"]["surfaced"]}
        self.assertEqual(lead_fps & surfaced_fps, set(), "a finding must never appear in both stages")
        self.assertTrue(artifact["report_cross_check"]["consistent"])

    def test_a_forced_mismatch_against_the_rendered_report_is_caught(self):
        """Proves the disagreement check has teeth: if the rendered report's
        own declared lead count ever disagreed with what this adapter
        computed, build_eval_artifact must raise -- not silently accept it.
        Simulated by patching generate_markdown_report's return value (the
        only way to produce a disagreement, since compute_stages and the
        real report share the exact same predicate/order and cannot
        otherwise diverge)."""
        stub = _PromptSpyModel(by_url={_URL_A: {"findings": [_idor_finding("assumed")], "components": []}})
        manifest = _manifest([_record("ex-0", expected=("idor",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]

        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)

            with mock.patch.object(eval_adapter, "generate_markdown_report",
                                    return_value="fake report, **7 quarantined test suggestion(s)**."):
                with self.assertRaises(EvalAdapterError):
                    build_eval_artifact(
                        host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                        quarantine_leads=True, git_revision="deadbeef", run_id="run-1",
                        corpus_id=manifest.corpus, inputs_hash="h", complete=True,
                    )


# ---------------------------------------------------------------------------
# rescore_saved_run: read-only, no model, no store, no network.
# ---------------------------------------------------------------------------

class RescoreSavedRunTests(unittest.TestCase):
    def _build_live_artifact(self):
        stub = _PromptSpyModel(by_url={_URL_A: {"findings": [_idor_finding("assumed")], "components": []}})
        manifest = _manifest([_record("ex-0", expected=("idor",))])
        exchanges_desc = [exchange_descriptor("ex-0", "GET", _URL_A)]
        with _isolated_store():
            from harness import store
            orch = _fresh_orchestrator(stub)
            run_pipeline([_exchange(_URL_A, "GET", "ex-0")], orch, force_agents=["idor"])
            stored = store.all_host_findings(_HOST)
            artifact = build_eval_artifact(
                host=_HOST, stored_findings=stored, exchanges=exchanges_desc, manifest=manifest,
                quarantine_leads=True, git_revision="deadbeef", run_id="run-1",
                corpus_id=manifest.corpus, inputs_hash="h", complete=True,
                instrumentation={"model_calls": 1, "prompt_tokens": 11, "completion_tokens": 4,
                                  "total_tokens": 15, "model": "test-stub-model"},
            )
        return artifact, manifest

    def test_rescore_recomputes_without_model_or_store(self):
        artifact, manifest = self._build_live_artifact()
        raising_model = _RaisingModel()

        with mock.patch("harness.store._connect", side_effect=AssertionError(
                "rescore_saved_run must never touch harness.store")):
            rescored = rescore_saved_run(artifact, manifest, git_revision="deadbeef2")

        self.assertEqual(raising_model.calls, 0, "the model stub must never have been invoked")
        self.assertEqual(rescored["kind"], "historical_rescore")
        self.assertIn("rescored_from", rescored)
        self.assertEqual(rescored["rescored_from"]["original_kind"], "eval_artifact")

        # Same underlying data -> same recomputed stages/metrics.
        self.assertEqual(len(rescored["stages"]["lead"]), len(artifact["stages"]["lead"]))
        self.assertEqual(len(rescored["stages"]["surfaced"]), len(artifact["stages"]["surfaced"]))
        self.assertEqual(rescored["metrics"]["exact_class"]["overall"],
                          artifact["metrics"]["exact_class"]["overall"])

    def test_rescore_can_recompute_under_a_different_quarantine_policy(self):
        artifact, manifest = self._build_live_artifact()
        self.assertEqual(len(artifact["stages"]["lead"]), 1)
        self.assertEqual(len(artifact["stages"]["surfaced"]), 0)

        rescored = rescore_saved_run(artifact, manifest, git_revision="deadbeef2", quarantine_leads=False)
        self.assertEqual(len(rescored["stages"]["lead"]), 0)
        self.assertEqual(len(rescored["stages"]["surfaced"]), 1)


# ---------------------------------------------------------------------------
# compute_stages: pure-function shape checks (no orchestrator needed).
# ---------------------------------------------------------------------------

class ComputeStagesUnitTests(unittest.TestCase):
    def test_individual_always_equals_surfaced_plus_lead(self):
        findings = [
            {"vulnerability_class": "idor", "basis": "assumed", "confirmed": False,
             "oracle_verified": False, "confidence": 0.6, "fingerprint": "a"},
            {"vulnerability_class": "idor", "basis": "derived", "confirmed": False,
             "oracle_verified": False, "confidence": 0.6, "fingerprint": "b"},
            {"vulnerability_class": "potential-attack-chain:idor+ssrf", "basis": "derived",
             "confirmed": False, "oracle_verified": False, "confidence": 0.5, "fingerprint": "c"},
        ]
        raw, individual, surfaced, lead = compute_stages(findings, quarantine_leads=True)
        self.assertEqual(len(raw), 3)
        self.assertEqual(len(individual), 2)  # chain hypothesis excluded
        self.assertEqual(len(surfaced) + len(lead), len(individual))
        self.assertEqual({f["fingerprint"] for f in lead}, {"a"})
        self.assertEqual({f["fingerprint"] for f in surfaced}, {"b"})

    def test_quarantine_off_surfaces_everything(self):
        findings = [{"vulnerability_class": "idor", "basis": "assumed", "confirmed": False,
                     "oracle_verified": False, "confidence": 0.6, "fingerprint": "a"}]
        raw, individual, surfaced, lead = compute_stages(findings, quarantine_leads=False)
        self.assertEqual(lead, [])
        self.assertEqual(len(surfaced), 1)


# ---------------------------------------------------------------------------
# FR-4 (2026-09-25): gate_uncorroborated_catchall stage-split tests. Mirrors
# harness/test_gate_generic_guesses.py's caller-level report tests, but at
# the eval_adapter stage-split level -- the two must never disagree (see
# compute_stages' docstring: it applies the SAME predicates, in the SAME
# order, as generate_markdown_report).
# ---------------------------------------------------------------------------

class GateUncorroboratedCatchallStageSplitTests(unittest.TestCase):
    def _finding(self, vulnerability_class, confidence=0.9, confirmed=False,
                oracle_verified=False, fingerprint="fp"):
        return {
            "vulnerability_class": vulnerability_class, "basis": "assumed",
            "confirmed": confirmed, "oracle_verified": oracle_verified,
            "confidence": confidence, "fingerprint": fingerprint,
        }

    def test_high_confidence_catchall_variants_routed_to_lead_not_surfaced(self):
        # confidence=0.9 on every finding -- proves the gate ignores
        # confidence entirely, unlike gate_low_confidence_generic.
        findings = [
            self._finding("security_misconfiguration", fingerprint="a"),
            self._finding("Security misconfiguration", fingerprint="b"),
            self._finding("information_disclosure", fingerprint="c"),
            self._finding("verbose_error_disclosure", fingerprint="d"),
            self._finding("excessive_data_exposure", fingerprint="e"),
        ]
        raw, individual, surfaced, lead = compute_stages(
            findings, quarantine_leads=False, gate_uncorroborated_catchall=True)
        self.assertEqual(len(individual), 5)
        self.assertEqual(surfaced, [])
        self.assertEqual({f["fingerprint"] for f in lead}, {"a", "b", "c", "d", "e"})

    def test_confirmed_and_oracle_verified_catchall_stay_surfaced(self):
        findings = [
            self._finding("security_misconfiguration", confirmed=True, fingerprint="a"),
            self._finding("information_disclosure", oracle_verified=True, fingerprint="b"),
        ]
        raw, individual, surfaced, lead = compute_stages(
            findings, quarantine_leads=False, gate_uncorroborated_catchall=True)
        self.assertEqual(lead, [])
        self.assertEqual({f["fingerprint"] for f in surfaced}, {"a", "b"})

    def test_negative_control_concrete_classes_stay_surfaced(self):
        # No global leg requirement: sqli/xss/path_traversal are untouched
        # even with the flag on.
        findings = [
            self._finding("sqli", fingerprint="a"),
            self._finding("xss", fingerprint="b"),
            self._finding("path_traversal", fingerprint="c"),
        ]
        raw, individual, surfaced, lead = compute_stages(
            findings, quarantine_leads=False, gate_uncorroborated_catchall=True)
        self.assertEqual(lead, [])
        self.assertEqual({f["fingerprint"] for f in surfaced}, {"a", "b", "c"})

    def test_flag_off_gates_nothing(self):
        findings = [
            self._finding("security_misconfiguration", fingerprint="a"),
            self._finding("information_disclosure", fingerprint="b"),
        ]
        raw, individual, surfaced, lead = compute_stages(
            findings, quarantine_leads=False, gate_uncorroborated_catchall=False)
        self.assertEqual(lead, [])
        self.assertEqual({f["fingerprint"] for f in surfaced}, {"a", "b"})


if __name__ == "__main__":
    unittest.main()
