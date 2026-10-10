"""Tests for testing/strict_benchmark.py's run-health certification (FR-1, F04).

FR-1's defect: `_one_run()` discarded `run_exchanges`'s return value, and
`run_corpus_strict()` passed a hardcoded `complete=True` to
`build_eval_artifact` regardless of whether the run actually worked -- an
all-failing (or entirely un-persisted) run still emitted a "complete"
artifact. This module tests the fix at two layers:

  * `assess_run_health` -- a PURE function (no IO, no model): given
    synthetic `ExchangeOutcome`s + the findings a run persisted, does it
    correctly certify eligible/ineligible, including the negative control
    (a genuinely healthy run stays eligible)?
  * `run_corpus_strict` -- the run-health FALSIFIER: with `_one_run`
    monkeypatched to a synthetic stub (never touching the model/network),
    does an all-failing run actually come out of `run_corpus_strict` marked
    `run_health.eligible=False` / `complete=False` with its metrics still
    visible, and does a healthy stub still certify `eligible=True`/
    `complete=True` -- plus does the `harness.cache` global get restored?

Entirely OFFLINE: no live Ollama, no network target, no Docker. The only
"orchestrator" ever exercised here is the synthetic `_one_run` stub this
file installs -- `strict_benchmark.rbe.default_orchestrator_factory`
(which would construct a REAL `harness.orchestrator.Orchestrator`) is never
called. No `*ANSWER_KEY*` file or a blind target's `app.py` is read; the
corpus/manifest fixtures used are synthetic, built in this file.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TESTING_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTING_DIR.parent
for p in (str(_REPO_ROOT), str(_TESTING_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import strict_benchmark  # noqa: E402
from strict_benchmark import assess_run_health  # noqa: E402
from labels.manifest import LabelRecord, compute_hash  # noqa: E402
from harness import store, cache  # noqa: E402

ExchangeOutcome = strict_benchmark.rbe.ExchangeOutcome

_HOST = "strict-benchmark-health-fixture.invalid"
_URL = f"http://{_HOST}/api/widgets/1"


def _outcome(idx: int, *, error=None, findings=None, dispatched_agents=("sqli",)) -> ExchangeOutcome:
    return ExchangeOutcome(
        idx=idx, label="", ground_truth="?", dispatched_agents=list(dispatched_agents),
        findings=list(findings) if findings is not None else [], validation_reports=[],
        elapsed_seconds=0.01, tokens_spent=0, error=error,
    )


# ---------------------------------------------------------------------------
# Layer 1: assess_run_health -- pure function, synthetic ExchangeOutcomes.
# ---------------------------------------------------------------------------

class AssessRunHealthPureTests(unittest.TestCase):
    def test_all_error_outcomes_are_ineligible(self):
        outcomes = [_outcome(i, error=f"boom-{i}") for i in range(3)]
        health = assess_run_health(outcomes, stored_findings=[], n_expected=3)
        self.assertFalse(health["eligible"], health)
        self.assertEqual(health["failed"], 3)
        self.assertTrue(health["reasons"])
        self.assertTrue(health["degraded"])

    def test_one_error_among_many_is_ineligible(self):
        outcomes = [_outcome(i, findings=[{"vulnerability_class": "sqli"}]) for i in range(4)]
        outcomes[2] = _outcome(2, error="boom")
        stored = [{"fingerprint": "f1"}]
        health = assess_run_health(outcomes, stored_findings=stored, n_expected=4)
        self.assertFalse(health["eligible"], health)
        self.assertEqual(health["failed"], 1)
        self.assertEqual(health["completed"], 3)

    def test_empty_findings_on_a_completed_run_is_ineligible(self):
        # All 3 exchanges "completed" (no error, agents dispatched), but
        # nothing was ever found/persisted -- FR-1 says this must NOT be
        # certified eligible: offline, it is indistinguishable from a
        # silently-inoperative detector.
        outcomes = [_outcome(i, findings=[]) for i in range(3)]
        health = assess_run_health(outcomes, stored_findings=[], n_expected=3)
        self.assertFalse(health["eligible"], health)
        self.assertEqual(health["failed"], 0)
        self.assertIn("no findings were persisted to the store for a run with exchanges to analyze",
                      health["reasons"])

    def test_incomplete_run_fewer_outcomes_than_expected_is_ineligible(self):
        outcomes = [_outcome(0, findings=[{"vulnerability_class": "sqli"}])]
        health = assess_run_health(outcomes, stored_findings=[{"fingerprint": "f1"}], n_expected=3)
        self.assertFalse(health["eligible"], health)
        self.assertEqual(health["missing"], 2)

    def test_negative_control_healthy_run_is_eligible(self):
        """NEGATIVE CONTROL: a genuinely healthy run (all completed, no
        errors, findings actually persisted) must certify eligible."""
        outcomes = [_outcome(i, findings=[{"vulnerability_class": "sqli"}]) for i in range(3)]
        stored = [{"fingerprint": "f1"}, {"fingerprint": "f2"}]
        health = assess_run_health(outcomes, stored_findings=stored, n_expected=3)
        self.assertTrue(health["eligible"], health)
        self.assertEqual(health["reasons"], [])
        self.assertFalse(health["degraded"])
        self.assertEqual(health["failed"], 0)
        self.assertEqual(health["missing"], 0)


# ---------------------------------------------------------------------------
# Layer 2: run_corpus_strict falsifier -- _one_run monkeypatched, no model.
# ---------------------------------------------------------------------------

def _write_corpus(tmp_path: Path) -> Path:
    exchanges = [{
        "id": "ex-0", "url": _URL, "method": "GET",
        "request_headers": {}, "request_body": "",
        "response_status": 200, "response_headers": {}, "response_body": "{}",
        "label": "synthetic fixture exchange (no answer-key)", "ground_truth": "sqli",
    }]
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(exchanges))
    return path


def _write_manifest(tmp_path: Path) -> Path:
    records = [LabelRecord(
        exchange_id="ex-0", expected_classes=("sqli",), tested_negative_classes=(),
        label_scope="synthetic fixture", status="positive",
        provenance="unit test fixture -- no answer-key read",
    )]
    payload = {
        "corpus": "strict-benchmark-health-fixture", "version": "0.0.1",
        "hash": compute_hash(records), "records": [r.to_dict() for r in records],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload))
    return path


async def _failing_one_run(exchanges, config, *, force_agents=None):
    """Simulates an all-failing run: every exchange errors, nothing is ever
    persisted to the store."""
    return [
        ExchangeOutcome(idx=i, label="", ground_truth="?", dispatched_agents=[],
                       findings=[], validation_reports=[], elapsed_seconds=0.01,
                       tokens_spent=0, error="synthetic injected failure")
        for i in range(len(exchanges))
    ]


async def _healthy_one_run(exchanges, config, *, force_agents=None):
    """Simulates a healthy run: persists one real finding per exchange to
    the (already-isolated, per-run) store and returns non-error outcomes."""
    from harness.models import HttpExchange, Finding
    outcomes = []
    for i, e in enumerate(exchanges):
        ex = HttpExchange(
            url=e["url"], method=e["method"], request_headers=e["request_headers"],
            request_body=e["request_body"], response_status=e["response_status"],
            response_headers=e["response_headers"], response_body=e["response_body"],
            capture_id=str(e.get("id", i)),
        )
        finding = Finding(
            vulnerability_class="sqli", confidence=0.9, summary="synthetic fixture finding",
            evidence="synthetic fixture -- no live model/target", suggested_test="n/a",
            basis="derived",
        )
        store.persist_findings(ex, "test-agent", [finding])
        outcomes.append(ExchangeOutcome(
            idx=i, label="", ground_truth="?", dispatched_agents=["sqli"],
            findings=[finding.model_dump()], validation_reports=[],
            elapsed_seconds=0.01, tokens_spent=5, error=None,
        ))
    return outcomes


class RunCorpusStrictHealthFalsifierTests(unittest.TestCase):
    def _run(self, one_run_stub):
        # mkdtemp + best-effort rmtree (not tempfile.TemporaryDirectory's
        # auto-cleanup): sqlite's WAL/journal sidecar files opened+closed by
        # harness.store/harness.cache in this process can still hold a
        # transient Windows file lock at the moment this context exits, and
        # a leftover temp dir is harmless -- mirrors testing/test_eval_adapter
        # .py's _isolated_store() idiom for the same reason.
        tmp = Path(tempfile.mkdtemp(prefix="strict_benchmark_health_test_"))
        try:
            corpus = _write_corpus(tmp)
            manifest_path = _write_manifest(tmp)
            orig_db, orig_cache = store._DB_PATH, cache._cache
            try:
                with mock.patch.object(strict_benchmark, "_one_run", one_run_stub):
                    result = strict_benchmark.run_corpus_strict(
                        str(corpus), str(manifest_path), n_runs=1,
                        workdir=str(tmp / "work"), config={"reporting": {}},
                        git_revision="deadbeef",
                    )
            finally:
                # FR-1 cleanup: the cache global must come back exactly as
                # it went in, even though run_corpus_strict re-inits it
                # per run internally.
                self.assertEqual(store._DB_PATH, orig_db,
                                 "store._DB_PATH was not restored")
                self.assertIs(cache._cache, orig_cache,
                              "harness.cache's global was not restored (FR-1 cleanup)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return result

    def test_all_failing_run_is_not_certified_but_metrics_stay_visible(self):
        result = self._run(_failing_one_run)
        run = result["runs"][0]
        self.assertIn("run_health", run)
        self.assertFalse(run["run_health"]["eligible"], run["run_health"])
        self.assertFalse(run["provenance"]["complete"])
        # Partial scores stay VISIBLE -- the artifact/metrics are still
        # emitted, only mislabeled ineligible, never suppressed outright.
        self.assertIn("metrics", run)
        self.assertIn("exact_class", run["metrics"])
        self.assertEqual(result["certified"], 0)
        self.assertFalse(result["all_runs_eligible"])

    def test_negative_control_healthy_run_is_certified(self):
        """NEGATIVE CONTROL: a stub simulating a genuinely healthy run must
        still certify complete=True/eligible=True -- the live path for a
        working run is unaffected by this fix."""
        result = self._run(_healthy_one_run)
        run = result["runs"][0]
        self.assertTrue(run["run_health"]["eligible"], run["run_health"])
        self.assertTrue(run["provenance"]["complete"])
        self.assertEqual(result["certified"], 1)
        self.assertTrue(result["all_runs_eligible"])
        # A real finding was actually persisted and scored.
        self.assertGreaterEqual(run["metrics"]["exact_class"]["overall"]["tp"], 1, run["metrics"])

    def test_inputs_identity_is_present_and_deterministic_component_hashes(self):
        result = self._run(_healthy_one_run)
        identity = result["inputs_identity"]
        for key in ("corpus_hash", "config_hash", "manifest_hash", "git_revision",
                   "git_dirty", "model_digest", "identity_hash"):
            self.assertIn(key, identity)
        self.assertEqual(identity["model_digest"], "unavailable",
                         "model digest must never be fabricated when not supplied")
        self.assertEqual(identity["git_revision"], "deadbeef")
        # Every run of the same corpus/config carries the SAME identity hash.
        self.assertEqual(result["runs"][0]["provenance"]["inputs_hash"], identity["identity_hash"])


if __name__ == "__main__":
    unittest.main()
