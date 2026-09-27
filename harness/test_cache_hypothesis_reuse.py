"""FR-7 (F11): caller-level coverage for the run-INDEPENDENT hypothesis
cache (harness/cache.py ExchangeCache.get_hypothesis/put_hypothesis), wired
into Orchestrator.analyze() in orchestrator_detect.py behind
runs.hypothesis_cache.enabled (config.yaml default: false).

Mirrors test_orchestrator_detect.py / test_smoke_detection.py's pattern: a
real Orchestrator with only the Ollama boundary stubbed, temp store/cache
DBs, config loaded from the shipped harness/config.yaml. No live Ollama/
network, no answer-key/blind-target content read.

Covers:
  1. Cross-run hypothesis reuse (flag ON): two fresh RunContexts analyzing
     identical traffic -- the 2nd run must NOT re-invoke the model, and the
     hypothesis-cache hit rate must be > 0.
  2. Proof is re-bound per run, never shared: each run's case_id/proof_id
     are independently minted (never identical-by-reuse across runs), and
     the RAW stored hypothesis-cache payload never carries a proof/case/
     oracle field.
  3. Negative control: a coordinator-model change, a prompt-version change,
     or a config-fingerprint change each force a MISS and a re-dispatch.
  4. Default-off byte-identical: with the flag off (the shipped default,
     explicit or simply unset), two fresh runs on identical traffic behave
     exactly as before this feature existed -- every run re-dispatches.
"""
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from harness import cache, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_smoke_detection import _test_config, _SQLI_ANCHOR, _SQLI_FINDING

_HARNESS = Path(__file__).resolve().parent

# A SECOND finding the stub sqli agent emits alongside the SQLi one, of a
# class (verbose_error) with a PASSIVE validator (VerboseErrorValidator,
# active=False -- see harness/validators/verbose_error_validator.py). Passive
# validators run regardless of validators.active_enabled (see
# ValidatorRegistry.for_finding: "not v.active or self.active_enabled"), and
# VerboseErrorValidator deterministically CONFIRMS when the real exchange's
# response body matches one of its patterns (no network, no model). This is
# what lets these tests exercise a genuinely case_id/proof_id-stamped
# finding without active_enabled=True (which would need a live target).
_VERBOSE_ERROR_FINDING = {
    "vulnerability_class": "verbose_error",
    "confidence": 0.6,
    "severity": "medium",
    "summary": "Response includes a Python traceback.",
    "evidence": "Traceback (most recent call last)",
    "suggested_test": "Trigger the error again and inspect the traceback for internal paths.",
    "basis": "derived",
    "validation_hints": [],
}


class _CountingStubOllama:
    """Answers the SQLi specialist with the canned SQLi finding PLUS the
    verbose_error finding above, and every other agent with nothing, while
    counting every model call this stub receives -- so a test can assert
    the dispatch/inference leg was (or was not) re-invoked between two
    analyze() calls."""

    def __init__(self):
        self.calls = 0

    def _answer(self, system_prompt: str) -> dict:
        if _SQLI_ANCHOR in system_prompt:
            return {"findings": [dict(_SQLI_FINDING), dict(_VERBOSE_ERROR_FINDING)],
                    "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls += 1
        return self._answer(system_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls += 1
        return OllamaResult(data=self._answer(system_prompt), prompt_tokens=1, completion_tokens=1)


def _exchange(host: str) -> HttpExchange:
    """The same unambiguous SQLi shape as test_smoke_detection's
    _sqli_exchange (a quote-broken id param + a MySQL error body):
    fast_path_selector dispatches ``sqli`` deterministically, with no
    coordinator LLM routing call, so the only model call on a fresh
    dispatch is the sqli specialist's own detection call -- a clean,
    minimal signal for dispatch-call counting. The response body ALSO
    carries a Python traceback marker so the passive VerboseErrorValidator
    (see _VERBOSE_ERROR_FINDING above) deterministically confirms the
    second stub finding, independent of validators.active_enabled."""
    return HttpExchange(
        url=f"http://{host}/api/items?id=1'",
        method="GET",
        request_headers={"User-Agent": "hyp-cache-test"},
        request_body="",
        response_status=500,
        response_headers={"Content-Type": "application/json"},
        response_body=(
            '{"error": "You have an error in your SQL syntax; check the manual that '
            "corresponds to your MySQL server version for the right syntax near '1''\"}"
            '\nTraceback (most recent call last):\n  File "app.py", line 1, in handler\n'
            "    raise ValueError('boom')\n"
        ),
    )


def _wire_stub(orch: Orchestrator, stub: _CountingStubOllama) -> None:
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub


def _build(host: str, *, hypothesis_cache_enabled: bool) -> tuple[Orchestrator, _CountingStubOllama]:
    cfg = _test_config()
    cfg.setdefault("server", {})["allowed_hosts"] = list(
        cfg["server"]["allowed_hosts"]) + [host]
    cfg.setdefault("runs", {})["hypothesis_cache"] = {"enabled": hypothesis_cache_enabled}
    orch = Orchestrator(cfg)
    stub = _CountingStubOllama()
    _wire_stub(orch, stub)
    return orch, stub


def _fresh_run_context(orch: Orchestrator, host: str) -> RunContext:
    """A brand-new RunContext (fresh run_id -> fresh cache_namespace) each
    call -- the run-namespaced full-response cache (ExchangeCache.get/put)
    can therefore never cross-run-hit between two calls that each pass one
    of these in, exactly the gap FR-7 exists to close for the pre-proof
    half of the work."""
    return RunContext.create(allowed_hosts=[host], config=orch.config)


class _HypothesisCacheTestBase(unittest.IsolatedAsyncioTestCase):
    """Shared temp store/cache DB plumbing, mirroring
    test_orchestrator_detect.py's CoordinatorFallbackResponseFlagTests."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="fr7_hypothesis_cache_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)


class CrossRunHypothesisReuseTests(_HypothesisCacheTestBase):
    """#1 + #2: with the flag ON, a 2nd run on identical traffic under a
    FRESH RunContext hits the hypothesis cache (no re-dispatch), while its
    proof/case identifiers are still independently minted for that run."""

    async def test_second_run_does_not_redispatch_and_hit_rate_positive(self):
        host = "hyp-reuse.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=True)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        resp1 = await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(
            calls_after_run1, 0,
            "run 1 (a guaranteed MISS -- the hypothesis cache starts empty) "
            "never called the model at all; the test fixture itself is broken.",
        )

        rc2 = _fresh_run_context(orch, host)
        resp2 = await orch.analyze(exchange, run_context=rc2)

        self.assertEqual(
            stub.calls, calls_after_run1,
            "run 2 re-invoked the model dispatch/inference leg even though it "
            "should have been a hypothesis-cache HIT on identical traffic under "
            "a fresh RunContext.",
        )
        hyp_stats = cache.get_cache().hypothesis_stats()
        self.assertGreater(
            hyp_stats.hit_rate, 0.0,
            f"expected a positive hypothesis-cache hit rate, got {hyp_stats.to_dict()!r}",
        )
        self.assertGreaterEqual(hyp_stats.hits, 1)

        # #2: proof re-bound per run, never shared. Keyed on the "sqli"
        # agent's own verbose_error finding (see _VERBOSE_ERROR_FINDING):
        # its class has a PASSIVE validator that deterministically confirms
        # it (see _exchange's docstring), unlike sql_injection here, which
        # has no applicable validator with validators.active_enabled=False
        # and so is never proof-stamped at all -- not a useful signal for
        # this assertion.
        ve1 = next(f for r in resp1.agent_reports for f in r.findings
                   if r.agent == "sqli" and f.vulnerability_class == "verbose_error")
        ve2 = next(f for r in resp2.agent_reports for f in r.findings
                   if r.agent == "sqli" and f.vulnerability_class == "verbose_error")

        self.assertTrue(ve1.case_id, "run 1's finding has no case_id -- proof minting never ran")
        self.assertTrue(
            ve2.case_id,
            "run 2's finding has no case_id -- the hypothesis-cache hit path "
            "early-returned instead of falling through to _validate_findings.",
        )
        self.assertNotEqual(
            ve1.case_id, ve2.case_id,
            "the two runs share a case_id -- proof identity leaked across runs "
            "instead of being freshly minted per run.",
        )
        self.assertTrue(ve1.proof_id, "run 1's finding was never proof-stamped")
        self.assertTrue(ve2.proof_id, "run 2's finding was never proof-stamped")
        self.assertNotEqual(
            ve1.proof_id, ve2.proof_id,
            "the two runs share a proof_id -- proof identity leaked across runs.",
        )

    async def test_stored_hypothesis_payload_has_no_proof_case_or_oracle_fields(self):
        """Inspect the RAW stored row directly (not through get_hypothesis,
        which by construction only ever returns pre-proof reports) -- a
        structural check that nothing proof-shaped ever reaches the DB."""
        host = "hyp-payload.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=True)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)

        exchange_hash = cache.ExchangeCache.compute_exchange_hash(exchange, namespace="")
        conn = sqlite3.connect(str(cache.get_cache()._DB_PATH))
        try:
            row = conn.execute(
                "SELECT payload_json FROM hypothesis_cache_entries WHERE exchange_hash = ?",
                (exchange_hash,),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row, "no hypothesis-cache row was written for this exchange")

        payload = json.loads(row[0])
        # The payload must never carry a proof_records key/AnalysisResponse
        # shape at all -- it is a hand-built dict of exactly six keys.
        self.assertEqual(
            set(payload.keys()),
            {"reports", "dispatch", "reason", "stage_outcomes",
             "findings_reviewed", "findings_rejected"},
            f"hypothesis-cache payload has unexpected top-level keys: {sorted(payload.keys())!r}",
        )
        self.assertGreaterEqual(len(payload["reports"]), 1)
        for report in payload["reports"]:
            for finding in report.get("findings", []):
                self.assertEqual(finding.get("proof_id", ""), "",
                                  "a cached finding carries a non-empty proof_id")
                self.assertEqual(finding.get("case_id", ""), "",
                                  "a cached finding carries a non-empty case_id")
                self.assertFalse(finding.get("oracle_verified", False),
                                  "a cached finding carries oracle_verified=True")
                self.assertEqual(finding.get("oracle_capsule_id", ""), "",
                                  "a cached finding carries a non-empty oracle_capsule_id")
                self.assertEqual(finding.get("oracle_reason", ""), "",
                                  "a cached finding carries a non-empty oracle_reason")


class HypothesisCacheNegativeControlTests(_HypothesisCacheTestBase):
    """#3: a coordinator-model change, a prompt-version change, or a
    config-fingerprint change must each MISS the hypothesis cache and force
    a re-dispatch, even for otherwise-identical traffic."""

    async def test_config_fingerprint_change_forces_redispatch(self):
        host = "hyp-neg-config.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=True)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(calls_after_run1, 0)

        # The hypothesis-cache hook reads config_fingerprint(self.config) --
        # the ORCHESTRATOR's own config, independent of either RunContext --
        # so mutating it here changes the fingerprint between the two calls.
        orch.config["_fr7_negative_control_marker"] = "changed"

        rc2 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc2)

        self.assertGreater(
            stub.calls, calls_after_run1,
            "a config-fingerprint change did not force a hypothesis-cache MISS "
            "and re-dispatch.",
        )

    async def test_model_change_forces_redispatch(self):
        host = "hyp-neg-model.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=True)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(calls_after_run1, 0)

        orch.coordinator_model = orch.coordinator_model + "-changed"

        rc2 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc2)

        self.assertGreater(
            stub.calls, calls_after_run1,
            "a coordinator_model change did not force a hypothesis-cache MISS "
            "and re-dispatch.",
        )

    async def test_prompt_version_change_forces_redispatch(self):
        host = "hyp-neg-prompt.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=True)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(calls_after_run1, 0)

        sqli_agent = orch.agent_manager.agents["sqli"]
        sqli_agent._prompt_version = lambda: "changed-prompt-version"

        rc2 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc2)

        self.assertGreater(
            stub.calls, calls_after_run1,
            "a prompt-version change did not force a hypothesis-cache MISS "
            "and re-dispatch.",
        )


class HypothesisCacheDefaultOffTests(_HypothesisCacheTestBase):
    """#4: with the flag OFF (the shipped default -- explicit or simply
    unset), two fresh runs on identical traffic behave exactly as before
    this feature existed: no cross-run hypothesis reuse, every run
    re-dispatches."""

    async def test_flag_explicitly_off_every_fresh_run_redispatches(self):
        host = "hyp-default-off.hyp-cache.test"
        orch, stub = _build(host, hypothesis_cache_enabled=False)
        exchange = _exchange(host)

        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(calls_after_run1, 0)

        rc2 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc2)

        self.assertGreater(
            stub.calls, calls_after_run1,
            "with runs.hypothesis_cache.enabled=False, run 2 did not re-dispatch "
            "-- default-off behavior has changed from before this feature existed.",
        )

    async def test_flag_unset_defaults_to_off_same_as_explicit_false(self):
        """The shipped harness/config.yaml's default (no override at all)
        must behave identically to an explicit False -- this exercises the
        committed safe default itself, not just an explicitly-disabled
        path."""
        host = "hyp-default-unset.hyp-cache.test"
        cfg = _test_config()
        cfg.setdefault("server", {})["allowed_hosts"] = list(
            cfg["server"]["allowed_hosts"]) + [host]
        # Deliberately do NOT touch cfg["runs"] at all -- exercise the
        # shipped harness/config.yaml default as-is.
        self.assertFalse(
            (cfg.get("runs", {}) or {}).get("hypothesis_cache", {}).get("enabled", False),
            "harness/config.yaml's committed default for runs.hypothesis_cache.enabled "
            "is not False -- unsafe default shipped.",
        )
        orch = Orchestrator(cfg)
        stub = _CountingStubOllama()
        _wire_stub(orch, stub)

        exchange = _exchange(host)
        rc1 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc1)
        calls_after_run1 = stub.calls
        self.assertGreater(calls_after_run1, 0)

        rc2 = _fresh_run_context(orch, host)
        await orch.analyze(exchange, run_context=rc2)

        self.assertGreater(stub.calls, calls_after_run1)


if __name__ == "__main__":
    unittest.main()
