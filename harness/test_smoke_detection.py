"""
End-to-end detection smoke test -- SESSION_4_PLAN.md T1.1.

Runs the REAL orchestrator.analyze() pipeline (routing -> dispatch -> agent
output parsing -> deterministic detectors -> synthesis -> gating) against a
known SQL-injection exchange, with ONLY the Ollama boundary stubbed to return
canned JSON.

Why this test exists, when 889 others already pass: those mock at the plumbing
layer and stayed green three separate times while real detection was silently
ZERO (a prompt validator that rejected every agent; the circuit breaker zeroing
agents mid-run; qwen3 thinking-mode never disabled). This test asserts a known
finding actually survives the pipeline -- and the negative control proves it is
testing detection, not plumbing. If this goes red, detection is broken even if
every other test is green.

Fast + hermetic: no network, no GPU, no target. State/cache DBs are redirected
to a temp dir; every path that would call out (critique, active validators,
autonomous discovery, advisory/KEV/registry lookups) is turned off.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

_HARNESS = Path(__file__).resolve().parent

import store
import cache
import coordinator
from orchestrator import Orchestrator
from models import HttpExchange
from ollama_client import OllamaResult


# Unique anchor from sqli_agent.specialty_prompt. Keyed on this so the stub
# answers ONLY the SQLi specialist -- note the NoSQL agent's prompt also
# contains the substring "SQL injection", so a looser match would misfire.
_SQLI_ANCHOR = "SQL injection. Look at parameters"

# The class the stub emits and the class both assertions key on. A deterministic
# detector will not emit this exact class for a GET id-parameter error, so the
# negative control cleanly proves the positive result came from the model path.
_SQLI_CLASS = "sql_injection"

_SQLI_FINDING = {
    "vulnerability_class": _SQLI_CLASS,
    "confidence": 0.9,
    "severity": "high",
    "owasp_category": "A03:2021-Injection",
    "summary": "Error-based SQL injection in the id parameter.",
    "evidence": "Response returns a MySQL syntax error reflecting the injected quote.",
    "suggested_test": "Append a single quote to id and compare the error response.",
    "basis": "derived",
    "validation_hints": [],
}

# Unambiguous SQLi shape: a MySQL error in the body plus a quote-broken id param.
# Both are strong fast-path signals, so routing selects sqli without any LLM call.
# Parametrized by host so persistence tests can use a private host and not
# collide in the class-scoped state DB (store keys findings by host).
def _sqli_exchange(host: str = "localhost") -> HttpExchange:
    return HttpExchange(
        url=f"http://{host}/api/items?id=1'",
        method="GET",
        request_headers={"User-Agent": "smoke-test"},
        request_body="",
        response_status=500,
        response_headers={"Content-Type": "application/json"},
        response_body=(
            '{"error": "You have an error in your SQL syntax; check the manual that '
            "corresponds to your MySQL server version for the right syntax near '1''\"}"
        ),
    )


_SQLI_EXCHANGE = _sqli_exchange()


class _StubOllama:
    """Stands in for OllamaClient. Returns the SQLi finding for the SQLi
    specialist and nothing for every other agent. ``detect=False`` makes the
    model silent -- the negative control."""

    def __init__(self, detect: bool = True):
        self.detect = detect

    def _answer(self, system_prompt: str) -> dict:
        if self.detect and _SQLI_ANCHOR in system_prompt:
            return {"findings": [dict(_SQLI_FINDING)], "components": []}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._answer(system_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._answer(system_prompt), prompt_tokens=1, completion_tokens=1)


def _test_config() -> dict:
    """The shipped config, with everything that would call out (network/GPU) or
    add nondeterminism silenced. We are testing the detection spine, not the LLM
    or the external confirmers."""
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = False
    validators["allow_mutating_replay"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = [
        "localhost", "127.0.0.1",
        # Private hosts used only by the persistence-stage tests, so their
        # findings live under a host of their own in the class-scoped state DB.
        "persist-pos.smoke-test.local", "persist-neg.smoke-test.local",
    ]
    return cfg


def _build(detect: bool = True) -> Orchestrator:
    orch = Orchestrator(_test_config())
    stub = _StubOllama(detect=detect)
    # Replace the LLM client everywhere it is held -- the orchestrator, every
    # specialist agent, the pipeline's critique client, and the coordinator.
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coordinator = getattr(orch, "coordinator", None)
    if coordinator is not None and hasattr(coordinator, "ollama"):
        coordinator.ollama = stub
    return orch


class SmokeDetectionTest(unittest.TestCase):
    # Redirect the global state/cache DBs to a temp dir for the LIFETIME OF THIS
    # CLASS ONLY, then restore them. Doing this at import time leaks the temp
    # paths into every other test in the suite (store._connect and cache._cache
    # read module globals) -- which silently breaks tests that rely on the
    # defaults. Scoped + restored here, no other test is affected.
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="smoke_detbench_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    @staticmethod
    def _findings(resp):
        return [f for report in resp.agent_reports for f in report.findings]

    def test_known_sqli_survives_pipeline(self):
        coordinator.reset_fail_open_stats()
        orch = _build(detect=True)
        resp = asyncio.run(orch.analyze(_SQLI_EXCHANGE, bypass_cache=True))

        self.assertIn(
            "sqli", resp.dispatched_agents,
            f"fast-path routing did not dispatch the sqli agent; got {resp.dispatched_agents}",
        )
        sql_findings = [f for f in self._findings(resp) if f.vulnerability_class == _SQLI_CLASS]
        self.assertTrue(
            sql_findings,
            "END-TO-END DETECTION IS ZERO: the SQLi agent's finding did not survive the "
            "analyze() pipeline. This is the 'green tests, dead pipeline' failure -- something "
            "between dispatch and synthesis (prompt validation, gating, a broken validator, the "
            "circuit breaker) is silently dropping findings.",
        )
        # This clean SQLi shape routes via the deterministic fast-path, so the
        # coordinator must NOT have failed open to all agents (T4.1). A non-zero
        # count here means routing silently degraded to the fire-everything path.
        self.assertEqual(
            coordinator.fail_open_stats()["count"], 0,
            "coordinator failed open during normal detection -- routing silently fell back "
            "to dispatching all agents instead of the fast-path selection.",
        )

    def test_negative_control_no_detection_when_model_silent(self):
        # Proves the test guards DETECTION, not plumbing: with the model
        # returning nothing, the SQLi finding must NOT appear. If it does, the
        # positive test is passing via some deterministic path, not the pipeline
        # carrying a model finding through -- i.e. it isn't testing what it claims.
        orch = _build(detect=False)
        resp = asyncio.run(orch.analyze(_SQLI_EXCHANGE, bypass_cache=True))
        sql_findings = [f for f in self._findings(resp) if f.vulnerability_class == _SQLI_CLASS]
        self.assertEqual(
            sql_findings, [],
            "Smoke test is not actually testing detection: a SQL finding appeared even though "
            "the model returned nothing.",
        )

    def test_finding_is_persisted_with_api_shape(self):
        """PERSISTENCE + read-back stage (W-10 coverage gap).

        A finding that survives analyze() but never reaches the store -- or
        persists malformed -- would pass the spine test above yet be invisible
        to every operator surface: the findings API, ``/report`` and the Burp
        panel all read back through ``store.all_host_findings``. This asserts
        the surviving finding lands there with the fields those surfaces need.
        Uses a private host so it does not depend on the order of the other
        tests that write to the class-scoped state DB.
        """
        exchange = _sqli_exchange("persist-pos.smoke-test.local")
        orch = _build(detect=True)
        resp = asyncio.run(orch.analyze(exchange, bypass_cache=True))
        self.assertTrue(
            [f for f in self._findings(resp) if f.vulnerability_class == _SQLI_CLASS],
            "precondition failed: finding did not survive analyze()",
        )

        persisted = store.all_host_findings(exchange.url)
        sqli_rows = [r for r in persisted if r["vulnerability_class"] == _SQLI_CLASS]
        self.assertTrue(
            sqli_rows,
            "PERSISTENCE STAGE DROPPED THE FINDING: it survived analyze() but is not in "
            "store.all_host_findings() -- the findings API, /report and the Burp panel all "
            "read from here, so the operator would never see it.",
        )
        row = sqli_rows[0]
        for key in ("url", "method", "vulnerability_class", "severity",
                    "confidence", "summary", "evidence", "agent", "fingerprint"):
            self.assertIn(key, row, f"persisted finding is missing API field {key!r}")
        # url/method are structural and preserved verbatim.
        self.assertEqual(row["url"], exchange.url)
        self.assertEqual(row["method"], exchange.method)
        # severity/confidence are legitimately ADJUSTED by gating (an
        # unconfirmed model finding is demoted -- the behavior W-7 formalizes),
        # so assert they are well-formed, not that they equal the stub's input.
        self.assertIn(
            str(row["severity"]).lower(),
            {"info", "informational", "low", "medium", "high", "critical"},
            f"persisted severity is not a recognized level: {row['severity']!r}",
        )
        self.assertIsInstance(row["confidence"], (int, float))
        self.assertGreaterEqual(row["confidence"], 0.0)
        self.assertLessEqual(row["confidence"], 1.0)
        self.assertTrue(row["summary"], "persisted finding has an empty summary")
        self.assertTrue(row["fingerprint"], "persisted finding has no fingerprint")

    def test_negative_control_nothing_persisted_when_model_silent(self):
        """The persistence stage must be clean in the negative control too:
        model silent -> no sqli row in the store for that host."""
        exchange = _sqli_exchange("persist-neg.smoke-test.local")
        orch = _build(detect=False)
        asyncio.run(orch.analyze(exchange, bypass_cache=True))
        persisted = store.all_host_findings(exchange.url)
        self.assertEqual(
            [r for r in persisted if r["vulnerability_class"] == _SQLI_CLASS],
            [],
            "a sqli finding was persisted even though the model returned nothing.",
        )


if __name__ == "__main__":
    unittest.main()
