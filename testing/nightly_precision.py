"""CPU-only, model-free precision/recall CI check (P0.10).

This is NOT a measurement of the local model's real detection accuracy --
that needs a GPU-built fixture (`testing/test-target/detection_fixture.py`)
and runs only on the `scored` [self-hosted, gpu] CI tier. This script proves
the SCORING PLUMBING itself (analyze() -> agent output -> score.py's per-
category precision/recall math -> SCORECARD.md) stays wired end to end, on
every commit, with zero GPU/network dependency: a tiny, committed corpus of
4 exchanges (2 true positives across 2 OWASP categories, 2 true negatives)
run through the REAL orchestrator.analyze() pipeline with the Ollama
boundary stubbed to return DETERMINISTIC, hand-scripted findings.

Why this exists: the project's #0 failure mode ("green tests, dead
pipeline") has hit the scoring path before -- a cached/stale score artifact
can look like a fresh, real result. A CI job that runs this script and then
independently asserts SCORECARD.md exists closes that gap for the scoring
plumbing itself: if the plumbing breaks (an exception, a routing change that
silently drops findings, a scorer regression), the script exits non-zero and
the file is never written, so an unavailable/broken run can never be read as
a pass.

Run standalone: `python testing/nightly_precision.py`
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402

from harness import store, cache  # noqa: E402
from harness.orchestrator import Orchestrator  # noqa: E402
from harness.models import HttpExchange  # noqa: E402
from harness.ollama_client import OllamaResult  # noqa: E402
import score  # noqa: E402  (testing/score.py)

SCORECARD_PATH = _REPO_ROOT / "SCORECARD.md"

# --- The tiny, committed, deterministic corpus -------------------------------

_SQLI_FINDING = {
    "vulnerability_class": "sql_injection", "confidence": 0.9, "severity": "high",
    "owasp_category": "A03:2021-Injection",
    "summary": "Error-based SQL injection in the id parameter.",
    "evidence": "MySQL syntax error reflecting the injected quote.",
    "suggested_test": "Append a single quote to id and compare the error response.",
    "basis": "derived", "validation_hints": [],
}
_IDOR_FINDING = {
    "vulnerability_class": "idor", "confidence": 0.75, "severity": "high",
    "owasp_category": "A01:2021-Broken-Access-Control",
    "summary": "Sequential numeric order id with no ownership check apparent.",
    "evidence": "GET /api/orders/{id} returns another account's order data shape.",
    "suggested_test": "Replay with a different authenticated identity, same id.",
    "basis": "derived", "validation_hints": [],
}

_LABELS = {
    "TP-sqli-1": ("sqli", _SQLI_FINDING),
    "TP-idor-1": ("idor", _IDOR_FINDING),
    "TN-sqli-1": ("sqli", None),   # same agent forced, model finds nothing -- true negative
    "TN-idor-1": ("idor", None),
}

_LABEL_CATEGORY = {
    "TP-sqli-1": "A03:Injection",
    "TP-idor-1": "A01:Broken-Access-Control",
}


def _exchange(label: str) -> HttpExchange:
    return HttpExchange(
        url=f"http://127.0.0.1/api/nightly-precision/{label}",
        method="GET", request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="{}",
    )


class _ScriptedOllama:
    """Deterministic stand-in for OllamaClient: returns the one scripted
    finding for its label, or nothing -- no model, no GPU, no network."""

    def __init__(self, finding: dict | None):
        self._finding = finding

    def _answer(self) -> dict:
        return {"findings": [dict(self._finding)] if self._finding else [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._answer()

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._answer(), prompt_tokens=1, completion_tokens=1)


def _test_config() -> dict:
    with open(_REPO_ROOT / "harness" / "config.yaml") as f:
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
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    cfg.setdefault("oracle", {})["enabled"] = False
    return cfg


def _build_orchestrator(finding: dict | None) -> Orchestrator:
    orch = Orchestrator(_test_config())
    stub = _ScriptedOllama(finding)
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub
    return orch


async def _run_corpus() -> dict[str, list[str]]:
    labeled_findings: dict[str, list[str]] = {}
    for label, (agent_name, finding) in _LABELS.items():
        orch = _build_orchestrator(finding)
        resp = await orch.analyze(_exchange(label), force_agents=[agent_name], bypass_cache=True)
        classes = [f.vulnerability_class for report in resp.agent_reports for f in report.findings]
        labeled_findings[label] = classes
    return labeled_findings


def main() -> int:
    from harness.eval_health import evaluate_health  # R01: real production consumer

    tmp = tempfile.mkdtemp(prefix="nightly_precision_")
    orig_db_path = store._DB_PATH
    orig_cache = cache._cache
    completed_phases: list[str] = []
    exit_code = 0
    try:
        store._DB_PATH = Path(tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(tmp, "cache.db"))

        labeled_findings = asyncio.run(_run_corpus())
        completed_phases.append("run_corpus")
        report = score.score(labeled_findings, label_category=_LABEL_CATEGORY)
        completed_phases.append("score")
        report["provenance"] = (
            "CPU-only, model-STUBBED plumbing check (P0.10) -- NOT a measurement of "
            "real model detection accuracy. See testing/test-target/ + the `scored` "
            "[self-hosted, gpu] CI tier for that."
        )
        table = score.format_table(report, corpus="nightly-precision-fixture", model="stubbed/none")
        SCORECARD_PATH.write_text(
            table + "\n\n" + report["provenance"] + "\n", encoding="utf-8")
        completed_phases.append("write_scorecard")
        print(table)
        print()
        print(report["provenance"])

        # This tiny fixture is fully deterministic -- both TPs must be found and
        # both TNs must stay clean, or the plumbing itself is broken.
        overall = report["overall"]
        if overall["tp"] != 2 or overall["fp"] != 0 or overall["fn"] != 0:
            print(f"NIGHTLY PRECISION PLUMBING CHECK FAILED: expected tp=2 fp=0 fn=0, "
                  f"got {overall}", file=sys.stderr)
            exit_code = 1

        # R01/P0.7: the four independent process/artifact/target/phase health
        # signals, explicit rather than a bare exit code -- the SAME failure
        # mode ("green tests, dead pipeline") this whole script exists to
        # guard against also applies to trusting a lone tp/fp/fn check.
        # `target_healthy=True` here is an honest structural fact, not an
        # inferred default: this job is fully stubbed (no live target at
        # all), so "no target to be unhealthy" is the true state, not a
        # guess from the exit code.
        health = evaluate_health({
            "exit_code": exit_code,
            "expected_artifacts": ["SCORECARD.md"],
            "present_artifacts": ["SCORECARD.md"] if SCORECARD_PATH.exists() else [],
            "target_healthy": True,
            "target_health_reason": "no live target in this stubbed CPU-only plumbing check",
            "expected_phases": ["run_corpus", "score", "write_scorecard"],
            "completed_phases": completed_phases,
        })
        print(f"\neval_health: eval_valid={health['eval_valid']} reasons={health['reasons']}")
        if not health["eval_valid"]:
            print("NIGHTLY PRECISION PLUMBING CHECK FAILED health gate: "
                  f"{health['reasons']}", file=sys.stderr)
            exit_code = 1
        return exit_code
    finally:
        store._DB_PATH = orig_db_path
        cache._cache = orig_cache
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
