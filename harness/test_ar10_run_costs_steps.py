"""AR-10 P3 (owner decision Q5): the job result carries a per-run iterative step count
and a top-level `costs` object, so the sealed scorer computes duplicate share,
parse-error rate and the cost secondaries instead of reporting null.

Both are driven through the real `Orchestrator.investigate_engagement`:

- steps: P1's scripted iterative probes against an owned loopback target. The
  scripted model's own count of probe turns is the independent measure.
- costs: the real OllamaClient on a scripted wire (no network). The wire's own count
  of requests is the independent measure of calls and retries.

Each check has an in-process control that removes the new logic and shows the same
check failing. Synthetic fixtures only; no live target or model.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch

import httpx

from harness import ar10_scorer
from harness import instrumentation
from harness import test_instrumentation as ti
from harness import test_iterative_run_diagnostics as p1
from harness import worklist_investigator
from harness.test_engagement_transport_callers import _OBJECT_NODE, _EngagementCallerBase
from harness.test_iterative_run_diagnostics import _FIRST_PROBE, _ORDER_NODE, _SECOND_PROBE


def _scored(result: dict) -> dict:
    """The scorer's secondary metrics for a result, after the JSON round trip an export makes."""
    return ar10_scorer._secondary(json.loads(json.dumps(result, default=str)))


class RunStepCountTests(_EngagementCallerBase, unittest.TestCase):
    _engage = p1.IterativeRunDiagnosticsTests._engage  # module access: not re-collected

    def _check_steps(self):
        result, _, model = self._engage([*_FIRST_PROBE, *_SECOND_PROBE],
                                         endpoints=[_OBJECT_NODE, _ORDER_NODE])
        block = result["worklist_summary"]["iterative_diagnostics"]
        # Independent measure: every turn the scripted model answered for a probe.
        self.assertEqual(model.probe_calls, len(_FIRST_PROBE) + len(_SECOND_PROBE))
        self.assertEqual(block["totals"]["steps"], model.probe_calls)
        self.assertEqual({r: row["steps"] for r, row in block["by_stop_reason"].items()},
                         {"refused": len(_FIRST_PROBE), "gave_up": len(_SECOND_PROBE)})
        scored = _scored(result)
        # One parse error and one duplicate over seven model turns.
        self.assertEqual(scored["duplicate_share"], round(1 / 7, 4))
        self.assertEqual(scored["parse_error_rate"], round(1 / 7, 4))
        return result

    def test_step_count_reaches_the_result_and_the_scorer_computes_the_ratios(self):
        self._check_steps()

    def test_control_without_the_step_count_the_ratios_are_null(self):
        original = worklist_investigator._probe_diagnostics

        def no_steps(outcome):
            out = original(outcome)
            if out is not None:
                out.pop("steps", None)
            return out

        with patch.object(worklist_investigator, "_probe_diagnostics", no_steps):
            with self.assertRaises(AssertionError):
                self._check_steps()

    def test_a_probe_without_a_step_count_makes_the_run_total_unknown_not_partial(self):
        result, _, _ = self._engage([*_SECOND_PROBE], endpoints=[_OBJECT_NODE], max_nodes=1)
        self.assertEqual(result["worklist_summary"]["iterative_diagnostics"]["totals"]["steps"], 2)
        outcomes = [{"stop_reason": "gave_up", "diagnostics": {"steps": 2}},
                    {"stop_reason": "gave_up", "diagnostics": {"duplicate_proposals": 1}}]
        block = worklist_investigator.iterative_diagnostics(outcomes)
        self.assertIsNone(block["totals"]["steps"])
        self.assertIsNone(block["by_stop_reason"]["gave_up"]["steps"])
        self.assertIsNone(ar10_scorer._secondary({"iterative_diagnostics": block})["duplicate_share"])

    def test_a_client_without_counters_reports_null_costs_never_zero(self):
        # The scripted model of this fixture keeps no metrics, so nothing may be invented.
        result, _, _ = self._engage([*_SECOND_PROBE], endpoints=[_OBJECT_NODE], max_nodes=1)
        costs = result["costs"]
        self.assertEqual((costs["model_calls"], costs["model_errors"], costs["retries"]),
                         (None, None, None))
        self.assertIsInstance(costs["wall_seconds"], float)


_REPLY = ti._counted_reply   # bound before any test patches the module attribute


def _wire(*statuses):
    """A scripted Ollama wire answering `statuses` in order ("ok" is a counted reply),
    recording each request it receives."""
    seen = []
    queue = list(statuses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        step = queue.pop(0) if queue else "ok"
        return _REPLY(request) if step == "ok" else httpx.Response(step, text="synthetic")
    return handler, seen


class RunCostsTests(ti._InvestigateBase):
    def setUp(self):
        super().setUp()
        sleep = patch.object(ti.oc, "_backoff_sleep", ti.AsyncMock())
        sleep.start()
        self.addCleanup(sleep.stop)

    def _run(self, *statuses):
        handler, seen = _wire(*statuses)
        started = time.monotonic()
        with patch.object(ti, "_counted_reply", handler):
            result, _ = self._investigate()
        return result, seen, time.monotonic() - started

    def _check_costs(self, statuses, *, calls, errors, retries):
        result, seen, outer = self._run(*statuses)
        costs = result["costs"]
        self.assertEqual(set(costs), set(ar10_scorer.COST_KEYS))
        self.assertEqual((costs["model_calls"], costs["model_errors"], costs["retries"]),
                         (calls, errors, retries))
        # Independent measure: what the wire received is the calls plus their retries.
        self.assertEqual(len(seen), calls + retries)
        self.assertGreaterEqual(costs["wall_seconds"], 0.0)
        self.assertLessEqual(costs["wall_seconds"], round(outer, 1) + 0.1)
        # The costs agree with the instrumentation block taken in the same snapshot.
        client = result["instrumentation"]["model_metrics"]["client"]
        self.assertEqual(costs["model_calls"], client["attempted"])
        scored = _scored(result)
        for key in ar10_scorer.COST_KEYS:
            self.assertEqual(scored[key], costs[key], key)
        return result

    def test_one_clean_call(self):
        self._check_costs(["ok"], calls=1, errors=0, retries=0)

    def test_a_retried_call_counts_once_with_one_retry(self):
        self._check_costs([500, "ok"], calls=1, errors=0, retries=1)

    def test_a_failed_call_counts_as_a_call_and_an_error(self):
        self._check_costs([404], calls=1, errors=1, retries=0)

    def test_control_without_the_costs_block_the_check_fails(self):
        with patch.object(instrumentation.RunInstrumentation, "result_blocks",
                          lambda self: {"instrumentation": self.snapshot()}):
            with self.assertRaises((AssertionError, KeyError)):
                self._check_costs(["ok"], calls=1, errors=0, retries=0)

    def test_control_counting_the_wire_instead_of_calls_is_caught(self):
        # A run_costs that reported completed calls would drop the failed one.
        with patch.object(instrumentation, "run_costs",
                          lambda block, wall: {"model_calls": block["model_metrics"]["client"]["completed"],
                                               "model_errors": 0, "retries": 0,
                                               "wall_seconds": wall}):
            with self.assertRaises(AssertionError):
                self._check_costs([404], calls=1, errors=1, retries=0)


if __name__ == "__main__":
    unittest.main()
