"""AR-10 P1: run-level iterative diagnostics reach the job result.

AR-09 records `diagnostics` on each probe's `iterative_result`. These tests drive
`Orchestrator.investigate_engagement` (discovery canned, model scripted) through the
real `investigate_worklist` and the real iterative probe against an owned loopback
target, and read the counts from the job result's `worklist_summary`. The target's
own record of probe sends is the independent measure of useful unique actions.

Controls: a run with no iterative probe reports zeros, never fabricated counts; a
probe whose result carries no diagnostics is reported as such, not as zeros; and the
block holds counts and attempt IDs only, never prompt or payload text.

Caller verification only: no live target, model accuracy or recall is measured.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from harness import security
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_engagement_transport_callers import (_PROBE_HEADER, _ROLES, _EngagementCallerBase,
                                                       _OBJECT_NODE, _Model, _canned, _config,
                                                       _install_model)

_ORDER_NODE = {"method": "GET", "path": "/api/orders/{id}", "by_role": {"anonymous": 200},
               "reachable_roles": ["anonymous"], "object_scoped": True}
_COUNTS = ("parse_errors", "refusals", "rejected_proposals", "unavailable_selections",
           "duplicate_proposals", "blocked_attempts", "useful_unique_actions")
_PAYLOAD = "p1-payload-marker"

# The model's queue is shared, so the first probe takes the first five actions
# whichever node the worklist ranks first.
_FIRST_PROBE = [
    {},                                                                   # parse error
    {"action": "set_header", "name": _PROBE_HEADER, "value": _PAYLOAD},   # useful send
    {"action": "set_header", "name": _PROBE_HEADER, "value": _PAYLOAD},   # duplicate
    {"action": "teleport", "thought": "unsupported"},                     # rejected
    {"action": "stop", "verdict": "refused", "thought": "declined"},      # refusal
]
_SECOND_PROBE = [
    {"action": "set_header", "name": _PROBE_HEADER, "value": "2"},        # useful send
    {"action": "stop", "verdict": "gave_up", "thought": "nothing here"},
]


class IterativeRunDiagnosticsTests(_EngagementCallerBase, unittest.TestCase):

    def _engage(self, actions, *, endpoints, max_nodes=2, wrap_probe=None):
        target = self._target()
        cfg = _config(mutating=False)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        model = _Model(actions)
        _install_model(orch, model)
        if wrap_probe is not None:
            orch.run_active_probe = wrap_probe(orch.run_active_probe)
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200, config=cfg,
                               gate_config={"active_enabled": True, "allow_mutating_replay": False})

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        target.base, _ROLES, max_nodes=max_nodes, step_budget=6,
                        max_chain_rounds=0, run_context=rc)
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_canned(endpoints, ())),
                   patch("harness.browser_driver.default_driver", return_value=None)]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        return result, target, model

    def test_probe_diagnostics_are_summed_per_run_and_per_stop_reason(self):
        result, target, model = self._engage([*_FIRST_PROBE, *_SECOND_PROBE],
                                             endpoints=[_OBJECT_NODE, _ORDER_NODE])
        self.assertEqual(model.probe_calls, len(_FIRST_PROBE) + len(_SECOND_PROBE))
        block = result["worklist_summary"]["iterative_diagnostics"]
        self.assertEqual((block["probes"], block["probes_without_diagnostics"]), (2, 0), block)
        totals = block["totals"]
        self.assertEqual({k: totals[k] for k in _COUNTS},
                         {"parse_errors": 1, "refusals": 1, "rejected_proposals": 1,
                          "unavailable_selections": 0, "duplicate_proposals": 1,
                          "blocked_attempts": 0, "useful_unique_actions": 2})
        # Independent measure: the sends the target actually received from the probes.
        self.assertEqual(totals["useful_unique_actions"], len(target.probe_requests()))
        self.assertEqual(totals["evidence_attempts"], 2)
        self.assertEqual(len(set(totals["evidence_attempt_ids"])), 2)
        self.assertTrue(all(i.startswith("req:") for i in totals["evidence_attempt_ids"]))

        by_reason = block["by_stop_reason"]
        self.assertEqual(sorted(by_reason), ["gave_up", "refused"])
        refused, gave_up = by_reason["refused"], by_reason["gave_up"]
        self.assertEqual((refused["probes"], refused["parse_errors"], refused["duplicate_proposals"],
                          refused["rejected_proposals"], refused["refusals"],
                          refused["useful_unique_actions"], refused["evidence_attempts"]),
                         (1, 1, 1, 1, 1, 1, 1))
        self.assertEqual((gave_up["probes"], gave_up["useful_unique_actions"], gave_up["refusals"],
                          gave_up["parse_errors"]), (1, 1, 0, 0))
        for key in (*_COUNTS, "evidence_attempts", "probes"):
            self.assertEqual(sum(r[key] for r in by_reason.values()),
                             block["probes"] if key == "probes" else totals[key], key)

        # Each probe's own outcome carries the counts the run sums.
        per_probe = [o["diagnostics"] for o in result["outcomes"] if o.get("diagnostics")]
        self.assertEqual(len(per_probe), 2)
        self.assertEqual(sum(d["useful_unique_actions"] for d in per_probe), 2)

        # Counts and attempt IDs only: no payload, header name, prompt or hypothesis text,
        # and the block survives the job-status sanitizer unchanged.
        text = json.dumps(block)
        for leaked in (_PAYLOAD, _PROBE_HEADER, "teleport", "declined", "HYPOTHESIS"):
            self.assertNotIn(leaked, text)
        self.assertEqual(security.sanitize_data(block), block)

    def test_run_with_no_iterative_probe_reports_zeros(self):
        result, target, model = self._engage([*_FIRST_PROBE], endpoints=[_OBJECT_NODE],
                                             max_nodes=0)
        self.assertEqual(model.probe_calls, 0)
        block = result["worklist_summary"]["iterative_diagnostics"]
        self.assertEqual((block["probes"], block["probes_without_diagnostics"]), (0, 0))
        self.assertEqual(block["by_stop_reason"], {})
        self.assertEqual({k: v for k, v in block["totals"].items() if k != "evidence_attempt_ids"},
                         {**{k: 0 for k in _COUNTS}, "evidence_attempts": 0, "steps": 0})
        self.assertEqual(block["totals"]["evidence_attempt_ids"], [])
        self.assertFalse(any("diagnostics" in o for o in result["outcomes"]))

    def test_probe_result_without_diagnostics_is_not_reported_as_zero_counts(self):
        """Defect injection: a probe whose iterative_result lost its diagnostics (the
        pre-AR-09 shape) must show as unreported, never as a probe with zero counts."""
        def strip(original):
            async def probe(*a, **kw):
                out = await original(*a, **kw)
                out["iterative_result"].pop("diagnostics", None)
                return out
            return probe

        result, target, _ = self._engage([*_SECOND_PROBE], endpoints=[_OBJECT_NODE],
                                         max_nodes=1, wrap_probe=strip)
        self.assertEqual(len(target.probe_requests()), 1, "the probe never sent")
        block = result["worklist_summary"]["iterative_diagnostics"]
        self.assertEqual((block["probes"], block["probes_without_diagnostics"]), (0, 1))
        self.assertEqual(block["totals"]["useful_unique_actions"], 0)
        self.assertEqual(block["by_stop_reason"], {})


if __name__ == "__main__":
    unittest.main()
