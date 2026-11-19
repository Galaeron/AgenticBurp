"""A cancelled job reports the same instrumentation block a finished one does (R11-4b).

The server's cancelled-job result was built from the run context alone, with no
instrumentation block, so a cancelled (or soft-cancel-deadline) job reported no
`phase_timings` and no `sqlmap_targeting`, and its manifest's `phase_timings` was
empty. That may be why the r11 post-mortem read `phase_timings` as empty.

Callers: POST /engagement/{host}/investigate then .../cancel over the durable-job
server fixture (no target I/O). The stand-in engagement opens phases on a
RunInstrumentation bound to its run as investigate_engagement does
(test_final_pass checks the real one leaves it on the run). Controls: a finished
job's block is unchanged; a job cancelled before any engagement started reports
no block and no error.
"""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from pathlib import Path

from harness import test_job_status_passive as _durable
from harness.instrumentation import RunInstrumentation


class CancelledJobInstrumentationTests(_durable.DurableJobCallerTests, unittest.TestCase):

    def _engagement(self, *, wait: bool, bind: bool = True):
        async def stub(*args, **kwargs):
            self.calls += 1
            rc = kwargs["run_context"]
            if bind:
                instr = RunInstrumentation(None, rc, rc.budget)
                rc.instrumentation = instr
                instr.phases.begin("discovery", budget_s=30.0)
                instr.phases.begin("worklist", budget_s=60.0)
            if wait:
                await asyncio.Event().wait()
            return {"summary": {}, "findings": [], **(rc.instrumentation.result_blocks() if bind else {})}
        self.server.orchestrator.investigate_engagement = stub

    def _cancel(self):
        job_id = self.start()
        for _ in range(100):
            if self.calls:
                break
            time.sleep(0.01)
        reply = self.client.post(f"/engagement/captured.example/investigate/{job_id}/cancel")
        self.assertEqual(reply.status_code, 200, reply.text)
        return self.poll(job_id, "cancelled")

    def test_a_cancelled_job_reports_phase_timings_and_the_sqlmap_report(self):
        self._engagement(wait=True)
        job = self._cancel()
        result = job["result"]
        self.assertTrue(result["partial"])
        instr = result["instrumentation"]
        phases = [r["phase"] for r in instr["phase_timings"]]
        self.assertEqual(phases, ["discovery", "worklist"])
        discovery, worklist = instr["phase_timings"]
        self.assertEqual(discovery["budget_s"], 30.0)
        self.assertNotIn("interrupted", discovery)
        self.assertTrue(worklist["interrupted"])               # the phase the cancel cut
        self.assertEqual(worklist["budget_s"], 60.0)
        self.assertIn("sqlmap_targeting", instr)
        self.assertIn("costs", result)
        # The manifest keeps them (RunManifest.finish reads the result's block).
        manifest = json.loads(Path(job["manifest_path"]).read_text())
        self.assertEqual([r["phase"] for r in manifest["phase_timings"]], ["discovery", "worklist"])
        self.assertIn("sqlmap_targeting", manifest)

    def test_control_a_finished_job_reports_its_block_as_before(self):
        self._engagement(wait=False)
        result = self.poll(self.start(), "done")["result"]
        timings = result["instrumentation"]["phase_timings"]
        self.assertEqual([r["phase"] for r in timings], ["discovery", "worklist"])
        self.assertFalse(any(r.get("interrupted") for r in timings))

    def test_control_cancelled_before_an_engagement_started_reports_no_block(self):
        self._engagement(wait=True, bind=False)
        result = self._cancel()["result"]
        self.assertTrue(result["partial"])
        self.assertNotIn("instrumentation", result)
        self.assertNotIn("instrumentation_error", result)


if __name__ == "__main__":
    unittest.main()
