"""Tests for the Phase 4 cloud-coordinator reasoning seam.

reasoning_model() selects the cloud model for the iterative agent + critique only
when the seam is toggled on AND a cloud_model is configured -- default off, since
enabling it sends real exchange content off-host."""
import unittest

from harness import coordinator
import harness.orchestrator as orch_mod


def _cfg(cloud_reasoning=False, cloud_model="cloud-frontier", model="qwen3:8b"):
    coord = {"model": model, "cloud_reasoning": cloud_reasoning}
    if cloud_model is not None:
        coord["cloud_model"] = cloud_model
    return {"coordinator": coord}


class ReasoningModelTests(unittest.TestCase):
    def test_default_off_uses_local(self):
        self.assertEqual(coordinator.reasoning_model(_cfg(cloud_reasoning=False)), "qwen3:8b")

    def test_enabled_with_cloud_model_uses_cloud(self):
        self.assertEqual(coordinator.reasoning_model(_cfg(cloud_reasoning=True)), "cloud-frontier")

    def test_enabled_without_cloud_model_falls_back_to_local(self):
        self.assertEqual(
            coordinator.reasoning_model(_cfg(cloud_reasoning=True, cloud_model=None)), "qwen3:8b")

    def test_missing_coordinator_block_is_empty(self):
        self.assertEqual(coordinator.reasoning_model({}), "")


class OrchestratorSeamTests(unittest.TestCase):
    def _orch(self):
        # object.__new__ avoids the heavy 36-agent init; reasoning_model/toggle
        # only need self.config.
        o = object.__new__(orch_mod.Orchestrator)
        o.config = _cfg(cloud_reasoning=False)
        return o

    def test_reasoning_model_reflects_config(self):
        o = self._orch()
        self.assertEqual(o.reasoning_model(), "qwen3:8b")

    def test_toggle_flips_reasoning_model(self):
        o = self._orch()
        state = o.set_cloud_reasoning(True)
        self.assertTrue(state["cloud_reasoning"])
        self.assertEqual(state["reasoning_model"], "cloud-frontier")
        self.assertEqual(o.reasoning_model(), "cloud-frontier")
        o.set_cloud_reasoning(False)
        self.assertEqual(o.reasoning_model(), "qwen3:8b")

    def test_toggle_mutates_shared_config_for_the_pipeline(self):
        # The critique pass reads the SAME config dict, so the toggle must be
        # visible there -- assert the mutation lands on self.config.
        o = self._orch()
        o.set_cloud_reasoning(True)
        self.assertTrue(o.config["coordinator"]["cloud_reasoning"])
        self.assertEqual(coordinator.reasoning_model(o.config), "cloud-frontier")


if __name__ == "__main__":
    unittest.main()
