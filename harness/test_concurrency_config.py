"""W-13: concurrency caps come from one config block, not magic numbers, and
the bounded fan-out never exceeds the configured cap."""
import asyncio
import unittest
from pathlib import Path

import yaml

from orchestrator import Orchestrator, bounded_gather

_HARNESS = Path(__file__).resolve().parent


def _config(**concurrency):
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {}).update(concurrency)
    return cfg


class ConcurrencyConfigTests(unittest.TestCase):
    def test_knobs_read_from_config(self):
        orch = Orchestrator(_config(max_concurrent_validations=9,
                                    early_termination_batch_size=5))
        self.assertEqual(orch.max_concurrent_validations, 9)
        self.assertEqual(orch.early_termination_batch_size, 5)

    def test_knobs_floor_at_one(self):
        orch = Orchestrator(_config(max_concurrent_validations=0,
                                    early_termination_batch_size=0))
        self.assertGreaterEqual(orch.max_concurrent_validations, 1)
        self.assertGreaterEqual(orch.early_termination_batch_size, 1)

    def test_bounded_gather_never_exceeds_the_cap(self):
        # asyncio is single-threaded, so a plain counter around the await is a
        # correct concurrency gauge: peak = the most jobs ever in-flight at once.
        state = {"cur": 0, "peak": 0}

        async def job():
            state["cur"] += 1
            state["peak"] = max(state["peak"], state["cur"])
            await asyncio.sleep(0.005)
            state["cur"] -= 1
            return 1

        results = asyncio.run(bounded_gather([job() for _ in range(20)], 4))
        self.assertEqual(len(results), 20)
        self.assertLessEqual(state["peak"], 4,
                             f"in-flight peaked at {state['peak']}, above the cap of 4")


if __name__ == "__main__":
    unittest.main()
