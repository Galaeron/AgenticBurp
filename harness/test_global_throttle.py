"""Tests for the global outbound-request throttle."""
import asyncio
import time
import unittest

from harness.global_throttle import GlobalRequestThrottle


class GlobalThrottleTests(unittest.TestCase):
    def test_disabled_is_immediate_noop(self):
        t = GlobalRequestThrottle()
        t.configure(0)
        self.assertFalse(t.enabled)
        start = time.monotonic()
        async def run():
            for _ in range(50):
                await t.acquire()
        asyncio.run(run())
        self.assertLess(time.monotonic() - start, 0.05)  # no blocking at all

    def test_none_is_disabled(self):
        t = GlobalRequestThrottle()
        t.configure(None)
        self.assertFalse(t.enabled)

    def test_caps_sustained_rate(self):
        # 20 req/s, burst 1 => after the initial token, ~1/20s between grants.
        t = GlobalRequestThrottle()
        t.configure(20, burst=1)
        N = 11
        start = time.monotonic()
        async def run():
            for _ in range(N):
                await t.acquire()
        asyncio.run(run())
        elapsed = time.monotonic() - start
        # (N-1) gaps of 1/20s = 0.5s floor; generous upper bound for CI jitter.
        self.assertGreaterEqual(elapsed, 0.4)
        self.assertLess(elapsed, 2.0)

    def test_burst_then_throttle(self):
        # burst of 5 should grant 5 immediately, then pace the rest.
        t = GlobalRequestThrottle()
        t.configure(10, burst=5)
        async def run():
            start = time.monotonic()
            for _ in range(5):
                await t.acquire()
            burst_time = time.monotonic() - start
            return burst_time
        burst_time = asyncio.run(run())
        self.assertLess(burst_time, 0.1)  # first 5 are ~instant

    def test_stats_track_acquisitions(self):
        t = GlobalRequestThrottle()
        t.configure(0)
        async def run():
            for _ in range(3):
                await t.acquire()
        asyncio.run(run())
        # disabled acquisitions are no-ops and not counted
        self.assertEqual(t.stats()["acquired"], 0)

        t.configure(1000, burst=1000)
        async def run2():
            for _ in range(7):
                await t.acquire()
        asyncio.run(run2())
        self.assertEqual(t.stats()["acquired"], 7)

    def test_reconfigure_toggles(self):
        t = GlobalRequestThrottle()
        t.configure(50)
        self.assertTrue(t.enabled)
        t.configure(0)
        self.assertFalse(t.enabled)


if __name__ == "__main__":
    unittest.main()
