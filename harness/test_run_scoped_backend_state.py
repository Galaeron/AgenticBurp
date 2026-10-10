"""AR-2 (LOOP half) -- run-scoped model-backend state by default.

Attaches an isolated per-run circuit breaker + fail-open counters to
RunContext (via the ambient-ContextVar pattern from harness.safety_gate,
NOT B2-2's snapshot/restore scoped_ollama_breaker) so concurrent/sequential
runs cannot poison each other's model-backend state.

Ships OFF byte-for-byte: with no RunContext `async with`-entered, every
resolver (current_ollama_breaker, coordinator.fail_open_stats) returns
today's process-wide singleton/module-global -- identical object identity.

Critical: get_ollama_circuit_breaker("ollama") is a process-wide singleton
shared across the whole test suite (see test_circuit_isolation.py). setUp/
tearDown here reset it so no OPEN state leaks into unrelated tests.

Offline: no live Ollama/network, no answer-key/blind-target content read.
"""
import asyncio
import unittest

from harness.circuit_breaker import (
    CircuitState,
    current_ollama_breaker,
    get_ollama_circuit_breaker,
)
from harness.coordinator import fail_open_stats
from harness.run_context import RunContext


class RunScopedBackendStateTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        get_ollama_circuit_breaker("ollama").reset()

    # -- POSITIVE: two sequential runs in one process ------------------------

    async def test_sequential_runs_do_not_poison_each_other(self):
        run1 = RunContext.create(allowed_hosts=["example.test"])
        async with run1:
            breaker1 = current_ollama_breaker()
            await breaker1._force_open_async()
            self.assertTrue(breaker1.is_open)

        # Run 1 has exited; run 2 starts fresh.
        run2 = RunContext.create(allowed_hosts=["example.test"])
        async with run2:
            breaker2 = current_ollama_breaker()
            self.assertFalse(
                breaker2.is_open,
                "run 2's ambient breaker inherited run 1's OPEN trip -- "
                "agent calls would be silently zeroed for run 2.",
            )
            self.assertEqual(
                fail_open_stats()["count"], 0,
                "run 2's fail-open count did not start at 0.",
            )

    # -- POSITIVE: two concurrent runs ---------------------------------------

    async def test_concurrent_runs_are_isolated(self):
        started = asyncio.Event()
        other_seen_open = {"value": None}

        async def run_a():
            ctx = RunContext.create(allowed_hosts=["a.test"])
            async with ctx:
                breaker = current_ollama_breaker()
                await breaker._force_open_async()
                started.set()
                # Give run_b a chance to read its own (unrelated) breaker
                # state while run_a's breaker is OPEN.
                await asyncio.sleep(0.05)

        async def run_b():
            await started.wait()
            ctx = RunContext.create(allowed_hosts=["b.test"])
            async with ctx:
                other_seen_open["value"] = current_ollama_breaker().is_open

        await asyncio.gather(run_a(), run_b())

        self.assertFalse(
            other_seen_open["value"],
            "run_b's ambient breaker observed run_a's OPEN trip -- "
            "ContextVar task-locality failed to isolate concurrent runs.",
        )

    # -- NEGATIVE: within one run, an OPEN breaker still short-circuits -----

    async def test_within_run_open_breaker_still_short_circuits(self):
        run1 = RunContext.create(allowed_hosts=["example.test"])
        async with run1:
            breaker = current_ollama_breaker()
            await breaker._force_open_async()
            self.assertTrue(breaker.is_open)
            # A later resolve within the SAME run must still see it OPEN --
            # isolation must not defeat the breaker's own job.
            self.assertIs(current_ollama_breaker().state, CircuitState.OPEN)
            self.assertTrue(current_ollama_breaker().is_open)

    # -- NEGATIVE: no run context -> byte-for-byte today's -------------------

    async def test_no_run_context_returns_identical_singleton(self):
        singleton = get_ollama_circuit_breaker("ollama")
        self.assertIs(
            current_ollama_breaker(),
            singleton,
            "current_ollama_breaker() with no active RunContext did not "
            "return the identical pre-existing singleton object.",
        )

        # fail_open_stats() reads the module-global _FAIL_OPEN, not some
        # per-run dict, with no run active.
        from harness import coordinator
        coordinator.reset_fail_open_stats()
        coordinator._record_fail_open("local", "unit-test-reason", 3)
        self.assertEqual(fail_open_stats()["count"], 1)
        self.assertEqual(coordinator._FAIL_OPEN["count"], 1)
        coordinator.reset_fail_open_stats()

    async def test_run_context_never_entered_allocates_nothing(self):
        # The ~70 existing tests that construct a RunContext but never
        # `async with` it must see byte-for-byte unchanged behavior: no
        # ambient breaker/counters pushed, current_ollama_breaker() still
        # the singleton.
        RunContext.create(allowed_hosts=["example.test"])  # never entered
        self.assertIs(current_ollama_breaker(), get_ollama_circuit_breaker("ollama"))


if __name__ == "__main__":
    unittest.main()
