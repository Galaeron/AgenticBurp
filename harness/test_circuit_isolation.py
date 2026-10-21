"""Caller-level coverage for the B2-2 (LOOP half) per-run circuit-breaker
isolation seam and loud-fail starvation assertion.

harness.circuit_breaker.py's shared "ollama" circuit breaker is a
deliberate process-wide singleton (see get_ollama_circuit_breaker's
docstring). In a multi-run process (eval/ablation driver looping over
several runs in one interpreter) that singleton has two failure modes this
module exercises the fix for:

  1. Silent poisoning -- one run's cascade trips the breaker OPEN and a
     later run silently inherits that OPEN state.
  2. Silent starvation -- a run that ends with the breaker OPEN emits
     degraded/zero results with nothing raising or flagging it.

The new API (reset_ollama_circuit_breaker, scoped_ollama_breaker,
raise_if_ollama_starved) is additive and OFF/opt-in: nothing in the
committed run path calls it. This module proves both the positive
(isolation/loud-fail work when invoked) and negative (a healthy breaker is
untouched, and the default unscoped path still shares state) cases.

Offline: no live Ollama/network, no answer-key/blind-target content is
read.

Critical: the breaker is a process-wide singleton shared across the whole
test suite. setUp/tearDown here reset it explicitly (mirroring
test_degraded_circuit.py) so no OPEN state forced by a positive test can
leak into unrelated tests, and _force_open_async() is used instead of
force_open() (which calls asyncio.run() and errors inside a running loop).
"""
import unittest

from harness.circuit_breaker import (
    CircuitStarvationError,
    CircuitState,
    get_ollama_circuit_breaker,
    raise_if_ollama_starved,
    reset_ollama_circuit_breaker,
    scoped_ollama_breaker,
)


class CircuitIsolationTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Process-wide singleton -- always start each test from a known
        # CLOSED state so no prior test's breaker state leaks in.
        get_ollama_circuit_breaker("ollama").reset()

    def tearDown(self):
        # Critical: undo force_open()/scoping from this test so an OPEN
        # breaker never leaks into unrelated tests elsewhere in the full
        # suite.
        get_ollama_circuit_breaker("ollama").reset()

    # -- POSITIVE: isolation -------------------------------------------------

    async def test_scoped_breaker_isolates_run_from_prior_cascade(self):
        # Simulate run 1's cascade: force the shared breaker OPEN.
        await get_ollama_circuit_breaker("ollama")._force_open_async()
        self.assertTrue(get_ollama_circuit_breaker("ollama").is_open)

        # Run 2 opts in to per-run isolation and must see a fresh breaker,
        # not run 1's OPEN state.
        with scoped_ollama_breaker() as breaker:
            self.assertFalse(
                breaker.is_open,
                "scoped_ollama_breaker() did not isolate run 2 from run 1's "
                "OPEN trip -- starvation cascade leaked across runs.",
            )
            self.assertIs(breaker.state, CircuitState.CLOSED)

    async def test_reset_ollama_circuit_breaker_clears_prior_open_state(self):
        await get_ollama_circuit_breaker("ollama")._force_open_async()
        self.assertTrue(get_ollama_circuit_breaker("ollama").is_open)

        breaker = reset_ollama_circuit_breaker()

        self.assertFalse(breaker.is_open)
        self.assertIs(get_ollama_circuit_breaker("ollama").state, CircuitState.CLOSED)

    # -- POSITIVE: loud-fail ---------------------------------------------

    async def test_raise_if_ollama_starved_raises_when_breaker_open(self):
        await get_ollama_circuit_breaker("ollama")._force_open_async()

        with self.assertRaises(CircuitStarvationError):
            raise_if_ollama_starved(context="unit-test-run")

    # -- NEGATIVE CONTROL: healthy breaker ----------------------------------

    async def test_scoped_breaker_is_noop_shaped_for_healthy_breaker(self):
        # Healthy CLOSED breaker, normal timing -- no prior cascade.
        self.assertFalse(get_ollama_circuit_breaker("ollama").is_open)

        with scoped_ollama_breaker() as breaker:
            self.assertFalse(breaker.is_open)
            self.assertIs(breaker.state, CircuitState.CLOSED)

        # After the scope, the breaker is still healthy/CLOSED -- no
        # isolation side-effect turned a healthy run into a degraded one.
        self.assertFalse(get_ollama_circuit_breaker("ollama").is_open)
        self.assertIs(get_ollama_circuit_breaker("ollama").state, CircuitState.CLOSED)

    async def test_raise_if_ollama_starved_is_noop_for_healthy_breaker(self):
        self.assertFalse(get_ollama_circuit_breaker("ollama").is_open)

        try:
            raise_if_ollama_starved(context="healthy-run")
        except CircuitStarvationError:
            self.fail(
                "raise_if_ollama_starved() raised for a healthy CLOSED "
                "breaker -- the positive path fires unconditionally."
            )

    # -- Default committed path unaffected -----------------------------------

    async def test_default_unscoped_path_still_shares_singleton_state(self):
        # Proves opt-in-OFF behavior: without invoking the new seam, the
        # shared "ollama" breaker is still the same deliberate singleton
        # today's committed code relies on (get_ollama_circuit_breaker's
        # docstring) -- a trip made through one accessor call is visible
        # through another, unscoped call.
        await get_ollama_circuit_breaker("ollama")._force_open_async()

        self.assertTrue(
            get_ollama_circuit_breaker("ollama").is_open,
            "Default get_ollama_circuit_breaker() path no longer shares "
            "singleton state -- committed behavior changed.",
        )


if __name__ == "__main__":
    unittest.main()
