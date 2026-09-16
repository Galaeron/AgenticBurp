"""
Tests for the circuit breaker module.
"""
import unittest
import asyncio
import time
from harness.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    CircuitState,
    CircuitOpenError,
    CircuitBreakerRegistry,
    get_registry,
    get_circuit_breaker,
    OllamaCircuitBreaker,
    get_ollama_circuit_breaker,
)


class TestCircuitBreaker(unittest.IsolatedAsyncioTestCase):
    """Test the CircuitBreaker class."""

    def setUp(self):
        """Set up test circuit breaker."""
        self.config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout_seconds=1.0,  # Short timeout for testing
            half_open_max_requests=1,
            enabled=True,
        )
        self.breaker = CircuitBreaker(self.config, "test")
    
    def test_initial_state(self):
        """Initial state should be CLOSED."""
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
        self.assertTrue(self.breaker.is_closed)
        self.assertFalse(self.breaker.is_open)
        self.assertFalse(self.breaker.is_half_open)
    
    async def test_successful_requests(self):
        """Successful requests should not trip the circuit."""
        async def make_request():
            return "success"
        
        # Make several successful requests
        for _ in range(5):
            async with self.breaker:
                result = await make_request()
                self.assertEqual(result, "success")
        
        # Circuit should still be closed
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
    
    async def test_failure_threshold(self):
        """Circuit should open after failure threshold is reached."""
        async def failing_request():
            raise ValueError("Test error")
        
        # Make requests until circuit opens
        for i in range(self.config.failure_threshold):
            with self.assertRaises(ValueError):
                async with self.breaker:
                    await failing_request()
        
        # Circuit should now be open
        self.assertEqual(self.breaker.state, CircuitState.OPEN)
        self.assertTrue(self.breaker.is_open)
    
    async def test_circuit_open_rejects_requests(self):
        """Open circuit should reject requests immediately."""
        # Trip the circuit
        async def failing_request():
            raise ValueError("Test error")
        
        for _ in range(self.config.failure_threshold):
            try:
                async with self.breaker:
                    await failing_request()
            except ValueError:
                pass
        
        # Now circuit should be open, requests should be rejected
        with self.assertRaises(CircuitOpenError):
            async with self.breaker:
                pass
    
    async def test_half_open_state(self):
        """Circuit should transition to HALF_OPEN after timeout."""
        # Trip the circuit
        async def failing_request():
            raise ValueError("Test error")
        
        for _ in range(self.config.failure_threshold):
            try:
                async with self.breaker:
                    await failing_request()
            except ValueError:
                pass
        
        self.assertEqual(self.breaker.state, CircuitState.OPEN)
        
        # Wait for timeout
        await asyncio.sleep(self.config.timeout_seconds + 0.1)
        
        # Now check if we can make a request (should transition to HALF_OPEN)
        async with self.breaker:
            pass
        
        # State should be HALF_OPEN
        self.assertEqual(self.breaker.state, CircuitState.HALF_OPEN)
    
    async def test_half_open_to_closed(self):
        """Circuit should close after success threshold in HALF_OPEN state."""
        # Trip the circuit
        async def failing_request():
            raise ValueError("Test error")
        
        for _ in range(self.config.failure_threshold):
            try:
                async with self.breaker:
                    await failing_request()
            except ValueError:
                pass
        
        # Wait for timeout
        await asyncio.sleep(self.config.timeout_seconds + 0.1)
        
        # Make successful requests in HALF_OPEN state
        async def successful_request():
            return "success"
        
        for _ in range(self.config.success_threshold):
            async with self.breaker:
                await successful_request()
        
        # Circuit should now be closed
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
    
    async def test_half_open_max_requests(self):
        """HALF_OPEN state should limit *concurrent* trial requests."""
        # Trip the circuit
        async def failing_request():
            raise ValueError("Test error")

        for _ in range(self.config.failure_threshold):
            try:
                async with self.breaker:
                    await failing_request()
            except ValueError:
                pass

        # Wait for timeout
        await asyncio.sleep(self.config.timeout_seconds + 0.1)

        # Enter HALF_OPEN and hold the single trial slot open; a *concurrent*
        # second entry (before the first exits and releases the slot) must be
        # rejected because half_open_max_requests == 1.
        async with self.breaker:
            self.assertEqual(self.breaker.state, CircuitState.HALF_OPEN)
            with self.assertRaises(CircuitOpenError):
                async with self.breaker:
                    pass

        # After the slot is released, a subsequent sequential request is
        # admitted again (the gate is on concurrency, not total count).
        async with self.breaker:
            pass
    
    async def test_half_open_failure_resets_to_open(self):
        """Failure in HALF_OPEN state should reset to OPEN."""
        # Trip the circuit
        async def failing_request():
            raise ValueError("Test error")
        
        for _ in range(self.config.failure_threshold):
            try:
                async with self.breaker:
                    await failing_request()
            except ValueError:
                pass
        
        # Wait for timeout
        await asyncio.sleep(self.config.timeout_seconds + 0.1)
        
        # Enter HALF_OPEN state and fail
        async def failing_request_2():
            raise ValueError("Test error 2")
        
        try:
            async with self.breaker:
                await failing_request_2()
        except ValueError:
            pass
        
        # Circuit should be back to OPEN
        self.assertEqual(self.breaker.state, CircuitState.OPEN)
    
    async def test_call_method(self):
        """The call() method should work correctly."""
        async def successful_request():
            return "success"
        
        result = await self.breaker.call(successful_request)
        self.assertEqual(result, "success")
    
    async def test_excluded_exceptions(self):
        """Excluded exceptions should not count as failures."""
        class CustomError(Exception):
            pass
        
        config = CircuitBreakerConfig(
            failure_threshold=3,
            excluded_exceptions=(CustomError,),
        )
        breaker = CircuitBreaker(config, "test_excluded")
        
        async def excluded_error_request():
            raise CustomError("This should not trip the circuit")
        
        # These should not trip the circuit
        for _ in range(5):
            with self.assertRaises(CustomError):
                await breaker.call(excluded_error_request)
        
        # Circuit should still be closed
        self.assertEqual(breaker.state, CircuitState.CLOSED)
    
    def test_manual_reset(self):
        """Manual reset should close the circuit."""
        # Trip the circuit
        async def trip():
            async def failing_request():
                raise ValueError("Test error")
            
            for _ in range(self.config.failure_threshold):
                try:
                    async with self.breaker:
                        await failing_request()
                except ValueError:
                    pass
        
        asyncio.run(trip())
        
        self.assertEqual(self.breaker.state, CircuitState.OPEN)
        
        # Reset
        self.breaker.reset()
        
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
    
    def test_force_open(self):
        """Force open should open the circuit."""
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
        
        self.breaker.force_open()
        
        self.assertEqual(self.breaker.state, CircuitState.OPEN)
    
    def test_get_stats(self):
        """get_stats should return current statistics."""
        stats = self.breaker.get_stats()
        
        self.assertIsInstance(stats, CircuitBreakerStats)
        self.assertEqual(stats.state, CircuitState.CLOSED)
        self.assertEqual(stats.total_requests, 0)
    
    async def test_stats_tracking(self):
        """Statistics should be tracked correctly."""
        async def successful_request():
            return "success"
        
        async def failing_request():
            raise ValueError("Test error")
        
        # Make some successful requests
        for _ in range(3):
            await self.breaker.call(successful_request)
        
        stats = self.breaker.get_stats()
        self.assertEqual(stats.total_successes, 3)
        self.assertEqual(stats.total_failures, 0)
        
        # Make some failing requests
        for _ in range(3):
            try:
                await self.breaker.call(failing_request)
            except ValueError:
                pass
        
        stats = self.breaker.get_stats()
        self.assertEqual(stats.total_failures, 3)
    
    def test_disabled_circuit_breaker(self):
        """Disabled circuit breaker should always allow requests."""
        config = CircuitBreakerConfig(enabled=False)
        breaker = CircuitBreaker(config, "disabled")
        
        # Even after many failures, circuit should stay closed
        async def trip():
            async def failing_request():
                raise ValueError("Test error")
            
            for _ in range(100):
                try:
                    async with breaker:
                        await failing_request()
                except ValueError:
                    pass
        
        asyncio.run(trip())
        
        # Circuit should still be closed (disabled)
        self.assertEqual(breaker.state, CircuitState.CLOSED)


class TestCircuitBreakerRegistry(unittest.TestCase):
    """Test the CircuitBreakerRegistry class."""
    
    def test_get_creates_breaker(self):
        """get() should create a new circuit breaker if not exists."""
        registry = CircuitBreakerRegistry()
        
        breaker = registry.get("test")
        self.assertIsInstance(breaker, CircuitBreaker)
        self.assertEqual(breaker.name, "test")
    
    def test_get_returns_existing(self):
        """get() should return existing circuit breaker."""
        registry = CircuitBreakerRegistry()
        
        breaker1 = registry.get("test")
        breaker2 = registry.get("test")
        
        self.assertIs(breaker1, breaker2)
    
    def test_get_all_stats(self):
        """get_all_stats should return stats for all breakers."""
        registry = CircuitBreakerRegistry()
        
        registry.get("breaker1")
        registry.get("breaker2")
        
        stats = registry.get_all_stats()
        
        self.assertEqual(len(stats), 2)
        self.assertIn("breaker1", stats)
        self.assertIn("breaker2", stats)
    
    def test_reset_all(self):
        """reset_all should reset all circuit breakers."""
        registry = CircuitBreakerRegistry()

        # Explicit threshold: the default failure_threshold is 5, so tripping
        # three times would never open the breakers and this test would assert
        # nothing meaningful.
        config = CircuitBreakerConfig(failure_threshold=3, timeout_seconds=1.0)
        breaker1 = registry.get("breaker1", config)
        breaker2 = registry.get("breaker2", config)

        # Trip both breakers
        async def trip():
            async def failing_request():
                raise ValueError("Test error")

            for breaker in [breaker1, breaker2]:
                for _ in range(3):
                    try:
                        async with breaker:
                            await failing_request()
                    except ValueError:
                        pass
        
        asyncio.run(trip())
        
        # Both should be open
        self.assertTrue(breaker1.is_open)
        self.assertTrue(breaker2.is_open)
        
        # Reset all
        registry.reset_all()
        
        # Both should be closed
        self.assertTrue(breaker1.is_closed)
        self.assertTrue(breaker2.is_closed)


class TestGlobalRegistry(unittest.TestCase):
    """Test the global registry functions."""
    
    def test_get_registry(self):
        """get_registry should return a registry instance."""
        registry = get_registry()
        self.assertIsInstance(registry, CircuitBreakerRegistry)
    
    def test_get_circuit_breaker(self):
        """get_circuit_breaker should return a circuit breaker."""
        breaker = get_circuit_breaker("test_global")
        self.assertIsInstance(breaker, CircuitBreaker)
        self.assertEqual(breaker.name, "test_global")


class TestOllamaCircuitBreaker(unittest.TestCase):
    """Test the OllamaCircuitBreaker class."""
    
    def test_default_config(self):
        """OllamaCircuitBreaker should use Ollama-specific defaults."""
        breaker = OllamaCircuitBreaker()
        
        self.assertEqual(breaker.config.failure_threshold, 3)
        self.assertEqual(breaker.config.success_threshold, 2)
        self.assertEqual(breaker.config.timeout_seconds, 60.0)
    
    def test_custom_config(self):
        """OllamaCircuitBreaker should allow custom config."""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=120.0,
        )
        breaker = OllamaCircuitBreaker("custom", config)
        
        self.assertEqual(breaker.config.failure_threshold, 5)
        self.assertEqual(breaker.config.timeout_seconds, 120.0)


class TestGetOllamaCircuitBreakerIsShared(unittest.TestCase):
    """
    Regression test for a real bug found during audit: constructing
    `OllamaCircuitBreaker(name)` directly does NOT register into the
    shared registry the way `get_circuit_breaker(name)` does, so two
    independently-constructed OllamaClients never shared failure state --
    meaning a call site that builds a fresh OllamaClient per call (as
    analysis_pipeline._critique() used to) got a breaker that could never
    trip, regardless of how many consecutive failures occurred elsewhere.
    """

    def setUp(self):
        # Each test gets a clean global registry so state from other
        # tests (or import order) can't leak in.
        import harness.circuit_breaker as cb_module
        self._original_registry = cb_module._registry
        cb_module._registry = None

    def tearDown(self):
        import harness.circuit_breaker as cb_module
        cb_module._registry = self._original_registry

    def test_two_calls_with_same_name_return_the_same_breaker(self):
        b1 = get_ollama_circuit_breaker("ollama")
        b2 = get_ollama_circuit_breaker("ollama")
        self.assertIs(b1, b2)

    def test_failure_recorded_via_one_reference_is_visible_via_another(self):
        b1 = get_ollama_circuit_breaker("ollama")
        b2 = get_ollama_circuit_breaker("ollama")
        # Directly manipulate internal failure count the way the base
        # CircuitBreaker's call() path does, to avoid needing a full
        # async failing call here -- this isolates the sharing behavior
        # from the trip-threshold behavior, which is already covered by
        # TestCircuitBreaker's own tests.
        b1._consecutive_failures = 3
        self.assertEqual(b2._consecutive_failures, 3)

    def test_different_names_get_different_breakers(self):
        b1 = get_ollama_circuit_breaker("ollama")
        b2 = get_ollama_circuit_breaker("some_other_service")
        self.assertIsNot(b1, b2)

    def test_ollama_client_uses_the_shared_accessor(self):
        """
        The actual regression: two OllamaClient instances pointed at the
        same logical service must share one breaker. Before the fix,
        this was False because OllamaClient.__init__ called
        OllamaCircuitBreaker("ollama") directly instead of
        get_ollama_circuit_breaker("ollama").
        """
        from harness.ollama_client import OllamaClient
        c1 = OllamaClient(base_url="http://example.invalid")
        c2 = OllamaClient(base_url="http://example.invalid")
        self.assertIs(c1.circuit_breaker, c2.circuit_breaker)


if __name__ == "__main__":
    unittest.main()
