"""
Circuit breaker pattern for Ollama API calls.

This module provides a circuit breaker implementation to prevent cascading
failures when the Ollama service is unavailable or overloaded.

Design principles:
1. Fail fast: Don't wait for timeouts when the service is known to be down
2. Self-healing: Automatically recover when the service becomes available
3. Configurable: Allow different thresholds for different use cases
4. Observable: Track state and statistics for monitoring

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Service is down, requests fail immediately
- HALF_OPEN: Testing if service has recovered, limited requests allowed
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto

log = logging.getLogger("harness.circuit_breaker")


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = auto()      # Normal operation
    OPEN = auto()        # Service is down, requests fail immediately
    HALF_OPEN = auto()   # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    
    # Failure threshold: number of consecutive failures before opening
    failure_threshold: int = 5
    
    # Success threshold: number of consecutive successes in half-open state before closing
    success_threshold: int = 3
    
    # Timeout: seconds to wait before transitioning from OPEN to HALF_OPEN
    timeout_seconds: float = 30.0
    
    # Half-open max requests: maximum requests allowed in half-open state
    half_open_max_requests: int = 1
    
    # Excluded exceptions: exceptions that don't count as failures
    excluded_exceptions: tuple[type[Exception], ...] = ()
    
    # Enabled: whether the circuit breaker is active
    enabled: bool = True


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker."""
    state: CircuitState
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_requests: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    last_state_change: Optional[float] = None
    state_changes: list[tuple[CircuitState, float]] = field(default_factory=list)


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.
    
    This implementation tracks failures and automatically opens the circuit
    when the failure threshold is exceeded, preventing further requests until
    the timeout period has elapsed.
    
    Usage:
        breaker = CircuitBreaker(config)
        
        async def make_request():
            async with breaker:
                # This code runs only if circuit is closed or half-open
                return await actual_request()
        
        try:
            result = await make_request()
        except CircuitOpenError:
            # Service is down, handle accordingly
            pass
    """
    
    def __init__(self, config: CircuitBreakerConfig = None, name: str = "default"):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._last_failure_time: Optional[float] = None
        self._last_success_time: Optional[float] = None
        self._last_state_change = time.time()  # Initialize to current time
        self._state_changes: list[tuple[CircuitState, float]] = [(CircuitState.CLOSED, self._last_state_change)]
        self._half_open_requests = 0
        self._lock = asyncio.Lock()
        self._stats = CircuitBreakerStats(state=CircuitState.CLOSED)
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit is open (service is down)."""
        return self._state == CircuitState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self._state == CircuitState.HALF_OPEN
    
    def _should_trip(self) -> bool:
        """Check if the circuit should trip (open)."""
        return (self._consecutive_failures >= self.config.failure_threshold and 
                self.config.enabled)
    
    def _should_reset(self) -> bool:
        """Check if the circuit should reset (close)."""
        return (self._consecutive_successes >= self.config.success_threshold and 
                self._state == CircuitState.HALF_OPEN)
    
    def _should_transition_to_half_open(self) -> bool:
        """Check if the circuit should transition to half-open."""
        if not self.config.enabled:
            return False
        if self._state != CircuitState.OPEN:
            return False
        if self._last_state_change is None:
            return False
        elapsed = time.time() - self._last_state_change
        return elapsed >= self.config.timeout_seconds
    
    def _change_state(self, new_state: CircuitState) -> None:
        """Change circuit state and log the transition."""
        old_state = self._state
        if old_state != new_state:
            self._state = new_state
            self._last_state_change = time.time()
            self._state_changes.append((new_state, self._last_state_change))
            log.info(
                "Circuit breaker '%s' state changed: %s -> %s",
                self.name, old_state.name, new_state.name
            )
    
    def _record_failure(self) -> None:
        """Record a failure."""
        self._consecutive_failures += 1
        self._consecutive_successes = 0
        self._last_failure_time = time.time()
        self._stats.total_failures += 1
    
    def _record_success(self) -> None:
        """Record a success."""
        self._consecutive_failures = 0
        self._consecutive_successes += 1
        self._last_success_time = time.time()
        self._stats.total_successes += 1
    
    async def __aenter__(self) -> CircuitBreaker:
        """Enter the circuit breaker context."""
        async with self._lock:
            # Check if we should transition to half-open
            if self._should_transition_to_half_open():
                self._change_state(CircuitState.HALF_OPEN)
                self._half_open_requests = 0
            
            # Check current state
            if self._state == CircuitState.OPEN:
                raise CircuitOpenError(
                    f"Circuit breaker '{self.name}' is OPEN. "
                    f"Service unavailable. Retry after {self.config.timeout_seconds}s."
                )
            
            # For half-open state, check if we've exceeded the request limit
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_requests >= self.config.half_open_max_requests:
                    raise CircuitOpenError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN with max requests exceeded."
                    )
                self._half_open_requests += 1
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the circuit breaker context."""
        async with self._lock:
            # Release the half-open trial slot this request occupied, so
            # half_open_max_requests gates *concurrent* trial requests rather
            # than the *total* ever admitted. Without this, a breaker whose
            # success_threshold exceeds half_open_max_requests (e.g. the
            # defaults, 3 > 1) could never accumulate enough sequential
            # successes to close: after one trial it would stay HALF_OPEN
            # forever, rejecting every request and defeating the module's
            # stated self-healing design principle.
            if self._half_open_requests > 0:
                self._half_open_requests -= 1

            # Update stats
            self._stats.total_requests += 1
            self._stats.consecutive_failures = self._consecutive_failures
            self._stats.consecutive_successes = self._consecutive_successes
            self._stats.last_failure_time = self._last_failure_time
            self._stats.last_success_time = self._last_success_time
            self._stats.last_state_change = self._last_state_change
            self._stats.state = self._state
            self._stats.state_changes = self._state_changes.copy()
            
            # Check if this was a failure
            is_failure = exc_type is not None and not isinstance(exc_val, self.config.excluded_exceptions)
            
            if is_failure:
                self._record_failure()
                
                # Check if we should trip the circuit
                if self._should_trip():
                    self._change_state(CircuitState.OPEN)
            else:
                self._record_success()
                
                # Check if we should reset the circuit
                if self._should_reset():
                    self._change_state(CircuitState.CLOSED)
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function within the circuit breaker.
        
        This is a convenience method for using the circuit breaker without
        the context manager syntax.
        
        Args:
            func: The async function to call
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function call
            
        Raises:
            CircuitOpenError: If the circuit is open
            Any exception raised by the function
        """
        async with self:
            return await func(*args, **kwargs)
    
    def reset(self) -> None:
        """Manually reset the circuit breaker to closed state."""
        asyncio.run(self._reset_async())
    
    async def _reset_async(self) -> None:
        """Async version of reset."""
        async with self._lock:
            self._change_state(CircuitState.CLOSED)
            self._consecutive_failures = 0
            self._consecutive_successes = 0
            self._half_open_requests = 0
    
    def force_open(self) -> None:
        """Manually force the circuit breaker to open state."""
        asyncio.run(self._force_open_async())
    
    async def _force_open_async(self) -> None:
        """Async version of force_open."""
        async with self._lock:
            self._change_state(CircuitState.OPEN)
    
    def get_stats(self) -> CircuitBreakerStats:
        """Get current circuit breaker statistics."""
        return CircuitBreakerStats(
            state=self._state,
            consecutive_failures=self._consecutive_failures,
            consecutive_successes=self._consecutive_successes,
            total_requests=self._stats.total_requests,
            total_failures=self._stats.total_failures,
            total_successes=self._stats.total_successes,
            last_failure_time=self._last_failure_time,
            last_success_time=self._last_success_time,
            last_state_change=self._last_state_change,
            state_changes=self._state_changes.copy(),
        )


class CircuitOpenError(Exception):
    """Raised when the circuit is open and requests are being rejected."""
    pass


# =============================================================================
# Global Circuit Breaker Management
# =============================================================================

class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.
    
    This allows centralized configuration and monitoring of circuit breakers
    for different services or endpoints.
    """
    
    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}
        self._default_config = CircuitBreakerConfig()
    
    def get(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create a circuit breaker for the given name."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                config or self._default_config, name
            )
        return self._breakers[name]
    
    def get_all_stats(self) -> dict[str, CircuitBreakerStats]:
        """Get statistics for all registered circuit breakers."""
        return {name: breaker.get_stats() for name, breaker in self._breakers.items()}
    
    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()
    
    def set_default_config(self, config: CircuitBreakerConfig) -> None:
        """Set the default configuration for new circuit breakers."""
        self._default_config = config


# Global registry instance
_registry: Optional[CircuitBreakerRegistry] = None


def get_registry() -> CircuitBreakerRegistry:
    """Get the global circuit breaker registry."""
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry


def get_circuit_breaker(name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
    """Get a circuit breaker from the global registry."""
    return get_registry().get(name, config)


# =============================================================================
# Ollama-Specific Circuit Breaker
# =============================================================================

class OllamaCircuitBreaker(CircuitBreaker):
    """
    Specialized circuit breaker for Ollama API calls.
    
    This extends the base CircuitBreaker with Ollama-specific configuration
    and error handling.
    """
    
    def __init__(self, name: str = "ollama", config: CircuitBreakerConfig = None):
        # Use Ollama-specific defaults
        ollama_config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout_seconds=60.0,
            half_open_max_requests=1,
            enabled=True,
        )
        if config:
            # Merge config with defaults
            ollama_config = CircuitBreakerConfig(
                failure_threshold=config.failure_threshold or ollama_config.failure_threshold,
                success_threshold=config.success_threshold or ollama_config.success_threshold,
                timeout_seconds=config.timeout_seconds or ollama_config.timeout_seconds,
                half_open_max_requests=config.half_open_max_requests or ollama_config.half_open_max_requests,
                excluded_exceptions=config.excluded_exceptions or ollama_config.excluded_exceptions,
                enabled=config.enabled if config.enabled is not None else ollama_config.enabled,
            )
        
        super().__init__(ollama_config, name)


def get_ollama_circuit_breaker(name: str = "ollama", config: CircuitBreakerConfig = None) -> "OllamaCircuitBreaker":
    """
    Get a shared OllamaCircuitBreaker from the global registry, creating it
    once per name.

    This exists because `OllamaCircuitBreaker(name)` alone does NOT
    register into the shared registry the way `get_circuit_breaker(name)`
    does for the plain `CircuitBreaker` class -- constructing it directly
    gives every caller its own independent, always-CLOSED breaker with no
    memory of previous failures. Any code that wants Ollama-call failures
    to actually trip a breaker across multiple call sites (e.g. the main
    orchestrator's agent dispatch AND the critique pass) must go through
    this accessor, not `OllamaCircuitBreaker(...)` directly. Found via a
    from-scratch audit: `analysis_pipeline._critique()` was constructing a
    fresh `OllamaClient()` -- and therefore a fresh, never-tripped breaker
    -- on every single critique call, while the orchestrator's own
    long-lived breaker accumulated real state. See CHANGELOG / audit
    report for the reproduction.
    """
    registry = get_registry()
    if name not in registry._breakers:
        registry._breakers[name] = OllamaCircuitBreaker(name, config)
    return registry._breakers[name]


# =============================================================================
# Per-run isolation + loud-fail seam (B2-2, LOOP half)
# =============================================================================
#
# The shared "ollama" breaker above is a DELIBERATE process-wide singleton
# (see get_ollama_circuit_breaker's docstring): a short-lived OllamaClient
# still needs to accumulate failures across call sites within one run. But
# in a multi-run process (e.g. an eval/ablation driver that loops over many
# targets in one interpreter) that singleton has two failure modes:
#
#   1. Silent poisoning: run 1's cascade trips the breaker OPEN; run 2 starts
#      with an already-OPEN breaker and every one of its detections silently
#      fails-open/degrades with no indication the *breaker*, not run 2's own
#      traffic, is why.
#   2. Silent starvation: a run that ends with the breaker OPEN just emits
#      zeros/degraded results -- nothing raises, nothing flags the run as
#      unreliable.
#
# Everything below is NEW, ADDITIVE, and OFF/opt-in: it is never called from
# any committed run path, so importing this module and using
# get_ollama_circuit_breaker() as today is byte-for-byte unchanged unless a
# caller explicitly invokes one of these. No trip/reset thresholds or logic
# are touched -- this only adds scoping/observability around the existing
# reset()/state primitives.


class CircuitStarvationError(RuntimeError):
    """Raised by raise_if_ollama_starved() when the shared "ollama" circuit
    breaker is OPEN -- i.e. a run ended (or is running) starved of a working
    model backend. Distinct exception type so callers can catch/report it
    specifically instead of it being swallowed as a generic RuntimeError."""
    pass


def _set_state(
    breaker: "CircuitBreaker",
    state: CircuitState,
    consecutive_failures: int,
    consecutive_successes: int,
    half_open_requests: int,
) -> None:
    """Directly set a breaker's state fields, bypassing the lock and the
    asyncio.run()-based sync reset()/force_open() wrappers.

    reset()/force_open() are meant for sync call sites with no event loop
    already running -- calling asyncio.run() from inside a running loop
    (e.g. an async run-driver using these seams from inside `async def`
    code) raises. The state mutation itself is the same handful of
    attribute assignments _reset_async()/_force_open_async() perform under
    their lock; scoped_ollama_breaker/reset_ollama_circuit_breaker own the
    breaker for the duration of their call, so the lock isn't needed here
    any more than it already isn't needed by direct attribute reads like
    `.is_open` elsewhere in this module.
    """
    breaker._state = state
    breaker._consecutive_failures = consecutive_failures
    breaker._consecutive_successes = consecutive_successes
    breaker._half_open_requests = half_open_requests
    breaker._last_state_change = time.time()


def reset_ollama_circuit_breaker(name: str = "ollama") -> "OllamaCircuitBreaker":
    """Explicitly reset the shared Ollama circuit breaker to a fresh, CLOSED
    state and return it.

    This is the opt-in per-run isolation primitive: an eval/engagement
    driver that loops over multiple runs in one process can call this at the
    start of each run so a prior run's OPEN trip cannot silently poison the
    next one. Safe to call from sync or async call sites (see _set_state).

    This is never called automatically by any committed code path; a caller
    must invoke it explicitly.
    """
    breaker = get_ollama_circuit_breaker(name)
    _set_state(breaker, CircuitState.CLOSED, 0, 0, 0)
    return breaker


class scoped_ollama_breaker:
    """Context manager that gives the wrapped block a fresh, isolated
    "ollama" circuit breaker and restores the breaker's prior state on exit.

    Usage (opt-in -- a runner must choose to wrap a run with this):

        with scoped_ollama_breaker():
            # this run starts with a CLOSED breaker regardless of what a
            # prior run left behind, and any tripping that happens here is
            # rolled back on exit so it can't leak into the next block.
            await orchestrator.analyze(...)

    Implementation note: the shared "ollama" breaker is a process-wide
    singleton by design (see get_ollama_circuit_breaker's docstring), so
    "isolation" here means snapshot-and-restore around the registry's one
    instance, not swapping in a second instance -- callers elsewhere in the
    process (e.g. a concurrently running critique pass) still observe the
    same object identity throughout, matching today's sharing semantics.
    Only the *state* (open/closed, failure counts) is scoped to the `with`
    block.
    """

    def __init__(self, name: str = "ollama"):
        self.name = name
        self._breaker: Optional["OllamaCircuitBreaker"] = None
        self._saved_state: Optional[CircuitState] = None
        self._saved_consecutive_failures = 0
        self._saved_consecutive_successes = 0
        self._saved_half_open_requests = 0

    def __enter__(self) -> "OllamaCircuitBreaker":
        breaker = get_ollama_circuit_breaker(self.name)
        self._breaker = breaker
        # Snapshot so __exit__ can restore rather than merely reset-to-closed,
        # in case this scope is nested inside a caller that relies on the
        # breaker's pre-existing state once the scope ends.
        self._saved_state = breaker.state
        self._saved_consecutive_failures = breaker._consecutive_failures
        self._saved_consecutive_successes = breaker._consecutive_successes
        self._saved_half_open_requests = breaker._half_open_requests
        # Set directly (not via the sync reset()/force_open() wrappers,
        # which call asyncio.run() and would raise if this context manager
        # is entered from inside an already-running event loop, e.g. a
        # caller inside async run code). This mirrors what
        # CircuitBreaker._reset_async() does, minus the lock, since this
        # scope owns the breaker for its duration.
        _set_state(breaker, CircuitState.CLOSED, 0, 0, 0)
        return breaker

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        breaker = self._breaker
        if breaker is None:
            return
        # Restore the pre-scope snapshot rather than leaving whatever state
        # this run's traffic produced, so a subsequent unscoped caller sees
        # the same breaker state it would have if this scope never ran.
        _set_state(
            breaker,
            self._saved_state,
            self._saved_consecutive_failures,
            self._saved_consecutive_successes,
            self._saved_half_open_requests,
        )


def raise_if_ollama_starved(context: str = "", name: str = "ollama") -> None:
    """Loud-fail assertion helper: raise CircuitStarvationError if the shared
    "ollama" circuit breaker is currently OPEN, otherwise no-op.

    Intended for a runner to call at the end of a run (or periodically
    during one) to turn a silent starvation cascade -- a run that quietly
    emits degraded/zero results because the model backend has been
    unavailable -- into a loud, attributable failure. Never called
    automatically; a caller must invoke it explicitly.

    Args:
        context: optional free-text describing what was starved (e.g. a run
            id or target name), included in the raised error for
            attribution.
        name: circuit breaker name to check (default "ollama").

    Raises:
        CircuitStarvationError: if the breaker is OPEN.
    """
    breaker = get_ollama_circuit_breaker(name)
    if breaker.is_open:
        suffix = f" ({context})" if context else ""
        raise CircuitStarvationError(
            f"Ollama circuit breaker '{name}' is OPEN{suffix} -- this run is "
            f"starved of a working model backend. Results from this run are "
            f"unreliable (silent fail-open/degraded), not a clean signal."
        )
