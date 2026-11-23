"""
Rate limiting for Ollama API calls.

This module provides token-based and request-based rate limiting to prevent
overloading the Ollama service and to stay within API limits.

Design principles:
1. Token-based limiting: Track token usage across all requests
2. Request-based limiting: Limit requests per time window
3. Configurable: Allow different limits for different use cases
4. Fair: Distribute available capacity fairly across requests
5. Observable: Track usage and limits for monitoring

Rate Limiting Strategies:
- Token Bucket: Smooth rate limiting with burst capacity
- Fixed Window: Strict per-window limits
- Sliding Window: More accurate but more expensive
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from collections import deque
from enum import Enum, auto

log = logging.getLogger("harness.rate_limiter")


class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    TOKEN_BUCKET = auto()    # Smooth rate limiting with burst capacity
    FIXED_WINDOW = auto()    # Strict per-window limits
    SLIDING_WINDOW = auto()  # More accurate but more expensive


@dataclass
class RateLimitConfig:
    """Configuration for rate limiter."""
    
    # Strategy to use
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    
    # Token-based limits (for TOKEN_BUCKET strategy)
    tokens_per_second: float = 100.0  # Tokens to add per second
    max_tokens: int = 1000  # Maximum tokens in the bucket
    
    # Request-based limits (for FIXED_WINDOW and SLIDING_WINDOW strategies)
    max_requests: int = 100  # Maximum requests per window
    window_seconds: float = 60.0  # Window size in seconds
    
    # Token estimation (for token-based limiting)
    tokens_per_request: int = 100  # Estimated tokens per request
    
    # Enabled
    enabled: bool = True

    # Longest an `async with` entry waits for a token before raising
    # RateLimitWaitExceeded. None waits without a bound (the generic default);
    # the model-call pacer (pacer_config) always sets one.
    max_wait_seconds: float | None = None


# How often a waiter re-checks the bucket.
POLL_SECONDS = 0.1


class RateLimitWaitExceeded(Exception):
    """An `async with limiter` entry waited `max_wait_seconds` without a token.
    Nothing was admitted, so the caller's work did not run."""

    def __init__(self, name: str, max_wait_seconds: float, waited_seconds: float):
        super().__init__(f"rate limiter {name!r}: no token within {max_wait_seconds:g}s "
                         f"(waited {waited_seconds:.1f}s)")
        self.name = name
        self.max_wait_seconds = max_wait_seconds
        self.waited_seconds = waited_seconds


@dataclass
class RateLimitStats:
    """Statistics for rate limiter."""
    allowed: int = 0
    rejected: int = 0
    current_tokens: int = 0
    current_requests: int = 0
    last_update: float = 0.0
    waiting: int = 0
    # wait_for_token calls that found the bucket empty and had to wait, their
    # summed and longest wait, and those that gave up at their timeout.
    waited: int = 0
    wait_seconds_total: float = 0.0
    wait_seconds_max: float = 0.0
    timed_out: int = 0


class RateLimiter:
    """
    Rate limiter for controlling API call rates.
    
    This implementation supports multiple rate limiting strategies and
    provides both token-based and request-based limiting.
    
    Usage:
        limiter = RateLimiter(config)
        
        # Check if request is allowed
        if limiter.allow():
            # Make the request
            pass
        else:
            # Wait or reject
            pass
        
        # Or use as async context manager
        async with limiter:
            # Make the request
            pass
    """
    
    def __init__(self, config: RateLimitConfig = None, name: str = "default"):
        self.config = config or RateLimitConfig()
        self.name = name
        self._tokens = self.config.max_tokens
        self._last_update = time.time()
        self._requests: deque[float] = deque()
        self._lock = asyncio.Lock()
        self._stats = RateLimitStats(
            current_tokens=self.config.max_tokens,
            last_update=self._last_update,
        )
    
    def _update_tokens(self) -> None:
        """Update token count based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_update
        
        if elapsed > 0:
            # Add tokens based on rate
            new_tokens = elapsed * self.config.tokens_per_second
            self._tokens = min(self.config.max_tokens, self._tokens + new_tokens)
            self._last_update = now
    
    def _cleanup_requests(self) -> None:
        """Remove old requests from the window."""
        now = time.time()
        window_start = now - self.config.window_seconds
        
        while self._requests and self._requests[0] < window_start:
            self._requests.popleft()
    
    def allow(self) -> bool:
        """
        Check if a request is allowed.
        
        Returns:
            True if the request is allowed, False otherwise
        """
        if not self.config.enabled:
            return True
        
        if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            self._update_tokens()
            allowed = self._tokens >= self.config.tokens_per_request
            if allowed:
                self._tokens -= self.config.tokens_per_request
                self._stats.allowed += 1
                self._stats.current_tokens = self._tokens
                self._stats.last_update = self._last_update
            else:
                self._stats.rejected += 1
            return allowed
        
        elif self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
            self._cleanup_requests()
            allowed = len(self._requests) < self.config.max_requests
            if allowed:
                self._requests.append(time.time())
                self._stats.allowed += 1
                self._stats.current_requests = len(self._requests)
            else:
                self._stats.rejected += 1
            return allowed
        
        elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            self._cleanup_requests()
            allowed = len(self._requests) < self.config.max_requests
            if allowed:
                self._requests.append(time.time())
                self._stats.allowed += 1
                self._stats.current_requests = len(self._requests)
            else:
                self._stats.rejected += 1
            return allowed
        
        return True
    
    async def wait_for_token(self, timeout: float = None) -> bool:
        """
        Wait until a token is available.
        
        Args:
            timeout: Maximum time to wait in seconds (None = no timeout)
            
        Returns:
            True if a token became available, False if timeout was reached
        """
        if not self.config.enabled:
            return True

        if self.allow():
            return True
        start_time = time.time()
        self._stats.waited += 1
        try:
            while True:
                if timeout is not None and time.time() - start_time >= timeout:
                    self._stats.timed_out += 1
                    return False
                # Wait a bit before checking again
                await asyncio.sleep(POLL_SECONDS)
                if self.allow():
                    return True
        finally:
            waited = time.time() - start_time
            self._stats.wait_seconds_total += waited
            self._stats.wait_seconds_max = max(self._stats.wait_seconds_max, waited)

    async def __aenter__(self) -> RateLimiter:
        """Enter the rate limiter context: wait for a token, at most
        config.max_wait_seconds, then raise RateLimitWaitExceeded."""
        if self.config.enabled:
            started = time.time()
            if not await self.wait_for_token(self.config.max_wait_seconds):
                raise RateLimitWaitExceeded(self.name, self.config.max_wait_seconds,
                                            time.time() - started)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the rate limiter context."""
        pass
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function within the rate limiter.
        
        Args:
            func: The async function to call
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function call
        """
        async with self:
            return await func(*args, **kwargs)
    
    def reset(self) -> None:
        """Reset the rate limiter to initial state."""
        self._tokens = self.config.max_tokens
        self._last_update = time.time()
        self._requests.clear()
        self._stats = RateLimitStats(
            current_tokens=self.config.max_tokens,
            last_update=self._last_update,
        )
    
    def get_stats(self) -> RateLimitStats:
        """Get current rate limiter statistics."""
        return RateLimitStats(
            allowed=self._stats.allowed,
            rejected=self._stats.rejected,
            current_tokens=self._tokens,
            current_requests=len(self._requests),
            last_update=self._last_update,
            waiting=self._stats.waiting,
            waited=self._stats.waited,
            wait_seconds_total=self._stats.wait_seconds_total,
            wait_seconds_max=self._stats.wait_seconds_max,
            timed_out=self._stats.timed_out,
        )


# =============================================================================
# Token-Based Rate Limiter (for LLM token usage)
# =============================================================================

class TokenRateLimiter:
    """
    Rate limiter specifically for LLM token usage.
    
    This tracks actual token usage and limits based on tokens per minute
    or other token-based constraints.
    """
    
    def __init__(self, config: RateLimitConfig = None, name: str = "token_limiter"):
        self.config = config or RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=1000.0 / 60.0,  # 1000 tokens per minute
            max_tokens=1000,
            enabled=True,
        )
        self.name = name
        self._limiter = RateLimiter(self.config, name)
        self._token_usage: deque[tuple[float, int]] = deque()  # (timestamp, tokens_used)
        self._total_tokens_used = 0
        self._unknown_usage: deque[float] = deque()

    def record_usage(self, prompt_tokens: int | None, completion_tokens: int | None) -> None:
        """Track known consumption; missing counts retain a separate marker."""
        recorded_at = time.time()
        if prompt_tokens is None or completion_tokens is None:
            self._unknown_usage.append(recorded_at)
        total_tokens = (prompt_tokens or 0) + (completion_tokens or 0)
        self._token_usage.append((recorded_at, total_tokens))
        self._total_tokens_used += total_tokens
        
        # Clean up old entries (older than 1 minute)
        cutoff = time.time() - 60.0
        while self._token_usage and self._token_usage[0][0] < cutoff:
            _, tokens = self._token_usage.popleft()
            self._total_tokens_used -= tokens
        while self._unknown_usage and self._unknown_usage[0] < cutoff:
            self._unknown_usage.popleft()
    
    def get_recent_usage(self, seconds: float = 60.0) -> int:
        """Get token usage in the last N seconds."""
        cutoff = time.time() - seconds
        total = 0
        for timestamp, tokens in self._token_usage:
            if timestamp >= cutoff:
                total += tokens
        return total
    
    def allow(self, estimated_tokens: int = None) -> bool:
        """
        Check if a request is allowed based on token usage.
        
        Args:
            estimated_tokens: Estimated tokens for this request
            
        Returns:
            True if the request is allowed, False otherwise
        """
        if not self.config.enabled:
            return True
        
        # Use the underlying limiter
        if estimated_tokens is None:
            estimated_tokens = self.config.tokens_per_request
        
        # Temporarily adjust tokens per request
        original_tokens_per_request = self._limiter.config.tokens_per_request
        self._limiter.config.tokens_per_request = estimated_tokens
        
        try:
            return self._limiter.allow()
        finally:
            self._limiter.config.tokens_per_request = original_tokens_per_request
    
    async def __aenter__(self) -> TokenRateLimiter:
        """Enter the token rate limiter context."""
        await self._limiter.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the token rate limiter context."""
        await self._limiter.__aexit__(exc_type, exc_val, exc_tb)
    
    def reconfigure(self, config: RateLimitConfig) -> None:
        """Replace the config in place, keeping the bucket's current fill (capped
        at the new size) and its counters, so every holder of this limiter paces
        to the new values from its next entry on."""
        self.config = config
        self._limiter.config = config
        self._limiter._tokens = min(self._limiter._tokens, config.max_tokens)

    def reset(self) -> None:
        """Reset the token rate limiter."""
        self._limiter.reset()
        self._token_usage.clear()
        self._total_tokens_used = 0
        self._unknown_usage.clear()
    
    def get_stats(self) -> dict:
        """Get token rate limiter statistics."""
        stats = self._limiter.get_stats()
        unknown = sum(recorded_at >= time.time() - 60.0 for recorded_at in self._unknown_usage)
        return {
            **stats.__dict__,
            'total_tokens_used': self._total_tokens_used,
            'recent_usage_60s': self.get_recent_usage(60.0),
            'unknown_usage_calls_60s': unknown,
            'usage_complete_60s': unknown == 0,
        }


# =============================================================================
# Request-Based Rate Limiter
# =============================================================================

class RequestRateLimiter:
    """
    Rate limiter for request counts.
    
    This limits the number of requests per time window.
    """
    
    def __init__(self, config: RateLimitConfig = None, name: str = "request_limiter"):
        self.config = config or RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=100,
            window_seconds=60.0,
            enabled=True,
        )
        self.name = name
        self._limiter = RateLimiter(self.config, name)
    
    def allow(self) -> bool:
        """Check if a request is allowed."""
        return self._limiter.allow()
    
    async def __aenter__(self) -> RequestRateLimiter:
        """Enter the request rate limiter context."""
        await self._limiter.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the request rate limiter context."""
        await self._limiter.__aexit__(exc_type, exc_val, exc_tb)
    
    def reset(self) -> None:
        """Reset the request rate limiter."""
        self._limiter.reset()
    
    def get_stats(self) -> RateLimitStats:
        """Get request rate limiter statistics."""
        return self._limiter.get_stats()


# =============================================================================
# Combined Rate Limiter
# =============================================================================

class CombinedRateLimiter:
    """
    Combined rate limiter that uses both token-based and request-based limiting.
    
    A request is only allowed if both the token limit and request limit allow it.
    """
    
    def __init__(
        self,
        token_config: RateLimitConfig = None,
        request_config: RateLimitConfig = None,
        name: str = "combined_limiter"
    ):
        self.token_limiter = TokenRateLimiter(token_config, f"{name}_tokens")
        self.request_limiter = RequestRateLimiter(request_config, f"{name}_requests")
        self.name = name
    
    def allow(self, estimated_tokens: int = None) -> bool:
        """
        Check if a request is allowed.
        
        Args:
            estimated_tokens: Estimated tokens for this request
            
        Returns:
            True if both token and request limits allow it, False otherwise
        """
        return (self.token_limiter.allow(estimated_tokens) and 
                self.request_limiter.allow())
    
    async def __aenter__(self) -> CombinedRateLimiter:
        """Enter the combined rate limiter context."""
        async with self.token_limiter:
            async with self.request_limiter:
                return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the combined rate limiter context."""
        pass
    
    async def call(self, func: Callable, estimated_tokens: int = None, *args, **kwargs) -> Any:
        """
        Execute a function within the combined rate limiter.
        
        Args:
            func: The async function to call
            estimated_tokens: Estimated tokens for this request
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function call
        """
        async with self:
            return await func(*args, **kwargs)
    
    def record_usage(self, prompt_tokens: int | None, completion_tokens: int | None) -> None:
        """Record token usage for a request."""
        self.token_limiter.record_usage(prompt_tokens, completion_tokens)
    
    def reset(self) -> None:
        """Reset both rate limiters."""
        self.token_limiter.reset()
        self.request_limiter.reset()
    
    def get_stats(self) -> dict:
        """Get combined rate limiter statistics."""
        return {
            'token_limiter': self.token_limiter.get_stats(),
            'request_limiter': self.request_limiter.get_stats(),
        }


# =============================================================================
# Global Rate Limiter Management
# =============================================================================

class RateLimiterRegistry:
    """
    Registry for managing multiple rate limiters.
    
    This allows centralized configuration and monitoring of rate limiters
    for different services or endpoints.
    """
    
    def __init__(self):
        self._limiters: dict[str, RateLimiter] = {}
        # The model-call pacer's shipped values (see pacer_config); get_token_limiter
        # hands this to "ollama" unless ollama.rate_limit replaces it.
        self._default_token_config = pacer_config()
        self._default_request_config = RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=100,
            window_seconds=60.0,
            enabled=True,
        )
    
    def get_token_limiter(self, name: str, config: RateLimitConfig = None) -> TokenRateLimiter:
        """Get or create a token rate limiter."""
        key = f"token:{name}"
        if key not in self._limiters:
            self._limiters[key] = TokenRateLimiter(
                config or self._default_token_config, name
            )
        return self._limiters[key]
    
    def get_request_limiter(self, name: str, config: RateLimitConfig = None) -> RequestRateLimiter:
        """Get or create a request rate limiter."""
        key = f"request:{name}"
        if key not in self._limiters:
            self._limiters[key] = RequestRateLimiter(
                config or self._default_request_config, name
            )
        return self._limiters[key]
    
    def get_combined_limiter(self, name: str, token_config: RateLimitConfig = None, request_config: RateLimitConfig = None) -> CombinedRateLimiter:
        """Get or create a combined rate limiter."""
        key = f"combined:{name}"
        if key not in self._limiters:
            self._limiters[key] = CombinedRateLimiter(
                token_config or self._default_token_config,
                request_config or self._default_request_config,
                name
            )
        return self._limiters[key]
    
    def get_all_stats(self) -> dict[str, dict]:
        """Get statistics for all registered rate limiters."""
        return {name: limiter.get_stats() for name, limiter in self._limiters.items()}
    
    def reset_all(self) -> None:
        """Reset all rate limiters."""
        for limiter in self._limiters.values():
            limiter.reset()
    
    def set_default_token_config(self, config: RateLimitConfig) -> None:
        """Set the default token rate limiter configuration."""
        self._default_token_config = config
    
    def set_default_request_config(self, config: RateLimitConfig) -> None:
        """Set the default request rate limiter configuration."""
        self._default_request_config = config


# =============================================================================
# The model-call pacer
# =============================================================================
#
# Every OllamaClient enters the same process-wide token limiter,
# get_token_limiter(PACER_NAME), before each model-call attempt. Each call costs
# PACER_TOKENS_PER_CALL tokens whatever its size, so the bucket counts calls:
# `burst_calls` may start at once, then `calls_per_minute` refill. The shipped
# values (PACER_DEFAULTS, the ones this limiter has always had) are a 10-call
# burst, then one call every 6 s. `ollama.rate_limit` in config sets them
# (OllamaClient applies it, see ollama_client.parse_rate_limit). A call not
# admitted within `max_wait_seconds` raises RateLimitWaitExceeded, unsent.

PACER_NAME = "ollama"
PACER_TOKENS_PER_CALL = 100
PACER_DEFAULTS = {"enabled": True, "burst_calls": 10, "calls_per_minute": 10.0,
                  "max_wait_seconds": 300.0}
# The process-lifetime counters pacer_state reports; a run's share is the
# difference between its finish and start values.
PACER_COUNTERS = ("admitted", "waited", "wait_seconds_total", "timed_out")


def pacer_config(*, enabled: bool = PACER_DEFAULTS["enabled"],
                 burst_calls: int = PACER_DEFAULTS["burst_calls"],
                 calls_per_minute: float = PACER_DEFAULTS["calls_per_minute"],
                 max_wait_seconds: float = PACER_DEFAULTS["max_wait_seconds"]) -> RateLimitConfig:
    """The pacer's token-bucket config for settings given in calls."""
    return RateLimitConfig(
        strategy=RateLimitStrategy.TOKEN_BUCKET,
        tokens_per_second=calls_per_minute * PACER_TOKENS_PER_CALL / 60.0,
        max_tokens=burst_calls * PACER_TOKENS_PER_CALL,
        tokens_per_request=PACER_TOKENS_PER_CALL,
        enabled=enabled,
        max_wait_seconds=max_wait_seconds,
    )


def configure_pacer(config: RateLimitConfig) -> TokenRateLimiter:
    """Apply `config` to the shared pacer (created if absent) and return it."""
    limiter = get_token_limiter(PACER_NAME)
    limiter.reconfigure(config)
    return limiter


def _plain(value: float) -> float | int:
    value = round(value, 6)
    return int(value) if value == int(value) else value


def pacer_state() -> dict:
    """The pacer's effective settings, in calls, and its process-lifetime counters
    (admitted calls, calls that waited, their summed and longest wait, calls
    refused at max_wait_seconds), for the run manifest. Read off the live
    limiter, so it shows what paced the calls, not what a config file says."""
    limiter = get_token_limiter(PACER_NAME)
    cfg = limiter.config
    per_call = cfg.tokens_per_request or 1
    stats = limiter._limiter.get_stats()
    return {
        "enabled": cfg.enabled,
        "burst_calls": _plain(cfg.max_tokens / per_call),
        "calls_per_minute": _plain(cfg.tokens_per_second * 60.0 / per_call),
        "max_wait_seconds": cfg.max_wait_seconds,
        "poll_seconds": POLL_SECONDS,
        "admitted": stats.allowed,
        "waited": stats.waited,
        "wait_seconds_total": round(stats.wait_seconds_total, 3),
        "wait_seconds_max": round(stats.wait_seconds_max, 3),
        "timed_out": stats.timed_out,
    }


# Global registry instance
_registry: Optional[RateLimiterRegistry] = None


def get_registry() -> RateLimiterRegistry:
    """Get the global rate limiter registry."""
    global _registry
    if _registry is None:
        _registry = RateLimiterRegistry()
    return _registry


def get_token_limiter(name: str = "default", config: RateLimitConfig = None) -> TokenRateLimiter:
    """Get a token rate limiter from the global registry."""
    return get_registry().get_token_limiter(name, config)


def get_request_limiter(name: str = "default", config: RateLimitConfig = None) -> RequestRateLimiter:
    """Get a request rate limiter from the global registry."""
    return get_registry().get_request_limiter(name, config)


def get_combined_limiter(name: str = "default", token_config: RateLimitConfig = None, request_config: RateLimitConfig = None) -> CombinedRateLimiter:
    """Get a combined rate limiter from the global registry."""
    return get_registry().get_combined_limiter(name, token_config, request_config)
