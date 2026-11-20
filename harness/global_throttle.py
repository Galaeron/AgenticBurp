"""
Global outbound-request throttle.

A single process-wide ceiling on how fast the harness sends requests to a
TARGET -- across every active path at once: the validators (CORS, sqlmap's
own excepted, recon, web-cache, etc.), active verification, autonomous
scope discovery, and (once it exists) the iterative agent loop. Unlike
rate_limiter.py, which paces Ollama/model calls, this paces the traffic the
harness aims at the application under test.

Why global, not per-validator: an engagement's real blast radius is the
aggregate request rate hitting the target, not any one component's rate.
Five agents and three validators each "politely" capped at 10 req/s still add
up to 80 req/s at the target. The tester sets one number -- a global ceiling --
and every outbound path draws from the same bucket.

The limiter BLOCKS (awaits) rather than rejecting: a throttled caller waits
its turn, so behavior is "slower", never "requests silently dropped". A rate
of 0 (or None) means unlimited -- the throttle is off and acquire() returns
immediately, so the default costs nothing.

Async token bucket, serialized by an asyncio.Lock. Configure once (from
config / the Burp setting); every send site does `await throttle.acquire()`
immediately before it sends.

ARC-3: the same configured rate is also enforced PER TARGET ORIGIN inside
TargetTransport._execute (`acquire_origin`), so every transport send -- from any
run, any concurrent job, any caller that never calls acquire() itself -- draws
from one process-wide bucket per origin. The caller-side acquire() calls stay
(they still pace the paths that have not moved onto the transport); a transport
send that already waited there passes the origin bucket with little or no wait.
Every rate change is kept in a bounded change log (`changes`) that the run
manifest copies, with who set it ("config", "settings", ...).
"""
from __future__ import annotations
import asyncio
import collections
import contextlib
import contextvars
import math
import threading
import time
from dataclasses import dataclass

# ARC-3: validators whose point is precise, intentional concurrency (a race burst,
# a request-smuggling pair, a TOCTOU write burst). Their sends are CHARGED to the
# origin bucket but not delayed by it, so a burst still lands together and the
# traffic after it waits off the debt: the origin's sustained rate holds. The gate's
# authorize_burst (validators.max_burst_size) bounds each burst.
BURST_CAPABILITIES = frozenset({"race_condition_validator",
                                "http_request_smuggling_validator", "toctou"})
_MAX_CHANGES = 200      # throttle change events kept for run manifests
_MAX_ORIGINS = 1024     # origin buckets kept before idle (full) ones are pruned

# Sends inside `unpaced()` skip the origin bucket (the leg self-test's disposable
# loopback fixture). Context-local, so a concurrent real run is never affected.
_UNPACED: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "global_throttle_unpaced", default=False)


@contextlib.contextmanager
def unpaced():
    """Exempt sends made in this context (and tasks it starts) from origin pacing."""
    token = _UNPACED.set(True)
    try:
        yield
    finally:
        _UNPACED.reset(token)


@dataclass
class _ThrottleStats:
    acquired: int = 0
    total_wait_s: float = 0.0
    max_wait_s: float = 0.0


class GlobalRequestThrottle:
    """Process-wide blocking token bucket for outbound target requests."""

    def __init__(self) -> None:
        self._rate: float = 0.0          # tokens (requests) per second; 0 = unlimited
        self._burst: float = 0.0         # bucket capacity
        self._tokens: float = 0.0
        self._last: float = time.monotonic()
        self._lock = asyncio.Lock()
        self._stats = _ThrottleStats()
        # ARC-3 per-origin buckets: origin -> [tokens, last refill]. A threading lock
        # guards them and is never held across an await, so the buckets are shared
        # by every event loop and thread in the process.
        self._origins: dict[str, list[float]] = {}
        self._origin_lock = threading.Lock()
        self._origin_stats = {"acquired": 0, "paced": 0, "burst_charged": 0,
                              "total_wait_s": 0.0, "max_wait_s": 0.0}
        self._changes: collections.deque = collections.deque(maxlen=_MAX_CHANGES)
        self._set_by: dict = {"source": "default", "at": None}

    def configure(self, max_requests_per_second: float | None, burst: float | None = None,
                  *, source: str = "config", detail: dict | None = None) -> None:
        """Set the global ceiling. `max_requests_per_second` <= 0 or None turns
        the throttle OFF (unlimited). `burst` defaults to one second's worth of
        capacity (at least 1) so a short cluster of near-simultaneous callers
        isn't serialized more strictly than the sustained rate requires.
        `source` says who set it ("config", "settings"); a change of rate or
        burst is logged with it and `detail` for the run manifest (ARC-3)."""
        rate = float(max_requests_per_second or 0.0)
        if not math.isfinite(rate) or (burst is not None and not math.isfinite(float(burst))):
            raise ValueError("throttle rate and burst must be finite numbers")
        previous = (self._rate, self._burst)
        self._rate = max(0.0, rate)
        if self._rate <= 0.0:
            self._burst = 0.0
            self._tokens = 0.0
        else:
            self._burst = float(burst) if burst and burst > 0 else max(1.0, self._rate)
            # Start full so the first burst isn't penalized.
            self._tokens = self._burst
            self._last = time.monotonic()
        with self._origin_lock:
            if self._rate <= 0.0:
                self._origins.clear()
            else:   # a lower burst caps what an origin may still spend at once
                for bucket in self._origins.values():
                    bucket[0] = min(bucket[0], self._burst)
        if (self._rate, self._burst) != previous:
            event = {"at": time.time(), "source": str(source or "unknown"),
                     "rate_per_second": self._rate, "burst": self._burst,
                     "previous_rate_per_second": previous[0], "previous_burst": previous[1],
                     **(detail or {})}
            self._changes.append(event)
            self._set_by = {"source": event["source"], "at": event["at"]}

    @property
    def enabled(self) -> bool:
        return self._rate > 0.0

    def _refill(self, now: float) -> None:
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last = now

    async def acquire(self) -> None:
        """Block until one request slot is available, then consume it. No-op
        (returns immediately) when the throttle is disabled."""
        if self._rate <= 0.0:
            return
        waited = 0.0
        async with self._lock:
            while True:
                now = time.monotonic()
                self._refill(now)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._stats.acquired += 1
                    self._stats.total_wait_s += waited
                    self._stats.max_wait_s = max(self._stats.max_wait_s, waited)
                    return
                # Sleep exactly until the next whole token accrues.
                deficit = 1.0 - self._tokens
                sleep_for = deficit / self._rate
                waited += sleep_for
                await asyncio.sleep(sleep_for)

    async def acquire_origin(self, origin: str, *, capability: str = "") -> float:
        """ARC-3: take one send slot from `origin`'s process-wide bucket, waiting
        until it accrues; returns the seconds waited. No-op while the throttle is
        off, for an empty origin, or inside `unpaced()`. A BURST_CAPABILITIES send
        is charged without waiting. The slot is reserved under a threading lock
        (tokens may go negative: each waiter's turn is fixed when it arrives), and
        the wait happens outside it, so concurrent jobs on any loop share one pace."""
        if self._rate <= 0.0 or not origin or _UNPACED.get():
            return 0.0
        charge_only = capability in BURST_CAPABILITIES
        with self._origin_lock:
            rate, capacity = self._rate, self._burst
            if rate <= 0.0:
                return 0.0
            now = time.monotonic()
            bucket = self._origins.get(origin)
            if bucket is None:
                if len(self._origins) >= _MAX_ORIGINS:
                    self._prune_origins(now, rate, capacity)
                bucket = self._origins[origin] = [capacity, now]
            elif now > bucket[1]:
                bucket[0] = min(capacity, bucket[0] + (now - bucket[1]) * rate)
                bucket[1] = now
            bucket[0] -= 1.0
            wait = 0.0 if bucket[0] >= 0.0 or charge_only else -bucket[0] / rate
            stats = self._origin_stats
            stats["acquired"] += 1
            stats["burst_charged"] += int(charge_only)
            if wait > 0.0:
                stats["paced"] += 1
                stats["total_wait_s"] += wait
                stats["max_wait_s"] = max(stats["max_wait_s"], wait)
        if wait > 0.0:
            await asyncio.sleep(wait)
        return wait

    def _prune_origins(self, now: float, rate: float, capacity: float) -> None:
        """Drop buckets that have refilled to capacity (indistinguishable from new)."""
        for origin in [o for o, (tokens, last) in self._origins.items()
                       if tokens + (now - last) * rate >= capacity]:
            del self._origins[origin]

    def changes(self, since: float | None = None) -> list[dict]:
        """Logged rate changes (oldest first), those at or after `since` if given."""
        return [dict(e) for e in list(self._changes) if since is None or e["at"] >= since]

    def audit_state(self) -> dict:
        """The live setting and who set it last: what a run manifest records."""
        return {"enabled": self.enabled, "rate_per_second": self._rate, "burst": self._burst,
                "enforced": "per target origin in TargetTransport, shared by every job",
                "set_by": dict(self._set_by)}

    def stats(self) -> dict:
        with self._origin_lock:
            per_origin = {**self._origin_stats, "origins": len(self._origins)}
        per_origin["total_wait_s"] = round(per_origin["total_wait_s"], 3)
        per_origin["max_wait_s"] = round(per_origin["max_wait_s"], 3)
        return {
            "enabled": self.enabled,
            "rate_per_second": self._rate,
            "burst": self._burst,
            "acquired": self._stats.acquired,
            "total_wait_s": round(self._stats.total_wait_s, 3),
            "max_wait_s": round(self._stats.max_wait_s, 3),
            "per_origin": per_origin,
            "set_by": dict(self._set_by),
        }


# The process-wide singleton every outbound send site shares.
throttle = GlobalRequestThrottle()


async def acquire() -> None:
    """Module-level convenience: `await global_throttle.acquire()`."""
    await throttle.acquire()


async def acquire_origin(origin: str, *, capability: str = "") -> float:
    """Module-level convenience for TargetTransport: one slot from `origin`'s bucket."""
    return await throttle.acquire_origin(origin, capability=capability)


def configure(max_requests_per_second: float | None, burst: float | None = None,
              *, source: str = "config", detail: dict | None = None) -> None:
    throttle.configure(max_requests_per_second, burst, source=source, detail=detail)
