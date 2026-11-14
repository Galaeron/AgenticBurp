"""
Capture review alongside the request-bound phases of investigate_engagement.

r9 (20 h, one local model): the capture review is the model-bound phase; the chain
rounds, the coverage drive and the server-error pass after it are request-bound and
make no model call. Each phase was awaited in turn, so once the capture-review slice
(`engagement.phase_slices`) ran out, the captures it left waited for the retry rounds
while the model sat idle: hours 13-14 sent 24k and 30k requests and made no model
call, with 279 of 484 captures unreviewed (about 64 s each).

`ReviewOverlap` runs that review as a background task instead. The engagement waits
for it as long as the slice allows (`hold`), as before; when the slice ends with
captures left, the review keeps going while the chain rounds, second-order pass,
coverage drive and server-error pass send their requests, and the engagement stops
it (`drain`) before the retry rounds, which review what is still left. What it
reviews is unchanged: the same review_captured_exchanges call with the same seen set,
journal hooks, stats and error records, over the same captures, plus each chain
round's captures (`extend`) in the order the rounds produce them.

Bounds: the review's own deadline (capture_review_seconds, the investigation
deadline) is a hard one here -- a capture still being analyzed when it passes is
cancelled and stays unreviewed -- and every request the review's validators send
spends the same run request budget as before. `drain` lets the capture in flight
finish (never past that deadline), then the task is gone. `reaps_review_overlaps`
cancels and awaits any overlap the engagement leaves running when it returns early,
raises or is cancelled, so no task outlives the engagement.

ON by default (`engagement.review_overlap`), and only used when a model reviews the
captures and the slice would cut the review short of its own deadline; otherwise the
review runs inline exactly as before.
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import logging
import time
from collections import deque

log = logging.getLogger(__name__)

__all__ = ["ReviewOverlap", "reaps_review_overlaps", "review_uses_model", "enabled"]

DRAIN_REASON = "end of the request-bound phases"
ENGAGEMENT_END = "engagement end"
TIME_BUDGET = "capture review time budget"
LIMIT = "capture review limit"
NOTHING_LEFT = "nothing left to review"

# The overlaps started under the innermost reaps_review_overlaps call.
_LIVE: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "review_overlaps", default=None)


def enabled(config: dict | None) -> bool:
    return bool(((config or {}).get("engagement") or {}).get("review_overlap", True))


def review_uses_model(orch) -> bool:
    """True when analyze() has a model agent to call: only then is the review
    model-bound, and worth running beside the request-bound phases."""
    try:
        return bool(orch.agent_manager.get_enabled_agents())
    except Exception:
        return False


class ReviewOverlap:
    """One background capture review, fed batches of captures.

    `review(captured, *, deadline, should_stop, outcome_out)` is one
    review_captured_exchanges call over `captured` with everything else bound (state,
    seen set, stats, journal hooks). Batches are reviewed in order, each with its own
    call, as the inline review did; a batch cut by the review limit moves on to the
    next, a batch cut by the deadline or a stop ends the review."""

    def __init__(self, review, *, deadline: float | None, clock=time.monotonic):
        self._review = review
        self.deadline = deadline
        self.clock = clock
        self._batches: deque = deque()
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self._idle = asyncio.Event()
        self._stop_reason: str | None = None
        self.stopped_by: str | None = None
        self.batches = 0
        self.produced = 0
        self.reviewed = 0
        # True once hold() let the engagement go on with captures still to review.
        self.background = False
        self.error: str | None = None

    # -- life cycle -------------------------------------------------------------
    def start(self, captured) -> "ReviewOverlap":
        self._batches.append(captured)
        self._task = asyncio.create_task(self._run(), name="capture-review-overlap")
        live = _LIVE.get()
        if live is not None:
            live.append(self)
        return self

    @property
    def accepting(self) -> bool:
        """Still reviewing (or waiting for captures): extend() will be reviewed."""
        return self._task is not None and not self._task.done() and self._stop_reason is None

    def extend(self, captured) -> bool:
        if not self.accepting:
            return False
        self._batches.append(captured)
        self._idle.clear()
        self._wake.set()
        return True

    async def hold(self, until: float | None) -> bool:
        """Wait while the review runs, up to `until` (a clock value): the time the
        review had to itself before. True when it has nothing left to review (or has
        ended); False when `until` came first and it goes on in the background."""
        if self._task is None:
            return True
        waiters = {self._task, asyncio.ensure_future(self._idle.wait())}
        try:
            timeout = None if until is None else max(0.0, until - self.clock())
            await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters - {self._task}:
                waiter.cancel()
            await asyncio.gather(*(waiters - {self._task}), return_exceptions=True)
        done = self._task.done() or self._idle.is_set()
        if not done:
            self.background = True
            log.info("capture review: slice ended with captures left -- review continues "
                     "beside the request-bound phases")
        return done

    async def drain(self, reason: str = DRAIN_REASON) -> None:
        """Stop taking captures; let the one in flight finish (never past the
        deadline), then make sure the task is gone."""
        task = self._task
        if task is None:
            return
        if task.done():   # ended by itself (a bound, nothing left, an error)
            self._retrieve(task)
            return
        self._stop_reason = self._stop_reason or reason
        self._wake.set()
        timeout = None if self.deadline is None else max(0.0, self.deadline - self.clock())
        await asyncio.wait({task}, timeout=timeout)
        if not task.done():   # the worker's own timeout should have ended it; belt and braces
            task.cancel()
            await asyncio.wait({task})
        self._retrieve(task)

    async def aclose(self) -> None:
        """Cancel and await: for an engagement that ends with the review running."""
        task = self._task
        if task is None:
            return
        if not task.done():
            self._stop_reason = self._stop_reason or ENGAGEMENT_END
            task.cancel()
            await asyncio.wait({task})
        self._retrieve(task)

    def _retrieve(self, task) -> None:
        if task.cancelled():
            self.stopped_by = self.stopped_by or self._stop_reason or ENGAGEMENT_END
            return
        exc = task.exception()
        if exc is not None:
            self.error = f"{type(exc).__name__}: {exc}"

    # -- the worker -------------------------------------------------------------
    def _should_stop(self) -> str | None:
        return self._stop_reason

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            if self._stop_reason is not None:
                self.stopped_by = self.stopped_by or self._stop_reason
                return
            if not self._batches:
                self._idle.set()
                self._wake.clear()
                remaining = None if self.deadline is None else self.deadline - self.clock()
                if remaining is not None and remaining <= 0:
                    self.stopped_by = TIME_BUDGET
                    return
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=remaining)
                except TimeoutError:
                    self.stopped_by = NOTHING_LEFT
                    return
                continue
            self._idle.clear()
            captured = self._batches[0]
            outcome: dict = {}
            try:
                if self.deadline is None:
                    produced = await self._review(captured, deadline=None,
                                                  should_stop=self._should_stop,
                                                  outcome_out=outcome)
                else:
                    # A hard deadline: an analysis still running when it passes is
                    # cancelled (the review puts that capture back as unreviewed).
                    async with asyncio.timeout_at(loop.time() + self.deadline - self.clock()):
                        produced = await self._review(captured, deadline=self.deadline,
                                                      should_stop=self._should_stop,
                                                      outcome_out=outcome)
            except TimeoutError:
                self._count(outcome)
                self.stopped_by = TIME_BUDGET
                return
            self._count(outcome)
            self.batches += 1
            stopped = outcome.get("stopped_by")
            if stopped and stopped != LIMIT:
                self.stopped_by = stopped
                return
            self._batches.popleft()

    def _count(self, outcome: dict) -> None:
        self.reviewed += int(outcome.get("reviewed") or 0)
        self.produced += int(outcome.get("produced") or 0)

    def report(self) -> dict:
        return {"background": self.background, "reviewed": self.reviewed,
                "produced": self.produced, "batches": self.batches,
                "stopped_by": self.stopped_by,
                **({"error": self.error} if self.error else {})}


def reaps_review_overlaps(fn):
    """Decorate an async engagement so every ReviewOverlap started inside it is
    cancelled and awaited when it returns, raises or is cancelled."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        token = _LIVE.set([])
        try:
            return await fn(*args, **kwargs)
        finally:
            live = _LIVE.get() or []
            _LIVE.reset(token)
            for overlap in live:
                await overlap.aclose()
    return wrapper
