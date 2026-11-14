"""
When the local model last worked, and for whom.

r9 and r10 (one local llama.cpp slot): the worklist's model-driven probes were done by
about hour 3.7, and the rest of its slice (about 7.8 h of `phase_slices`) was validator
legs that send requests and make no model call. Model calls stayed at 695 from hour
3.74 while target requests grew by about 24k an hour. Nothing could tell that the
model was idle, so nothing used it.

`ACTIVITY` counts the model calls in flight and when each caller's last call ended.
`OllamaClient._chat`, which every model call in the harness goes through, wraps each
call in `begin()` / `end()`. A caller is the `owner` set in its context (`owned_by`);
calls made with no owner set are the run's own foreground work. A background worker
sets its own owner token, so `idle_for(exclude=token)` is how long the model has been
free of everyone else's calls (0 while one is in flight, or queued for the one slot).

Bookkeeping only: it sends nothing, changes no call and is process-wide, like the one
model it describes. A call made through another provider (a cloud model) is not seen.
"""
from __future__ import annotations

import contextlib
import contextvars
import time

__all__ = ["ACTIVITY", "ModelActivity", "owned_by", "current_owner"]

_OWNER: contextvars.ContextVar[object | None] = contextvars.ContextVar(
    "model_activity_owner", default=None)
_NOBODY = object()   # "exclude no owner"; None is the foreground's owner


def current_owner():
    return _OWNER.get()


@contextlib.contextmanager
def owned_by(owner):
    """Model calls made inside this block (and in tasks started from it) are `owner`'s."""
    token = _OWNER.set(owner)
    try:
        yield
    finally:
        _OWNER.reset(token)


class ModelActivity:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._in_flight: dict = {}
        self._last_end: dict = {}

    def begin(self):
        """A model call starts (queued or sent). Returns the owner to pass to end()."""
        owner = _OWNER.get()
        self._in_flight[owner] = self._in_flight.get(owner, 0) + 1
        return owner

    def end(self, owner) -> None:
        count = self._in_flight.get(owner, 0) - 1
        if count > 0:
            self._in_flight[owner] = count
        else:
            self._in_flight.pop(owner, None)
        self._last_end[owner] = self.clock()

    @contextlib.contextmanager
    def call(self):
        owner = self.begin()
        try:
            yield
        finally:
            self.end(owner)

    def in_flight(self, exclude=_NOBODY) -> int:
        """Model calls in flight, but `exclude`'s (by default every call counts)."""
        return sum(n for owner, n in self._in_flight.items() if owner is not exclude)

    def idle_for(self, *, exclude=_NOBODY, since: float | None = None) -> float:
        """Seconds the model has had no call but `exclude`'s: 0 while another call is in
        flight, else the time since the last one ended or since `since`, whichever is
        later (infinite when there is neither)."""
        if self.in_flight(exclude=exclude):
            return 0.0
        ends = [t for owner, t in self._last_end.items() if owner is not exclude]
        if since is not None:
            ends.append(since)
        if not ends:
            return float("inf")
        return max(0.0, self.clock() - max(ends))

    def forget(self, owner) -> None:
        """Drop a finished background owner's record (never the foreground's)."""
        if owner is not None and not self._in_flight.get(owner):
            self._last_end.pop(owner, None)


ACTIVITY = ModelActivity()
