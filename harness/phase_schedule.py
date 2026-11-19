"""
Phase time-slices under the engagement's wall-clock deadline.

In the 8-hour Juice Shop run (2026-11-03) the worklist took 2 h 20 min and capture
review then held the rest of the run (about 2.8 min per capture, uncapped), so the
chain rounds -- leaked-credential re-crawl, composed chains -- never started.
`investigation_seconds` bounded the engagement as a whole but every phase was free
to spend all of what was left.

`engagement.phase_slices` gives each phase a share of the time REMAINING when it
begins: phase P gets `remaining * share[P] / (share[P] + shares of the phases after
it)`. Time a phase leaves unused therefore rolls forward to the later ones, and the
last sliced phase gets everything up to the deadline. Phases without a share are not
sliced. An explicit per-phase cap (capture_review_seconds) still applies: the phase
stops at whichever comes first.

`final_passes` is a share for the passes after the chain rounds: second-order
confirmation, the coverage drive, the server-error lead pass and the retry rounds.
Nothing asks for its deadline; it only keeps that share out of the earlier phases.
Without it the chain rounds, the last sliced phase, are granted everything up to the
deadline. The server-error pass, which starts no lead confirmation past the
deadline, then dispatches nothing (r6, job a674352e19b6, ran its chain rounds to the
deadline and never reached the later passes).

The capture_review slice bounds how long the engagement WAITS for the review. With
`engagement.review_overlap` (on by default) a model-bound review its slice cuts short
goes on in the background beside the request-bound passes after it, up to its own
deadline (harness/review_overlap.py); with it off the review stops at its slice.
With `engagement.review_on_idle_seconds` (0, off, by default) the review can also
start earlier, inside the worklist and recrawl slices, once the model has sat idle
that long (IdleReview); the capture_review slice then takes only what it left.

R11-4: `rollover()` is the slack the last sliced phase left: the time from now to
the end of its slice. r11 (2026-11-18) granted the chain rounds 3 h and they used
0.4 s; the coverage drive after them kept its fixed `coverage_drive_seconds` and
stopped with 283 legs not attempted. With `engagement.coverage_drive_rollover` the
drive is given that slack on top of its own seconds (orchestrator_chain).

OFF by default: with no `phase_slices` (or no `investigation_seconds`, the deadline
the slices divide) every phase keeps exactly today's deadline.
"""
from __future__ import annotations

import time

__all__ = ["PHASES", "PhaseSchedule"]

# The sliceable phases of investigate_engagement, in run order. `final_passes` is the
# time after the chain rounds (see the module docstring): it is reserved, never gated.
PHASES = ("worklist", "recrawl", "capture_review", "chain_rounds", "final_passes")


class PhaseSchedule:
    def __init__(self, deadline: float | None, shares: dict | None, *, clock=time.monotonic):
        self.deadline = deadline
        self.clock = clock
        self.shares = {}
        for phase, share in (shares or {}).items():
            try:
                value = float(share)
            except (TypeError, ValueError):
                continue
            if phase in PHASES and value > 0:
                self.shares[phase] = value
        self.granted: dict[str, float] = {}
        self._ends: dict[str, float] = {}   # phase -> the clock value its slice ends at

    @classmethod
    def from_config(cls, config: dict | None, deadline: float | None, **kwargs) -> "PhaseSchedule":
        raw = ((config or {}).get("engagement", {}) or {}).get("phase_slices") or {}
        return cls(deadline, raw if isinstance(raw, dict) else {}, **kwargs)

    @property
    def active(self) -> bool:
        return self.deadline is not None and bool(self.shares)

    def deadline_for(self, phase: str, explicit: float | None = None) -> float | None:
        """The deadline `phase` must stop starting work at, decided when it begins.
        `explicit` is the phase's own cap (or the overall deadline); the earlier of
        it and the slice wins. Inactive or unsliced: `explicit` unchanged."""
        if not self.active or phase not in self.shares:
            return explicit
        now = self.clock()
        remaining = max(0.0, self.deadline - now)
        later = sum(self.shares[p] for p in PHASES[PHASES.index(phase):] if p in self.shares)
        sliced = now + remaining * self.shares[phase] / later
        self.granted[phase] = round(sliced - now, 3)
        self._ends[phase] = sliced
        return sliced if explicit is None else min(sliced, explicit)

    def rollover(self) -> float:
        """Seconds the last sliced phase granted so far left unused: from now to the
        end of its slice (0 when it ran to its slice end, or nothing was sliced).
        Earlier phases' slack already went to the later sliced phases, because
        each slice is a share of the time left when it begins."""
        if not self.active:
            return 0.0
        last = next((p for p in reversed(PHASES) if p in self._ends), None)
        if last is None:
            return 0.0
        return max(0.0, self._ends[last] - self.clock())

    def report(self) -> dict:
        return {"shares": dict(self.shares), "granted_seconds": dict(self.granted)}
