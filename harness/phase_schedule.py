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

OFF by default: with no `phase_slices` (or no `investigation_seconds`, the deadline
the slices divide) every phase keeps exactly today's deadline.
"""
from __future__ import annotations

import time

__all__ = ["PHASES", "PhaseSchedule"]

# The sliceable phases of investigate_engagement, in run order.
PHASES = ("worklist", "recrawl", "capture_review", "chain_rounds")


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
        return sliced if explicit is None else min(sliced, explicit)

    def report(self) -> dict:
        return {"shares": dict(self.shares), "granted_seconds": dict(self.granted)}
