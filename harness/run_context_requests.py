"""Typed request/outcome records and the ambient case/send-count scopes,
split from run_context.py (ARC-9). Import these names from harness.run_context.
"""
from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field

import httpx


# ---------------------------------------------------------------------------
# Typed request + outcome
# ---------------------------------------------------------------------------

@dataclass
class TypedRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None


@dataclass
class ExecutionOutcome:
    # ok | out_of_scope | blocked | budget_exhausted | cancelled | error, plus
    # session_expired | route_unavailable (E5a): refused unsent, like blocked.
    outcome: str
    status: int | None = None
    body: str = ""
    headers: dict = field(default_factory=dict)
    final_url: str = ""
    error: str = ""
    artifact: "evidence.ExchangeArtifact | None" = None

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"

    @property
    def executed(self) -> bool:
        """A real network send happened. A denied/blocked/out-of-scope attempt did
        NOT execute (and did not consume budget)."""
        return self.outcome in ("ok", "error")

    @property
    def artifact_id(self) -> str:
        """The exchange artifact this send recorded ("" when none was built)."""
        return getattr(self.artifact, "artifact_id", "") or ""

    # Response contract: `body` is the DECODED text (the transport already
    # undid Content-Encoding); `headers` are the ORIGINAL wire headers, kept
    # as-is for evidence. The raw wire bytes are not carried here.
    _FRAMING_HEADERS = ("content-encoding", "content-length", "transfer-encoding")

    def to_httpx_response(self, method: str, url: str) -> "httpx.Response":
        """Consumer view of an ok outcome: the decoded body with the framing
        headers that describe the wire bytes dropped, so httpx does not decode
        or length-check it a second time. Evidence keeps the original headers."""
        import httpx
        headers = {k: v for k, v in (self.headers or {}).items()
                   if k.lower() not in self._FRAMING_HEADERS}
        return httpx.Response(self.status or 0, headers=headers,
                              content=(self.body or "").encode("utf-8"),
                              request=httpx.Request(method, url),
                              extensions={"harness_artifact_id": self.artifact_id})


# Ticket 6 follow-up: the confirmation case a validator job runs for. The
# orchestrator enters it around one validator dispatch, so every send that job
# makes is recorded as a case-bound EXECUTION event (artifact id + redacted
# request/response blobs) without each validator threading a case_ref. Inside
# a scope it is the record's case (a validator's finding id is not a case). It
# binds that field only: the record's finding_ref and the gate's per-finding
# mutating ceiling (R16) stay keyed on the caller's own case_ref, as before, so
# per-finding reconstruction is unchanged; a caller with none files under the case.
_ambient_case_ref: "contextvars.ContextVar[str]" = contextvars.ContextVar(
    "harness_case_ref_ambient", default="")


# Batch 02: answered sends made inside a `count_sends()` block, across every
# TargetTransport and the tasks the block starts (the counters are shared
# lists, so a child task's increments reach the caller). Nested blocks each
# see their own sends.
_ambient_send_counters: "contextvars.ContextVar[tuple]" = contextvars.ContextVar(
    "harness_send_counters", default=())


@contextlib.contextmanager
def count_sends():
    """Yield a one-item list holding the answered sends made in this block."""
    counter = [0]
    token = _ambient_send_counters.set(_ambient_send_counters.get() + (counter,))
    try:
        yield counter
    finally:
        _ambient_send_counters.reset(token)


def current_case_ref() -> str:
    """The case id of the enclosing `case_scope`, or "" outside one."""
    return _ambient_case_ref.get()


@contextlib.contextmanager
def case_scope(case_ref: str):
    """Bind sends made in this block (and in tasks it starts) to `case_ref`."""
    token = _ambient_case_ref.set(case_ref or "")
    try:
        yield
    finally:
        _ambient_case_ref.reset(token)


# Bound last (run_context imports this module): read only at call time.
from harness import run_context as _rc  # noqa: E402
