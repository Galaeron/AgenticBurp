"""SC-13: provider composition + one unified cost/latency trace through the
existing Provider protocol, consumed by the run ledger (harness.effort).

Upstream's borrowable idea is a provider interface + per-role routing + a
metering wrapper. AgenticVibe already has the provider interface
(:class:`harness.llm_provider.Provider`) and a real budget/ledger
(:mod:`harness.effort`, with SC-8 atomic reservations). This module supplies the
missing composition layer WITHOUT a parallel abstraction:

* :func:`traced_call` -- the single trace path. It reserves budget (SC-8
  ``reserve``), invokes ``provider.chat_json`` with bounded retries, measures
  latency, then settles the reservation with the REAL usage (``commit``) on
  success or refunds it (``release``) on failure. Every call -- ok, error, or
  streamed -- lands in the run ledger as one enriched ``CallRecord`` carrying
  provider / model / prompt-version / usage / retries / latency / outcome and
  case/run identity. A hard-budget reservation that cannot be admitted returns a
  ``budget_blocked`` outcome and never touches the provider, so concurrent
  reservations cannot exceed the SC-8 hard cap.
* :class:`TracingProvider` -- a drop-in ``Provider`` that routes its own
  ``chat_json`` through ``traced_call``. Wrapping an existing provider adds the
  trace at a call site with no logic change (it is still ``.chat_json(...)``).
* :class:`ProviderRouter` -- optional per-CallKind routing (cheap classify vs
  deeper reasoning). The MECHANISM is here and off by default (no routes ->
  everything uses the default); whether a given routing WINS is an OWNER/LIVE
  measurement (fixed cases at equal total budget) and is deliberately not
  asserted here.

Nothing in the default pipeline wraps its provider in this yet, so importing
this module sends no traffic and changes no verdict; live adoption is a separate
step. Remote use still goes through llm_provider.build_provider, which keeps the
explicit-opt-in + redaction contract.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from harness.effort import CallKind, CallRecord, EffortBudget
from harness.llm_provider import Provider
from harness.ollama_client import OllamaResult


class ProviderBudgetError(RuntimeError):
    """Raised by TracingProvider.chat_json when a hard budget refuses the
    reservation, so a drop-in caller that expects an exception on failure still
    sees one instead of a silently skipped call."""


@dataclass
class TracedOutcome:
    """Result of one traced provider call. ``ok`` is True only when the provider
    returned a result within the retry budget; a budget block or an exhausted
    retry is ``ok=False`` with ``outcome`` telling them apart."""
    ok: bool
    outcome: str  # "ok" | "error" | "budget_blocked"
    result: OllamaResult | None = None
    record: CallRecord | None = None
    error: str = ""
    reason: str = ""  # budget reason when outcome == "budget_blocked"
    retries: int = 0
    latency_ms: float = 0.0
    exception: BaseException | None = None


def _provider_name(provider) -> str:
    return str(getattr(provider, "name", None) or provider.__class__.__name__)


async def traced_call(
    provider: Provider, budget: EffortBudget, *, kind: CallKind, model: str,
    system_prompt: str, user_prompt: str, temperature: float = 0.1,
    prompt_version: str = "", case_ref: str = "", run_id: str = "",
    estimate: int | None = None, max_retries: int = 0, retry_on=(Exception,),
    clock=time.monotonic, streamed: bool | None = None, **kw,
) -> TracedOutcome:
    """Run one provider call through the budget + trace. See module docstring.

    ``budget`` with ``total_tokens=None`` is a pure tracer (reserve always
    admits); with a hard cap it enforces SC-8 admission. ``estimate`` defaults to
    the ledger's calibrated average for ``kind``. ``max_retries`` is the number of
    RETRIES after the first attempt; only exceptions in ``retry_on`` are retried,
    and any other exception propagates after the reservation is refunded."""
    est = int(estimate) if estimate is not None else max(1, round(budget.ledger.average_tokens(kind)))
    provider_name = _provider_name(provider)

    admitted, reason = budget.reserve(est)
    if not admitted:
        return TracedOutcome(ok=False, outcome="budget_blocked", reason=reason)

    settled = False
    attempt = 0
    result: OllamaResult | None = None
    last_exc: BaseException | None = None
    start = clock()
    try:
        while True:
            try:
                result = await provider.chat_json(
                    model, system_prompt, user_prompt, temperature=temperature, **kw)
                break
            except retry_on as exc:  # noqa: B012 -- deliberate bounded retry
                last_exc = exc
                if attempt >= max_retries:
                    result = None
                    break
                attempt += 1
        latency_ms = (clock() - start) * 1000.0

        if result is not None:
            is_streamed = bool(getattr(result, "streamed", False)) if streamed is None else bool(streamed)
            record = budget.commit(
                kind, model, int(result.prompt_tokens), int(result.completion_tokens),
                reserved=est, provider=provider_name, prompt_version=prompt_version,
                latency_ms=latency_ms, retries=attempt, outcome="ok",
                streamed=is_streamed, case_ref=case_ref, run_id=run_id)
            settled = True
            return TracedOutcome(ok=True, outcome="ok", result=result, record=record,
                                 retries=attempt, latency_ms=latency_ms)

        # Retries exhausted on a retry_on exception: refund the reservation but
        # still account the failed model path as a zero-usage error trace.
        budget.release(est)
        record = budget.record(
            kind, model, 0, 0, provider=provider_name, prompt_version=prompt_version,
            latency_ms=latency_ms, retries=attempt, outcome="error",
            case_ref=case_ref, run_id=run_id)
        settled = True
        return TracedOutcome(ok=False, outcome="error", error=str(last_exc), record=record,
                             retries=attempt, latency_ms=latency_ms, exception=last_exc)
    finally:
        if not settled:
            # A non-retryable exception is propagating out; don't leak the reservation.
            budget.release(est)


class TracingProvider:
    """A drop-in :class:`Provider` that traces every ``chat_json`` through the
    budget/ledger. Wrap any provider to add the SC-13 trace at a call site with
    no other change; ``chat_json_metered`` is aliased so it also replaces a bare
    OllamaClient/OllamaProvider."""

    def __init__(self, inner: Provider, budget: EffortBudget, *, kind: CallKind,
                 prompt_version: str = "", case_ref: str = "", run_id: str = "",
                 estimate: int | None = None, max_retries: int = 0,
                 retry_on=(Exception,), clock=time.monotonic):
        self._inner = inner
        self._budget = budget
        self._kind = kind
        self._prompt_version = prompt_version
        self._case_ref = case_ref
        self._run_id = run_id
        self._estimate = estimate
        self._max_retries = max_retries
        self._retry_on = retry_on
        self._clock = clock

    @property
    def name(self) -> str:
        return _provider_name(self._inner)

    async def chat_json(self, model: str, system_prompt: str, user_prompt: str,
                        temperature: float = 0.1, **kw) -> OllamaResult:
        outcome = await traced_call(
            self._inner, self._budget, kind=self._kind, model=model,
            system_prompt=system_prompt, user_prompt=user_prompt, temperature=temperature,
            prompt_version=self._prompt_version, case_ref=self._case_ref, run_id=self._run_id,
            estimate=self._estimate, max_retries=self._max_retries, retry_on=self._retry_on,
            clock=self._clock, **kw)
        if outcome.ok:
            return outcome.result
        if outcome.outcome == "budget_blocked":
            raise ProviderBudgetError(outcome.reason)
        # Failed call: the trace + refund already happened; behave like the inner
        # provider by re-raising the original error.
        raise outcome.exception if outcome.exception is not None else RuntimeError(outcome.error)

    chat_json_metered = chat_json


@dataclass(frozen=True)
class RouteChoice:
    provider: Provider
    model: str


@dataclass
class ProviderRouter:
    """Optional per-CallKind routing between a cheap classify path and a deeper
    reasoning path. Off by default: with no ``routes`` every kind resolves to
    ``default``. The routing mechanism ships here; whether a routing wins is an
    OWNER/LIVE measurement (fixed cases at equal total budget) -- not asserted."""
    default: RouteChoice
    routes: dict = field(default_factory=dict)  # CallKind -> RouteChoice

    @property
    def enabled(self) -> bool:
        return bool(self.routes)

    def route(self, kind: CallKind) -> RouteChoice:
        return self.routes.get(kind, self.default)


async def traced_route_call(router: ProviderRouter, budget: EffortBudget, *,
                            kind: CallKind, system_prompt: str, user_prompt: str,
                            **kw) -> TracedOutcome:
    """Resolve the route for ``kind`` and run it through :func:`traced_call`. The
    chosen provider/model is recorded in the trace like any other call, so the
    run ledger shows exactly which path each call took."""
    choice = router.route(kind)
    return await traced_call(choice.provider, budget, kind=kind, model=choice.model,
                             system_prompt=system_prompt, user_prompt=user_prompt, **kw)
