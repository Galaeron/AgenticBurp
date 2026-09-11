"""
TOCTOU privilege-escalation race leg (V19, WSTG-BUSL-07 / atomicity).

The distinction from the two legs it sits between:

  - race_condition_validator fires N concurrent copies and counts "clean
    successes", but never re-reads state -- it proves an operation succeeded more
    than once, not that a PRIVILEGE actually changed as a result.
  - sequence_validator sends ONE write and checks a privileged field persisted --
    it catches mass-assignment, but a single serialized write can't expose a
    check-then-WRITE race (the escalation only slips through when two requests
    interleave between the authorization check and the commit).

This leg is the interleaved-check-then-write differential:
  1. BASELINE read   -- GET the resource, record the authority fields (reusing the
                        sequence leg's authority-field detection so the two agree).
  2. CONCURRENT burst -- fire N genuinely-overlapping copies of the captured
                        state-changing request (asyncio.gather, like race_condition).
  3. VERIFY read     -- GET again; CONFIRM only when a privileged/authority field
                        FLIPPED to a privileged value that the baseline did not have
                        AND >= 2 of the concurrent requests came back a clean success.

Tying the confirmation to an independent re-read of the authority state (not just
a success count) is what makes this a privilege-escalation race rather than a
generic "succeeded twice", and deterministic rather than an agent narrating a
race. Fully code-built: no LLM composes the requests. The burst is authorised once
through the run's safety gate authorize_burst (needs allow_mutating_replay + a
raised max_burst_size), then fired through its executor. Standalone registry
callers retain the legacy direct-client compatibility path.
"""
from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import get_default_gate
from .base import Validator, ValidationResult
# reuse the sequence leg's authority-field machinery so routing/detection agree
from .sequence_validator import _PRIV_FIELDS, _AUTHORITY_RE, _walk, _is_priv, _present_privileged
from validators.sqlmap import _looks_like_json, _content_type_of

log = logging.getLogger("harness.validators.toctou")

# Rejection markers -- a burst response carrying one of these is NOT a clean
# success (mirrors race_condition's vocabulary).
import re
_REJECTION = re.compile(
    r"already|expired|invalid|insufficient|limit reached|too many|rate limit|"
    r"not found|forbidden|unauthorized|denied|error", re.IGNORECASE)


class ToctouValidator(Validator):
    name = "toctou"
    finding_classes = {"toctou", "time-of-check", "time of check", "toctou_privilege_escalation",
                       "time-of-check to time-of-use", "time of check to time of use",
                       "privilege escalation race", "race privilege escalation",
                       "priv esc race", "check-then-act", "check then act"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 burst_size: int = 12, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.burst_size = burst_size
        self.run_context = run_context

    def _json_object(self, body: str):
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            return None
        return obj if isinstance(obj, dict) else None

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        return (exchange.method or "").upper() in ("POST", "PUT", "PATCH")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "toctou", summary=why)

    def _not_confirmed(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "not_confirmed", "toctou", confidence=0.2,
                                confirmed=False, summary=why)

    async def _get_json(self, url, headers):
        if self.run_context is not None:
            from run_context import TypedRequest
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)
            result = await self.run_context.executor().execute(
                TypedRequest("GET", url, headers=request_headers),
                capability=self.name, session_ref=session_ref)
            if not result.ok:
                return result.status, None
            try:
                return result.status, json.loads(result.body or "")
            except (ValueError, TypeError):
                return result.status, None
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False,
                                     verify=False) as client:
            resp = await client.request("GET", url, headers=headers or None)
        try:
            return resp.status_code, json.loads(resp.text or "")
        except (ValueError, TypeError):
            return resp.status_code, None

    def _escalation_candidates(self, baseline: dict, base_body: dict) -> dict:
        """Privileged fields to attempt to set via the racing write: the canonical
        set not already privileged, plus authority-named fields the resource
        exposes but the request didn't set (same policy as sequence_validator)."""
        cands = {f: v for f, v in _PRIV_FIELDS.items() if not _is_priv(base_body.get(f), v)}
        for k, v in _walk(baseline):
            if k in _PRIV_FIELDS or k in base_body or not isinstance(k, str):
                continue
            if not _AUTHORITY_RE.search(k):
                continue
            if isinstance(v, bool) and v is not True:
                cands[k] = True
            elif isinstance(v, str) and not _is_priv(v, "admin"):
                cands[k] = "admin"
        return {f: v for f, v in cands.items() if not _present_privileged(baseline, f, v)}

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "").upper()

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}

        # 1. baseline read of the authority state.
        try:
            b_status, baseline = await self._get_json(exchange.url, headers)
        except httpx.HTTPError as e:
            return self._skip(f"baseline read failed: {e.__class__.__name__}")
        if not isinstance(baseline, dict):
            return self._skip(f"resource not readable as JSON for an authority differential "
                              f"(GET -> {b_status})")

        base_body = self._json_object(exchange.request_body or "") or {}
        cands = self._escalation_candidates(baseline, base_body)
        if not cands:
            return self._skip("no non-privileged authority field to race toward "
                              "(request/resource already privileged)")
        # Build the racing write body: inject the escalation candidates. Preserve
        # the captured content-type (json vs form).
        if _looks_like_json(exchange.request_body or "", _content_type_of(exchange)) or base_body:
            headers.setdefault("Content-Type", "application/json")
            content = json.dumps({**base_body, **cands})
        else:
            from urllib.parse import urlencode, parse_qsl
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            merged = dict(parse_qsl(exchange.request_body or "", keep_blank_values=True))
            merged.update({k: (str(v)) for k, v in cands.items()})
            content = urlencode(merged)

        # 2. authorise + fire the concurrent burst.
        gate = self.run_context.gate if self.run_context is not None else get_default_gate()
        decision = gate.authorize_burst(
            validator_name=self.name, method=method, url=exchange.url,
            requested_burst_size=self.burst_size, body=content)
        if not decision.allowed:
            return self._skip(f"burst not authorized by safety gate: {decision.reason}")
        n = decision.allowed_burst_size
        if n < 2:
            return self._skip(f"burst ceiling {n} < 2 -- raise validators.max_burst_size to test a "
                              f"check-then-write race (inconclusive)")

        async def fire_one():
            try:
                if self.run_context is not None:
                    from types import SimpleNamespace
                    from run_context import TypedRequest
                    from .transport import bind_session
                    session_ref, request_headers = bind_session(self.run_context, headers)
                    result = await self.run_context.executor().execute(
                        TypedRequest(method, exchange.url, headers=request_headers, body=content),
                        capability=self.name, session_ref=session_ref)
                    if not result.ok:
                        return None
                    return SimpleNamespace(status_code=result.status, text=result.body,
                                           headers=result.headers)
                await global_throttle.acquire()
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False,
                                             verify=False) as client:
                    return await client.request(method, exchange.url, headers=headers,
                                                content=content.encode())
            except Exception:
                return None

        responses = await asyncio.gather(*[fire_one() for _ in range(n)])
        clean = 0
        for r in responses:
            if r is None:
                continue
            body = r.text or ""
            if 200 <= r.status_code < 400 and not _REJECTION.search(body):
                clean += 1

        # 3. verify read: did an authority field actually flip?
        try:
            v_status, after = await self._get_json(exchange.url, headers)
        except httpx.HTTPError as e:
            return self._skip(f"verify read failed: {e.__class__.__name__}")
        if not isinstance(after, dict):
            return self._not_confirmed(f"verify read returned no JSON object (GET -> {v_status})")

        flipped = [f for f, v in cands.items()
                   if _present_privileged(after, f, v) and not _present_privileged(baseline, f, v)]

        if flipped and clean >= 2:
            return ValidationResult(
                self.name, "confirmed", "toctou", confidence=0.85, confirmed=True,
                summary=f"TOCTOU privilege escalation: field(s) {flipped} became privileged under a "
                        f"{n}-way concurrent burst ({clean} clean successes), confirmed by an "
                        f"independent re-read.",
                evidence=f"Baseline showed {flipped} not privileged; {n} genuinely-concurrent "
                         f"{method}s were fired (asyncio.gather), {clean} returned a clean success, and "
                         f"a fresh GET shows the privileged value set. A single serialized write is the "
                         f"sequence leg's case; requiring concurrency + a state re-read isolates a "
                         f"check-then-write atomicity failure on a privilege boundary.")
        if flipped:
            return self._not_confirmed(
                f"an authority field flipped but only {clean} concurrent request(s) succeeded cleanly -- "
                f"looks like a plain mass-assignment (sequence leg's case), not a race")
        return self._not_confirmed(
            f"no authority field flipped after a {n}-way concurrent burst ({clean} clean successes) -- "
            f"no check-then-write privilege race confirmed")
