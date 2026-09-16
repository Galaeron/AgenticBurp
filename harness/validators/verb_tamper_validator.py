"""
Verb-tampering / HTTP method access-control bypass (V15, WSTG-CONF-06).

Safe subset: read-only method alternates (HEAD, OPTIONS, GET) + method-override
headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method). Confirms a
denial→2xx transition: an endpoint that denies the intended method (401/403) but
serves a substantive 2xx for a different method or override has a method-scoped
authorization hole.

By default does NOT send blind PUT/DELETE. The mutating-method case (the common
high-value shape: GET-protected but PUT/PATCH/DELETE-open) is gated behind an
explicit opt-in `validators.verb_tamper.try_mutating_methods` (off by default),
and even then every mutating send goes through the safety gate + allow_mutating_replay
(triple-gated) per LEG_DECISIONS.md #1. Active; scope-gated.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
_SAFE_METHODS = ("HEAD", "OPTIONS", "GET")
# Only reached under the explicit try_mutating_methods opt-in + allow_mutating_replay.
_MUTATING_METHODS = ("PUT", "PATCH", "DELETE")


class VerbTamperValidator(Validator):
    name = "verb_tamper"
    finding_classes = {"misconfig", "misconfiguration", "verb tamper", "verb_tamper",
                       "method tampering", "http method", "http_method"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 try_mutating_methods: bool = False, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        # Off by default: sending a blind PUT/DELETE to an endpoint we have not
        # confirmed is safe to mutate can destroy data. When on, still gated by
        # the safety gate (allow_mutating_replay).
        self.try_mutating_methods = bool(try_mutating_methods)
        self.run_context = run_context

    async def _request(self, method: str, url: str, headers: dict):
        if self.run_context is not None:
            from harness.run_context import TypedRequest
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)
            return await self.run_context.executor().execute(
                TypedRequest(method, url, headers=request_headers),
                capability=self.name, session_ref=session_ref)
        await global_throttle.acquire()
        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                    follow_redirects=False, verify=False) as client:
            return await client.request(method, url, headers=headers or None)

    def _response_parts(self, response):
        if self.run_context is not None:
            if not response.executed or response.outcome == "error":
                return None, ""
            return response.status, response.body or ""
        return response.status_code, response.text or ""

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "misconfig", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        url = exchange.url
        orig_method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        orig_status = exchange.response_status or 0

        if 200 <= orig_status < 300:
            return self._skip("original request already succeeded (2xx) — no denial to bypass")

        if orig_status not in (401, 403, 405):
            return self._skip(f"original status {orig_status} is not a denial (401/403/405)")

        for method in _SAFE_METHODS:
            if method == orig_method:
                continue
            try:
                resp = await self._request(method, url, headers)
            except httpx.HTTPError:
                continue
            except Exception:
                continue
            status, text = self._response_parts(resp)
            if status is not None and 200 <= status < 300 and len(text) > 10:
                # RETIRED (review 2026-09-09): an alternate method returning 2xx where
                # the original was denied is NOT proof of an authz bypass -- it can be
                # ordinary routing (a public GET beside a private POST). It no longer
                # sets confirmed=True. Re-qualify: compare the SAME protected data/
                # action under the SAME unauthorized principal across methods, with a
                # public-GET/private-write control; only then confirmed=True.
                return ValidationResult(
                    self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                    summary=f"OBSERVATION (not confirmed): {orig_method} returns {orig_status} but "
                            f"{method} returns {status} with a substantive body -- may be "
                            f"ordinary routing, not an authz bypass; needs a same-principal same-data control.",
                    evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                             f"Alternate: {method} -> {status} ({len(text)} bytes).")

        for override_header in _OVERRIDE_HEADERS:
            try:
                h = dict(headers or {})
                h[override_header] = orig_method
                resp = await self._request("POST", url, h)
            except httpx.HTTPError:
                continue
            except Exception:
                continue
            status, text = self._response_parts(resp)
            if status is not None and 200 <= status < 300 and len(text) > 10:
                # RETIRED (review 2026-09-09) -- see the note above; observation only.
                return ValidationResult(
                    self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                    summary=f"OBSERVATION (not confirmed): POST with {override_header}: {orig_method} "
                            f"returns {status} (original {orig_method} returns {orig_status}) "
                            f"-- needs a same-principal same-data control to distinguish a real bypass.",
                    evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                             f"Override: POST + {override_header}: {orig_method} -> {status}.")

        # Opt-in mutating-method variant: the common exploitable shape is a
        # GET/POST-denied endpoint that serves a mutating method. Triple-gated
        # (this flag + active_enabled + allow_mutating_replay via GatedAsyncClient).
        if self.try_mutating_methods:
            for method in _MUTATING_METHODS:
                if method == orig_method:
                    continue
                try:
                    resp = await self._request(method, url, headers)
                except SafetyGateBlocked:
                    # mutating replay not authorized -- stop trying mutating methods.
                    break
                except httpx.HTTPError:
                    continue
                except Exception:
                    continue
                status, text = self._response_parts(resp)
                if status is not None and 200 <= status < 300 and len(text) > 10:
                    # RETIRED (review 2026-09-09) -- see the note above; observation only.
                    return ValidationResult(
                        self.name, "not_confirmed", "misconfig", confidence=0.4, confirmed=False,
                        summary=f"OBSERVATION (not confirmed, mutating): {orig_method} returns {orig_status} "
                                f"but {method} returns {status} with a substantive body -- "
                                f"needs a same-principal same-data control to distinguish a real bypass.",
                        evidence=f"Original: {orig_method} {url} -> {orig_status}. "
                                 f"Mutating alternate: {method} -> {status} "
                                 f"({len(text)} bytes). Sent under the try_mutating_methods opt-in "
                                 f"+ allow_mutating_replay.")

        tried_mut = f" + {len(_MUTATING_METHODS)} mutating methods" if self.try_mutating_methods else ""
        return ValidationResult(
            self.name, "not_confirmed", "misconfig", confidence=0.0, confirmed=False,
            summary="No verb-tamper bypass found with safe methods and override headers"
                    + (" or mutating methods" if self.try_mutating_methods else "") + ".",
            evidence=f"Tried {len(_SAFE_METHODS)-1} safe alternate methods + {len(_OVERRIDE_HEADERS)} "
                     f"override headers{tried_mut}; none returned a substantive 2xx.")
