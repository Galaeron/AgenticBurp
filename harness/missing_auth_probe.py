"""
Missing-authentication probe -- A1 part 2.

The single-shot agents and the iterative agent both reason about an exchange the
tester already captured *with* their credentials attached. That leaves a whole
class of finding invisible: an endpoint the front end only ever calls while
logged in, which the server nonetheless serves to *anyone* because it forgot to
check the session. You never see it passively, because your captured traffic is
always authenticated. This is the Aikido "generateReport unauthenticated" bug --
a privileged report endpoint that returned data with no credentials at all.

This module closes that gap deterministically. Given a call shape recovered from
the application's own JavaScript (js_endpoint_extractor.extract_call_shapes) --
or any discovered (method, path) -- it RECONSTRUCTS the request and fires it with
authentication deliberately stripped:

  1. unauthenticated: no Authorization / Cookie / API-key headers at all.
  2. (optional) garbage-token: a syntactically-valid but bogus bearer token,
     to tell "this endpoint needs no auth" apart from "this endpoint accepts
     *any* token" (an auth check that runs but doesn't actually validate).

An endpoint is flagged `missing_authentication` when the stripped request comes
back 2xx with *substantive* content -- not a login redirect (we never follow
redirects, so a 302 -> /login stays a 3xx), not a 401/403, not an empty body,
and not an HTML login page served with a 200. Those all mean the control worked;
only real data returned to an anonymous caller is the bug.

Safe by construction, same envelope as every other outbound path here:
  - Scope-gated against `allowed_hosts` (never probes off-target).
  - Throttled through the global request throttle.
  - Read-only by default: only GET/HEAD/OPTIONS are probed unless the caller
    opts into mutating methods, which then go through the safety_gate exactly
    like the iterative agent and the mass-assignment validator.

Deterministic aside from the network I/O; no model call.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

import httpx

from harness import global_throttle
from harness.js_endpoint_extractor import CallShape
from harness.models import Finding
from harness.safety_gate import SafetyGate, get_default_gate

log = logging.getLogger("harness.missing_auth_probe")

# Request headers that carry identity/credentials. When we reconstruct a request
# to probe it unauthenticated, every one of these is dropped; the whole point is
# that NONE of them are present. (Content-negotiation / tracing headers are left
# alone -- stripping them would change what the endpoint returns for reasons
# unrelated to auth.)
_AUTH_HEADERS = frozenset({
    "authorization", "cookie", "x-api-key", "api-key", "apikey",
    "x-auth-token", "x-access-token", "x-session-token", "authentication",
    "x-csrf-token", "x-xsrf-token",
})

# A deliberately-invalid bearer token: well-formed enough to pass a header-shape
# check, but not a credential the server ever issued. If the endpoint returns
# data for THIS, its auth check runs but doesn't actually validate the token.
_GARBAGE_TOKEN = "Bearer harness.invalid.0000000000000000000000000000"

# Markers that a 2xx HTML body is actually a login / auth-challenge page rather
# than the protected resource -- so we don't call a served login form a leak.
_LOGIN_PAGE = re.compile(
    r"""(?:type\s*=\s*['"]password['"]|name\s*=\s*['"]password['"]"""
    r"""|<form[^>]*(?:login|signin|sign-in)|please\s+(?:log\s?in|sign\s?in)"""
    r"""|<title[^>]*>[^<]*(?:log\s?in|sign\s?in)[^<]*</title>)""",
    re.IGNORECASE,
)

# Bodies that are technically 2xx but carry no protected data.
_EMPTY_BODIES = frozenset({"", "[]", "{}", "null", "[ ]", "{ }"})

_MAX_EVIDENCE_CHARS = 400
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class ProbeOutcome:
    """The result of probing one (method, path) for missing authentication."""
    method: str
    url: str
    classification: str          # missing_auth | any_token_accepted | protected | inconclusive | skipped | error
    unauth_status: int | None = None
    unauth_len: int = 0
    garbage_status: int | None = None
    garbage_len: int = 0
    note: str = ""
    finding: Finding | None = None

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "classification": self.classification,
            "unauth_status": self.unauth_status,
            "unauth_len": self.unauth_len,
            "garbage_status": self.garbage_status,
            "garbage_len": self.garbage_len,
            "note": self.note,
            "finding": self.finding.model_dump() if self.finding else None,
        }


def _host_allowed(url: str, allowed_hosts: list[str] | None) -> bool:
    if not allowed_hosts:
        return True
    host = (urlsplit(url).hostname or "").lower()
    return any(host == h.lower() or host.endswith("." + h.lower()) for h in allowed_hosts)


def _build_url(base_url: str, path: str, id_fill: str) -> str:
    """Combine the target origin with a (possibly normalized) path. `{id}`
    placeholders left by the extractor's normalization are filled with a benign
    concrete value so the request is actually dispatchable."""
    concrete = path.replace("{id}", id_fill)
    if not concrete.startswith("/"):
        concrete = "/" + concrete
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}{concrete}"


def _substantive(status: int | None, body: str) -> bool:
    """True when a response is a real protected payload returned to an
    anonymous caller: a 2xx, with a non-empty body that isn't just an empty
    collection and isn't an HTML login page."""
    if status is None or not (200 <= status < 300):
        return False
    stripped = (body or "").strip()
    if stripped.lower() in _EMPTY_BODIES or len(stripped) < 2:
        return False
    if _LOGIN_PAGE.search(stripped):
        return False
    return True


def _strip_auth(headers: dict[str, str] | None) -> dict[str, str]:
    """Drop every identity/credential-bearing header, keeping the rest (Accept,
    User-Agent, content negotiation) so only the auth dimension changes."""
    out = {k: v for k, v in (headers or {}).items() if k.lower() not in _AUTH_HEADERS}
    out.setdefault("User-Agent", "harness-missing-auth-probe/1.0")
    return out


async def _send(method: str, url: str, headers: dict[str, str], timeout: float, *,
                run_context=None, session_ref: str | None = None) -> tuple[int | None, str]:
    try:
        if run_context is not None:
            from harness.run_context import TypedRequest
            outcome = await run_context.executor().execute(
                TypedRequest(method, url, headers=headers),
                capability="missing_auth_probe", session_ref=session_ref)
            if not outcome.ok:
                return None, f"request {outcome.outcome}: {outcome.error}"
            return outcome.status, outcome.body or ""
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url, headers=headers)
        return resp.status_code, (resp.text or "")
    except httpx.HTTPError as e:
        return None, f"request failed: {e.__class__.__name__}"


def _finding(kind: str, method: str, url: str, outcome: ProbeOutcome,
             expected_protected: bool) -> Finding:
    if kind == "missing_auth":
        conf = 0.85 if expected_protected else 0.75
        summary = (f"{method} {url} returns data with no authentication -- the endpoint "
                   f"served a {outcome.unauth_status} response ({outcome.unauth_len} bytes) "
                   f"to a request with all credentials stripped.")
        evidence = (f"Unauthenticated {method} (no Authorization/Cookie/API-key) -> "
                    f"HTTP {outcome.unauth_status}, {outcome.unauth_len} bytes of substantive body.")
        suggested = ("Confirm the response contains protected data (not a public resource), then "
                     "add an authentication/authorization check to this route.")
    else:  # any_token_accepted
        conf = 0.6
        summary = (f"{method} {url} accepts ANY bearer token -- unauthenticated it returned "
                   f"{outcome.unauth_status}, but with a bogus (never-issued) token it returned "
                   f"{outcome.garbage_status} ({outcome.garbage_len} bytes). The auth check runs "
                   f"but does not validate the token.")
        evidence = (f"No token -> HTTP {outcome.unauth_status}; garbage token -> HTTP "
                    f"{outcome.garbage_status}, {outcome.garbage_len} bytes of substantive body.")
        suggested = ("Verify token signature/issuer/expiry server-side; a forged or expired token "
                     "must be rejected, not merely required to be present.")
    return Finding(
        vulnerability_class="missing_authentication",
        confidence=conf,
        summary=summary,
        evidence=evidence[:_MAX_EVIDENCE_CHARS],
        suggested_test=suggested,
        basis="derived",
        severity="high",
        owasp_category="A07:2021-Identification and Authentication Failures",
        confirmed=True,  # this IS the active confirmation -- we sent it and observed the leak
        validation_hints=[f"{method} {url} with no credentials returned {outcome.unauth_status}"],
    )


async def probe(
    base_url: str,
    shape: CallShape | tuple[str, str],
    *,
    allowed_hosts: list[str] | None = None,
    baseline_headers: dict[str, str] | None = None,
    send_garbage_token: bool = True,
    include_mutating: bool = False,
    expected_protected: bool = False,
    id_fill: str = "1",
    timeout: float = 15.0,
    gate: SafetyGate | None = None,
    run_context=None,
) -> ProbeOutcome:
    """Probe one endpoint for missing authentication.

    `base_url` supplies the target origin; `shape` supplies (method, path).
    `baseline_headers` are the headers a legitimate request would carry (e.g.
    from the tester's Burp session) -- they are passed through *with the auth
    ones stripped*, so non-auth headers (Accept, content negotiation) are
    preserved. `expected_protected=True` (caller knows the endpoint is meant to
    be authenticated, e.g. it was only found in authenticated JS) nudges the
    confidence up. Read-only unless `include_mutating` and the safety gate allow
    the method.
    """
    method = (shape.method if isinstance(shape, CallShape) else shape[0]).upper()
    path = shape.path if isinstance(shape, CallShape) else shape[1]
    url = _build_url(base_url, path, id_fill)
    outcome = ProbeOutcome(method=method, url=url, classification="skipped")

    if not _host_allowed(url, allowed_hosts):
        outcome.classification = "skipped"
        outcome.note = f"out of scope: {urlsplit(url).hostname}"
        return outcome

    if method not in _SAFE_METHODS:
        if not include_mutating:
            outcome.note = f"mutating method {method} not probed (include_mutating is off)"
            return outcome
        if run_context is None:
            gate = gate or get_default_gate()
            decision = gate.authorize(validator_name="missing_auth_probe", method=method, url=url)
            if not decision.allowed:
                outcome.note = f"blocked by safety gate: {decision.reason}"
                return outcome

    unauth_headers = _strip_auth(baseline_headers)
    status, body = await _send(method, url, unauth_headers, timeout,
                               run_context=run_context)
    if status is None:
        outcome.classification = "error"
        outcome.note = body
        return outcome
    outcome.unauth_status = status
    outcome.unauth_len = len((body or "").strip())

    if _substantive(status, body):
        outcome.classification = "missing_auth"
        outcome.finding = _finding("missing_auth", method, url, outcome, expected_protected)
        return outcome

    # Not served anonymously. Optionally check whether ANY token is accepted --
    # a distinct, weaker weakness (auth present but not validated).
    if send_garbage_token:
        garb_headers = dict(unauth_headers)
        garb_headers["Authorization"] = _GARBAGE_TOKEN
        garbage_ref = None
        if run_context is not None:
            from harness.run_context import ScopePolicy
            garbage_ref = "missing-auth:garbage"
            run_context.sessions.register(
                garbage_ref, garbage_ref, {"Authorization": _GARBAGE_TOKEN},
                allowed_origins=[ScopePolicy.origin_of(url)], role="negative-control")
            garb_headers = {k: v for k, v in garb_headers.items()
                            if k.lower() != "authorization"}
        g_status, g_body = await _send(
            method, url, garb_headers, timeout, run_context=run_context,
            session_ref=garbage_ref)
        if g_status is not None:
            outcome.garbage_status = g_status
            outcome.garbage_len = len((g_body or "").strip())
            if _substantive(g_status, g_body):
                outcome.classification = "any_token_accepted"
                outcome.finding = _finding("any_token_accepted", method, url, outcome, expected_protected)
                return outcome

    outcome.classification = "protected" if status in (401, 403) or (300 <= status < 400) else "inconclusive"
    outcome.note = f"unauth -> {status}" + (
        f", garbage token -> {outcome.garbage_status}" if send_garbage_token else "")
    return outcome


async def probe_call_shapes(
    base_url: str,
    shapes: Iterable[CallShape | tuple[str, str]],
    **kwargs,
) -> list[ProbeOutcome]:
    """Probe a batch of call shapes, in sequence (the throttle already paces
    them). Returns every ProbeOutcome; callers pull `.finding` off the ones that
    flagged. Duplicate (method, path) shapes are collapsed."""
    seen: set[tuple[str, str]] = set()
    outcomes: list[ProbeOutcome] = []
    for shape in shapes:
        method = (shape.method if isinstance(shape, CallShape) else shape[0]).upper()
        path = shape.path if isinstance(shape, CallShape) else shape[1]
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        outcomes.append(await probe(base_url, shape, **kwargs))
    return outcomes


def findings_from(outcomes: Iterable[ProbeOutcome]) -> list[Finding]:
    """Collect just the Findings from a batch of outcomes."""
    return [o.finding for o in outcomes if o.finding is not None]
