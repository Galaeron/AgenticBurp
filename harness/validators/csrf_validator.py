"""CSRF confirmation leg (V32, WSTG-SESS-09).

A token-bearing, cookie-authenticated form can be confirmed when a tokenless
top-level GET performs the same state change and the authenticated redirect page
independently reads back a distinct submitted value. This covers applications
whose CSRF-token validation depends on the request method. SameSite=Strict blocks
the check; SameSite=Lax permits the top-level GET navigation.

Ordinary token-stripping POST replays remain observations rather than confirmation
because a successful status alone does not prove that the state changed.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from harness import browser_driver, global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

log = logging.getLogger("harness.validators.csrf_validator")

_CSRF_TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken"
    r"|_csrf_token|anti.?forgery|nonce)",
    re.IGNORECASE)

_SAMESITE_RE = re.compile(r"SameSite\s*=\s*(Strict|Lax|None)", re.IGNORECASE)


def _has_csrf_token(exchange: HttpExchange) -> bool:
    """Check whether the original request carried any CSRF-like token."""
    body = exchange.request_body or ""
    url = exchange.url or ""
    headers = exchange.request_headers or {}
    for source in (body, url):
        if _CSRF_TOKEN_NAMES.search(source):
            return True
    for name in headers:
        if _CSRF_TOKEN_NAMES.search(name):
            return True
    return False


def _session_cookie_samesite(exchange: HttpExchange) -> str | None:
    """Return SameSite value of the session cookie, or None if no session cookie
    or no SameSite attribute."""
    resp_headers = exchange.response_headers or {}
    for name, value in resp_headers.items():
        if name.lower() != "set-cookie":
            continue
        cookie_name = value.split("=", 1)[0].strip().lower()
        if any(k in cookie_name for k in ("session", "sess", "sid", "auth", "token", "jwt")):
            m = _SAMESITE_RE.search(value)
            if m:
                return m.group(1)
            return None
    return None


def _method_bypass_url(exchange: HttpExchange) -> tuple[str, list[tuple[str, str]]]:
    """Turn a token-bearing form write into a top-level-navigation GET shape.

    Returns the URL and the non-token form fields retained in the query. Empty
    means this is not a browser-simple method-bypass candidate.
    """
    parts = urlsplit(exchange.url or "")
    pairs = parse_qsl(exchange.request_body or "", keep_blank_values=True)
    retained = [(k, v) for k, v in pairs if not _CSRF_TOKEN_NAMES.search(k or "")]
    if not retained or len(retained) == len(pairs):
        return "", []
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True) + retained)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), retained


def _readback_matches(body: str, submitted: list[tuple[str, str]]) -> bool:
    """Require an independently fetched response to contain a submitted value.

    Short/common values are ignored so an ordinary 200 page cannot accidentally
    confirm a state transition merely because it contains `1` or `on`.
    """
    rendered = body or ""
    return any(len(value.strip()) >= 5 and value in rendered for _, value in submitted)


def _primary_cookie(cookie_header: str) -> tuple[str, str] | None:
    """The first name=value pair in a Cookie header, or None. Good enough for
    a single ambient-session cookie -- LB-5's scope is proving ONE ambient
    cookie rides along cross-site, not picking the "right" one out of
    several the original capture may have carried."""
    for part in (cookie_header or "").split(";"):
        if "=" in part:
            name, _, value = part.strip().partition("=")
            if name:
                return name, value
    return None


def _cross_site_form_fields(exchange: HttpExchange) -> tuple[dict, list[tuple[str, str]]] | None:
    """Build the LB-5 auto-submit form's fields from the captured request
    body. A real cross-site <form> can only carry
    application/x-www-form-urlencoded (or multipart) content, never raw
    JSON -- so this only ever applies to an urlencoded body; a JSON-bodied
    capture returns None (not form-submittable, nothing to prove with that
    shape).

    Swaps exactly ONE non-token field's value for a fresh, distinguishing
    token (secrets.token_hex) -- enough to prove an INDEPENDENTLY-submitted
    value reached victim state via the GET-only readback (_readback_matches),
    without needing every field to be a sentinel. Returns None when there is
    no eligible field to swap."""
    pairs = parse_qsl(exchange.request_body or "", keep_blank_values=True)
    if not pairs:
        return None
    token = secrets.token_hex(8)
    fields: dict = {}
    submitted: list[tuple[str, str]] = []
    swapped = False
    for k, v in pairs:
        if not swapped and not _CSRF_TOKEN_NAMES.search(k or ""):
            fields[k] = token
            submitted.append((k, token))
            swapped = True
        else:
            fields.setdefault(k, v)
    if not swapped:
        return None
    return fields, submitted


class CsrfValidator(Validator):
    name = "csrf"
    finding_classes = {"csrf", "cross-site request forgery", "cross site request forgery", "xsrf"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None, cross_site_poc_enabled: bool = False,
                 cross_site_readback_url: "Callable[[str], str] | None" = None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context
        # LB-5 (default OFF, config: cross_site_poc.enabled): when True AND a
        # real browser driver is available AND `cross_site_readback_url` can
        # map the captured victim URL to a GET-only state-readback URL,
        # `validate()` attempts a REAL cross-site browser PoC (ambient
        # cookie, no header forged by us) instead of settling for the
        # RETIRED token-strip-replay-as-observation path below. See
        # `_attempt_cross_site_poc`.
        self.cross_site_poc_enabled = cross_site_poc_enabled
        self.cross_site_readback_url = cross_site_readback_url

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        method = (exchange.method or "GET").upper()
        return method in ("POST", "PUT", "PATCH", "DELETE")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "csrf", summary=why)

    async def _attempt_cross_site_poc(self, exchange: HttpExchange, method: str,
                                      headers_lower: dict) -> "ValidationResult | None":
        """LB-5: attempt the real cross-site browser PoC instead of settling
        for the RETIRED token-strip-replay observation below. Returns a
        ValidationResult ONLY on a decisive CONFIRM; returns None for every
        other outcome (disabled, no driver, no ambient cookie, no readback
        mapping, the PoC ran but the victim stayed unchanged) so the caller
        falls through to the EXISTING 0.4 OBSERVATION path UNCHANGED -- this
        method only ever ADDS a confirm path, it never changes what
        "not confirmed" looks like.

        Requires an ambient Cookie (never an Authorization-only exchange --
        a bearer-only/non-ambient victim has nothing for this primitive's
        cookie jar to carry, so it is skipped here, by construction, exactly
        matching the "stays silent on bearer-only" control) and a body this
        validator can turn into form fields (urlencoded only -- see
        `_cross_site_form_fields`)."""
        if not self.cross_site_poc_enabled or self.cross_site_readback_url is None:
            return None
        if "authorization" in headers_lower:
            return None
        primary = _primary_cookie(headers_lower.get("cookie", ""))
        if primary is None:
            return None
        cookie_name, cookie_value = primary
        fields_info = _cross_site_form_fields(exchange)
        if fields_info is None:
            return None
        fields, submitted = fields_info

        driver = browser_driver.default_driver()
        if driver is None:
            return None

        victim_url = exchange.url
        try:
            readback_url = self.cross_site_readback_url(victim_url)
        except Exception:
            return None
        if not readback_url:
            return None

        scheme = urlsplit(victim_url).scheme or "http"
        cookie_domain = urlsplit(victim_url).hostname or ""
        if not cookie_domain:
            return None
        # Synthesized attacker origin -- NEVER dispatched to the real
        # network (cross_site_submit's own route policy fulfils it locally),
        # so this placeholder host needs no real DNS entry. It only needs to
        # be a different SITE than the victim, which any domain name is,
        # relative to the victim's loopback/IP-literal or distinct-hostname
        # origin.
        attacker_url = f"{scheme}://csrf-poc-attacker.localhost/csrf-poc-attacker"

        try:
            result = await driver.cross_site_submit(
                attacker_url=attacker_url, victim_url=victim_url, victim_method=method,
                form_fields=fields, readback_url=readback_url,
                cookie_name=cookie_name, cookie_value=cookie_value,
                cookie_domain=cookie_domain, same_site=None)
        except Exception as e:
            log.debug("CSRF cross-site PoC attempt errored: %s", e)
            return None

        if result.load_error:
            return None

        if (result.submitted and result.readback_status is not None
                and 200 <= result.readback_status < 300
                and _readback_matches(result.readback_body, submitted)):
            names = ", ".join(k for k, _ in submitted)
            return ValidationResult(
                self.name, "confirmed", "csrf", confidence=0.95, confirmed=True,
                summary=("A real cross-site browser PoC delivered the victim's AMBIENT session "
                         "cookie on a tokenless, cross-site auto-submit POST, and an "
                         "INDEPENDENT GET-only readback confirmed the resulting state change."),
                evidence=(f"Attacker-origin auto-submit form POSTed to {victim_url} "
                          f"(status {result.submit_status}); independent GET {readback_url} "
                          f"(status {result.readback_status}) read back the submitted "
                          f"field(s): {names}."))
        return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")

        method = (exchange.method or "GET").upper()
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return self._skip("endpoint does not accept a state-changing method")

        samesite = _session_cookie_samesite(exchange)

        # Token validation that disappears when POST is changed to GET is a
        # distinct, browser-deliverable CSRF case. A top-level cross-site GET can
        # carry SameSite=Lax cookies; require Cookie ambient credentials, reject
        # bearer-only shapes, and confirm only when the followed response reads
        # back a non-token value submitted by the probe.
        bypass_url, submitted = _method_bypass_url(exchange)
        headers_lower = {str(k).lower(): str(v)
                         for k, v in (exchange.request_headers or {}).items()}
        if bypass_url and "cookie" in headers_lower and "authorization" not in headers_lower:
            if samesite and samesite.lower() == "strict":
                return ValidationResult(
                    self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
                    summary="Session cookie has SameSite=Strict, blocking cross-site navigation credentials.")
            method_headers = replay_headers(exchange)
            method_headers = {k: v for k, v in (method_headers or {}).items()
                              if (k or "").lower() not in
                              ("content-type", "content-length", "origin", "referer")
                              and not _CSRF_TOKEN_NAMES.search(k or "")}
            try:
                if self.run_context is not None:
                    from harness.run_context import TypedRequest
                    from .transport import bind_session
                    session_ref, request_headers = bind_session(self.run_context, method_headers)
                    outcome = await self.run_context.executor().execute(
                        TypedRequest("GET", bypass_url, headers=request_headers),
                        capability=self.name, session_ref=session_ref)
                    if not outcome.executed:
                        return self._skip(f"CSRF method-bypass probe declined: {outcome.outcome}")
                    if outcome.outcome == "error":
                        return ValidationResult(self.name, "error", "csrf",
                                                summary=f"HTTP error during method-bypass probe: {outcome.error}")
                    status_code, response_body = outcome.status or 0, outcome.body or ""
                else:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=True, verify=False) as client:
                        resp = await client.get(bypass_url, headers=method_headers or None)
                    status_code, response_body = resp.status_code, resp.text or ""
            except SafetyGateBlocked:
                return self._skip("CSRF method-bypass probe not authorized")
            except httpx.HTTPError as e:
                return ValidationResult(self.name, "error", "csrf",
                                        summary=f"HTTP error during method-bypass probe: {e}")
            if 200 <= status_code < 300 and _readback_matches(response_body, submitted):
                names = ", ".join(k for k, _ in submitted)
                return ValidationResult(
                    self.name, "confirmed", "csrf", confidence=0.95, confirmed=True,
                    summary=("Token-bearing form accepted as a tokenless GET and the resulting "
                             "authenticated page independently read back the submitted value."),
                    evidence=(f"GET {bypass_url} without the CSRF field returned {status_code}; "
                              f"readback matched submitted field(s): {names}."))
            return ValidationResult(
                self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
                summary=(f"Tokenless GET method-bypass returned {status_code}, but no submitted "
                         "value was independently read back."))

        if samesite and samesite.lower() in ("strict", "lax"):
            return ValidationResult(
                self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
                summary=f"Session cookie has SameSite={samesite} — CSRF mitigated.",
                evidence=f"SameSite={samesite} prevents cross-site request submission.")

        headers = replay_headers(exchange)
        strip_headers = dict(headers or {})
        for name in list(strip_headers.keys()):
            if _CSRF_TOKEN_NAMES.search(name):
                del strip_headers[name]

        body = exchange.request_body or ""
        stripped_body = _CSRF_TOKEN_NAMES.sub("REMOVED", body) if body else ""

        try:
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                from .transport import bind_session
                session_ref, request_headers = bind_session(self.run_context, strip_headers)
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, exchange.url, headers=request_headers,
                                 body=stripped_body or None),
                    capability=self.name, session_ref=session_ref)
                if not outcome.executed:
                    return self._skip(f"CSRF replay declined: {outcome.outcome}")
                if outcome.outcome == "error":
                    return ValidationResult(self.name, "error", "csrf",
                                            summary=f"HTTP error during replay: {outcome.error}")
                status_code = outcome.status or 0
            else:
                await global_throttle.acquire()
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    resp = await client.request(method, exchange.url,
                                                headers=strip_headers or None,
                                                content=stripped_body or None)
                status_code = resp.status_code
        except SafetyGateBlocked:
            return self._skip("mutating CSRF replay not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(
                self.name, "error", "csrf", summary=f"HTTP error during replay: {e}")

        if 200 <= status_code < 300:
            poc_result = await self._attempt_cross_site_poc(exchange, method, headers_lower)
            if poc_result is not None:
                return poc_result

            token_present = _has_csrf_token(exchange)
            evidence_parts = [
                f"Replayed {method} {exchange.url} without CSRF token → {status_code}.",
            ]
            if not token_present:
                evidence_parts.append("Original request also carried no CSRF token.")
            if samesite:
                evidence_parts.append(f"Session cookie SameSite={samesite} (not protective).")
            else:
                evidence_parts.append("No SameSite attribute on session cookie.")

            # RETIRED (review 2026-09-09): a token-strip replay returning 2xx does
            # NOT prove CSRF -- it does not show a victim BROWSER can send the
            # request with AMBIENT credentials. Bearer/JSON APIs aren't ambient,
            # Origin/Referer may be enforced server-side, and a default SameSite=Lax
            # already blocks cross-site POSTs even with "no SameSite" in this
            # response. This no longer sets confirmed=True. Re-qualify: a cross-site
            # browser PoC that fires the request with the victim's ambient cookies
            # and independently verifies the state change, plus controls for
            # bearer-only requests, Origin enforcement and default-SameSite; only
            # then confirmed=True (and re-add "csrf" to the gate's LIVE set).
            return ValidationResult(
                self.name, "not_confirmed", "csrf", confidence=0.4, confirmed=False,
                summary=f"OBSERVATION (not confirmed): {method} request was accepted without an "
                        f"anti-CSRF token. NOT a confirmed CSRF -- needs a cross-site browser PoC "
                        f"with ambient credentials (this replay proves neither ambient-credential "
                        f"delivery nor absence of Origin/SameSite protection).",
                evidence=" ".join(evidence_parts))

        return ValidationResult(
            self.name, "not_confirmed", "csrf", confidence=0.0, confirmed=False,
            summary=f"Replay without CSRF token returned {status_code} (rejected).",
            evidence=f"{method} {exchange.url} without token → {status_code}.")
