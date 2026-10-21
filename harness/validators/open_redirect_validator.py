"""
Open-redirect confirmation leg (deterministic, in-band Location-header signal).

The open_redirect agent can only GUESS that a redirect parameter is attacker-
controllable. This proves it: set the redirect parameter to a unique off-origin
sentinel host, send the request WITHOUT following redirects, and check the
response's Location header. If the server issues a 3xx whose Location points at
our sentinel host (not the target's own origin), the redirect target is
attacker-controlled -- confirmed open redirect. Inspecting the Location host,
rather than trusting a reflected value, is what distinguishes a real redirect from
the parameter merely appearing in the body.

Fires on open_redirect findings, or -- shape-decoupled -- on any request with a
redirect-shaped parameter. Scope-gated; active (validators.active_enabled). The
sends are read-only follows (a non-GET capture still routes through the gate).
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, parse_qsl

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers

_REDIRECT_PARAM_NAMES = {"url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
                         "next", "return", "returnurl", "return_url", "returnto", "return_to",
                         "dest", "destination", "continue", "goto", "go", "to", "u", "r",
                         "target", "forward", "callback", "checkout_url", "success_url", "back"}
# A sentinel host no legitimate same-origin redirect would ever point to.
_SENTINEL_HOST = "oob-openredirect.example"
# Statuses a browser follows to the Location header. A Location on any other
# status (a 200, a 300 choice page, a 304) is not a redirect (R16).
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", re.DOTALL)


def _destination_host(location: str, request_url: str) -> str:
    """The host a browser navigates to for this Location, resolved against the
    request URL the way browsers parse http(s) URLs: tab/newline dropped, outer
    whitespace trimmed, a backslash read as a slash. An origin- or path-relative
    Location (``/oob-openredirect.example/x``) resolves to the request's own host,
    so a sentinel that only appears in the path never counts as off-origin (R16)."""
    loc = re.sub(r"[\t\r\n]", "", location or "").strip().replace("\\", "/")
    base = urlsplit(request_url)
    m = _SCHEME.match(loc)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme not in ("http", "https"):
            return ""  # javascript:, data:, ... -- no http destination host
        if scheme == (base.scheme or "").lower() and not rest.startswith("//"):
            # "http:/x" on an http page is a relative path on the same origin.
            return (base.hostname or "").lower()
        authority = rest.lstrip("/")
    elif loc.startswith("//"):
        authority = loc.lstrip("/")  # scheme-relative: //host/...
    else:
        return (base.hostname or "").lower()
    try:
        return (urlsplit("//" + authority).hostname or "").lower()
    except ValueError:
        return ""


def _redirect_params(exchange: HttpExchange) -> list[tuple[str, str]]:
    qs = dict(parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True))
    out = []
    for loc, param in param_targets(exchange):
        val = qs.get(param, "") if loc == "query" else ""
        if param.lower() in _REDIRECT_PARAM_NAMES or re.match(r"^(https?:)?//|^/\w", val or ""):
            out.append((loc, param))
    return out


class OpenRedirectValidator(Validator):
    name = "open_redirect"
    finding_classes = {"open_redirect", "open redirect", "url redirect"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return (super().applies(finding, exchange) and bool(_redirect_params(exchange))) \
            or bool(_redirect_params(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "open_redirect", summary=why)

    def _payloads(self, token: str) -> list[str]:
        # Absolute, scheme-relative, and a backslash bypass some parsers treat as //.
        return [f"https://{_SENTINEL_HOST}/{token}",
                f"//{_SENTINEL_HOST}/{token}",
                f"https:/{_SENTINEL_HOST}/{token}",
                f"/\\{_SENTINEL_HOST}/{token}"]

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        targets = _redirect_params(exchange)
        if not targets:
            return self._skip("no redirect-shaped parameter to point off-origin")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        candidate = ""  # sentinel reached Location, but no off-origin redirect
        # Sends that got no response: a check that never reached the target is
        # not a negative (RV-L L2). The gate's refusal stops the remaining sends.
        refused, errors, sends = "", [], 0
        for loc, param in targets:
            for payload in self._payloads(f"{loc}-{param}"):
                if refused:
                    break
                url, body = mutate(exchange, loc, param, payload)
                sends += 1
                try:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=False, verify=False) as client:
                        resp = await client.request(method, url, headers=headers or None, content=body or None)
                except SafetyGateBlocked as e:
                    refused = e.decision.reason
                    continue
                except httpx.HTTPError as e:
                    errors.append(f"{param!r} = `{payload}`: {e.__class__.__name__}")
                    continue
                location = ""
                try:
                    location = resp.headers.get("location", "") or resp.headers.get("Location", "")
                except Exception:
                    location = ""
                if not location:
                    continue
                # Confirm only a real redirect whose parsed destination host is the
                # sentinel. A relative Location that merely contains the sentinel in
                # its path, or a Location on a non-redirect status, stays a candidate.
                is_redirect = resp.status_code in _REDIRECT_STATUSES
                if is_redirect and _destination_host(location, url) == _SENTINEL_HOST:
                    return ValidationResult(
                        self.name, "confirmed", "open_redirect", confidence=0.9, confirmed=True,
                        summary=f"Open redirect confirmed: the {loc} parameter {param!r} controls the "
                                f"Location the server redirects to.",
                        evidence=f"Set {param!r} to `{payload}`; the server responded with HTTP "
                                 f"{resp.status_code}, a redirect to the off-origin sentinel host "
                                 f"{_SENTINEL_HOST!r} (Location: {location}).")
                if not candidate and _SENTINEL_HOST in location.lower():
                    why = ("it stays on the target's own origin" if is_redirect
                           else f"HTTP {resp.status_code} is not a redirect status")
                    candidate = (f"Set {loc} param {param!r} to `{payload}`; the response carried "
                                 f"Location: {location}, but {why}.")
        if candidate:
            return ValidationResult(
                self.name, "inconclusive", "open_redirect", confidence=0.3, confirmed=False,
                summary="Open-redirect candidate (unconfirmed): the parameter reaches the Location "
                        "header, but no redirect to an off-origin host was observed",
                evidence=candidate + " A browser would not leave the site, so this is not proof of "
                                     "an open redirect; check manually for another bypass.")
        unanswered = len(errors) + (1 if refused else 0)
        if unanswered:
            answered = sends - unanswered
            why = "; ".join(([f"refused by the safety gate ({refused})"] if refused else []) + errors[:3])
            return ValidationResult(
                self.name, "blocked" if refused and not answered else "inconclusive", "open_redirect",
                confidence=0.0, confirmed=False,
                summary=f"Open-redirect check incomplete: {unanswered} of {sends} send(s) got no "
                        f"response ({why}); not a negative result",
                evidence=f"Tried {len(targets)} redirect-shaped parameter(s); {answered} answered "
                         f"send(s) carried no Location pointing at the sentinel host, but a send that "
                         f"never reached the target cannot show one.")
        return ValidationResult(
            self.name, "not_confirmed", "open_redirect", confidence=0.0, confirmed=False,
            summary="No off-origin redirect observed -- the redirect target is not attacker-controlled",
            evidence=f"Tried {len(targets)} redirect-shaped parameter(s); no Location pointed at the sentinel host.")
