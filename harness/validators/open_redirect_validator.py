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
        for loc, param in targets:
            for payload in self._payloads(f"{loc}-{param}"):
                url, body = mutate(exchange, loc, param, payload)
                try:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=False, verify=False) as client:
                        resp = await client.request(method, url, headers=headers or None, content=body or None)
                except SafetyGateBlocked:
                    return self._skip("mutating open-redirect replay not authorized "
                                      "(set validators.allow_mutating_replay)")
                except httpx.HTTPError:
                    continue
                location = ""
                try:
                    location = resp.headers.get("location", "") or resp.headers.get("Location", "")
                except Exception:
                    location = ""
                if not location:
                    continue
                # Confirm only if the redirect actually lands on the sentinel host.
                loc_host = (urlsplit(location).hostname or "")
                if loc_host.lower() == _SENTINEL_HOST or location.lstrip("/\\").lower().startswith(_SENTINEL_HOST):
                    return ValidationResult(
                        self.name, "confirmed", "open_redirect", confidence=0.9, confirmed=True,
                        summary=f"Open redirect confirmed: the {loc} parameter {param!r} controls the "
                                f"Location the server redirects to.",
                        evidence=f"Set {param!r} to `{payload}`; the server responded with a redirect to the "
                                 f"off-origin sentinel host {_SENTINEL_HOST!r} (Location: {location}).")
        return ValidationResult(
            self.name, "not_confirmed", "open_redirect", confidence=0.0, confirmed=False,
            summary="No off-origin redirect observed -- the redirect target is not attacker-controlled",
            evidence=f"Tried {len(targets)} redirect-shaped parameter(s); no Location pointed at the sentinel host.")
