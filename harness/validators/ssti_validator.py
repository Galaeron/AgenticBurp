"""
Server-side template injection (SSTI) confirmation leg (deterministic, in-band
arithmetic differential).

The ssti agent can only GUESS that a parameter is rendered inside a template. This
proves it without executing any OS command: inject a template expression that
multiplies two constants, wrapped in a per-attempt nonce, and check the RESPONSE
for the *product* between the nonce boundaries. If the engine evaluated the
expression, the response contains `<nonce>8633<nonce>`; if the parameter is merely
reflected (ordinary output, or reflected XSS), the response contains the literal
`89*97` instead. The nonce makes an accidental "8633" collision with real page
content essentially impossible, and the boundary proves the engine concatenated
our own delimiter -- so this is a specific proof of template *evaluation*, not
reflection.

Arithmetic evaluation is the confirmation (it proves the injection is real);
deliberately NOT a full RCE payload -- weaponisation (reading env, popping a shell
via the engine's sandbox escape) is a separate, higher-risk step this leg does not
take.

Fires on ssti findings; injects into every query/body parameter. Scope-gated;
active (validators.active_enabled), and a non-GET replay additionally needs
validators.allow_mutating_replay (safety gate).
"""
from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers

# Two 2-digit primes -> a distinctive 4-digit product unlikely to appear by
# chance, and one no reasonable page computes for an unrelated reason.
_A, _B = 89, 97
_PRODUCT = str(_A * _B)  # "8633"
_EXPR = f"{_A}*{_B}"
# Template syntaxes across the common engines: Jinja2/Twig, JSP-EL/Freemarker/
# Velocity, Thymeleaf/Ruby, a nested variant, ERB/JSP scriptlet, single-brace.
_SYNTAXES = ("{{%s}}", "${%s}", "#{%s}", "${{%s}}", "<%%= %s %%>", "{%s}")
_MAX_PARAMS = 6


def _payloads(nonce: str) -> list[str]:
    return [f"{nonce}{syn % _EXPR}{nonce}" for syn in _SYNTAXES]


class SstiValidator(Validator):
    name = "ssti"
    finding_classes = {"ssti", "template injection", "server-side template injection",
                       "server side template injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(param_targets(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "ssti", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        targets = param_targets(exchange)[:_MAX_PARAMS]
        if not targets:
            return self._skip("no parameter to inject a template expression into")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        for loc, param in targets:
            for payload in _payloads(secrets.token_hex(3)):
                nonce = payload[:6]
                evaluated = f"{nonce}{_PRODUCT}{nonce}"
                url, body = mutate(exchange, loc, param, payload)
                try:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=False, verify=False) as client:
                        resp = await client.request(method, url, headers=headers or None, content=body or None)
                except SafetyGateBlocked:
                    return self._skip("mutating SSTI replay not authorized "
                                      "(set validators.allow_mutating_replay)")
                except httpx.HTTPError:
                    continue
                try:
                    text = resp.text
                except Exception:
                    continue
                if evaluated in text:
                    return ValidationResult(
                        self.name, "confirmed", "ssti", confidence=0.95, confirmed=True,
                        summary=f"SSTI confirmed: a template expression in the {loc} parameter {param!r} "
                                f"was evaluated server-side.",
                        evidence=f"Injected `{payload}`; the response contained the evaluated product "
                                 f"`{evaluated}` (not the literal `{_EXPR}`), proving template evaluation.")
        return ValidationResult(
            self.name, "not_confirmed", "ssti", confidence=0.0, confirmed=False,
            summary="No template expression was evaluated -- parameters are reflected literally, if at all",
            evidence=f"Tried {len(targets)} parameter(s) across {len(_SYNTAXES)} engine syntaxes; "
                     f"the arithmetic product never appeared between the nonce boundaries.")
