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
from dataclasses import replace
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
_MAX_READBACKS = 12


def _payloads(nonce: str) -> list[str]:
    return [f"{nonce}{syn % _EXPR}{nonce}" for syn in _SYNTAXES]


def _restore_succeeded(outcome) -> tuple[bool, str]:
    """Whether the restore send reached the target and was accepted (R12). A send the
    gate or budget refused, one that errored, and one the target rejected (HTTP 4xx/5xx)
    all leave the planted value in place, so none of them is a restoration."""
    if not getattr(outcome, "executed", False):
        why = getattr(outcome, "outcome", "") or "not sent"
        err = getattr(outcome, "error", "") or ""
        return False, f"not sent: {why}" + (f" ({err})" if err else "")
    if not getattr(outcome, "ok", False):
        return False, f"send failed: {getattr(outcome, 'outcome', '') or 'error'}"
    status = getattr(outcome, "status", None)
    if status is not None and status >= 400:
        return False, f"the target answered HTTP {status}"
    return True, f"HTTP {status}" if status is not None else "sent"


class SstiValidator(Validator):
    name = "ssti"
    finding_classes = {"ssti", "template injection", "server-side template injection",
                       "server side template injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None, readback_urls: list[str] | None = None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context
        # Already-discovered, same-origin GET pages that may render a value saved
        # by a separate settings/editor request.  The orchestrator supplies these;
        # the validator never invents routes or crosses origin boundaries.
        self.readback_urls = list(dict.fromkeys(readback_urls or []))[:_MAX_READBACKS]

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(param_targets(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "ssti", summary=why)

    def _cleanup_unaffordable(self, finding: Finding, reads: int) -> str | None:
        """Why the run cannot pay for a stored plant AND its restore, or None when it
        can (R12). The restore is a second mutating send plus its own request, and the
        readbacks sit between them: if the per-finding write ceiling or the request
        budget cannot cover all of it, the plant must not be written, because the
        restore would be refused and the planted value would stay behind."""
        run = self.run_context
        if run is None:
            return None
        need = 2 + reads
        remaining = run.budget.remaining
        if remaining is not None and remaining < need:
            return (f"the run's request budget has {remaining} request(s) left; the plant, "
                    f"{reads} readback(s) and the restore need {need}")
        finding_id = getattr(finding, "finding_id", "") or ""
        if finding_id:
            gate = run.gate
            try:
                ceiling = gate._mutating_ceiling(self.name)
                used = gate._mutating_counts.get(finding_id, 0)
            except AttributeError:
                return ("the safety gate's mutating-send accounting cannot be read, so the "
                        "restore cannot be guaranteed")
            if ceiling - used < 2:
                return (f"the per-finding write ceiling allows {max(ceiling - used, 0)} more "
                        f"mutating send(s) ({used}/{ceiling} used); the plant and the restore "
                        f"need 2 (raise validators.mutating_ceiling_by_check.{self.name})")
        return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        targets = param_targets(exchange)[:_MAX_PARAMS]
        if not targets:
            return self._skip("no parameter to inject a template expression into")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        session_ref = None
        request_headers = headers
        if self.run_context is not None:
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)
        async def _send(send_method: str, send_url: str, *, send_body=None,
                        send_headers=None, redirects=0):
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                return await self.run_context.executor().execute(
                    TypedRequest(send_method, send_url, headers=send_headers or {}, body=send_body),
                    capability=self.name, session_ref=session_ref,
                    case_ref=finding.finding_id or "", max_redirects=redirects)
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name,
                                        timeout=self.timeout, follow_redirects=False,
                                        verify=False) as client:
                resp = await client.request(send_method, send_url,
                                            headers=send_headers or None,
                                            content=send_body)
            class _Outcome:
                executed = True
                ok = True
                outcome = "ok"
                body = resp.text
            return _Outcome()

        # A stored template setting can be written at one endpoint and evaluated
        # only when a different page renders.  Establish a negative control before
        # changing state, then require the product to appear on the same page after
        # the write.  Credential binding and scope checks remain in RunContext.
        readbacks = []
        if self.run_context is not None and method in ("POST", "PUT", "PATCH"):
            origin = f"{urlsplit(exchange.url).scheme}://{urlsplit(exchange.url).netloc}"
            readbacks = [u for u in self.readback_urls
                         if u.startswith(origin + "/") and u != exchange.url][:_MAX_READBACKS]
        baseline_product = {}
        for read_url in readbacks:
            out = await _send("GET", read_url, send_headers=request_headers, redirects=2)
            if out.ok:
                baseline_product[read_url] = _PRODUCT in (out.body or "")

        # R12: every attempt to put the captured request back is checked, and any that
        # failed is disclosed on whatever result this call returns.
        residual: list[str] = []
        last_plant = ""
        answered = 0

        async def _restore_original():
            """Replay the captured request. None when no stored plant is in play, else
            (restored, detail) from the send's outcome, never assumed."""
            if not readbacks:
                return None
            try:
                restore_outcome = await _send(method, exchange.url,
                                              send_body=exchange.request_body or None,
                                              send_headers=request_headers, redirects=2)
            except (SafetyGateBlocked, httpx.HTTPError) as exc:
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            else:
                ok, detail = _restore_succeeded(restore_outcome)
            if not ok:
                residual.append(detail)
            return ok, detail

        def _finish(result: ValidationResult) -> ValidationResult:
            if not residual:
                return result
            note = (f"RESIDUAL STATE: the original captured request was NOT restored "
                    f"({'; '.join(dict.fromkeys(residual))}). The target may still hold the "
                    f"injected value `{last_plant}` at {exchange.url} and the pages that render "
                    f"it; restore it manually.")
            return replace(result, summary=f"{result.summary} [{note.split(':')[0]}: original "
                                           f"setting NOT restored]",
                           evidence=f"{result.evidence} {note}".strip())

        for loc, param in targets:
            payloads = _payloads(secrets.token_hex(3))
            # Some preference fields hold an expression fragment (for example
            # `user.name`) that the server later places inside its own template
            # delimiters.  A plain arithmetic expression is the correct benign
            # probe for that shape; the baseline read above supplies its nonce-like
            # collision control.
            contextual = any(token in param.lower() for token in
                             ("template", "display", "format", "expression", "view"))
            if contextual and readbacks:
                payloads.insert(0, _EXPR)
            for payload in payloads:
                nonce = payload[:6]
                evaluated = f"{nonce}{_PRODUCT}{nonce}"
                if readbacks:
                    # R12: do not write a plant the run cannot afford to take back.
                    unaffordable = self._cleanup_unaffordable(
                        finding, len(readbacks) if payload == _EXPR else 0)
                    if unaffordable:
                        return _finish(ValidationResult(
                            self.name, "inconclusive" if answered else "blocked", "ssti",
                            confidence=0.0, confirmed=False,
                            summary=f"Stored SSTI check NOT completed: {unaffordable}, so the plant "
                                    f"would be written without a guaranteed restore and was refused. "
                                    f"This is not a negative result.",
                            evidence=f"{answered} plant(s) were sent and restored before the run "
                                     f"ran out of room to restore another."))
                url, body = mutate(exchange, loc, param, payload)
                last_plant = payload if readbacks else last_plant
                try:
                    outcome = await _send(method, url, send_body=body or None,
                                          send_headers=request_headers, redirects=2)
                    if not outcome.executed:
                        return _finish(self._skip(f"SSTI replay declined: {outcome.outcome}"))
                    if not outcome.ok:
                        # the plant may have landed even though no response came back
                        await _restore_original()
                        continue
                    text = outcome.body or ""
                except SafetyGateBlocked:
                    return _finish(self._skip("mutating SSTI replay not authorized "
                                              "(set validators.allow_mutating_replay)"))
                except httpx.HTTPError:
                    await _restore_original()
                    continue
                answered += 1
                if evaluated in text:
                    await _restore_original()
                    return _finish(ValidationResult(
                        self.name, "confirmed", "ssti", confidence=0.95, confirmed=True,
                        summary=f"SSTI confirmed: a template expression in the {loc} parameter {param!r} "
                                f"was evaluated server-side.",
                        evidence=f"Injected `{payload}`; the response contained the evaluated product "
                                 f"`{evaluated}` (not the literal `{_EXPR}`), proving template evaluation."))
                if payload == _EXPR and readbacks:
                    for read_url in readbacks:
                        rendered = await _send("GET", read_url,
                                               send_headers=request_headers, redirects=2)
                        if (rendered.ok and not baseline_product.get(read_url, False)
                                and _PRODUCT in (rendered.body or "")):
                            # Restore the captured setting before returning, and say
                            # only what the restore send actually achieved (R12).
                            restore = await _restore_original()
                            if restore and restore[0]:
                                replayed = (f"The original captured setting was replayed afterward "
                                            f"({restore[1]}).")
                            else:
                                replayed = (f"The original captured setting was NOT restored"
                                            f"{f' ({restore[1]})' if restore else ''}.")
                            return _finish(ValidationResult(
                                self.name, "confirmed", "ssti", confidence=0.95,
                                confirmed=True,
                                summary=(f"Stored SSTI confirmed: the {loc} parameter {param!r} "
                                         "was evaluated on a separate rendered page."),
                                evidence=(f"Baseline `{read_url}` lacked `{_PRODUCT}`; after saving "
                                          f"`{_EXPR}`, the rendered page contained `{_PRODUCT}`. "
                                          f"{replayed}")))
                await _restore_original()
        return _finish(ValidationResult(
            self.name, "not_confirmed", "ssti", confidence=0.0, confirmed=False,
            summary="No template expression was evaluated -- parameters are reflected literally, if at all",
            evidence=f"Tried {len(targets)} parameter(s) across {len(_SYNTAXES)} engine syntaxes; "
                     f"the arithmetic product never appeared between the nonce boundaries."))
