"""
SSRF confirmation leg (deterministic, OOB via the in-process collaborator).

The ssrf agent can only GUESS that a URL-shaped parameter is server-side-fetched.
This proves it: replace the parameter's value with a unique collaborator URL,
send the request, and watch for the target to CALL BACK. A callback is proof the
server fetched an attacker-controlled URL -- confirmed SSRF -- with zero reliance
on the response body (blind SSRF included). A response that merely differs between
a served and a closed loopback target is reported as a candidate, not confirmed.

Targets URL-shaped parameters (by name -- url/uri/target/webhook/callback/... --
or by value shape -- an http(s):// value). Scope-gated; sends the request the
capture already used (this is active testing, gated by validators.active_enabled).
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, parse_qsl, unquote, quote

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import SentAnswer, Validator, ValidationResult, artifact_id_of
from .injection_targets import (param_targets, select_targets, coverage_note, tested_inputs,
                                NAMED_PARAMETER_UNTESTED)
from harness.validators.sqlmap import (_mutate_query_param, _mutate_json_param, _mutate_form_param,
                               _looks_like_json, _content_type_of)

_URL_PARAM_NAMES = {"url", "uri", "target", "callback", "webhook", "dest", "destination",
                    "fetch", "link", "src", "source", "host", "endpoint", "proxy", "feed",
                    "image", "img", "avatar", "resource", "redirect", "next", "return",
                    "remote", "address", "upstream", "site", "domain", "server", "u", "hook"}
_URL_VALUE = re.compile(r"^https?://", re.IGNORECASE)

# Transport failures after the request was written: the response was lost, but
# the server may still have fetched the callback URL, so an out-of-band send
# that fails this way still waits for its callback (RV-O O5). A send that never
# connected (ConnectError, ConnectTimeout, a refusal) is not waited on.
_DELIVERED = ("ReadTimeout", "ReadError", "RemoteProtocolError")

# Connection-failure signatures a server-side fetcher surfaces when its target is
# unreachable. Their presence/absence across two loopback targets is one candidate
# signal that the response depended on the fetch outcome (never proof on its own).
_FETCH_ERROR_TOKENS = (
    "connection refused", "connection reset", "could not connect", "failed to connect",
    "connection aborted", "econnrefused", "no route to host", "network is unreachable",
    "timed out", "timeout", "could not resolve", "name or service not known",
)


def _strip_all(text: str, subs) -> str:
    """Remove every occurrence of each substring -- used to delete an echoed URL
    from a response so a plain reflection cannot look like a fetch difference."""
    for s in subs:
        if s:
            text = text.replace(s, "")
    return text


def _fetch_outcome_differs(status_a: int | None, body_a: str,
                           status_c: int | None, body_c: str) -> bool:
    """True when two same-host/different-port SSRF probes produced responses that
    differ after the echoed URL is stripped from both bodies. A real fetch causes
    this, but so does an app that validates the URL and rejects one of the ports
    (R17), so a difference is a candidate signal, never proof of a fetch."""
    if status_a != status_c:
        return True
    if body_a == body_c:
        return False
    if abs(len(body_a) - len(body_c)) >= 16:
        return True
    low_a, low_c = body_a.lower(), body_c.lower()
    err_a = any(t in low_a for t in _FETCH_ERROR_TOKENS)
    err_c = any(t in low_c for t in _FETCH_ERROR_TOKENS)
    return err_a != err_c


def _candidate_params(exchange: HttpExchange) -> list[tuple[str, str]]:
    """[(location, param)] worth swapping with a callback URL -- URL-shaped by
    name or by value, in the query and the JSON/form body."""
    out: list[tuple[str, str]] = []
    for k, v in parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True):
        if k.lower() in _URL_PARAM_NAMES or _URL_VALUE.match(v or ""):
            out.append(("query", k))
    body = exchange.request_body or ""
    if _looks_like_json(body, _content_type_of(exchange)):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower() in _URL_PARAM_NAMES or (isinstance(v, str) and _URL_VALUE.match(v)):
                        out.append(("body", k))
        except (ValueError, json.JSONDecodeError):
            pass
    else:
        for pair in body.split("&"):
            k, _, v = pair.partition("=")
            # Match a form-body param by name OR by value shape, symmetric with
            # the query/JSON branches above. A url-encoded http(s):// value
            # (e.g. stockApi=http%3A%2F%2F... on a stock-check form) is a URL
            # sink even when its NAME is not in the known-name list.
            if k.lower() in _URL_PARAM_NAMES or _URL_VALUE.match(unquote(v or "")):
                out.append(("body", k))
    return out


class SsrfValidator(Validator):
    name = "ssrf"
    finding_classes = {"ssrf", "server_side_request_forgery"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None, oob_callbacks_enabled: bool = True):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator
        self.oob_callbacks_enabled = bool(oob_callbacks_enabled)

    def collab(self):
        return _collab.resolve(self._collab)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(_candidate_params(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "ssrf", summary=why)

    def _mutated(self, exchange: HttpExchange, loc: str, param: str, value: str):
        url, body = exchange.url, (exchange.request_body or "")
        if loc == "query":
            url = _mutate_query_param(url, param, value) or url
        elif _looks_like_json(body, _content_type_of(exchange)):
            body = _mutate_json_param(body, param, value) or body
        else:
            body = _mutate_form_param(body, param, value) or body
        return url, body

    async def _send(self, method: str, url: str, headers: dict, body: str,
                    unsent: list | None = None, label: str = ""):
        """Send one replay through the safety gate; return (status, text) or None
        when the gate blocks it or the request errors, recording why in `unsent`
        as ("blocked" | "delivered" | "error", description), "delivered" being a
        failure after the request was written. Read-only from the target's
        perspective -- it never posts to a destructive path, only swaps a URL value."""
        try:
            await global_throttle.acquire()
            from harness.run_context import current_run_context
            run = current_run_context()
            if run is not None:
                return await self._send_in_run(run, method, url, headers, body, unsent, label)
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request(method, url, headers=headers or None,
                                            content=body or None)
            return SentAnswer((resp.status_code, (resp.text or "")), artifact_id_of(resp))
        except SafetyGateBlocked as e:
            if unsent is not None:
                unsent.append(("blocked", f"{label}: refused ({e.decision.reason})"))
            return None
        except httpx.HTTPError as e:
            self._record_failure(unsent, label, e.__class__.__name__)
            return None

    async def _proof_send(self, method: str, url: str, headers: dict, body: str, label: str):
        """One extra exchange a confirmation's proof names (Ticket 6): the answer,
        or None when it got none. Best effort -- any failure leaves that artifact
        unnamed and never changes the verdict the callback already established."""
        try:
            return await self._send(method, url, headers, body, None, label)
        except Exception:
            return None

    @staticmethod
    def _record_failure(unsent: list | None, label: str, failure: str) -> None:
        if unsent is not None:
            unsent.append(("delivered" if failure in _DELIVERED else "error", f"{label}: {failure}"))

    async def _send_in_run(self, run, method: str, url: str, headers: dict, body: str,
                           unsent: list | None, label: str):
        """The path GatedAsyncClient takes inside an entered run, taken here
        because GatedAsyncClient reports every run transport failure as a
        ConnectError, and a lost response must be told apart from a refused
        connection. Same policy: the default gate when it is not the run's own,
        then the run transport's scope, gate and budget."""
        url = str(httpx.URL(url))
        gate = get_default_gate()
        if gate is not run.gate:
            decision = gate.authorize(validator_name=self.name, method=method, url=url,
                                      body=body or None)
            if not decision.allowed:
                raise SafetyGateBlocked(decision)
        outcome = await run.target_transport().send_creds(
            method, url, capability=self.name, headers=dict(headers or {}), body=body or None,
            max_redirects=0)
        if outcome.ok:
            return SentAnswer((outcome.status or 0, (outcome.body or "")), outcome.artifact_id)
        if outcome.outcome == "error":
            failure = getattr(outcome.artifact, "transport_outcome", "").partition(":")[2]
            self._record_failure(unsent, label, failure or "transport error")
        elif unsent is not None:
            unsent.append(("blocked", f"{label}: refused (run transport refused the send: "
                                      f"{outcome.outcome}"
                                      + (f" ({outcome.error})" if outcome.error else "") + ")"))
        return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        from harness.scope_lock import host_in_scope
        if self.allowed_hosts and not host_in_scope(exchange.url, self.allowed_hosts, active_mode=True):
            return self._skip("target origin is out of scope")
        shaped = _candidate_params(exchange)
        # Every URL-shaped parameter is tried (no cap), plus the one the finding
        # names when it is not URL-shaped; a per-parameter dispatch tries only it.
        cands, coverage = select_targets(finding, shaped, len(shaped) + 1,
                                         available=param_targets(exchange))
        if not cands:
            if getattr(finding, "parameter_only", False):
                return ValidationResult(
                    self.name, "skipped", "ssrf",
                    summary=f"the {finding.parameter_location or 'unnamed'} parameter "
                            f"{finding.parameter_name!r} is not a parameter of the replayed "
                            "request, so it was not tested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
            return self._skip("no URL-shaped parameter to redirect to a collaborator")
        tested = tested_inputs(finding, cands)
        if not self.oob_callbacks_enabled:
            # The in-band differential uses alternate loopback ports as fetch
            # controls. Those are separate services outside an exact target
            # origin's authorization too, so disabled callback policy skips the
            # entire SSRF leg before sending any probes or opening a listener.
            return ValidationResult(
                self.name, "inconclusive", "ssrf", confidence=0.0, confirmed=False,
                summary="SSRF check incomplete: its alternate-host probes and out-of-band callbacks are disabled by policy",
                evidence=("This check requires a separately authorized internal-service or callback target. "
                          "No SSRF probe was sent and no callback listener was opened."))
        collab = self.collab()
        method = (exchange.method or "GET").upper()
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}
        # 1) In-band differential: fast (two loopback reads) and needs no reachable
        #    collaborator, but it is a CANDIDATE signal only (R17). An app that
        #    merely validates URL syntax (rejects port 1, accepts port 80) answers
        #    the two probes differently without ever making a request.
        # Every send that got no response, as ("blocked" | "error", description):
        # a check that never reached the target is not a negative (RV-L L1).
        unsent: list[tuple[str, str]] = []
        sends = 0
        inband = await self._inband_differential(exchange, cands, method, headers, unsent)
        sends += 2 * len(cands[:2])
        # 2) Out-of-band proof: the target calling back to a unique collaborator
        #    URL is independent fetch evidence (blind SSRF included).
        for loc, param in cands:
            token = collab.token()
            url, body = self._mutated(exchange, loc, param, collab.url(token))
            sends += 1
            # Routes the (possibly mutating) replay through the safety gate --
            # a non-GET send needs the allow_mutating_replay opt-in.
            reply = await self._send(method, url, headers, body, unsent,
                                     f"out-of-band send via {loc} {param!r}")
            if reply is None and unsent[-1][0] != "delivered":
                continue  # never reached the target: no callback to wait for
            if await collab.wait_for_hit(token, timeout=self.timeout):
                lost = (f" The send itself got no response ({unsent[-1][1].rpartition(': ')[2]}), "
                        f"but the callback shows the request was delivered." if reply is None else "")
                # Ticket 6 proof exchanges: the original request replayed (baseline)
                # and the same parameter pointed at a closed loopback port, a URL
                # that is not the collaborator (control). Neither is a verdict input.
                baseline = control = None
                if self.run_context is not None:  # outside a run they would name nothing
                    baseline = await self._proof_send(method, exchange.url, headers,
                                                      exchange.request_body or "", "proof baseline")
                    ctrl_url, ctrl_body = self._mutated(exchange, loc, param, self._INBAND_CLOSED)
                    # Rules out the request alone causing the callback; named only if answered.
                    control = await self._proof_send(method, ctrl_url, headers, ctrl_body,
                                                     "proof control")
                return ValidationResult(
                    self.name, "confirmed", "ssrf", confidence=0.95, confirmed=True,
                    summary=f"SSRF confirmed: the server fetched an attacker-controlled URL placed in "
                            f"the {loc} parameter {param!r}.",
                    evidence=f"Set {loc} param {param!r} to a unique collaborator URL; the target called "
                             f"back to it out-of-band, proving server-side request forgery (blind-safe)."
                             + lost, tested_parameters=tested).with_artifacts(baseline=baseline, attack=reply, controls=[control])
            if reply is None:
                kind, why = unsent[-1]
                unsent[-1] = (kind, f"{why} after the request was sent; no callback within "
                                    f"{self.timeout:g}s")
        failed = "; ".join(w for _, w in unsent[:4])
        if inband is not None:
            return ValidationResult(
                self.name, "inconclusive", "ssrf", confidence=0.4, confirmed=False,
                summary="SSRF candidate (unconfirmed): the response depends on the URL supplied, "
                        "but no request from the target was observed",
                evidence=inband + " A server that only validates the URL (for example, rejects "
                                  "some ports) answers the same way without fetching anything, "
                                  "and no collaborator callback arrived. Confirm manually or with "
                                  "a collaborator the target can reach."
                         + (f" Sends that got no response: {failed}." if unsent else ""))
        if unsent:
            answered = sends - len(unsent)
            refused = any(kind == "blocked" for kind, _ in unsent)
            return ValidationResult(
                self.name, "blocked" if refused and not answered else "inconclusive", "ssrf",
                confidence=0.0, confirmed=False,
                summary=f"SSRF check incomplete: {len(unsent)} of {sends} send(s) got no response "
                        f"({failed}); not a negative result",
                evidence=f"Tried {len(cands)} URL-shaped parameter(s); no collaborator hit was seen, "
                         f"but a send that never reached the target cannot show one.")
        unavailable = _collab.unavailable_result(collab, exchange.url, self.name, "ssrf")
        if unavailable is not None:
            return unavailable
        return ValidationResult(
            self.name, "not_confirmed", "ssrf", confidence=0.0, confirmed=False,
            summary="No out-of-band callback and no in-band fetch differential observed",
            evidence=f"Tried {len(cands)} parameter(s) "
                     f"({', '.join(repr(p) for _l, p in cands)}); no collaborator hit and the "
                     f"response did not depend on internal-target reachability."
                     + coverage_note(coverage, finding),
            control_outcome=coverage, tested_parameters=tested)

    # A served vs a closed loopback port on the same host: identical URL strings
    # (so echo cancels), differing only in whether a server-side fetch succeeds.
    _INBAND_REACHABLE = "http://127.0.0.1:80/"
    _INBAND_CLOSED = "http://127.0.0.1:1/"

    async def _inband_differential(self, exchange, cands, method, headers, unsent=None):
        """Evidence text when a served vs a closed loopback target change the
        response (after removing the echoed URL), else None. Candidate only.
        Sends that got no response are recorded in `unsent`."""
        for loc, param in cands[:2]:  # bound the request budget
            ra_url, ra_body = self._mutated(exchange, loc, param, self._INBAND_REACHABLE)
            rc_url, rc_body = self._mutated(exchange, loc, param, self._INBAND_CLOSED)
            a = await self._send(method, ra_url, headers, ra_body, unsent,
                                 f"in-band read via {loc} {param!r}")
            c = await self._send(method, rc_url, headers, rc_body, unsent,
                                 f"in-band read via {loc} {param!r}")
            if a is None or c is None:
                continue
            (sa, ta), (sc, tc) = a, c
            # Strip the submitted URLs (raw, url-encoded) and the shared loopback
            # host, so a plain echo of the input -- in any encoding -- cannot
            # masquerade as a fetch-outcome difference. Fetched CONTENT does not
            # contain these, so a real SSRF's differential survives.
            echoes = (self._INBAND_REACHABLE, self._INBAND_CLOSED,
                      quote(self._INBAND_REACHABLE, safe=""), quote(self._INBAND_CLOSED, safe=""),
                      quote(self._INBAND_REACHABLE), quote(self._INBAND_CLOSED), "127.0.0.1")
            na = _strip_all(ta, echoes)
            nc = _strip_all(tc, echoes)
            if _fetch_outcome_differs(sa, na, sc, nc):
                return (f"Pointing the {loc} parameter {param!r} at a served loopback port vs a "
                        f"closed one produced different responses (HTTP {sa} vs {sc}; body "
                        f"{len(na)} vs {len(nc)} bytes after removing the echoed URL).")
        return None
