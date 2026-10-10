"""
SSRF confirmation leg (deterministic, OOB via the in-process collaborator).

The ssrf agent can only GUESS that a URL-shaped parameter is server-side-fetched.
This proves it: replace the parameter's value with a unique collaborator URL,
send the request, and watch for the target to CALL BACK. A callback is proof the
server fetched an attacker-controlled URL -- confirmed SSRF -- with zero reliance
on the response body (blind SSRF included).

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
from .base import Validator, ValidationResult
from harness.validators.sqlmap import (_mutate_query_param, _mutate_json_param, _mutate_form_param,
                               _looks_like_json, _content_type_of)

_URL_PARAM_NAMES = {"url", "uri", "target", "callback", "webhook", "dest", "destination",
                    "fetch", "link", "src", "source", "host", "endpoint", "proxy", "feed",
                    "image", "img", "avatar", "resource", "redirect", "next", "return",
                    "remote", "address", "upstream", "site", "domain", "server", "u", "hook"}
_URL_VALUE = re.compile(r"^https?://", re.IGNORECASE)

# Connection-failure signatures a server-side fetcher surfaces when its target is
# unreachable. Their presence/absence across two loopback targets is one signal
# that the response depended on the fetch outcome (i.e. a real SSRF).
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
    differ in a way only a real server-side fetch explains. The echoed URL has
    already been stripped from both bodies, and both targets are syntactically
    identical bar the port, so an app that merely validates the URL returns the
    same thing for both -- a difference means the server actually connected."""
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
                 collaborator=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator

    def collab(self):
        return self._collab or _collab.shared()

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

    async def _send(self, method: str, url: str, headers: dict, body: str):
        """Send one replay through the safety gate; return (status, text) or None
        when the gate blocks it or the request errors. Read-only from the target's
        perspective -- it never posts to a destructive path, only swaps a URL value."""
        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request(method, url, headers=headers or None,
                                            content=body or None)
            return resp.status_code, (resp.text or "")
        except SafetyGateBlocked:
            return None
        except httpx.HTTPError:
            return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        cands = _candidate_params(exchange)
        if not cands:
            return self._skip("no URL-shaped parameter to redirect to a collaborator")
        collab = self.collab()
        method = (exchange.method or "GET").upper()
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}
        # 1) In-band differential proof first: fast (two loopback reads), needs no
        #    reachable collaborator, and works on labs/egress-filtered targets.
        inband = await self._inband_confirm(exchange, cands, method, headers)
        if inband is not None:
            return inband
        # 2) Out-of-band proof: catches BLIND SSRF (no response differential) when
        #    a collaborator is reachable.
        for loc, param in cands:
            token = collab.token()
            url, body = self._mutated(exchange, loc, param, collab.url(token))
            try:
                await global_throttle.acquire()
                # Routes the (possibly mutating) replay through the safety gate --
                # a non-GET send needs the allow_mutating_replay opt-in.
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    await client.request(method, url, headers=headers or None, content=body or None)
            except SafetyGateBlocked:
                continue  # mutating replay not authorized -- skip this candidate
            except httpx.HTTPError:
                continue
            if await collab.wait_for_hit(token, timeout=self.timeout):
                return ValidationResult(
                    self.name, "confirmed", "ssrf", confidence=0.95, confirmed=True,
                    summary=f"SSRF confirmed: the server fetched an attacker-controlled URL placed in "
                            f"the {loc} parameter {param!r}.",
                    evidence=f"Set {loc} param {param!r} to a unique collaborator URL; the target called "
                             f"back to it out-of-band, proving server-side request forgery (blind-safe).")
        return ValidationResult(
            self.name, "not_confirmed", "ssrf", confidence=0.0, confirmed=False,
            summary="No out-of-band callback and no in-band fetch differential observed",
            evidence=f"Tried {len(cands)} URL-shaped parameter(s); no collaborator hit and the "
                     f"response did not depend on internal-target reachability.")

    # A served vs a closed loopback port on the same host: identical URL strings
    # (so echo cancels), differing only in whether a server-side fetch succeeds.
    _INBAND_REACHABLE = "http://127.0.0.1:80/"
    _INBAND_CLOSED = "http://127.0.0.1:1/"

    async def _inband_confirm(self, exchange, cands, method, headers):
        for loc, param in cands[:2]:  # bound the request budget
            ra_url, ra_body = self._mutated(exchange, loc, param, self._INBAND_REACHABLE)
            rc_url, rc_body = self._mutated(exchange, loc, param, self._INBAND_CLOSED)
            a = await self._send(method, ra_url, headers, ra_body)
            c = await self._send(method, rc_url, headers, rc_body)
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
                return ValidationResult(
                    self.name, "confirmed", "ssrf", confidence=0.8, confirmed=True,
                    summary=f"SSRF confirmed (in-band): the server fetched the URL in the {loc} "
                            f"parameter {param!r}; its response depended on the internal target.",
                    evidence=(f"Pointing {param!r} at a served loopback port vs a closed one produced "
                              f"different responses (HTTP {sa} vs {sc}; body {len(na)} vs {len(nc)} "
                              f"bytes after removing the echoed URL). Only a server-side fetch makes "
                              f"the response depend on internal reachability. No application path or "
                              f"state-changing action was touched."))
        return None
