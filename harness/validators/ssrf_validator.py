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
from urllib.parse import urlsplit, parse_qsl

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
            k = pair.split("=", 1)[0]
            if k.lower() in _URL_PARAM_NAMES:
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
            summary="No out-of-band callback observed",
            evidence=f"Tried {len(cands)} URL-shaped parameter(s); no collaborator hit within the window.")
