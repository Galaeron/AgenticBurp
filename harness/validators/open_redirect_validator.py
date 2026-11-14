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

An allowlisted redirect answers the four sentinel shapes with a refusal. When the
run has seen the endpoint redirect a GET parameter to an allowed external target
(the handed exchange, the run's own answers in RunContext.observations, or the
engagement's captures), that parameter also gets the textbook allowlist-bypass
shapes: the allowed URL in the query, fragment or path of a sentinel URL, and the
allowed host as the sentinel URL's userinfo. A check that matches the allowed URL
as a substring or prefix, rather than comparing the parsed host, accepts them.
The confirmation rule does not change: a redirect status whose Location's parsed
host is the sentinel. GET only.
"""
from __future__ import annotations
from harness import scope_lock

import re
from urllib.parse import urlsplit, parse_qsl

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.run_observations import allowed_redirect_targets
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import (param_targets, mutate, replay_headers, select_targets,
                                coverage_note, tested_inputs, NAMED_PARAMETER_UNTESTED)

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
# Allowed targets a parameter's bypass shapes are built from, and the captures
# scanned for them: a bound on the extra sends (4 per target).
_MAX_ALLOWED_TARGETS = 2
_MAX_CAPTURES_SCANNED = 2000


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


def _redirects_to_sentinel(resp, request_url: str) -> bool:
    """True when this response is a real redirect whose parsed destination host is
    the sentinel: the attack's own test, applied to the proof control."""
    return (resp.status_code in _REDIRECT_STATUSES
            and _destination_host(resp.headers.get("location", ""), request_url) == _SENTINEL_HOST)


def _location_of(headers) -> str:
    return next((str(v) for k, v in (headers or {}).items()
                 if str(k or "").lower() == "location"), "")


def _same_endpoint(a: str, b: str) -> bool:
    try:
        pa, pb = urlsplit(a), urlsplit(b)
    except ValueError:
        return False
    return ((pa.scheme or "").lower(), (pa.netloc or "").lower(), pa.path or "/") == \
        ((pb.scheme or "").lower(), (pb.netloc or "").lower(), pb.path or "/")


def _captured_answer(item) -> tuple[str, object, dict]:
    """(url, status, response headers) of one capture, an HttpExchange or a dict."""
    if isinstance(item, dict):
        return (str(item.get("url") or ""), item.get("response_status"),
                item.get("response_headers") or {})
    return (str(getattr(item, "url", "") or ""), getattr(item, "response_status", None),
            getattr(item, "response_headers", None) or {})


def _bypass_payloads(token: str, allowed: str) -> list[tuple[str, str]]:
    """(shape, payload): the sentinel URL with the allowed URL where a substring or
    prefix allowlist finds it but a browser does not navigate to it."""
    parts = urlsplit(allowed)
    scheme = (parts.scheme or "https").lower()
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    authority = host + (f":{port}" if port else "")
    out = [("allowed URL in the query", f"https://{_SENTINEL_HOST}/{token}?{allowed}"),
           ("allowed URL in the fragment", f"https://{_SENTINEL_HOST}/{token}#{allowed}")]
    if authority:
        out.append(("allowed host as userinfo", f"{scheme}://{authority}@{_SENTINEL_HOST}/{token}"))
    out.append(("allowed URL in the path", f"https://{_SENTINEL_HOST}/{token}/{allowed}"))
    return out


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

    def _allowed_targets(self, exchange: HttpExchange, param: str) -> list[str]:
        """The external URLs this endpoint was seen redirecting `param` to: from the
        handed exchange's own answer, the run's observed answers, and the
        engagement's captures of the same endpoint. Learned, never configured."""
        found: list[str] = []

        def add(pairs):
            for name, value in pairs:
                # This check's own confirmed redirects reach the observer too.
                if (name == param and value not in found and len(found) < _MAX_ALLOWED_TARGETS
                        and (urlsplit(value).hostname or "").lower() != _SENTINEL_HOST):
                    found.append(value)

        add(allowed_redirect_targets(exchange.url, exchange.response_status,
                                     _location_of(exchange.response_headers)))
        run = self.run_context
        observations = getattr(run, "observations", None)
        if observations is not None:
            try:
                add((param, v) for v in observations.redirect_targets(exchange.url, param))
            except Exception:
                pass
        context = getattr(run, "experiment_context", None)
        captured = (context.get("captured") if isinstance(context, dict) else None) or ()
        for item in list(captured)[:_MAX_CAPTURES_SCANNED]:
            if len(found) >= _MAX_ALLOWED_TARGETS:
                break
            url, status, headers = _captured_answer(item)
            if url and _same_endpoint(url, exchange.url):
                add(allowed_redirect_targets(url, status, _location_of(headers)))
        return found

    def _attempts(self, exchange: HttpExchange, method: str, loc: str, param: str
                  ) -> list[tuple[str, str]]:
        """(shape, payload) for one parameter: the four sentinel shapes, then, for a
        GET query parameter the run saw redirect to an allowed external target, the
        allowlist-bypass shapes built from each such target."""
        token = f"{loc}-{param}"
        out = [("", payload) for payload in self._payloads(token)]
        if method == "GET" and loc == "query":
            for allowed in self._allowed_targets(exchange, param):
                out += [(f"{shape} ({allowed})", payload)
                        for shape, payload in _bypass_payloads(token, allowed)]
        return out

    async def _proof_send(self, method: str, url: str, headers: dict, body: str):
        """One extra exchange a confirmation's proof names (Ticket 6); None when
        it got no response, and not sent outside a run (it would name nothing)."""
        if self.run_context is None:
            return None
        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                return await client.request(method, url, headers=headers or None, content=body or None)
        except (SafetyGateBlocked, httpx.HTTPError):
            return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {host!r} out of scope")
        shaped = _redirect_params(exchange)
        # No cap here: every redirect-shaped parameter is tried, plus the one the
        # finding names when it is not redirect-shaped.
        targets, coverage = select_targets(finding, shaped, len(shaped) + 1,
                                           available=param_targets(exchange))
        if not targets:
            if getattr(finding, "parameter_only", False):
                return ValidationResult(
                    self.name, "skipped", "open_redirect",
                    summary=f"the {finding.parameter_location or 'unnamed'} parameter "
                            f"{finding.parameter_name!r} is not a parameter of the replayed "
                            "request, so it was not tested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
            return self._skip("no redirect-shaped parameter to point off-origin")
        tested = tested_inputs(finding, targets)
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        candidate = ""  # sentinel reached Location, but no off-origin redirect
        # Sends that got no response: a check that never reached the target is
        # not a negative (RV-L L2). The gate's refusal stops the remaining sends.
        refused, errors, sends = "", [], 0
        bypass_tried = 0   # allowlist-bypass shapes sent (an observed allowed target)
        for loc, param in targets:
            for shape, payload in self._attempts(exchange, method, loc, param):
                if refused:
                    break
                url, body = mutate(exchange, loc, param, payload)
                sends += 1
                bypass_tried += 1 if shape else 0
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
                    # Proof exchanges: the original request replayed (baseline) and
                    # the same parameter set to an on-origin path (control).
                    baseline = await self._proof_send(method, exchange.url, headers,
                                                      exchange.request_body or "")
                    control_url, control_body = mutate(exchange, loc, param, f"/{loc}-{param}")
                    control = await self._proof_send(method, control_url, headers, control_body)
                    # Rules out a redirect the parameter does not control: the on-origin
                    # path must not reach the sentinel host. Unsent or redirecting, it names nothing.
                    if control is not None and _redirects_to_sentinel(control, control_url):
                        control = None
                    bypass = (f" The parameter's allowlist accepted it: {shape}, so the check "
                              f"matches the allowed URL as text, not the parsed host."
                              if shape else "")
                    return ValidationResult(
                        self.name, "confirmed", "open_redirect", confidence=0.9, confirmed=True,
                        summary=f"Open redirect confirmed: the {loc} parameter {param!r} controls the "
                                f"Location the server redirects to.",
                        evidence=f"Set {param!r} to `{payload}`; the server responded with HTTP "
                                 f"{resp.status_code}, a redirect to the off-origin sentinel host "
                                 f"{_SENTINEL_HOST!r} (Location: {location}).{bypass}",
                        tested_parameters=tested,
                    ).with_artifacts(baseline=baseline, attack=resp, controls=[control])
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
            evidence=f"Tried {len(targets)} parameter(s) "
                     f"({', '.join(repr(p) for _l, p in targets)}); no Location pointed at the sentinel host."
                     + (f" {bypass_tried} allowlist-bypass shape(s), built from an allowed external "
                        f"target the endpoint was seen redirecting to, were refused too."
                        if bypass_tried else "")
                     + coverage_note(coverage, finding),
            control_outcome=coverage, tested_parameters=tested)
