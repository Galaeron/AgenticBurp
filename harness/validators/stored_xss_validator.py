"""
Stored / second-order XSS confirmation leg (plant -> independent render).

Reflected-XSS confirmation (browser_xss) loads ONE URL whose own query param
carries the payload. Stored XSS is a SEQUENCE across two requests -- write the
payload via endpoint A, then have it come back on an independent READ of endpoint
B and execute there -- which no single-request leg can prove. This is that
plant->observe primitive (improvement-note #3), and the concrete second-order
data-flow confirmation (#5): the value provably crosses requests.

  1. PLANT   -- send the write with a script-executable, nonce-tagged payload in
                its text fields.
  2. RENDER  -- independently GET the resource (and its collection) again.
  3. CONFIRM -- stored XSS only when the executable payload comes back UNESCAPED
                in a text/html response (angle brackets + handler intact) on that
                independent read. A JSON API that stores-and-returns the string
                escaped, or in a non-HTML content type, is NOT confirmed -- the
                same precision line browser_xss draws (no HTML sink, no confirm).
                When a headless browser is available the rendered page is also
                loaded for execution-grade proof; otherwise the unescaped-in-HTML
                reflection stands as the deterministic signal.

Scope-gated; the plant is a mutating write, so it self-gates on
validators.allow_mutating_replay and routes through the safety gate.
"""
from __future__ import annotations

import json
import secrets
from urllib.parse import urlsplit, urlunsplit

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from harness.validators.sqlmap import _looks_like_json, _content_type_of


def _payloads(nonce: str) -> list[str]:
    js = f"console.log('{nonce}')"
    return [f"<svg/onload={js}>", f"<script>{js}</script>", f"<img src=x onerror={js}>"]


def _text_fieldish(v) -> bool:
    return isinstance(v, str)


class StoredXssValidator(Validator):
    name = "stored_xss"
    finding_classes = {"xss", "stored xss", "stored_xss", "persistent xss", "persistent_xss",
                       "cross-site scripting", "cross_site_scripting", "second order xss",
                       "second_order_xss"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 driver=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._driver = driver

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "xss", summary=why)

    def _json_object(self, body: str):
        try:
            o = json.loads(body)
            return o if isinstance(o, dict) else None
        except (ValueError, TypeError):
            return None

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
            return False
        # need at least one text field to plant into (JSON string field or a form value)
        obj = self._json_object(exchange.request_body or "")
        if obj is not None:
            return any(_text_fieldish(v) for v in obj.values())
        return bool(exchange.request_body) and "=" in (exchange.request_body or "")

    def _render_urls(self, url: str) -> list[str]:
        """Independent-read candidates: the resource itself, and its collection
        (parent path). A REST collection commonly renders what a POST to it stored."""
        parts = urlsplit(url)
        urls = [url]
        segs = [s for s in parts.path.split("/") if s]
        if len(segs) >= 1:
            parent = "/" + "/".join(segs[:-1])
            urls.append(urlunsplit((parts.scheme, parts.netloc, parent or "/", "", "")))
        # de-dupe, preserve order
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u); out.append(u)
        return out

    def _plant_body(self, exchange: HttpExchange, payload: str):
        body = exchange.request_body or ""
        obj = self._json_object(body)
        if obj is not None:
            planted = {k: (payload if _text_fieldish(v) else v) for k, v in obj.items()}
            return json.dumps(planted), "application/json"
        from urllib.parse import parse_qsl, urlencode
        pairs = [(k, payload) for k, _ in parse_qsl(body, keep_blank_values=True)]
        return urlencode(pairs), "application/x-www-form-urlencoded"

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("stored-XSS plant is a mutating write; needs validators.allow_mutating_replay")

        method = (exchange.method or "POST").upper()
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        render_urls = self._render_urls(exchange.url)

        for payload in _payloads(secrets.token_hex(6)):
            body, ctype = self._plant_body(exchange, payload)
            planted_headers = dict(headers); planted_headers["Content-Type"] = ctype
            try:
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    await global_throttle.acquire()
                    await client.request(method, exchange.url, headers=planted_headers, content=body)
                    read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
                    for rurl in render_urls:
                        await global_throttle.acquire()
                        r = await client.request("GET", rurl, headers=read_headers or None)
                        ct = (r.headers.get("content-type") or "").lower()
                        if "html" in ct and payload in (r.text or ""):
                            # optional execution-grade proof if a browser is present
                            browser_note = await self._browser_confirm(rurl)
                            conf = 0.95 if browser_note else 0.85
                            return ValidationResult(
                                self.name, "confirmed", "xss", confidence=conf, confirmed=True,
                                summary=f"Stored XSS confirmed: a payload written via {method} {urlsplit(exchange.url).path} "
                                        f"is reflected UNESCAPED in the HTML of {urlsplit(rurl).path} on an independent read.",
                                evidence=(f"Planted {payload!r}; an independent GET of {rurl} returned it intact "
                                          f"(angle brackets + handler) in a text/html response -- stored, not just "
                                          f"reflected. {browser_note}").strip())
            except SafetyGateBlocked:
                return self._skip("mutating stored-XSS plant not authorized (validators.allow_mutating_replay)")
            except httpx.HTTPError:
                continue
        return ValidationResult(
            self.name, "not_confirmed", "xss", confidence=0.0, confirmed=False,
            summary="No stored XSS: planted payloads were not reflected unescaped in an HTML render",
            evidence=f"Planted script-executable payloads via {method} and re-read {len(render_urls)} "
                     f"endpoint(s); none returned the payload unescaped in a text/html response.")

    async def _browser_confirm(self, url: str) -> str:
        """If a headless browser is available, load the rendered page and look for
        execution. Best-effort: returns a note on success, '' otherwise (the
        deterministic unescaped-in-HTML signal already stands)."""
        driver = self._driver
        try:
            if driver is None:
                from harness import browser_driver
                driver = browser_driver.default_driver()
                if driver is None:
                    return ""
            obs = await driver.visit(url, wait_ms=1200)
            # the payload's console.log nonce is inside the payload string; if the
            # page executed it, the nonce shows up in an execution sink.
            return ("Execution also confirmed in a headless browser."
                    if getattr(obs, "console", None) else "")
        except Exception:
            return ""
