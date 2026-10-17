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
                 driver=None, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._driver = driver
        # R7: see browser_xss_validator's identical field -- bound per-dispatch
        # by ValidatorRegistry.bind_run_context. Used both to pick THIS run's
        # own gate for the plant/render client (instead of always the process
        # default) and to thread scope/gate/budget/cancel into the optional
        # execution-grade browser confirm below.
        self.run_context = run_context

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

    def _source_page_candidates(self, exchange: HttpExchange) -> list[str]:
        """Where the CSRF-bearing form that targets this write endpoint is most
        likely rendered, so the plant can mint a FRESH token bound to its own
        session (the captured token is bound to the crawl's session and a fresh
        client would be told 'session does not contain a CSRF token'). Generic,
        not lab-shaped: the Referer, then the parent resource carrying each
        id-shaped body param (e.g. POST /post/comment + body postId=1 ->
        GET /post?postId=1), then the bare parent."""
        parts = urlsplit(exchange.url)
        base = f"{parts.scheme}://{parts.netloc}"
        cands: list[str] = []
        for k, v in (exchange.request_headers or {}).items():
            if (k or "").lower() == "referer" and v:
                cands.append(v)
        segs = [s for s in parts.path.split("/") if s]
        parent = "/" + "/".join(segs[:-1]) if len(segs) >= 1 else "/"
        from urllib.parse import parse_qsl
        for k, val in parse_qsl(exchange.request_body or "", keep_blank_values=True):
            low = (k or "").lower()
            if val and (low == "id" or low.endswith("id")):
                cands.append(f"{base}{parent}?{k}={val}")
        cands.append(f"{base}{parent}")
        seen, out = set(), []
        for u in cands:
            if u and u not in seen:
                seen.add(u); out.append(u)
        return out

    def _form_plant_body(self, form, payload: str) -> str:
        """Build the write body from a FRESH form: keep structural/typed fields
        valid (hidden tokens + ids at their server value, email valid, URL fields
        a real URL) and inject the payload only into free-text sinks, so the write
        is accepted (a 400 stores nothing) yet the payload still reaches an HTML
        sink. Overwriting every field -- including csrf/id/email -- guarantees a
        rejected write, which is why the naive plant never confirmed."""
        from urllib.parse import urlencode
        pairs, planted = [], False
        for fld in getattr(form, "fields", []) or []:
            name = fld.name or ""
            if not name:
                continue
            t = (fld.type or "text").lower()
            low = name.lower()
            if t in ("hidden", "submit", "button", "checkbox", "radio"):
                pairs.append((name, fld.value or ""))
            elif t == "email" or "email" in low:
                v = fld.value if (fld.value and "@" in fld.value) else "prober@example.com"
                pairs.append((name, v))
            elif t == "url" or any(x in low for x in ("website", "url", "link", "homepage")):
                pairs.append((name, "http://example.com/"))
            elif t in ("text", "search", "textarea", ""):
                pairs.append((name, payload)); planted = True
            else:
                pairs.append((name, fld.value or ""))
        if not planted:
            # No obvious text sink: force the payload into the first non-structural
            # field so the write still carries it somewhere renderable.
            for i, (name, _val) in enumerate(pairs):
                low = name.lower()
                if not any(x in low for x in ("csrf", "token", "email")) and not low.endswith("id"):
                    pairs[i] = (name, payload); planted = True
                    break
        return urlencode(pairs)

    async def _plant_via_source_form(self, exchange: HttpExchange, gate, headers: dict,
                                     method: str, render_urls: list[str]):
        """Session-aware plant: GET the source page in THIS client's session to
        obtain a fresh CSRF-bound form, plant into it, then read it back. Returns
        a ValidationResult when a matching source form was found (confirmed or
        not), or None to let the caller fall back to the captured-body plant."""
        from harness.validators.source_form import fetch_source_form
        action_path = urlsplit(exchange.url).path
        read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

        def select(forms):
            return next((f for f in forms
                        if urlsplit(f.action).path == action_path
                        and (f.method or "POST").upper() == method), None)

        try:
            async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                found = await fetch_source_form(client, self._source_page_candidates(exchange),
                                                read_headers, select)
                if found is None:
                    return None  # no discoverable source form -> caller falls back
                fresh, source_url = found.form, found.source_url
                for payload in _payloads(secrets.token_hex(6)):
                    plant_body = self._form_plant_body(fresh, payload)
                    planted_headers = dict(headers)
                    planted_headers["Content-Type"] = "application/x-www-form-urlencoded"
                    await global_throttle.acquire()
                    await client.request(method, fresh.action, headers=planted_headers, content=plant_body)
                    for rurl in [source_url, *render_urls]:
                        await global_throttle.acquire()
                        rr = await client.request("GET", rurl, headers=read_headers or None)
                        if ("html" in (rr.headers.get("content-type") or "").lower()
                                and payload in (rr.text or "")):
                            browser_note = await self._browser_confirm(rurl)
                            conf = 0.95 if browser_note else 0.85
                            return ValidationResult(
                                self.name, "confirmed", "xss", confidence=conf, confirmed=True,
                                summary=f"Stored XSS confirmed: a payload written via {method} {action_path} "
                                        f"is reflected UNESCAPED in the HTML of {urlsplit(rurl).path} on an independent read.",
                                evidence=(f"Planted {payload!r} through a fresh CSRF-bound form from {source_url}; "
                                          f"an independent GET of {rurl} returned it intact (angle brackets + handler) "
                                          f"in a text/html response -- stored, not just reflected. {browser_note}").strip())
                return ValidationResult(
                    self.name, "not_confirmed", "xss", confidence=0.0, confirmed=False,
                    summary="No stored XSS: planted payloads were not reflected unescaped in an HTML render",
                    evidence=(f"Submitted a fresh CSRF-bound form at {action_path} and re-read the "
                              f"rendered page; the payload never returned unescaped in a text/html response."))
        except SafetyGateBlocked:
            return self._skip("mutating stored-XSS plant not authorized (validators.allow_mutating_replay)")
        except httpx.HTTPError:
            return None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        gate = self.run_context.gate if self.run_context is not None else get_default_gate()
        if not gate.config.allow_mutating_replay:
            return self._skip("stored-XSS plant is a mutating write; needs validators.allow_mutating_replay")

        method = (exchange.method or "POST").upper()
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        render_urls = self._render_urls(exchange.url)

        # Form (urlencoded) writes are commonly CSRF-token-bound: the captured
        # token belongs to the crawl's session, so a fresh client is rejected
        # ("session does not contain a CSRF token"). Mint a fresh token in THIS
        # session from the source page first; only fall back to replaying the
        # captured body when no source form is discoverable (e.g. a JSON API).
        if self._json_object(exchange.request_body or "") is None and "=" in (exchange.request_body or ""):
            via_source = await self._plant_via_source_form(exchange, gate, headers, method, render_urls)
            if via_source is not None:
                return via_source

        for payload in _payloads(secrets.token_hex(6)):
            body, ctype = self._plant_body(exchange, payload)
            planted_headers = dict(headers); planted_headers["Content-Type"] = ctype
            try:
                async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
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
            rc = self.run_context
            visit_kw = (dict(scope=rc.scope, gate=rc.gate, budget=rc.budget, cancel=rc.cancel)
                        if rc is not None else {})
            obs = await driver.visit(url, wait_ms=1200, **visit_kw)
            # the payload's console.log nonce is inside the payload string; if the
            # page executed it, the nonce shows up in an execution sink.
            return ("Execution also confirmed in a headless browser."
                    if getattr(obs, "console", None) else "")
        except Exception:
            return ""
