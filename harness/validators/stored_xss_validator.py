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
  3. CONFIRM -- stored XSS only when the payload comes back UNESCAPED in a
                text/html response on that independent read AND a headless
                browser loading that page logs a console message, or raises an
                alert/confirm/prompt dialog, EXACTLY equal to the value THIS
                attempt's payload computes at run time (R19, E2; the dialog is
                RV-O O8, an owner decision of 2026-10-21). The payload alerts
                and logs a product of two random operands, so the stored text
                holds the operands but never the result: a page that logs the
                stored source (a textarea's value) shows the operands, not the
                product. Any other dialog, or a page error, is noted as a
                candidate to check by hand. The unescaped string alone is a
                candidate (inconclusive): an inert context (<textarea>, a comment,
                a CSP) stores it without running it, and with no browser there is
                no execution proof. A JSON API that stores-and-returns the string
                escaped, or in a non-HTML content type, is NOT a candidate -- the
                same precision line browser_xss draws (no HTML sink, no confirm).

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


def _challenge() -> tuple[int, int, str]:
    """Two random six-digit operands and the product the payload logs when it
    runs. The product (under 2**53, so exact in JavaScript) never appears in
    the payload text, so only execution can produce it (E2)."""
    a, b = (100000 + secrets.randbelow(900000) for _ in range(2))
    return a, b, str(a * b)


def _payloads(a: int, b: int) -> list[str]:
    # Alert first: a sink that lets only alert() run still shows the product (RV-O O8).
    js = f"alert({a}*{b});console.log({a}*{b})"
    return [f"<svg/onload={js}>", f"<script>{js}</script>", f"<img src=x onerror={js}>"]


_DIALOG_TYPES = ("alert", "confirm", "prompt")


def _dialog_messages(obs) -> list[str]:
    """The message of each alert/confirm/prompt dialog the page raised (the
    driver records one as "type:message")."""
    out = []
    for entry in getattr(obs, "dialogs", None) or []:
        kind, sep, message = str(entry).partition(":")
        if sep and kind in _DIALOG_TYPES:
            out.append(message.strip())
    return out


def _unmatched_signal(obs) -> tuple[str, str]:
    """(note, detail) for a page that raised a dialog or a page error without
    the computed product -- a candidate to check by hand, never a negative
    (RV-O O8) -- or ("", "") when it raised neither."""
    if getattr(obs, "dialogs", None):
        return ("a dialog fired, but not with the computed value; check manually",
                f"dialog {str(obs.dialogs[0])[:120]!r}")
    if getattr(obs, "page_errors", None):
        return ("a page error was raised, but no computed value was shown; check manually",
                f"error {str(obs.page_errors[0])[:120]!r}")
    return "", ""


# The closing sentence of a confirm shown by a dialog alone, and the marker of a
# candidate note that asks for a manual check (RV-O O8).
_DIALOG_ONLY = "Execution was shown by a dialog only, not by the console."
_CHECK_MANUALLY = "check manually"


def _keep(candidate, payload: str, rurl: str, note: str):
    """The candidate to report: the first one, unless a later one raised a
    dialog or a page error and it did not."""
    if candidate is None or (_CHECK_MANUALLY in note and _CHECK_MANUALLY not in candidate[2]):
        return payload, rurl, note
    return candidate


class _Recorded:
    """A client whose sends are recorded in `attempts`, for a helper that
    swallows its own transport errors (fetch_source_form skips a page it could
    not read)."""

    def __init__(self, client, attempts: list, stage: str):
        self._client, self._attempts, self._stage = client, attempts, stage

    async def request(self, method: str, url: str, **kwargs):
        try:
            resp = await self._client.request(method, url, **kwargs)
        except SafetyGateBlocked as e:
            self._attempts.append(("blocked", f"{self._stage} {url}: refused ({e.decision.reason})"))
            raise
        except httpx.HTTPError as e:
            self._attempts.append(("error", f"{self._stage} {url}: {e.__class__.__name__}"))
            raise
        self._attempts.append(("ok", self._stage))
        return resp


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

    async def _request(self, client, method: str, url: str, attempts: list, stage: str, **kwargs):
        """One throttled send, recorded in `attempts` as ("ok" | "blocked" |
        "error", description). Returns the response, or None when it got none.
        A gate or run refusal is recorded and re-raised: it refuses the rest too."""
        await global_throttle.acquire()
        try:
            resp = await client.request(method, url, **kwargs)
        except SafetyGateBlocked as e:
            attempts.append(("blocked", f"{stage}: refused ({e.decision.reason})"))
            raise
        except httpx.HTTPError as e:
            attempts.append(("error", f"{stage}: {e.__class__.__name__}"))
            return None
        attempts.append(("ok", stage))
        return resp

    def _incomplete(self, attempts: list, method: str, write_path: str,
                    via: str = "") -> ValidationResult:
        """A plant or render that got no response is not a negative (RV-L rule)."""
        unsent = [(kind, why) for kind, why in attempts if kind != "ok"]
        answered = len(attempts) - len(unsent)
        refused = any(kind == "blocked" for kind, _ in unsent)
        failed = "; ".join(why for _, why in unsent[:4])
        return ValidationResult(
            self.name, "blocked" if refused and not answered else "inconclusive", "xss",
            confidence=0.0, confirmed=False,
            summary=f"Stored-XSS check incomplete: {len(unsent)} of {len(attempts)} send(s) got no "
                    f"response ({failed}); not a negative result",
            evidence=(f"Planted script-executable payloads via {method} {write_path}{via}; no "
                      f"unescaped render was seen, but a plant or render that never got a response "
                      f"cannot show one."))

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
                                     method: str, render_urls: list[str], attempts: list):
        """Session-aware plant: GET the source page in THIS client's session to
        obtain a fresh CSRF-bound form, plant into it, then read it back. Returns
        a ValidationResult when a matching source form was found (confirmed,
        candidate, incomplete or not), or None to let the caller fall back to the
        captured-body plant. Every send is recorded in `attempts`."""
        from harness.validators.source_form import fetch_source_form
        action_path = urlsplit(exchange.url).path
        read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

        def select(forms):
            return next((f for f in forms
                        if urlsplit(f.action).path == action_path
                        and (f.method or "POST").upper() == method), None)

        candidate, via = None, ""
        try:
            async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                found = await fetch_source_form(_Recorded(client, attempts, "source page GET"),
                                                self._source_page_candidates(exchange),
                                                read_headers, select)
                if found is None:
                    return None  # no discoverable source form -> caller falls back
                fresh, source_url = found.form, found.source_url
                via = f" through a fresh CSRF-bound form from {source_url}"
                a, b, expected = _challenge()
                for payload in _payloads(a, b):
                    plant_body = self._form_plant_body(fresh, payload)
                    planted_headers = dict(headers)
                    planted_headers["Content-Type"] = "application/x-www-form-urlencoded"
                    if await self._request(client, method, fresh.action, attempts,
                                           f"plant {method} {urlsplit(fresh.action).path}",
                                           headers=planted_headers, content=plant_body) is None:
                        continue  # this payload never landed; try the next shape
                    for rurl in [source_url, *render_urls]:
                        rr = await self._request(client, "GET", rurl, attempts,
                                                 f"render GET {urlsplit(rurl).path}",
                                                 headers=read_headers or None)
                        if rr is None:
                            continue
                        if ("html" in (rr.headers.get("content-type") or "").lower()
                                and payload in (rr.text or "")):
                            executed, note = await self._browser_confirm(rurl, expected)
                            if executed:
                                return self._executed(method, action_path, payload, rurl, note, via)
                            candidate = _keep(candidate, payload, rurl, note)
                            if executed is None:
                                return self._unproven(method, action_path, *candidate, via)
                            break  # inert here; try the next payload shape
                if candidate:
                    return self._unproven(method, action_path, *candidate, via)
                if any(kind != "ok" for kind, _ in attempts):
                    return self._incomplete(attempts, method, action_path, via)
                return ValidationResult(
                    self.name, "not_confirmed", "xss", confidence=0.0, confirmed=False,
                    summary="No stored XSS: planted payloads were not reflected unescaped in an HTML render",
                    evidence=(f"Submitted a fresh CSRF-bound form at {action_path} and re-read the "
                              f"rendered page; the payload never returned unescaped in a text/html response."))
        except SafetyGateBlocked:
            # recorded where it was raised; it refuses every further send
            if candidate:
                return self._unproven(method, action_path, *candidate, via)
            return self._incomplete(attempts, method, action_path, via)
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
        # Every send, as ("ok" | "blocked" | "error", description): a plant that
        # never landed, or a render never read back, is not a negative (RV-L rule).
        attempts: list[tuple[str, str]] = []

        # Form (urlencoded) writes are commonly CSRF-token-bound: the captured
        # token belongs to the crawl's session, so a fresh client is rejected
        # ("session does not contain a CSRF token"). Mint a fresh token in THIS
        # session from the source page first; only fall back to replaying the
        # captured body when no source form is discoverable (e.g. a JSON API).
        if self._json_object(exchange.request_body or "") is None and "=" in (exchange.request_body or ""):
            via_source = await self._plant_via_source_form(exchange, gate, headers, method,
                                                           render_urls, attempts)
            if via_source is not None:
                return via_source

        write_path = urlsplit(exchange.url).path
        a, b, expected = _challenge()
        candidate = None
        read_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        for payload in _payloads(a, b):
            body, ctype = self._plant_body(exchange, payload)
            planted_headers = dict(headers); planted_headers["Content-Type"] = ctype
            try:
                async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    if await self._request(client, method, exchange.url, attempts,
                                           f"plant {method} {write_path}",
                                           headers=planted_headers, content=body) is None:
                        continue  # this payload never landed; try the next shape
                    for rurl in render_urls:
                        r = await self._request(client, "GET", rurl, attempts,
                                                f"render GET {urlsplit(rurl).path}",
                                                headers=read_headers or None)
                        if r is None:
                            continue
                        ct = (r.headers.get("content-type") or "").lower()
                        if "html" in ct and payload in (r.text or ""):
                            # R19: an unescaped string is not execution (an inert
                            # <textarea>, a comment, a CSP). Only the payload's
                            # computed value, logged or shown in a dialog by a
                            # browser, confirms.
                            executed, note = await self._browser_confirm(rurl, expected)
                            if executed:
                                return self._executed(method, write_path, payload, rurl, note)
                            candidate = _keep(candidate, payload, rurl, note)
                            if executed is None:
                                return self._unproven(method, write_path, *candidate)
                            break  # inert here; try the next payload shape
            except SafetyGateBlocked:
                break  # recorded by _request; the gate or run refuses every further send
        if candidate:
            return self._unproven(method, write_path, *candidate)
        if any(kind != "ok" for kind, _ in attempts):
            return self._incomplete(attempts, method, write_path)
        return ValidationResult(
            self.name, "not_confirmed", "xss", confidence=0.0, confirmed=False,
            summary="No stored XSS: planted payloads were not reflected unescaped in an HTML render",
            evidence=f"Planted script-executable payloads via {method} and re-read {len(render_urls)} "
                     f"endpoint(s); none returned the payload unescaped in a text/html response.")

    def _executed(self, method: str, write_path: str, payload: str, rurl: str, note: str,
                  via: str = "") -> ValidationResult:
        shown = " (shown by a dialog only)" if note.endswith(_DIALOG_ONLY) else ""
        return ValidationResult(
            self.name, "confirmed", "xss", confidence=0.95, confirmed=True,
            summary=f"Stored XSS confirmed{shown}: a payload written via {method} {write_path} "
                    f"executed when {urlsplit(rurl).path} was rendered on an independent read.",
            evidence=(f"Planted {payload!r}{via}; an independent GET of {rurl} returned it intact "
                      f"(angle brackets + handler) in a text/html response -- stored, not just "
                      f"reflected. {note}"))

    def _unproven(self, method: str, write_path: str, payload: str, rurl: str, note: str,
                  via: str = "") -> ValidationResult:
        return ValidationResult(
            self.name, "inconclusive", "xss", confidence=0.5, confirmed=False,
            summary=f"Stored XSS candidate, not confirmed: a payload written via {method} {write_path} "
                    f"comes back unescaped in the HTML of {urlsplit(rurl).path}, but execution was not "
                    f"observed.",
            evidence=(f"Planted {payload!r}{via}; an independent GET of {rurl} returned it intact in a "
                      f"text/html response. A raw string match is not execution (an inert context such "
                      f"as <textarea>, or a CSP, stops it). {note}"))

    async def _browser_confirm(self, url: str, expected: str) -> tuple[bool | None, str]:
        """Load the rendered page in a headless browser and look for a console
        message, or an alert/confirm/prompt dialog, exactly equal to
        ``expected``, the value THIS attempt's payload computes when it runs
        (RV-O O8 added the dialog). Returns (executed, note): True only for
        that exact event; False when the page loaded and the payload did not
        run, the note saying so when a dialog or page error fired; None when no
        browser could check. Any other output, including a message that merely
        contains the payload's text, is the page's own (E2: a page that logs
        the stored source echoes it without running it)."""
        driver = self._driver
        try:
            if driver is None:
                from harness import browser_driver
                driver = browser_driver.default_driver()
                if driver is None:
                    return None, "No browser available to prove execution."
            rc = self.run_context
            visit_kw = (dict(scope=rc.scope, gate=rc.gate, budget=rc.budget, cancel=rc.cancel)
                        if rc is not None else {})
            obs = await driver.visit(url, wait_ms=1200, **visit_kw)
        except Exception as e:
            return None, f"The browser check of {url} failed ({type(e).__name__}); execution unproven."
        if getattr(obs, "load_error", None):
            return None, f"The browser could not load {url} ({obs.load_error}); execution unproven."
        if any(str(m).strip() == expected for m in (getattr(obs, "console", None) or [])):
            return True, (f"Execution confirmed: the payload executed in a headless browser "
                          f"(it logged {expected}, a value computed at run time that the stored "
                          f"text does not contain).")
        if expected in _dialog_messages(obs):
            return True, (f"Execution confirmed: the payload executed in a headless browser "
                          f"(a dialog showed {expected}, a value computed at run time that the "
                          f"stored text does not contain). {_DIALOG_ONLY}")
        signal, detail = _unmatched_signal(obs)
        if signal:
            return False, (f"A headless browser loaded {url}: {signal} ({detail}); the computed "
                           f"value was not shown.")
        return False, f"A headless browser loaded {url} and the payload did not execute."
