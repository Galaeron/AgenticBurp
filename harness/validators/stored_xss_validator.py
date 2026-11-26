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
                same precision line browser_xss draws (no HTML sink, no confirm)
                -- unless a client view renders it:
     A plant the server rejects (an error status) stored nothing. Writing the
     payload into every string field also overwrites the ones the server checks
     (a CAPTCHA answer, a token, an email), so a rejected plant is retried with
     the payload in one string field at a time, the others at their captured
     values (_MAX_FIELD_PLANTS fields, the most text-like first); the field that
     is accepted carries the later payload shapes too. When every plant is
     rejected nothing was stored, and the result is inconclusive, not a negative.
  4. VIEWS   -- a JSON render that holds the payload in one of its strings
                (however the serializer escaped it) runs no script, but a page
                script that fetches it may render it. The client views a crawl
                saw read that API (client_routes.views_for_api: the run's route
                map, or the host's stored engagement snapshot) are loaded in the
                browser as the captured identity, and only the same computed
                value confirms. A view that raised a dialog or a page error, or
                no browser to load one, leaves a candidate, never a negative.

Scope-gated; the plant is a mutating write, so it self-gates on
validators.allow_mutating_replay and routes through the safety gate.
"""
from __future__ import annotations
from harness import scope_lock

import json
import re
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

# Client views loaded after a JSON render held the payload: at most this many per
# payload, each given this long to fetch the API and render it.
_MAX_VIEWS = 3
# Click recipes loaded per payload shape, apart from _MAX_VIEWS.
_MAX_CLICK_VIEWS = 2
_VIEW_WAIT_MS = 2500


def _in_json(text: str, payload: str) -> bool:
    """Whether a JSON body holds `payload` intact in one of its strings, however
    the serializer escaped it (`\\u003c`, `\\/`)."""
    try:
        doc = json.loads(text or "")
    except (ValueError, TypeError):
        return False
    stack, seen = [doc], 0
    while stack and seen < 50_000:
        node = stack.pop()
        seen += 1
        if isinstance(node, str):
            if payload in node:
                return True
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _identity_headers(headers: dict | None) -> dict:
    """The headers of a captured API call that carry its identity (Authorization,
    Cookie, X-* tokens), for loading a page as the same user. Accept, Origin and
    the like describe the API call, not the page the browser loads."""
    keep = {}
    for k, v in (headers or {}).items():
        low = (k or "").lower()
        if low in ("authorization", "cookie", "proxy-authorization") or (
                low.startswith("x-") and low != "x-requested-with"
                and not low.startswith("x-forwarded")):
            keep[k] = v
    return keep


def _view_label(view: str) -> str:
    parts = urlsplit(view)
    return (parts.path or "/") + (f"#{parts.fragment}" if parts.fragment else "")


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


# The per-field retry of a rejected plant (see the module doc): at most this many
# string fields, those whose name reads as a checked value last, then those whose
# captured value is no prose (no whitespace), then the shorter.
_MAX_FIELD_PLANTS = 4
_CHECKED_FIELD = re.compile(
    r"token|csrf|xsrf|captcha|nonce|signature|hash|pass(?:word|wd)?|secret|key|e-?mail|"
    r"answer|code|otp|url|uri|href|date|time|uuid|(?:^|_|[a-z])id$|^id$", re.I)


def _plant_field_order(items) -> list[str]:
    """The string field names of `items` ((name, value) pairs), most text-like first."""
    def text_like(item):
        name, value = item
        value = str(value or "")
        return (bool(_CHECKED_FIELD.search(name or "")), not any(c.isspace() for c in value),
                -len(value))
    out: list[str] = []
    for name, _value in sorted(items, key=text_like):
        if name and name not in out:
            out.append(name)
    return out


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

    def _plant_body(self, exchange: HttpExchange, payload: str, only: str | None = None):
        """The write body with `payload` in every string field, or in the field
        `only` alone (the others at their captured values)."""
        body = exchange.request_body or ""
        obj = self._json_object(body)
        if obj is not None:
            planted = {k: (payload if _text_fieldish(v) and (only is None or k == only) else v)
                       for k, v in obj.items()}
            return json.dumps(planted), "application/json"
        from urllib.parse import parse_qsl, urlencode
        pairs = [(k, payload if only is None or k == only else v)
                 for k, v in parse_qsl(body, keep_blank_values=True)]
        return urlencode(pairs), "application/x-www-form-urlencoded"

    def _plant_fields(self, exchange: HttpExchange) -> list[str]:
        """The string fields a rejected plant is retried in, one at a time (see
        _plant_field_order); none when the body has a single one."""
        body = exchange.request_body or ""
        obj = self._json_object(body)
        if obj is not None:
            items = [(k, v) for k, v in obj.items() if _text_fieldish(v)]
        else:
            from urllib.parse import parse_qsl
            items = parse_qsl(body, keep_blank_values=True)
        names = _plant_field_order(items)
        return names[:_MAX_FIELD_PLANTS] if len(names) > 1 else []

    async def _plant(self, client, exchange: HttpExchange, method: str, payload: str,
                     headers: dict, attempts: list, write_path: str, chosen: list,
                     rejected: list):
        """Send the plant of `payload` and return the accepted response, or None.
        `chosen` holds the variant an earlier payload landed with ([None] for every
        string field, [name] for that one field) and is set by the first accepted
        one; until then a rejected plant (an error status, recorded in `rejected`)
        is retried field by field (_plant_fields). None also when a send got no
        response (recorded by _request)."""
        variants = list(chosen) or [None] + self._plant_fields(exchange)
        for only in variants:
            body, ctype = self._plant_body(exchange, payload, only)
            planted_headers = dict(headers); planted_headers["Content-Type"] = ctype
            stage = f"plant {method} {write_path}" + (f" (field {only})" if only else "")
            resp = await self._request(client, method, exchange.url, attempts, stage,
                                       headers=planted_headers, content=body)
            if resp is None:
                return None
            if resp.status_code >= 400:
                rejected.append(f"{stage} -> {resp.status_code}")
                continue
            chosen[:] = [only]
            return resp
        return None

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
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
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
        # (view, note) for each client view loaded after a JSON render held the
        # payload; no_browser is the note of a view no browser could load.
        viewed: list[tuple[str, str]] = []
        no_browser = ""
        # The plant variant that landed (see _plant), and every rejected plant.
        chosen: list = []
        rejected: list[str] = []
        for payload in _payloads(a, b):
            try:
                async with GatedAsyncClient(gate, self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    if await self._plant(client, exchange, method, payload, headers, attempts,
                                         write_path, chosen, rejected) is None:
                        continue  # this payload never landed; try the next shape
                    json_renders: list[str] = []
                    for rurl in render_urls:
                        r = await self._request(client, "GET", rurl, attempts,
                                                f"render GET {urlsplit(rurl).path}",
                                                headers=read_headers or None)
                        if r is None:
                            continue
                        ct = (r.headers.get("content-type") or "").lower()
                        if "html" not in ct and _in_json(r.text or "", payload):
                            json_renders.append(rurl)
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
                    if json_renders and not no_browser:
                        executed, view, rurl, note = await self._confirm_in_views(
                            json_renders, expected, read_headers, viewed)
                        if executed:
                            return self._executed_in_view(method, write_path, payload, rurl,
                                                          view, note)
                        if executed is None and view:
                            no_browser = note
            except SafetyGateBlocked:
                break  # recorded by _request; the gate or run refuses every further send
        if candidate:
            return self._unproven(method, write_path, *candidate)
        if any(kind != "ok" for kind, _ in attempts):
            return self._incomplete(attempts, method, write_path)
        if not chosen and rejected:
            return ValidationResult(
                self.name, "inconclusive", "xss", confidence=0.0, confirmed=False,
                summary=f"Stored-XSS check incomplete: the server rejected every plant "
                        f"({len(rejected)}); nothing was stored, so this is not a negative result",
                evidence=(f"Planted script-executable payloads via {method} {write_path}, in "
                          f"every string field and then one field at a time; each write was "
                          f"refused ({'; '.join(rejected[:4])})."))
        flagged = next(((v, n) for v, n in viewed if _CHECK_MANUALLY in n), None)
        if no_browser or flagged:
            view, note = flagged or ("", no_browser)
            return self._view_unproven(method, write_path, view, note)
        labels = sorted({_view_label(v) for v, _ in viewed})
        return ValidationResult(
            self.name, "not_confirmed", "xss", confidence=0.0, confirmed=False,
            summary="No stored XSS: planted payloads were not reflected unescaped in an HTML render"
                    + (", nor run by the client views that read the JSON API" if viewed else ""),
            evidence=f"Planted script-executable payloads via {method} and re-read {len(render_urls)} "
                     f"endpoint(s); none returned the payload unescaped in a text/html response."
                     + (f" A JSON response returned it, and {len(viewed)} load(s) of the client "
                        f"view(s) that read that API ({', '.join(labels)}) did not run it."
                        if viewed else ""))

    def _client_views(self, api_url: str) -> list[str]:
        """The page URLs of the client views a crawl saw read `api_url`, in scope:
        from the run's route map, or, for a run without one, from the host's stored
        engagement snapshot (route_candidates.stored_routes)."""
        rc = self.run_context
        routes = getattr(rc, "client_routes", None) if rc is not None else None
        if routes is None:
            from harness.validators.route_candidates import stored_routes
            routes = stored_routes(api_url)
        try:
            views = routes.views_for_api("GET", api_url) if routes is not None else []
        except Exception:
            return []
        return [v for v in views
                if not self.allowed_hosts or scope_lock.host_in_scope(v, self.allowed_hosts)]

    def _client_click_views(self, api_url: str) -> list[tuple[str, str]]:
        """(page URL, selector) of each click recipe a crawl recorded for `api_url`
        (client_routes.clicks_for_api: the view read that API only after a click on
        that control, e.g. a dialog), in scope, from the same map as _client_views."""
        rc = self.run_context
        routes = getattr(rc, "client_routes", None) if rc is not None else None
        if routes is None:
            from harness.validators.route_candidates import stored_routes
            routes = stored_routes(api_url)
        clicks_for_api = getattr(routes, "clicks_for_api", None)
        try:
            recipes = clicks_for_api("GET", api_url) if callable(clicks_for_api) else []
        except Exception:
            return []
        return [(v, s) for v, s in recipes
                if not self.allowed_hosts or scope_lock.host_in_scope(v, self.allowed_hosts)]

    async def _confirm_in_views(self, json_renders: list[str], expected: str, headers: dict,
                                viewed: list) -> tuple:
        """Load the client views that read the JSON renders holding the payload (at
        most _MAX_VIEWS), as the captured identity, and look for the computed value
        (_browser_confirm). Returns (executed, view, render url, note) for the first
        view that ran it or that no browser could load, else for the last one
        loaded; view is "" when no view is known. Each load goes into `viewed`."""
        views: list[tuple[str, str, tuple]] = []
        for rurl in json_renders:
            for view in self._client_views(rurl):
                if len(views) < _MAX_VIEWS and view not in [v for v, _, _c in views]:
                    views.append((view, rurl, ()))
        # Click recipes (driver_capture.click_explore): a view that reads the API
        # only once a control is clicked is loaded and that control clicked.
        recipes = 0
        for rurl in json_renders:
            for view, selector in self._client_click_views(rurl):
                entry = (view, rurl, (selector,))
                if recipes < _MAX_CLICK_VIEWS and entry not in views:
                    views.append(entry)
                    recipes += 1
        last = (False, "", "", "")
        for view, rurl, clicks in views:
            executed, note = await self._browser_confirm(
                view, expected, headers=_identity_headers(headers), wait_ms=_VIEW_WAIT_MS,
                clicks=clicks)
            if executed is not None:
                viewed.append((view, note))
            last = (executed, view, rurl, note)
            if executed or executed is None:
                break
        return last

    def _executed_in_view(self, method: str, write_path: str, payload: str, api_url: str,
                          view: str, note: str) -> ValidationResult:
        shown = " (shown by a dialog only)" if note.endswith(_DIALOG_ONLY) else ""
        api_path = urlsplit(api_url).path
        return ValidationResult(
            self.name, "confirmed", "xss", confidence=0.95, confirmed=True,
            summary=f"Stored XSS confirmed{shown}: a payload written via {method} {write_path} "
                    f"executed when the client view {_view_label(view)} rendered it from "
                    f"{api_path}.",
            evidence=(f"Planted {payload!r}; an independent GET of {api_url} returned it in a JSON "
                      f"response, and loading {view}, a client view a crawl saw read {api_path}, "
                      f"ran it -- stored, then rendered by the page's own script. {note}"))

    def _view_unproven(self, method: str, write_path: str, view: str,
                       note: str) -> ValidationResult:
        where = f"the client view {_view_label(view)}" if view else "a client view"
        return ValidationResult(
            self.name, "inconclusive", "xss", confidence=0.4, confirmed=False,
            summary=f"Stored XSS candidate, not confirmed: a payload written via {method} {write_path} "
                    f"comes back in a JSON response that {where} reads, but execution was not "
                    f"observed.",
            evidence=(f"Planted script-executable payloads; an independent read returned one intact "
                      f"in a JSON response, and a crawl saw {where} read that API. {note}"))

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

    async def _browser_confirm(self, url: str, expected: str, *, headers: dict | None = None,
                               wait_ms: int = 1200, clicks=()) -> tuple[bool | None, str]:
        """Load the rendered page in a headless browser and look for a console
        message, or an alert/confirm/prompt dialog, exactly equal to
        ``expected``, the value THIS attempt's payload computes when it runs
        (RV-O O8 added the dialog). Returns (executed, note): True only for
        that exact event; False when the page loaded and the payload did not
        run, the note saying so when a dialog or page error fired; None when no
        browser could check. Any other output, including a message that merely
        contains the payload's text, is the page's own (E2: a page that logs
        the stored source echoes it without running it). `headers` (an identity's,
        for a client view) go to the driver only when given. `clicks` (a click
        recipe's selectors) are clicked after the load (driver.visit(clicks=...));
        a recipe click that could not be made leaves a candidate to check
        manually, never a negative."""
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
            if headers:
                visit_kw["headers"] = headers
            if clicks:
                visit_kw["clicks"] = tuple(clicks)
            obs = await driver.visit(url, wait_ms=wait_ms, **visit_kw)
        except Exception as e:
            return None, f"The browser check of {url} failed ({type(e).__name__}); execution unproven."
        if getattr(obs, "load_error", None):
            return None, f"The browser could not load {url} ({obs.load_error}); execution unproven."
        if clicks:
            done = list(getattr(obs, "clicks", None) or [])
            clicked = len(done) >= len(clicks) and all(d.endswith(": clicked") for d in done)
            how = f"After clicking {', '.join(clicks)} on the view: "
            if not clicked:
                return False, (f"A headless browser loaded {url}, but the recorded click on "
                               f"{', '.join(clicks)} could not be made "
                               f"({'; '.join(done)[:200] or 'no click reported'}); "
                               f"{_CHECK_MANUALLY}.")
            executed, note = self._judge(obs, url, expected)
            return executed, how + note
        return self._judge(obs, url, expected)

    @staticmethod
    def _judge(obs, url: str, expected: str) -> tuple[bool, str]:
        """_browser_confirm's reading of one loaded page."""
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
