"""
Excessive-trust-in-client-side-controls confirmation leg (business logic).

A price/amount/total that the SERVER should own is instead taken from a
client-supplied request field (a hidden form input, a JSON value). The bug is
confirmed by TAMPERING that field to a distinctive sentinel value and observing
the server REFLECT it back on an independent read (the cart/order summary), i.e.
the server stored the attacker-chosen amount rather than its own authoritative
price. A server that ignores the client value and re-derives its own price shows
the real amount instead, so the sentinel is absent and this stays un-confirmed.

Safe + non-destructive: the tamper is a normal add-to-cart/update write (gated by
validators.allow_mutating_replay); NO checkout/purchase is performed -- the proof
is that the amount was trusted, read back from the cart, not an order placed.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urlsplit, parse_qsl, urlencode

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

# Fields whose value the SERVER should own; a client-supplied one is the bug.
_VALUE_KEYS = re.compile(
    r"^(price|amount|cost|total|subtotal|unit[_-]?price|fee|balance|discount|"
    r"pay(?:ment)?_?amount|value)$", re.I)
_CSRF_KEYS = re.compile(r"csrf|xsrf|authenticity|_token|nonce", re.I)
# Re-read targets that commonly render a stored cart/order amount.
_SUMMARY_PATHS = ("/cart", "/basket", "/checkout", "/order", "/orders",
                  "/cart/summary", "/my-account")


def _parse(body: str):
    """(fields, kind) for a urlencoded or JSON body; kind in {'form','json'}."""
    s = (body or "").strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj, "json"
        except ValueError:
            pass
    return dict(parse_qsl(body or "", keep_blank_values=True)), "form"


def _encode(fields: dict, kind: str) -> str:
    return json.dumps(fields) if kind == "json" else urlencode(fields)


def _value_field(fields: dict) -> str | None:
    for k, v in fields.items():
        if _VALUE_KEYS.match(str(k)) and re.fullmatch(r"-?\d+", str(v) or ""):
            return k
    return None


def _formats(cents: int) -> list[str]:
    """Distinctive renderings of a cents amount to look for in a summary page."""
    dollars = f"{cents // 100}.{cents % 100:02d}"
    return [dollars, str(cents)]


class ClientTrustValidator(Validator):
    name = "client_trust"
    finding_classes = {
        "business_logic", "business logic", "business logic vulnerability",
        "client_side_controls", "client-side controls", "excessive trust",
        "price_manipulation", "price manipulation", "logic_flaw", "logic flaw",
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "business_logic", summary=why)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
            return False
        fields, _ = _parse(exchange.request_body or "")
        return _value_field(fields) is not None

    async def _send(self, client, method, url, headers, body):
        await global_throttle.acquire()
        return await client.request(method, url, headers=headers or None, content=body or None)

    def _headers(self, exchange) -> dict:
        return {k: v for k, v in (exchange.request_headers or {}).items()
                if k.lower() not in ("content-length", "host")}

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("client-trust tamper is a mutating write; needs validators.allow_mutating_replay")

        fields, kind = _parse(exchange.request_body or "")
        vkey = _value_field(fields)
        if vkey is None:
            return self._skip("no server-owned value field (price/amount/total) in the request body")
        original = str(fields.get(vkey))
        # A distinctive 5-digit sentinel amount (in cents) -> $DDD.CC, unlikely to
        # appear by chance; kept well below the original so it also demonstrates the
        # "buy for less" exploit direction without any purchase.
        sentinel = secrets.randbelow(90000) + 1000
        if str(sentinel) == original:
            sentinel += 7
        method = (exchange.method or "POST").upper()
        p = urlsplit(exchange.url)
        origin = f"{p.scheme}://{p.netloc}"

        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=True, verify=False) as client:
                tampered = dict(fields)
                tampered[vkey] = str(sentinel)
                # Refresh an in-session CSRF token if the write is token-bound.
                ckey = next((k for k in fields if _CSRF_KEYS.search(str(k))), None)
                if ckey is not None:
                    tampered = await self._refresh_csrf(client, exchange, tampered, ckey, kind)
                resp = await self._send(client, method, exchange.url,
                                        self._headers(exchange), _encode(tampered, kind))
                if resp.status_code >= 400:
                    return ValidationResult(
                        self.name, "not_confirmed", "business_logic", confidence=0.0, confirmed=False,
                        summary=f"Tampered {vkey} write rejected (HTTP {resp.status_code}).",
                        evidence=f"POST {exchange.url} with {vkey}={sentinel} → {resp.status_code}.")

                wanted = _formats(sentinel)
                read_headers = {k: v for k, v in self._headers(exchange).items()
                                if k.lower() != "content-type"}
                pages = [resp.text or ""]
                targets = [str(resp.url)] + [origin + sp for sp in _SUMMARY_PATHS]
                seen = set()
                for t in targets:
                    if t in seen:
                        continue
                    seen.add(t)
                    try:
                        rr = await self._send(client, "GET", t, read_headers, None)
                        pages.append(rr.text or "")
                    except httpx.HTTPError:
                        continue
                for body in pages:
                    if wanted[0] in body:  # the $DDD.CC rendering of the sentinel
                        return ValidationResult(
                            self.name, "confirmed", "business_logic", confidence=0.9, confirmed=True,
                            summary=(f"Excessive trust in client-side controls confirmed: the server accepted a "
                                     f"client-supplied {vkey} and reflected it back on an independent read."),
                            evidence=(f"The captured request set {vkey}={original}; replaying it with "
                                      f"{vkey}={sentinel} caused the summary to show the attacker-chosen amount "
                                      f"(${wanted[0]}). The server trusts the client value instead of its own "
                                      f"authoritative price. No checkout/purchase was performed."))
                return ValidationResult(
                    self.name, "not_confirmed", "business_logic", confidence=0.0, confirmed=False,
                    summary=f"Server did not reflect the tampered {vkey}; it appears to own the value.",
                    evidence=f"Set {vkey}={sentinel} but ${wanted[0]} was not shown on re-read -- the server "
                             f"likely re-derives its own authoritative amount.")
        except SafetyGateBlocked:
            return self._skip("mutating client-trust tamper not authorized (validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(self.name, "error", "business_logic",
                                    summary=f"request failed: {e.__class__.__name__}")

    async def _refresh_csrf(self, client, exchange, fields: dict, ckey: str, kind: str) -> dict:
        """Mint a fresh CSRF token in THIS session from the write's source page."""
        from harness.validators.source_form import fetch_source_form

        def select(forms):
            for f in forms:
                tok = next((fld.value for fld in f.fields
                            if _CSRF_KEYS.search(fld.name or "") and fld.value), None)
                if tok:
                    return f
            return None

        try:
            found = await fetch_source_form(client, [exchange.url], self._headers(exchange), select)
            if found is not None:
                tok = next((fld.value for fld in found.form.fields
                            if _CSRF_KEYS.search(fld.name or "") and fld.value), None)
                if tok:
                    out = dict(fields); out[ckey] = tok
                    return out
        except (httpx.HTTPError, Exception):
            pass
        return fields
