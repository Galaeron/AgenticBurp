"""
Secret-disclosure confirmation -- Phase 3.1.

confidential_info_detector DETECTS secrets in a response but can only ever mark
them unconfirmed -- it cannot tell a real live key from an example string. This
closes that for the highest-value case: a leaked JWT SIGNING SECRET.

If any string present in the response CRYPTOGRAPHICALLY VERIFIES the HMAC
signature of a JWT the client is already using (from the request Authorization /
Cookie), then that string IS the signing key -- proven, not guessed, with zero
false-positive risk (an HMAC match is exact). That directly confirms the
admin/debug "signing secret leaked to the response" class: an attacker who reads
that value can forge arbitrary (e.g. admin) tokens the server will accept.

Deterministic and OFFLINE -- pure crypto over the captured exchange, no network
send at all (so it runs under the safe default config, like the passive
deserialization check). The secret is REDACTED in the finding evidence; the
detector never becomes a second copy of the leak.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from harness.models import Finding, HttpExchange

# JWT anywhere in a header/body/response: three base64url segments.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}")
# HMAC algorithms we can verify a candidate secret against.
_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

_MAX_CANDIDATES = 400
_MAX_JWTS = 20


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwts_in(exchange: HttpExchange) -> list[str]:
    """JWTs the client is presenting -- from the request's Authorization/Cookie
    headers and body, plus the response (a debug endpoint may echo the token)."""
    blobs = list((exchange.request_headers or {}).values())
    blobs.append(exchange.request_body or "")
    blobs.append(exchange.response_body or "")
    blobs.extend((exchange.response_headers or {}).values())
    seen: list[str] = []
    for blob in blobs:
        for m in _JWT_RE.finditer(blob or ""):
            tok = m.group(0)
            if tok not in seen:
                seen.append(tok)
                if len(seen) >= _MAX_JWTS:
                    return seen
    return seen


def _candidate_secrets(exchange: HttpExchange) -> list[str]:
    """Strings from the RESPONSE worth testing as the HMAC key: JSON string
    values (any depth) plus quoted/whitespace-delimited tokens. Bounded and
    deduped. A wide net is safe here -- only a real key produces an HMAC match."""
    body = exchange.response_body or ""
    cands: list[str] = []
    seen: set[str] = set()

    def _add(s):
        if isinstance(s, str) and 4 <= len(s) <= 1024 and s not in seen:
            seen.add(s)
            cands.append(s)

    def _walk(obj):
        if isinstance(obj, str):
            _add(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    try:
        _walk(json.loads(body))
    except (ValueError, TypeError):
        pass
    # Fallback / non-JSON: quoted strings and bare tokens.
    for m in re.finditer(r'"([^"\\]{4,1024})"|\'([^\'\\]{4,1024})\'', body):
        _add(m.group(1) or m.group(2))
    for tok in re.split(r"[\s,;={}\[\]()<>]+", body):
        _add(tok)
        if len(cands) >= _MAX_CANDIDATES:
            break
    return cands[:_MAX_CANDIDATES]


def _secret_signs_jwt(jwt: str, secret: str) -> bool:
    parts = jwt.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, TypeError):
        return False
    algfn = _HS_ALGS.get(str(header.get("alg", "")).upper())
    if algfn is None:
        return False  # not an HMAC token -- can't confirm a symmetric key
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii", "ignore")
    expected = _b64url(hmac.new(secret.encode("utf-8", "ignore"), signing_input, algfn).digest())
    return hmac.compare_digest(expected, parts[2])


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return secret[0] + "*" * (len(secret) - 1) if secret else ""
    return f"{secret[:3]}…{secret[-3:]} ({len(secret)} chars)"


def findings_from_exchange(exchange: HttpExchange) -> list[Finding]:
    """A CONFIRMED finding when a response string is proven (by HMAC) to be the
    JWT signing key the client's token uses. Empty otherwise."""
    jwts = _jwts_in(exchange)
    if not jwts:
        return []
    candidates = _candidate_secrets(exchange)
    for jwt in jwts:
        # Don't count the JWT (or its own segments) as its own "secret".
        for secret in candidates:
            if secret in jwt:
                continue
            if _secret_signs_jwt(jwt, secret):
                return [Finding(
                    vulnerability_class="jwt",
                    confidence=0.99,
                    confirmed=True,
                    severity="critical",
                    owasp_category="A02:2021-Cryptographic Failures",
                    summary="Disclosed JWT signing secret CONFIRMED: a string in the response is the "
                            "HMAC key that signs the session token.",
                    evidence=f"A value in the response (redacted: {_redact(secret)}) verifies the "
                             f"HS* signature of the JWT the client presents -- proven by recomputing "
                             f"the HMAC, not guessed. Anyone who can read this response can forge "
                             f"arbitrary tokens (e.g. an admin identity) the server will accept.",
                    suggested_test="Rotate the signing secret immediately and stop returning it in any "
                                   "response; the leak is exploitable as shown (HMAC match).",
                    basis="derived",
                    validation_hints=["secret_disclosure:jwt_signing_key"],
                )]
    return []
