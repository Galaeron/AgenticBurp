"""
Predictable reset/session-token confirmation leg (V3, WSTG-ATHN / WSTG-SESS).

Oracle (LEG_DECISIONS.md #5): collect several password-reset (or session) tokens
and show they are predictable -- sequential, timestamp-derived, a constant, below
an entropy floor, or a transform of a known value (the user id / email).

The decision this leg encodes: it confirms ONLY the UNAMBIGUOUS, deterministic
cases, and leaves fuzzy "looks low-entropy" as not_confirmed -- so a genuinely
random but short-ish token is never falsely called weak (the precision risk the
doc flags). The predictability test (`analyze_tokens`) is pure and unit-tested on
its own; the validator only supplies the sampling.

Sampling triggers the reset flow N times and reads the token where it is
OBSERVABLE in the response (a JSON token field, a reset link's token param, or a
Set-Cookie). If the token isn't observable (emailed out-of-band), the leg skips
as inconclusive rather than guess. The trigger is a mutating POST, routed through
GatedAsyncClient (needs allow_mutating_replay); N is small (default 5).
"""
from __future__ import annotations

import base64
import math
import re
import string
from urllib.parse import urlsplit, parse_qs

import httpx

from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult

# A token seen in a JSON body, a reset link, or a cookie.
_JSON_TOKEN_RE = re.compile(
    r'"(?:reset_?token|token|reset_?code|code|otp|nonce|key)"\s*:\s*"([^"]{4,})"', re.I)
_LINK_TOKEN_RE = re.compile(r'[?&](?:reset_?token|token|t|code|key)=([A-Za-z0-9._\-]{4,})', re.I)


def _charset_bits_per_char(token: str) -> float:
    """Bits-per-character implied by the token's alphabet (an upper bound on its
    per-char entropy)."""
    classes = 0
    if any(c in string.digits for c in token):
        classes += 10
    if any(c in string.ascii_lowercase for c in token):
        classes += 26
    if any(c in string.ascii_uppercase for c in token):
        classes += 26
    if any(c in "._-+/=" for c in token):
        classes += 6
    return math.log2(classes) if classes > 1 else 0.0


def _max_entropy_bits(token: str) -> float:
    """Upper bound on the entropy this token could carry (charset x length). A
    token whose CEILING is below 64 bits is weak no matter how random -- it simply
    can't hold enough state."""
    return _charset_bits_per_char(token) * len(token)


def _as_int(token: str):
    if token.isdigit():
        return int(token)
    if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) % 2 == 0:
        try:
            return int(token, 16)
        except ValueError:
            return None
    return None


def analyze_tokens(tokens: list[str], *, known_values: list[str] | None = None
                   ) -> tuple[bool, str]:
    """Deterministic predictability oracle. Returns (predictable, reason).
    Confirms ONLY unambiguous cases; anything else is (False, why-not)."""
    toks = [t for t in (tokens or []) if t]
    known = [k for k in (known_values or []) if k]
    if not toks:
        return False, "no tokens observed to analyse"

    # 1. constant: the "random" token never changes.
    if len(set(toks)) == 1 and len(toks) >= 2:
        return True, f"the reset token is CONSTANT across {len(toks)} requests ({toks[0]!r})"

    # 2. below the entropy floor: charset x length can't hold 64 bits.
    weak = [t for t in toks if _max_entropy_bits(t) < 64]
    if weak and len(weak) == len(toks):
        bits = min(_max_entropy_bits(t) for t in toks)
        return True, (f"every sampled token is below the 64-bit entropy floor "
                      f"(max ~{bits:.0f} bits for a {len(toks[0])}-char token) -- brute-forceable")

    # 3. strictly sequential / small-delta integers.
    ints = [_as_int(t) for t in toks]
    if all(i is not None for i in ints) and len(ints) >= 2:
        deltas = [b - a for a, b in zip(ints, ints[1:])]
        if all(d == deltas[0] for d in deltas) and deltas[0] != 0:
            return True, (f"tokens are strictly arithmetic (constant delta {deltas[0]}) across "
                          f"samples -- fully predictable ({ints[:3]}...)")
        if all(0 < d <= 16 for d in deltas):
            return True, (f"tokens increment by small deltas {deltas} across samples -- "
                          f"predictable / guessable")

    # 4. timestamp-derived: 10-digit unix-seconds (or 13-digit ms) values.
    if all(t.isdigit() and len(t) in (10, 13) and t[0] == "1" for t in toks):
        return True, "tokens are unix-timestamp-shaped (10/13 digit, leading 1) -- time-predictable"

    # 5. transform of a known value (user id / email): equals it, or base64 of it.
    for t in toks:
        for k in known:
            if k and (k in t or t == k):
                return True, f"a token embeds a known value {k!r} -- derived, not random"
            try:
                dec = base64.b64decode(t + "===", validate=False).decode("utf-8", "ignore")
            except Exception:
                dec = ""
            if k and k in dec and len(k) >= 3:
                return True, f"a token base64-decodes to a known value ({k!r}) -- derived, not random"

    return False, (f"{len(toks)} sampled tokens show no deterministic weakness "
                   f"(not constant/sequential/timestamped/below-floor) -- not confirmed")


class ResetTokenValidator(Validator):
    name = "reset_token"
    finding_classes = {"reset_token", "reset token", "predictable token", "weak token",
                       "insecure token", "predictable reset token", "token entropy",
                       "weak_reset_token", "insufficient randomness"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 samples: int = 5):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.samples = max(2, int(samples))

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "reset_token", summary=why)

    def _extract_token(self, resp) -> str | None:
        body = getattr(resp, "text", "") or ""
        m = _JSON_TOKEN_RE.search(body)
        if m:
            return m.group(1)
        m = _LINK_TOKEN_RE.search(body)
        if m:
            return m.group(1)
        headers = getattr(resp, "headers", {}) or {}
        loc = next((v for k, v in headers.items() if k.lower() == "location"), "")
        if loc:
            m = _LINK_TOKEN_RE.search(loc)
            if m:
                return m.group(1)
            qs = parse_qs(urlsplit(loc).query)
            for key in ("token", "reset_token", "t", "code", "key"):
                if key in qs and qs[key]:
                    return qs[key][0]
        setc = " ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
        m = re.search(r'(?:reset_?token|token|code)=([A-Za-z0-9._\-]{4,})', setc, re.I)
        return m.group(1) if m else None

    def _known_values(self, exchange: HttpExchange) -> list[str]:
        """Values a predictable token might be derived from -- the email/username
        submitted, drawn from the request body/query."""
        known: list[str] = []
        blob = (exchange.request_body or "") + "&" + (urlsplit(exchange.url).query or "")
        for m in re.finditer(r'(?:email|user(?:name)?|login|account)["\s:=]+([^"&\s]{3,})', blob, re.I):
            known.append(m.group(1))
        for m in re.finditer(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', blob):
            known.append(m.group(0))
            known.append(m.group(0).split("@")[0])
        return known

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        # Triggering N reset flows is a mutating action (side effects/emails).
        method = "POST"
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        content = exchange.request_body.encode() if exchange.request_body else None
        tokens: list[str] = []
        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                for _ in range(self.samples):
                    await global_throttle.acquire()
                    try:
                        resp = await client.request(method, exchange.url,
                                                    headers=headers or None, content=content)
                    except SafetyGateBlocked as e:
                        return self._skip(f"mutating reset replay not authorized: {e.decision.reason}")
                    except httpx.HTTPError:
                        continue
                    tok = self._extract_token(resp)
                    if tok:
                        tokens.append(tok)
        except SafetyGateBlocked as e:
            return self._skip(f"mutating reset replay not authorized: {e.decision.reason}")
        except Exception as e:
            return self._skip(f"reset sampling failed: {e.__class__.__name__}")

        if len(tokens) < 2:
            return self._skip(f"only {len(tokens)} token(s) observable in responses -- token is "
                              f"likely emailed out-of-band; cannot sample entropy (inconclusive)")

        predictable, reason = analyze_tokens(tokens, known_values=self._known_values(exchange))
        if predictable:
            # RETIRED (review 2026-09-09): a predictability PATTERN in a small sample
            # is an OBSERVATION, not proof of exploitability -- two numeric samples
            # always have a constant delta, a public prefix + strong random suffix is
            # not predictable, and reusing an unexpired random token can be legitimate.
            # This no longer sets confirmed=True. Re-qualify: a HOLDOUT test -- predict
            # the NEXT token from prior samples, submit it, and show it is ACCEPTED for
            # another account -- plus lifetime / single-use / rate-limit context; only
            # then may this emit confirmed=True (and re-add to the gate's LIVE set).
            return ValidationResult(
                self.name, "not_confirmed", "reset_token", confidence=0.35, confirmed=False,
                summary=f"OBSERVATION (not confirmed): a reset-token predictability pattern was seen "
                        f"-- {reason}. NOT a confirmed weakness: needs a holdout prediction (forge the "
                        f"next token and show it is accepted for another account) to confirm.",
                evidence=f"Sampled {len(tokens)} reset tokens from independent requests; {reason}. "
                         f"Small-sample pattern only -- no holdout prediction/acceptance was performed.")
        return ValidationResult(
            self.name, "not_confirmed", "reset_token", confidence=0.1, confirmed=False,
            summary=f"No deterministic reset-token weakness observed: {reason}.",
            evidence=f"Sampled {len(tokens)} tokens; none of the predictability tests "
                     f"(constant / sequential / timestamp / below-floor / known-value-derived) matched.")
