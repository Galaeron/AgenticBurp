"""
Negative-control builders for the oracle framework (precision item #1).

Each builder takes the original (vulnerable) exchange and returns a BENIGN variant
of the same request that the class's probe should NOT confirm on. Running the same
probe against this variant and requiring it to stay clean is what turns "the leg
fired" into "the leg fired AND is discriminating" -- the paired negative control
that filters a probe which would confirm on any input.

A builder returns None when it cannot construct a control for a specific exchange
(e.g. the injectable parameter it neutralises isn't present); the oracle treats
that identically to "no builder for this class" -- control unavailable, finding
stays a candidate.

`SELF_CONTROLLING` names the legs whose confirmation is inherently a negative
control of itself: an out-of-band collaborator callback carries a unique,
unguessable token, so a hit PROVES the server fetched our URL -- there is no
benign input that produces the same callback. Those legs reach VERIFIED on N-of-N
reproduction alone.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit, parse_qsl

from harness.models import HttpExchange

# A single benign literal reused across builders: it is not a URL, not numeric,
# not a path, and contains no metacharacters, so no discriminating probe should
# treat it as an injection/redirect/traversal payload.
_BENIGN = "benign_control_value"


def _content_type(exchange: HttpExchange) -> str:
    for k, v in (exchange.request_headers or {}).items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def _looks_json(body: str, ctype: str) -> bool:
    if "json" in ctype:
        return True
    b = (body or "").strip()
    return b.startswith("{") or b.startswith("[")


def _neutralise_query(url: str, replacement: str) -> str:
    """Replace EVERY query value with the benign literal, keeping param names."""
    parts = urlsplit(url or "")
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return ""
    new_q = "&".join(f"{k}={replacement}" for k, _ in pairs)
    return f"{parts.scheme}://{parts.netloc}{parts.path}?{new_q}"


def _neutralise_body(exchange: HttpExchange, replacement: str) -> str:
    body = exchange.request_body or ""
    if not body.strip():
        return ""
    if _looks_json(body, _content_type(exchange)):
        try:
            obj = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            return ""
        if isinstance(obj, dict):
            return json.dumps({k: replacement for k in obj})
        return ""
    # urlencoded form
    parts = [p for p in body.split("&") if p]
    if not parts:
        return ""
    return "&".join(f"{p.split('=', 1)[0]}={replacement}" for p in parts)


def _replace_all_params(exchange: HttpExchange, replacement: str) -> HttpExchange | None:
    """Benign variant with every query AND body value replaced by `replacement`.
    None when there is nothing to neutralise (no params to make a control from)."""
    new_url = _neutralise_query(exchange.url, replacement)
    new_body = _neutralise_body(exchange, replacement)
    if not new_url and not new_body:
        return None
    data = exchange.model_dump()
    if new_url:
        data["url"] = new_url
    if new_body:
        data["request_body"] = new_body
    return HttpExchange(**data)


def _benign_literal(exchange: HttpExchange) -> HttpExchange | None:
    return _replace_all_params(exchange, _BENIGN)


def _benign_integer(exchange: HttpExchange) -> HttpExchange | None:
    # For SQLi: a plain integer in every param carries no SQL metacharacters, so a
    # discriminating boolean/error/time probe must not confirm on it.
    return _replace_all_params(exchange, "1")


# Class-name -> builder. Keyed by VALIDATOR name (oracle_framework looks the
# builder up by the validator it picked, so the key matches validators/*.name).
BUILDERS: dict = {
    "sqlmap": _benign_integer,
    "ssti": _benign_integer,
    "path_traversal": _benign_literal,
    "open_redirect": _benign_literal,
    "header_injection": _benign_literal,
    "sequence": _benign_literal,
    "stored_xss": _benign_literal,
    "browser_xss": _benign_literal,
    "dom_xss": _benign_literal,
}

# Legs whose confirmation is a self-contained proof (unique OOB token callback):
# reproduced N-of-N is sufficient for VERIFIED, no benign-variant control needed.
SELF_CONTROLLING: frozenset = frozenset({
    "ssrf", "xxe", "command_injection", "deserialization_oob",
})
