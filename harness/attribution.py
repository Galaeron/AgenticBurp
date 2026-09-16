"""
Category-attribution reliability -- Phase 3.5.

Detection breadth is one axis; whether a finding's CLASS label is correct is a
separate one, and agents mislabel: on one endpoint an agent emitted several
mutually-exclusive classes (none the real bug) while the correct class landed on
a different, structurally-similar endpoint. Three defenses, each a pure function:

(a) relabel_confirmed_finding -- when a deterministic leg CONFIRMS a finding, the
    class is authoritative from the leg (which actually proved that class),
    overriding a wrong/variant agent label.
(b) shape_consistent -- the endpoint's own shape is a prior. A class that needs a
    specific shape (xxe needs an XML body, sqli needs an injectable param, jwt
    needs a token, idor needs an object id) is flagged inconsistent on an
    endpoint that lacks it, so a shape-contradicting label doesn't stand
    unchallenged. Classes with no strong shape requirement are never flagged.
(c) chain_input_speculative -- a chain composed from an unconfirmed input whose
    basis is 'assumed'/'recalled' (not directly observed) is built on a premise
    that may itself be a mislabel; such chains are tagged speculative.
"""
from __future__ import annotations

import re

from harness import categories
from harness.recall_benchmark import confirmation_leg_of

# The class each confirmation leg is authoritative for -- the leg proved THIS
# class, whatever the agent had labelled the finding.
_LEG_CLASS = {
    "cross_identity": "idor",
    "browser_xss": "xss",
    "jwt_forge": "jwt",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "command_injection": "command_injection",
    "ssti": "ssti",
    "path_traversal": "path_traversal",
    "open_redirect": "open_redirect",
    "sqlmap": "sqli",
    "confidential_info": "info_disclosure",
}

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]+")
_OBJECT_ID_RE = re.compile(r"/(?:\d+|\{[^/]+\})(?:/|$)")


def _canon(raw) -> str:
    return categories.canonicalize(raw) or (raw or "").strip().lower()


def _get(finding, key):
    return getattr(finding, key, None) if not isinstance(finding, dict) else finding.get(key)


def _set(finding, key, value) -> None:
    if isinstance(finding, dict):
        finding[key] = value
    else:
        setattr(finding, key, value)


# --- (a) validator-authoritative relabel -------------------------------------

def relabel_confirmed_finding(finding) -> bool:
    """If a finding was CONFIRMED by a deterministic leg, set its class from the
    leg (the authoritative source for what was actually proven), overriding a
    wrong or variant agent label. No-op unless the finding is confirmed, names a
    known leg in its evidence, and that leg's class differs from the current one.
    Accepts a Finding object or a dict. Returns whether it relabelled."""
    if not _get(finding, "confirmed"):
        return False
    # confirmation_leg_of reads evidence/proactive_leg/validation_hints.
    probe = {"evidence": _get(finding, "evidence") or "",
             "proactive_leg": _get(finding, "proactive_leg"),
             "validation_hints": _get(finding, "validation_hints") or []}
    canon = _LEG_CLASS.get(confirmation_leg_of(probe))
    if not canon:
        return False
    if _canon(_get(finding, "vulnerability_class")) == canon:
        return False
    _set(finding, "original_vulnerability_class", _get(finding, "vulnerability_class"))
    _set(finding, "vulnerability_class", canon)
    return True


def relabel_confirmed_findings(findings) -> int:
    return sum(1 for f in (findings or []) if relabel_confirmed_finding(f))


# --- (b) shape-based label sanity --------------------------------------------

def _has_jwt(exchange) -> bool:
    blob = " ".join([
        " ".join((exchange.request_headers or {}).values()),
        exchange.request_body or "", exchange.response_body or "",
        " ".join((exchange.response_headers or {}).values()),
    ])
    return bool(_JWT_RE.search(blob))


def _has_object_id(url: str) -> bool:
    from urllib.parse import urlsplit
    return bool(_OBJECT_ID_RE.search(urlsplit(url or "").path))


def shape_consistent(finding_class, exchange) -> bool:
    """False only when `finding_class` has a shape requirement the exchange
    clearly does not meet (an xxe label on a non-XML endpoint, a jwt label where
    no token appears, an injection label with no injectable param). Classes with
    no strong shape requirement return True -- this flags contradictions, it does
    not require every class to justify its shape."""
    canon = _canon(finding_class)
    # Reuse the orchestrator's own shape predicates so routing and this sanity
    # check never drift. Lazy import: orchestrator is already loaded at call time
    # and importing it at module top would be circular.
    from harness.orchestrator import (_accepts_xml, _has_url_param, _has_injectable_param,
                              _has_file_shape, _has_redirect_param)
    if canon in ("sqli", "command_injection", "ssti", "nosql", "xss"):
        return _has_injectable_param(exchange)
    if canon == "xxe":
        return _accepts_xml(exchange)
    if canon == "ssrf":
        return _has_url_param(exchange)
    if canon == "open_redirect":
        return _has_redirect_param(exchange)
    if canon == "path_traversal":
        return _has_file_shape(exchange)
    if canon == "jwt":
        return _has_jwt(exchange)
    if canon == "idor":
        return _has_object_id(exchange.url)
    return True


def annotate_shape_inconsistent(findings, exchange) -> int:
    """Flag each UNCONFIRMED finding whose class contradicts the endpoint shape
    (a confirmed finding needs no shape prior -- it was proven). Non-destructive:
    records review_note + a marker, leaving severity to the confirmation gate.
    Returns the number flagged."""
    n = 0
    for f in findings or []:
        if _get(f, "confirmed"):
            continue
        if not shape_consistent(_get(f, "vulnerability_class"), exchange):
            note = (f"shape-inconsistent label: {_get(f, 'vulnerability_class')} on an endpoint "
                    f"whose shape does not support that class")
            _set(f, "review_note", ((_get(f, "review_note") or "") + " || " + note).strip(" |"))
            _set(f, "shape_inconsistent", True)
            n += 1
    return n


# --- (c) chain-input gating --------------------------------------------------

def chain_input_speculative(finding: dict) -> bool:
    """A chain input is speculative when it was neither confirmed nor directly
    observed -- basis 'assumed'/'recalled'. Composing a chain on such an input
    risks building a plausible story on a mislabel (improvement-note #5)."""
    if finding.get("confirmed"):
        return False
    return (finding.get("basis") or "").strip().lower() in ("assumed", "recalled")
