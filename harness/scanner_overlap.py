"""
Scanner-overlap classification (HU-8, `reporting.scanner_overlap_appendix`).

A passive scanner such as Burp Scanner already reports missing security headers,
CSP, CORS, framing, cookie flags, verbose errors, server banners and JWT header
hygiene. When the option is on, findings of these classes leave the main report for
a counted appendix (report_generator.generate_markdown_report), and worklist nodes
whose only findings are of these classes stop drawing from the agent budget
(worklist_investigator.investigate_worklist, skip reason `scanner_overlap`).

One exception keeps a finding in the main view: a PROVEN exploit. "Proven" reads
the stored proof and verification fields, never severity or confidence alone:

- the finding is confirmed, is not an external tool's unreproduced detection, and
  names its proof (proof_id / confirmed_by_leg / confirmation_method) or carries an
  oracle verification; and
- the proof shows impact for the class. Only two classes can show it:
  * cors: the CORS leg's own wording for a credentialed origin grant (the
    attacker origin is reflected together with Allow-Credentials: true), found in
    the finding's evidence/summary or a confirmed proof's observed_result;
  * jwt_header: a confirmation by the token-forgery leg (a forged token was
    accepted).
  Every other class is a passive observation and has no exception.

Classification reads only harness-owned fields (class label, validator, proof
fields, evidence text). It names no target route or field. Sends nothing.
"""
from __future__ import annotations

import re

from harness.categories import canonicalize

# The scanner-equivalent classes, as the harness emits them. Each maps to how it is
# recognised; see overlap_class(). Order is the appendix's row order.
#   missing_headers -- WSTG-CONF-02 (security_headers validator), canonical
#                      `missing_headers`, anomaly `missing_security_header`
#   csp             -- WSTG-CONF-05 (csp validator), canonical `csp`
#   clickjacking    -- framing (X-Frame-Options / frame-ancestors); canonicalises to csp
#   cors            -- WSTG-CONF-08 (cors validator), canonical `cors`
#   cookie_flags    -- Secure / HttpOnly / SameSite cookie attributes
#   verbose_error   -- WSTG-ERRH-01 (error_handling) and verbose_error validators,
#                      class `verbose_error_disclosure`, stack traces
#   server_banner   -- Server / X-Powered-By version banners, anomaly
#                      `information_disclosure_header`
#   jwt_header      -- JWT header / alg hygiene (alg, kid, typ, algorithm confusion)
SCANNER_OVERLAP_CLASSES: tuple[str, ...] = (
    "missing_headers", "csp", "clickjacking", "cors", "cookie_flags",
    "verbose_error", "server_banner", "jwt_header",
)

SCANNER_OVERLAP_LABELS: dict[str, str] = {
    "missing_headers": "Missing security headers",
    "csp": "Content-Security-Policy",
    "clickjacking": "Clickjacking / framing",
    "cors": "CORS policy",
    "cookie_flags": "Cookie flags",
    "verbose_error": "Verbose error / stack trace",
    "server_banner": "Server / version banner",
    "jwt_header": "JWT header / alg hygiene",
}

# Validator names (ValidationResult.validator / proof_records.validator /
# confirmed_by_leg) of the passive legs behind these classes.
_VALIDATOR_CLASS = {
    "security_headers": "missing_headers", "security_headers_validator": "missing_headers",
    "csp": "csp", "csp_validator": "csp",
    "cors": "cors", "cors_validator": "cors",
    "verbose_error": "verbose_error", "verbose_error_validator": "verbose_error",
    "error_handling": "verbose_error", "error_handling_validator": "verbose_error",
}
_JWT_FORGE_LEGS = frozenset({"jwt_forge", "jwt_forge_validator"})

_FRAMING = ("clickjack", "x frame options", "frame ancestors", "framing")
_HEADER_WORDS = ("missing security header", "security header", "x content type options",
                 "nosniff", "referrer policy", "strict transport security", "hsts",
                 "permissions policy", "x xss protection", "missing header")
_COOKIE_ATTRS = ("flag", "secure", "httponly", "http only", "samesite", "same site", "attribute")
_ERROR_WORDS = ("verbose error", "stack trace", "stacktrace", "traceback",
                "debug error", "error page", "error handling", "error message disclosure")
_BANNER_WORDS = ("banner", "version disclosure", "server version", "server header",
                 "x powered by", "powered by header", "disclosure header", "server fingerprint",
                 "technology disclosure")
_JWT_HYGIENE = re.compile(r"\b(alg|algorithm|header|kid|typ|jku|x5u|hs256|rs256|none)\b")

# Catch-all canonical classes whose summary may name a scanner class
# ("Security misconfiguration" + "missing X-Frame-Options"). Only the specific
# header/error/banner words are read there, never a broad term.
_CATCHALL = {None, "misconfig", "info_disclosure", "recon"}

# The CORS leg's wording for a credentialed origin grant
# (validators/cors_validator._REFLECTION_CREDENTIALED_DETAIL and its evidence).
_CREDENTIALED_CORS = (
    re.compile(r"sent with the user'?s cookies"),
    re.compile(r"origin: (?!null\b)\S+ -> access-control-allow-origin: (?!\*)\S+, "
               r"access-control-allow-credentials: true"),
)


def enabled(config: dict | None) -> bool:
    """`reporting.scanner_overlap_appendix` from an effective config (default False)."""
    return bool(((config or {}).get("reporting") or {}).get("scanner_overlap_appendix", False))


def _norm(text) -> str:
    return re.sub(r"[\s_\-:/()]+", " ", str(text or "").lower()).strip()


def _get(finding, key, default=None):
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _leg_names(finding) -> set[str]:
    return {str(v).lower() for v in (_get(finding, "validator"), _get(finding, "confirmed_by_leg"),
                                     _get(finding, "confirmation_method")) if v}


def _match_text(text: str, specific_only: bool) -> str | None:
    if any(w in text for w in _FRAMING):
        return "clickjacking"
    if "content security policy" in text or (not specific_only and re.search(r"\bcsp\b", text)):
        return "csp"
    if any(w in text for w in _HEADER_WORDS):
        return "missing_headers"
    if "cookie" in text and any(w in text for w in _COOKIE_ATTRS):
        return "cookie_flags"
    if any(w in text for w in _ERROR_WORDS):
        return "verbose_error"
    if any(w in text for w in _BANNER_WORDS):
        return "server_banner"
    if "access control allow origin" in text or (not specific_only and re.search(r"\bcors\b", text)):
        return "cors"
    return None


def overlap_class(finding) -> str | None:
    """The SCANNER_OVERLAP_CLASSES entry a finding belongs to, else None.

    Reads the class label first (canonical category, then the label's own words),
    then the passive validator that judged it, and -- only for a catch-all class
    (misconfig / info_disclosure / recon / unmapped) -- the summary's specific
    header, error and banner words. A chain hypothesis is never matched."""
    vc = str(_get(finding, "vulnerability_class", "") or "")
    if vc.startswith("potential-attack-chain:"):
        return None
    canon = canonicalize(vc)
    text = _norm(vc)
    if canon == "jwt" or "jwt" in text or "json web token" in text:
        hay = text + " " + _norm(_get(finding, "summary", ""))
        return "jwt_header" if _JWT_HYGIENE.search(hay) else None
    if "algorithm confusion" in text:
        return "jwt_header"
    by_text = _match_text(text, specific_only=False)
    if by_text:
        return by_text
    if canon in ("missing_headers", "csp", "cors"):
        return canon
    for leg in _leg_names(finding):
        if leg in _VALIDATOR_CLASS:
            return _VALIDATOR_CLASS[leg]
    if canon in _CATCHALL:
        return _match_text(_norm(_get(finding, "summary", "")), specific_only=True)
    return None


def _has_proof(finding) -> bool:
    if not _get(finding, "confirmed", False):
        return False
    if _get(finding, "evidence_source", "") == "tool_reported" or _get(finding, "tool_reported", False):
        return False
    return bool(_get(finding, "proof_id", "") or _get(finding, "confirmed_by_leg", "")
                or _get(finding, "confirmation_method", "") or _get(finding, "oracle_verified", False))


def is_proven_exception(finding, proof_texts: list[str] | tuple = ()) -> bool:
    """True for a scanner-class finding with a recorded proof of impact, which stays
    in the main report (see the module docstring). `proof_texts` are the
    observed_result strings of the finding's confirmed proof records, when the
    caller has them; the finding's own evidence and summary are always read."""
    cls = overlap_class(finding)
    if cls is None or not _has_proof(finding):
        return False
    if cls == "cors":
        hay = " ".join([str(_get(finding, "evidence", "") or ""),
                        str(_get(finding, "summary", "") or ""), *map(str, proof_texts)]).lower()
        return any(p.search(hay) for p in _CREDENTIALED_CORS)
    if cls == "jwt_header":
        return bool(_leg_names(finding) & _JWT_FORGE_LEGS)
    return False


def routes_to_appendix(finding, proof_texts: list[str] | tuple = ()) -> bool:
    """True when the finding is scanner-equivalent and not a proven exception."""
    return overlap_class(finding) is not None and not is_proven_exception(finding, proof_texts)


def _low_trust_privileged(node: dict) -> bool:
    reasons = node.get("reasons") or []
    return (any("privileged-looking" in r and "reach" in r for r in reasons)
            or any("authz gap" in r.lower() for r in reasons))


def is_scanner_equivalent_node(node: dict) -> bool:
    """True for a worklist node whose findings are all appendix-routed scanner
    classes and that carries no structural signal of its own: not object-scoped,
    no low-trust role reaching a privileged-looking path, and not a write with a
    captured body. Such a node's rank comes from scanner noise, so it takes no
    agent-budget slot (its shape-driven legs still run)."""
    findings = node.get("findings") or []
    if not findings or not all(routes_to_appendix(f) for f in findings):
        return False
    if node.get("object_scoped") or _low_trust_privileged(node):
        return False
    template = node.get("template") or {}
    if ((node.get("method") or "GET").upper() in ("POST", "PUT", "PATCH")
            and str(template.get("body") or "").strip()):
        return False
    return True
