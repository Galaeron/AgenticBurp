from __future__ import annotations
import re

"""
Canonical vulnerability categories, and normalization from the free-text
`vulnerability_class` string an LLM specialist writes into one of them.

Why this exists
----------------
`Finding.vulnerability_class` is genuinely free text (see base_agent.py's
prompt -- there is no enum constraint on what the model writes). Before
this module existed, planner.py matched that free text against
capability keys with an EXACT lowercase string comparison. If the idor
agent wrote "Insecure Direct Object Reference" or "IDOR" instead of the
literal string "idor", the lookup silently failed: no TestPlan was ever
created, no error was raised, and nothing downstream (including an
analyst reading the response) had any indication that a plan should
have existed and didn't. This is exactly the kind of silent gap the
project's own "known vs rediscover" and confirmation-honesty principles
exist to prevent -- it just happened to live in the plumbing rather
than in a finding's confidence number.

CANONICAL_CATEGORIES intentionally matches the specialist agent names in
orchestrator.py's _AGENT_CLASSES, since that mapping (AgentReport.agent)
IS reliable -- it's set programmatically by each agent class, never by
model output. Category-derived logic (the coverage ledger, capability
planning) should key off this canonical set, not off raw
vulnerability_class strings.
"""

CANONICAL_CATEGORIES: tuple[str, ...] = (
    "sqli", "xss", "idor", "ssrf", "auth", "business_logic",
    "business_logic_enhanced", "misconfig", "ai_llm", "supply_chain", "rate_limit",
    "jwt", "xxe", "csrf", "file_upload", "nosql",
    "command_injection", "ssti", "open_redirect", "info_disclosure",
    "path_traversal",
    "anomaly",
    "cors", "recon", "http_request_smuggling",
    "web_cache_poisoning", "oauth", "subdomain_takeover",
    "crypto", "csp", "header_injection", "api_security",
    "websocket", "race_condition", "deserialization",
    "session_fixation", "session_timeout", "reset_token", "dom_xss", "toctou",
)

# Deliberately generous but not promiscuous: each entry is a phrase an
# LLM plausibly writes for that category, lowercased. Keep this list
# reviewable -- a synonym that's too broad (e.g. mapping bare "access"
# to idor) would misclassify unrelated findings, which is worse than
# leaving them unmapped and visibly NOT_TESTED.
_SYNONYMS: dict[str, str] = {
    "sqli": "sqli", "sql injection": "sqli", "sql-injection": "sqli", "sqlinjection": "sqli",
    "xss": "xss", "cross-site scripting": "xss", "cross site scripting": "xss",
    "reflected xss": "xss", "stored xss": "xss", "dom xss": "xss", "dom-based xss": "xss",
    "idor": "idor", "insecure direct object reference": "idor",
    "insecure direct object references": "idor", "broken object level authorization": "idor",
    "bola": "idor", "object level authorization": "idor",
    "ssrf": "ssrf", "server-side request forgery": "ssrf", "server side request forgery": "ssrf",
    "auth": "auth", "authentication": "auth", "broken authentication": "auth",
    "session management": "auth", "broken session management": "auth",
    "business_logic": "business_logic", "business logic": "business_logic",
    "business logic flaw": "business_logic", "workflow abuse": "business_logic",
    "race condition": "business_logic",
    "misconfig": "misconfig", "misconfiguration": "misconfig",
    "security misconfiguration": "misconfig",
    # 2026-09-25 FR-4: the model's dominant snake_case spelling of this class
    # (35x in the captured benchmark runs) was NOT covered by _normalize()'s
    # hyphen-to-space folding (underscores are deliberately left untouched --
    # see _normalize's docstring -- so this needs its own explicit entry
    # rather than relying on the already-present "security misconfiguration").
    "security_misconfiguration": "misconfig",
    "ai_llm": "ai_llm", "prompt injection": "ai_llm", "llm": "ai_llm",
    "insecure output handling": "ai_llm",
    "supply_chain": "supply_chain", "supply chain": "supply_chain",
    "vulnerable and outdated components": "supply_chain",
    "outdated dependency": "supply_chain", "known vulnerable component": "supply_chain",
    "rate_limit": "rate_limit", "rate limiting": "rate_limit",
    "missing rate limiting": "rate_limit", "brute force": "rate_limit",
    "jwt": "jwt", "json web token": "jwt", "json-web-token": "jwt",
    "jws": "jwt", "jwe": "jwt", "jwt token": "jwt",
    "xxe": "xxe", "xml external entity": "xxe", "xml-external-entity": "xxe",
    "xee": "xxe", "xml injection": "xxe",
    "csrf": "csrf", "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf", "xsrf": "csrf",
    "file_upload": "file_upload", "file upload": "file_upload",
    "arbitrary file upload": "file_upload", "file upload vulnerability": "file_upload",
    "nosql": "nosql", "nosql injection": "nosql", "no-sql": "nosql",
    "no sql": "nosql", "mongodb injection": "nosql", "mongo injection": "nosql",
    "command_injection": "command_injection", "command injection": "command_injection",
    "rce": "command_injection", "remote code execution": "command_injection",
    "code injection": "command_injection", "shell injection": "command_injection",
    "ssti": "ssti", "template injection": "ssti", "server-side template injection": "ssti",
    "server side template injection": "ssti",
    "open_redirect": "open_redirect", "open redirect": "open_redirect",
    "redirect": "open_redirect", "url redirect": "open_redirect",
    "path_traversal": "path_traversal", "path traversal": "path_traversal",
    "directory traversal": "path_traversal", "directory_traversal": "path_traversal",
    "lfi": "path_traversal", "local file inclusion": "path_traversal",
    "file path traversal": "path_traversal", "file inclusion": "path_traversal",
    "arbitrary file read": "path_traversal", "dot dot slash": "path_traversal",
    "info_disclosure": "info_disclosure", "information disclosure": "info_disclosure",
    "info disclosure": "info_disclosure", "information leak": "info_disclosure",
    "data leak": "info_disclosure", "sensitive data exposure": "info_disclosure",
    # 2026-09-25 FR-4: every one of these snake_case/compound variants missed
    # entirely before this fix (canonicalize() returned None, so the gate's
    # raw-lowercase fallback never matched the "info_disclosure" key) -- the
    # model's dominant info-disclosure spellings in the captured benchmark
    # runs. Same underscore-vs-space rationale as security_misconfiguration
    # above: _normalize() folds hyphens to spaces, not underscores, so both
    # forms are listed explicitly where they differ.
    "information_disclosure": "info_disclosure",
    "verbose_error_disclosure": "info_disclosure", "verbose error disclosure": "info_disclosure",
    "excessive_data_exposure": "info_disclosure",
    "exposure_of_internal_data": "info_disclosure", "exposure of internal data": "info_disclosure",
    "exposure_of_sensitive_information": "info_disclosure",
    "exposure of sensitive information": "info_disclosure",
    "information_disclosure_header": "info_disclosure",
    "information disclosure header": "info_disclosure",
    "business_logic_enhanced": "business_logic_enhanced", "business logic enhanced": "business_logic_enhanced",
    "workflow abuse": "business_logic_enhanced", "state manipulation": "business_logic_enhanced",
    "anomaly": "anomaly", "anomaly detection": "anomaly", "unknown vulnerability": "anomaly",
    "cors": "cors",
    "cross-origin resource sharing": "cors",
    "cross origin resource sharing": "cors",
    "cors misconfiguration": "cors",
    "recon": "recon",
    "reconnaissance": "recon",
    "attack surface mapping": "recon",
    "attack map": "recon",
    "http_request_smuggling": "http_request_smuggling",
    "request smuggling": "http_request_smuggling",
    "http smuggling": "http_request_smuggling",
    "cl.te": "http_request_smuggling",
    "te.cl": "http_request_smuggling",
    "te.te": "http_request_smuggling",
    "web_cache_poisoning": "web_cache_poisoning",
    "web cache poisoning": "web_cache_poisoning",
    "cache poisoning": "web_cache_poisoning",
    "cache_poisoning": "web_cache_poisoning",
    "cache deception": "web_cache_poisoning",
    "web cache deception": "web_cache_poisoning",
    "oauth": "oauth", "oauth2": "oauth", "oauth 2.0": "oauth",
    "oidc": "oauth", "openid connect": "oauth", "open id connect": "oauth",
    "subdomain_takeover": "subdomain_takeover",
    "subdomain takeover": "subdomain_takeover",
    "dangling dns": "subdomain_takeover",
    "dangling_dns": "subdomain_takeover",
    "dns takeover": "subdomain_takeover",
    "crypto": "crypto", "cryptography": "crypto", "weak crypto": "crypto",
    "weak_crypto": "crypto", "tls": "crypto", "ssl": "crypto",
    "csp": "csp", "content security policy": "csp", "content_security_policy": "csp",
    "clickjacking": "csp",
    "header_injection": "header_injection", "header injection": "header_injection",
    "crlf injection": "header_injection", "crlf_injection": "header_injection",
    "response splitting": "header_injection",
    "smtp header injection": "header_injection", "email header injection": "header_injection",
    "api_security": "api_security", "api security": "api_security",
    "mass assignment": "api_security", "mass_assignment": "api_security",
    "excessive data exposure": "api_security",
    "unbounded resource consumption": "api_security",
    "websocket": "websocket", "websockets": "websocket", "cswsh": "websocket",
    "cross-site websocket hijacking": "websocket", "cross site websocket hijacking": "websocket",
    "race_condition": "race_condition", "race condition": "race_condition",
    "toctou": "race_condition", "time of check to time of use": "race_condition",
    "deserialization": "deserialization", "insecure deserialization": "deserialization",
    "insecure_deserialization": "deserialization",
    "session_fixation": "session_fixation", "session fixation": "session_fixation",
    "fixation": "session_fixation",
    "reset_token": "reset_token", "reset token": "reset_token",
    "predictable token": "reset_token", "predictable reset token": "reset_token",
    "weak token": "reset_token", "insecure token": "reset_token",
    "token entropy": "reset_token", "weak_reset_token": "reset_token",
    "dom_xss": "dom_xss", "dom xss": "dom_xss", "dom-based xss": "dom_xss",
    "dom based xss": "dom_xss", "dom-based cross-site scripting": "dom_xss",
    "client-side xss": "dom_xss", "client side xss": "dom_xss",
    "client-side cross-site scripting": "dom_xss",
    "toctou": "toctou", "time-of-check": "toctou", "time of check": "toctou",
    "time-of-check to time-of-use": "toctou", "time of check to time of use": "toctou",
    "check-then-act": "toctou", "check then act": "toctou",
    "privilege escalation race": "toctou", "race privilege escalation": "toctou",
    "priv esc race": "toctou", "toctou_privilege_escalation": "toctou",
    "session_timeout": "session_timeout", "session timeout": "session_timeout",
    "logout invalidation": "session_timeout", "logout_invalidation": "session_timeout",
    "session not invalidated": "session_timeout",
    "behavioral anomaly": "anomaly", "suspicious behavior": "anomaly",
}


def _normalize(text: str) -> str:
    """
    Normalize surface variation that isn't a real ambiguity -- a
    trailing parenthetical annotation (found live: "Insecure Direct
    Object Reference (IDOR)", "Broken Object-Level Authorization
    (BOLA/IDOR)"), and hyphens used where the synonym table has a space
    ("Object-Level" vs "object level"). This is still exact matching
    against a fixed table afterward, not fuzzy/substring matching --
    canonicalize()'s "return None rather than guess" guarantee is
    unchanged for anything that isn't just cosmetic variation of a
    phrase already in the table.
    """
    text = re.sub(r"\s*\([^)]*\)\s*$", "", text)  # strip one trailing "(...)"
    text = text.replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def canonicalize(raw: str | None) -> str | None:
    """
    Map a free-text vulnerability_class to one of CANONICAL_CATEGORIES,
    or None if it doesn't recognizably match any of them. Returning None
    (rather than guessing) is deliberate: an unmapped category should
    surface as visibly uncategorized, not get silently absorbed into the
    nearest-sounding bucket.
    """
    if not raw:
        return None
    key = raw.strip().lower()
    if key in CANONICAL_CATEGORIES:
        return key
    if key in _SYNONYMS:
        return _SYNONYMS[key]
    normalized = _normalize(key)
    if normalized in CANONICAL_CATEGORIES:
        return normalized
    return _SYNONYMS.get(normalized)


def all_known_phrases() -> dict[str, str]:
    """
    Public accessor for the full exact-match phrase table: every
    canonical category name mapped to itself, plus every synonym
    mapped to its canonical target. Exists so other modules that want
    to build a LOOSER match (e.g. chaining.py's substring fallback,
    which deliberately accepts more false positives than canonicalize()
    would because a chain hypothesis is human-reviewed, low-confidence
    output, not a routing decision) can reuse this table rather than
    maintaining their own copy that can drift out of sync, without
    reaching into the private _SYNONYMS dict directly.
    """
    table = {cat: cat for cat in CANONICAL_CATEGORIES}
    table.update(_SYNONYMS)
    return table
