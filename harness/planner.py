from __future__ import annotations
from harness.models import Finding, HttpExchange, TestPlan
from harness.categories import canonicalize
import hashlib

# Declarative capabilities that the Burp execution plane can implement without
# granting an LLM arbitrary HTTP or shell access.
_CAPABILITIES = {
    "idor": ("cross_identity_compare", True),
    "business_logic": ("workflow_replay_compare", True),
    "business_logic_enhanced": ("workflow_replay_compare", True),
    "rate_limit": ("bounded_rate_limit_probe", True),
    "ssrf": ("controlled_callback_probe", True),
    "auth": ("authorization_boundary_compare", True),
    "xss": ("reflection_context_validation", True),
    "jwt": ("jwt_validation", True),
    "xxe": ("xxe_validation", True),
    "csrf": ("csrf_validation", True),
    "file_upload": ("file_upload_validation", True),
    "nosql": ("nosql_validation", True),
    "command_injection": ("command_injection_validation", True),
    "ssti": ("ssti_validation", True),
    "open_redirect": ("open_redirect_validation", True),
    "info_disclosure": ("info_disclosure_scan", False),  # Passive, no active validation
    "cors": ("cors_misconfiguration_detection", True),
    "recon": ("attack_surface_mapping", True),
    "http_request_smuggling": ("http_request_smuggling_detection", True),
    "web_cache_poisoning": ("web_cache_poisoning_detection", True),
    "oauth": ("oauth_flow_validation", True),
    "subdomain_takeover": ("subdomain_takeover_detection", True),
    "crypto": ("crypto_transport_validation", True),
    "csp": ("csp_clickjacking_validation", True),
    "header_injection": ("header_injection_validation", True),
    "api_security": ("api_security_validation", True),
    "websocket": ("websocket_cswsh_validation", True),
    "race_condition": ("race_condition_validation", True),
    "deserialization": ("deserialization_format_confirmation", False),
    "session_fixation": ("session_fixation_compare", True),
    "session_timeout": ("logout_invalidation_compare", True),
}

def exchange_fingerprint(exchange: HttpExchange) -> str:
    material = "\x1f".join([
        exchange.method.upper(), exchange.url,
        *[f"{k.lower()}:{v}" for k, v in sorted(exchange.request_headers.items())],
        exchange.request_body,
    ]).encode()
    return hashlib.sha256(material).hexdigest()

def plan_key_fingerprint(exchange: HttpExchange) -> str:
    """exchange_fingerprint with cache-buster query parameters dropped
    (volatile_params.stable_url): the key a plan id is built from, so two captures
    of one request that differ only in a timestamp or random token are one plan.
    exchange_fingerprint itself stays exact -- it is the plan's binding to the
    capture (source_exchange_hash), which the Burp side recomputes."""
    from harness.volatile_params import stable_url
    return exchange_fingerprint(exchange.model_copy(update={"url": stable_url(exchange.url)}))


def _plan_id(capability: str, finding: Finding, exchange: HttpExchange) -> str:
    material = f"{capability}|{finding.vulnerability_class}|{plan_key_fingerprint(exchange)}".encode()
    return f"{capability}:{hashlib.sha256(material).hexdigest()[:20]}"


# Capabilities that mutate an HTTP parameter or body (injection) or replay a
# state-changing form (CSRF). Not planned for an Engine.IO long-polling request,
# whose query and body are transport framing (volatile_params.is_polling_transport);
# websocket and passive capabilities still are.
POLLING_EXCLUDED_CAPABILITIES = frozenset({
    "sql_injection_validation", "nosql_validation", "command_injection_validation",
    "ssti_validation", "xxe_validation", "header_injection_validation",
    "reflection_context_validation", "open_redirect_validation", "csrf_validation",
})


def plans_for_findings(exchange: HttpExchange, findings: list[Finding]) -> list[TestPlan]:
    """Translate hypotheses into safe capabilities without asking each agent
    to know implementation details. Explicit hints remain supported for
    tool-specific capabilities such as sqlmap.

    Category matching goes through categories.canonicalize() rather than a
    bare lowercase string comparison against finding.vulnerability_class.
    That field is genuinely free text an LLM writes (see base_agent.py's
    prompt -- there is no enum constraint on it); an exact-match lookup
    meant an agent writing "Insecure Direct Object Reference" instead of
    the literal string "idor" would silently produce zero test plans,
    with no error and no visible sign that a plan should have existed.
    """
    from harness.volatile_params import is_polling_transport
    polling = is_polling_transport(exchange.url)
    plans: list[TestPlan] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        candidates = list(finding.validation_hints or [])
        category = canonicalize(finding.vulnerability_class)
        # "sqlmap" is a tool name, not a category name, and is the ONLY
        # hint value with its own direct dispatch further down (`if hint
        # == "sqlmap"`) -- unlike other hint values, which only do
        # anything if they happen to match a real category key in
        # _CAPABILITIES. Filtering it out of `candidates` itself here,
        # rather than only guarding the separate append below, closes
        # BOTH the places this value gets trusted: the append two lines
        # down, and the "if hint == sqlmap" branch inside the dispatch
        # loop later in this function, which would otherwise still fire
        # on the raw, unfiltered hint regardless of that guard.
        if "sqlmap" in candidates and not (category == "sqli" or not category):
            candidates = [h for h in candidates if h != "sqlmap"]
        if category and category in _CAPABILITIES:
            candidates.append(category)
        # NOTE: "sqlmap" in candidates is trusted here ONLY as a fallback
        # when the finding's own vulnerability_class didn't canonicalize
        # to anything (category is None) -- never when it already
        # resolved to something else. validation_hints is free-text the
        # LLM writes, just like vulnerability_class, and just as prone to
        # copying the worked example in the prompt (which always shows
        # "validation_hints": ["sqlmap"] regardless of context) rather
        # than genuinely reasoning about it. Found live: an idor finding,
        # a business_logic finding, an xss finding, and several graphql
        # findings all carried "sqlmap" in validation_hints despite none
        # of them being SQL injection, flooding the analyst's plan picker
        # with 7 near-identical "sql_injection_validation" buttons for a
        # single exchange. Trusting the hint only when category is
        # unresolved preserves the intended fallback (a finding the
        # canonicalizer doesn't recognize, where the model's own hint is
        # the best information available) without letting it override an
        # already-successful, more authoritative categorization.
        if category == "sqli" or (not category and "sqlmap" in candidates):
            candidates.append("sql_injection_validation")
        if category == "jwt":
            candidates.append("jwt_validation")
        if category == "xxe":
            candidates.append("xxe_validation")
        if category == "csrf":
            candidates.append("csrf_validation")
        if category == "file_upload":
            candidates.append("file_upload_validation")
        if category == "nosql":
            candidates.append("nosql_validation")
        if category == "command_injection":
            candidates.append("command_injection_validation")
        if category == "ssti":
            candidates.append("ssti_validation")
        if category == "open_redirect":
            candidates.append("open_redirect_validation")
        if category == "business_logic_enhanced":
            candidates.append("workflow_replay_compare")
        # Route by response evidence, not only by label: a captured GET whose
        # response (or the finding's evidence body) holds an unmasked allowlisted
        # credential-secret field also gets the exposure oracle, in addition to
        # the plan its own class earns (r7: BOLA/BFLA-labelled findings on
        # responses carrying other accounts' secrets reached cross_identity only).
        if "api_security" not in candidates:
            from harness.validators.api_security_validator import exposure_evidence
            if exposure_evidence(finding, exchange):
                candidates.append("api_security")
        for hint in candidates:
            if hint == "sqlmap":
                cap, requires, plane = "sql_injection_validation", True, "local_tool"
            elif hint in _CAPABILITIES:
                cap, requires = _CAPABILITIES[hint]
                plane = "burp"
            elif hint == "sql_injection_validation":
                # The only genuine local_tool capability in this group --
                # sqlmap is a real external binary, not a Burp executor.
                cap, requires, plane = hint, True, "local_tool"
            elif hint in ("jwt_validation", "xxe_validation", "csrf_validation", "file_upload_validation", "nosql_validation", "command_injection_validation", "ssti_validation", "open_redirect_validation"):
                # These all have (or, for nosql_validation, are deliberately
                # missing -- see HANDOVER.md 5f) a Burp executor, not a
                # local_tool one -- must match the plane the category-based
                # branch above already assigns for the same capabilities
                # (_CAPABILITIES), or a plan reached via this literal-hint
                # path instead gets an execution_plane Burp can never run,
                # producing "Plan is not assigned to Burp." on click.
                cap, requires, plane = hint, True, "burp"
            else:
                continue
            if polling and cap in POLLING_EXCLUDED_CAPABILITIES:
                continue
            key = (finding.vulnerability_class, cap)
            if key in seen:
                continue
            seen.add(key)
            plans.append(TestPlan(
                id=_plan_id(cap, finding, exchange),
                capability=cap,
                finding_class=finding.vulnerability_class,
                category=category,
                source_exchange_url=exchange.url,
                mutation={"strategy": "validator-defined", "source": "captured-exchange"},
                success_signals=["independent evidence supports the hypothesis"],
                requires_approval=requires,
                execution_plane=plane,
                rationale=finding.suggested_test,
                source_exchange_hash=exchange_fingerprint(exchange),
                severity=finding.severity,
                confidence=finding.confidence,
            ))
    return plans
