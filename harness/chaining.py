from __future__ import annotations
from dataclasses import dataclass

from harness.models import Finding
from harness.categories import canonicalize, all_known_phrases
import re

# Sorted longest-first so a substring match prefers the most specific
# phrase available (e.g. "session timeout" over a shorter, coincidental
# partial match) when scanning a free-text vulnerability_class. Each
# phrase is pre-compiled with word boundaries so a short phrase like
# "auth" cannot match inside an unrelated word like "unauthorized" or
# "author" -- \b requires a transition between a word character and a
# non-word character (or string start/end), which "un|auth|orized" and
# "auth|or" don't have at the relevant positions.
_KNOWN_PHRASE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b' + re.escape(phrase) + r'\b'), target)
    for phrase, target in sorted(all_known_phrases().items(), key=lambda kv: len(kv[0]), reverse=True)
]

# Rule-based, not LLM-based, deliberately: the ARTEMIS benchmark (Dec
# 2025, 8,000-host live network) found autonomous agents specifically
# lose ground to top human testers on "creative chaining and business
# logic" -- the risk with an LLM narrating a chain from a list of
# findings is that it's exactly the kind of fluent-sounding, hard-to-
# verify claim this whole harness exists to avoid. A rule match over
# labeled finding categories is auditable -- a reader can see exactly
# which two findings triggered which rule -- where an LLM's "these might
# chain into X" is not.
#
# The escalation pattern in CHAIN rule "open_redirect+ssrf" is not
# invented for this tool -- it mirrors Intigriti's own published triage
# guidance, which gives exactly this example: an open redirect report
# followed by a separate SSRF report that escalates through it to RCE.


@dataclass(frozen=True)
class ChainRule:
    signature: str
    tag_a: str
    tag_b: str
    severity: str
    narrative_template: str  # {a_url} {b_url} get filled in


_RULES: list[ChainRule] = [
    ChainRule(
        signature="open_redirect+ssrf",
        tag_a="open_redirect", tag_b="ssrf",
        severity="critical",
        narrative_template=(
            "An open-redirect-shaped finding at {a_url} and an SSRF-shaped finding at "
            "{b_url} are both present on this host. This is a documented escalation "
            "pattern (open redirect used to bypass an SSRF allowlist that only checks "
            "the initial hostname) that has previously escalated to RCE in triaged bug "
            "bounty reports. Worth testing together even though each was flagged "
            "independently."
        ),
    ),
    ChainRule(
        signature="admin_exposure+access_control",
        tag_a="admin_exposure", tag_b="access_control",
        severity="high",
        narrative_template=(
            "Exposed admin/internal surface at {a_url} plus an access-control gap "
            "(IDOR or missing authorization) at {b_url} on the same host raises the "
            "combined risk above either alone: the access-control gap may be reachable "
            "specifically through the exposed admin surface rather than needing a "
            "separate discovery path."
        ),
    ),
    ChainRule(
        signature="dependency_exposure+known_vuln",
        tag_a="dependency_exposure", tag_b="known_vuln",
        severity="high",
        narrative_template=(
            "A dependency manifest/lockfile exposure at {a_url} is what made precise "
            "version fingerprinting possible, and a disclosed advisory was then "
            "confirmed at {b_url} via the deterministic GitHub Advisory lookup. "
            "Treat the exposure itself as worth fixing independently of whether this "
            "specific advisory turns out to be exploitable here -- it will keep "
            "enabling this kind of match against future advisories too."
        ),
    ),
    ChainRule(
        signature="weak_auth+business_logic",
        tag_a="weak_auth", tag_b="business_logic",
        severity="high",
        narrative_template=(
            "A weak authentication/session primitive at {a_url} combined with a "
            "sensitive state-changing action at {b_url} means the auth weakness's "
            "real-world impact is higher than its isolated severity suggests -- it's "
            "not just \"a weak token\", it's \"a weak token that gates {b_url}\"."
        ),
    ),
    ChainRule(
        signature="idor+rate_limit",
        tag_a="access_control", tag_b="rate_limit",
        severity="high",
        narrative_template=(
            "An object-level access-control weakness at {a_url} combined with a "
            "rate-limit gap at {b_url} may permit automated enumeration at scale. "
            "Treat this as a chain hypothesis requiring a controlled bulk test."
        ),
    ),
    ChainRule(
        signature="xss+weak_auth",
        tag_a="xss", tag_b="weak_auth",
        severity="high",
        narrative_template=(
            "An XSS-shaped finding at {a_url} combined with a weak authentication "
            "or session primitive at {b_url} may increase the impact of script execution."
        ),
    ),
    ChainRule(
        signature="open_redirect+oauth",
        tag_a="open_redirect", tag_b="oauth",
        severity="high",
        narrative_template=(
            "An open redirect at {a_url} plus an OAuth/OIDC finding at {b_url} "
            "may create a token/code redirection path -- an open redirect on a "
            "domain that's a registered (or loosely-matched) redirect_uri can let "
            "an attacker receive an authorization code or token meant for the "
            "legitimate app. Verify exact redirect_uri validation before treating "
            "this as an account-takeover chain."
        ),
    ),
    ChainRule(
        signature="graphql_introspection+access_control",
        tag_a="graphql_introspection", tag_b="access_control",
        severity="high",
        narrative_template=(
            "GraphQL introspection exposure at {a_url} plus an access-control gap "
            "at {b_url} may make sensitive fields or operations easier to enumerate. "
            "Verify field-level authorization explicitly."
        ),
    ),
    ChainRule(
        signature="subdomain_takeover+oauth",
        tag_a="subdomain_takeover", tag_b="oauth",
        severity="critical",
        narrative_template=(
            "A subdomain takeover candidate at {a_url} and an OAuth/OIDC finding at "
            "{b_url} on the same host: if the takeover-vulnerable subdomain is a "
            "registered (or loosely-matched, per the redirect_uri validation finding) "
            "OAuth redirect_uri, claiming that subdomain lets an attacker receive "
            "real authorization codes or tokens issued for legitimate users -- this "
            "is a well-understood account-takeover path, not a hypothetical one. "
            "Confirm which specific hostname the OAuth client's registered "
            "redirect_uri actually points to before treating this as confirmed."
        ),
    ),
    ChainRule(
        signature="web_cache_poisoning+xss",
        tag_a="web_cache_poisoning", tag_b="xss",
        severity="critical",
        narrative_template=(
            "A web cache poisoning primitive at {a_url} and an XSS-shaped finding "
            "at {b_url}: if the XSS-vulnerable response is also cacheable, "
            "poisoning it once serves the payload to every subsequent visitor of "
            "that cache key, not just a victim tricked into clicking a link -- "
            "converting an ordinary reflected XSS into something that behaves like "
            "stored XSS at the scale of the cache, with none of the per-victim "
            "delivery effort stored XSS normally requires."
        ),
    ),
    ChainRule(
        signature="header_injection+web_cache_poisoning",
        tag_a="header_injection", tag_b="web_cache_poisoning",
        severity="high",
        narrative_template=(
            "A header/CRLF injection finding at {a_url} and a cache poisoning "
            "primitive at {b_url} on the same host: if the injected header lands "
            "in a response that then gets cached, a single injection request "
            "poisons the shared cache with the attacker's extra header (or split "
            "response) for every subsequent visitor, not just the requester -- the "
            "cache turns a one-shot header injection into a persistent, widely "
            "-served one."
        ),
    ),
    ChainRule(
        signature="deserialization+known_vuln",
        tag_a="deserialization", tag_b="known_vuln",
        severity="critical",
        narrative_template=(
            "A confirmed serialized-object format at {a_url} and a disclosed "
            "advisory for a specific library version at {b_url}: a serialization "
            "format alone only proves the mechanism exists, not that it's "
            "exploitable -- a matching known-vulnerable library version is what "
            "typically supplies the actual gadget chain. This combination is "
            "exactly what the deserialization agent's own prompt flags as worth "
            "escalating; the two were reported independently, so verify they're "
            "the same component before treating this as confirmed."
        ),
    ),
    ChainRule(
        signature="session_fixation+xss",
        tag_a="session_fixation", tag_b="xss",
        severity="critical",
        narrative_template=(
            "Session fixation at {a_url} (the server doesn't rotate the session "
            "ID on login) and an XSS-shaped finding at {b_url} on the same host: "
            "XSS supplies the practical delivery mechanism fixation alone lacks -- "
            "a script can set the victim's session cookie to an attacker-chosen "
            "value before they log in, turning a theoretical fixation weakness "
            "into a working account-takeover path without needing to steal "
            "anything after the fact."
        ),
    ),
    ChainRule(
        signature="websocket+access_control",
        tag_a="websocket", tag_b="access_control",
        severity="high",
        narrative_template=(
            "A WebSocket finding at {a_url} (commonly missing Origin validation "
            "on the handshake, i.e. cross-site WebSocket hijacking) and an "
            "access-control gap at {b_url}: if an attacker's page can open a "
            "victim's WebSocket connection at all, a per-message authorization "
            "gap on that same channel means the attacker can read or act on other "
            "users' data through the victim's hijacked connection, not just "
            "eavesdrop on the victim's own traffic."
        ),
    ),

    # --- Added during audit follow-up: these four categories (sqli,
    # csrf, xxe, command_injection) were flagged as having zero
    # chain-rule path despite being among the highest-severity, most
    # classic vulnerability classes this project tests for. The prior
    # session's 7 new rules were all scoped to that session's own new
    # categories and didn't touch this pre-existing gap. These four are
    # not the whole gap (~20 categories still have no rule -- see
    # test_chaining.py::test_categories_with_no_chain_rule_are_the_known,
    # documented set), but they're the highest-value pairs to close
    # first: two of the OWASP Top 10's most cited vulnerability classes
    # (SQLi, XXE) plus two extremely common real-world escalation
    # patterns (SQLi reachable only through a broken access check; CSRF
    # whose real impact depends on how weak/long-lived the victim
    # session is).
    ChainRule(
        signature="sqli+idor",
        tag_a="sqli", tag_b="idor",
        severity="critical",
        narrative_template=(
            "A SQL injection finding at {a_url} and an object-level access-control "
            "gap (IDOR) at {b_url} on the same host: if the injectable endpoint is "
            "one an IDOR exposes to users who shouldn't be able to reach it at all "
            "(e.g. an admin-only report endpoint reachable by any authenticated "
            "user via ID substitution), the practical severity of the SQLi is "
            "governed by who the IDOR lets in, not just by what the injection can "
            "do. Verify whether the injectable endpoint is actually the one the "
            "IDOR exposes before treating this as one combined finding rather than "
            "two independent ones."
        ),
    ),
    ChainRule(
        signature="csrf+weak_auth",
        tag_a="csrf", tag_b="weak_auth",
        severity="high",
        narrative_template=(
            "A CSRF finding (missing/predictable anti-CSRF token) at {a_url} and a "
            "weak authentication/session primitive at {b_url}: CSRF's real-world "
            "impact is a function of what the victim's session can do and how long "
            "it lasts, not just whether the token check is missing -- a session "
            "that never expires or survives password changes turns a CSRF gap into "
            "a standing, repeatable forgery path rather than a one-shot one. Verify "
            "the CSRF-vulnerable endpoint actually performs a state-changing action "
            "under the same session model the weak-auth finding describes."
        ),
    ),
    ChainRule(
        signature="xxe+ssrf",
        tag_a="xxe", tag_b="ssrf",
        severity="critical",
        narrative_template=(
            "An XXE finding at {a_url} and an SSRF-shaped finding at {b_url}: XXE's "
            "external entity resolution is one of the most common ways to obtain an "
            "SSRF primitive in the first place (the parser fetches an "
            "attacker-supplied URI as part of resolving the entity) -- this is a "
            "well-documented technique, not a speculative one, and is frequently "
            "how XXE reaches cloud metadata endpoints or internal-only services. "
            "Confirm the entity-resolution behavior actually reaches attacker-"
            "controlled URIs (not just local file disclosure) before treating this "
            "as a working SSRF path rather than XXE alone."
        ),
    ),
    # --- Second-order chains (V22 / V17): a WRITE that persists user input,
    # combined with a later SQLi- or IDOR-suspected READ that consumes stored
    # data. The classic second-order shape (HARNESS_IMPROVEMENT_NOTES #3): a value
    # accepted safely by A is reused unsafely by B on an unrelated path. The write
    # ("stored_write" umbrella: mass-assignment / stored-XSS / persisted input) is
    # the plant; the read is the trigger. Composed as a hypothesis here; the active
    # boolean differential that confirms it lives in second_order.py.
    ChainRule(
        signature="second_order_sqli",
        tag_a="stored_write", tag_b="sqli",
        severity="critical",
        narrative_template=(
            "A write that persists user-controlled input at {a_url} and a SQL-injection"
            "-suspected read at {b_url} on the same host: this is the second-order SQLi "
            "shape -- a value stored safely by the write is later concatenated into a "
            "query on the read path, so single-request sqlmap on {b_url} alone misses it. "
            "Confirm with a plant->trigger boolean differential (store a TRUE vs FALSE SQL "
            "marker via {a_url}, compare {b_url}'s response); see second_order.py."
        ),
    ),
    ChainRule(
        signature="second_order_idor",
        tag_a="stored_write", tag_b="idor",
        severity="high",
        narrative_template=(
            "A write that persists an object reference at {a_url} and an object-level "
            "access-control gap at {b_url}: the value planted by the write may be read "
            "back by another identity through the IDOR on {b_url} -- a second-order IDOR "
            "chain. Confirm by planting a marker object as one identity via {a_url} and "
            "reading it as another identity via {b_url}."
        ),
    ),
    ChainRule(
        signature="command_injection+known_vuln",
        tag_a="command_injection", tag_b="known_vuln",
        severity="critical",
        narrative_template=(
            "A command injection finding at {a_url} and a disclosed advisory for a "
            "specific library/binary version at {b_url}: a blind or low-confidence "
            "command injection finding is much more actionable when the host is "
            "independently confirmed to be running a known-vulnerable version of "
            "software that would explain (or amplify) it -- e.g. a vulnerable "
            "version of the exact binary being invoked. Verify the advisory's "
            "affected component is the one actually being invoked by the injectable "
            "code path, not just present somewhere on the host, before treating "
            "this as a single confirmed chain."
        ),
    ),
]

# Keyword -> tag mapping. A finding gets a tag if any of its keywords
# appear in its vulnerability_class or summary (lowercased). A finding
# can carry multiple tags.
_CLASS_TAGS: dict[str, set[str]] = {
    "open_redirect": {"open_redirect", "open-redirect", "open redirect"},
    "ssrf": {"ssrf", "server-side request forgery"},
    "admin_exposure": {"admin_exposure", "admin-exposure"},
    "access_control": {"idor", "access_control", "access-control", "broken-access-control", "missing-authorization"},
    "dependency_exposure": {"dependency_exposure", "dependency-exposure", "manifest-exposure"},
    "known_vuln": {"known-vulnerable-dependency"},
    "weak_auth": {"weak_auth", "weak-auth", "authentication-bypass", "session"},
    "business_logic": {"business_logic", "business-logic", "workflow", "race-condition"},
    "rate_limit": {"rate_limit", "rate-limit", "rate limiting", "throttling"},
    "xss": {"xss", "cross-site-scripting", "cross-site scripting"},
    "oauth_redirect": {"oauth_redirect", "oauth-redirect", "oauth redirect"},
    "graphql_introspection": {"graphql_introspection", "graphql-introspection", "graphql introspection"},
    # A write that PERSISTS user-controlled input -- the plant side of a
    # second-order chain. Umbrella over mass-assignment / stored-XSS / explicitly
    # second-order-labelled findings. (Deliberately not the canonical category
    # name "api_security", so the canonical-category chain-coverage audit is
    # unchanged; a real mass_assignment/stored-xss finding still gets this tag.)
    "stored_write": {"mass_assignment", "mass assignment", "stored_xss", "stored xss",
                     "stored cross-site scripting", "second-order", "second order",
                     "second-order sqli", "second order idor"},
}


def _tags_for(vulnerability_class: str, summary: str) -> set[str]:
    """Tag only from the structured vulnerability class, never free text.

    Summaries/evidence are model-controlled and may contain arbitrary words;
    using them as a taxonomy oracle can manufacture chains.

    Three sources of tags, all keyed off vulnerability_class only:
    1. _CLASS_TAGS -- a hand-curated vocabulary for chain-specific
       concepts that don't correspond to a single canonical category
       (e.g. "admin_exposure", "access_control" spans idor + missing-
       authorization, "known_vuln"). Kept as its own list because these
       genuinely aren't the same thing as categories.CANONICAL_CATEGORIES.
    2. The canonical category itself, via categories.canonicalize()
       (exact match only, by that function's own deliberate design).
    3. A substring fallback over categories.all_known_phrases(), used
       ONLY here, not in canonicalize() itself. This is deliberately
       looser than (2): vulnerability_class has no enum constraint in
       the agent JSON schema, so realistic output looks like "Race
       Condition (TOCTOU) on coupon redemption", which (2) alone
       cannot resolve (canonicalize() matches the whole trimmed string
       only). Chaining's own output is already capped at 0.5 confidence
       and explicitly requires human review before acting on it --
       that asymmetry (a missed chain is a silent loss; a spurious
       chain hypothesis is a human dismissing one extra suggestion)
       justifies looser matching here specifically. This fallback is
       NOT applied to canonicalize() itself, which feeds real routing
       decisions and stays conservative on purpose.
    """
    normalized = vulnerability_class.lower().strip()
    tags = {tag for tag, aliases in _CLASS_TAGS.items() if normalized in aliases}

    canonical = canonicalize(vulnerability_class)
    if canonical:
        tags.add(canonical)
    else:
        for pattern, target in _KNOWN_PHRASE_PATTERNS:
            if pattern.search(normalized):
                tags.add(target)
                break  # longest match wins; don't also add shorter overlapping phrases

    return tags
def pivot_hints(new_finding_class: str, new_summary: str, host_findings: list[dict]) -> list[dict]:
    """Given a finding just made (its class + summary) and everything already
    known for the host, return the chain rules where this finding supplies ONE
    side and the host doesn't yet have the other -- i.e. what to go looking for
    next to complete a chain. This turns the same rule table detect() uses for
    *retrospective* combination into *directed* pivoting: not "these two already
    chain" but "you now have half of {signature}; find {look_for} to finish it".

    Deterministic and rule-based for the same reason detect() is (see the module
    comment). Each hint is a dict {signature, have, look_for, severity};
    deduplicated on (signature, look_for)."""
    new_tags = _tags_for(new_finding_class, new_summary)
    if not new_tags:
        return []
    present: set[str] = set()
    for f in host_findings:
        present |= _tags_for(f["vulnerability_class"], f.get("summary", ""))

    seen: set[tuple[str, str]] = set()
    hints: list[dict] = []
    for rule in _RULES:
        for have, look_for in ((rule.tag_a, rule.tag_b), (rule.tag_b, rule.tag_a)):
            # This finding supplies `have`; the host doesn't already have
            # `look_for` (neither from prior findings nor from this same
            # finding, which would make it a completed chain, not a pivot).
            if have in new_tags and look_for not in present and look_for not in new_tags:
                key = (rule.signature, look_for)
                if key in seen:
                    continue
                seen.add(key)
                hints.append({"signature": rule.signature, "have": have,
                              "look_for": look_for, "severity": rule.severity})
    return hints


def second_order_candidates(host_findings: list[dict]) -> list[dict]:
    """The structured (A,B) plant->trigger pairs for the second-order chains, so
    an active confirmer can act on them (the narrative Findings from detect() bury
    the urls in prose). A = a write that persists input (tag `stored_write`),
    B = the SQLi- or IDOR-suspected read. Each candidate:
    {signature, kind ('sqli'|'idor'), a: <write finding>, b: <read finding>}."""
    tagged = [(f, _tags_for(f.get("vulnerability_class", ""), f.get("summary", "")))
              for f in host_findings]
    writes = [f for f, tags in tagged if "stored_write" in tags]
    out: list[dict] = []
    for kind, read_tag, sig in (("sqli", "sqli", "second_order_sqli"),
                                ("idor", "idor", "second_order_idor")):
        reads = [f for f, tags in tagged if read_tag in tags]
        for a in writes:
            for b in reads:
                if a.get("url") == b.get("url"):
                    continue  # A and B must be distinct requests
                out.append({"signature": sig, "kind": kind, "a": a, "b": b})
    return out


def detect(host_findings: list[dict]) -> list[Finding]:
    """
    host_findings: dicts as returned by store.all_host_findings() --
    {url, vulnerability_class, severity, confidence, summary}.
    Returns Finding objects for chains found. Caller is responsible for
    checking store.is_chain_already_detected()/mark_chain_detected() so
    the same chain isn't re-reported on every subsequent exchange.
    """
    tagged = [(f, _tags_for(f["vulnerability_class"], f["summary"])) for f in host_findings]

    results: list[Finding] = []
    for rule in _RULES:
        a_matches = [f for f, tags in tagged if rule.tag_a in tags]
        b_matches = [f for f, tags in tagged if rule.tag_b in tags]
        if not a_matches or not b_matches:
            continue
        a, b = a_matches[0], b_matches[0]
        if a["url"] == b["url"] and rule.tag_a == rule.tag_b:
            continue
        # Phase 3.5(c): a chain composed from an unconfirmed, non-observed input
        # (basis assumed/recalled) inherits that input's uncertainty -- possibly a
        # mislabel -- so tag it speculative rather than presenting it as a clean
        # rule match. Confirmed-or-observed inputs keep the standard confidence.
        from harness import attribution
        speculative = [f for f in (a, b) if attribution.chain_input_speculative(f)]
        is_speculative = bool(speculative)
        spec_note = ""
        if is_speculative:
            which = ", ".join(sorted({f.get("vulnerability_class", "?") for f in speculative}))
            spec_note = (f" SPECULATIVE INPUT: this chain rests on an unconfirmed, non-observed "
                         f"finding ({which}, basis assumed/recalled); its premise may itself be a "
                         f"mislabel -- verify the input before trusting the chain.")
        results.append(Finding(
            vulnerability_class=f"potential-attack-chain:{rule.signature}",
            # rule match on category labels, not a confirmed chain -- always needs
            # a human look, and less so when an input is itself speculative.
            confidence=0.35 if is_speculative else 0.5,
            severity=rule.severity,
            owasp_category=None,
            summary=f"Potential attack chain: {rule.signature.replace('+', ' -> ')}"
                    + (" [speculative inputs]" if is_speculative else ""),
            evidence=rule.narrative_template.format(a_url=a["url"], b_url=b["url"]) + spec_note,
            suggested_test="Test these together explicitly, in the order implied by the chain -- "
                            "individually-valid findings don't automatically compose, this is a "
                            "hypothesis to verify, not a confirmed exploit path.",
            basis="derived",
        ))
    return results


def discovery_chain_candidates(exchanges: list) -> list[dict]:
    """Discovery-driven pair composition: any POST that stores user input paired
    with any GET that renders content = a candidate stored-XSS/second-order pair.
    This heuristic doesn't require prior findings — it works from the raw exchange
    surface, catching chains the finding-based `second_order_candidates` misses
    when the LLM didn't label either side.

    Returns [{kind, write_url, write_method, read_url, read_method}]."""
    writes: list[dict] = []
    reads: list[dict] = []
    for ex in exchanges:
        if hasattr(ex, "method"):
            method = (ex.method or "GET").upper()
            url = ex.url or ""
            status = getattr(ex, "response_status", 200) or 200
            ctype = ""
            for k, v in (getattr(ex, "response_headers", {}) or {}).items():
                if k.lower() == "content-type":
                    ctype = v.lower()
            body = getattr(ex, "request_body", "") or ""
        elif isinstance(ex, dict):
            method = (ex.get("method") or "GET").upper()
            url = ex.get("url", "")
            status = ex.get("response_status", 200) or 200
            ctype = ""
            for k, v in (ex.get("response_headers") or {}).items():
                if k.lower() == "content-type":
                    ctype = v.lower()
            body = ex.get("request_body", "") or ""
        else:
            continue

        if method in ("POST", "PUT", "PATCH") and body and 200 <= status < 400:
            writes.append({"url": url, "method": method})
        if method == "GET" and 200 <= status < 300:
            if "html" in ctype or "json" in ctype:
                # keep the content-type so the read's kind can be classified below
                reads.append({"url": url, "method": method, "ctype": ctype})

    pairs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for w in writes:
        for r in reads:
            if w["url"] == r["url"]:
                continue
            key = (w["url"], r["url"])
            if key in seen:
                continue
            seen.add(key)
            # html read -> stored-XSS candidate; json read -> generic second-order
            # (e.g. second-order SQLi). The consumer routes each to the oracle its
            # TYPE supports and never force-routes everything to SQLi (R14).
            kind = "stored_xss" if "html" in r.get("ctype", "") else "second_order"
            pairs.append({
                "kind": kind,
                "write_url": w["url"],
                "write_method": w["method"],
                "read_url": r["url"],
                "read_method": r["method"],
            })
    return pairs
