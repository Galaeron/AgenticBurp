"""
Report Generator

Turns confirmed and unconfirmed findings for a host into a submission
-ready Markdown report: title, severity, confidence/status, affected
endpoint, evidence, reproduction steps, generic remediation guidance,
and a clearly-separated "Potential Attack Chains" section for anything
chaining.py produced.

This replaces generate_juice_shop_report.py, which was a one-off
hardcoded writeup for a single past run rather than something that
works off the live data model. This module is the reusable version:
point it at any host that has findings in store.py and get a report,
not just Juice Shop.

Design principles, matching the harness's own "know vs. guessed" ethos
throughout the rest of this project:
- CONFIRMED findings (validator-confirmed, Finding.confirmed=True) are
  visually and textually distinguished from UNCONFIRMED ones. A report
  reader should never have to guess which is which.
- basis ("derived"/"recalled"/"assumed") is always shown -- an
  "assumed" finding gets flagged as needing manual verification before
  submission, not silently presented with the same confidence as a
  "derived" one.
- Remediation guidance is GENERIC, category-keyed best practice, never
  a claim about this specific target's actual code. It's explicitly
  labeled as a starting point for the analyst, not authoritative
  advice about the target.
- Chain hypotheses (from chaining.py) are never mixed into the same
  list as individually-confirmed findings -- they're a distinct
  section with their own disclaimer, matching chaining.py's own
  confidence cap and "needs a human look" framing.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from harness import risk_allocator
from harness.effort import CallKind, EffortLedger
from harness.engagement import normalize_path
from harness.categories import canonicalize

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_BADGE = {
    "critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
    "low": "🔵 LOW", "info": "⚪ INFO",
}

# Generic, uncontroversial, category-keyed remediation starting points.
# Deliberately generic -- these are NOT claims about how this specific
# target's code is structured, just the standard first-line mitigation
# for the category. An analyst should always adapt these to what the
# actual root cause turns out to be.
_REMEDIATION_HINTS: dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements everywhere user input reaches SQL; never build queries via string concatenation.",
    "xss": "Apply context-aware output encoding at the point of rendering, and adopt a restrictive Content-Security-Policy without 'unsafe-inline'/'unsafe-eval' as defense in depth.",
    "idor": "Enforce object-level authorization checks server-side on every request that accepts a resource identifier -- never rely on an identifier being 'hard to guess' as an access control.",
    "ssrf": "Validate and allowlist destination hosts server-side after DNS resolution (not just the input string), and block requests to internal/link-local address ranges.",
    "auth": "Review session token generation (entropy, rotation on login), cookie attributes (Secure/HttpOnly/SameSite), and CSRF protection on state-changing endpoints.",
    "business_logic": "Add server-side validation of business rules (limits, sequencing, ownership) that doesn't rely on client-side enforcement or UI flow alone.",
    "business_logic_enhanced": "Same as business_logic: enforce workflow/state rules server-side, independent of the order the client happens to call endpoints in.",
    "misconfig": "Review server/framework configuration against current vendor hardening guidance; remove default credentials, debug endpoints, and verbose error output in production.",
    "rate_limit": "Add server-side rate limiting keyed on account/IP/API-key for sensitive or resource-intensive endpoints.",
    "jwt": "Enforce a single expected signing algorithm server-side (reject 'alg: none' and algorithm-confusion attempts), and validate signatures on every request.",
    "xxe": "Disable external entity resolution and DTD processing in the XML parser configuration.",
    "csrf": "Require a per-session, unpredictable CSRF token on all state-changing requests, validated server-side.",
    "file_upload": "Validate file type by content (not extension/Content-Type alone), store uploads outside the web root, and serve them without execute permissions.",
    "nosql": "Validate and sanitize input types before passing to NoSQL query operators; reject operator-shaped input ($ne, $gt, etc.) from untrusted fields.",
    "command_injection": "Avoid shell invocation with user-controlled input entirely; use parameterized subprocess APIs and strict allowlisting if shell use is unavoidable.",
    "ssti": "Avoid passing user input directly into template rendering; use a logic-less template engine or sandbox template execution.",
    "open_redirect": "Validate redirect targets against an allowlist of known-safe destinations rather than accepting arbitrary URLs.",
    "path_traversal": "Resolve user-supplied paths against a fixed base directory and reject any that escape it (canonicalize, then verify the prefix); never pass raw filenames to filesystem APIs.",
    "info_disclosure": "Remove verbose error messages, stack traces, and internal identifiers from responses served to end users.",
    "cors": "Set Access-Control-Allow-Origin to a specific, validated origin allowlist -- never reflect Origin unconditionally, especially alongside Access-Control-Allow-Credentials.",
    "recon": "Remove or restrict access to discovery-relevant files/endpoints (.git, .env, API docs) not intended for public access.",
    "http_request_smuggling": "Ensure front-end and back-end servers agree on request framing (Content-Length vs. Transfer-Encoding); prefer HTTP/2 end-to-end where possible.",
    "web_cache_poisoning": "Include all inputs that affect the response (headers, params) in the cache key, or strip/normalize unkeyed inputs before the origin processes them.",
    "oauth": "Enforce exact-match redirect_uri validation, require state on every authorization request, and require PKCE for public clients.",
    "subdomain_takeover": "Remove the dangling DNS record, or claim the resource on the third-party provider before an attacker does.",
    "crypto": "Enforce HTTPS with HSTS, set Secure/HttpOnly/SameSite on session cookies, and disable deprecated TLS versions/ciphers.",
    "csp": "Add a restrictive Content-Security-Policy (no unsafe-inline/unsafe-eval) and frame-ancestors/X-Frame-Options to prevent framing.",
    "header_injection": "Strip or encode CR/LF characters from any user input before it reaches a response header or outbound email header.",
    "api_security": "Apply an explicit allowlist of bindable fields on create/update endpoints, and cap page-size/limit parameters server-side.",
    "websocket": "Validate the Origin header on the WebSocket handshake server-side, and apply the same per-resource authorization checks to WebSocket messages as to equivalent REST endpoints.",
    "race_condition": "Wrap the check-then-act sequence in a database transaction or distributed lock so concurrent requests can't both pass the check before either commits.",
    "deserialization": "Avoid deserializing untrusted data with a format that carries type information (Java serialization, pickle, etc.); use a data-only format (JSON) instead, or a strict allowlist deserializer.",
    "session_fixation": "Issue a new session identifier immediately after successful authentication; never continue using a pre-login session ID.",
    "session_timeout": "Invalidate the session server-side on logout (not just client-side cookie clearing), and enforce an absolute/idle session timeout.",
    "reset_token": "Generate password-reset/session tokens from a cryptographically secure RNG with at least 128 bits of entropy; never derive them from a timestamp, user id, email, or a sequential counter, and expire them after a short single use.",
    "dom_xss": "Never pass client-side sources (location.hash/.search, document.referrer, postMessage data) into a dangerous sink (innerHTML, document.write, eval, jQuery .html()); use textContent or a sanitizer (e.g. DOMPurify) and treat all URL/DOM input as untrusted in client JS.",
    "toctou": "Make the authorization check and the state change atomic: perform the privilege/ownership check inside the same transaction (or under a row/advisory lock) that commits the write, so two interleaved requests cannot both pass the check before either commits.",
    "graphql": "Disable introspection in production, and enforce field-level authorization independent of the overall query being otherwise valid.",
    "supply_chain": "Pin dependency versions, monitor for disclosed advisories against them, and remove exposed manifests/lockfiles from public access.",
}

_DEFAULT_REMEDIATION = ("Review the specific mechanism described in the evidence above and apply the "
                         "standard mitigation for this vulnerability class; no category-specific "
                         "guidance is available for this one yet.")


@dataclass
class ReportFinding:
    """Normalized view of a stored finding, ready for rendering."""
    url: str
    vulnerability_class: str
    severity: str
    confidence: float
    summary: str
    evidence: str
    suggested_test: str
    owasp_category: str | None
    basis: str
    confirmed: bool
    agent: str
    is_chain: bool = False
    fingerprint: str = ""
    duplicate_count: int = 1   # how many raw findings collapsed into this survivor
    # T06: the concrete case coordinates + stable issue identity.
    method: str = ""
    parameter_location: str = ""
    parameter_name: str = ""
    issue_id: str = ""
    # W-7: explicit CONFIRMED/SUSPECTED/LEAD state (from confirmation_gate).
    lifecycle_state: str = "SUSPECTED"
    # Oracle-verification axis (precision items #1/#2): "verified" only when the
    # oracle reproduced the finding N-of-N with a clean negative control; else
    # "candidate". Orthogonal to lifecycle_state -- a CONFIRMED finding (a leg
    # fired once) can still be a candidate until an oracle reproduces it.
    verification_state: str = "candidate"
    # Step 4 (2026-09-17 coverage-recovery plan): True for a class with NO
    # deterministic exploit-confirmation leg at all (leg_tier == "none" --
    # cors, csp, verbose_error, info_disclosure, ...). These validators are
    # passive header/content checks, not live exploitation, so a "confirmed"
    # CORS misconfiguration and a "confirmed" SQL injection are not the same
    # kind of claim; bundling them under one "confirmed" count inflated the
    # headline number without the reader being able to tell which is which.
    is_observation: bool = False


def _from_store_dict(d: dict) -> ReportFinding:
    from harness import issues
    from harness.confirmation_gate import leg_tier
    vc = d.get("vulnerability_class", "")
    return ReportFinding(
        url=d.get("url", ""),
        vulnerability_class=vc,
        severity=d.get("severity", "info"),
        confidence=float(d.get("confidence", 0.0)),
        summary=d.get("summary", ""),
        evidence=d.get("evidence", "") or "",
        suggested_test=d.get("suggested_test", "") or "",
        owasp_category=d.get("owasp_category"),
        basis=d.get("basis", "derived") or "derived",
        confirmed=bool(d.get("confirmed", False)),
        agent=d.get("agent", ""),
        is_chain=vc.startswith("potential-attack-chain:"),
        fingerprint=d.get("fingerprint", ""),
        method=(d.get("method") or "").upper(),
        parameter_location=d.get("parameter_location", "") or "",
        parameter_name=d.get("parameter_name", "") or "",
        issue_id=("" if vc.startswith("potential-attack-chain:")
                  else issues.issue_id_for(issues.issue_key(d))),
        lifecycle_state=d.get("lifecycle_state")
        or __import__("harness.confirmation_gate",
                      fromlist=["finding_lifecycle_state"]).finding_lifecycle_state(d),
        is_observation=(leg_tier(vc) == "none"),
        verification_state=__import__("harness.oracle_framework",
                      fromlist=["derive_verification_state"]).derive_verification_state(d),
    )


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "very likely"
    if confidence >= 0.6:
        return "likely"
    if confidence >= 0.35:
        return "possible"
    return "speculative"


def _basis_note(basis: str) -> str:
    return {
        "derived": "Derived directly from what's visible in the captured traffic.",
        "recalled": "Based on the model's training-time knowledge, not independently verified against this target -- confirm manually before relying on this.",
        "assumed": "Rests on an assumption the model made, not something directly observed -- confirm the assumption holds before relying on this.",
    }.get(basis, "")


def _remediation_for(vulnerability_class: str) -> str:
    return _REMEDIATION_HINTS.get(vulnerability_class, _DEFAULT_REMEDIATION)


# Weakness #5: a finding's suggested_test sometimes carries REMEDIATION advice
# ("rotate the signing key"), which must not be rendered as "Steps to reproduce".
_REMEDIATION_LEADS = (
    "rotate", "remediate", "fix ", "patch", "upgrade", "update ", "disable", "enable",
    "use ", "implement", "configure", "restrict", "sanitize", "sanitise", "escape",
    "validate ", "add a ", "add an ", "do not", "avoid ", "never ", "always ", "ensure ",
)


def _looks_like_remediation(text: str) -> bool:
    t = (text or "").strip().lower()
    return any(t.startswith(w) for w in _REMEDIATION_LEADS)


def _rank_unconfirmed_by_value_density(
    unconfirmed: list["ReportFinding"], effort_ledger: EffortLedger,
) -> list["ReportFinding"]:
    """
    Orders unconfirmed findings by risk_allocator's value_density
    (expected_risk / cost) instead of the plain severity/confidence sort
    `individual.sort(...)` already applied -- this is specifically about
    "what should the analyst spend their next round of validation effort
    on," which is a cost-vs-risk question that plain severity/confidence
    doesn't capture (a critical-but-cheap-to-confirm finding and a
    critical-but-expensive-to-confirm one aren't equally good uses of the
    next validation round).

    This was previously fully unwired -- risk_allocator.rank() and
    allocate_retry_budget() had no caller anywhere in the live codebase,
    not even a partial one (confirmed by grep before writing this). This
    is the first live caller.

    Cost honesty, stated precisely (this project's own "known vs.
    guessed" standard applies here same as anywhere else): `cost` here
    is `EffortLedger.average_tokens(CallKind.VALIDATION_RETRY)` -- a
    REAL, measured average token cost (once at least one real validation
    retry has happened this session; a labeled prior before that, same
    as everywhere else in effort.py), but it is a PER-CATEGORY-OF-CALL
    average, not a cost individually attributed to this specific
    finding. This codebase does not currently persist which finding a
    given retry's tokens were spent confirming (noted as a known gap in
    HANDOVER.md), so a genuinely per-finding cost isn't available data --
    using the average validation-retry cost as a shared proxy for "how
    expensive is confirming something like this, generally" is the most
    honest approximation available today, not a claim of per-finding
    precision. Confirmed findings are deliberately NOT re-ranked this
    way -- they're already resolved, so a forward-looking "what to spend
    effort on next" question doesn't apply to them; they keep the plain
    severity/confidence ordering.
    """
    scores = [
        risk_allocator.RiskScore(
            category=f.vulnerability_class,
            url=f.url,
            probability=f.confidence,
            severity=f.severity,
            source="agent_confidence",
            cost=effort_ledger.average_tokens(CallKind.VALIDATION_RETRY),
        )
        for f in unconfirmed
    ]
    # RiskScore doesn't carry a back-reference to the ReportFinding it
    # came from, and (category, url) isn't guaranteed unique across
    # findings -- rebuild the order by index instead of re-matching on
    # content, which would silently misorder same-category/same-url
    # findings (e.g. two different confidence findings at the same URL).
    order = list(range(len(unconfirmed)))
    order.sort(key=lambda i: -scores[i].value_density)
    return [unconfirmed[i] for i in order]


def _dedup_key(f: "ReportFinding") -> tuple:
    """The identity a duplicate shares (T06, conservative): endpoint FAMILY (object
    ids collapsed to {id}, so /tickets/1 and /tickets/2 are one family), method,
    canonical class, affected input, and authorization boundary. This is what makes
    the same IDOR proven on ticket 1..8 collapse to one issue about /tickets/{id},
    while keeping two SQLi inputs on one endpoint -- and a read vs a write -- as
    distinct issues. It is exactly `issues.issue_key`, so the report's collapse and
    the issue export agree by construction."""
    from harness import issues
    return issues.issue_key({
        "url": f.url, "method": f.method, "vulnerability_class": f.vulnerability_class,
        "parameter_location": f.parameter_location, "parameter_name": f.parameter_name})


def _rank_tuple(f: "ReportFinding") -> tuple:
    # Higher is better: confirmed first, then more-severe, then higher confidence.
    return (1 if f.confirmed else 0, -_SEVERITY_ORDER.get(f.severity, 99), f.confidence)


def _collapse_duplicates(findings: list["ReportFinding"]) -> tuple[list["ReportFinding"], int]:
    """Collapse findings that share an (endpoint-family, class) into a single best
    representative -- confirmed beats unconfirmed, then more-severe, then
    higher-confidence -- so a proven bug floats up and its duplicates don't bury
    the shortlist. The survivor carries `duplicate_count` (how many collapsed into
    it). Returns (survivors, number_removed). Order-stable on first appearance;
    the caller re-sorts anyway."""
    groups: dict[tuple[str, str], "ReportFinding"] = {}
    order: list[tuple[str, str]] = []
    for f in findings:
        k = _dedup_key(f)
        cur = groups.get(k)
        if cur is None:
            f.duplicate_count = 1
            groups[k] = f
            order.append(k)
        else:
            total = cur.duplicate_count + 1
            winner = f if _rank_tuple(f) > _rank_tuple(cur) else cur
            winner.duplicate_count = total
            groups[k] = winner
    survivors = [groups[k] for k in order]
    return survivors, len(findings) - len(survivors)


def generate_markdown_report(host: str, findings: list[dict], generated_at: datetime | None = None,
                              effort_ledger: EffortLedger | None = None, suppressed_count: int = 0,
                              quarantine_leads: bool = False) -> str:
    """
    Build a submission-ready Markdown report from store.all_host_findings()
    -shaped dicts (or anything with the same keys). Chain hypotheses
    (vulnerability_class starting with "potential-attack-chain:") are
    automatically separated into their own section.

    `effort_ledger`: optional. When provided, UNCONFIRMED findings are
    additionally re-ordered by risk_allocator's cost-aware value_density
    (see `_rank_unconfirmed_by_value_density`'s docstring for exactly
    what "cost" means here and its honest limits). When omitted (the
    default, and the only behavior that existed before this feature),
    unconfirmed findings keep the same plain severity/confidence sort as
    confirmed findings -- this parameter is purely additive; no existing
    caller's behavior changes unless it opts in.

    `quarantine_leads`: when True, assumed/recalled live-class findings with no
    oracle verification and no leg confirmation are routed to a separate
    "Test Suggestions" section rather than counting toward reported findings.
    Intended for blind / no-oracle measurement runs. SHIPPED OFF (False) so a
    fully-confirmed run is unaffected.
    """
    from harness.confirmation_gate import should_quarantine_as_lead

    generated_at = generated_at or datetime.now(timezone.utc)

    # Parse raw dicts alongside their findings so the quarantine predicate can
    # read all stored fields (oracle_verified, basis, confirmed, ...) from the
    # original dict -- the ReportFinding view does not carry every field.
    pairs = [(raw, _from_store_dict(raw)) for raw in findings]

    individual_pairs = [(r, f) for r, f in pairs if not f.is_chain]
    chains = [f for _, f in pairs if f.is_chain]

    # Quarantine: route assumed/recalled live-class unverified findings to a
    # separate bucket rather than the main list. The predicate uses the raw dict
    # so it sees oracle_verified / basis / confirmed exactly as stored.
    if quarantine_leads:
        leads_bucket: list = []
        individual: list = []
        for raw, f in individual_pairs:
            if should_quarantine_as_lead(raw):
                leads_bucket.append(f)
            else:
                individual.append(f)
    else:
        individual = [f for _, f in individual_pairs]
        leads_bucket = []

    # Collapse per-(endpoint-family, class) duplicates, floating confirmed. A
    # max-coverage run's 225 findings / 45 confirmed were heavy duplicates over ~4
    # endpoint-families (HANDOVER_6 §4/§6.2); this turns that pile into a real
    # shortlist without dropping any distinct bug.
    individual, collapsed_count = _collapse_duplicates(individual)

    individual.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.confidence))

    confirmed = [f for f in individual if f.confirmed]
    unconfirmed = [f for f in individual if not f.confirmed]

    if effort_ledger is not None and unconfirmed:
        unconfirmed = _rank_unconfirmed_by_value_density(unconfirmed, effort_ledger)

    lines: list[str] = []
    lines.append(f"# Security Findings Report -- {host}")
    lines.append("")
    lines.append(f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    _leads_note = (f", **{len(leads_bucket)} quarantined test suggestion(s)**"
                   if leads_bucket else "")
    lines.append(f"**{len(confirmed)} confirmed finding(s)**, **{len(unconfirmed)} unconfirmed finding(s)**, "
                 f"**{len(chains)} potential attack chain(s)**{_leads_note}.")
    if collapsed_count:
        lines.append("")
        lines.append(f"*{collapsed_count} duplicate finding(s) were collapsed* -- the same class proven or "
                     f"suspected on the same endpoint family (object ids normalised) is shown once, as one "
                     f"finding, with the confirmed/highest-confidence instance kept.")
    if suppressed_count:
        lines.append("")
        lines.append(f"*{suppressed_count} previously-suppressed finding(s) from earlier scans are not "
                      f"shown below.* Suppression means an analyst already reviewed and dismissed these "
                      f"(typically as false positives) -- not that they were re-checked and cleared this "
                      f"run. Declared here so the count is never silently missing from the total.")
    lines.append("")
    lines.append("> Unconfirmed findings are hypotheses from an LLM agent's analysis of captured "
                 "traffic, not verified vulnerabilities. Each is labeled with its `basis` -- treat "
                 "`assumed` and `recalled` findings with extra scrutiny before acting on them. "
                 "Confirmed findings were independently checked by a validator (an active probe, "
                 "a byte-level format check, or equivalent) and carry stronger evidence.")
    lines.append("")

    if confirmed:
        # Step 4 (2026-09-17 coverage-recovery plan): an exploit a deterministic
        # leg actually confirmed (SQLi, IDOR, RCE, ...) is a different kind of
        # claim than a passive header/content OBSERVATION (CORS, CSP,
        # verbose-error, ...) that happens to also set confirmed=True -- split
        # them so the reader (and anyone counting "N confirmed") can tell which
        # is which, without changing the overall confirmed count or heading any
        # existing caller already relies on.
        confirmed_exploits = [f for f in confirmed if not f.is_observation]
        confirmed_observations = [f for f in confirmed if f.is_observation]
        lines.append("## Confirmed Findings")
        lines.append("")
        if confirmed_observations:
            lines.append(f"Of these, **{len(confirmed_exploits)}** are confirmed EXPLOITS "
                        f"(a deterministic leg actively proved the vulnerability) and "
                        f"**{len(confirmed_observations)}** are confirmed OBSERVATIONS "
                        f"(a passive header/content check, not a live exploit).")
            lines.append("")
        if confirmed_exploits:
            if confirmed_observations:
                lines.append("### Confirmed Exploits")
                lines.append("")
            for f in confirmed_exploits:
                lines.extend(_render_finding(f))
        if confirmed_observations:
            lines.append("### Confirmed Observations")
            lines.append("")
            lines.append("_Passive header/content checks (CORS, CSP, verbose errors, ...) -- real "
                        "findings, but not live-exploited the way the findings above were._")
            lines.append("")
            for f in confirmed_observations:
                lines.extend(_render_finding(f))

    if unconfirmed:
        lines.append("## Unconfirmed Findings")
        lines.append("")
        lines.append("_These have not been independently validated. Verify manually before including "
                     "them in a submission._")
        lines.append("")
        for f in unconfirmed:
            lines.extend(_render_finding(f))

    if chains:
        lines.append("## Potential Attack Chains")
        lines.append("")
        lines.append("_Rule-based hypotheses from combining two independently-flagged findings on the "
                     "same host. These are NOT confirmed exploit paths -- individually-valid findings "
                     "don't automatically compose. Each requires an explicit, deliberate test to confirm "
                     "the chain actually works before it's submitted as one finding rather than two._")
        lines.append("")
        for f in chains:
            lines.append(f"### {f.vulnerability_class.replace('potential-attack-chain:', '').replace('+', ' → ')}")
            lines.append("")
            lines.append(f"**Severity if confirmed:** {_SEVERITY_BADGE.get(f.severity, f.severity)}")
            lines.append("")
            lines.append(f.evidence)
            lines.append("")
            lines.append(f"**Suggested verification:** {f.suggested_test}")
            lines.append("")

    if leads_bucket:
        lines.append("## Test Suggestions (unverified leads)")
        lines.append("")
        lines.append("_These assumed/recalled-basis findings were quarantined from the main list because "
                     "the class has a live-verified oracle leg that did not run on this exchange, and no "
                     "leg independently confirmed or refuted them. They are test suggestions, not reported "
                     "vulnerabilities -- manually trigger the appropriate validator before treating these "
                     "as real findings._")
        lines.append("")
        for f in leads_bucket:
            lines.extend(_render_finding(f))

    if not individual and not chains and not leads_bucket:
        lines.append("_No findings recorded for this host._")
        lines.append("")

    return "\n".join(lines)


_STATE_BADGE = {
    "CONFIRMED": "✅ CONFIRMED",
    # SUSPECTED: a still-open hypothesis (no leg, or a not-yet-live-verified
    # leg). LEAD: a reliable check had its shot and it did not hold -- likely a
    # false positive or unverifiable. Both are unconfirmed, but they are not the
    # same thing to an analyst deciding what to look at first (W-7).
    "SUSPECTED": "❓ SUSPECTED (unconfirmed)",
    "LEAD": "🔻 LEAD (demoted, unconfirmed)",
}

# Oracle-verification badge (precision item #2): VERIFIED means an oracle
# reproduced it N-of-N with a clean negative control; CANDIDATE means it did not
# clear that bar (a leg may still have fired once -- see the Status badge).
_VERIFICATION_BADGE = {
    "verified": "🔒 VERIFIED (oracle-reproduced)",
    "candidate": "🧪 CANDIDATE (not oracle-verified)",
}


def _render_finding(f: ReportFinding) -> list[str]:
    # R03: this Markdown path did not share issues.py's redaction (redact/
    # redact_url) with the structured issue-export path -- a captured
    # ?token=... query string or an Authorization/Cookie-shaped value quoted
    # into evidence/summary/suggested_test survived here even though the
    # separate JSON export already masked it. Redact at this render boundary
    # (not earlier in ReportFinding construction) so URL-based dedup/grouping
    # upstream still sees the real, unredacted URL.
    from harness import issues
    url = issues.redact_url(f.url)
    summary = issues.redact(f.summary)
    evidence = issues.redact(f.evidence)
    suggested_test = issues.redact(f.suggested_test)

    lines = []
    status = _STATE_BADGE.get(f.lifecycle_state, "❓ SUSPECTED (unconfirmed)")
    verification = _VERIFICATION_BADGE.get(f.verification_state, "🧪 CANDIDATE")
    lines.append(f"### {f.vulnerability_class} -- {url}")
    lines.append("")
    lines.append(f"**Status:** {status} &nbsp;|&nbsp; **Verification:** {verification} "
                 f"&nbsp;|&nbsp; **Severity:** {_SEVERITY_BADGE.get(f.severity, f.severity)} "
                 f"&nbsp;|&nbsp; **Confidence:** {f.confidence:.2f} ({_confidence_label(f.confidence)}) "
                 f"&nbsp;|&nbsp; **Basis:** {f.basis}")
    if f.duplicate_count > 1:
        lines.append(f"**Also observed on {f.duplicate_count - 1} other instance(s)** of this endpoint "
                     f"family (same class, different object id) -- collapsed into this one finding.")
    if f.owasp_category:
        lines.append(f"**OWASP category:** {f.owasp_category}")
    basis_note = _basis_note(f.basis)
    if basis_note and f.basis != "derived":
        lines.append(f"> ⚠️ {basis_note}")
    lines.append("")
    lines.append(f"**Description:** {summary}")
    lines.append("")
    if evidence:
        lines.append("**Evidence:**")
        lines.append("```")
        # R03: captured/model text inside a code fence must not be able to
        # break OUT of that fence -- a literal ``` in evidence would close it
        # early and let the rest render as ordinary (attacker-influenced)
        # Markdown/HTML instead of a fenced block.
        lines.append(evidence.replace("`", "'"))
        lines.append("```")
        lines.append("")
    # Weakness #5: keep the reproduction field ACTUAL reproduction, not remediation.
    if suggested_test and not _looks_like_remediation(suggested_test):
        lines.append(f"**Steps to reproduce:** {suggested_test}")
        lines.append("")
    elif evidence:
        lines.append("**Steps to reproduce:** replay the exact captured request/response shown in the "
                     "Evidence block above, as the identity/session it was captured under, and compare "
                     "the actual result against a secure baseline.")
        lines.append("")
    # A remediation-shaped suggested_test is surfaced as a fix note, never as repro.
    if suggested_test and _looks_like_remediation(suggested_test):
        lines.append(f"**Fix note (from the detector):** {suggested_test}")
        lines.append("")
    lines.append(f"**Suggested remediation:** {_remediation_for(f.vulnerability_class)} "
                 f"_(generic starting point -- verify against this target's actual implementation)_")
    lines.append("")
    lines.append(f"_Reported by: `{f.agent}`_")
    if f.issue_id:
        lines.append(f"_Issue: `{f.issue_id}` -- stable across runs; a retest of this bug links "
                      f"to this same issue id rather than opening a new one._")
    if f.fingerprint:
        lines.append(f"_Fingerprint: `{f.fingerprint[:16]}` -- use this to suppress if this is a "
                      f"false positive, so it doesn't resurface on a future scan of this host._")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def generate_report_for_host(url: str, effort_ledger: EffortLedger | None = None) -> str:
    """
    Convenience entry point: pulls findings from store.py for the given
    host's URL. `effort_ledger`: optional, forwarded to
    `generate_markdown_report` -- pass `orchestrator.effort_budget.ledger`
    if calling this from code that has a live orchestrator instance, to
    get cost-aware ordering of unconfirmed findings. Omitted by default
    since this function is also used as a standalone script entry point
    with no orchestrator in scope.
    """
    from harness import store
    findings = store.all_host_findings(url)  # excludes suppressed, by default
    all_including_suppressed = store.all_host_findings(url, include_suppressed=True)
    suppressed_count = len(all_including_suppressed) - len(findings)
    host = store.host_of(url)
    return generate_markdown_report(host, findings, effort_ledger=effort_ledger, suppressed_count=suppressed_count)


def issue_exports(findings: list[dict], proofs_by_case: dict | None = None,
                   merges: dict[str, str] | None = None) -> list[dict]:
    """Group store-shaped findings into stable issues and render each as a
    reproducible, secret-free export (T06). This is the machine-readable
    counterpart to the Markdown report: it keeps EVERY affected case/instance
    (not just a winner + count) and links case/proof ids, so an issue exported
    from one run maps to the same issue id on a patched-fixture retest.

    `merges` (P1.8), when given, applies operator-declared REVERSIBLE
    root-cause merges on top of the automatic grouping -- see
    issues.apply_merge_overrides. Omitted/empty -> unchanged automatic
    grouping, exactly as before this parameter existed."""
    from harness import issues
    grouped = issues.group_findings_into_issues(findings)
    if merges:
        grouped = issues.apply_merge_overrides(grouped, merges)
    return [issues.export_issue(i, proofs_by_case=proofs_by_case) for i in grouped]


def export_issues_for_host(url: str) -> list[dict]:
    """Convenience: pull a host's findings from store.py and return their T06 issue
    exports, enriched with the FULL append-only proof-attempt history per case
    (store.proofs_for_case) -- so every attempt, including a patched-fixture retest,
    is preserved with its own proof id and verdict (T06 history preservation).
    Also applies any operator-declared merge overrides for this host (P1.8)."""
    from harness import store
    findings = store.all_host_findings(url)
    proofs_by_case: dict = {}
    for f in findings:
        cid = f.get("case_id")
        if cid and cid not in proofs_by_case:
            attempts = store.proofs_for_case(cid)   # every recorded attempt, append-only
            if attempts:
                proofs_by_case[cid] = attempts
    merges = store.all_issue_merges(store.host_of(url))
    return issue_exports(findings, proofs_by_case=proofs_by_case, merges=merges)
