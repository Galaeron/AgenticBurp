"""
Confirmation-suppression gate -- leg-aware, 3-state (Phase 1.1).

An unconfirmed hypothesis is not one thing: what its non-confirmation MEANS
depends on whether the harness even had a reliable way to confirm it. So the gate
places every unconfirmed finding into one of three states, keyed off the
verification TIER of the confirmation leg for its class:

  1. CONFIRMED   -- a leg proved it (confirmed=True). Untouched; ships at its true
                    severity/confidence with reproduction evidence.
  2. REFUTED     -- unconfirmed, and the class has a LIVE-VERIFIED leg (one proven
                    to actually confirm real instances on a live target). The
                    leg had its shot and stayed silent, so this is likely a false
                    positive: demote to "low", cap confidence <= 0.35, verdict
                    "unconfirmed_hypothesis", prefix "[Hypothesis]".
  3. UNPROVEN    -- unconfirmed, and the class's leg is only SMOKE/hermetic-verified
                    (not yet proven to bite live). Its silence is weak evidence, so
                    burying a possibly-real finding to "low" would cost recall:
                    instead cap severity at "medium" (never high/critical
                    unconfirmed), cap confidence <= 0.5, verdict
                    "unproven_unverified_leg", prefix "[Unconfirmed]".

Classes with NO confirmation leg are left untouched (the gate is about classes we
could have confirmed). The live-verified set is what Phase 2's leg
live-verification refreshes: as a leg graduates smoke_only -> live_verified, its
class moves from UNPROVEN (medium) to REFUTED (low) suppression. Callers may pass
`live_verified_markers` to override the default seed.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.models import AgentReport, Finding, ValidationReport

log = logging.getLogger("harness.confirmation_gate")

# Confidence caps. REFUTED (live-verified leg stayed silent) is capped hard,
# below the standard triage threshold; UNPROVEN (leg not live-verified) is capped
# at the threshold -- visible but not asserted.
_REFUTED_CONFIDENCE_CAP = 0.35
_UNPROVEN_CONFIDENCE_CAP = 0.5
# Back-compat alias (older imports).
_UNCONFIRMED_HYPOTHESIS_CONFIDENCE_CAP = _REFUTED_CONFIDENCE_CAP

# Vulnerability classes that possess a deterministic confirmation leg in this harness.
# Matched case-insensitively as substrings against finding.vulnerability_class.
CONFIRMABLE_CLASS_MARKERS = frozenset({
    # IDOR / Access Control family (cross_identity_validator)
    "idor",
    "insecure_direct_object",
    "insecure direct object",
    "broken_access_control",
    "broken access control",
    "bola",
    "bfla",
    "privilege escalation",
    "privilege_escalation",
    "missing authorization",
    "missing_authorization",

    # SQL Injection family (sqlmap / sqlmap_validator)
    "sql_injection",
    "sql injection",
    "sqli",

    # XSS family (browser_xss_validator)
    "xss",
    "cross_site_scripting",
    "cross-site scripting",
    "cross site scripting",

    # SSRF family (ssrf_validator)
    "ssrf",
    "server_side_request_forgery",
    "server-side request forgery",
    "server side request forgery",

    # XXE family (xxe_validator)
    "xxe",
    "xml_external_entity",
    "xml external entity",

    # JWT family (jwt_forge_validator)
    "jwt",
    "jwt_forge",
    "algorithm confusion",
    "algorithm_confusion",
    "weak_token",

    # Command Injection family (command_injection_validator)
    "command_injection",
    "command injection",
    "rce",
    "remote code execution",
    "remote_code_execution",
    "shell injection",
    "shell_injection",

    # SSTI family (ssti_validator)
    "ssti",
    "template_injection",
    "template injection",

    # Path Traversal family (path_traversal_validator)
    "path_traversal",
    "path traversal",
    "directory traversal",
    "directory_traversal",
    "lfi",
    "local file inclusion",
    "file inclusion",

    # Open Redirect family (open_redirect_validator)
    "open_redirect",
    "open redirect",
    "unvalidated redirect",
    "unvalidated_redirect",

    # Mass-assignment / privilege escalation (sequence_validator, Phase 3)
    "mass_assignment",
    "mass assignment",

    # Insecure deserialization -- active OOB pickle beacon (deserialization_oob)
    "deserialization",
    "insecure deserialization",
    "insecure_deserialization",
    "pickle",

    # Auth-mechanism family (auth_sequence): session fixation / weak-password /
    # username enumeration multi-request flows.
    "session_fixation",
    "session fixation",
    "weak_password",
    "weak password",
    "username_enumeration",
    "username enumeration",
    "user enumeration",

    # CSRF family (csrf_validator)
    "csrf",
    "cross-site request forgery",
    "cross site request forgery",
    "xsrf",

    # File upload bypass (file_upload_validator)
    "file_upload",
    "file upload",
    "arbitrary file upload",
    "unrestricted file upload",

    # Verb tamper / method bypass (verb_tamper_validator)
    "verb_tamper",
    "verb tamper",
    "method tampering",
    "http method",
    "misconfig",

    # Rate limiting / lockout absence (rate_limit_validator)
    "rate_limit",
    "rate limit",
    "no rate limiting",
    "brute force",
    "brute_force",
    "lockout",
    "account lockout",

    # Predictable reset/session token (reset_token_validator)
    "reset_token",
    "reset token",
    "predictable token",
    "weak token",
    "insecure token",
    "token entropy",

    # DOM-based XSS (dom_xss_validator -- fragment-payload browser execution)
    "dom_xss",
    "dom xss",
    "dom-based xss",
    "dom based xss",
    "client-side xss",

    # TOCTOU privilege-escalation race (toctou_validator)
    "toctou",
    "time-of-check",
    "time of check",
    "check-then-act",
    "privilege escalation race",
})

# The subset of confirmable classes whose leg is LIVE-VERIFIED -- proven to
# actually confirm real instances against a live target. Sources:
#   - session-11 max-coverage run vs VulnCorp: cross_identity (IDOR/access
#     control), sqlmap (SQLi), jwt_forge (JWT alg:none), xxe, path_traversal.
#   - Phase 2 (this session), test_leg_live_verification against a real local
#     vulnerable fixture: ssti (Jinja render), open_redirect (blind 302), ssrf
#     (real server-side fetch to the collaborator), command_injection (real shell
#     fetch), and the sequence leg (real mass-assignable write -> re-read).
# THIS SET is what live-verification refreshes. See LEG_VERIFICATION.md for the
# full split.
LIVE_VERIFIED_MARKERS = frozenset({
    "idor", "insecure_direct_object", "insecure direct object",
    "broken_access_control", "broken access control", "bola", "bfla",
    "missing authorization", "missing_authorization",
    "sql_injection", "sql injection", "sqli",
    "xxe", "xml_external_entity", "xml external entity",
    "path_traversal", "path traversal", "directory traversal", "directory_traversal",
    "lfi", "local file inclusion", "file inclusion",
    "jwt", "jwt_forge", "algorithm confusion", "algorithm_confusion", "weak_token",
    # Phase 2 live-verified (test_leg_live_verification, real local fixture):
    "ssti", "template_injection", "template injection",
    "open_redirect", "open redirect", "unvalidated redirect", "unvalidated_redirect",
    "ssrf", "server_side_request_forgery", "server-side request forgery",
    "server side request forgery",
    "command_injection", "command injection", "rce", "remote code execution",
    "remote_code_execution", "shell injection", "shell_injection",
    "mass_assignment", "mass assignment",
    # Session-16: the sequence leg's write->re-read differential IS privilege
    # escalation (inject role=admin/is_admin, re-read shows it persisted) --
    # live-verified against the fixture (test_sequence_confirms_privilege_escalation_class).
    "privilege escalation", "privilege_escalation",
    # Session-13: active deserialization OOB pickle beacon, live-verified against a
    # real pickle.loads sink in test_leg_live_verification.
    "deserialization", "insecure deserialization", "insecure_deserialization", "pickle",
    # Session-13: auth-mechanism legs, live-verified against fixture flows
    # (session-not-rotated / weak-password-accepted / existence-discriminating error).
    "session_fixation", "session fixation", "weak_password", "weak password",
    "username_enumeration", "username enumeration", "user enumeration",

    # NOTE (review 2026-09-09 oracle retirements): csrf and verb_tamper were
    # REMOVED from the live set -- their legs overconfirmed (a token-strip 2xx
    # replay is not CSRF; an alternate-method 2xx is not necessarily an authz
    # bypass) and now emit observations, not confirmations (see ORACLE_RETIREMENTS.md).
    # They remain in CONFIRMABLE_CLASS_MARKERS, so they are treated as PROVISIONAL
    # (capped at medium, not refuted). Re-add here only when a sound oracle is
    # restored and live-verified.

    # File upload bypass (file_upload_validator, session-15) -- kept: a disallowed
    # extension stored AND served with an active HTML/script Content-Type (not as an
    # attachment) is a real filter bypass (oracle tightened per the review).
    "file_upload", "file upload", "arbitrary file upload",
    "unrestricted file upload",

    # XSS family (browser_xss_validator, session-15: live-verified against the
    # vuln_fixture reflected-XSS endpoint with real Playwright + Chromium).
    "xss", "cross_site_scripting", "cross-site scripting", "cross site scripting",
})


# Provisional technique markers: a leg EXISTS but is NOT yet live-verified.
# These are checked BEFORE the live set so a provisional subclass whose name
# merely CONTAINS a live class's name as a substring is not mis-promoted to
# "live" (R09). The reproduced defects: leg_tier("dom_xss") returned "live"
# because "xss" is a substring; leg_tier("privilege escalation race") returned
# "live" because "privilege escalation" is a substring. dom_xss / toctou-race /
# rate_limit / reset_token are provisional (see CURRENT_STATE leg tiers) and must
# resolve to "provisional" regardless of those substrings.
PROVISIONAL_MARKERS = frozenset({
    # DOM XSS (⊃ "xss", which is live)
    "dom_xss", "dom xss", "dom-based xss", "dom based xss", "client-side xss", "client side xss",
    # TOCTOU / privilege-escalation RACE (⊃ "privilege escalation", which is live)
    "toctou", "time-of-check", "time of check", "check-then-act", "check then act",
    "privilege escalation race", "privilege_escalation_race",
    # rate limit / lockout
    "rate_limit", "rate limit", "no rate limiting", "brute force", "brute_force",
    "lockout", "account lockout",
    # predictable reset/session token
    "reset_token", "reset token", "predictable token", "insecure token", "token entropy",
})


def is_confirmable_class(vuln_class: str | None) -> bool:
    """Check if the given vulnerability class has a deterministic confirmation leg."""
    if not vuln_class:
        return False
    lowered = vuln_class.lower()
    return any(marker in lowered for marker in CONFIRMABLE_CLASS_MARKERS)


# --------------------------------------------------------------------------- #
# W-7: explicit finding lifecycle states, surfaced to the operator so the UI
# shows CONFIRMED vs not at a glance instead of asking a reader to interpret a
# raw confidence number ("unconfirmed != confirmed in the UI"). Derived from the
# confirmed flag plus the review verdict the suppression gate / cross-identity
# reject / critique already set -- one canonical mapping for the findings API,
# the report, and the Burp tab.
# --------------------------------------------------------------------------- #
STATE_CONFIRMED = "CONFIRMED"
STATE_SUSPECTED = "SUSPECTED"
STATE_LEAD = "LEAD"

# Verdicts meaning a reliable check had its shot and the finding did not hold up
# (a live-verified leg refuted it or could not run a negative, a cross-identity
# reject, or a critique rejection) -> demoted, weakest actionable state.
_LEAD_VERDICTS = frozenset({
    "unconfirmed_hypothesis",   # REFUTED: a live-verified leg ran and stayed silent
    "inconclusive_unverified",  # live-verified leg for the class, but none ran a negative
    "downgraded",               # cross-identity reject cap (every other identity denied)
    "rejected",                 # adversarial critique rejected the hypothesis
})


def lifecycle_state(confirmed: bool, review_verdict: str | None = "") -> str:
    """Map (confirmed, review_verdict) to a CONFIRMED / SUSPECTED / LEAD state.

    CONFIRMED: a deterministic leg proved it -- ships at true severity.
    SUSPECTED: a plausible, still-open hypothesis (no leg for the class, or a
      not-yet-live-verified leg) -- kept visible, capped, awaiting verification.
    LEAD: a reliable check had its shot and the finding did not hold (likely a
      false positive, or unverifiable) -- demoted, lowest actionable.
    """
    if confirmed:
        return STATE_CONFIRMED
    if (review_verdict or "").lower() in _LEAD_VERDICTS:
        return STATE_LEAD
    return STATE_SUSPECTED


def finding_lifecycle_state(finding) -> str:
    """lifecycle_state for a Finding object or a finding dict."""
    if isinstance(finding, dict):
        confirmed = bool(finding.get("confirmed", False))
        verdict = finding.get("review_verdict", "") or ""
    else:
        confirmed = bool(getattr(finding, "confirmed", False))
        verdict = getattr(finding, "review_verdict", "") or ""
    return lifecycle_state(confirmed, verdict)


def leg_tier(vuln_class: str | None, live_verified_markers: frozenset | None = None) -> str:
    """Verification tier of the confirmation leg for a class:
    "live" (a live-verified leg exists), "provisional" (a leg exists but is only
    smoke/hermetic-verified), or "none" (no leg). `live_verified_markers` overrides
    the default LIVE_VERIFIED_MARKERS seed -- the seam Phase 2 uses to promote a
    leg once it is live-verified.

    R09: a provisional subclass is NOT promoted to "live" merely because a live
    class's NAME is a substring of it (dom_xss ⊃ "xss"; "privilege escalation
    race" ⊃ "privilege escalation"). It is promoted only when an explicit override
    lists one of ITS OWN provisional markers -- the deliberate Phase-2 promotion
    path, not an accidental substring."""
    if not is_confirmable_class(vuln_class):
        return "none"
    lowered = (vuln_class or "").lower()
    live = LIVE_VERIFIED_MARKERS if live_verified_markers is None else live_verified_markers
    prov_hit = {m for m in PROVISIONAL_MARKERS if m in lowered}
    if prov_hit:
        # Only a deliberate override that names one of this technique's OWN
        # provisional markers promotes it to live; the built-in default never does.
        if live_verified_markers is not None and (prov_hit & set(live)):
            return "live"
        return "provisional"
    return "live" if any(marker in lowered for marker in live) else "provisional"


def active_confirmation_is_unproven(finding: dict) -> bool:
    """2026-09-17 coverage-recovery plan, Step 4: True when a finding claims
    `confirmed=True` for a class that HAS a deterministic leg (leg_tier !=
    "none") but carries none of `confirmed_by_leg`, `proof_id`, or the older
    `confirmation_method` (a pre-Step-4 synonym some call sites still use) --
    an active-class confirmation with no leg named at all.

    This is the honesty backstop, not the primary path: `_validate_findings`
    and `coverage_confirmation_finding` always stamp `confirmed_by_leg`
    alongside `confirmed=True` (Step 4), so a finding that reaches here
    unstamped got `confirmed=True` from somewhere else entirely -- an agent's
    own claim that survived sanitize_agent_finding some other way, or a future
    call site that sets the flag directly. A class with NO leg at all
    (leg_tier == "none") is a *different*, already-handled case
    (engagement.needs_human_review's human-verification hand-off) and is
    deliberately excluded here -- this function only polices classes where an
    automated leg exists and therefore SHOULD have been the one to confirm."""
    if not finding.get("confirmed"):
        return False
    if finding.get("confirmed_by_leg") or finding.get("proof_id") or finding.get("confirmation_method"):
        return False
    return leg_tier(finding.get("vulnerability_class")) != "none"


def should_quarantine_as_lead(finding) -> bool:
    """True when a finding should be surfaced as a LEAD test suggestion rather
    than a reported finding, on a blind / no-oracle run.

    Quarantine conditions (ALL must hold):
      - The class has a live-verified leg (leg_tier == "live") -- so a real
        oracle EXISTS but never ran.
      - The agent's basis is "assumed" or "recalled" -- not directly observed.
      - The finding was not confirmed by any leg (confirmed is False).
      - The oracle did not verify the finding (oracle_verified is False).

    A finding that is already CONFIRMED or ORACLE-VERIFIED is never quarantined.
    A finding whose class has NO live leg (provisional / none) is never quarantined
    here; those are handled by the ordinary confirmation-suppression gate.

    This is a SURFACING decision, not a deletion: callers route quarantined findings
    into a separate `leads` bucket rather than removing them."""
    if isinstance(finding, dict):
        basis = (finding.get("basis") or "derived").lower()
        oracle_verified = bool(finding.get("oracle_verified", False))
        confirmed = bool(finding.get("confirmed", False))
        vc = finding.get("vulnerability_class", "")
    else:
        basis = (getattr(finding, "basis", "derived") or "derived").lower()
        oracle_verified = bool(getattr(finding, "oracle_verified", False))
        confirmed = bool(getattr(finding, "confirmed", False))
        vc = getattr(finding, "vulnerability_class", "")

    if confirmed or oracle_verified:
        return False
    if basis not in ("assumed", "recalled"):
        return False
    return leg_tier(vc) == "live"


# 2026-09-23 B2-5: the scorecard's dominant FP driver across blind runs is a
# narrow set of generic-class, low-confidence agent GUESSES with no
# confirming leg -- named offenders (2026-09-22 reviews/2026-09-22/
# BLIND_SCORECARD_P0-3.md): "Security misconfiguration",
# "Broken Access Control (Workflow Bypass)", "SQL injection" at confidence
# 0.3-0.5, firing on nearly every exchange regardless of actual target
# behavior. `is_low_confidence_generic_guess` below is a SIBLING gate to
# `should_quarantine_as_lead` -- same recall guard (never a confirmed /
# oracle-verified / at-or-above-floor finding), a different trigger (class +
# raw confidence number, rather than basis + leg_tier).
#
# `categories.canonicalize()` deliberately returns None for ambiguous
# OWASP-style category names it refuses to guess at (see
# test_categories.py's assertion that canonicalize("Broken Access Control")
# is None -- a real OWASP Top 10 heading that could mean idor, business
# logic, or auth) -- so "Broken Access Control (Workflow Bypass)" can't be
# reached purely through the canonical-key synonym table. The default set
# below is built from canonicalize()'s result where it succeeds, falling
# back to the raw lowercased phrase where it refuses to guess; the SAME
# canonicalize-or-lowercase rule is applied to the finding under test in
# `_generic_class_key`, so matching stays a single narrow exact-key lookup
# either way -- never a substring/fuzzy match.
_GENERIC_CLASS_SOURCE_PHRASES: tuple[str, ...] = (
    "Security misconfiguration",
    "Broken Access Control (Workflow Bypass)",
    "SQL injection",
    # 2026-09-25 FR-4: info_disclosure joins the generic set now that
    # categories.py's synonym table folds the model's actual info-disclosure
    # spelling variants (information_disclosure, verbose_error_disclosure,
    # excessive_data_exposure, exposure_of_internal_data,
    # exposure_of_sensitive_information, information_disclosure_header, ...)
    # into this one canonical key -- see categories._SYNONYMS. Before that
    # fix this class could never be reached here at all.
    "Information Disclosure",
)


def _generic_class_key(vuln_class) -> str:
    from harness.categories import canonicalize
    vc = vuln_class or ""
    return canonicalize(vc) or vc.strip().lower()


DEFAULT_GENERIC_CLASSES: frozenset = frozenset(
    _generic_class_key(p) for p in _GENERIC_CLASS_SOURCE_PHRASES
)


def is_low_confidence_generic_guess(finding, floor: float = 0.5, generic_classes=None) -> bool:
    """Sibling predicate to `should_quarantine_as_lead`: True when a finding is
    an UNCONFIRMED, LOW-CONFIDENCE guess in one of a narrow set of generic
    vulnerability classes, with no confirming leg -- the dominant FP driver
    identified in the 2026-09-22 blind scorecard.

    ALL of the following must hold:
      - Not confirmed (confirmed is False) -- no confirming leg.
      - Not oracle-verified (oracle_verified is False).
      - `confidence` is a real number strictly below `floor`.
      - The finding's vulnerability_class resolves (via
        `_generic_class_key`: categories.canonicalize, falling back to the
        raw lowercased string where canonicalize refuses to guess) to one of
        `generic_classes`.

    This is the SAME recall guard as `should_quarantine_as_lead`: a confirmed
    or oracle-verified finding is NEVER routed here, and neither is one at or
    above the confidence floor -- regardless of class. `generic_classes`
    defaults to `DEFAULT_GENERIC_CLASSES`, a deliberately narrow, reviewable
    set -- never a broad substring match.

    Accepts a dict-or-object finding, mirroring `should_quarantine_as_lead`."""
    generic_classes = DEFAULT_GENERIC_CLASSES if generic_classes is None else generic_classes

    if isinstance(finding, dict):
        confirmed = bool(finding.get("confirmed", False))
        oracle_verified = bool(finding.get("oracle_verified", False))
        confidence = finding.get("confidence", None)
        vc = finding.get("vulnerability_class", "")
    else:
        confirmed = bool(getattr(finding, "confirmed", False))
        oracle_verified = bool(getattr(finding, "oracle_verified", False))
        confidence = getattr(finding, "confidence", None)
        vc = getattr(finding, "vulnerability_class", "")

    if confirmed or oracle_verified:
        return False
    if not isinstance(confidence, (int, float)) or confidence >= floor:
        return False
    return _generic_class_key(vc) in generic_classes


# 2026-09-25 FR-4 (supersedes BM-1): offline re-score of the captured
# benchmark findings (reviews/2026-09-25/benchmark/*_strict_3x.json) showed
# confidence is the WRONG lever for exactly two catch-all classes --
# `misconfig` and `info_disclosure` are 69 of 101 pooled FPs but only 8 of 30
# pooled TPs, and 86/96 misconfig + 65/76 info-disclosure findings sit at
# confidence >= 0.5 (many pinned at exactly 0.50, an uncalibrated default) --
# so `is_low_confidence_generic_guess`'s confidence floor barely reaches them.
# The measured effective lever is instead an EVIDENCE requirement: for ONLY
# these two classes, require a confirming leg (confirmed OR oracle_verified)
# before the finding is surfaced, regardless of its self-reported confidence.
# Offline re-score: pooled precision 0.232 -> 0.407, F1 0.358 -> 0.500 (recall
# 0.784 -> 0.649; demoted findings are routed to leads, not deleted).
#
# This is DELIBERATELY narrow -- a GLOBAL leg requirement collapses recall to
# 0.05 (see the same re-score) and is explicitly NOT what this predicate
# does: only `DEFAULT_CATCHALL_CLASSES` is affected. sqli/xss/idor/
# path_traversal/jwt/csrf/etc. are untouched by this gate.
_CATCHALL_CLASS_SOURCE_PHRASES: tuple[str, ...] = (
    "Security misconfiguration",
    "Information Disclosure",
)

DEFAULT_CATCHALL_CLASSES: frozenset = frozenset(
    _generic_class_key(p) for p in _CATCHALL_CLASS_SOURCE_PHRASES
)


def is_uncorroborated_catchall_guess(finding, catchall_classes=None) -> bool:
    """True when a finding is an UNCONFIRMED, UNCORROBORATED guess in one of
    a narrow set of catch-all vulnerability classes (`misconfig`,
    `info_disclosure` by default) -- the measured effective FP lever for
    these two classes (see the module comment above this function).

    ALL of the following must hold:
      - Not confirmed (confirmed is False).
      - Not oracle-verified (oracle_verified is False).
      - The finding's vulnerability_class resolves (via `_generic_class_key`)
        to one of `catchall_classes`.

    UNLIKE `is_low_confidence_generic_guess`, this predicate ignores
    `confidence` entirely -- that is the point: these two classes sit at
    confidence >= 0.5 far too often for a confidence floor to catch them, so
    the lever here is corroborating evidence (a confirming leg or an oracle
    verification), not the model's own confidence number.

    Same recall guard as its siblings: a confirmed or oracle-verified finding
    is NEVER routed here, no matter its class. `catchall_classes` defaults to
    `DEFAULT_CATCHALL_CLASSES`, a deliberately narrow, reviewable set --
    never a broad substring match, and never applied globally (a same-class
    concrete finding of any OTHER class always still surfaces).

    Accepts a dict-or-object finding, mirroring `is_low_confidence_generic_guess`."""
    catchall_classes = DEFAULT_CATCHALL_CLASSES if catchall_classes is None else catchall_classes

    if isinstance(finding, dict):
        confirmed = bool(finding.get("confirmed", False))
        oracle_verified = bool(finding.get("oracle_verified", False))
        vc = finding.get("vulnerability_class", "")
    else:
        confirmed = bool(getattr(finding, "confirmed", False))
        oracle_verified = bool(getattr(finding, "oracle_verified", False))
        vc = getattr(finding, "vulnerability_class", "")

    if confirmed or oracle_verified:
        return False
    return _generic_class_key(vc) in catchall_classes


def _controlled_negative_classes(validation_reports: list | None) -> set:
    """Canonical finding classes for which a validator produced a real controlled
    NEGATIVE -- it actually ran and returned `not_confirmed` (R08). This is what
    separates a refutation ("a reliable leg ran and said no") from a leg that
    never produced a verdict (skipped / error / disabled / absent), which is NOT
    evidence of a false positive and must not be labelled as one."""
    from harness.categories import canonicalize
    neg: set = set()
    for vr in validation_reports or []:
        status = (getattr(vr, "status", "") or "").lower()
        confirmed = bool(getattr(vr, "confirmed", False))
        if status == "not_confirmed" and not confirmed:
            fc = getattr(vr, "finding_class", "") or ""
            neg.add(canonicalize(fc) or fc.lower())
    return neg


def apply_confirmation_suppression(
    reports: list[AgentReport],
    validation_reports: list[ValidationReport] | None = None,
    live_verified_markers: frozenset | None = None,
    config: dict | None = None,
) -> int:
    """
    Place each unconfirmed finding into an execution-aware, leg-aware state model.
    Mutates findings in place; returns the number demoted. Confirmed findings and
    no-leg classes are left untouched.

    - REFUTED  (live-verified leg AND a real controlled negative for the class in
      `validation_reports`): the leg actually ran and said no -> likely false
      positive. severity -> "low", confidence <= 0.35, verdict
      "unconfirmed_hypothesis", prefix "[Hypothesis]".
    - UNVERIFIED (live-verified leg but NO controlled negative executed -- the leg
      was skipped / errored / disabled / not run, or no validation reports were
      supplied): NOT a refutation (R08). Still capped for safety (severity -> low,
      confidence <= 0.35 -- the precision floor), but labelled honestly: verdict
      "inconclusive_unverified", prefix "[Unverified]", note says it was neither
      confirmed nor refuted so it must not be treated as a false positive.
    - UNPROVEN (class has a leg, but only smoke/hermetic-verified): severity capped
      at "medium", confidence <= 0.5, verdict "unproven_unverified_leg", prefix
      "[Unconfirmed]".

    `live_verified_markers` overrides which classes count as live-verified -- the
    seam Phase 2 uses to promote a leg after live-verifying it.
    """
    demoted = 0
    negatives = _controlled_negative_classes(validation_reports)
    from harness.categories import canonicalize as _canon

    def _emit_revision(finding, tier: str) -> None:
        # P0-1: FINDING_REVISION -- this gate's severity/confidence/verdict
        # demotion is already fully computed on `finding` by this point (the
        # lines above this call); this only RECORDS that decision onto the
        # ledger, it never feeds back into it. No-op when the finding has no
        # finding_id (nothing to attach the event to) -- never raises.
        if not getattr(finding, "finding_id", ""):
            return
        try:
            from harness import evidence_ledger
            evidence_ledger.emit(
                evidence_ledger.EventType.FINDING_REVISION, finding.finding_id,
                f"confirmation-suppression gate ({tier}): {finding.review_verdict} "
                f"-> severity={finding.severity}, confidence={finding.confidence:.2f}",
                data={"tier": tier, "review_verdict": finding.review_verdict,
                      "severity": finding.severity, "confidence": finding.confidence,
                      "original_severity": finding.original_severity,
                      "original_confidence": finding.original_confidence},
                provenance=evidence_ledger.Provenance.capture(config=config))
        except Exception:
            pass

    for report in reports:
        for finding in report.findings:
            if finding.confirmed:
                continue  # a leg proved it -- ships at true severity/confidence
            tier = leg_tier(finding.vulnerability_class, live_verified_markers)
            if tier == "none":
                continue  # no leg could have confirmed it -- not the gate's business

            demoted += 1
            if finding.original_confidence is None:
                finding.original_confidence = finding.confidence

            if tier == "live":
                fc_canon = _canon(finding.vulnerability_class) or (finding.vulnerability_class or "").lower()
                has_controlled_negative = fc_canon in negatives
                # Cap for safety in both cases (the precision floor: an unconfirmed
                # live-class finding never ships actionable), but DISTINGUISH why.
                finding.confidence = min(finding.confidence, _REFUTED_CONFIDENCE_CAP)
                if finding.severity in ("critical", "high", "medium"):
                    if finding.original_severity is None:
                        finding.original_severity = finding.severity
                    finding.severity = "low"
                if has_controlled_negative:
                    # REFUTED: a reliable leg ran and stayed silent -> likely FP.
                    finding.review_verdict = "unconfirmed_hypothesis"
                    prefix = "[Hypothesis]"
                    note = ("Demoted by confirmation-suppression gate: this class has a LIVE-VERIFIED "
                            "leg that RAN and did not confirm the finding on target -- treated as a "
                            "likely false positive.")
                else:
                    # UNVERIFIED: no leg produced a negative -- inconclusive, not refuted (R08).
                    finding.review_verdict = "inconclusive_unverified"
                    prefix = "[Unverified]"
                    note = ("Capped by confirmation-suppression gate: this class has a live-verified "
                            "leg, but NO confirmation execution produced a negative for this finding "
                            "(the leg was skipped/errored/disabled or not run). It is neither confirmed "
                            "nor refuted -- do NOT treat it as a false positive; re-run with the leg enabled.")
                finding.review_note = (
                    (finding.review_note + " " + note) if finding.review_note else note
                )
                if finding.summary and not finding.summary.startswith(prefix):
                    finding.summary = f"{prefix} {finding.summary}"
                _emit_revision(finding, "live")
                continue
            else:  # provisional
                # UNPROVEN: the leg isn't live-verified, so silence is weak
                # evidence -- keep it visible (capped) rather than bury it.
                finding.confidence = min(finding.confidence, _UNPROVEN_CONFIDENCE_CAP)
                if finding.severity in ("critical", "high"):
                    if finding.original_severity is None:
                        finding.original_severity = finding.severity
                    finding.severity = "medium"
                finding.review_verdict = "unproven_unverified_leg"
                prefix = "[Unconfirmed]"
                note = ("Capped by confirmation-suppression gate: this class's confirmation leg is "
                        "not yet live-verified, so the finding is neither confirmed nor reliably "
                        "refutable -- kept at capped severity pending live verification (Phase 2).")

            finding.review_note = (
                (finding.review_note + " " + note) if finding.review_note else note
            )
            if finding.summary and not finding.summary.startswith(prefix):
                finding.summary = f"{prefix} {finding.summary}"
            _emit_revision(finding, "provisional")

    if demoted > 0:
        log.info("Confirmation-suppression gate processed %d unconfirmed finding(s) "
                 "(REFUTED to low / UNPROVEN capped at medium)", demoted)

    return demoted
