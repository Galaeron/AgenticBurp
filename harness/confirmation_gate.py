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

    if demoted > 0:
        log.info("Confirmation-suppression gate processed %d unconfirmed finding(s) "
                 "(REFUTED to low / UNPROVEN capped at medium)", demoted)

    return demoted
