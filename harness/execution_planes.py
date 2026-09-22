"""
Execution-plane capability-ownership matrix (RB-6, LOOP half).

AgenticBurp has TWO active-traffic execution planes that can each independently
send live requests at a target:

  - **Python plane** -- `harness/validators/*.py`, dispatched by
    `ValidatorRegistry` (`harness/validators/registry.py`) and, for the
    engagement coverage-matrix driver, by the `_val_by_conf` confirmation-name
    map in `harness/orchestrator_chain.py::investigate_engagement`. Every send
    routes through the single `TargetTransport` (`harness/run_context.py`)
    under `SafetyGate` (`harness/safety_gate.py`), the two-flag mutating opt-in
    (`validators.active_enabled` + `allow_mutating_replay`), a request budget,
    and the `EvidenceLedger` (`harness/evidence_ledger.py`).
  - **Java plane** -- `burp-extension/src/main/java/com/harness/llm/
    ValidationExecutor.java`, a `switch (plan.capability)` (~lines 99-129) whose
    ~30 case arms each call `api.http().sendRequest()` (or, for the two purely
    passive scans, inspect the already-captured exchange). The only gate is
    Burp's own `isInScope` check (line 93) on the source request -- there is no
    Python `SafetyGate`, no shared budget, and no per-hop evidence emitted into
    the Python evidence ledger. `*Logic.java` classes (e.g. `XssPayloadLogic`,
    `WorkflowReplayLogic`) are pure, Montoya-free decision helpers unit-tested
    in isolation -- they do not execute anything themselves and are not
    modelled here as a third plane.

**Shared evidence/gate contract** (what both planes SHOULD satisfy so a
capability's result means the same thing regardless of which plane ran it):
for every live send, record (1) the scope decision that authorized the
destination host, (2) the gate/budget decision that authorized the send itself
(mutating opt-in, rate/budget ceiling), and (3) the per-hop request/response
pair as evidence in the shared trail. The Python plane already satisfies this
via `SafetyGate` + `TargetTransport` + `EvidenceLedger`. **The Java plane does
not emit into that trail today** -- making `ValidationExecutor` emit its scope
decision, its (currently nonexistent) gate decision, and its per-hop
request/response pairs into the shared trail is the OWNER/JDK follow-up this
module intentionally leaves undone. This module and its test
(`harness/test_execution_planes.py`) are the LOOP half only: a committed record
of which plane(s) can run each capability today, and a test that keeps that
record honest as the source changes.

**Authoritative-assignment rule (LOOP, pre-ablation).** A capability present in
BOTH planes is assigned `authoritative="python"`: the Python plane is the one
carrying the safety gate, the mutating opt-in, the budget, and the evidence
ledger; the Java plane for the same capability has only Burp's `isInScope`.
Record the Java presence as `java_present=True` regardless -- "authoritative"
is about which plane's result should be trusted/preferred, not about deleting
or disabling the other plane's executor. A capability present in only ONE
plane is authoritative in that plane by construction (there is nothing to
prefer it over). **RB-7's owner-run A-F ablation may later revise these
assignments** with real evidence about which plane's execution is actually
better on a live target -- this matrix is the current-state contract, not a
final verdict, and nothing here deletes or disables either plane's executor.

Do NOT edit any Java file to "fix" a drift this module surfaces -- that is the
OWNER/JDK half of RB-6. This module changes no execution behavior in either
plane.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CapabilityOwnership:
    """One canonical capability's presence/ownership across the two planes.

    `python_name` is the `ValidatorRegistry`/`_val_by_conf` key that
    implements it (None if `python_present` is False). `java_names` is the
    tuple of literal `case "..."` label(s) in `ValidationExecutor.java`'s
    switch that implement it (empty if `java_present` is False; more than one
    entry when several Java case labels share one executor method, e.g.
    `cross_identity`'s `authorization_boundary_compare` /
    `cross_identity_compare`). `note` records the source evidence for the
    mapping, especially for pairs whose names differ between planes.
    """
    canonical: str
    python_present: bool
    java_present: bool
    authoritative: str  # "python" | "java"
    python_name: str | None = None
    java_names: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if self.authoritative not in ("python", "java"):
            raise ValueError(f"{self.canonical}: authoritative must be 'python' or 'java', got {self.authoritative!r}")
        if self.authoritative == "python" and not self.python_present:
            raise ValueError(f"{self.canonical}: authoritative='python' but python_present=False")
        if self.authoritative == "java" and not self.java_present:
            raise ValueError(f"{self.canonical}: authoritative='java' but java_present=False")
        if not self.python_present and not self.java_present:
            raise ValueError(f"{self.canonical}: present in neither plane")
        if self.python_present and not self.python_name:
            raise ValueError(f"{self.canonical}: python_present=True needs a python_name")
        if self.java_present and not self.java_names:
            raise ValueError(f"{self.canonical}: java_present=True needs at least one java_names entry")


def _dual(canonical: str, python_name: str, java_name: str, note: str = "", *, java_names: tuple[str, ...] = ()) -> CapabilityOwnership:
    """A capability present in both planes -- Python-authoritative per the rule above."""
    return CapabilityOwnership(
        canonical=canonical, python_present=True, java_present=True, authoritative="python",
        python_name=python_name, java_names=java_names or (java_name,), note=note,
    )


def _java_only(canonical: str, java_name: str, note: str = "") -> CapabilityOwnership:
    return CapabilityOwnership(
        canonical=canonical, python_present=False, java_present=True, authoritative="java",
        java_names=(java_name,), note=note,
    )


def _python_only(canonical: str, python_name: str, note: str = "") -> CapabilityOwnership:
    return CapabilityOwnership(
        canonical=canonical, python_present=True, java_present=False, authoritative="python",
        python_name=python_name, note=note,
    )


# ---------------------------------------------------------------------------
# Dual-plane capabilities (java_present=True, python_present=True).
# All Python-authoritative per the assignment rule above.
# ---------------------------------------------------------------------------
_DUAL: tuple[CapabilityOwnership, ...] = (
    _dual("cross_identity", "cross_identity",
          java_name="cross_identity_compare", java_names=("authorization_boundary_compare", "cross_identity_compare"),
          note="Java's identityCompare() serves both authorization_boundary_compare and "
               "cross_identity_compare from one switch arm; Python's cross_identity_validator "
               "(Autorize-style access-control leg) is the same check."),
    _dual("jwt", "jwt_forge", "jwt_validation",
          note="Java jwtForgery(); Python JwtForgeValidator -- alg:none / reused-sig forgery + replay."),
    _dual("xxe", "xxe", "xxe_validation",
          note="Both are the XXE out-of-band collaborator leg."),
    _dual("csrf", "csrf", "csrf_validation",
          note="Both replay a state-changing request without the CSRF token / check SameSite."),
    _dual("ssti", "ssti", "ssti_validation",
          note="Both are the server-side template-injection arithmetic differential."),
    _dual("command_injection", "command_injection", "command_injection_validation",
          note="Both are OS command-injection legs (Java: differential timing probe; "
               "Python: OOB collaborator). Same vulnerability class/capability slot."),
    _dual("open_redirect", "open_redirect", "open_redirect_validation",
          note="Both point a redirect-shaped parameter off-origin and check Location."),
    _dual("rate_limit", "rate_limit", "bounded_rate_limit_probe",
          note="Both replay the captured auth/action request N times and check for a "
               "missing 429/lockout."),
    _dual("file_upload", "file_upload", "file_upload_validation",
          note="Both upload a benign/EICAR probe file and check if it is stored+retrievable."),
    _dual("sql_injection", "sqlmap", "sql_injection_validation",
          note="Java sqlInjection() targets one request parameter directly; Python's "
               "'sqlmap' registry entry shells out to sqlmap. Same capability slot."),
    _dual("cors_misconfiguration", "cors", "cors_misconfiguration_detection",
          note="Both add a foreign Origin header and inspect ACAO/ACAC."),
    _dual("csp_clickjacking", "csp", "csp_clickjacking_validation",
          note="registry.py labels the Python entry '# CSP / Clickjacking validator' -- "
               "same pairing Java's case name encodes."),
    _dual("header_injection", "header_injection", "header_injection_validation"),
    _dual("api_security_mass_assignment", "api_security", "api_security_validation",
          note="Java method name is literally apiSecurityMassAssignment()."),
    _dual("http_request_smuggling", "http_request_smuggling", "http_request_smuggling_detection"),
    _dual("oauth_flow", "oauth", "oauth_flow_validation"),
    _dual("subdomain_takeover", "subdomain_takeover", "subdomain_takeover_detection"),
    _dual("web_cache_poisoning", "web_cache_poisoning", "web_cache_poisoning_detection"),
    _dual("websocket_cswsh", "websocket", "websocket_cswsh_validation"),
    _dual("crypto_transport", "crypto", "crypto_transport_validation",
          note="Python 'crypto' is the TLS/crypto-transport validator."),
    _dual("info_disclosure", "verbose_error", "info_disclosure_scan",
          note="Java infoDisclosureScan() is a passive scan of the captured response body "
               "(InfoDisclosureLogic, no sendRequest); Python 'verbose_error' is likewise "
               "passive (stack trace / debug info). Both are local-inspection only -- no "
               "SafetyGate concern either way, listed here because both route through the "
               "same per-plane capability-dispatch surface being reconciled."),
    _dual("race_condition", "race_condition", "race_condition_validation",
          note="Both fire N concurrent copies of the same request and count clean successes; "
               "same heuristic (status-code + no rejection-language marker) on both sides. "
               "Distinct from Python's 'toctou' (privilege-escalation re-read differential, "
               "Python-only -- see below)."),
    _dual("ssrf", "ssrf", "controlled_callback_probe",
          note="SsrfCallbackLogic.java's own docstring: 'Decision logic for the "
               "controlled_callback_probe capability (category: ssrf)' -- both are the "
               "blind-SSRF OOB-collaborator leg (redirect a URL-shaped param to a callback, "
               "watch for the hit)."),
    _dual("session_fixation", "auth_sequence", "session_fixation_compare",
          note="Python AuthSequenceValidator dispatches session_fixation as one of three "
               "classes (session_fixation / weak_password_policy / username_enumeration); "
               "Java has a dedicated sessionFixationCompare(). Only the session_fixation "
               "class overlaps -- see weak_password_policy/username_enumeration below "
               "(Python-only) and logout_invalidation below (Java-only)."),
    _dual("deserialization_format", "deserialization", "deserialization_format_confirmation",
          note="Both are the PASSIVE format-fingerprint scan (no live send on either side). "
               "Distinct from Python's 'deserialization_oob' (active pickle OOB beacon, "
               "Python-only -- see below)."),
)

# ---------------------------------------------------------------------------
# Java-only capabilities (no Python validator/confirmation leg implements them).
# ---------------------------------------------------------------------------
_JAVA_ONLY: tuple[CapabilityOwnership, ...] = (
    _java_only("xss_reflected_context", "reflection_context_validation",
               note="XssPayloadLogic.java: 'Payload selection + verdict logic for "
                    "reflection_context_validation (XSS)' -- canary-based, in-band, static "
                    "classification of a reflected parameter (no live script-execution proof). "
                    "JUDGMENT CALL: NOT merged into one canonical entry with Python's "
                    "'browser_xss' below, even though both ultimately target reflected-XSS-"
                    "shaped signals. browser_xss_validator.py's own docstring explicitly "
                    "contrasts itself against exactly this inferential "
                    "reflected-in-the-body-therefore-it-would-execute shape and requires a real "
                    "headless-browser execution sink instead -- the two are different oracles "
                    "for a related but not identical claim, not one duplicated check under two "
                    "names. Flagged for reviewer attention rather than silently conflated."),
    _java_only("workflow_replay_boundary", "workflow_replay_compare",
               note="WorkflowReplayLogic.java: 'Decision logic for the workflow_replay_compare "
                    "capability (category: business_logic)' -- numeric price/quantity/amount "
                    "boundary-value differential. Grounded absence on the Python side: "
                    "orchestrator_chain.py's investigate_engagement explicitly hands an "
                    "unconfirmed finding with no automated leg to state.flag_business_logic() "
                    "as a human-verification task instead of confirming it -- business logic "
                    "is a deliberate no-leg class in the Python plane today, not an oversight."),
    _java_only("logout_invalidation", "logout_invalidation_compare",
               note="auth_sequence_validator.py's docstring enumerates exactly three dispatched "
                    "classes (session_fixation, weak_password_policy, username_enumeration) and "
                    "explicitly does not include logout/session invalidation. No Python leg "
                    "confirms it, so this Java executor's live traffic for this capability is "
                    "the only one of the two planes reachable, and today runs with no Python "
                    "SafetyGate/evidence-ledger visibility at all -- worth owner attention "
                    "independent of the dual-plane drift concern RB-6 is about."),
    _java_only("nosql_injection", "nosql_validation",
               note="No harness/validators/*.py implements a NoSQL-injection leg; "
                    "harness/validators/registry.py has no 'nosql' entry."),
)

# ---------------------------------------------------------------------------
# Python-only capabilities (no Java case label implements them).
# ---------------------------------------------------------------------------
_PYTHON_ONLY: tuple[CapabilityOwnership, ...] = (
    _python_only("recon", "recon",
                 note="Active reconnaissance / attack-surface mapping; no Java equivalent."),
    _python_only("path_traversal", "path_traversal",
                 note="In-band canonical-file-read traversal leg; no Java case."),
    _python_only("mass_assignment_sequence", "sequence",
                 note="Write-then-independent-reread mass-assignment differential "
                      "(sequence_validator.py). Distinct from Java's workflow_replay_compare "
                      "(numeric boundary value, single-shot, business_logic category, "
                      "see workflow_replay_boundary above) -- not the same capability."),
    _python_only("toctou_privilege_race", "toctou",
                 note="Interleaved check-then-write privilege-escalation race with an "
                      "independent authority-field re-read (toctou_validator.py). Distinct "
                      "from the generic concurrent-burst 'race_condition' capability above, "
                      "which Java does implement -- toctou has no Java equivalent."),
    _python_only("stored_xss", "stored_xss",
                 note="Plant-via-write, confirm-on-independent-render second-order XSS; "
                      "no Java case."),
    _python_only("dom_xss", "dom_xss",
                 note="Client-side URL-fragment taint, confirmed via a real browser; payload "
                      "never reaches the server, so it is structurally outside Java's "
                      "server-request-response executor model."),
    _python_only("xss_browser_execution", "browser_xss",
                 note="Real headless-browser script-execution proof for reflected/generic XSS. "
                      "See xss_reflected_context above (Java-only) for why this is kept as its "
                      "own entry rather than merged with reflection_context_validation."),
    _python_only("verb_tamper", "verb_tamper",
                 note="HTTP-method access-control bypass (safe read-only-method subset); "
                      "no Java case."),
    _python_only("reset_token", "reset_token",
                 note="Predictable password/session reset-token sampling; no Java case."),
    _python_only("deserialization_oob", "deserialization_oob",
                 note="ACTIVE pickle OOB-beacon leg (proves code execution). Distinct from the "
                      "passive 'deserialization_format' capability above, which IS dual-plane."),
    _python_only("weak_password_policy", "auth_sequence",
                 note="One of AuthSequenceValidator's three dispatched classes; no Java case."),
    _python_only("username_enumeration", "auth_sequence",
                 note="One of AuthSequenceValidator's three dispatched classes; no Java case."),
)

CAPABILITY_MATRIX: dict[str, CapabilityOwnership] = {
    c.canonical: c for c in (*_DUAL, *_JAVA_ONLY, *_PYTHON_ONLY)
}

if len(CAPABILITY_MATRIX) != len(_DUAL) + len(_JAVA_ONLY) + len(_PYTHON_ONLY):
    raise AssertionError("execution_planes: duplicate canonical capability key in the matrix")


def python_capability_names() -> frozenset[str]:
    """Every ValidatorRegistry/_val_by_conf key the matrix accounts for."""
    return frozenset(c.python_name for c in CAPABILITY_MATRIX.values() if c.python_present)


def java_capability_names() -> frozenset[str]:
    """Every ValidationExecutor.java switch case label the matrix accounts for."""
    names: set[str] = set()
    for c in CAPABILITY_MATRIX.values():
        names.update(c.java_names)
    return frozenset(names)


def authoritative_plane(canonical: str) -> str:
    return CAPABILITY_MATRIX[canonical].authoritative


def dual_plane_capabilities() -> frozenset[str]:
    return frozenset(c.canonical for c in CAPABILITY_MATRIX.values()
                      if c.python_present and c.java_present)
