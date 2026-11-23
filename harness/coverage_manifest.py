"""
Requirement-coverage manifest -- security requirements ⇄ regression tests + evidence.

This is deliberately SEPARATE from `coverage_model.CoverageMatrix`:

- `CoverageMatrix` is the per-RUN outcome substrate (identity × endpoint × check
  cells filled by what a live engagement actually did on a target).
- This module is the per-REPO *requirement coverage* ledger: which requirements have
  an isolated regression test standing behind them, what that test's outcome was IN
  THE CURRENT RUN, and where its evidence lives.

Guiding rules (each one is a fix for a real hole the reviewer found):

- **A passing test proves only the aspect it exercises, never a whole requirement.**
  A requirement with a passing aspect is `covered_partial`; every other aspect
  (failed / skipped / missing / manual) stays visible as a residual gap, INCLUDING
  under a partially-covered requirement.
- **Evidence is bound to the current run.** Every artifact records a `run_id`; the
  gate only trusts artifacts whose `run_id` matches this run and lives in a
  run-specific directory. A stale passing artifact from a previous run can NOT
  satisfy a new run, and a failed/skipped execution overwrites the old verdict.
- **Outcomes come from the test runner, not the test body** (`coverage_evidence_case`):
  a fail or skip is recorded as such, so "the test did not run / did not pass" is
  never silently a pass.
- **Identity must match exactly.** Evidence with an empty or mismatched `test_id`,
  an unsupported schema, or a duplicate file for one aspect is rejected -- it never
  counts as covered.
- **Reproducible observations are separate from execution metadata.** The `observation`
  block (what the fixture showed) is reproducible; the `execution` block (status,
  run id, timestamp) is per-run.

Report vocabulary: pass / fail / skipped / manual / not_applicable, plus
`not_implemented` flagged SEPARATELY (a declared automated aspect with no fresh
evidence, or a requirement with no test at all).

What blocks `--check` (`declared_coverage_ok`, run after the unit tests of the smoke
and full tiers): every DECLARED automated aspect, of a requirement or a harness safety
property, must have fresh `pass` evidence. It blocks on

- `fail`: the test failed or errored, or its artifact was invalid, duplicated, or
  carried an empty or mismatched `test_id`;
- `skipped`: the test ran and was skipped;
- `not_implemented`: no fresh artifact for this run (the test did not run).

It does NOT block on `manual` aspects, `not_applicable` requirements, or
`gap_unimplemented` requirements. `gap_unimplemented` means "no test is registered in
this ledger"; it does not mean no test exists, and it never means the weakness was
verified absent. The requirement rollup (`covered_partial`, `gap_*`) is a report; the
gate checks each declared aspect on its own.
"""
from __future__ import annotations

import functools
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from harness.coverage_model import (
    CHECK_ID_SCHEME, CHECKS_BY_ID, CHECK_CATALOG, Check, UnknownCheckIdError,
    check_id_scheme_of, is_legacy_check_id, resolve_check_id,
)

SCHEMA_VERSION = 1
_HARNESS = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Run identity + run-specific evidence directory (freshness -- issue 2)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def current_run_id() -> str:
    """A stable identifier for THIS run/commit, shared by the test-writer process
    and the gate process. Prefers an explicit `COVERAGE_RUN_ID` (CI sets it to the
    commit sha), else the current git HEAD, else a clearly-marked local fallback.
    Cached so the writer and a same-process reader agree."""
    env = os.environ.get("COVERAGE_RUN_ID")
    if env:
        return env.strip()
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(_HARNESS),
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "local-unknown-run"


def run_evidence_dir(run_id: str | None = None) -> Path:
    """The run-specific evidence directory. An explicit `COVERAGE_EVIDENCE_DIR` wins
    (CI points both steps at one fresh path); otherwise a per-run subdir under
    `.coverage_runs/` (git-ignored). Keying by run id keeps runs from bleeding into
    each other without any shared mutable committed directory."""
    env = os.environ.get("COVERAGE_EVIDENCE_DIR")
    if env:
        return Path(env)
    return _HARNESS / ".coverage_runs" / (run_id or current_run_id())


# ---------------------------------------------------------------------------
# Reporting vocabulary
# ---------------------------------------------------------------------------

class TestStatus(str, Enum):
    """The outcome of ONE regression test (never the coverage of a requirement)."""
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    MANUAL = "manual"                 # verified/handled by a human, not automated
    NOT_APPLICABLE = "not_applicable"
    NOT_IMPLEMENTED = "not_implemented"  # no fresh evidence for a declared automated aspect

    @classmethod
    def coerce(cls, value) -> "TestStatus":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            # An unrecognized status is conservatively a FAIL, never a silent pass.
            return cls.FAIL


# A test outcome counts toward requirement coverage ONLY if it is a real pass.
_COVERING_STATUSES = frozenset({TestStatus.PASS})


class RequirementStatus(str, Enum):
    """The coverage rollup for a WHOLE requirement -- distinct from TestStatus."""
    COVERED_PARTIAL = "covered_partial"   # ≥1 aspect has fresh passing evidence (never "complete")
    GAP_FAILED = "gap_failed"             # a wired test is failing
    GAP_SKIPPED = "gap_skipped"           # a wired test is skipped / evidence missing
    GAP_MANUAL = "gap_manual"             # only manual verification is declared
    GAP_UNIMPLEMENTED = "gap_unimplemented"  # no wired test at all (missing implementation)
    NOT_APPLICABLE = "not_applicable"     # requirement declared N/A for the target, with rationale


# ---------------------------------------------------------------------------
# Static wiring: which regression test covers which requirement (and how)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TestSpec:
    """A repo-declared link from a requirement to a regression test.

    `aspect` names the SPECIFIC scenario the test exercises (so the report says "this
    aspect is covered", never "the requirement is covered"). `mode` is "automated" (a
    fresh evidence artifact is expected) or "manual" (a documented human step -- always
    a gap for automated coverage). `label` is the semantic kind of evidence
    (e.g. "fixture_invariant", "harness_confirmation") so a fixture self-test is never
    presented as application-wide or pipeline coverage (issue 5)."""
    check_id: str
    test_id: str            # "module.TestClass.test_method" (must match the runner's)
    aspect: str
    mode: str = "automated"       # "automated" | "manual"
    label: str = "automated"      # semantic evidence kind
    evidence_file: str = ""       # basename under the evidence dir (automated specs)

    def __post_init__(self):
        if self.check_id not in CHECKS_BY_ID and self.check_id not in SAFETY_PROPERTIES_BY_ID:
            raise ValueError(f"TestSpec references unknown check id {self.check_id!r}")
        if self.mode not in ("automated", "manual"):
            raise ValueError(f"TestSpec.mode must be 'automated' or 'manual', got {self.mode!r}")
        if self.mode == "automated" and not self.test_id:
            raise ValueError("an automated TestSpec must declare a non-empty test_id")


def _slug(text: str) -> str:
    """A filesystem-safe, deterministic slug for an aspect label."""
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s[:60] or "aspect"


def evidence_basename(check_id: str, aspect: str) -> str:
    """The deterministic evidence filename for a (requirement, aspect) pair."""
    return f"{check_id}__{_slug(aspect)}.json"


# ---- the mass-assignment vertical slice (WSTG-INJT-20; was internal AV-MASSASSIGN-01) ----
_MASS = "WSTG-INJT-20"
_ASPECT_INVARIANT = ("patched fixture leaves server-controlled fields unchanged under "
                     "an ordinary update (independent re-read)")
_ASPECT_CONFIRM = ("harness SequenceValidator confirms mass assignment on the vulnerable "
                   "fixture (write then independent re-read differential)")
_ASPECT_CONTROL = ("harness SequenceValidator returns a controlled negative on the "
                   "patched fixture")

# ---- the open-redirect vertical slice (WSTG-CLNT-04, Client-side URL Redirect) ----
# WSTG has no server-side open-redirect test; CLNT-04 is the closest current id. The
# v4.2-era binding to WSTG-INPV-17 was wrong (INPV-17 is Host header injection).
_OR = "WSTG-CLNT-04"
_ASPECT_OR_INVARIANT = ("patched login neutralises an off-origin next and never issues "
                        "an off-origin redirect")
_ASPECT_OR_CONFIRM = ("harness OpenRedirectValidator confirms open redirect on the "
                      "vulnerable fixture (off-origin Location)")
_ASPECT_OR_CONTROL = ("harness OpenRedirectValidator returns a controlled negative on the "
                      "patched fixture")

# ---- caller-level evidence for the deterministic confirmation legs (I11) ----
# Each row binds ONE existing caller/fixture test to ONE aspect: a confirmation on the
# vulnerable fixture or a controlled negative on the matching secure control. Every
# pair is real HTTP against an owned loopback fixture; no model. A test method carries
# exactly the (check_id, aspect, label) listed here via `@evidence_for(**caller_evidence(key))`,
# so the declaration and the decorator cannot drift apart. The aspect text names the
# scenario exercised; it never claims the whole requirement.
_LEG = "harness.test_leg_live_verification.LiveLegVerificationTest"
_AUTHZ = "harness.test_smoke_authorization_workflow.AuthorizationSliceSmokeTest"
_LOGOUT = "harness.test_auth_logout_invalidation.LogoutInvalidationCallerTests"
_UPLOAD = "harness.test_file_upload_busl08.FileUploadCallerTests"
_RACE = "harness.test_oracle_gaps_race.OracleGapRaceTests"
_NOSQL = "harness.test_oracle_gaps_nosql.OracleGapNosqlTests"
_CORS = "harness.test_cors_transport.CorsDecodedResponseTests"
_CONFIRM, _CONTROL = "harness_confirmation", "harness_control"

# key -> (check_id, test class, test method, label, aspect)
_CALLER_EVIDENCE: dict[str, tuple[str, str, str, str, str]] = {
    "idor_confirm": ("WSTG-ATHZ-04", _AUTHZ, "test_1_vulnerable_confirms_the_crossing", _CONFIRM,
                     "harness CrossIdentityValidator confirms object-level authorization failure "
                     "(a second principal reads the owner's private object over real HTTP)"),
    "idor_control": ("WSTG-ATHZ-04", _AUTHZ, "test_2_patched_does_not_confirm", _CONTROL,
                     "harness CrossIdentityValidator does not confirm on the patched fixture (the "
                     "second principal's attempt reached the target; verdict is inconclusive, never "
                     "confirmed)"),
    # The second-factor legs belong to WSTG-ATHN-11 (MFA); WG-2 added that row and
    # moved them off the authentication-bypass row (ATHN-04) where WG-1 parked them.
    "mfa_confirm": ("WSTG-ATHN-11", _LEG, "test_auth_2fa_bypass_confirms", _CONFIRM,
                    "harness AuthSequenceValidator confirms a second-factor bypass (a step-1-only "
                    "session reaches the account page that a tokenless request is denied)"),
    "mfa_control": ("WSTG-ATHN-11", _LEG, "test_auth_2fa_bypass_silent_on_enforcing_control", _CONTROL,
                    "harness AuthSequenceValidator returns a controlled negative where the account "
                    "page enforces the second factor"),
    "weakpw_confirm": ("WSTG-ATHN-07", _LEG, "test_auth_weak_password_confirms", _CONFIRM,
                       "harness AuthSequenceValidator confirms an unrestricted password policy "
                       "(a weak password is accepted at registration)"),
    "weakpw_control": ("WSTG-ATHN-07", _LEG, "test_auth_weak_password_silent_on_policy_control", _CONTROL,
                       "harness AuthSequenceValidator returns a controlled negative where the "
                       "registration policy rejects the weak password"),
    "fixation_confirm": ("WSTG-SESS-03", _LEG, "test_auth_session_fixation_confirms", _CONFIRM,
                         "harness AuthSequenceValidator confirms session fixation (the login "
                         "succeeds, the pre-auth session id is not rotated and is then "
                         "authenticated, and the anonymous control is a healthy denial)"),
    "fixation_control": ("WSTG-SESS-03", _LEG, "test_auth_session_fixation_silent_on_rotating_control",
                         _CONTROL,
                         "harness AuthSequenceValidator returns a controlled negative where the "
                         "session token rotates at login"),
    # WG-3: the logout-invalidation leg's caller-level confirm and control.
    "logout_confirm": ("WSTG-SESS-06", _LOGOUT, "test_client_side_only_logout_confirms", _CONFIRM,
                       "harness AuthSequenceValidator confirms missing logout invalidation (a "
                       "fresh throwaway session reaches the account page, is logged out, and its "
                       "pre-logout cookie still reaches the page; the operator is never logged out)"),
    "logout_control": ("WSTG-SESS-06", _LOGOUT, "test_server_side_invalidation_is_not_confirmed",
                       _CONTROL,
                       "harness AuthSequenceValidator returns a controlled negative where logout "
                       "invalidates the session server-side"),
    # WG-2: the benign disallowed-extension upload leg (WSTG-BUSL-08).
    "upload_confirm": ("WSTG-BUSL-08", _UPLOAD, "test_disallowed_html_upload_served_confirms",
                       _CONFIRM,
                       "harness FileUploadValidator confirms an unexpected file type upload (a "
                       "benign .html file is stored and served back as text/html)"),
    "upload_control": ("WSTG-BUSL-08", _UPLOAD, "test_rejected_disallowed_type_is_not_confirmed",
                       _CONTROL,
                       "harness FileUploadValidator returns a controlled negative where the "
                       "server rejects the disallowed file type"),
    "stored_xss_confirm": ("WSTG-INJT-02", _LEG, "test_stored_xss_confirms_on_raw_render", _CONFIRM,
                           "harness StoredXssValidator confirms stored XSS (plant, then the "
                           "payload executes on an independent render, logging a value computed "
                           "at run time to the console; a raw render alone is a candidate)"),
    "stored_xss_control": ("WSTG-INJT-02", _LEG, "test_stored_xss_silent_on_escaped_render_control",
                           _CONTROL,
                           "harness StoredXssValidator returns a controlled negative where the "
                           "stored value renders escaped"),
    "stored_xss_form_confirm": ("WSTG-INJT-02", _LEG, "test_stored_xss_confirms_through_csrf_bound_form",
                                _CONFIRM,
                                "harness StoredXssValidator confirms stored XSS through a CSRF-token "
                                "bound comment form (token refreshed in-session)"),
    "stored_xss_form_control": ("WSTG-INJT-02", _LEG,
                                "test_stored_xss_silent_on_escaped_csrf_bound_form_control", _CONTROL,
                                "harness StoredXssValidator returns a controlled negative through a "
                                "CSRF-token bound comment form that renders escaped"),
    "cmdi_confirm": ("WSTG-INJT-12", _LEG, "test_command_injection_confirms_via_shell", _CONFIRM,
                     "harness CommandInjectionValidator confirms command injection (shell fetch "
                     "reaches the out-of-band collaborator)"),
    "cmdi_control": ("WSTG-INJT-12", _LEG, "test_command_injection_silent_on_no_shell_control", _CONTROL,
                     "harness CommandInjectionValidator returns a controlled negative where the "
                     "parameter never reaches a shell"),
    "ssti_confirm": ("WSTG-INJT-18", _LEG, "test_ssti_confirms_on_real_template_render", _CONFIRM,
                     "harness SstiValidator confirms server-side template injection (the "
                     "expression is evaluated by a real Jinja render)"),
    "ssti_control": ("WSTG-INJT-18", _LEG, "test_ssti_silent_on_escaped_echo_control", _CONTROL,
                     "harness SstiValidator returns a controlled negative where the probe is "
                     "only echoed escaped"),
    "xxe_confirm": ("WSTG-INJT-07", _LEG, "test_xxe_confirms_on_entity_resolving_parser", _CONFIRM,
                    "harness XxeValidator confirms XXE (a SYSTEM entity in an XML POST is "
                    "fetched server-side, seen by the out-of-band collaborator)"),
    "xxe_control": ("WSTG-INJT-07", _LEG, "test_xxe_silent_on_non_resolving_parser_control", _CONTROL,
                    "harness XxeValidator returns a controlled negative where the XML parser "
                    "never resolves external entities"),
    "ssrf_confirm": ("WSTG-INJT-19", _LEG, "test_ssrf_confirms_on_real_server_side_fetch", _CONFIRM,
                     "harness SsrfValidator confirms SSRF (the server fetches the supplied URL, "
                     "seen by the out-of-band collaborator)"),
    "ssrf_control": ("WSTG-INJT-19", _LEG, "test_ssrf_silent_on_no_fetch_control", _CONTROL,
                     "harness SsrfValidator returns a controlled negative where the URL "
                     "parameter is never fetched"),
    "jwt_kid_confirm": ("WSTG-SESS-10", _LEG, "test_jwt_kid_confusion_confirms", _CONFIRM,
                        "harness JwtForgeValidator confirms kid key-confusion (a token HS256-signed "
                        "with the key its attacker-chosen kid implies is accepted)"),
    "jwt_kid_control": ("WSTG-SESS-10", _LEG, "test_jwt_kid_silent_on_fixed_secret_control", _CONTROL,
                        "harness JwtForgeValidator returns a controlled negative where the "
                        "verification key is fixed server-side"),
    "jwt_unverified_confirm": ("WSTG-SESS-10", _LEG, "test_jwt_unverified_signature_confirms",
                               _CONFIRM,
                               "harness JwtForgeValidator confirms an unverified JWT signature (an "
                               "invalid-signature token is accepted where a tokenless request is denied)"),
    "jwt_unverified_control": ("WSTG-SESS-10", _LEG,
                               "test_jwt_unverified_silent_on_public_endpoint_control", _CONTROL,
                               "harness JwtForgeValidator claims no signature bug on a public endpoint "
                               "the token does not gate (probed, then declined with that reason)"),
    "deser_confirm": ("WSTG-INJT-23", _LEG, "test_deserialization_oob_confirms_on_pickle_sink", _CONFIRM,
                      "harness DeserializationOobValidator confirms unsafe deserialization (a "
                      "pickle payload reaches the out-of-band collaborator)"),
    "deser_control": ("WSTG-INJT-23", _LEG, "test_deserialization_oob_silent_on_json_control", _CONTROL,
                      "harness DeserializationOobValidator returns a controlled negative where "
                      "the cookie is parsed as JSON"),
    # GAP-2: live loopback legs that existed but were not registered in this ledger.
    "enum_confirm": ("WSTG-IDNT-04", _LEG, "test_auth_username_enum_confirms", _CONFIRM,
                     "harness AuthSequenceValidator confirms username enumeration (the login "
                     "response for a known username differs from an unknown one)"),
    "enum_control": ("WSTG-IDNT-04", _LEG, "test_auth_username_enum_silent_on_uniform_control",
                     _CONTROL,
                     "harness AuthSequenceValidator returns a controlled negative where the "
                     "login response is uniform for known and unknown usernames"),
    "client_trust_confirm": ("WSTG-BUSL-02", _LEG, "test_client_trust_confirms_reflected_price",
                             _CONFIRM,
                             "harness ClientTrustValidator confirms a client-supplied price is "
                             "trusted (the tampered price is reflected back by the cart)"),
    "client_trust_control": ("WSTG-BUSL-02", _LEG, "test_client_trust_silent_on_server_priced_control",
                             _CONTROL,
                             "harness ClientTrustValidator returns a controlled negative where "
                             "the server prices the item itself"),
    "race_confirm": ("WSTG-BUSL-05", _RACE,
                     "test_once_only_like_raced_past_its_check_confirms_by_read_back", _CONFIRM,
                     "harness RaceConditionValidator confirms a once-only operation raced past "
                     "its check (a concurrent burst records the effect several times, a "
                     "sequential repeat is refused, and a read-back shows the duplicates)"),
    "race_control": ("WSTG-BUSL-05", _RACE, "test_control_operation_holding_its_limit_is_a_negative",
                     _CONTROL,
                     "harness RaceConditionValidator returns a controlled negative where the "
                     "operation holds its limit under the concurrent burst"),
    "nosql_confirm": ("WSTG-INJT-05.6", _NOSQL, "test_quoted_where_on_a_string_path_id_is_confirmed",
                      _CONFIRM,
                      "harness NosqlValidator confirms NoSQL injection through a single-quoted "
                      "$where on a string path id (true and false probes split the response)"),
    "nosql_control": ("WSTG-INJT-05.6", _NOSQL, "test_control_plain_string_route_is_a_negative",
                      _CONTROL,
                      "harness NosqlValidator returns a controlled negative where the path id "
                      "is matched as a plain string"),
    "cors_confirm": ("WSTG-CLNT-07", _CORS, "test_compressed_and_plain_grants_agree", _CONFIRM,
                     "harness CorsValidator confirms a credentialed CORS grant to a reflected "
                     "foreign origin (plain, gzip and br responses agree)"),
    "cors_control": ("WSTG-CLNT-07", _CORS, "test_compressed_and_plain_secure_controls_agree",
                     _CONTROL,
                     "harness CorsValidator reports safe where the server grants no foreign "
                     "origin (plain, gzip and br responses agree)"),
}


# ---- harness safety properties (GAP-4): NOT security requirements of the target ----
#
# These are properties of the harness's OWN transport and cleanup, proven over loopback
# sockets by `harness.test_live_safety_loopback`. They are not WSTG checks and are not
# catalog rows: they never appear under `requirements`, never change the requirement
# counts, and are reported in their own `safety_properties` section. The declared
# coverage gate holds their automated aspects to the same fresh-pass rule.

@dataclass(frozen=True)
class SafetyProperty:
    id: str           # "HS-*": harness safety, never a WSTG id
    name: str
    description: str


SAFETY_PROPERTIES: tuple[SafetyProperty, ...] = (
    SafetyProperty("HS-PIN-01", "DNS-rebinding address pin",
                   "every target send connects to the address the name resolved to when it "
                   "was checked; a special-purpose answer is refused before any connect"),
    SafetyProperty("HS-HOST-01", "Caller-set Host is not sent",
                   "a Host header from a caller or the agent never reaches the target; the "
                   "URL authority is sent"),
    SafetyProperty("HS-PROXY-01", "Environment proxies are ignored",
                   "target sends never go through an HTTP(S)_PROXY / ALL_PROXY from the "
                   "environment, and the address pin still holds"),
    SafetyProperty("HS-REDIR-01", "Redirect hops are re-checked",
                   "each redirect hop is re-checked against scope and the gate before it is "
                   "followed"),
    SafetyProperty("HS-CLEAN-01", "Cleanup after a mutating leg",
                   "a mutating leg that raises, is cancelled or fails its undo still sends its "
                   "cleanup, and the write is marked restored or restore_failed"),
)
SAFETY_PROPERTIES_BY_ID: dict[str, SafetyProperty] = {p.id: p for p in SAFETY_PROPERTIES}

_LOOP = "harness.test_live_safety_loopback"
_SAFETY = "harness_safety"

# key -> (property id, test class, test method, label, aspect); same shape as above.
_SAFETY_EVIDENCE: dict[str, tuple[str, str, str, str, str]] = {
    "safety_pin_rebinding": (
        "HS-PIN-01", f"{_LOOP}.DnsRebindingPinTests",
        "test_rebound_name_is_sent_to_its_pinned_address", _SAFETY,
        "rebound name: sends and a redirect hop reach only the address pinned at check "
        "time (127.0.0.1), never the rebound 127.0.0.2"),
    "safety_pin_special_purpose": (
        "HS-PIN-01", f"{_LOOP}.DnsRebindingPinTests",
        "test_special_purpose_first_answer_is_refused_before_connect", _SAFETY,
        "special-purpose first answer (169.254.169.254) is refused as destination_blocked "
        "before any connect"),
    "safety_host_header": (
        "HS-HOST-01", f"{_LOOP}.CallerHostHeaderTests",
        "test_caller_set_host_is_stripped_before_the_send", _SAFETY,
        "caller-set Host (any case or padding) on send and send_creds is stripped; the "
        "server sees the URL authority"),
    "safety_host_agent": (
        "HS-HOST-01", f"{_LOOP}.CallerHostHeaderTests",
        "test_agent_set_header_host_is_refused_with_zero_sends", _SAFETY,
        "agent set_header Host is refused with zero sends; an allowed header from the same "
        "agent is sent"),
    "safety_env_proxy": (
        "HS-PROXY-01", f"{_LOOP}.EnvironmentProxyTests",
        "test_target_sends_bypass_environment_proxies_and_keep_pins", _SAFETY,
        "with env proxies set, default, session and GatedAsyncClient sends reach the target "
        "directly and the pin holds"),
    "safety_redirect_recheck": (
        "HS-REDIR-01", f"{_LOOP}.RedirectRecheckTests",
        "test_redirect_to_out_of_scope_host_is_not_followed", _SAFETY,
        "302 to an out-of-scope host or metadata address is not followed; a same-origin 302 "
        "is"),
    "safety_cleanup_on_error": (
        "HS-CLEAN-01", f"{_LOOP}.MutatingCleanupTests",
        "test_cleanup_runs_when_the_leg_raises_part_way", _SAFETY,
        "workflow leg raising after its create still sends the DELETE; the write is marked "
        "restored"),
    "safety_cleanup_on_cancel": (
        "HS-CLEAN-01", f"{_LOOP}.MutatingCleanupTests",
        "test_cleanup_runs_after_cancellation", _SAFETY,
        "cancelled workflow leg still sends its cleanup; the write is marked restored"),
    "safety_cleanup_owed": (
        "HS-CLEAN-01", f"{_LOOP}.MutatingCleanupTests",
        "test_failed_cleanup_is_recorded_as_owed", _SAFETY,
        "failed cleanup (DELETE answers 500) is recorded as restore_failed at level error"),
    "safety_cleanup_write_integrity": (
        "HS-CLEAN-01", f"{_LOOP}.WriteIntegrityCleanupTests",
        "test_write_integrity_leg_raising_part_way_deletes_its_creates", _SAFETY,
        "write-integrity leg raising after an attack create deletes every create and marks "
        "each restored"),
}


def caller_evidence(key: str) -> dict:
    """The `@evidence_for` keyword arguments for one declared caller-evidence row
    (a requirement row or a harness safety-property row)."""
    check_id, _cls, _method, label, aspect = (_CALLER_EVIDENCE.get(key)
                                              or _SAFETY_EVIDENCE[key])
    return {"check_id": check_id, "aspect": aspect, "label": label}


def _caller_specs(table: dict | None = None) -> tuple[TestSpec, ...]:
    return tuple(
        TestSpec(check_id, f"{cls}.{method}", aspect, mode="automated", label=label,
                 evidence_file=evidence_basename(check_id, aspect))
        for check_id, cls, method, label, aspect in
        (_CALLER_EVIDENCE if table is None else table).values())


# The harness safety-property specs; kept OUT of REQUIREMENT_TESTS (which lists only
# catalog requirements).
SAFETY_TESTS: tuple[TestSpec, ...] = _caller_specs(_SAFETY_EVIDENCE)


REQUIREMENT_TESTS: tuple[TestSpec, ...] = (
    TestSpec(_MASS,
             "harness.test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_patched_upholds_protected_field_invariant",
             _ASPECT_INVARIANT, mode="automated", label="fixture_invariant",
             evidence_file=evidence_basename(_MASS, _ASPECT_INVARIANT)),
    TestSpec(_MASS,
             "harness.test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_harness_sequence_validator_confirms_vulnerable",
             _ASPECT_CONFIRM, mode="automated", label="harness_confirmation",
             evidence_file=evidence_basename(_MASS, _ASPECT_CONFIRM)),
    TestSpec(_MASS,
             "harness.test_mass_assignment_slice.MassAssignmentSliceTest."
             "test_harness_sequence_validator_controlled_negative_on_patched",
             _ASPECT_CONTROL, mode="automated", label="harness_control",
             evidence_file=evidence_basename(_MASS, _ASPECT_CONTROL)),

    # open redirect (WSTG-CLNT-04)
    TestSpec(_OR,
             "harness.test_open_redirect_slice.OpenRedirectSliceTest."
             "test_patched_neutralises_off_origin_redirect",
             _ASPECT_OR_INVARIANT, mode="automated", label="fixture_invariant",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_INVARIANT)),
    TestSpec(_OR,
             "harness.test_open_redirect_slice.OpenRedirectSliceTest."
             "test_harness_validator_confirms_vulnerable",
             _ASPECT_OR_CONFIRM, mode="automated", label="harness_confirmation",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_CONFIRM)),
    TestSpec(_OR,
             "harness.test_open_redirect_slice.OpenRedirectSliceTest."
             "test_harness_validator_controlled_negative_on_patched",
             _ASPECT_OR_CONTROL, mode="automated", label="harness_control",
             evidence_file=evidence_basename(_OR, _ASPECT_OR_CONTROL)),

    # deterministic confirmation legs over real HTTP (I11): confirmation + control pairs
    *_caller_specs(),

    # Manual checks: genuinely need a human / host access, so they are declared MANUAL
    # (a flagged gap, never automated coverage) rather than left as silent
    # "unimplemented". The CSRF leg's verdict is retired to an observation
    # (ORACLE_RETIREMENTS.md), so its confirmation stays a manual browser PoC even
    # though the catalog row now names the csrf leg (WG-2); malicious-file upload
    # (BUSL-09) is manual; file-permission needs host access.
    TestSpec("WSTG-CONF-09", "", "server files/directories are least-privilege "
             "(host-level review)", mode="manual", label="manual"),
    TestSpec("WSTG-SESS-05", "", "state-changing requests carry anti-CSRF protection "
             "(manual PoC / analyst review)", mode="manual", label="manual"),
    TestSpec("WSTG-BUSL-09", "", "upload endpoints validate type/size/content "
             "(manual review)", mode="manual", label="manual"),
)

# Public aliases the slice test modules reference at decoration time, so each test's
# @evidence_for aspects stay in lock-step with the declared specs above.
MASS_ASSIGNMENT_CHECK_ID = _MASS
ASPECT_MASS_INVARIANT = _ASPECT_INVARIANT
ASPECT_MASS_CONFIRM = _ASPECT_CONFIRM
ASPECT_MASS_CONTROL = _ASPECT_CONTROL
OPEN_REDIRECT_CHECK_ID = _OR
ASPECT_OR_INVARIANT = _ASPECT_OR_INVARIANT
ASPECT_OR_CONFIRM = _ASPECT_OR_CONFIRM
ASPECT_OR_CONTROL = _ASPECT_OR_CONTROL


# ---------------------------------------------------------------------------
# Applicability declarations (issue 6): explicit, with rationale
# ---------------------------------------------------------------------------

# check_id -> (applicable, rationale). Absent means "applicable by default". A
# declaration here is the honest, auditable place to record a scope-based exclusion
# (e.g. "no XML endpoints in scope"); it is intentionally empty in the shipped repo
# so we never fabricate a scope claim -- the mechanism is exercised by the tests.
REQUIREMENT_APPLICABILITY: dict[str, tuple[bool, str]] = {}


def applicability_of(check_id: str,
                     table: dict[str, tuple[bool, str]] | None = None) -> tuple[bool, str]:
    table = REQUIREMENT_APPLICABILITY if table is None else table
    if check_id in table:
        return table[check_id]
    return (True, "applicable by default; no scope-based exclusion declared")


# ---------------------------------------------------------------------------
# Evidence artifacts (reproducible observation vs per-run execution -- issue 2)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    check_id: str
    aspect: str
    status: TestStatus
    kind: str = "automated"
    invariant: str = ""
    observation: dict = field(default_factory=dict)   # reproducible
    # execution metadata (per-run):
    test_id: str = ""
    run_id: str = ""
    recorded_at: str = ""
    reason: str = ""
    schema_version: int = SCHEMA_VERSION
    # WG-2: the check-id scheme `check_id` uses; None = unmarked (scheme 1, pre-WG-1).
    # Additive and optional, so SCHEMA_VERSION is unchanged and older records stay valid.
    check_id_scheme: int | None = None
    # runtime-only:
    path: str = ""
    conflict: bool = False
    invalid_reason: str = ""

    def to_dict(self) -> dict:
        out = {
            "schema_version": self.schema_version,
            "check_id": self.check_id,
            "aspect": self.aspect,
            "kind": self.kind,
            "invariant": self.invariant,
            "observation": self.observation,
            "execution": {
                "test_id": self.test_id,
                "status": self.status.value,
                "run_id": self.run_id,
                "recorded_at": self.recorded_at,
                "reason": self.reason,
            },
        }
        if self.check_id_scheme is not None:
            out["check_id_scheme"] = self.check_id_scheme
        return out

    @classmethod
    def from_dict(cls, d: dict, *, path: str = "") -> "EvidenceRecord":
        ex = d.get("execution") or {}
        return cls(
            check_id=str(d.get("check_id", "")),
            aspect=str(d.get("aspect", "")),
            status=TestStatus.coerce(ex.get("status", "")),
            kind=str(d.get("kind", "automated")),
            invariant=str(d.get("invariant", "")),
            observation=d.get("observation") or {},
            test_id=str(ex.get("test_id", "")),
            run_id=str(ex.get("run_id", "")),
            recorded_at=str(ex.get("recorded_at", "")),
            reason=str(ex.get("reason", "")),
            schema_version=d.get("schema_version"),
            check_id_scheme=d.get("check_id_scheme"),
            path=path,
        )


def write_evidence(*, check_id: str, aspect: str, status, test_id: str,
                   kind: str = "automated", invariant: str = "", reason: str = "",
                   observation: dict | None = None, run_id: str | None = None,
                   recorded_at: str | None = None,
                   evidence_dir: Path | str | None = None) -> Path:
    """Write a regression test's evidence artifact for the CURRENT run and return its
    path. The observation block is reproducible; the execution block binds the record
    to `run_id` (defaults to the current run) with a timestamp. Writes into the
    run-specific dir by default."""
    # WG-1: a legacy (pre-WG-1) id is written under its current id; anything else
    # is refused.
    if check_id not in SAFETY_PROPERTIES_BY_ID:
        try:
            check_id = resolve_check_id(check_id)
        except UnknownCheckIdError:
            raise ValueError(f"evidence references unknown check id {check_id!r}") from None
    st = status if isinstance(status, TestStatus) else TestStatus.coerce(status)
    rid = run_id or current_run_id()
    rec = EvidenceRecord(
        check_id=check_id, aspect=aspect, status=st, kind=kind, invariant=invariant,
        observation=observation or {}, test_id=test_id, run_id=rid,
        recorded_at=recorded_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        reason=reason, check_id_scheme=CHECK_ID_SCHEME)
    d = Path(evidence_dir) if evidence_dir is not None else run_evidence_dir(rid)
    d.mkdir(parents=True, exist_ok=True)
    path = d / evidence_basename(check_id, aspect)
    path.write_text(json.dumps(rec.to_dict(), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def load_evidence(evidence_dir: Path | str | None = None, *,
                  run_id: str | None = None) -> dict[tuple[str, str], EvidenceRecord]:
    """Load evidence artifacts, keyed by (check_id, aspect), enforcing:

    - **freshness**: when `run_id` is given, artifacts from a DIFFERENT run are
      ignored entirely (a stale pass can never satisfy the gate -- issue 2);
    - **schema validation**: a wrong/absent `schema_version` is surfaced as an
      invalid FAIL record, never a pass (issue 3);
    - **no duplicates**: two artifacts for one aspect become a conflict FAIL rather
      than letting the last file silently win (issue 3).
    """
    d = Path(evidence_dir) if evidence_dir is not None else run_evidence_dir(run_id)
    buckets: dict[tuple[str, str], list[EvidenceRecord]] = {}
    if not d.is_dir():
        return {}
    for p in sorted(d.glob("*.json")):
        try:
            body = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(body, dict) or not body.get("check_id") or body.get("aspect") is None:
            continue
        rel = p.relative_to(d.parent) if d.parent in p.parents else p
        rec = EvidenceRecord.from_dict(body, path=rel.as_posix())
        # WG-1: an artifact written under a legacy id counts for its current id. An
        # unknown id stays as written, so it matches no requirement. Each record is
        # read under its own `check_id_scheme` (absent = 1): an unmarked BUSL-08
        # record is pre-WG-1 TOCTOU evidence and counts for ATHZ-03.
        try:
            scheme = check_id_scheme_of(rec.check_id_scheme)
        except ValueError:
            scheme = None
        if scheme is not None and is_legacy_check_id(rec.check_id, scheme):
            rec.check_id = resolve_check_id(rec.check_id, scheme=scheme)
        # Freshness FIRST: a record from another run is not part of this run at all.
        if run_id is not None and rec.run_id != run_id:
            continue
        # Schema validation (on records that survived freshness).
        if rec.schema_version != SCHEMA_VERSION:
            rec.conflict = True
            rec.status = TestStatus.FAIL
            rec.invalid_reason = f"unsupported schema_version {rec.schema_version!r} (expected {SCHEMA_VERSION})"
        elif scheme is None:
            rec.conflict = True
            rec.status = TestStatus.FAIL
            rec.invalid_reason = f"unsupported check_id_scheme {rec.check_id_scheme!r}"
        buckets.setdefault((rec.check_id, rec.aspect), []).append(rec)

    out: dict[tuple[str, str], EvidenceRecord] = {}
    for key, recs in buckets.items():
        if len(recs) == 1:
            out[key] = recs[0]
        else:
            conflict = EvidenceRecord(
                check_id=key[0], aspect=key[1], status=TestStatus.FAIL, conflict=True,
                invalid_reason=f"{len(recs)} duplicate evidence artifacts for this aspect "
                               f"({', '.join(sorted(r.path for r in recs))}) -- refusing to let one win",
                path=";".join(sorted(r.path for r in recs)))
            out[key] = conflict
    return out


# ---------------------------------------------------------------------------
# Reconciliation: specs + evidence -> requirement coverage report
# ---------------------------------------------------------------------------

def _resolve_spec(spec: TestSpec, evidence: dict) -> dict:
    """Resolve one TestSpec to a concrete TEST outcome, reading its evidence artifact.
    Requires an EXACT, non-empty identity match (issue 3) and rejects conflicts."""
    base = {"test_id": spec.test_id, "aspect": spec.aspect, "mode": spec.mode,
            "label": spec.label}
    if spec.mode == "manual":
        return {**base, "status": TestStatus.MANUAL, "evidence_path": None,
                "reason": "manual verification step -- no automated regression evidence"}
    rec = evidence.get((spec.check_id, spec.aspect))
    if rec is None:
        return {**base, "status": TestStatus.NOT_IMPLEMENTED, "evidence_path": None,
                "reason": "no fresh evidence artifact for this run -- the regression test "
                          "did not execute and pass in this run (never counted as covered)"}
    if rec.conflict:
        return {**base, "status": TestStatus.FAIL, "evidence_path": rec.path,
                "reason": rec.invalid_reason or "invalid/duplicate evidence artifact"}
    # Exact, NON-EMPTY identity match required -- an empty or mismatched test_id fails.
    if not rec.test_id or rec.test_id != spec.test_id:
        return {**base, "status": TestStatus.FAIL, "evidence_path": rec.path,
                "reason": f"evidence test_id {rec.test_id!r} does not exactly match declared "
                          f"{spec.test_id!r} (empty or mismatched identity)"}
    return {**base, "status": rec.status, "evidence_path": rec.path,
            "reason": rec.reason or f"evidence status={rec.status.value}"}


def _status_of(resolved: list[dict], applicable: bool = True) -> RequirementStatus:
    """The rollup verdict for one requirement (or safety property) from its resolved
    aspects. See the module docstring for which of these the gate blocks on."""
    if not applicable:
        return RequirementStatus.NOT_APPLICABLE
    if not resolved:
        return RequirementStatus.GAP_UNIMPLEMENTED
    if any(r["status"] in _COVERING_STATUSES for r in resolved):
        return RequirementStatus.COVERED_PARTIAL  # a pass covers only its aspect
    if any(r["status"] == TestStatus.FAIL for r in resolved):
        return RequirementStatus.GAP_FAILED
    if any(r["status"] in (TestStatus.SKIPPED, TestStatus.NOT_IMPLEMENTED) for r in resolved):
        return RequirementStatus.GAP_SKIPPED
    if all(r["status"] == TestStatus.MANUAL for r in resolved):
        return RequirementStatus.GAP_MANUAL
    return RequirementStatus.GAP_SKIPPED


def _residual(resolved: list[dict]) -> list[dict]:
    # Residual gaps: every resolved aspect that did NOT contribute passing evidence --
    # retained EVEN when the requirement is partially covered (issue 6).
    return [{"aspect": r["aspect"], "label": r["label"], "status": r["status"].value,
             "reason": r["reason"]}
            for r in resolved if r["status"] not in _COVERING_STATUSES]


def _test_rows(resolved: list[dict]) -> list[dict]:
    return [{"test_id": r["test_id"], "aspect": r["aspect"], "mode": r["mode"],
             "label": r["label"], "status": r["status"].value,
             "evidence_path": r["evidence_path"], "reason": r["reason"]}
            for r in resolved]


def _rollup(check: Check, resolved: list[dict], applicable: bool, rationale: str) -> dict:
    """Roll resolved specs up into a single requirement-coverage verdict."""
    covered_aspects = [r["aspect"] for r in resolved if r["status"] in _COVERING_STATUSES]
    residual = _residual(resolved)

    status = _status_of(resolved, applicable)
    note = ""
    if status == RequirementStatus.COVERED_PARTIAL:
        note = ("partial coverage: the passing aspect(s) are verified; other scenarios of "
                "this requirement are not exercised yet (see residual_gaps)")

    return {
        "check_id": check.id,
        "name": check.name,
        "ref": check.reference_label(),
        "is_wstg": check.is_wstg(),
        "wstg_version": check.wstg_version if check.is_wstg() else "",
        "phase": check.phase.value,
        "confirmation": check.confirmation,
        "external_refs": [{"catalog": e.catalog, "ref": e.ref, "url": e.url, "title": e.title}
                          for e in check.external_refs],
        "applicability": {"applicable": applicable, "rationale": rationale},
        "requirement_status": status.value,
        "covered_aspects": covered_aspects,
        "residual_gaps": residual,
        "note": note,
        "tests": _test_rows(resolved),
    }


def _rollup_property(prop: SafetyProperty, resolved: list[dict]) -> dict:
    """A harness safety property's verdict, in the same per-aspect shape as a
    requirement but marked `kind: harness_safety_property` (never WSTG)."""
    return {
        "check_id": prop.id,
        "name": prop.name,
        "description": prop.description,
        "kind": "harness_safety_property",
        "is_wstg": False,
        "requirement_status": _status_of(resolved).value,
        "covered_aspects": [r["aspect"] for r in resolved if r["status"] in _COVERING_STATUSES],
        "residual_gaps": _residual(resolved),
        "tests": _test_rows(resolved),
    }


def _is_gap(req: dict) -> bool:
    """A requirement belongs in the top-level gaps list if it is not N/A and has any
    unresolved aspect -- INCLUDING a partially-covered requirement with a failing or
    missing sibling aspect (issue 6)."""
    if req["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value:
        return False
    if req["requirement_status"] == RequirementStatus.COVERED_PARTIAL.value:
        return bool(req["residual_gaps"])
    return True


def reconcile(specs: tuple[TestSpec, ...] = REQUIREMENT_TESTS, *,
              evidence_dir: Path | str | None = None, run_id: str | None = None,
              checks: tuple[Check, ...] = CHECK_CATALOG,
              applicability: dict[str, tuple[bool, str]] | None = None,
              safety_specs: tuple[TestSpec, ...] | None = None,
              properties: tuple[SafetyProperty, ...] = SAFETY_PROPERTIES) -> dict:
    """Reconcile declared specs + this run's evidence into a requirement-coverage
    report over the whole catalog, plus the harness safety properties in their own
    `safety_properties` list (never mixed into the requirement totals). `run_id`
    defaults to the current run (so only fresh evidence counts); pass an explicit
    one in tests. `safety_specs` defaults to the declared SAFETY_TESTS only when
    `specs` is the declared REQUIREMENT_TESTS; a caller passing its own `specs`
    reconciles exactly those unless it also passes `safety_specs`."""
    if safety_specs is None:
        safety_specs = SAFETY_TESTS if specs is REQUIREMENT_TESTS else ()
    rid = run_id if run_id is not None else current_run_id()
    evidence = load_evidence(evidence_dir, run_id=rid)
    by_check: dict[str, list[TestSpec]] = {}
    for spec in specs:
        by_check.setdefault(spec.check_id, []).append(spec)
    by_property: dict[str, list[TestSpec]] = {}
    for spec in safety_specs:
        by_property.setdefault(spec.check_id, []).append(spec)
    safety = [_rollup_property(p, [_resolve_spec(s, evidence) for s in by_property.get(p.id, [])])
              for p in properties]
    safety_counts: dict[str, int] = {}
    for p in safety:
        safety_counts[p["requirement_status"]] = safety_counts.get(p["requirement_status"], 0) + 1

    requirements: list[dict] = []
    for check in checks:
        applicable, rationale = applicability_of(check.id, applicability)
        resolved = [_resolve_spec(s, evidence) for s in by_check.get(check.id, [])]
        requirements.append(_rollup(check, resolved, applicable, rationale))

    req_by_status: dict[str, int] = {}
    for r in requirements:
        req_by_status[r["requirement_status"]] = req_by_status.get(r["requirement_status"], 0) + 1
    test_by_status: dict[str, int] = {}
    for r in requirements:
        for t in r["tests"]:
            test_by_status[t["status"]] = test_by_status.get(t["status"], 0) + 1

    covered_partial = req_by_status.get(RequirementStatus.COVERED_PARTIAL.value, 0)
    not_applicable = req_by_status.get(RequirementStatus.NOT_APPLICABLE.value, 0)
    total_reqs = len(requirements)
    gaps = [r for r in requirements if _is_gap(r)]
    return {
        "run_id": rid,
        "totals": {
            "requirements": total_reqs,
            "applicable": total_reqs - not_applicable,
            "not_applicable": not_applicable,
            "covered_partial": covered_partial,
            "gaps": len(gaps),
            "requirement_status_counts": req_by_status,
            "test_status_counts": test_by_status,
            "safety_properties": len(safety),
            "safety_property_status_counts": safety_counts,
        },
        "requirements": requirements,
        "safety_properties": safety,
        "gaps": gaps,
        "unimplemented": [r["check_id"] for r in requirements
                          if r["requirement_status"] == RequirementStatus.GAP_UNIMPLEMENTED.value],
        "manual": [r["check_id"] for r in requirements
                   if r["requirement_status"] == RequirementStatus.GAP_MANUAL.value],
        "not_applicable": [r["check_id"] for r in requirements
                           if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value],
    }


def declared_coverage_ok(report: dict) -> tuple[bool, list[str]]:
    """CI gate: EVERY declared automated aspect must be a fresh pass -- checked
    INDEPENDENTLY per aspect, so one passing aspect can never hide a failing sibling
    (issue 1). Manual aspects and requirements declared not-applicable are known,
    non-regression states and are skipped."""
    problems: list[str] = []
    for r in [*report.get("requirements", []), *report.get("safety_properties", [])]:
        if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value:
            continue
        for t in r["tests"]:
            if t["mode"] != "automated":
                continue
            if t["status"] != TestStatus.PASS.value:
                problems.append(
                    f"{r['check_id']} :: [{t['label']}] {t['aspect']}: declared automated "
                    f"test {t['test_id']} is '{t['status']}' ({t['reason']})")
    return (not problems), problems


def render_markdown(report: dict) -> str:
    """Render the requirement-coverage report as Markdown for a human / CI log."""
    t = report["totals"]
    lines = [
        "# Requirement-coverage report",
        "",
        f"_Run id: `{report.get('run_id', '')}`. Requirement coverage is tracked "
        "SEPARATELY from test outcomes: a passing test proves only the aspect it "
        "exercises, never the whole requirement. Only FRESH evidence from this run "
        "counts; missing / skipped / failed / manual never count as covered._",
        "",
        f"- Requirements in catalog: **{t['requirements']}** "
        f"(applicable **{t['applicable']}**, not-applicable **{t['not_applicable']}**)",
        f"- With fresh passing regression evidence (partial coverage): **{t['covered_partial']}**",
        f"- Gaps (unimplemented / manual / skipped / failed / residual): **{t['gaps']}**",
        "",
        f"- Requirement status counts: `{t['requirement_status_counts']}`",
        f"- Test outcome counts: `{t['test_status_counts']}`",
        "",
        "## Requirements",
        "",
        "| Ref | Name | Requirement status | Aspects (label: status) | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in report["requirements"]:
        if r["tests"]:
            tests_cell = "<br>".join(f"{x['label']}: {x['status']}" for x in r["tests"])
            ev_cell = "<br>".join(x["evidence_path"] or "-" for x in r["tests"])
        else:
            tests_cell, ev_cell = "-", "-"
        lines.append(f"| {r['ref']} | {r['name']} | {r['requirement_status']} "
                     f"| {tests_cell} | {ev_cell} |")
    if report.get("safety_properties"):
        lines += ["", "## Harness safety properties (the harness's own transport and "
                  "cleanup; not WSTG requirements)", "",
                  "| Id | Property | Status | Aspects (status) |", "| --- | --- | --- | --- |"]
        for p in report["safety_properties"]:
            cell = "<br>".join(f"{x['status']}: {x['aspect']}" for x in p["tests"]) or "-"
            lines.append(f"| {p['check_id']} | {p['name']} | {p['requirement_status']} | {cell} |")
        owed = [(p, rg) for p in report["safety_properties"] for rg in p["residual_gaps"]]
        if owed:
            lines += ["", "Safety-property aspects without fresh passing evidence (these block "
                      "`--check`):", ""]
            for p, rg in owed:
                lines.append(f"- **{p['check_id']}** [{rg['label']}] {rg['status']}: "
                             f"{rg['aspect']} — {rg['reason']}")
    if report.get("gaps"):
        lines += ["", "## Gaps (flagged, incl. residual aspects under partial coverage)", ""]
        for g in report["gaps"]:
            lines.append(f"- **{g['ref']} {g['name']}** — {g['requirement_status']}")
            for rg in g["residual_gaps"]:
                lines.append(f"  - [{rg['label']}] {rg['status']}: {rg['aspect']} — {rg['reason']}")
    na = [r for r in report["requirements"]
          if r["requirement_status"] == RequirementStatus.NOT_APPLICABLE.value]
    if na:
        lines += ["", "## Not applicable (declared, with rationale)", ""]
        for r in na:
            lines.append(f"- **{r['ref']} {r['name']}** — {r['applicability']['rationale']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual/CI invocation
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Requirement-coverage report")
    ap.add_argument("--evidence-dir", default=None,
                    help="evidence directory (default: this run's run-specific dir)")
    ap.add_argument("--run-id", default=None,
                    help="run id to reconcile against (default: current run/commit)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a declared automated aspect is not a fresh pass")
    args = ap.parse_args()

    rid = args.run_id if args.run_id is not None else current_run_id()
    rep = reconcile(evidence_dir=args.evidence_dir, run_id=rid)
    print(json.dumps(rep, indent=2) if args.json else render_markdown(rep))
    if args.check:
        ok, problems = declared_coverage_ok(rep)
        if not ok:
            print("\nDECLARED-COVERAGE CHECK FAILED:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            sys.exit(1)
