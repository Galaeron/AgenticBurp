"""
Deterministic WSTG/PortSwigger-Academy-driven coverage model.

The spine of the coverage engine (I1–I5 from the operator's expanded goal):

- **Check catalog**: a fixed, code-defined list of security checks, each tagged
  with a WSTG/Academy id, a phase (domain|endpoint|parameter — I4), a mapped
  vulnerability class, and a deterministic applicability predicate (I1/I5).
- **CoverageMatrix**: identity × endpoint × check, each cell recording an
  auditable status (I2/I5). Naturally memoises (item #4) and is the report
  substrate. Integrates with the existing EngagementState/validators rather
  than replacing them.
- **Check.confirmation**: how a check is confirmed — a deterministic leg/tool
  name where one exists (I3), else "agent" or "manual".

Every check declares WHY it applies or doesn't (the predicate's `reason`), so
"what was NOT tested and why" (I2/I5) is always answerable.

The module is split by seam (ARC-9). This module stays the import path and holds the
check-id aliases and import guard (they read `REUSED_LEGACY_IDS` and
`is_current_wstg_id`, which tests patch here) and the CoverageMatrix; it re-exports
every name of its siblings:

    coverage_model_cells    Phase, CellStatus, CellResult, CaseKey, input cases
    coverage_model_checks   applicability predicates, ExternalRef, Check
    coverage_model_catalog  CHECK_CATALOG, CHECKS_BY_ID
"""
from __future__ import annotations

import re

from harness.categories import canonicalize
from harness.wstg_ids import is_current_wstg_id
from harness.coverage_model_catalog import (  # noqa: F401
    CHECKS_BY_ID, CHECK_CATALOG, _CALLER_INDEPENDENT_CHECKS,
)
from harness.coverage_model_cells import (  # noqa: F401
    ATTEMPT_SCHEMA_VERSION, CaseKey, CellResult, CellStatus, NO_PARAMETER_CASE, Phase,
    _CAPTURED_INPUT_LOCATIONS, _CONCLUSIVE_STATUSES, _NON_INPUT_HEADERS, _NOT_TESTED_REASONS,
    _NOT_TESTED_STATUSES, _OPEN_STATUSES, _json_pointers, _merge_facts, captured_parameter_names,
    derive_input_cases, derive_input_cases_from_template,
)
from harness.coverage_model_checks import (  # noqa: F401
    ApplicabilityPredicate, Check, ExternalRef, _CLIENT_VALUE_FIELD, _CLIENT_VALUE_PATH,
    _LOOKUP_IDENTIFIERS, _OAUTH_PARAMS, _accepts_body, _accepts_create, _accepts_input,
    _accepts_xml, _always_applicable, _flow_shape, _has_auth_endpoint,
    _has_auth_endpoint_or_lookup, _has_client_value_field, _has_cookie_or_session,
    _has_denied_role, _has_file_path_segment, _has_oauth_params, _has_params, _has_url_param,
    _is_authed, _is_authed_get, _is_file_upload_write, _is_get, _is_object_scoped,
    _is_websocket_endpoint, _issues_session_cookie, _query_and_body_keys,
)


def specific_class_token(text: str) -> str:
    """Fold a finding-class spelling to the snake token `specific_classes` match on:
    lower-case, one trailing "(...)" dropped, runs of space / hyphen / slash -> "_"."""
    low = re.sub(r"\s*\([^)]*\)\s*$", "", (text or "").strip().lower())
    return re.sub(r"[\s\-/]+", "_", low).strip("_")


def shared_class_specificity_problems(checks=None) -> list[str]:
    """WG-2 (4) guard, pure so a test can inject a bad row set. Returns one message
    per problem (empty = sound):
    - every row whose canonical class is shared by another row declares
      `specific_classes`;
    - no token (after `specific_class_token`) sits on two rows;
    - no token canonicalizes to the class of a DIFFERENT row, so a specific token
      never steals a finding that belongs to another class's row. A token whose
      class no row carries (e.g. "bfla", "missing security headers") may sit on a
      row: there is no other row to steal from, and the token is its only route."""
    checks = CHECK_CATALOG if checks is None else tuple(checks)
    problems: list[str] = []
    by_class: dict[str, list] = {}
    for c in checks:
        by_class.setdefault(canonicalize(c.vulnerability_class) or c.vulnerability_class,
                            []).append(c)
    for cls, rows in sorted(by_class.items()):
        if len(rows) < 2:
            continue
        for c in rows:
            if not c.specific_classes:
                problems.append(f"{c.id}: shares class {cls!r} with "
                                f"{len(rows) - 1} other row(s) but declares no specific_classes")
    owner: dict[str, str] = {}
    for c in checks:
        row_cls = canonicalize(c.vulnerability_class) or c.vulnerability_class
        for tok in c.specific_classes:
            key = specific_class_token(tok)
            if not key:
                problems.append(f"{c.id}: empty specific_classes token {tok!r}")
                continue
            prev = owner.get(key)
            if prev is not None and prev != c.id:
                problems.append(f"{c.id}: token {tok!r} is already on {prev}")
            owner.setdefault(key, c.id)
            tok_cls = canonicalize(tok)
            if tok_cls is not None and tok_cls != row_cls and tok_cls in by_class:
                problems.append(f"{c.id}: token {tok!r} canonicalizes to {tok_cls!r}, "
                                f"not the row class {row_cls!r}")
    return problems

# WG-1: the ONE table of pre-WG-1 check ids (WSTG v4.2 numbering, plus the old
# internal mass-assignment id) -> the current catalog id. Coverage cells, evidence
# files and event ledgers written by r9, r10 and earlier carry these; every reader
# resolves them through `resolve_check_id`. An id in neither CHECKS_BY_ID nor this
# table is rejected, never guessed. A key that is also a current id must be declared
# in REUSED_LEGACY_IDS (the import guard enforces it).
#
# ID schemes: data stamped `check_id_scheme: 2` (CHECK_ID_SCHEME) uses current WSTG
# ids; data with no stamp is scheme 1 (pre-WG-1, v4.2 numbering). Everything written
# before the stamp existed is unmarked, which is safe: post-WG-1 writers never wrote
# "WSTG-BUSL-08", and no other alias key is a current id.
CHECK_ID_SCHEME = 2
LEGACY_CHECK_ID_SCHEME = 1

LEGACY_CHECK_ID_ALIASES: dict[str, str] = {
    "WSTG-CONF-05": "WSTG-CONF-12",      # v4.2 CONF-05 = admin interfaces; CSP is CONF-12
    "WSTG-CONF-08": "WSTG-CLNT-07",      # v4.2 CONF-08 = RIA cross-domain policy; CORS is CLNT-07
    "WSTG-CONF-02": "WSTG-CONF-14",      # v4.2 CONF-02 = platform config; headers are CONF-14
    "WSTG-ATHN-01": "WSTG-ATHN-04",      # v4.2 ATHN-01 = encrypted channel; bypass is ATHN-04
    "WSTG-BUSV-04": "WSTG-INJT-16",      # no BUSV category exists; smuggling is INJT-16
    "WSTG-INPV-14": "WSTG-INJT-15",      # v4.2 INPV-14 = incubated; CRLF splitting is INJT-15
    "WSTG-INPV-05": "WSTG-INJT-05",      # INPV-* was renumbered INJT-*
    "WSTG-INPV-01": "WSTG-INJT-01",
    "WSTG-INPV-02": "WSTG-INJT-02",
    "WSTG-INPV-12": "WSTG-INJT-12",
    "WSTG-INPV-18": "WSTG-INJT-18",
    "WSTG-INPV-07": "WSTG-INJT-07",
    "WSTG-INPV-19": "WSTG-INJT-19",
    "WSTG-INPV-17": "WSTG-CLNT-04",      # v4.2 INPV-17 = Host header; redirect is CLNT-04
    "WSTG-INPV-06": "WSTG-INJT-05.6",    # v4.2 INPV-06 = LDAP; NoSQL is sub-test INJT-05.6
    "WSTG-CRYP-04": "WSTG-SESS-10",      # v4.2 CRYP-04 = weak encryption; JWT is SESS-10
    "WSTG-INPV-11": "WSTG-INJT-23",      # v4.2 INPV-11 = code injection; deserialization is INJT-23
    "WSTG-BUSL-07": "WSTG-BUSL-05",      # v4.2 BUSL-07 = misuse defenses; race is BUSL-05
    "WSTG-BUSL-08": "WSTG-ATHZ-03",      # v4.2 BUSL-08 = unexpected file types; TOCTOU is ATHZ-03
    "AV-MASSASSIGN-01": "WSTG-INJT-20",  # internal id; current WSTG adds Mass Assignment
}

# Alias keys that are ALSO current catalog ids but meant something else in scheme 1.
# They resolve through the alias table only in scheme-1 data; in scheme-2 data they
# are the current row. WSTG-BUSL-08 was the v4.2-era TOCTOU row; today it is
# "Upload of Unexpected File Types" (the file_upload leg).
REUSED_LEGACY_IDS: frozenset[str] = frozenset({"WSTG-BUSL-08"})


class UnknownCheckIdError(KeyError):
    """A check id that is neither a current catalog id nor a known legacy alias."""


def check_id_scheme_of(value) -> int:
    """The id scheme a stored `check_id_scheme` value names: absent (None) is scheme 1;
    1 or 2 is itself. Anything else raises ValueError -- an unknown scheme is never
    read as a known one."""
    if value is None:
        return LEGACY_CHECK_ID_SCHEME
    if isinstance(value, int) and not isinstance(value, bool) and value in (
            LEGACY_CHECK_ID_SCHEME, CHECK_ID_SCHEME):
        return value
    raise ValueError(f"unsupported check_id_scheme {value!r}")


def is_legacy_check_id(check_id: str, scheme: int = CHECK_ID_SCHEME) -> bool:
    """True when `check_id`, read under `scheme`, is a legacy alias that resolves to
    another id. In scheme 1 every alias key is legacy; in scheme 2 a reused id
    (REUSED_LEGACY_IDS) is the current row, not an alias."""
    if check_id not in LEGACY_CHECK_ID_ALIASES:
        return False
    if scheme == LEGACY_CHECK_ID_SCHEME:
        return True
    if scheme == CHECK_ID_SCHEME:
        return check_id not in REUSED_LEGACY_IDS
    raise ValueError(f"unsupported check_id_scheme {scheme!r}")


def resolve_check_id(check_id: str, *, scheme: int = CHECK_ID_SCHEME) -> str:
    """Return the current catalog id for `check_id` read under `scheme`.

    Scheme 1 (pre-WG-1 data): an alias key resolves through the table (BUSL-08 ->
    ATHZ-03); a current id resolves to itself. Scheme 2 (current): a current id
    resolves to itself; a non-reused alias still resolves (tolerant reads). Raises
    `UnknownCheckIdError` for anything else -- an unknown id is never silently
    mapped to a neighbour."""
    if is_legacy_check_id(check_id, scheme):
        target = LEGACY_CHECK_ID_ALIASES[check_id]
        if target in CHECKS_BY_ID:
            return target
        raise UnknownCheckIdError(check_id)
    if check_id in CHECKS_BY_ID:
        return check_id
    raise UnknownCheckIdError(check_id)


def _check_catalog_ids() -> None:
    """Import-time guard: every WSTG-labelled row names a current WSTG test, no alias
    shadows a current id unless it is declared in REUSED_LEGACY_IDS, every declared
    reused id really is both an alias key and a current id, and every alias lands on
    a catalog row."""
    for c in CHECK_CATALOG:
        if c.is_wstg() and not is_current_wstg_id(c.id):
            raise ValueError(f"catalog id {c.id!r} is not in harness/wstg_ids.py")
    for old, new in LEGACY_CHECK_ID_ALIASES.items():
        if old in CHECKS_BY_ID and old not in REUSED_LEGACY_IDS:
            raise ValueError(f"legacy alias {old!r} shadows a current catalog id")
        if new not in CHECKS_BY_ID:
            raise ValueError(f"legacy alias {old!r} -> {new!r} has no catalog row")
    for reused in REUSED_LEGACY_IDS:
        if reused not in LEGACY_CHECK_ID_ALIASES or reused not in CHECKS_BY_ID:
            raise ValueError(f"reused legacy id {reused!r} is not both a legacy alias "
                             f"and a current catalog id")


_check_catalog_ids()


# ---------------------------------------------------------------------------
# WG-2: confirmation kinds <-> registered validators
# ---------------------------------------------------------------------------

# Confirmation kinds that deliberately name no `validators/registry.py` validator.
NON_VALIDATOR_CONFIRMATIONS: dict[str, str] = {
    "manual": "needs a human, a browser PoC or host access; never automated coverage",
    "agent": "confirmed by the LLM agent's own evidence, not a deterministic leg",
}

# Registered validators that confirm no catalog row, each with the reason.
VALIDATOR_ROW_EXCLUSIONS: dict[str, str] = {
    "api_security": "mass-assignment / resource-consumption probes from one exchange; the "
                    "mass-assignment row (WSTG-INJT-20) confirms via the sequence leg",
    "deserialization": "passive serialized-format fingerprint, no verdict of its own; "
                       "WSTG-INJT-23 confirms via deserialization_oob",
    "idor_read": "single-principal read differential; WSTG-ATHZ-04 confirms via "
                 "cross_identity (switching or adding a kind is an owner decision)",
    "verbose_error": "passive stack-trace scan; WSTG-ERRH-01 is judged by the passive "
                     "error_handling adapter instead",
    "challenge_echo": "R11-8 (c): routed by capture shape on the analyze path; it records "
                      "leads until the owner signs off, so a WSTG-BUSL-07 row (and its "
                      "drive) is an owner decision",
}

# Current WSTG tests deliberately left without a row, each with the reason.
EXCLUDED_CATALOG_ROWS: dict[str, str] = {
    "WSTG-INJT-14": "no registry validator confirms it: the second-order differentials "
                    "(second_order.py) run inside orchestrator_chain and their findings "
                    "carry second_order_sqli / second_order_idor, which canonicalize to no "
                    "class; a row needs a categories.py synonym and a kind decision",
}


def catalog_kind_problems(rows, registered_names, exclusions=None, *,
                          non_validator=None, excluded_rows=None) -> list[str]:
    """Every problem between catalog confirmation kinds and the registered
    validators; empty means consistent. A row's kind must be a registered validator
    or a documented non-validator kind; every registered validator must confirm a
    row or sit on `exclusions` with a reason; an exclusion must not be stale (the
    validator gained a row, or is no longer registered); an excluded row id must not
    have a row."""
    exclusions = VALIDATOR_ROW_EXCLUSIONS if exclusions is None else exclusions
    non_validator = NON_VALIDATOR_CONFIRMATIONS if non_validator is None else non_validator
    excluded_rows = EXCLUDED_CATALOG_ROWS if excluded_rows is None else excluded_rows
    registered = set(registered_names)
    rows = tuple(rows)
    kinds = {r.confirmation for r in rows}
    problems: list[str] = []
    for r in rows:
        if r.confirmation not in non_validator and r.confirmation not in registered:
            problems.append(f"{r.id}: confirmation {r.confirmation!r} names no registered "
                            f"validator and is not a documented non-validator kind")
    for name in sorted(registered):
        if name in kinds:
            if name in exclusions:
                problems.append(f"{name}: excluded but a row names it (stale exclusion)")
        elif not (exclusions.get(name) or "").strip():
            problems.append(f"{name}: registered validator has no catalog row and no "
                            f"exclusion reason")
    for name in sorted(set(exclusions) - registered):
        problems.append(f"{name}: excluded but not registered (stale exclusion)")
    ids = {r.id for r in rows}
    for row_id, why in sorted(excluded_rows.items()):
        if row_id in ids:
            problems.append(f"{row_id}: on the excluded-row list but has a row")
        elif not (why or "").strip():
            problems.append(f"{row_id}: excluded row has no reason")
    return problems


CHECKS_BY_PHASE: dict[Phase, list[Check]] = {}
for _c in CHECK_CATALOG:
    CHECKS_BY_PHASE.setdefault(_c.phase, []).append(_c)


# ---------------------------------------------------------------------------
# Coverage matrix — identity × endpoint × check (I2)
# ---------------------------------------------------------------------------

class CoverageMatrix:
    """The auditable coverage matrix.

    Keys: (identity, endpoint_key, check_id) → CellResult.
    endpoint_key is "METHOD path" matching EngagementState.endpoints keys.
    """

    def __init__(self) -> None:
        self._cells: dict[tuple[str, str, str], CellResult] = {}
        # T05: child cases UNDER a cell -- {(identity, ep, check): {coord_id: (CaseKey, CellResult)}}.
        # A cell with child cases derives its status by aggregation; a cell with
        # none behaves exactly as before (leaf cell), so every existing caller,
        # test, and serialized matrix is unaffected.
        self._cases: dict[tuple[str, str, str], dict[str, tuple[CaseKey, CellResult]]] = {}

    def get(self, identity: str, endpoint_key: str, check_id: str) -> CellResult | None:
        return self._cells.get((identity, endpoint_key, check_id))

    def set(self, identity: str, endpoint_key: str, check_id: str, result: CellResult) -> None:
        self._cells[(identity, endpoint_key, check_id)] = result

    def fill_applicability(self, identities: list[str], endpoints: dict[str, dict],
                           checks: tuple[Check, ...] | None = None) -> int:
        """Pre-fill cells based on each check's applicability predicate.

        Returns the number of cells set to not_applicable. Cells already
        populated (e.g. from a prior run) are not overwritten.
        """
        checks = checks or CHECK_CATALOG
        na_count = 0
        for identity in identities:
            for ep_key, ep_data in endpoints.items():
                for check in checks:
                    key = (identity, ep_key, check.id)
                    if key in self._cells:
                        continue
                    applicable, reason = check.applies(ep_data)
                    if not applicable:
                        self._cells[key] = CellResult.not_applicable(reason)
                        na_count += 1
                    else:
                        self._cells[key] = CellResult(
                            status=CellStatus.PENDING,
                            reason=reason)
        return na_count

    def record(self, identity: str, endpoint_key: str, check_id: str, *,
               status: CellStatus, reason: str = "", severity: str | None = None,
               confidence: float | None = None, validator: str | None = None,
               evidence: str | None = None, executed: bool = False,
               attempts=(), referenced_attempts=()) -> CellResult:
        """Record a check result. Does NOT overwrite a CONFIRMED cell.

        `executed` (R07) must be True only when a deterministic leg actually
        dispatched a request/comparison for this cell -- callers recording a
        purely agent-attributed result (no leg ran) must leave it False.
        Attempt facts (batch 02) are merged even where the verdict is locked,
        and a later record never clears an earlier execution."""
        key = (identity, endpoint_key, check_id)
        existing = self._cells.get(key)
        if existing and (existing.reason.startswith("origin_scoped:")
                         or existing.status == CellStatus.CONFIRMED):
            # Endpoint findings cannot recreate a host-level denominator, and a
            # confirmed verdict stays; only the attempt facts are added.
            existing.executed = existing.executed or executed
            existing.attempts = _merge_facts(existing.attempts, attempts)
            existing.referenced_attempts = _merge_facts(
                existing.referenced_attempts, referenced_attempts)
            return existing
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence,
                            executed=executed or bool(existing and existing.executed),
                            attempts=_merge_facts(existing and existing.attempts, attempts),
                            referenced_attempts=_merge_facts(
                                existing and existing.referenced_attempts, referenced_attempts))
        self._cells[key] = result
        return result

    # --- child cases (T05/R26): concrete inputs/states under a cell ---

    def expand_cases(self, identity: str, endpoint_key: str, check_id: str,
                     case_keys, *, budget_remaining: int | None = None) -> dict:
        """Register concrete child cases under an applicable cell, LAZILY within a
        budget (T05). Each case starts PENDING; once `budget_remaining` is spent the
        rest are registered SKIPPED with an explicit "budget exhausted" reason so
        they stay VISIBLE and are never counted as executed. Returns
        {added, budget_skipped}. Already-registered cases are left untouched.

        `budget_remaining is None` means unbounded. A non-positive budget registers
        every case as budget-skipped (nothing attempted)."""
        key = (identity, endpoint_key, check_id)
        bucket = self._cases.setdefault(key, {})
        added = 0
        budget_skipped = 0
        for ck in case_keys:
            cid = ck.coord_id()
            if cid in bucket:
                continue
            if budget_remaining is not None and budget_remaining <= 0:
                bucket[cid] = (ck, CellResult(
                    status=CellStatus.SKIPPED,
                    reason=f"case budget exhausted before {ck.label()} was attempted "
                           f"(visible, not counted as tested)"))
                budget_skipped += 1
                continue
            bucket[cid] = (ck, CellResult(status=CellStatus.PENDING,
                                          reason=f"case {ck.label()} awaiting attempt"))
            added += 1
            if budget_remaining is not None:
                budget_remaining -= 1
        if bucket:
            self._aggregate_cell(key)
        return {"added": added, "budget_skipped": budget_skipped}

    def record_case(self, identity: str, endpoint_key: str, check_id: str,
                    case_key: CaseKey, *, status: CellStatus, reason: str = "",
                    severity: str | None = None, confidence: float | None = None,
                    validator: str | None = None, evidence: str | None = None,
                    executed: bool = False, attempts=(), referenced_attempts=()) -> CellResult:
        """Record the outcome of ONE concrete case, then re-aggregate its parent
        cell. A CONFIRMED case is never overwritten (same monotonicity as `record`).
        Registers the case if `expand_cases` had not already."""
        key = (identity, endpoint_key, check_id)
        bucket = self._cases.setdefault(key, {})
        cid = case_key.coord_id()
        existing = bucket.get(cid)
        prior = existing[1] if existing else None
        if prior and prior.status == CellStatus.CONFIRMED:
            prior.executed = prior.executed or executed
            prior.attempts = _merge_facts(prior.attempts, attempts)
            prior.referenced_attempts = _merge_facts(prior.referenced_attempts, referenced_attempts)
            self._aggregate_cell(key)
            return prior
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence,
                            executed=executed or bool(prior and prior.executed),
                            attempts=_merge_facts(prior and prior.attempts, attempts),
                            referenced_attempts=_merge_facts(
                                prior and prior.referenced_attempts, referenced_attempts))
        # Preserve the original replay spelling if the caller passed a bare key.
        stored_key = existing[0] if existing else case_key
        bucket[cid] = (stored_key, result)
        self._aggregate_cell(key)
        return result

    def cases_for_cell(self, identity: str, endpoint_key: str,
                       check_id: str) -> list[tuple[CaseKey, CellResult]]:
        return list(self._cases.get((identity, endpoint_key, check_id), {}).values())

    def has_cases(self, identity: str, endpoint_key: str, check_id: str) -> bool:
        return bool(self._cases.get((identity, endpoint_key, check_id)))

    def pending_cases(self) -> list[tuple[str, str, str, CaseKey]]:
        """(identity, endpoint_key, check_id, CaseKey) for every child case still
        PENDING -- the case-granular work-program the driver fires."""
        out: list[tuple[str, str, str, CaseKey]] = []
        for (i, e, c), bucket in self._cases.items():
            for _cid, (ck, res) in bucket.items():
                if res.status == CellStatus.PENDING:
                    out.append((i, e, c, ck))
        return out

    def _aggregate_cell(self, key: tuple[str, str, str]) -> None:
        """Roll the child-case statuses up into the parent cell (T05).

        Rule: a CONFIRMED child marks the cell CONFIRMED (endpoint risk), but the
        cell may claim completion (not_detected/controlled_negative) ONLY when
        EVERY child is a conclusive negative -- any open child (pending, skipped,
        budget-exhausted, blocked, inconclusive) keeps the cell PENDING. This is
        what forbids "one input tested" from reading as "endpoint tested". A
        directly-recorded CONFIRMED/DETECTED on the cell (e.g. from a finding) is
        folded in as a participant so the case layer never erases it."""
        bucket = self._cases.get(key)
        if not bucket:
            return
        statuses = {res.status for _ck, res in bucket.values()}
        prior = self._cells.get(key)
        if prior and prior.status in (CellStatus.CONFIRMED, CellStatus.DETECTED):
            statuses.add(prior.status)

        n_cases = len(bucket)
        confirmed = sum(1 for _c, r in bucket.values() if r.status == CellStatus.CONFIRMED)
        # Completion (not_detected / controlled_negative) requires EVERY child to be
        # a conclusive negative. An errored, blocked, inconclusive, or still-open
        # child forbids the cell from claiming the endpoint was fully tested (R06):
        # a negative sibling next to an errored one is NOT "all tested".
        _NEG = {CellStatus.NOT_DETECTED, CellStatus.CONTROLLED_NEGATIVE}
        if CellStatus.CONFIRMED in statuses:
            agg, reason = CellStatus.CONFIRMED, f"{confirmed}/{n_cases} case(s) confirmed"
        elif CellStatus.DETECTED in statuses:
            agg, reason = CellStatus.DETECTED, "a case was detected but unconfirmed"
        elif statuses <= {CellStatus.CONTROLLED_NEGATIVE}:
            agg, reason = CellStatus.CONTROLLED_NEGATIVE, f"all {n_cases} case(s) held under a controlled negative"
        elif statuses <= _NEG:
            agg, reason = CellStatus.NOT_DETECTED, f"all {n_cases} case(s) tested, none detected"
        elif statuses & _OPEN_STATUSES:
            n_open = sum(1 for _c, r in bucket.values() if r.status in _OPEN_STATUSES)
            agg, reason = CellStatus.PENDING, (
                f"{n_open}/{n_cases} case(s) not yet conclusively tested "
                f"-- endpoint not marked complete")
        elif CellStatus.ERROR in statuses:
            # remaining mix is negatives + errors (no open child): an unresolved
            # error means the cell is not a clean completion.
            agg, reason = CellStatus.ERROR, "a case attempt errored -- endpoint not marked complete"
        else:
            agg, reason = CellStatus.PENDING, "cases awaiting attempt"
        attempts = _merge_facts(prior and prior.attempts,
                                *(r.attempts for _ck, r in bucket.values()))
        referenced = _merge_facts(prior and prior.referenced_attempts,
                                  *(r.referenced_attempts for _ck, r in bucket.values()))
        # Never downgrade a locked CONFIRMED cell (its attempt facts still grow).
        if prior and prior.status == CellStatus.CONFIRMED and agg != CellStatus.CONFIRMED:
            prior.executed = prior.executed or any(r.executed for _ck, r in bucket.values())
            prior.attempts, prior.referenced_attempts = attempts, referenced
            return
        # R07: carry the representative child's executed/validator signal into
        # the rolled-up parent cell, so a matrix reader iterating top-level
        # cells (coverage_summary.py) sees whether the aggregate verdict
        # actually came from an executed leg -- never defaulting to
        # executed=False just because the parent cell itself never called
        # `record()` directly.
        # Execution is a fact of any child send, independent of the rolled-up
        # verdict. Pending siblings and prior risk must not erase that fact.
        rep_executed = any(r.executed for _ck, r in bucket.values()) or bool(
            prior and prior.executed)
        rep_validator: str | None = None
        for _ck, r in bucket.values():
            if r.status == agg:
                rep_validator = rep_validator or r.validator
        if prior and prior.status == agg:
            rep_validator = rep_validator or prior.validator
        self._cells[key] = CellResult(status=agg, reason=reason, validator=rep_validator,
                                      executed=rep_executed, attempts=attempts,
                                      referenced_attempts=referenced)

    # --- queries ---

    def cells(self) -> dict[tuple[str, str, str], CellResult]:
        return dict(self._cells)

    def for_endpoint(self, endpoint_key: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, check_id) → result for one endpoint."""
        return {(i, c): r for (i, e, c), r in self._cells.items() if e == endpoint_key}

    def for_identity(self, identity: str) -> dict[tuple[str, str], CellResult]:
        """All (endpoint_key, check_id) → result for one identity."""
        return {(e, c): r for (i, e, c), r in self._cells.items() if i == identity}

    def for_check(self, check_id: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, endpoint_key) → result for one check."""
        return {(i, e): r for (i, e, c), r in self._cells.items() if c == check_id}

    def summary(self) -> dict:
        """Aggregate counts by status, phase, and check."""
        by_status: dict[str, int] = {}
        by_phase: dict[str, dict[str, int]] = {}
        by_check: dict[str, dict[str, int]] = {}
        for (_, _, check_id), result in self._cells.items():
            s = result.status.value
            by_status[s] = by_status.get(s, 0) + 1
            check = CHECKS_BY_ID.get(check_id)
            if check:
                phase = check.phase.value
                by_phase.setdefault(phase, {})
                by_phase[phase][s] = by_phase[phase].get(s, 0) + 1
                by_check.setdefault(check_id, {})
                by_check[check_id][s] = by_check[check_id].get(s, 0) + 1
        total = len(self._cells)
        # Honest, separated counts (R02). Only cells where a leg was actually
        # executed count as an attempt. SKIPPED, PENDING, RUNNING and
        # NOT_APPLICABLE are NOT attempts and must never inflate a "tested"
        # number -- that is exactly what made 3,633 skipped cells look tested.
        # A CONTROLLED_NEGATIVE is a real executed verdict (the boundary held), so
        # it counts as conclusive/attempted. BLOCKED (gate-denied) and INCONCLUSIVE
        # (no verdict) are NOT executed -- they never inflate "attempted"/"tested".
        conclusive = (by_status.get("confirmed", 0) + by_status.get("detected", 0)
                      + by_status.get("not_detected", 0)
                      + by_status.get("controlled_negative", 0))
        attempted = conclusive + by_status.get("error", 0)
        return {
            "total_cells": total,
            # attempted: an execution was actually launched (produced a verdict, or errored).
            "attempted": attempted,
            # conclusive: the attempt produced a usable verdict.
            "conclusive": conclusive,
            # `tested` is retained for back-compat but is now an alias of `conclusive`
            # -- it deliberately EXCLUDES skipped/error/pending/running/not_applicable.
            "tested": conclusive,
            "not_applicable": by_status.get("not_applicable", 0),
            "pending": by_status.get("pending", 0),
            "skipped": by_status.get("skipped", 0),
            "running": by_status.get("running", 0),
            "error": by_status.get("error", 0),
            "confirmed": by_status.get("confirmed", 0),
            "detected": by_status.get("detected", 0),
            "not_detected": by_status.get("not_detected", 0),
            "controlled_negative": by_status.get("controlled_negative", 0),
            "blocked": by_status.get("blocked", 0),
            "inconclusive": by_status.get("inconclusive", 0),
            "by_status": by_status,
            "by_phase": by_phase,
            "by_check": by_check,
            # T05: aggregate child-case counts, so the coverage report shows the
            # finer parameter/state granularity WITHOUT changing the cell counts.
            "cases": self.case_summary(),
        }

    def case_summary(self) -> dict:
        """Aggregate counts over all child cases (T05). Same honest accounting as
        the cell summary: only real verdicts count as attempted/conclusive."""
        by_status: dict[str, int] = {}
        total = 0
        for bucket in self._cases.values():
            for _ck, res in bucket.values():
                total += 1
                by_status[res.status.value] = by_status.get(res.status.value, 0) + 1
        conclusive = (by_status.get("confirmed", 0) + by_status.get("detected", 0)
                      + by_status.get("not_detected", 0)
                      + by_status.get("controlled_negative", 0))
        return {
            "total_cases": total,
            "attempted": conclusive + by_status.get("error", 0),
            "conclusive": conclusive,
            "confirmed": by_status.get("confirmed", 0),
            "detected": by_status.get("detected", 0),
            "not_detected": by_status.get("not_detected", 0),
            "controlled_negative": by_status.get("controlled_negative", 0),
            "pending": by_status.get("pending", 0),
            "skipped": by_status.get("skipped", 0),
            "blocked": by_status.get("blocked", 0),
            "inconclusive": by_status.get("inconclusive", 0),
            "error": by_status.get("error", 0),
            "by_status": by_status,
        }

    def cases_not_tested(self) -> list[dict]:
        """Every child case that was NOT conclusively tested, with its reason
        (T05: budget-exhausted/pending/blocked cases stay visible and honest)."""
        out: list[dict] = []
        for (identity, ep_key, check_id), bucket in self._cases.items():
            for _cid, (ck, res) in bucket.items():
                if res.status in _CONCLUSIVE_STATUSES:
                    continue
                out.append({
                    "identity": identity, "endpoint": ep_key, "check": check_id,
                    "case": ck.label(), "parameter_location": ck.parameter_location,
                    "parameter_name": ck.parameter_name, "occurrence": ck.occurrence,
                    "status": res.status.value, "reason": res.reason,
                })
        return out

    def not_tested(self) -> list[dict]:
        """Cells that were NOT tested, with the reason (I2/I5). A leg that was
        blocked, gave no verdict or errored is listed too (RV-M M2, after R11),
        and so is a cell still pending or running (RV-O O6): only an executed
        verdict is tested, so the list must name those cells. A pending parent
        whose detail lives in child cases (T05) is left to `cases_not_tested`,
        which names each open case, as finalize_pending_reasons leaves it."""
        result = []
        for (identity, ep_key, check_id), cell in self._cells.items():
            if cell.status in (CellStatus.PENDING, CellStatus.RUNNING) \
                    and self._cases.get((identity, ep_key, check_id)):
                continue
            if cell.status in _NOT_TESTED_STATUSES:
                result.append({
                    "identity": identity,
                    "endpoint": ep_key,
                    "check": check_id,
                    "status": cell.status.value,
                    "reason": cell.reason or _NOT_TESTED_REASONS.get(cell.status, ""),
                })
        return result

    def to_dict(self) -> dict:
        out: dict = {
            # WG-2: the id scheme the keys below use; an unmarked dict is scheme 1.
            "check_id_scheme": CHECK_ID_SCHEME,
            "cells": {
                f"{i}|{e}|{c}": r.to_dict()
                for (i, e, c), r in self._cells.items()
            },
        }
        # T05: child cases, additive -- an older reader ignores the key and a
        # matrix with no cases omits it, so round-tripping stays compatible.
        if self._cases:
            out["cases"] = {
                f"{i}|{e}|{c}": [
                    {"key": ck.to_dict(), "result": res.to_dict()}
                    for ck, res in bucket.values()
                ]
                for (i, e, c), bucket in self._cases.items()
            }
        # Batch 02: versioned only when attempt facts exist, so a legacy matrix
        # round-trips unchanged; a reader without the key sees none.
        if any(r.attempts or r.referenced_attempts for r in self._cells.values()):
            out["attempt_schema_version"] = ATTEMPT_SCHEMA_VERSION
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "CoverageMatrix":
        """WG-1: a cell or case stored under a legacy check id (pre-WG-1 WSTG v4.2
        numbering) loads under its current id. When a matrix holds BOTH spellings of
        one cell, the entry already under the current id wins. An id that is neither
        current nor a known alias is kept verbatim -- never mapped onto a neighbour.
        The dict's `check_id_scheme` (absent = 1) decides how a reused id reads: a
        "WSTG-BUSL-08" key is the TOCTOU row (ATHZ-03) in scheme 1 and the
        file-upload row in scheme 2."""
        m = cls()
        scheme = check_id_scheme_of(d.get("check_id_scheme"))

        def split_key(key_str: str) -> tuple[tuple[str, str, str], bool] | None:
            parts = key_str.split("|", 2)
            if len(parts) != 3:
                return None
            check_id = parts[2]
            if is_legacy_check_id(check_id, scheme):
                return (parts[0], parts[1], resolve_check_id(check_id, scheme=scheme)), True
            return (parts[0], parts[1], check_id), False

        # Current-id entries first, so a legacy duplicate never overwrites one.
        cells = []
        for key_str, cell_dict in (d.get("cells", {}) or {}).items():
            parsed = split_key(key_str)
            if parsed is not None:
                cells.append((parsed[1], parsed[0], cell_dict))
        for legacy, key, cell_dict in sorted(cells, key=lambda t: t[0]):
            if legacy and key in m._cells:
                continue
            m._cells[key] = CellResult.from_dict(cell_dict)

        buckets = []
        for key_str, cases in (d.get("cases", {}) or {}).items():
            parsed = split_key(key_str)
            if parsed is not None:
                buckets.append((parsed[1], parsed[0], cases))
        for legacy, key, cases in sorted(buckets, key=lambda t: t[0]):
            bucket = m._cases.setdefault(key, {})
            for entry in cases or []:
                ck = CaseKey.from_dict(entry.get("key", {}) or {})
                res = CellResult.from_dict(entry.get("result", {}) or {})
                if legacy and ck.coord_id() in bucket:
                    continue
                bucket[ck.coord_id()] = (ck, res)
        return m
