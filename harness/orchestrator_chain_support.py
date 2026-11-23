"""orchestrator_chain_support.py -- helpers of the engagement loop (ARC-9 split of
orchestrator_chain.py): the confirmation cache, the driver budget scope, the
coverage-drive leg-routing predicates, the per-run object-id harvesters and
`EngagementRun`, the state object the investigate_engagement stages share.
Moved verbatim."""
from __future__ import annotations

import contextlib
import re as _re
from urllib.parse import urlsplit

# FR-6: need the module too (the driver scope reads its ambient run) -- aliased because
# investigate_engagement and several methods have a `run_context` parameter that would shadow it.
from harness import run_context as _run_context_mod
from harness import access_control_gate, identity_compare
from harness.execution_registry import ExecutionRegistry
from harness.models import HttpExchange
# W-16: the single TargetTransport. Imported by name (not as the module) because
# investigate_engagement has a `run_context` parameter that would shadow the module;
# `transport_for(run_context, ...)` then reads as "use this run's transport, or a
# standalone one when it is None".
from harness.run_context import ExecutionOutcome, case_scope, count_sends
from harness.security import is_credential_header
from harness.validators.base import binds_routed_class, mechanism_class_of


# FR-6 (F10) sentinel appended to a header value to make it a genuinely invalid
# credential control -- see `_invalidated_headers` below.
_FR6_INVALID_SENTINEL = "_fr6_invalid"


# Case locations a capture's own template names its inputs at
# (coverage_model.derive_input_cases_from_template).
_CAPTURE_INPUT_LOCATIONS = frozenset({"query", "body_form", "body_json"})


def _unbuilt(result):
    """Mark a coverage-drive result for a capture no request was built from: the
    capture lacked what the leg needs, so nothing was sent. Returns `result`."""
    result.replay_unbuilt = True
    return result


_FOLDED_SUMMARY_KEYS = frozenset({"eligible", "investigated", "extra_probes", "skipped",
                                  "duplicates_skipped", "skipped_by_reason",
                                  "iterative_diagnostics"})


def _fold_worklist_summary(total: dict, sweep: dict, all_outcomes: list[dict]) -> dict:
    """Fold one worklist sweep's summary into the run's aggregate: counters and
    per-reason counts are summed, skipped/duplicate records concatenated, and the
    probe diagnostics recomputed over every sweep's outcomes. `sweeps` counts the
    sweeps folded. Mutates and returns `total`."""
    if not sweep:
        return total
    total["sweeps"] = total.get("sweeps", 0) + 1
    for k in ("eligible", "investigated", "extra_probes"):
        total[k] = total.get(k, 0) + int(sweep.get(k) or 0)
    for k in ("skipped", "duplicates_skipped"):
        total[k] = list(total.get(k) or []) + list(sweep.get(k) or [])
    by_reason = dict(total.get("skipped_by_reason") or {})
    for reason, n in (sweep.get("skipped_by_reason") or {}).items():
        by_reason[reason] = by_reason.get(reason, 0) + n
    total["skipped_by_reason"] = by_reason
    if "iterative_diagnostics" in sweep:
        from harness import worklist_investigator
        total["iterative_diagnostics"] = worklist_investigator.iterative_diagnostics(all_outcomes)
    for k, v in sweep.items():          # any other key: the latest sweep's value
        if k not in _FOLDED_SUMMARY_KEYS:
            total[k] = v
    return total


class _ConfirmationCache:
    """Within-run memo of confirmation results for investigate_engagement().

    Delegates to the run's ExecutionRegistry (execution_registry.py), whose key
    includes the IDENTITY (auth headers) and finding subtype, so a probe AS one
    identity never returns a result computed AS another (R03), and which the
    model-review path shares so one run does not repeat a check across paths.
    Each entry also remembers the case its sends were recorded under."""

    def __init__(self, run_context, case_for, registry=None):
        self._run_context = run_context
        self._case_for = case_for  # (vulnerability_class, exchange) -> case id
        self._registry = registry if registry is not None else ExecutionRegistry(
            budget=getattr(run_context, "budget", None))

    async def validate(self, validator, finding_obj, exchange, case_ref=None):
        """Wrapper around validator.validate() that caches results within this
        run. A hit returns the previous ValidationResult without any
        HTTP/container work.

        The leg's sends are recorded under `case_ref` (default: the case
        _apply builds for this class and exchange), so the exchanges its
        result names resolve for that case's proof. A hit for the same case
        returns the cached result. A hit for another case returns a copy
        without the named exchanges, which were recorded under the first case
        and do not resolve here: that proof stays a candidate. The cached
        original is never changed. Ungated: callers go through confirm()."""
        if case_ref is None:
            try:
                case_ref = self._case_for(getattr(finding_obj, "vulnerability_class", ""), exchange)
            except Exception:
                case_ref = ""
        async def run_it():
            # Answered run-transport sends of this dispatch (batch 02). Kept apart
            # from sent_count, whose absence still means "decide from status"
            # for validators that send through a host tool.
            with case_scope(case_ref), count_sends() as sent:
                result = await validator.validate(finding_obj, exchange)
            if result is not None:
                result.observed_sends = sent[0]
            if result is not None and not getattr(result, "attempt_id", ""):
                # Batch 02: the stable id of this one real execution.
                from harness.coverage_tracker import new_attempt_id
                result.attempt_id = new_attempt_id()
            return result
        result = await self._registry.run(validator, finding_obj, exchange,
                                          case_ref=case_ref, call=run_it)
        # A same-case hit is the cached object itself: it carries the original
        # attempt id, which the matrix merges by id, so no fresh attempt is
        # counted twice. A hit for another case is the registry's covered copy.
        return result

    async def confirm(self, validator, finding_obj, exchange, case_ref=None, *,
                      routed_class: str = "", catalog_bound: bool = False):
        """validate(), then the R11-1 class gate (EFF-2).

        Every graph, shape-precondition and coverage leg dispatches through
        here, so this is where the gate PASS1 applies holds for them
        (validators.base.binds_routed_class). `routed_class` is the class of the
        _confirm branch that chose the leg; `catalog_bound` marks a coverage leg,
        which the check catalog chose for the finding's class. A confirmation
        that does not prove the finding's class comes back as a skipped copy
        naming the class it proved."""
        result = await self.validate(validator, finding_obj, exchange, case_ref)
        if (result is not None and getattr(result, "confirmed", False)
                and not binds_routed_class(validator, result, finding_obj, exchange,
                                           routed_class=routed_class,
                                           catalog_bound=catalog_bound)):
            import dataclasses
            proved = mechanism_class_of(validator, result)
            label = getattr(finding_obj, "vulnerability_class", "") or ""
            # A copy, as PASS1's gate makes: the cached original stays as it ran.
            result = dataclasses.replace(
                result, confirmed=False, status="skipped", confidence=0.0,
                summary=(f"{result.validator} proved {proved!r}, not this finding's class "
                         f"{label!r}; not bound to it ({result.summary})"))
        return result


# Foreign object identifiers to try in a single-principal IDOR read (usernames of
# OTHER people mentioned in public content, numeric ids seen in links). Purely a
# seed list: the IDOR read validator never confirms (RV-D2), so its best result
# for any id is an inconclusive candidate and a stray id cannot confirm anything.
_ID_QUERY_KEYS = {"id", "user", "user_id", "userid", "uid", "account", "account_id",
                  "customer", "customer_id", "profile", "pid", "oid", "owner"}


_AUTHOR_MENTION = _re.compile(
    r'(?:author|username|posted by|created by|by)["\'\s:>]{1,4}([A-Za-z][A-Za-z0-9_.\-]{2,30})',
    _re.IGNORECASE)


def _harvest_object_ids(captured, own_ids) -> list[str]:
    """Mine candidate foreign object ids from the run's own observed traffic:
    values of id-like query params seen in links, and other people's usernames
    mentioned in public content. Excludes the current principal(s)' own ids and is
    bounded. This is observed data, never a guessed wordlist."""
    from urllib.parse import urlsplit, parse_qsl
    own = {str(x).lower() for x in (own_ids or set())}
    seen: list[str] = []

    def _add(v: str):
        v = (v or "").strip()
        if (v and v.lower() not in own and v not in seen
                and 1 <= len(v) <= 32 and v.lower() not in ("anonymous", "user", "admin", "me")):
            seen.append(v)

    for cap in (captured or []):
        try:
            ex = cap if hasattr(cap, "url") else None
            url = (ex.url if ex is not None else (cap.get("url") if isinstance(cap, dict) else "")) or ""
            body = (ex.response_body if ex is not None
                    else (cap.get("response_body") if isinstance(cap, dict) else "")) or ""
        except Exception:
            continue
        for k, val in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if k.lower() in _ID_QUERY_KEYS:
                _add(val)
        for m in _AUTHOR_MENTION.finditer(body or ""):
            _add(m.group(1))
        if len(seen) >= 8:
            break
    return seen[:8]


def _ssti_readback_urls(captured) -> list[str]:
    """Candidate SSTI readback pages: same-origin GET urls already observed in
    this engagement with a 2xx response, excluding destructive-looking paths.

    `captured` (normally `_all_captured`) is a UNION of two shapes by design:
    `HttpExchange` objects (feature_workflow's own captures) and the dict form
    role_crawl's discovery captures use (`HttpExchange(...).model_dump()`,
    required by test_role_crawl.py's dict-indexed assertions on
    RoleCrawlResult.captured). `_harvest_object_ids` above already tolerates
    both; this normalizes each item the same way before reading any field, so
    a dict element no longer crashes here. A malformed item is skipped, not
    fatal -- it just never becomes a readback candidate."""
    urls: list[str] = []
    for cap in (captured or []):
        try:
            cap_ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except Exception:
            continue
        if (cap_ex.method or "GET").upper() != "GET":
            continue
        _parts = urlsplit(cap_ex.url or "")
        _path_low = (_parts.path or "/").lower()
        if any(token in _path_low for token in
               ("logout", "signout", "delete", "remove", "destroy", "reset")):
            continue
        if cap_ex.response_status is not None and not (200 <= cap_ex.response_status < 300):
            continue
        urls.append(cap_ex.url)
    return urls


def _invalidated_headers(headers: dict) -> dict:
    """Return a copy of `headers` with the credential corrupted, for the
    invalid-token control probe in `_credential_grants_access`. Corrupts the
    VALUE of every header recognised as a credential header
    (`security.is_credential_header`: authorization/cookie, API-key and token
    schemes, ...) so the server should reject it. If none of the supplied headers
    are recognised credential headers (a scheme the classifier does not know),
    corrupts every supplied header's value instead, so the control is always
    genuinely invalid rather than an accidental no-op. Header NAMES are always preserved
    so routing/auth dispatch is unchanged -- only the value is corrupted."""
    out = dict(headers or {})
    cred_keys = [k for k in out if is_credential_header(k)]
    for k in (cred_keys or list(out.keys())):
        out[k] = f"{out[k]}{_FR6_INVALID_SENTINEL}"
    return out


def _responses_equivalent(a: ExecutionOutcome, b: ExecutionOutcome) -> bool:
    """True when two probe outcomes represent the same access: identical status
    AND identical body. A None/errored outcome's status is treated as None and
    its body as "" (matching `ExecutionOutcome`'s own defaults), consistently
    for both sides. Deliberately simple and exact -- no fuzzy body diffing --
    so only a clear, real difference ever counts as evidence of a genuine
    credential grant."""
    a_status = a.status if a is not None else None
    b_status = b.status if b is not None else None
    a_body = (a.body or "") if a is not None else ""
    b_body = (b.body or "") if b is not None else ""
    return a_status == b_status and a_body == b_body


def _responses_materially_same(a: ExecutionOutcome, b: ExecutionOutcome) -> bool:
    """Noise-tolerant counterpart to _responses_equivalent: two probe outcomes
    represent the SAME access (not an authorization grant) when they share a
    status and their bodies are similar above identity_compare.MATCH_THRESHOLD.
    Per-request noise (nonce/timestamp/CSRF/ads/rate-limit/login pages) stays
    below the grant signal because trigram similarity of a body differing only
    in one volatile token lands well above the match threshold, while two
    genuinely different resources fall below it. Reuses the same
    None->status / errored->body normalization _responses_equivalent applies."""
    a_status = a.status if a is not None else None
    b_status = b.status if b is not None else None
    a_body = (a.body or "") if a is not None else ""
    b_body = (b.body or "") if b is not None else ""
    return a_status == b_status and identity_compare.similarity(a_body, b_body) >= identity_compare.MATCH_THRESHOLD


class _DriverBudget:
    """Atomic child reservations spend the parent budget without replacing it."""
    def __init__(self, parent, maximum):
        import threading
        self.parent, self.maximum, self.spent = parent, maximum, 0
        self.lock = threading.Lock()

    def reserve(self, n=1, label=""):
        with self.lock:
            # A parent that predates labels (no by_label) is reserved unlabelled.
            if self.spent + n > self.maximum or not (
                    self.parent.reserve(n, label=label) if hasattr(self.parent, "by_label")
                    else self.parent.reserve(n)):
                return False
            self.spent += n
            return True

    @property
    def by_label(self):
        return self.parent.by_label

    @property
    def remaining(self):
        remaining = self.parent.remaining
        own = max(0, self.maximum - self.spent)
        return own if remaining is None else min(own, remaining)

    @property
    def used(self):
        return self.parent.used


@contextlib.asynccontextmanager
async def _driver_scope(run, maximum):
    import copy
    from dataclasses import replace
    from harness.safety_gate import push_gate, pop_gate
    child = copy.copy(run)
    child.budget = run.budget if maximum is None else _DriverBudget(run.budget, maximum)
    child.gate = copy.copy(run.gate)
    child.gate.config = replace(run.gate.config, allow_mutating_replay=False)
    gate_restore = push_gate(child.gate)
    # Task-local binding: sibling drivers retain their own child budget.
    token = _run_context_mod._ambient_run.set(child)
    try:
        yield child
    finally:
        _run_context_mod._ambient_run.reset(token)
        pop_gate(gate_restore)
        # A lazily opened default client belongs to this child, not its parent.
        if child._default_client is not None and child._default_client is not run._default_client:
            await child._default_client.aclose()


# Leg routing for `_confirm` (r5, job ec2d4f39326d): a confident finding was sent to
# a leg that cannot test its request shape -- a login POST to the GET-only
# cross-identity replay, a collection read with no object id to it, exposed admin
# data to nothing. A class reaches a leg only when the leg can test the shape;
# otherwise the finding records `no_applicable_leg`, which is never a negative.
NO_APPLICABLE_LEG = "no_applicable_leg"


_AUTHN_ONLY_MARKERS = ("broken authentication", "broken_authentication")


_USER_ENUMERATION = _re.compile(
    r"(?:user|username|account|email|login)s?[\s_-]*enumerat|enumerat\w*\s+(?:of\s+)?(?:user|account)",
    _re.I)


def _authentication_only_class(vc: str) -> bool:
    """A broken-AUTHENTICATION claim with no authorization marker: the auth-sequence
    leg's, not the cross-identity replay's (the access-control gate lists the
    phrase only to cap denied claims)."""
    low = (vc or "").lower()
    if not any(m in low for m in _AUTHN_ONLY_MARKERS):
        return False
    return not any(m in low for m in access_control_gate._ACCESS_CONTROL_MARKERS
                   if m not in _AUTHN_ONLY_MARKERS)


def _missing_auth_class(vc: str, method: str) -> bool:
    """Classes the credential-stripped replay (missing_auth_probe) tests: the explicit
    missing-auth labels, and an unauthenticated / exposed-admin read claim that is
    not itself an access-control (second identity) claim."""
    low = (vc or "").strip().lower()
    if low in ("auth_bypass", "missing_authentication", "missing authentication"):
        return True
    if (method or "GET").upper() != "GET" or access_control_gate._is_access_control_class(vc):
        return False
    return "unauthenticated" in low or (("expos" in low or "disclos" in low) and "admin" in low)


def _access_control_shape_gap(exchange, xval=None) -> str:
    """Why neither cross-identity nor idor-read can test this request ('' if one can).

    A captured object write (PUT/PATCH/DELETE) is testable by `xval`'s write leg
    when that validator was built with mutating replay permitted (B1-T2). r7: this
    gate predated the write leg and refused every non-GET, so a write-method BOLA
    finding never reached cross_identity even with allow_mutating_replay on."""
    from harness.validators.cross_identity_validator import CrossIdentityValidator, _WRITE_METHODS
    from harness.validators.idor_read_validator import _locate_id
    method = (exchange.method or "GET").upper()
    if method in _WRITE_METHODS:
        if xval is None or not xval.write_admitted(method):
            return (f"cross-identity write authorization for a {method} request needs "
                    f"validators.allow_mutating_replay (and, for DELETE, a "
                    f"delete_restore_method=PUT contract); idor-read replays GET reads only")
        if CrossIdentityValidator.shape_applies(exchange):
            return ""
        return f"no object identifier in this {method} request to test write authorization on"
    if method != "GET":
        return f"cross-identity and idor-read replay GET reads only; this is a {method} request"
    if CrossIdentityValidator.shape_applies(exchange) or _locate_id(exchange) is not None:
        return ""
    return ("no object identifier to swap and not an admin-namespaced function; no "
            "collection-level cross-identity leg exists for a list read")


def _auth_sequence_shape_gap(exchange) -> str:
    """Why the auth-sequence leg cannot test this request ('' if it can)."""
    from harness.validators.auth_sequence_validator import (
        _parse_body, _find_key, _PASS_KEYS, _USER_KEYS)
    if (exchange.method or "").upper() not in ("POST", "PUT"):
        return "auth-sequence needs a captured credential POST/PUT"
    fields, _ = _parse_body(exchange)
    if _find_key(fields, _PASS_KEYS) is None and _find_key(fields, _USER_KEYS) is None:
        return "auth-sequence needs captured username/password fields"
    return ""


def _record_no_applicable_leg(finding: dict, leg: str, reason: str) -> None:
    """Mark a finding no leg could test. Untested, never refuted: confirmation,
    confidence and verdict are left as they are."""
    if finding.get("confirmed"):
        return
    finding.setdefault("leg_disposition", NO_APPLICABLE_LEG)
    finding.setdefault("leg_disposition_reason", f"{leg}: {reason}" if leg else reason)


class EngagementRun:
    """The locals `investigate_engagement` shares between its stages, as attributes of one object.

    ARC-9: the method was one 2,600-line function; each stage is now a method of its own
    (orchestrator_chain_*.py) and a local that more than one stage touches lives here.
    The driver seeds it with the call's arguments; stages read and write the rest."""

    def __init__(self, **values):
        self.__dict__.update(values)

    def __getattr__(self, name):
        # Only reached for an attribute no stage has set yet. The old single function raised
        # UnboundLocalError (a NameError) for a local read before its assignment, and
        # `except NameError` guards in the stages depend on it (feature_caps, set only when the
        # feature crawl runs); keep that exception. Protocol probes (`__deepcopy__`) stay AttributeError.
        if name.startswith("__"):
            raise AttributeError(name)
        raise UnboundLocalError(f"cannot access local variable {name!r} where it is not associated with a value")
