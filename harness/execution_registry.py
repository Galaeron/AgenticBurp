"""execution_registry.py -- one run-scoped record of what each validator already ran.

The worklist (P1), the model-review path (P2) and the coverage drive (P3) all
dispatch the same validators, each with its own key, so a heavy leg re-ran on the
same request shape under another route id, another path, or another phase. This
registry is the one place they all ask first. The key is the validator NAME
(the only identifier common to every path) plus, for the shape-keyed legs, the
request SHAPE rather than the exact URL and body.

A key is a statement about what the leg tests, never about who asked:
- SHAPE_KEYED legs inject into parameters, so /basket/1?q=a and /basket/6?q=b are
  one check (method, host, route template, parameter NAMES, identity, class family).
- Every other leg is about an object or an identity (cross_identity, idor_read,
  jwt_forge, csrf, ...), so its key stays exactly `confirmation_cache_key` and a
  different object id or identity is a different case.
- HEADER_CHECKED legs (csp, cors) read response headers, which belong to the route
  template and the identity, so their key is (validator, method, host, route template,
  identity) with no parameters or body: the universal header audit and the model-review
  path answer the same question once.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from harness.categories import canonicalize
from harness.engagement import capture_identity_key, normalize_path
from harness.orchestrator_helpers import _identity_signature, confirmation_cache_key

# Validators whose verdict depends on the request shape, not on a particular value.
SHAPE_KEYED = frozenset({
    "sqlmap", "command_injection", "ssti", "xxe", "nosql",
    "header_injection_validator", "verbose_error_validator",
})
# Validators whose verdict is a fact about a route's response headers (E2).
HEADER_CHECKED = frozenset({"csp_validator", "cors_validator"})
# Not shape-keyed although they test parameters: ssrf, open_redirect, path_traversal
# and deserialization_oob pick WHICH parameter to attack by its value (URL-, path- or
# blob-shaped), so two requests with the same names can need different checks.


def _body_shape(exchange) -> tuple:
    """The body's parameter NAMES: JSON top-level keys or form field names. A body
    that is neither (XML, multipart, a JSON list, a form with no declared content
    type) keeps its sha256, so two different opaque bodies never share a key."""
    body = exchange.request_body or ""
    if not body.strip():
        return ("none",)
    ctype = " ".join(str(v) for k, v in (exchange.request_headers or {}).items()
                     if str(k).lower() == "content-type").lower()
    if body.lstrip().startswith("{"):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return ("json", tuple(sorted(str(k) for k in parsed)))
    elif "application/x-www-form-urlencoded" in ctype:
        names = tuple(sorted(k for k, _ in parse_qsl(body, keep_blank_values=True)))
        if names:
            return ("form", names)
    return ("sha256", hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest())


def _header_claim(validator_name: str, finding_class: str | None) -> tuple:
    """Which header check a class asks for. The CSP validator decides a CSP claim and a
    framing claim from different headers, so they are different checks of one fetch;
    CORS runs one battery whatever the class, so its claim is empty."""
    if validator_name != "csp_validator":
        return ()
    from harness.validators.csp_validator import _claim_kinds
    return tuple(sorted(_claim_kinds(finding_class or "")))


def execution_key(validator_name: str, exchange, finding_class: str | None = None) -> tuple:
    """The within-run key for one validator execution (see the module docstring)."""
    # _identity_signature reads Authorization and Cookie only; capture_identity_key
    # adds every non-public header, so an X-Api-Key identity is not shared either.
    identity = capture_identity_key(exchange.request_headers)
    if validator_name in HEADER_CHECKED:
        return (validator_name, (exchange.method or "GET").upper(),
                urlsplit(exchange.url or "").netloc.lower(), normalize_path(exchange.url or ""),
                identity, _header_claim(validator_name, finding_class))
    if validator_name not in SHAPE_KEYED:
        return confirmation_cache_key(validator_name, exchange, finding_class) + (identity,)
    parts = urlsplit(exchange.url or "")
    raw_class = (finding_class or "").strip().lower()
    return (validator_name, (exchange.method or "GET").upper(), parts.netloc.lower(),
            normalize_path(exchange.url or ""),
            tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True))),
            _body_shape(exchange), _identity_signature(exchange.request_headers), identity,
            canonicalize(raw_class) or raw_class)


# A result with one of these statuses says the check did NOT run (it failed, the
# validator declined for a reason about its caller, or a budget or gate refused it),
# which is no evidence about the shape; it is returned to its caller but never
# stands in for another case's check.
_NOT_RUN = frozenset({"error", "skipped", "blocked"})


@dataclass
class _Stored:
    result: object
    case_ref: str
    sent_count: int


class ExecutionRegistry:
    """Run-scoped memo of validator executions, shared by every execution path.

    `budget` (the run's RequestBudget, optional) lets a miss record how many
    requests it spent, so `sends_saved` can say what the hits avoided. A result
    that already carries an int `sent_count` wins. Otherwise the figure is the
    budget delta, kept only when no other registry call overlapped (the run's
    spend is then this call's); an overlapped call records 0, so the saving is
    an under-estimate, never an over-claim."""

    def __init__(self, budget=None):
        self._budget = budget
        self._stored: dict[tuple, _Stored] = {}
        self._flying: dict[tuple, asyncio.Future] = {}
        self._active: list[dict] = []     # calls in progress, for overlap detection
        self._by_validator: dict[str, dict[str, int]] = {}

    def _tally(self, name: str) -> dict:
        return self._by_validator.setdefault(
            name, {"hits": 0, "misses": 0, "inflight_joins": 0, "sends_saved": 0})

    async def run(self, validator, finding, exchange, *, case_ref, call):
        """Return the validator's result for this execution key.

        A miss awaits `call()` (the real validate) and stores the result with the
        case it ran under. A caller that finds the key in flight waits for that run
        instead of starting another. A hit for the same case returns the stored
        result; a hit for another case returns a copy that names no exchanges, is
        not confirmed (the proof belongs to the first case), keeps the original
        status, and says which case covered it. A result whose check did not run
        (status error or skipped) is returned to its caller but not stored, and a
        run that was cancelled hands the key back, so a failure or a decline never
        stands in for a check that did not happen."""
        name = getattr(validator, "name", "") or "validator"
        key = execution_key(name, exchange, getattr(finding, "vulnerability_class", None))
        tally = self._tally(name)
        while True:
            stored = self._stored.get(key)
            if stored is not None:
                tally["hits"] += 1
                tally["sends_saved"] += stored.sent_count
                return self._for_case(stored, case_ref)
            flight = self._flying.get(key)
            if flight is None:
                break
            tally["inflight_joins"] += 1
            # shield: cancelling this waiter must not cancel the run others share.
            await asyncio.shield(flight)
        return await self._miss([key], tally, call, case_ref)

    async def run_audit(self, validator, exchange, classes, *, case_ref, call):
        """`run` for a validator that decides several classes from ONE send
        (CspValidator.audit): `call()` returns {class: result} and each class is stored
        under its own key, so a later single-class `run` for the same route and
        identity is a hit. Returns {class: result}; a hit for another case returns the
        covered copies `run` returns."""
        name = getattr(validator, "name", "") or "validator"
        keys = {c: execution_key(name, exchange, c) for c in classes}
        tally = self._tally(name)
        while True:
            stored = {c: self._stored.get(k) for c, k in keys.items()}
            if all(stored.values()):
                tally["hits"] += 1
                tally["sends_saved"] += max(s.sent_count for s in stored.values())
                return {c: self._for_case(s, case_ref) for c, s in stored.items()}
            flight = next((self._flying[k] for k in keys.values() if k in self._flying), None)
            if flight is None:
                break
            tally["inflight_joins"] += 1
            await asyncio.shield(flight)
        return await self._miss(list(keys.values()), tally, call, case_ref,
                                entries=lambda results: [(keys[c], results.get(c)) for c in keys])

    async def memo(self, key, coro_fn, *, name: str = "memo"):
        """(value, reused) for `key`: the first caller runs `coro_fn()`, a later caller
        gets the stored value (reused=True) and one that finds it in flight waits for
        that run. For work that is not a validator verdict (the recon crawl). A run
        that raises stores nothing; the caller owns copying a value it will change."""
        key = ("memo", name, *key)
        tally = self._tally(name)
        while True:
            stored = self._stored.get(key)
            if stored is not None:
                tally["hits"] += 1
                tally["sends_saved"] += stored.sent_count
                return stored.result, True
            flight = self._flying.get(key)
            if flight is None:
                break
            tally["inflight_joins"] += 1
            await asyncio.shield(flight)
        return await self._miss([key], tally, coro_fn, ""), False

    async def _miss(self, keys, tally, call, case_ref, entries=None):
        tally["misses"] += 1
        flight = asyncio.get_running_loop().create_future()
        for key in keys:
            self._flying[key] = flight
        state = {"overlapped": bool(self._active)}
        for other in self._active:
            other["overlapped"] = True
        self._active.append(state)
        used_before = getattr(self._budget, "used", None)
        try:
            result = await call()
        except BaseException as exc:
            for key in keys:
                self._flying.pop(key, None)
            if isinstance(exc, Exception):
                flight.set_exception(exc)
                flight.exception()          # waiters get it; nobody left is not an error
            else:
                flight.set_result(None)     # cancelled: waiters run the check themselves
            raise
        finally:
            self._active.remove(state)
        sent = getattr(result, "sent_count", None)
        if not isinstance(sent, int) or isinstance(sent, bool):
            sent = (self._budget.used - used_before
                    if used_before is not None and not state["overlapped"] else 0)
        for key, one in (entries(result) if entries else [(keys[0], result)]):
            if one is not None and getattr(one, "status", None) not in _NOT_RUN:
                self._stored[key] = _Stored(one, case_ref, max(0, sent))
        for key in keys:
            self._flying.pop(key, None)
        flight.set_result(None)
        return result

    @staticmethod
    def _for_case(stored: _Stored, case_ref):
        if stored.case_ref == case_ref:
            return stored.result
        covered = copy.copy(stored.result)
        covered.baseline_artifact_id = covered.attack_artifact_id = ""
        covered.control_artifact_ids = ()
        covered.confirmed = False
        # Nothing was sent for this case; the proof lives on stored.case_ref.
        covered.sent_count = 0
        covered.covered_by = stored.case_ref
        covered.summary = (f"covered by {stored.case_ref} (same check, route template, "
                           f"parameters and identity): {stored.result.summary or ''}")
        return covered

    def stats(self) -> dict:
        """Hits (every call served without running the check, including the ones
        that waited on a run in flight), misses (checks actually run), the waiters
        among the hits, and the requests the hits avoided."""
        rows = {name: dict(row) for name, row in sorted(self._by_validator.items())}
        total = {field: sum(row[field] for row in rows.values())
                 for field in ("hits", "misses", "inflight_joins", "sends_saved")}
        return {**total, "by_validator": rows}
