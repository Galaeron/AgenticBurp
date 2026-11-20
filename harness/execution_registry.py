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
  A TOOL_SCAN_KEYED leg (sqlmap) sends the same scan whatever class the finding
  claimed, so its key has no class family either.
- Every other leg is about an object or an identity (cross_identity, idor_read,
  jwt_forge, csrf, ...), so its key stays exactly `confirmation_cache_key` and a
  different object id or identity is a different case.
- HEADER_CHECKED legs (csp, cors) read response headers, which belong to the route
  template and the identity, so their key is (validator, method, host, route template,
  identity) with no parameters or body: the universal header audit and the model-review
  path answer the same question once.
- RESPONSE_JUDGED legs send nothing and judge the captured response they are handed,
  so the response is part of the case: two captures of one request that drew
  different responses are two cases.

Batch 04: reuse is conditional and evidence-linked. Every key also carries the
mechanism (validator) version and the finding's relevant workflow state, so a new
oracle or a changed state is a new experiment while a state change elsewhere leaves
this key alone. A shape-keyed body keys on its full nested shape. An incomplete
result is never stored; the same unchanged key is retried at most `retry_limit`
times, after which callers get a zero-send reference to the last attempt.

r9 (one 20 h run, 65% of sqlmap's requests were repeat scans of one shape): a tool
scan's parameter-only case (`-p`) is covered by a clean full scan of the same shape
and identity that reached that input (the validator's `full_scan_covers`), and an
incomplete tool scan the target answered at least `answered_floor` times is not
retried: what stopped it (its timeout, a per-scan cap) stops the next one the same
way, unless the result says the cause may clear by itself (`transient_stop`).

r9 (F4): a single-page app answers every client-side route (/, /about, /accounting,
/address/create, ...) with one HTML document, and each route was a new shape: ssti
sent 238 payloads to each. A shape-keyed leg's clean result on a GET whose captured
response is a full HTML document also covers another route whose capture is the
same document byte for byte (`_shell_key`): the server answered both with one
catch-all, so injecting there tests the catch-all again.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from harness.categories import canonicalize
from harness.control_outcome import covers_case
from harness.engagement import capture_identity_key, normalize_path
from harness.orchestrator_helpers import _identity_signature, confirmation_cache_key
from harness.volatile_params import stable_url

# Validators whose verdict depends on the request shape, not on a particular value.
SHAPE_KEYED = frozenset({
    "sqlmap", "command_injection", "ssti", "xxe", "nosql",
    "header_injection_validator", "verbose_error_validator",
})
# Tool scans that test EVERY parameter of the request whatever parameter the finding
# named (sqlmap runs without -p unless parameter_only), so the named parameter is not
# part of their key; identity (R03) and workflow state still are. The 8h juice-shop
# run re-ran sqlmap on one request shape because findings named different parameters
# (path id, query d, none) -- up to ~2.3k requests per rerun.
TOOL_SCAN_KEYED = frozenset({"sqlmap"})
# Validators whose verdict is a fact about a route's response headers (E2).
HEADER_CHECKED = frozenset({"csp_validator", "cors_validator"})
# Passive validators whose verdict is a fact about the one captured response.
RESPONSE_JUDGED = frozenset({"security_headers_validator", "error_handling_validator",
                             "content_exposure_validator"})
# Not shape-keyed although they test parameters: ssrf, open_redirect, path_traversal
# and deserialization_oob pick WHICH parameter to attack by its value (URL-, path- or
# blob-shaped), so two requests with the same names can need different checks.


def _json_shape(value):
    """The nested structure of a JSON value: object keys, list element shapes and
    leaf types, without the leaf values."""
    if isinstance(value, dict):
        return ("{", tuple(sorted((str(k), _json_shape(v)) for k, v in value.items())))
    if isinstance(value, list):
        return ("[", tuple(sorted({_json_shape(v) for v in value}, key=repr)))
    return type(value).__name__


def _body_shape(exchange) -> tuple:
    """The body's parameter NAMES: the nested JSON shape or form field names. A body
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
            return ("json", _json_shape(parsed))
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


def execution_key(validator_name: str, exchange, finding_class: str | None = None, *,
                  mechanism_version: str = "1", state: str = "",
                  parameter: tuple[str, str] = ("", "")) -> tuple:
    """The within-run key for one validator execution (see the module docstring).

    A named (location, parameter) is part of the case: a parameter leg tests the
    parameter the agent named first, so one parameter's result is not another's.
    It is appended only when named, so unnamed keys keep their shape."""
    key = _base_key(validator_name, exchange, finding_class) + (
        ("mechanism", str(mechanism_version)), ("state", state or ""))
    return key + (("parameter", tuple(parameter)),) if any(parameter) else key


_SHELL_MIN_CHARS = 256


def _html_document(exchange) -> bool:
    """A 200 GET whose captured response is a full HTML document."""
    if (exchange.method or "GET").upper() != "GET" or exchange.response_status != 200:
        return False
    body = exchange.response_body or ""
    if len(body) < _SHELL_MIN_CHARS:
        return False
    ctype = next((str(v) for k, v in (exchange.response_headers or {}).items()
                  if str(k).lower() == "content-type"), "")
    head = body.lstrip()[:64].lower()
    looks_html = head.startswith("<!doctype html") or head.startswith("<html")
    return looks_html and (not ctype or "html" in ctype.lower())


def _shell_key(validator_name: str, exchange, finding_class: str | None, conditions) -> tuple | None:
    """The key a shape-keyed leg's result is also kept under when its capture is a
    full HTML document: the document (by content) instead of the route template and
    parameters, so another route the server answered with the same catch-all
    document finds it. None for any other leg or response."""
    if validator_name not in SHAPE_KEYED or not _html_document(exchange):
        return None
    raw_class = (finding_class or "").strip().lower()
    family = "" if validator_name in TOOL_SCAN_KEYED else (canonicalize(raw_class) or raw_class)
    digest = hashlib.sha256((exchange.response_body or "").encode("utf-8", errors="replace"))
    return ("html-document", validator_name, urlsplit(exchange.url or "").netloc.lower(),
            digest.hexdigest(), _identity_signature(exchange.request_headers),
            capture_identity_key(exchange.request_headers), family,
            str(conditions.get("mechanism_version", "1")), conditions.get("state", "") or "")


def _base_key(validator_name: str, exchange, finding_class: str | None) -> tuple:
    # _identity_signature reads Authorization and Cookie only; capture_identity_key
    # adds every non-public header, so an X-Api-Key identity is not shared either.
    identity = capture_identity_key(exchange.request_headers)
    if validator_name in HEADER_CHECKED:
        return (validator_name, (exchange.method or "GET").upper(),
                urlsplit(exchange.url or "").netloc.lower(), normalize_path(exchange.url or ""),
                identity, _header_claim(validator_name, finding_class))
    if validator_name in RESPONSE_JUDGED:
        response = json.dumps([exchange.response_status, sorted(
            (str(k).lower(), str(v)) for k, v in (exchange.response_headers or {}).items()),
            exchange.response_body or ""], default=str)
        return confirmation_cache_key(validator_name, exchange, finding_class) + (
            identity, hashlib.sha256(response.encode("utf-8", errors="replace")).hexdigest())
    if validator_name not in SHAPE_KEYED:
        return confirmation_cache_key(validator_name, exchange, finding_class) + (identity,)
    # A cache-buster parameter present on one capture only is not a new shape.
    parts = urlsplit(stable_url(exchange.url or ""))
    raw_class = (finding_class or "").strip().lower()
    # A tool scan sends the same requests whatever class the finding claimed (r9:
    # findings filed as 'sqli', 'sql_injection' and an access-control class each
    # launched sqlmap on one shape), so it keys on no class.
    family = "" if validator_name in TOOL_SCAN_KEYED else (canonicalize(raw_class) or raw_class)
    return (validator_name, (exchange.method or "GET").upper(), parts.netloc.lower(),
            normalize_path(exchange.url or ""),
            tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True))),
            _body_shape(exchange), _identity_signature(exchange.request_headers), identity,
            family)


# These outcomes do not establish a completed reusable check. Some may have
# sent requests, but an incomplete observation cannot cover another case. Keep
# legacy not_confirmed semantics unchanged until its callers expose completeness.
_NOT_RUN = frozenset({"error", "skipped", "blocked", "inconclusive", "incomplete", "partial"})


@dataclass
class _Stored:
    result: object
    case_ref: str
    sent_count: int


def _conditions(validator, finding=None) -> dict:
    if (getattr(validator, "name", "") in TOOL_SCAN_KEYED
            and not getattr(finding, "parameter_only", False)):
        # The scan tests every parameter, whichever one the finding named.
        parameter = ("", "")
    else:
        parameter = (str(getattr(finding, "parameter_location", "") or "").strip().lower(),
                     str(getattr(finding, "parameter_name", "") or "").strip())
        # A parameter-only run tests nothing else, so it never
        # stands in for a named-first run (or the reverse).
        if getattr(finding, "parameter_only", False):
            parameter += ("only",)
    return {"mechanism_version": str(getattr(validator, "mechanism_version", "1") or "1"),
            "state": str(getattr(finding, "workflow_state_id", "") or ""),
            "parameter": parameter}


class ExecutionRegistry:
    """Run-scoped memo of validator executions, shared by every execution path.

    `budget` (the run's RequestBudget, optional) lets a miss record how many
    requests it spent, so `sends_saved` can say what the hits avoided. A result
    that already carries an int `sent_count` wins. Otherwise the figure is the
    budget delta, kept only when no other registry call overlapped (the run's
    spend is then this call's); an overlapped call records 0, so the saving is
    an under-estimate, never an over-claim."""

    def __init__(self, budget=None, *, retry_limit: int = 2, answered_floor: int = 100):
        self._budget = budget
        # Incomplete attempts per unchanged key: (count, last result, case, answered
        # sends when an answered tool scan used up the retries at once, else 0).
        self._retry_limit = max(1, int(retry_limit))
        self._answered_floor = max(1, int(answered_floor))
        self._incomplete: dict[tuple, tuple[int, object, str, int]] = {}
        self._stored: dict[tuple, _Stored] = {}
        self._flying: dict[tuple, asyncio.Future] = {}
        self._active: list[dict] = []     # calls in progress, for overlap detection
        self._by_validator: dict[str, dict[str, int]] = {}
        # html-document key -> (route template it ran on, its stored result).
        self._shells: dict[tuple, tuple[str, _Stored]] = {}

    def _tally(self, name: str) -> dict:
        return self._by_validator.setdefault(
            name, {"hits": 0, "misses": 0, "inflight_joins": 0, "sends_saved": 0,
                   "retry_limited": 0, "full_scan_covers": 0, "shell_covers": 0})

    def _shell_cover(self, shell_key, route, case_ref, tally):
        """A covered copy of a clean result another route's identical HTML document
        drew, or None (no such result, or it ran on this very route)."""
        held = self._shells.get(shell_key) if shell_key is not None else None
        if held is None or held[0] == route:
            return None
        other_route, stored = held
        tally["hits"] += 1
        tally["shell_covers"] += 1
        tally["sends_saved"] += stored.sent_count
        covered = self._covered_copy(stored, case_ref)
        covered.tested_parameters = ()
        covered.summary = (f"covered by {stored.case_ref}: this route's captured response is "
                           f"the same HTML document {other_route} returned, so the server "
                           f"answered both with one catch-all page and the clean "
                           f"{stored.result.validator} check there tested it: "
                           f"{stored.result.summary or ''}")
        return covered

    def _keep_shell(self, shell_key, route, key):
        """Keep a clean, complete result under its html-document key (first wins)."""
        stored = self._stored.get(key)
        if shell_key is None or stored is None or shell_key in self._shells:
            return
        one = stored.result
        if (getattr(one, "status", None) == "not_confirmed" and not getattr(one, "confirmed", False)
                and covers_case(getattr(one, "control_outcome", ""))):
            self._shells[shell_key] = (route, stored)

    async def run(self, validator, finding, exchange, *, case_ref, call):
        """Return the validator's result for this execution key.

        A miss awaits `call()` (the real validate) and stores the result with the
        case it ran under. A caller that finds the key in flight waits for that run
        instead of starting another. A hit for the same case returns the stored
        result; a hit for another case returns a copy that names no exchanges, is
        not confirmed (the proof belongs to the first case), keeps the original
        status, and says which case covered it. A result whose check did not run
        (error, skipped, blocked or explicitly incomplete) is returned to its caller but not stored, and a
        run that was cancelled hands the key back, so a failure or a decline never
        stands in for a check that did not happen.

        A tool scan's parameter-only case is also served by a clean full scan of the
        same shape and identity that reached its input (`_full_scan_cover`)."""
        name = getattr(validator, "name", "") or "validator"
        conditions = _conditions(validator, finding)
        key = execution_key(name, exchange, getattr(finding, "vulnerability_class", None),
                            **conditions)
        full_key = self._full_scan_key(validator, finding, exchange)
        shell_key = _shell_key(name, exchange, getattr(finding, "vulnerability_class", None),
                               conditions)
        route = normalize_path(exchange.url or "")
        tally = self._tally(name)
        while True:
            stored = self._stored.get(key)
            if stored is not None:
                tally["hits"] += 1
                tally["sends_saved"] += stored.sent_count
                return self._for_case(stored, case_ref)
            if full_key is not None:
                covered = self._full_scan_cover(full_key, validator, finding, exchange,
                                                case_ref, tally)
                if covered is not None:
                    return covered
            covered = self._shell_cover(shell_key, route, case_ref, tally)
            if covered is not None:
                return covered
            flight = self._flying.get(key)
            if flight is None and full_key is not None:
                # A full scan in flight may cover this case once it lands.
                flight = self._flying.get(full_key)
            if flight is None:
                limited = self._retry_limited(key, tally)
                if limited is not None:
                    return limited
                break
            tally["inflight_joins"] += 1
            # shield: cancelling this waiter must not cancel the run others share.
            await asyncio.shield(flight)
        result = await self._miss([key], tally, call, case_ref,
                                  tool_scan=name in TOOL_SCAN_KEYED)
        self._keep_shell(shell_key, route, key)
        return result

    @staticmethod
    def _full_scan_key(validator, finding, exchange):
        """The key of the full (no -p) tool scan of this request that a
        parameter-only case could be covered by; None for any other dispatch."""
        name = getattr(validator, "name", "") or ""
        if name not in TOOL_SCAN_KEYED or not getattr(finding, "parameter_only", False):
            return None
        conditions = dict(_conditions(validator, finding), parameter=("", ""))
        return execution_key(name, exchange, getattr(finding, "vulnerability_class", None),
                             **conditions)

    def _full_scan_cover(self, full_key, validator, finding, exchange, case_ref, tally):
        """A covered copy of the stored full scan, bound to this case's one input
        (tested_parameters), when that scan ended clean and the validator says it
        reached the input (`full_scan_covers(finding, exchange)` -> (location, name)).
        A full scan that detected something covers nothing: which input is injectable
        is learned by running that input alone. None when nothing covers the case."""
        stored = self._stored.get(full_key)
        if stored is None:
            return None
        full = stored.result
        if (getattr(full, "status", None) != "not_confirmed" or getattr(full, "confirmed", False)
                or not covers_case(getattr(full, "control_outcome", ""))):
            return None
        covers = getattr(validator, "full_scan_covers", None)
        target = covers(finding, exchange) if callable(covers) else None
        if not target:
            return None
        tally["hits"] += 1
        tally["full_scan_covers"] += 1
        tally["sends_saved"] += stored.sent_count
        covered = self._covered_copy(stored, case_ref)
        covered.tested_parameters = (tuple(target),)
        covered.summary = (f"covered by {stored.case_ref}: the full {stored.result.validator} scan "
                           f"of this request shape and identity tested every query and form "
                           f"parameter, {target[0]} {target[1]!r} among them: {full.summary or ''}")
        return covered

    async def run_audit(self, validator, exchange, classes, *, case_ref, call):
        """`run` for a validator that decides several classes from ONE send
        (CspValidator.audit): `call()` returns {class: result} and each class is stored
        under its own key, so a later single-class `run` for the same route and
        identity is a hit. Returns {class: result}; a hit for another case returns the
        covered copies `run` returns."""
        name = getattr(validator, "name", "") or "validator"
        keys = {c: execution_key(name, exchange, c, **_conditions(validator)) for c in classes}
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

    async def _miss(self, keys, tally, call, case_ref, entries=None, *, tool_scan=False):
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
            if one is None:
                continue
            if getattr(one, "status", None) not in _NOT_RUN and \
                    getattr(one, "control_outcome", "") != "inconclusive":
                self._stored[key] = _Stored(one, case_ref, max(0, sent))
                self._incomplete.pop(key, None)
            elif tool_scan and not getattr(one, "transient_stop", False) and \
                    self._answered(one, sent) >= self._answered_floor:
                # A tool scan the target answered at length that still stopped short
                # (its timeout, a per-scan cap, the run's budget) stops the same way
                # on a retry (r9: ~1.5-2k requests each, run twice per shape).
                self._incomplete[key] = (self._retry_limit, one, case_ref,
                                         self._answered(one, sent))
            elif self._attempted(one, sent):
                # An incomplete attempt that sent: the next caller may retry, up to
                # the bound. One that sent nothing (blocked, declined) is no attempt.
                count = self._incomplete.get(key, (0, None, "", 0))[0] + 1
                self._incomplete[key] = (count, one, case_ref, 0)
        for key in keys:
            self._flying.pop(key, None)
        flight.set_result(None)
        return result

    @staticmethod
    def _answered(result, sent) -> int:
        """Requests of this attempt that the target answered: the run transport's
        count (observed_sends) or the attempt's own sent figure, whichever is larger."""
        counts = [n for n in (getattr(result, "observed_sends", None), sent)
                  if isinstance(n, int) and not isinstance(n, bool)]
        return max(counts, default=0)

    @staticmethod
    def _attempted(result, sent) -> bool:
        if getattr(result, "status", None) in ("blocked", "skipped"):
            return False        # declined before the check ran: never a retry spent
        observed = getattr(result, "observed_sends", None)
        return (isinstance(observed, int) and observed > 0) or sent > 0

    def _retry_limited(self, key, tally):
        """A zero-send reference to the last incomplete attempt once this unchanged
        key has used its retries; None while a retry is still allowed."""
        count, last, case, answered = self._incomplete.get(key, (0, None, "", 0))
        if count < self._retry_limit:
            return None
        tally["retry_limited"] += 1
        ref = copy.copy(last)
        ref.baseline_artifact_id = ref.attack_artifact_id = ""
        ref.control_artifact_ids = ()
        ref.confirmed = False
        ref.sent_count = 0
        ref.referenced_attempt = getattr(last, "attempt_id", "") or ""
        if answered:
            ref.summary = (f"not retried: the scan under {case or 'this run'} was answered "
                           f"{answered} times and stopped short, and nothing changed: "
                           f"{last.summary or ''}")
        else:
            ref.summary = (f"retry limit reached ({count} incomplete attempts, nothing changed); "
                           f"last attempt under {case or 'this run'}: {last.summary or ''}")
        return ref

    @classmethod
    def _for_case(cls, stored: _Stored, case_ref):
        if stored.case_ref == case_ref:
            return stored.result
        return cls._covered_copy(stored, case_ref)

    @staticmethod
    def _covered_copy(stored: _Stored, case_ref):
        """A copy of the stored result for `case_ref`: no exchanges, not confirmed,
        nothing sent, naming the case that holds the proof."""
        covered = copy.copy(stored.result)
        covered.baseline_artifact_id = covered.attack_artifact_id = ""
        covered.control_artifact_ids = ()
        covered.confirmed = False
        # Nothing was sent for this case; the proof lives on stored.case_ref.
        covered.sent_count = 0
        covered.covered_by = stored.case_ref
        covered.referenced_attempt = getattr(stored.result, "attempt_id", "") or ""
        covered.summary = (f"covered by {stored.case_ref} (same check, route template, "
                           f"parameters and identity): {stored.result.summary or ''}")
        return covered

    def stats(self) -> dict:
        """Hits (every call served without running the check, including the ones
        that waited on a run in flight), misses (checks actually run), the waiters
        among the hits, and the requests the hits avoided."""
        rows = {name: dict(row) for name, row in sorted(self._by_validator.items())}
        total = {field: sum(row[field] for row in rows.values())
                 for field in ("hits", "misses", "inflight_joins", "sends_saved", "retry_limited",
                               "full_scan_covers")}
        return {**total, "by_validator": rows}
