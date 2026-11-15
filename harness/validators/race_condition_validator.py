"""
Race Condition Validator

Active validator: fires many copies of the same request concurrently
(genuinely overlapping, via asyncio.gather -- not sequential) and
checks how many of them came back looking like a "clean success"
rather than a rejection. If a check-then-act operation is meant to
succeed at most once (or some other bounded amount), seeing multiple
concurrent requests all succeed cleanly is direct evidence the
check-then-act window isn't atomic.

This can't know the application's exact success/rejection vocabulary
in advance, so it uses a heuristic: a response counts as a "clean
success" if its status code matches the original captured response's
status AND its body doesn't contain any of a small set of common
rejection-language markers. This is necessarily approximate --
flagged as such in the result -- but a burst producing several
identical-looking successes to an operation whose own response text
implies it should be limited is strong circumstantial evidence
regardless of the exact wording used.

Repeated success alone is still only a LEAD, never a confirmation: plenty of
mutating operations are legitimately repeatable. Confirming needs a state
read-back showing more effects than a one-time limit allows. Without one the
generic burst reports not_confirmed with the burst as lead evidence
(``limitation`` names the gap). Session/token-issuing endpoints (login, token
grants) are skipped as not applicable -- concurrent logins succeeding is the
designed behaviour.

Generic state read-back (oracle gap): when the request names an object (an
id-like body key or path segment), a GET that reads it -- a same-origin GET the
run captured whose answer carries the id, else the object under the request URL
or its parent, the path up to an id segment, or the request URL itself -- is
read twice before the burst (fields that differ between the two reads are
volatile and dropped), once after it, and once after ONE sequential repeat of
the request (kept inside the gate's burst allowance). The burst confirms when
that object recorded the effect 2..N times (a counter moved, an array grew,
ideally by a duplicate entry) and the sequential repeat was then refused or
changed nothing: the operation is limited to once, and the burst exceeded the
limit. A read-back showing exactly one effect is a negative (the limit held);
a repeat that is accepted and moves the state again means the operation is
repeatable, and the lead stays a lead, as it does with no reader at all. The
email-race path keeps its own account read-back.
"""

from __future__ import annotations
import asyncio
import collections
import html
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit

import httpx

from .base import Validator, ValidationResult
from .send_failures import SendFailures
from harness.safety_gate import get_default_gate

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.race_condition")

_REJECTION_MARKERS = re.compile(
    r"already (used|redeemed|claimed|applied|exists)|"
    r"expired|invalid (code|token)|insufficient|limit reached|"
    r"too many|rate limit|not found|forbidden|unauthorized",
    re.IGNORECASE,
)

_BURST_SIZE = 12

# Path segments of endpoints that ISSUE a session or token. Logging in (or
# minting a token) N times concurrently and getting N successes is the designed
# behaviour, not a one-time limit being exceeded.
_SESSION_ISSUING_SEGMENT = re.compile(
    r"^(?:log-?in|log-?on|sign-?in|authenticate|oauth2?|token|tokens"
    r"|refresh(?:-?token)?|access-?token)$", re.IGNORECASE)
_GRANT_TYPE = re.compile(r"[\"']?grant_type[\"']?\s*[:=]", re.IGNORECASE)


def is_session_issuing(exchange) -> bool:
    """True for a login / token-issuance request: a path segment naming a
    session-issuing operation, or an OAuth-style grant_type body."""
    path = urlsplit(exchange.url or "").path or ""
    if any(_SESSION_ISSUING_SEGMENT.match(seg) for seg in path.split("/") if seg):
        return True
    return bool(_GRANT_TYPE.search(exchange.request_body or ""))


# --- generic state read-back (see the module docstring) ----------------------
_ID_KEY = re.compile(r"^(?:_?id|uuid|guid)$", re.IGNORECASE)
_ID_SUFFIX_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:Id|ID|_id|_ID|Uuid|_uuid)$")
_ID_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
_ID_SEGMENT = re.compile(r"^(?:\d{1,19}|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9][A-Za-z0-9_-]{3,79})$")
_VERSION_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)
_UNSAFE_READER = re.compile(r"log-?out|sign-?out|delete|remove|destroy|reset|unsubscribe",
                            re.IGNORECASE)
_MAX_REFS = 3
_MAX_READER_PROBES = 4
_MAX_CAPTURES_SCANNED = 500
_MAX_JSON_NODES = 5000
# A sequential repeat answered with one of these never exercised the limit.
_CONTROL_UNDECIDED = {401, 407, 408, 425, 429}


def _is_id_key(key) -> bool:
    return isinstance(key, str) and bool(_ID_KEY.match(key) or _ID_SUFFIX_KEY.match(key))


def _id_of(value) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    if isinstance(value, str) and _ID_TOKEN.match(value):
        return value
    return None


def object_refs(exchange) -> list[tuple[str, str]]:
    """(key, value) of the objects a request names: id-like keys of its JSON or
    form body (top level, then one level down), then id-like path segments (key
    "#<segment index>"); at most _MAX_REFS, one per value."""
    found: list[tuple[str, str]] = []

    def add(key, value):
        if value is not None and value not in {v for _, v in found}:
            found.append((key, value))

    body = (exchange.request_body or "").strip()
    data = None
    if body[:1] in ("{", "["):
        try:
            data = json.loads(body)
        except ValueError:
            data = None
    if isinstance(data, dict):
        for obj in [data] + [v for v in data.values() if isinstance(v, dict)]:
            for key, value in obj.items():
                if _is_id_key(key):
                    add(key, _id_of(value))
    elif data is None and "=" in body:
        for key, value in parse_qsl(body, keep_blank_values=False):
            if _is_id_key(key):
                add(key, _id_of(value))
    for index, segment in enumerate((urlsplit(exchange.url or "").path or "").split("/")):
        segment = unquote(segment)
        if segment and _ID_SEGMENT.match(segment) and not _VERSION_SEGMENT.match(segment):
            add(f"#{index}", segment)
    return found[:_MAX_REFS]


def _capture(item) -> tuple[str, str, Any, str]:
    """(method, url, status, response body) of one capture, an HttpExchange or a dict."""
    get = item.get if isinstance(item, dict) else (lambda k: getattr(item, k, None))
    return (str(get("method") or "GET").upper(), str(get("url") or ""),
            get("response_status"), str(get("response_body") or ""))


def _origin_key(url: str) -> tuple[str, str]:
    parts = urlsplit(url or "")
    return (parts.scheme or "").lower(), (parts.netloc or "").lower()


def _mentions(text: str, value: str) -> bool:
    """True when a JSON answer carries `value` as a string or a whole number."""
    if f'"{value}"' in text:
        return True
    return value.isdigit() and re.search(
        rf"(?<![\w.\"]){re.escape(value)}(?![\w.\"])", text) is not None


def _shared_segments(a: str, b: str) -> int:
    n = 0
    for x, y in zip([s for s in urlsplit(a).path.split("/") if s],
                    [s for s in urlsplit(b).path.split("/") if s]):
        if x != y:
            break
        n += 1
    return n


def reader_candidates(exchange, refs, captured=()) -> list[str]:
    """GET URLs that may read the object `refs` name, best first: same-origin 2xx
    GETs the run captured whose answer carries one of the ids (nearest path
    first), then the object under the request URL or its parent, the path up to
    an id segment, and the request URL itself (a collection)."""
    url = exchange.url or ""
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    out: list[str] = []

    def add(candidate: str) -> None:
        if (candidate and candidate not in out
                and not _UNSAFE_READER.search(urlsplit(candidate).path or "")):
            out.append(candidate)

    ranked = []
    for order, item in enumerate(list(captured or ())[:_MAX_CAPTURES_SCANNED]):
        try:
            method, curl, status, body = _capture(item)
            if status is not None and not 200 <= int(status) < 300:
                continue
        except Exception:
            continue
        if method != "GET" or not curl or _origin_key(curl) != _origin_key(url):
            continue
        if any(_mentions(body, value) for _, value in refs):
            ranked.append((-_shared_segments(curl, url), order, curl))
    for _, _, curl in sorted(ranked):
        add(curl)
    path = (parts.path or "/").rstrip("/")
    segments = (parts.path or "").split("/")
    for key, value in refs:
        if key.startswith("#"):
            add(origin + "/".join(segments[:int(key[1:]) + 1]))
            continue
        add(f"{origin}{path}/{quote(value, safe='')}")
        parent = path.rsplit("/", 1)[0]
        if parent:
            add(f"{origin}{parent}/{quote(value, safe='')}")
    add(origin + (parts.path or "/"))
    return out


def _json_doc(text: str | None):
    try:
        return json.loads(text or "")
    except ValueError:
        return None


def _walk(doc):
    """Every dict and list of a JSON document, shallowest first, bounded."""
    if not isinstance(doc, (dict, list)):
        return
    queue, seen = collections.deque([doc]), 0
    while queue and seen < _MAX_JSON_NODES:
        node = queue.popleft()
        seen += 1
        yield node
        children = node.values() if isinstance(node, dict) else node
        queue.extend(c for c in children if isinstance(c, (dict, list)))


def _scalar(value) -> bool:
    return value is not None and not isinstance(value, (dict, list, bool))


def locate_object(doc, refs) -> tuple[dict | None, tuple[str, str] | None]:
    """(object, (key, value)) of the JSON object in `doc` that a ref names: a dict
    whose id-like key holds the ref's value -- the request's own key name first,
    then a plain id key, then any id-like key. (None, None) when absent."""
    best, anchor, rank = None, None, -1
    for node in _walk(doc):
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            if not (_scalar(value) and _is_id_key(key)):
                continue
            for ref_key, ref_value in refs:
                if str(value) != ref_value:
                    continue
                score = 2 if key == ref_key else (1 if _ID_KEY.match(key) else 0)
                if score > rank:
                    best, anchor, rank = node, (key, ref_value), score
    return best, anchor


def _find(doc, anchor) -> dict | None:
    key, value = anchor
    for node in _walk(doc):
        if isinstance(node, dict) and _scalar(node.get(key)) and str(node[key]) == value:
            return node
    return None


def state_fields(obj: dict) -> dict:
    """The counters (numbers) and arrays (canonical entries) of one JSON object and
    of the objects directly inside it; ids are not state."""
    out: dict = {}

    def take(name, value):
        if isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            out[name] = value
        elif isinstance(value, list):
            out[name] = [json.dumps(v, sort_keys=True, default=str) for v in value]

    for key, value in obj.items():
        if _is_id_key(key):
            continue
        if isinstance(value, dict):
            for inner, inner_value in value.items():
                if not _is_id_key(inner):
                    take(f"{key}.{inner}", inner_value)
        else:
            take(key, value)
    return out


def state_effects(before: dict, after: dict, limit: int) -> list[tuple[str, int, int, bool]]:
    """(field, effects, new duplicate entries, is array) for each field whose change
    the burst could explain -- a counter that moved by 1..limit or an array that
    grew by 1..limit -- most telling first: duplicates, then arrays, then size."""
    out = []
    for name, old in before.items():
        new = after.get(name)
        if isinstance(old, list) and isinstance(new, list):
            n = len(new) - len(old)
            dups = max(0, (len(new) - len(set(new))) - (len(old) - len(set(old))))
            is_array = True
        elif isinstance(old, (int, float)) and isinstance(new, (int, float)):
            delta = new - old
            if delta != int(delta):
                continue
            n, dups, is_array = abs(int(delta)), 0, False
        else:
            continue
        if 1 <= n <= limit:
            out.append((name, n, dups, is_array))
    out.sort(key=lambda e: (-e[2], -int(e[3]), -e[1]))
    return out


def _assigned_names(exchange) -> set[str]:
    """Lower-cased key names a JSON or form request body assigns (two levels)."""
    body = (exchange.request_body or "").strip()
    names: set[str] = set()
    data = None
    if body[:1] in ("{", "["):
        try:
            data = json.loads(body)
        except ValueError:
            data = None
    if isinstance(data, dict):
        for obj in [data] + [v for v in data.values() if isinstance(v, dict)]:
            names.update(str(k).lower() for k in obj)
    elif data is None and "=" in body:
        names.update(k.lower() for k, _ in parse_qsl(body, keep_blank_values=True))
    return names


def _change(name: str, old, new, dups: int) -> str:
    if isinstance(old, list):
        return (f"`{name}` grew from {len(old)} to {len(new)} entries"
                + (f", {dups} of them duplicates of an existing entry" if dups else ""))
    return f"`{name}` went from {old} to {new}"


@dataclass
class _ReadBack:
    """The pre-burst read of the object a request names."""
    url: str
    anchor: tuple[str, str]
    read: Callable
    stable: dict
    baseline_artifact: str = ""
    volatile: list = field(default_factory=list)
    control: bool = False

    @property
    def where(self) -> str:
        return urlsplit(self.url).path or "/"


@dataclass
class RaceConditionTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    checked: bool = True

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked,
        }


class RaceConditionValidator(Validator):
    """Validator for check-then-act race conditions via a concurrent request burst."""

    name = "race_condition_validator"
    finding_classes = {"race_condition", "race condition", "toctou", "time of check to time of use"}
    active = True

    def __init__(self, timeout: float = 15.0, max_redirects: int = 0,
                 burst_size: int = _BURST_SIZE, run_context=None,
                 target_email: str | None = None,
                 mailbox_url: str | None = None,
                 email_race_rounds: int = 6,
                 clock=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.burst_size = burst_size
        self.run_context = run_context
        self.target_email = target_email
        self.mailbox_url = mailbox_url
        self.email_race_rounds = max(1, min(int(email_race_rounds), 12))
        # SKL-1: injectable monotonic clock for burst dispatch timing.
        self._clock = clock or time.perf_counter
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def get_name(self) -> str:
        return "race_condition_validator"

    def get_capability(self) -> str:
        return "race_condition_validation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"race_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            mutation={"burst_size": str(self.burst_size)},
            rationale=f"Race condition validation for {finding.vulnerability_class}",
            success_signals=[f"Fire {self.burst_size} concurrent copies of this request and count clean successes"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        try:
            if exchange.method.upper() == "GET":
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="GET requests are (should be) idempotent -- no check-then-act state "
                            "change to race. This validator only tests mutating methods.",
                    evidence="", raw_output="[]",
                )

            if is_session_issuing(exchange):
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="Not applicable: this endpoint issues a session or token. Repeated "
                            "concurrent logins/token grants are expected to succeed; they are not "
                            "a single-use operation whose limit a race could exceed.",
                    evidence="", raw_output="[]",
                )

            if self._is_email_race(exchange):
                return await self._validate_email_race(finding, exchange)

            headers = {k: v for k, v in (exchange.request_headers or {}).items()
                       if k.lower() not in ("content-length", "host")}
            headers.setdefault("User-Agent", self.user_agent)

            gate = self.run_context.gate if self.run_context is not None else get_default_gate()
            gate_decision = gate.authorize_burst(
                validator_name=self.get_name(), method=exchange.method, url=exchange.url,
                requested_burst_size=self.burst_size, body=exchange.request_body,
            )
            if not gate_decision.allowed:
                return ValidationResult(
                    validator=self.get_name(), status="blocked",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary=f"Blocked by safety gate: {gate_decision.reason}",
                    evidence="", raw_output="[]",
                )
            effective_burst_size = gate_decision.allowed_burst_size
            # Read the named object back before the burst; when a reader exists, one
            # copy of the authorized allowance is kept for the sequential repeat
            # (the control), so the leg never sends more than the gate allowed.
            readback = None
            if self.run_context is not None:
                readback = await self._open_readback(exchange, headers)
            burst_copies = effective_burst_size
            if readback is not None and effective_burst_size >= 3:
                burst_copies = effective_burst_size - 1
                readback.control = True

            failures = SendFailures()
            label = SendFailures.label(exchange.method, exchange.url)

            def send_failed(e: Exception) -> None:
                failures.exception(label, e)

            # SKL-1: every copy is fully prepared (session binding, typed
            # request, client) BEFORE the shared release, so the copies'
            # sends are separated only by event-loop scheduling, not by
            # per-copy setup. The overlap is the point: all N requests are
            # genuinely in flight together. effective_burst_size, not
            # self.burst_size: the gate may have clamped it down to the
            # operator's or the hard ceiling.
            body_bytes = exchange.request_body.encode() if exchange.request_body else None
            if self.run_context is not None:
                from types import SimpleNamespace
                from harness.run_context import TypedRequest
                from .transport import bind_session
                executor = self.run_context.executor()

                def prepare_one():
                    failures.attempted += 1
                    try:
                        session_ref, request_headers = bind_session(self.run_context, headers)
                        typed = TypedRequest(exchange.method, exchange.url,
                                             headers=request_headers,
                                             body=exchange.request_body or None)
                    except Exception as e:
                        failures.exception(label, e)
                        log.debug(f"Burst request preparation failed: {e}")
                        return None

                    async def send():
                        result = await executor.execute(
                            typed, capability=self.get_name(), session_ref=session_ref)
                        if not result.ok:
                            failures.outcome(label, result)
                            return None
                        return SimpleNamespace(status_code=result.status, text=result.body,
                                               headers=result.headers)
                    return send

                sends = [prepare_one() for _ in range(burst_copies)]
                raw_responses, dispatch = await self._fire_together(sends, on_error=send_failed)
            else:
                # One shared client sized for the whole burst instead of a
                # fresh client (and connection pool) per copy.
                limit = max(1, effective_burst_size)
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=False, max_redirects=self.max_redirects,
                    limits=httpx.Limits(max_connections=limit, max_keepalive_connections=limit),
                ) as client:
                    def prepare_fallback():
                        failures.attempted += 1

                        async def send():
                            return await client.request(
                                exchange.method, exchange.url,
                                headers=headers, content=body_bytes)
                        return send
                    sends = [prepare_fallback() for _ in range(burst_copies)]
                    raw_responses, dispatch = await self._fire_together(sends, on_error=send_failed)
            responses = [r for r in raw_responses if r is not None]
            dispatch_note = self._dispatch_note(dispatch)

            if len(responses) < 2:
                if failures.refused or (responses and failures.failures):
                    return failures.result(self.get_name(), finding.vulnerability_class, "Race burst")
                return ValidationResult(
                    validator=self.get_name(), status="error",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary=f"Only {len(responses)}/{burst_copies} burst requests completed -- "
                            "too few to draw a conclusion, target may be rate-limiting the burst itself",
                    evidence=dispatch_note, raw_output="[]",
                )

            original_status = exchange.response_status
            clean_successes = 0
            status_counts: dict[int, int] = {}
            for r in responses:
                status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
                body = r.text or ""
                looks_clean = (
                    (original_status is None or r.status_code == original_status)
                    and r.status_code < 400
                    and not _REJECTION_MARKERS.search(body)
                )
                if looks_clean:
                    clean_successes += 1

            # Repeated success is only a LEAD: many operations are legitimately
            # repeatable. Confirmation needs a state read-back showing more effects
            # than a one-time limit allows; without a reader the burst never confirms.
            repeated = clean_successes >= 2
            if failures.failures and not repeated:
                return failures.result(self.get_name(), finding.vulnerability_class, "Race burst")
            readback_note = ""
            if readback is not None and repeated:
                verdict = await self._readback_verdict(
                    readback, finding, exchange, headers, completed=len(responses),
                    clean=clean_successes,
                    evidence=f"Status code distribution across burst: {status_counts}; {dispatch_note}",
                    raw={"burst_size": burst_copies, "requested_burst_size": self.burst_size,
                         "completed": len(responses), "clean_successes": clean_successes,
                         "status_counts": status_counts, "dispatch": dispatch})
                if isinstance(verdict, ValidationResult):
                    return verdict
                readback_note = verdict
            limitation = ""
            if repeated:
                detail = (
                    f"{clean_successes} of {len(responses)} concurrent requests came back looking like "
                    f"a clean success (status matching the original, no rejection-language markers) -- "
                    f"if this operation is meant to succeed at most once, this is evidence the "
                    f"check-then-act isn't atomic"
                )
                limitation = (
                    "Lead only: repeated success does not show a one-time limit was exceeded. "
                    + (f"The state read-back did not decide it: {readback_note}." if readback_note else
                       "No state read-back of the operation's effect (balance, redemption count, "
                       "stock) was available to prove more effects than allowed."))
            else:
                detail = (
                    f"{clean_successes} of {len(responses)} concurrent requests looked like clean "
                    f"successes -- no evidence of a race condition from this heuristic (note: this "
                    f"can't distinguish a well-locked operation from one that simply doesn't have a "
                    f"'succeed once' business rule at all)"
                )

            return ValidationResult(
                validator=self.get_name(),
                status="not_confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.3 if repeated else 0.2,
                confirmed=False,
                summary=(f"Lead, not confirmed ("
                         f"{'state read-back not decisive' if readback_note else 'no state read-back'}"
                         f"): {detail}" if repeated else detail),
                limitation=limitation,
                manual_verification=(
                    "Read back the operation's effect (e.g. balance, coupon use count, stock) "
                    "after the burst; confirm only if it exceeds the one-time limit."
                    if repeated else ""),
                evidence=(f"Status code distribution across burst: {status_counts}; {dispatch_note}"
                          + (f"; read-back {readback.where}: {readback_note}" if readback_note else "")),
                raw_output=str({"burst_size": burst_copies, "requested_burst_size": self.burst_size,
                                 "completed": len(responses),
                                 "clean_successes": clean_successes, "status_counts": status_counts,
                                 "dispatch": dispatch}
                               | ({"readback": readback.where} if readback is not None else {})),
            )
        except Exception as e:
            log.error(f"Race condition validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"Race condition validation failed: {e}", evidence="", raw_output=str(e),
            )

    async def _open_readback(self, exchange: HttpExchange, headers: dict) -> _ReadBack | None:
        """Read the object the request names before the burst, through the run's
        transport and the request's own session: the first reader candidate whose
        JSON answer holds the object, read a second time so fields that move on
        their own are dropped. None when the request names no object or no
        candidate answers with it (the burst then stays a lead)."""
        refs = object_refs(exchange)
        if not refs:
            return None
        from harness.run_context import TypedRequest
        from .transport import bind_session
        context = getattr(self.run_context, "experiment_context", None)
        captured = (context.get("captured") if isinstance(context, dict) else None) or ()
        try:
            session_ref, bound = bind_session(self.run_context, headers)
            executor = self.run_context.executor()
        except Exception as e:
            log.debug(f"Read-back preparation failed: {e}")
            return None
        read_headers = {k: v for k, v in bound.items() if k.lower() not in ("content-type", "accept")}
        read_headers["Accept"] = "application/json, */*;q=0.5"

        async def read(url: str):
            try:
                result = await executor.execute(TypedRequest("GET", url, headers=read_headers),
                                                capability=self.get_name(), session_ref=session_ref)
            except Exception as e:
                log.debug(f"Read-back GET failed: {e}")
                return None, None
            if not getattr(result, "ok", False) or not 200 <= (result.status or 0) < 300:
                return None, result
            return _json_doc(result.body), result

        for url in reader_candidates(exchange, refs, captured)[:_MAX_READER_PROBES]:
            doc, _first = await read(url)
            obj, anchor = locate_object(doc, refs)
            if obj is None:
                continue
            doc2, second = await read(url)
            again = _find(doc2, anchor)
            if again is None:
                continue
            first_fields, second_fields = state_fields(obj), state_fields(again)
            stable = {k: v for k, v in first_fields.items() if second_fields.get(k) == v}
            if stable:
                return _ReadBack(url=url, anchor=anchor, read=read, stable=stable,
                                 baseline_artifact=getattr(second, "artifact_id", "") or "",
                                 volatile=sorted(set(first_fields) - set(stable)))
        return None

    async def _readback_verdict(self, rb: _ReadBack, finding: Finding, exchange: HttpExchange,
                                headers: dict, *, completed: int, clean: int, evidence: str,
                                raw: dict):
        """A confirmation, or a negative, from the object read back after the burst
        and after one sequential repeat; else a note on why the read-back could not
        decide (the caller keeps the lead)."""
        from harness.run_context import TypedRequest
        from .transport import bind_session
        where = rb.where
        doc, after_result = await rb.read(rb.url)
        after_obj = _find(doc, rb.anchor)
        if after_obj is None:
            return f"the read of {where} after the burst no longer returned the object"
        after = state_fields(after_obj)
        # A field the request itself assigns changes by assignment, not by
        # accumulated effects, so it never counts.
        assigned = _assigned_names(exchange)
        effects = [e for e in state_effects(rb.stable, after, completed)
                   if e[0].rsplit(".", 1)[-1].lower() not in assigned]
        if not effects:
            moved = [k for k, v in rb.stable.items() if after.get(k) != v]
            if moved:
                return (f"fields of the object moved by more than the {completed} completed copies "
                        f"explain ({', '.join(moved[:3])})")
            return ("the object's counters and arrays did not change, so they may not record "
                    "this operation")
        name, n, dups, _is_array = effects[0]
        change = _change(name, rb.stable[name], after[name], dups)
        anchor = f"{rb.anchor[0]}={rb.anchor[1]}"
        raw = dict(raw, readback=where, anchor=anchor, effects=n, duplicates=dups,
                   volatile=rb.volatile)
        if n == 1:
            return ValidationResult(
                validator=self.get_name(), status="not_confirmed",
                finding_class=finding.vulnerability_class, confidence=0.2, confirmed=False,
                summary=(f"{clean} of {completed} concurrent copies looked successful, but the object "
                         f"read back from {where} recorded the effect once ({change}): no more "
                         f"effects than a single request makes, so no limit was exceeded."),
                evidence=f"{evidence}; read-back {where} ({anchor}): {change}",
                raw_output=str(raw))
        if not rb.control:
            return (f"the object recorded the effect {n} times ({change}), but the gate's burst "
                    f"allowance left no sequential repeat to show the operation is once-only")
        try:
            session_ref, bound = bind_session(self.run_context, headers)
            control = await self.run_context.executor().execute(
                TypedRequest(exchange.method, exchange.url, headers=bound,
                             body=exchange.request_body or None),
                capability=self.get_name(), session_ref=session_ref)
        except Exception as e:
            return (f"the object recorded the effect {n} times ({change}), but the sequential "
                    f"repeat failed ({e.__class__.__name__})")
        status = getattr(control, "status", None) or 0
        if not getattr(control, "ok", False) or not status:
            return (f"the object recorded the effect {n} times ({change}), but the sequential "
                    f"repeat went unanswered")
        if status in _CONTROL_UNDECIDED or status >= 500 or 300 <= status < 400:
            return (f"the object recorded the effect {n} times ({change}), but the sequential "
                    f"repeat answered HTTP {status}, which does not exercise the limit")
        refused = status >= 400 or bool(_REJECTION_MARKERS.search(getattr(control, "body", "") or ""))
        doc3, final_result = await rb.read(rb.url)
        final_obj = _find(doc3, rb.anchor)
        if final_obj is None:
            return (f"the object recorded the effect {n} times ({change}), but the read after "
                    f"the sequential repeat no longer returned it")
        final = state_fields(final_obj)
        moved = [k for k in rb.stable if final.get(k) != after.get(k)]
        if moved and refused:
            return (f"the object recorded the effect {n} times ({change}), but it moved again "
                    f"while the sequential repeat was refused ({', '.join(moved[:3])}), so other "
                    f"activity may explain the change")
        if moved:
            return (f"the object recorded the effect {n} times ({change}), and the sequential "
                    f"repeat was accepted (HTTP {status}) and changed it again: the operation is "
                    f"repeatable, so {n} effects do not exceed a limit")
        if not refused:
            # An accepted repeat that changes nothing may be an idempotent "set"
            # (the burst assigned a value rather than accumulating effects).
            return (f"the object recorded the effect {n} times ({change}); the sequential repeat "
                    f"was accepted (HTTP {status}) and changed nothing, which does not show the "
                    f"app limits the operation to once")
        how = f"was refused (HTTP {status})"
        result = ValidationResult(
            validator=self.get_name(), status="confirmed",
            finding_class=finding.vulnerability_class, confidence=0.9 if dups else 0.8,
            confirmed=True,
            summary=(f"Race condition confirmed by state read-back: {clean} of {completed} concurrent "
                     f"copies looked successful and the object read back from {where} recorded the "
                     f"effect {n} times ({change}), while one sequential repeat afterwards {how}. "
                     f"The operation is limited to once, and the concurrent burst exceeded that "
                     f"limit (the check and the update are not atomic)."),
            evidence=(f"{evidence}; read-back {where} ({anchor}) twice before the burst, once after "
                      f"it and once after the sequential repeat: {change}; the repeat {how} and "
                      f"left the object unchanged."
                      + (f" Volatile fields ignored: {', '.join(rb.volatile[:5])}." if rb.volatile
                         else "")),
            raw_output=str(dict(raw, control_status=status, control_refused=refused)))
        result.baseline_artifact_id = rb.baseline_artifact
        result.attack_artifact_id = getattr(after_result, "artifact_id", "") or ""
        result.control_artifact_ids = tuple(
            a for a in (getattr(control, "artifact_id", "") or "",
                        getattr(final_result, "artifact_id", "") or "") if a)
        return result

    async def _fire_together(self, sends: list, on_error=None) -> tuple[list, dict]:
        """Release already-prepared sends together and time each one (SKL-1).

        ``sends`` holds zero-argument coroutine functions (or None for a copy
        whose preparation failed, which yields None without sending). Every
        task parks on one shared Event; the event is set only after all of
        them are parked, so no send starts before every copy is prepared and
        waiting. A send that raises yields None and is passed to ``on_error``
        (the caller's send-failure accounting). Times are ms relative to the
        release; ``send_start`` is the moment the copy enters its send call,
        ``complete`` when that call returns.
        """
        clock = getattr(self, "_clock", None) or time.perf_counter
        n = len(sends)
        release = asyncio.Event()
        all_parked = asyncio.Event()
        parked = 0
        starts: list[float | None] = [None] * n
        completes: list[float | None] = [None] * n

        async def run(i, send):
            nonlocal parked
            parked += 1
            if parked == n:
                all_parked.set()
            await release.wait()
            if send is None:
                return None
            starts[i] = clock()
            try:
                return await send()
            except Exception as e:
                if on_error is not None:
                    on_error(e)
                log.debug(f"Burst request failed: {e}")
                return None
            finally:
                completes[i] = clock()

        tasks = [asyncio.ensure_future(run(i, s)) for i, s in enumerate(sends)]
        try:
            if n:
                await all_parked.wait()
            released_at = clock()
            release.set()
            results = list(await asyncio.gather(*tasks))
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

        def rel(v):
            return None if v is None else round((v - released_at) * 1000.0, 3)

        sent = [s for s in starts if s is not None]
        spread = round((max(sent) - min(sent)) * 1000.0, 3) if sent else None
        dispatch = {
            "copies": n, "sent": len(sent), "spread_ms": spread,
            "send_start_ms": [rel(v) for v in starts],
            "complete_ms": [rel(v) for v in completes],
        }
        return results, dispatch

    @staticmethod
    def _dispatch_note(dispatch: dict) -> str:
        spread = dispatch.get("spread_ms")
        if spread is None:
            return f"dispatch: 0/{dispatch.get('copies', 0)} copies sent"
        done = [v for v in dispatch.get("complete_ms", []) if v is not None]
        last = max(done) if done else None
        return (f"dispatch spread {spread:.3f} ms across {dispatch['sent']}/{dispatch['copies']} "
                f"sends released together after preparation (send start = transport call "
                f"entry; last response at {last} ms after release)")

    def _is_email_race(self, exchange: HttpExchange) -> bool:
        if not (self.target_email and self.mailbox_url and self.run_context):
            return False
        if (exchange.method or "GET").upper() not in ("POST", "PUT", "PATCH"):
            return False
        return any(k.lower() == "email" for k, _ in parse_qsl(
            exchange.request_body or "", keep_blank_values=True))

    async def _validate_email_race(self, finding: Finding,
                                   exchange: HttpExchange) -> ValidationResult:
        """Prove a single-endpoint email race with an independent readback.

        Two fresh values are submitted concurrently: an operator-declared target
        address and a controlled address at an operator-declared mailbox.  A
        confirmation link received by the controlled mailbox is followed, then
        the authenticated account page is read back.  Confirmation requires that
        the account contains the *target* address, so ordinary repeatable 200s and
        an ordinary controlled-address confirmation are both negative controls.
        """
        from harness.run_context import TypedRequest
        from .transport import bind_session

        pairs = parse_qsl(exchange.request_body or "", keep_blank_values=True)
        if not any(k.lower() == "email" for k, _ in pairs):
            return ValidationResult(
                validator=self.get_name(), status="skipped",
                finding_class=finding.vulnerability_class, confidence=0.0,
                confirmed=False, summary="No email field was present in the request.",
                evidence="", raw_output="[]")

        gate = self.run_context.gate
        decision = gate.authorize_burst(
            validator_name=self.get_name(), method=exchange.method, url=exchange.url,
            requested_burst_size=2, body=exchange.request_body)
        if not decision.allowed or decision.allowed_burst_size < 2:
            return ValidationResult(
                validator=self.get_name(), status="blocked",
                finding_class=finding.vulnerability_class, confidence=0.0,
                confirmed=False,
                summary=f"Blocked by safety gate: {decision.reason}",
                evidence="", raw_output="[]")

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        session_ref, request_headers = bind_session(self.run_context, headers)
        executor = self.run_context.executor()
        mailbox_host = urlsplit(self.mailbox_url).hostname or ""
        controlled = f"race-{uuid.uuid4().hex[:12]}@{mailbox_host}"
        account_url = urljoin(exchange.url, "/my-account")
        seen_links: set[str] = set()
        sent_pairs = 0
        pair_spreads: list[float | None] = []

        def spread_note() -> str:
            known = [s for s in pair_spreads if s is not None]
            return (f" Max pair dispatch spread {max(known):.3f} ms." if known else "")

        current_pairs = list(pairs)

        def body_for(email_value: str) -> str:
            return urlencode([(k, email_value if k.lower() == "email" else v)
                              for k, v in current_pairs])

        failures = SendFailures()

        async def execute(request, **kwargs):
            failures.attempted += 1
            label = SendFailures.label(request.method, request.url)
            try:
                result = await executor.execute(request, **kwargs)
            except Exception as e:
                failures.exception(label, e)
                from types import SimpleNamespace
                return SimpleNamespace(ok=False, body="")
            failures.outcome(label, result)
            return result

        def prepare_change(email_value: str):
            # SKL-1: build the typed request before the shared release.
            typed = TypedRequest(exchange.method, exchange.url,
                                 headers=request_headers, body=body_for(email_value))

            async def send():
                return await execute(
                    typed, capability=self.get_name(), session_ref=session_ref)
            return send

        async def fetch(url: str, *, bound: bool = False):
            return await execute(
                TypedRequest("GET", url, headers=request_headers if bound else {}),
                capability=self.get_name(), session_ref=session_ref if bound else None)

        def links_from(base: str, text: str) -> list[str]:
            decoded = html.unescape(text or "")
            values = re.findall(r'''(?:href=["']([^"']+)|
                                     (https?://[^\s<>"']+))''', decoded, re.I | re.X)
            return [urljoin(base, a or b).rstrip(".,)") for a, b in values]

        for _ in range(self.email_race_rounds):
            # Stateful feature crawling submitted this form once to capture its
            # shape, so its anti-CSRF value may already be spent.  Mint a fresh
            # session-bound form immediately before every pair.
            form_page = await fetch(account_url, bound=True)
            if form_page.ok:
                from harness.feature_workflow import extract_forms
                wanted_path = urlsplit(exchange.url).path
                form = next((f for f in extract_forms(form_page.body or "", account_url)
                             if urlsplit(f.action).path == wanted_path
                             and f.method.upper() == (exchange.method or "POST").upper()), None)
                if form is not None:
                    fresh_pairs = parse_qsl(form.body(), keep_blank_values=True)
                    if any(k.lower() == "email" for k, _ in fresh_pairs):
                        current_pairs = fresh_pairs
            responses, dispatch = await self._fire_together(
                [prepare_change(self.target_email), prepare_change(controlled)])
            pair_spreads.append(dispatch["spread_ms"])
            sent_pairs += 1
            if not any(r is not None and getattr(r, "ok", False)
                       for r in responses):
                continue

            mailbox = await fetch(self.mailbox_url)
            if not mailbox.ok:
                continue
            pages = [(self.mailbox_url, mailbox.body or "")]
            for link in links_from(self.mailbox_url, mailbox.body or ""):
                if urlsplit(link).hostname == mailbox_host and link not in seen_links:
                    seen_links.add(link)
                    message = await fetch(link)
                    if message.ok:
                        pages.append((link, message.body or ""))

            confirmation_links: list[str] = []
            app_host = urlsplit(exchange.url).hostname
            for page_url, text in pages:
                if controlled.lower() not in text.lower() and page_url != self.mailbox_url:
                    continue
                for link in links_from(page_url, text):
                    if (urlsplit(link).hostname == app_host
                            and ("confirm" in link.lower()
                                 or "change-email" in link.lower())):
                        confirmation_links.append(link)

            for link in confirmation_links:
                if link in seen_links:
                    continue
                seen_links.add(link)
                await fetch(link, bound=True)
                readback = await fetch(account_url, bound=True)
                visible = html.unescape(re.sub(r"<[^>]+>", " ", readback.body or ""))
                visible = " ".join(visible.lower().split())
                target_is_current = (
                    f"your email is: {self.target_email.lower()}" in visible)
                if readback.ok and target_is_current:
                    return ValidationResult(
                        validator=self.get_name(), status="confirmed",
                        finding_class=finding.vulnerability_class, confidence=0.95,
                        confirmed=True,
                        summary=("Concurrent email changes crossed their validation state: "
                                 "a link delivered to the controlled mailbox changed the "
                                 "authenticated account to the independently declared target address."),
                        evidence=(f"Independent account readback contained target address after "
                                  f"{sent_pairs} bounded request pair(s); mailbox/token values redacted."
                                  + spread_note()),
                        raw_output=str({"pairs": sent_pairs, "readback": True,
                                        "controlled_mailbox": "[REDACTED]",
                                        "pair_spread_ms": pair_spreads}))

        if failures.failures:
            return failures.result(self.get_name(), finding.vulnerability_class, "Email race")
        return ValidationResult(
            validator=self.get_name(), status="not_confirmed",
            finding_class=finding.vulnerability_class, confidence=0.1,
            confirmed=False,
            summary=("Bounded concurrent email changes did not produce a controlled-mailbox "
                     "confirmation whose account readback contained the target address."),
            evidence=(f"Tried {sent_pairs} request pair(s); no target-address readback."
                      + spread_note()),
            raw_output=str({"pairs": sent_pairs, "readback": False,
                            "pair_spread_ms": pair_spreads}))
