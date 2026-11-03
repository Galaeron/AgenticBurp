from __future__ import annotations
import asyncio
import json as _json
import os
import re
import secrets
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from harness.models import Finding, HttpExchange, TestPlan
from harness.planner import exchange_fingerprint
from harness.categories import canonicalize
from .base import Validator, ValidationResult
from harness.safety_gate import get_default_gate

# General-purpose parameter enumeration/mutation for the boolean-probe
# fallback below (see _boolean_probe_fallback's own docstring for why it
# exists at all). Deliberately NOT limited to credential fields: SQL
# injection is not an auth-only bug class -- an id/sort/filter/search
# parameter in the query string or body is at least as common a real-world
# injection point (see agents/sqli_agent.py's own prompt, which lists
# exactly this set of parameter shapes). Proper JSON/form/query-string
# parsing is used here rather than regex specifically so this generalizes
# to arbitrary field names correctly (a regex approach that hardcodes
# field names, as an earlier version of this module did for password/
# email specifically, cannot generalize to "whatever parameters this
# exchange happens to have").
# Why the run stopped the tool's proxied traffic (ToolProxy.stop_reason), for summaries.
_PROXY_STOP_WHY = {"budget_exhausted": "the run's request budget ran out",
                   "session_expired": "the identity's session expired during the scan",
                   "route_unavailable": "the route answered 5xx to every request and was paused"}


def _looks_like_json(body: str, content_type: str) -> bool:
    if "json" in content_type.lower():
        return True
    stripped = body.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def _json_top_level_params(body: str) -> list[str]:
    try:
        data = _json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    # bool is a subclass of int -- exclude it, flipping a boolean flag to
    # an injection string usually just breaks type validation, not SQL.
    return [k for k, v in data.items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)]


def _mutate_json_param(body: str, param: str, payload: str) -> str | None:
    try:
        data = _json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or param not in data:
        return None
    mutated = dict(data)
    mutated[param] = payload
    return _json.dumps(mutated)


def _form_top_level_params(body: str) -> list[str]:
    return [k for k, _ in parse_qsl(body, keep_blank_values=True)]


def _mutate_form_param(body: str, param: str, payload: str) -> str | None:
    pairs = parse_qsl(body, keep_blank_values=True)
    if not any(k == param for k, _ in pairs):
        return None
    return urlencode([(k, payload if k == param else v) for k, v in pairs])


# Field names that carry an anti-CSRF / anti-forgery token. Such a token is
# session-bound and often single-use, so a captured value is stale on replay --
# a login-bypass probe must fetch a FRESH one in-session before each attempt.
_CSRF_FIELD_TOKENS = ("csrf", "xsrf", "authenticity", "antiforgery", "anti-forgery",
                      "_token", "__requestverificationtoken", "nonce")


def _csrf_field_name(body: str, content_type: str) -> str | None:
    """The form field holding an anti-CSRF token, if the urlencoded body has one."""
    if not body or _looks_like_json(body, content_type):
        return None
    for key, _ in parse_qsl(body, keep_blank_values=True):
        low = key.lower()
        if any(tok in low for tok in _CSRF_FIELD_TOKENS):
            return key
    return None


def _extract_token(html: str, field: str) -> str | None:
    """Read a fresh token value for `field` from a form page's HTML."""
    from harness.feature_workflow import extract_forms
    for form in extract_forms(html or "", ""):
        for fld in form.fields:
            if fld.name == field and fld.value:
                return fld.value
    m = re.search(rf'name=["\']{re.escape(field)}["\'][^>]*value=["\']([^"\']+)', html or "")
    if m:
        return m.group(1)
    m = re.search(rf'value=["\']([^"\']+)["\'][^>]*name=["\']{re.escape(field)}["\']', html or "")
    return m.group(1) if m else None


def _query_top_level_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def _mutate_query_param(url: str, param: str, payload: str) -> str | None:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(k == param for k, _ in pairs):
        return None
    new_query = urlencode([(k, payload if k == param else v) for k, v in pairs])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def _content_type_of(exchange: HttpExchange) -> str:
    return next((v for k, v in exchange.request_headers.items() if k.lower() == "content-type"), "")


def _inferred_content_type_for_body(body: str, existing_ct: str) -> str | None:
    """Return the Content-Type a JSON/form-shaped body needs, or None.

    Found live (Juice Shop full run, sqlmap 0/26 diagnosis): the captured
    exchanges carried request_headers={} -- no Content-Type. Both the probe
    below and sqlmap replay the captured headers verbatim, so a JSON body was
    sent with NO Content-Type. Express's express.json() only parses a body
    when Content-Type is application/json, so req.body came back empty, the
    login SQL saw no email/password at all, and every payload returned an
    identical 401 -- making the tautology and contradiction indistinguishable
    and the injection point silently untestable. Returns the header to add
    ONLY when the body clearly needs one and none is already present; a body
    that already declares a content-type is left exactly as captured.
    """
    if not body or existing_ct.strip():
        return None
    stripped = body.lstrip()
    if stripped[:1] in ("{", "["):
        return "application/json"
    # A urlencoded form body: key=value pairs, no JSON braces. Kept narrow
    # (must contain '=') so arbitrary opaque bodies aren't mislabeled.
    if "=" in body:
        return "application/x-www-form-urlencoded"
    return None


def _responses_differ(resp_a: httpx.Response, resp_b: httpx.Response) -> bool:
    """Boolean-blind confirmation signal, generalized beyond auth
    endpoints: a status-code difference is always meaningful; otherwise
    (most non-auth endpoints return 200 regardless of the injected
    predicate) fall back to a relative response-length delta, the
    standard boolean-blind technique when there's no simple success/
    failure status code to key off. The >20-byte absolute floor avoids
    flagging noise (a timestamp, a nonce) on very small responses as a
    false differential.
    """
    if resp_a.status_code != resp_b.status_code:
        return True
    len_a, len_b = len(resp_a.content), len(resp_b.content)
    if len_a == 0 and len_b == 0:
        return False
    delta = abs(len_a - len_b)
    return delta > 20 and delta / max(len_a, len_b, 1) > 0.05


# Error-based signal, complementary to the boolean-blind differential
# above -- found necessary live, against a real target: Juice Shop's
# product search (`GET /rest/products/search?q=`) wraps the parameter in
# a LIKE '%...%' clause, where an unprefixed OR-based tautology/contradiction
# pair was not a true/false differential at all (the unconditional
# `LIKE '%'` half of the OR already matches everything, so both the
# "true" and "false" injected predicates return identical results -- a
# real, confirmed injection point that the boolean-blind check alone
# would have reported as not_confirmed). An unclosed quote or broken
# UNION reliably surfaces as a raw DB error message regardless of how the
# value is wrapped (exact match, LIKE, or otherwise), which is exactly
# why agents/sqli_agent.py's own prompt lists this as its first-choice
# signal. Markers are deliberately generic engine/error strings, not
# tied to one database.
_DB_ERROR_MARKERS = (
    "sql syntax", "sqlite_error", "sqlite3.", "you have an error in your sql syntax",
    "unclosed quotation mark", "ora-01756", "ora-00933", "pg::syntaxerror",
    "sqlstate", "odbc sql server driver", "npgsql", "sequelize",
)


def _text_has_db_error_markers(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _DB_ERROR_MARKERS)


def _looks_like_db_error(resp: httpx.Response) -> bool:
    try:
        text = resp.text
    except Exception:
        return False
    return _text_has_db_error_markers(text)


# Credential field names and auth-shaped path segments. Used ONLY to recognise an
# authentication attempt so sqlmap is told to keep analysing the auth-rejection
# response instead of skipping it (see _looks_like_auth_request / the --ignore-code
# block). Segment-exact path matching (not substring) so "author"/"passenger" don't
# false-match "auth"/"pass".
_CREDENTIAL_FIELDS = {"password", "passwd", "pwd", "pass", "secret", "otp", "pin",
                      "credential", "credentials", "current_password", "new_password"}
_AUTH_PATH_SEGMENTS = {"login", "signin", "sign-in", "logon", "authenticate",
                       "authentication", "auth", "session", "sessions", "token",
                       "oauth", "oauth2"}
# HTTP codes an authentication endpoint returns when a payload breaks the
# credential predicate. These are the boolean-blind signal on a valid-cred (2xx)
# login capture, but sqlmap treats them as "target not testable" unless ignored.
_AUTH_REJECTION_CODES = ("401", "403")


def _looks_like_auth_request(exchange: HttpExchange) -> bool:
    """Whether this exchange is an authentication attempt -- a credential field in
    the body/query, or an auth-shaped path. Such an endpoint captured with a
    SUCCESSFUL (2xx) baseline (valid credentials) flips to 401/403 the moment a
    payload alters the credential predicate; that auth-rejection code IS the
    boolean-blind true/false signal, but sqlmap's default is to treat any non-2xx
    response as "not authorized to test" and skip -- so a real login injection
    stays unconfirmed. HANDOVER_6 §3/§6.3."""
    body = exchange.request_body or ""
    ct = _content_type_of(exchange)
    names: set[str] = set()
    if body:
        if _looks_like_json(body, ct):
            names.update(n.lower() for n in _json_top_level_params(body))
        else:
            names.update(n.lower() for n in _form_top_level_params(body))
    names.update(n.lower() for n in _query_top_level_params(exchange.url))
    if names & _CREDENTIAL_FIELDS:
        return True
    path = (urlsplit(exchange.url).path or "").lower()
    return any(seg in _AUTH_PATH_SEGMENTS for seg in path.split("/") if seg)


# Ticket 2B: sqlmap's own report of WHERE it found injection. The block starts with
# "sqlmap identified|resumed the following injection point(s)" and holds, per
# parameter, a "Parameter: <name> (<place>)" line followed by repeated
# Type/Title/Payload lines.
_POINTS_HEADER_RE = re.compile(r"sqlmap (?:identified|resumed) the following injection point", re.I)
_POINT_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>.+)\)\s*$")
_POINT_FIELD_RE = re.compile(r"^(?P<key>Type|Title|Payload):\s*(?P<value>.*)$", re.I)
_HEADER_PLACES = frozenset({"user-agent", "referer", "host", "x-forwarded-for", "x-forwarded-host"})
# Where the harness's boolean differential can mutate a parameter (see
# _boolean_probe_fallback's only_params).
_DIFFERENTIAL_LOCATIONS = ("query", "body_form", "body_json")
_MAX_REPRODUCED_POINTS = 3
_MAX_LISTED_POINTS = 8
_PAYLOAD_LINE_CAP = 200
_TAIL_MARKER = "--- sqlmap output (tail) ---"


def _point_location(place: str, name: str) -> tuple[str, str]:
    """(harness parameter location, parameter name) for sqlmap's "(place)" label and
    its parameter name ("JSON email" is the JSON body field "email")."""
    label = place.strip().lower()
    if label == "get":
        return "query", name
    if label == "post":
        return "body_form", name
    if label == "(custom) post":
        return "body_json", name[5:].strip() if name[:5].lower() == "json " else name
    if label == "uri":
        return "path", name
    if label == "cookie":
        return "cookie", name
    if label in _HEADER_PLACES or label.startswith("x-"):
        return "header", name
    return label, name


def parse_injection_points(output: str) -> list[dict]:
    """The injection points sqlmap reported in its output: one dict per
    (parameter, type) with place (the harness's parameter location), parameter,
    type, title and payload. Missing lines leave "" and Windows line endings are
    fine. [] when the output has no injection-point block."""
    points: list[dict] = []
    in_block = False
    param: tuple[str, str] | None = None
    entry: dict | None = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if _POINTS_HEADER_RE.search(line):
            in_block, param, entry = True, None, None
            continue
        if not in_block:
            continue
        if line.startswith("[") and "] [" in line[:30]:
            in_block, param, entry = False, None, None   # a log line ends the block
            continue
        found = _POINT_PARAM_RE.match(line)
        if found:
            param, entry = _point_location(found.group("place"), found.group("name").strip()), None
            continue
        field = _POINT_FIELD_RE.match(line)
        if field is None or param is None:
            continue
        key, value = field.group("key").lower(), field.group("value").strip()
        # A Type line, or a Title/Payload that repeats one this entry already has,
        # starts a new entry for the parameter.
        if entry is None or key == "type" or entry[key]:
            entry = {"place": param[0], "parameter": param[1], "type": "", "title": "", "payload": ""}
            points.append(entry)
        entry[key] = value
    unique: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for point in points:
        ident = (point["place"], point["parameter"], point["type"])
        if ident not in seen:
            seen.add(ident)
            unique.append(point)
    return unique


def _point_label(point: dict) -> str:
    return f"{point['place']}:{point['parameter']}"


def _points_evidence(points: list[dict], tail: str, differential: str = "") -> str:
    """The evidence of a sqlmap confirmation: what it found where, then its payloads
    (and the harness's own differential, when it reproduced one), then the output
    tail (callers keep only the first 1000 characters)."""
    if not points:
        return tail
    listed = points[:_MAX_LISTED_POINTS]
    lines = [f"injection point: {_point_label(p)} — {p['type'] or 'injection'}"
             + (f" ({p['title']})" if p["title"] else "") for p in listed]
    lines += [f"payload ({_point_label(p)}): {p['payload'][:_PAYLOAD_LINE_CAP]}"
              for p in listed if p["payload"]]
    if differential:
        lines.append(f"harness differential: {differential}")
    return "\n".join(lines) + f"\n{_TAIL_MARKER}\n" + tail


# sqlmap's own conclusions: its warning/critical/error lines and any line about
# injectability. The decision lines come LAST in its output, after an early
# "heuristics detected ... WAF/IPS" line, so a head-truncated copy (the ledger keeps
# 1000 characters) lost the verdict on every not-confirmed run of the 8h juice-shop run.
_VERDICT_LINE = re.compile(r"\[(?:WARNING|CRITICAL|ERROR)\]|injectable|is vulnerable", re.I)
_LOG_TIME = re.compile(r"^\s*\[\d{2}:\d{2}:\d{2}\]\s*")
_VERDICT_MARKER = "sqlmap verdict:"
_MAX_VERDICT_LINES = 6
_VERDICT_LINE_CAP = 160


def verdict_lines(output: str) -> list[str]:
    """sqlmap's last few distinct verdict lines, oldest first, without timestamps."""
    picked: list[str] = []
    for line in reversed((output or "").splitlines()):
        if not _VERDICT_LINE.search(line):
            continue
        text = _LOG_TIME.sub("", line).strip()[:_VERDICT_LINE_CAP]
        if text and text not in picked:
            picked.append(text)
            if len(picked) == _MAX_VERDICT_LINES:
                break
    return picked[::-1]


def _verdict_evidence(output: str) -> tuple[str, str]:
    """(evidence, limitation) for a run sqlmap did not confirm: the parsed verdict
    lines first, so any head-truncated copy keeps them, then the output tail."""
    lines = verdict_lines(output)
    if not lines:
        return output, ""
    return (f"{_VERDICT_MARKER}\n" + "\n".join(lines) + f"\n{_TAIL_MARKER}\n" + output,
            "sqlmap: " + "; ".join(lines))


class SqlmapValidator(Validator):
    """Optional active SQLi validator.

    sqlmap is deliberately treated as a validator, not as an autonomous
    scanner. The LLM identifies a hypothesis; this adapter supplies the
    captured request and a tightly bounded, analyst-enabled invocation.
    No model-generated command line or URL is ever executed.
    """
    name = "sqlmap"
    finding_classes = {"sqli", "sql injection"}
    active = True

    def __init__(self, binary: str = "sqlmap", timeout_seconds: int = 90,
                 level: int = 1, risk: int = 1, container_image: str | None = None,
                 run_context=None, allowed_hosts: list[str] | None = None,
                 quick_only: bool = False):
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.level = max(1, min(level, 2))
        self.risk = max(1, min(risk, 2))
        # Safety item #12: sqlmap is the highest-risk active leg (it fuzzes the
        # target with many requests). It previously had NO scope check -- it ran
        # against exchange.url whatever the host was, trusting the caller to only
        # ever hand it in-scope exchanges. Enforce scope here too (defense in
        # depth): an off-scope host is refused before any sqlmap process starts.
        self.allowed_hosts = allowed_hosts or []
        # When set (and the docker daemon is up), sqlmap runs in a throwaway
        # container instead of on the host -- so the offensive tool never touches
        # host disk (where Defender quarantines it) and its version is pinned to
        # the image. The loopback target is rewritten to host.docker.internal so
        # the container reaches the same service the host means by localhost.
        self.container_image = container_image
        self.run_context = run_context
        self.quick_only = bool(quick_only)

    @staticmethod
    def _raw_request(exchange: HttpExchange) -> str:
        parts = urlsplit(exchange.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{exchange.method.upper()} {path} HTTP/1.1"]
        host = parts.netloc
        saw_host = False
        for k, v in exchange.request_headers.items():
            if k.lower() == "host":
                saw_host = True
            lines.append(f"{k}: {v}")
        if not saw_host and host:
            lines.append(f"Host: {host}")
        lines.append("")
        lines.append(exchange.request_body or "")
        return "\r\n".join(lines)

    def plan(self, finding: Finding, exchange: HttpExchange) -> TestPlan | None:
        if not self.applies(finding, exchange):
            return None
        return TestPlan(
            id=f"sqlmap:{finding.vulnerability_class}:{exchange_fingerprint(exchange)[:20]}",
            capability="sql_injection_validation",
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class) or "sqli",
            source_exchange_url=exchange.url,
            mutation={"strategy": "validate-captured-request", "target": "captured-request"},
            success_signals=["tool reports an injectable parameter", "tool identifies exploitable SQL injection"],
            requires_approval=True, execution_plane="local_tool",
            rationale="Use the original captured request; never use a model-generated URL or command.",
            source_exchange_hash=exchange_fingerprint(exchange),
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if not self.applies(finding, exchange):
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary="validator does not apply")
        if not exchange.url.startswith(("http://", "https://")):
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary="unsupported URL scheme")

        # Safety item #12: refuse an off-scope host before launching sqlmap.
        from harness import scope_lock
        if not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=scope_lock.out_of_scope_reason(exchange.url, self.allowed_hosts))

        # Per-parameter dispatch (coverage case driver): test the named parameter
        # alone, so a clean result is bound to it and to nothing else.
        only = None
        if getattr(finding, "parameter_only", False):
            from .injection_targets import NAMED_PARAMETER_UNTESTED  # (cycle: it imports us)
            loc = (finding.parameter_location or "").strip().lower()
            name = (finding.parameter_name or "").strip()
            present = (_query_top_level_params(exchange.url) if loc == "query" else
                       _form_top_level_params(exchange.request_body or "")
                       if loc == "body_form" and not _looks_like_json(
                           exchange.request_body or "", _content_type_of(exchange)) else [])
            if name not in present:
                return ValidationResult(
                    self.name, "skipped", finding.vulnerability_class,
                    summary=f"the {loc or 'unnamed'} parameter {name!r} is not a query or form "
                            "parameter of the replayed request, so it was not tested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
            only = [(loc, name)]

        if exchange.method.upper() != "GET":
            # sqlmap fuzzes a parameter by sending many requests with
            # different payloads to the SAME endpoint via the SAME
            # method. If that endpoint is a real mutating action (a
            # checkout, a transfer, a coupon redemption), sqlmap will
            # fire that real action repeatedly while fuzzing -- no
            # destructive SQL payload (DROP TABLE etc.) is required for
            # this to cause real harm, just the sheer repetition against
            # a live mutating endpoint. GET is exempted because it's
            # the one method HTTP semantics itself says shouldn't have
            # side effects; anything else requires the same explicit,
            # separate opt-in the rest of this harness's mutating-replay
            # techniques require.
            gate = self.run_context.gate if self.run_context is not None else get_default_gate()
            gate_decision = gate.authorize(
                validator_name=self.name, method=exchange.method, url=exchange.url,
                body=exchange.request_body,
            )
            if not gate_decision.allowed:
                return ValidationResult(
                    self.name, "blocked", finding.vulnerability_class,
                    summary=f"Blocked by safety gate: {gate_decision.reason} "
                            f"(sqlmap would fuzz a {exchange.method.upper()} endpoint, sending many "
                            f"requests to what may be a real mutating action)",
                )

        # A two-request boolean differential is both cheaper and more tightly
        # bounded than launching sqlmap. Run it first for parameterized GETs;
        # if it proves injection, avoid the heavier tool entirely. If it is
        # inconclusive, retain the existing sqlmap path for broader techniques.
        # This also keeps external authorized targets testable when a container
        # runtime's network policy cannot route directly to that hostname.
        if exchange.method.upper() == "GET":
            quick = await self._boolean_probe_fallback(finding, exchange, only_params=only)
            if quick is not None and quick.confirmed:
                quick.summary = "Bounded boolean preflight confirmed SQL injection: " + quick.summary
                return quick
            if self.quick_only:
                return quick or ValidationResult(
                    self.name, "not_confirmed", finding.vulnerability_class,
                    summary="bounded boolean preflight found no injectable parameter",
                )

        # I05-C: sqlmap is a separate process with its own traffic. Inside a run it
        # launches only while that run could still send: not cancelled, budget left,
        # URL in the run's scope. The run's cancel token then reaches the process.
        run = self.run_context
        refusal = None
        if run is not None:
            remaining = run.budget.remaining
            if run.cancel.cancelled:
                refusal = "the run was cancelled"
            elif remaining is not None and remaining <= 0:
                refusal = "the run's request budget is exhausted"
            elif not run.scope.in_scope(exchange.url):
                refusal = "the URL is outside the run's scope"
        if refusal:
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"sqlmap not launched: {refusal}")
        _cancel = run.cancel if run is not None else None

        with tempfile.TemporaryDirectory(prefix="harness-sqlmap-") as td:
            # Keep the raw request text around as an audit artifact (it's
            # what the original design intended an analyst to be able to
            # inspect), but invoke sqlmap with explicit -u/-H/--data flags
            # rather than `-r <file>`. Verified directly against a live
            # target (OWASP Juice Shop): `-r <file>` with this exact
            # request content silently matched zero targets and exited
            # instantly with no injection attempts and no error -- with
            # the request's content byte-for-byte identical fed via -u/
            # --data/-H instead, sqlmap correctly parsed it, tested it,
            # and found a real, confirmed injection. The `-r` failure
            # mode is unexplained (isolated it to request-file parsing
            # specifically, not to --ignore-code, --smart, or Content-
            # Length) and is a known-broken path in the sqlmap version
            # available here (1.8.4) rather than something worth working
            # around blindly -- -u/-H/--data is the standard, most-tested
            # sqlmap invocation shape, so prefer it outright.
            request_file = Path(td) / "request.txt"
            request_file.write_text(self._raw_request(exchange), encoding="utf-8")

            cmd = [self.binary, "-u", exchange.url, "--batch",
                   "--level", str(self.level), "--risk", str(self.risk),
                   "--threads", "1", "--timeout", "10", "--retries", "1",
                   "--flush-session", "--disable-coloring"]
            if only:
                cmd += ["-p", only[0][1]]
            # Deliberately no --smart: verified directly against a live
            # target (OWASP Juice Shop's login endpoint, a genuinely
            # injectable, well-known case) that --smart's cheap "is this
            # parameter dynamic" heuristic incorrectly judges a real JSON
            # boolean-blind injection point as not worth testing, and
            # skips it -- a false negative on exactly the kind of finding
            # this validator exists to confirm. --smart trades completeness
            # for fewer requests; for a single bounded, analyst-approved
            # confirmatory run (not a broad unattended crawl), a missed
            # real vulnerability is a worse failure than a few extra
            # seconds of testing.
            if exchange.request_body:
                cmd += ["--data", exchange.request_body]
            if exchange.method.upper() not in ("GET", "POST"):
                cmd += ["--method", exchange.method.upper()]
            for k, v in exchange.request_headers.items():
                if k.lower() in ("host", "content-length"):
                    continue  # sqlmap derives these itself from -u/--data
                cmd += ["-H", f"{k}: {v}"]
            # If the capture lacked a Content-Type but the body is JSON/form-
            # shaped, add it explicitly so the server actually parses the body
            # sqlmap is injecting into (same root cause as the probe fix above;
            # sqlmap's own JSON auto-detection is reliable but this makes the
            # invocation correct regardless of it).
            _inferred_ct = _inferred_content_type_for_body(
                exchange.request_body or "", _content_type_of(exchange)
            )
            if _inferred_ct is not None:
                cmd += ["-H", f"Content-Type: {_inferred_ct}"]
            ignore_codes: list[str] = []
            if exchange.response_status is not None and not (200 <= exchange.response_status < 300):
                # Verified against a live target (OWASP Juice Shop's login
                # endpoint, which returns 401 for invalid credentials --
                # the normal, expected baseline response): without this,
                # sqlmap's default behavior is to treat ANY non-2xx
                # response as "not authorized to test this target" and
                # skip it entirely, producing zero injection attempts and
                # no error -- indistinguishable from "tested, not
                # injectable" unless you read the raw output closely. Any
                # endpoint whose normal/expected response is non-2xx
                # (failed auth attempts, permission-gated endpoints, etc.)
                # would silently never be tested. Ignoring the exchange's
                # OWN baseline status code (rather than hardcoding 401) is
                # the general form of this fix: it tells sqlmap "this is
                # this endpoint's normal response," not "ignore all
                # errors everywhere."
                ignore_codes.append(str(exchange.response_status))
            if _looks_like_auth_request(exchange):
                # The other half of the same problem (HANDOVER_6 §3/§6.3): a login
                # captured with VALID credentials has a 2xx baseline, so the branch
                # above never fires -- yet sqlmap's injection payloads break the
                # credential predicate and get 401/403, which sqlmap then skips as
                # "target not testable." The 2xx-vs-401 flip IS the boolean-blind
                # signal; tell sqlmap those auth-rejection codes are valid responses
                # to analyse. Scoped to credential/auth-shaped requests, not a
                # blanket ignore-all. `--ignore-code` accepts a comma list (verified
                # against the pinned image).
                for code in _AUTH_REJECTION_CODES:
                    if code not in ignore_codes:
                        ignore_codes.append(code)
                if exchange.response_status is not None and 200 <= exchange.response_status < 300:
                    # live-v8: a successful login answers with a per-request token, so
                    # two identical requests differ in content and sqlmap's stability
                    # check passes or fails by timing. Failed, it compares page content
                    # and never reads the 2xx-vs-401 flip (v8, 191 requests, nothing
                    # found); passed, it picks --code itself (v7). Naming the success
                    # status makes the flip the comparison either way.
                    cmd += ["--code", str(exchange.response_status)]
            if ignore_codes:
                cmd += ["--ignore-code", ",".join(ignore_codes)]

            # Defense in depth, independent of the level/risk clamping in
            # __init__: assert none of sqlmap's destructive/exfiltration
            # flags are present in the final command, regardless of how
            # cmd got built. This exists so a future edit to this method
            # that adds a flag without realizing its implications fails
            # loudly here rather than silently shipping a validator that
            # can dump a database or open a shell on the target. See
            # test_safety_gate.py's test_sqlmap_command_never_contains_
            # destructive_flags for the corresponding test.
            _DENIED_SQLMAP_FLAGS = (
                "--dump", "--dump-all", "--os-shell", "--os-pwn", "--os-cmd",
                "--sql-shell", "--file-write", "--file-dest", "--file-read",
                "--reg-read", "--reg-add", "--reg-del", "--privesc",
            )
            # NOTE: these are `if ... raise`, NOT `assert`. A safety invariant must
            # never be a Python assert -- `python -O` strips assert statements, which
            # would silently remove the only guard stopping a --dump/--os-shell from
            # reaching the target. RuntimeError always runs regardless of -O.
            for denied in _DENIED_SQLMAP_FLAGS:
                if denied in cmd:
                    raise RuntimeError(
                        f"Refusing to run sqlmap: denied flag {denied!r} present in constructed "
                        f"command. This is a hard-coded safety invariant, not a config option.")
            if self.risk > 2:
                raise RuntimeError(f"Refusing to run sqlmap: risk={self.risk} exceeds the hard ceiling of 2.")
            if self.level > 2:
                raise RuntimeError(f"Refusing to run sqlmap: level={self.level} exceeds the hard ceiling of 2.")

            # Container mode: wrap the (already safety-checked) sqlmap args in a
            # `docker run --rm` and rewrite the -u target to host.docker.internal.
            # The safety-flag assertions above ran on the raw sqlmap `cmd`, so the
            # denied-flag invariant holds regardless of how the process is spawned.
            # I05: inside a run sqlmap never sees the real target. It is pointed at a
            # loopback proxy that replays each of its requests through the run --
            # budget, scope, gate, cancellation, TLS -- so its own traffic is counted,
            # and the run's budget running out stops it. `cmd` keeps the real target
            # as the record of what was tested; only the launched argv is proxied.
            proxy = None
            launch_cmd = cmd
            if run is not None:
                from harness.tool_proxy import ToolProxy
                proxy = await ToolProxy(run, exchange.url, capability="sqlmap_tool").start()
                launch_cmd = list(cmd)
                launch_cmd[launch_cmd.index("-u") + 1] = proxy.url_for(exchange.url)
                _cancel = lambda: run.cancel.cancelled or proxy.stop_requested  # noqa: E731
            run_cmd = launch_cmd
            _use_container = False
            _container_args: list[str] = []
            _egress_policy = None
            _tool_receipt: dict = {}
            if self.container_image:
                from harness import tool_runner
                if tool_runner.available()[0]:
                    _use_container = True
                    _container_args = list(launch_cmd[1:])  # drop self.binary; the image entrypoint IS sqlmap
                    for i in range(1, len(_container_args)):
                        if _container_args[i - 1] == "-u":
                            _container_args[i] = tool_runner.localhost_url(_container_args[i])
                    # PR-11/R02: a containerised sqlmap makes its OWN outbound
                    # requests, so this run's egress is constrained by a per-run
                    # EgressPolicy (the container should only reach the in-container
                    # host alias the target was rewritten to), it FAILS CLOSED if
                    # that control is unavailable, and it goes through
                    # tool_runner.run's force-clean wrapper -- a Python-side timeout
                    # does not bound container activity -- rather than a bare
                    # docker_cmd + subprocess.run.
                    _egress_policy = tool_runner.EgressPolicy(
                        allowed_hosts=(tool_runner._HOST_ALIAS,))
                    run_cmd = tool_runner.docker_cmd(
                        self.container_image, _container_args, egress=_egress_policy)

            try:
                if _use_container:
                    from harness import tool_runner
                    # I05-C: cancellable -- a cancelled run or task stops the CLI tree
                    # and removes the exact container before this returns.
                    rc, out, err = await tool_runner.call_cancellable(
                        tool_runner.run,
                        self.container_image,
                        _container_args,
                        timeout=self.timeout_seconds,
                        egress=_egress_policy,
                        enforce_egress=True,
                        receipt=_tool_receipt,
                        cancel=_cancel,
                    )
                    proc = subprocess.CompletedProcess(
                        _tool_receipt.get("argv", run_cmd), rc, out, err)
                else:
                    from harness import tool_runner
                    # I05-C: an owned process tree with bounded output, stopped as a
                    # whole on cancel/timeout. stdin is DEVNULL there: sqlmap can block
                    # on a stdin read even with --batch (verified: it hung silently
                    # until the timeout, indistinguishable from a slow scan).
                    proc = await tool_runner.call_cancellable(
                        tool_runner.run_process,
                        run_cmd,
                        timeout=self.timeout_seconds,
                        env=os.environ.copy(),
                        cancel=_cancel,
                    )
            except FileNotFoundError:
                # sqlmap is an optional, heavier dependency -- don't let its
                # absence silently mean "SQL injection can never be
                # actively confirmed on this machine." Found live, this
                # session: sqlmap wasn't installed at all, so every SQLi
                # confirmation attempt (including one against a request
                # that already carried a real, working injection payload)
                # failed with this exact error, and every sqli finding
                # stayed confirmed=False all session with no visible sign
                # why. Fall back to a lightweight, dependency-free boolean-
                # differential probe over every query/body parameter
                # (not just auth fields -- see _boolean_probe_fallback's
                # own docstring) rather than doing nothing.
                fallback = await self._boolean_probe_fallback(finding, exchange, only_params=only)
                if fallback is not None:
                    return fallback
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary="sqlmap executable not found; install sqlmap for full active SQLi "
                                                "validation (a lightweight boolean-probe fallback also ran and did "
                                                "not apply to this exchange -- no query or body parameters to mutate)",
                                        command=cmd)
            except subprocess.TimeoutExpired as exc:
                # Found live, against a real target: subprocess.run's
                # TimeoutExpired can carry .stdout/.stderr as bytes even
                # though the call passed text=True -- confirmed by
                # triggering a genuine sqlmap timeout (a slower, more
                # thorough level=2 scan against a real target legitimately
                # exceeded the configured timeout), which this exception
                # handler had never been exercised against before: every
                # prior real run either completed within the timeout or
                # hit a different exception path. The str+bytes
                # concatenation below crashed outright, turning a normal
                # "sqlmap took too long" outcome into an unhandled
                # TypeError instead of the intended graceful ValidationResult.
                # _decode() below normalizes either type to str so this
                # can't happen regardless of which form subprocess hands
                # back for a given Python/OS combination.
                def _decode(x) -> str:
                    if x is None:
                        return ""
                    if isinstance(x, bytes):
                        return x.decode("utf-8", errors="replace")
                    return x
                partial = (_decode(exc.stdout) + "\n" + _decode(exc.stderr))[-4000:]
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary=f"sqlmap timed out after {self.timeout_seconds}s",
                                        evidence=partial, raw_output=partial, command=cmd)
            except Exception as exc:
                from harness import tool_runner
                if isinstance(exc, tool_runner.ToolCleanupFailed):
                    raise   # never report a clean result while sqlmap may still run
                if isinstance(exc, tool_runner.ToolRunCancelled):
                    why = ("the run's request budget is exhausted "
                           f"({proxy.forwarded} sqlmap request(s) were sent through the run)"
                           if proxy is not None and proxy.stop_reason == "budget_exhausted"
                           else _PROXY_STOP_WHY.get(proxy.stop_reason if proxy is not None else "",
                                                    "the run was cancelled"))
                    return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                            summary=f"sqlmap stopped: {why}", command=cmd)
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary=f"sqlmap execution failed: {exc}", command=cmd)
            finally:
                if proxy is not None:
                    await proxy.close()

            output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-12000:]
            lower = output.lower()
            confirmed = proc.returncode == 0 and "is vulnerable" in lower
            if confirmed:
                return await self._sqlmap_confirmation(finding, exchange, output, cmd)
            verdict_evidence, verdict = _verdict_evidence(output)
            if proxy is not None and proxy.stop_reason:
                # The run refused part of the scan: an incomplete scan is not a negative.
                why = _PROXY_STOP_WHY.get(proxy.stop_reason, "the run was cancelled")
                return ValidationResult(
                    self.name, "skipped", finding.vulnerability_class,
                    summary=f"sqlmap incomplete: {why} after {proxy.forwarded} request(s) "
                            "were sent through the run -- not a negative result",
                    evidence=verdict_evidence, raw_output=output, command=cmd, limitation=verdict)
            # Secondary confirmation for auth/login endpoints (HANDOVER_6 §3/§6.3):
            # sqlmap's own analysis is fragile on a valid-cred (2xx) login capture
            # even with --ignore-code, because it must infer the 2xx<->401 flip
            # through its heuristics. The dependency-free boolean-differential probe
            # reads that flip DIRECTLY (tautology -> 200, contradiction -> 401), so
            # run it as a fallback and prefer a real CONFIRMED over sqlmap's miss.
            # Bounded to auth-shaped requests so a normal not_confirmed doesn't pay
            # for extra probes. The mutating method (if any) was already authorised
            # by the safety gate above before sqlmap ran.
            if _looks_like_auth_request(exchange):
                secondary = await self._boolean_probe_fallback(finding, exchange, only_params=only)
                if secondary is not None and secondary.confirmed:
                    secondary.summary = ("sqlmap did not confirm, but a boolean-differential probe did "
                                         "(auth endpoint): " + secondary.summary)
                    secondary.raw_output = (secondary.raw_output or "") + "\n\n--- sqlmap output ---\n" + output
                    return secondary
            if only and "not present within" in lower:
                # A `-p` sqlmap could not find tested nothing: never a negative.
                return ValidationResult(
                    self.name, "inconclusive", finding.vulnerability_class,
                    summary=f"sqlmap did not find parameter {only[0][1]!r} to test "
                            "-- not a negative result",
                    evidence=verdict_evidence, raw_output=output, command=cmd,
                    control_outcome=NAMED_PARAMETER_UNTESTED, limitation=verdict)
            return ValidationResult(
                self.name, "not_confirmed", finding.vulnerability_class,
                confidence=0.2 if proc.returncode == 0 else 0.0,
                confirmed=False,
                summary="sqlmap did not establish SQL injection for the captured request"
                        + (f" ({verdict_lines(output)[-1]})" if verdict else ""),
                evidence=verdict_evidence, raw_output=output, command=cmd, limitation=verdict,
            )

    async def _sqlmap_confirmation(self, finding: Finding, exchange: HttpExchange,
                                   output: str, cmd: list[str]) -> ValidationResult:
        """The confirmation for a sqlmap that reported the target injectable (Ticket 2B).

        sqlmap stays the authority for the verdict. Its injection points lead the
        evidence, and each boolean-based point the harness can mutate (up to
        _MAX_REPRODUCED_POINTS) is replayed through the boolean differential
        restricted to that parameter. The first one that reproduces gives the result
        the differential's baseline/attack/control artifacts; otherwise the result is
        marked tool-reported and names no exchanges, so its proof stays a candidate."""
        points = parse_injection_points(output)
        result = ValidationResult(
            self.name, "confirmed", finding.vulnerability_class,
            confidence=0.98, confirmed=True,
            summary="sqlmap independently reported the target as injectable",
            evidence=_points_evidence(points, output), raw_output=output, command=cmd,
            injection_points=tuple(points),
        )
        eligible = [p for p in points
                    if "boolean" in p["type"].lower() and p["place"] in _DIFFERENTIAL_LOCATIONS]
        for point in eligible[:_MAX_REPRODUCED_POINTS]:
            repro = await self._boolean_probe_fallback(
                finding, exchange, only_params=[(point["place"], point["parameter"])])
            if repro is None or not repro.confirmed:
                continue
            result.summary = (f"sqlmap reported injection at {_point_label(point)} ({point['type']}); "
                              "the harness reproduced a true/false differential on the same parameter")
            result.evidence = _points_evidence(points, output, repro.evidence)
            return result.with_artifacts(
                baseline=repro.baseline_artifact_id, attack=repro.attack_artifact_id,
                controls=repro.control_artifact_ids)
        result.summary = "tool-reported, not reproduced by the harness: " + result.summary
        return result

    # Cap on how many parameters this fallback probes per exchange -- this
    # is a bounded, opt-in active check (same philosophy as
    # recon_validator.py's own request caps and scope_discovery.py's
    # max_new_requests_per_trigger), not an unattended full-surface scan.
    # Query-string params are tried before body params: a GET-style
    # id/filter/search param is at least as common an injection point as
    # anything in a POST body, and this ordering means a cheap, common
    # case doesn't get starved out by a body with many unrelated fields.
    _MAX_PROBE_PARAMS = 5

    async def _boolean_probe_fallback(
        self, finding: Finding, exchange: HttpExchange,
        only_params: list[tuple[str, str]] | None = None,
    ) -> ValidationResult | None:
        """Dependency-free confirmation for SQL injection when sqlmap isn't
        installed. NOT limited to credential/auth fields -- SQLi is not an
        auth-only bug class (see agents/sqli_agent.py's own prompt: id,
        sort/filter, search-box parameters are at least as common a real
        injection point). Enumerates query-string parameters and top-level
        JSON/form body parameters (capped at _MAX_PROBE_PARAMS total), and
        for each sends two requests (four when they differ: the pair is
        repeated in reverse order, BM-2), identical to the original
        exchange except for that one parameter's value:

          A (tautology):  <marker>' OR '1'='1' --   -- true whatever the field holds
          B (contradiction): <marker>' OR '1'='2' -- -- same syntax, false predicate

        <marker> is a fresh random token shared by A and B. Without it B reduces
        to `field = ''`, which a stored empty value matches: live-v8's target
        held an account registered with an empty email, so both probes logged in.

        Confirmation is a response differential between A and B: a status-
        code difference is always meaningful; otherwise (most non-auth
        endpoints return 200 regardless of the injected predicate) a
        relative response-length delta is used instead, the standard
        boolean-blind signal when there's no simple success/failure status
        code to key off (see _responses_differ). This is the textbook
        definition of confirmed boolean-blind injection: the same syntax
        with the truth value flipped changes the outcome, so it isn't the
        syntax alone (a broken query would fail both identically) that
        changed it.

        `only_params` ((location, name) pairs with location query, body_form or
        body_json) restricts the candidates to those parameters, so a tool's
        reported injection point is replayed without probing the others.

        Returns None (not a ValidationResult) when there are no query or
        body parameters to mutate at all -- the caller falls back to a
        plain "sqlmap not found" error in that case, since this probe's
        scope is deliberately bounded, not a full sqlmap replacement.
        """
        content_type = _content_type_of(exchange)
        body = exchange.request_body or ""

        candidates: list[tuple[str, str]] = [("query", p) for p in _query_top_level_params(exchange.url)]
        body_kind = None
        if body:
            if _looks_like_json(body, content_type):
                body_kind = "json"
                candidates += [("body", p) for p in _json_top_level_params(body)]
            elif "form" in content_type.lower() or (
                not content_type and "=" in body and not body.strip().startswith(("{", "["))
            ):
                body_kind = "form"
                candidates += [("body", p) for p in _form_top_level_params(body)]
        if only_params is not None:
            wanted = set(only_params)
            candidates = [(loc, p) for loc, p in candidates
                          if (("query" if loc == "query" else f"body_{body_kind}"), p) in wanted]
        candidates = candidates[: self._MAX_PROBE_PARAMS]
        if not candidates:
            return None

        headers = {
            k: v for k, v in exchange.request_headers.items()
            if k.lower() not in ("host", "content-length")
        }
        # Ensure a JSON/form body carries the Content-Type the server needs to
        # parse it -- without this, a capture that lacked the header (e.g.
        # request_headers={}) makes every payload return an identical
        # unparsed-body response, silently defeating the differential. See
        # _inferred_content_type_for_body for the full root-cause note.
        inferred_ct = _inferred_content_type_for_body(body, content_type)
        if inferred_ct is not None:
            headers["Content-Type"] = inferred_ct
        # Baseline check so an endpoint that already returns DB-error-
        # shaped text for perfectly ordinary input doesn't get flagged
        # just for continuing to do so under a mutated value.
        baseline_already_errors = _text_has_db_error_markers(exchange.response_body or "")
        error_anomalies = []
        attempts: list[str] = []
        errors: list[str] = []
        had_clean_comparison = False
        marker = "zq" + secrets.token_hex(4)
        true_payload, false_payload = f"{marker}' OR '1'='1' -- ", f"{marker}' OR '1'='2' -- "

        for location, param in candidates:
            if location == "query":
                url_a = _mutate_query_param(exchange.url, param, true_payload)
                url_b = _mutate_query_param(exchange.url, param, false_payload)
                if url_a is None or url_b is None:
                    continue
                target_a, target_b, body_a, body_b = url_a, url_b, body, body
            else:
                mutate = _mutate_json_param if body_kind == "json" else _mutate_form_param
                body_a = mutate(body, param, true_payload)
                body_b = mutate(body, param, false_payload)
                if body_a is None or body_b is None:
                    continue
                target_a, target_b = exchange.url, exchange.url

            label = f"{location}:{param}"
            cmd_desc = [f"boolean-probe {exchange.method.upper()} {exchange.url} param={label}"]
            try:
                if self.run_context is not None:
                    from harness.run_context import TypedRequest
                    from .transport import bind_session

                    async def routed(url, probe_body):
                        session_ref, request_headers = bind_session(self.run_context, headers)
                        # CSRF/anti-forgery tokens are session-bound and often
                        # single-use: the captured value is stale, so both probes
                        # would fail identically and hide a real login injection.
                        # Fetch a FRESH token in the SAME session (session_ref
                        # keeps the cookie) and substitute it before sending.
                        csrf = _csrf_field_name(probe_body or "", inferred_ct or content_type)
                        if csrf and location == "body" and body_kind == "form":
                            try:
                                page = await self.run_context.executor().execute(
                                    TypedRequest("GET", exchange.url, headers=request_headers),
                                    capability="sqlmap_boolean_probe", session_ref=session_ref)
                                tok = _extract_token(page.body or "", csrf) if page.ok else None
                            except Exception:
                                tok = None
                            if tok:
                                fresh = _mutate_form_param(probe_body, csrf, tok)
                                if fresh is not None:
                                    probe_body = fresh
                        outcome = await self.run_context.executor().execute(
                            TypedRequest(exchange.method.upper(), url,
                                         headers=request_headers, body=probe_body or None),
                            capability="sqlmap_boolean_probe", session_ref=session_ref)
                        if not outcome.ok:
                            raise httpx.TransportError(outcome.error or outcome.outcome)
                        # RunContext exposes decoded text; the consumer view
                        # drops wire framing so httpx does not decode it twice.
                        return outcome.to_httpx_response(exchange.method.upper(), url)

                else:
                    from harness import global_throttle

                    async def routed(url, probe_body):
                        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                            await global_throttle.acquire()
                            return await client.request(
                                exchange.method.upper(), url, headers=headers, content=probe_body,
                            )

                resp_a = await routed(target_a, body_a)
                resp_b = await routed(target_b, body_b)
                # BM-2: two sequential answers also differ when the endpoint
                # changes between calls (a notice or lockout after the first
                # request, rotating content). Repeat the pair in reverse order:
                # the differential counts only when each probe answers as it
                # did the first time and the repeats still differ.
                stable = True
                if _responses_differ(resp_a, resp_b) and not (
                        _looks_like_db_error(resp_a) and _looks_like_db_error(resp_b)):
                    resp_b2 = await routed(target_b, body_b)
                    resp_a2 = await routed(target_a, body_a)
                    stable = (not _responses_differ(resp_a, resp_a2)
                              and not _responses_differ(resp_b, resp_b2)
                              and _responses_differ(resp_a2, resp_b2))
            except httpx.HTTPError as e:
                errors.append(f"{label}: probe failed ({e})")
                continue
            had_clean_comparison = True

            evidence = (
                f"{label}: tautology ({true_payload}) -> HTTP {resp_a.status_code} "
                f"({len(resp_a.content)}b); contradiction ({false_payload}) -> "
                f"HTTP {resp_b.status_code} ({len(resp_b.content)}b)"
            )
            both_db_errors = _looks_like_db_error(resp_a) and _looks_like_db_error(resp_b)
            if not stable:
                evidence += "; the repeated pair did not reproduce it (unstable endpoint)"
            elif _responses_differ(resp_a, resp_b) and not both_db_errors:
                baseline = None
                if self.run_context is not None:
                    try:
                        # The original value, replayed: the reference answer the
                        # differential is audited against (Ticket 6 proof baseline).
                        # Best effort: a proof send never changes the verdict.
                        baseline = await routed(exchange.url, body)
                    except Exception:
                        baseline = None
                return ValidationResult(
                    self.name, "confirmed", finding.vulnerability_class,
                    confidence=0.85, confirmed=True,
                    summary=f"Boolean-differential probe confirmed SQL injection via the "
                            f"{label} parameter: flipping the injected predicate's truth "
                            f"value (same syntax, true vs. false) changed the response.",
                    evidence=evidence, command=cmd_desc,
                ).with_artifacts(baseline=baseline, attack=resp_a, controls=[resp_b])
            # A changed database-error signature is worth retaining for review,
            # but without a differential it cannot establish exploitable injection.
            if not baseline_already_errors and (_looks_like_db_error(resp_a) or _looks_like_db_error(resp_b)):
                # A raw error alone is an anomaly, not proof of exploitable SQLi.
                # Keep testing other parameters for an independent differential.
                error_anomalies.append(evidence)
            attempts.append(evidence)

        if not had_clean_comparison:
            if not errors:
                return None  # every candidate param turned out not to be mutable after all
            # Every candidate's probe failed to even execute (network
            # error) -- this is "we don't know," not "tested, not
            # vulnerable." Reporting it as not_confirmed would silently
            # misrepresent a probe failure as a negative result.
            return ValidationResult(
                self.name, "error", finding.vulnerability_class,
                summary=f"boolean-probe fallback could not complete for any parameter: "
                        f"{'; '.join(errors)}",
            )

        if error_anomalies:
            return ValidationResult(
                self.name, "inconclusive", finding.vulnerability_class,
                confidence=0.3, confirmed=False,
                summary="SQL injection candidate: payloads produced database errors without a "
                        "independent truth-value differential; independent controlled evidence is required",
                evidence="; ".join(error_anomalies), command=cmd_desc)
        return ValidationResult(
            self.name, "not_confirmed", finding.vulnerability_class,
            confidence=0.1, confirmed=False,
            summary="Boolean-differential probe did not establish SQL injection "
                    f"(no truth-value-dependent response difference observed across "
                    f"{len(attempts)} parameter(s) tested)",
            evidence="; ".join(attempts) if attempts else "; ".join(errors),
        )
