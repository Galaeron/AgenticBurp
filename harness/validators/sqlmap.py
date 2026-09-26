from __future__ import annotations
import asyncio
import json as _json
import os
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
# a LIKE '%...%' clause, where an OR-based tautology/contradiction pair
# is not actually a true/false differential at all (the unconditional
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
                 run_context=None, allowed_hosts: list[str] | None = None):
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
            for denied in _DENIED_SQLMAP_FLAGS:
                assert denied not in cmd, (
                    f"Refusing to run sqlmap: denied flag {denied!r} present in constructed "
                    f"command. This is a hard-coded safety invariant, not a config option."
                )
            assert self.risk <= 2, f"Refusing to run sqlmap: risk={self.risk} exceeds the hard ceiling of 2."
            assert self.level <= 2, f"Refusing to run sqlmap: level={self.level} exceeds the hard ceiling of 2."

            # Container mode: wrap the (already safety-checked) sqlmap args in a
            # `docker run --rm` and rewrite the -u target to host.docker.internal.
            # The safety-flag assertions above ran on the raw sqlmap `cmd`, so the
            # denied-flag invariant holds regardless of how the process is spawned.
            run_cmd = cmd
            _use_container = False
            _container_args: list[str] = []
            _egress_policy = None
            _tool_receipt: dict = {}
            if self.container_image:
                from harness import tool_runner
                if tool_runner.available()[0]:
                    _use_container = True
                    _container_args = list(cmd[1:])  # drop self.binary; the image entrypoint IS sqlmap
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
                    rc, out, err = await asyncio.to_thread(
                        tool_runner.run,
                        self.container_image,
                        _container_args,
                        timeout=self.timeout_seconds,
                        egress=_egress_policy,
                        enforce_egress=True,
                        receipt=_tool_receipt,
                    )
                    proc = subprocess.CompletedProcess(
                        _tool_receipt.get("argv", run_cmd), rc, out, err)
                else:
                    proc = await asyncio.to_thread(
                        subprocess.run,
                        run_cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds,
                        env=os.environ.copy(),
                        # sqlmap can block waiting on stdin in some execution
                        # contexts even with --batch (verified by reproducing
                        # it directly: without this, the process hung silently
                        # until the timeout killed it, which then reported
                        # "sqlmap timed out" -- indistinguishable from a slow
                        # scan actually running). --batch suppresses prompts,
                        # not stdin reads; this closes the fd explicitly.
                        stdin=subprocess.DEVNULL,
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
                fallback = await self._boolean_probe_fallback(finding, exchange)
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
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary=f"sqlmap execution failed: {exc}", command=cmd)

            output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-12000:]
            lower = output.lower()
            confirmed = proc.returncode == 0 and "is vulnerable" in lower
            if confirmed:
                return ValidationResult(
                    self.name, "confirmed", finding.vulnerability_class,
                    confidence=0.98, confirmed=True,
                    summary="sqlmap independently reported the target as injectable",
                    evidence=output, raw_output=output, command=cmd,
                )
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
                secondary = await self._boolean_probe_fallback(finding, exchange)
                if secondary is not None and secondary.confirmed:
                    secondary.summary = ("sqlmap did not confirm, but a boolean-differential probe did "
                                         "(auth endpoint): " + secondary.summary)
                    secondary.raw_output = (secondary.raw_output or "") + "\n\n--- sqlmap output ---\n" + output
                    return secondary
            return ValidationResult(
                self.name, "not_confirmed", finding.vulnerability_class,
                confidence=0.2 if proc.returncode == 0 else 0.0,
                confirmed=False,
                summary="sqlmap did not establish SQL injection for the captured request",
                evidence=output, raw_output=output, command=cmd,
            )

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
        self, finding: Finding, exchange: HttpExchange
    ) -> ValidationResult | None:
        """Dependency-free confirmation for SQL injection when sqlmap isn't
        installed. NOT limited to credential/auth fields -- SQLi is not an
        auth-only bug class (see agents/sqli_agent.py's own prompt: id,
        sort/filter, search-box parameters are at least as common a real
        injection point). Enumerates query-string parameters and top-level
        JSON/form body parameters (capped at _MAX_PROBE_PARAMS total), and
        for each sends exactly two requests, identical to the original
        exchange except for that one parameter's value:

          A (tautology):  ' OR '1'='1' --   -- same predicate either way
          B (contradiction): ' OR '1'='2' -- -- same syntax, false predicate

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
        attempts: list[str] = []
        errors: list[str] = []
        had_clean_comparison = False

        for location, param in candidates:
            if location == "query":
                url_a = _mutate_query_param(exchange.url, param, "' OR '1'='1' -- ")
                url_b = _mutate_query_param(exchange.url, param, "' OR '1'='2' -- ")
                if url_a is None or url_b is None:
                    continue
                target_a, target_b, body_a, body_b = url_a, url_b, body, body
            else:
                mutate = _mutate_json_param if body_kind == "json" else _mutate_form_param
                body_a = mutate(body, param, "' OR '1'='1' -- ")
                body_b = mutate(body, param, "' OR '1'='2' -- ")
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
                        outcome = await self.run_context.executor().execute(
                            TypedRequest(exchange.method.upper(), url,
                                         headers=request_headers, body=probe_body or None),
                            capability="sqlmap_boolean_probe", session_ref=session_ref)
                        if not outcome.ok:
                            raise httpx.TransportError(outcome.error or outcome.outcome)
                        return httpx.Response(
                            outcome.status or 0, content=(outcome.body or "").encode(),
                            headers=outcome.headers,
                            request=httpx.Request(exchange.method.upper(), url))

                    resp_a = await routed(target_a, body_a)
                    resp_b = await routed(target_b, body_b)
                else:
                    from harness import global_throttle
                    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                        await global_throttle.acquire()
                        resp_a = await client.request(
                            exchange.method.upper(), target_a, headers=headers, content=body_a,
                        )
                        await global_throttle.acquire()
                        resp_b = await client.request(
                            exchange.method.upper(), target_b, headers=headers, content=body_b,
                        )
            except httpx.HTTPError as e:
                errors.append(f"{label}: probe failed ({e})")
                continue
            had_clean_comparison = True

            evidence = (
                f"{label}: tautology (' OR '1'='1' -- ) -> HTTP {resp_a.status_code} "
                f"({len(resp_a.content)}b); contradiction (' OR '1'='2' -- ) -> "
                f"HTTP {resp_b.status_code} ({len(resp_b.content)}b)"
            )
            if _responses_differ(resp_a, resp_b):
                return ValidationResult(
                    self.name, "confirmed", finding.vulnerability_class,
                    confidence=0.85, confirmed=True,
                    summary=f"Boolean-differential probe confirmed SQL injection via the "
                            f"{label} parameter: flipping the injected predicate's truth "
                            f"value (same syntax, true vs. false) changed the response.",
                    evidence=evidence, command=cmd_desc,
                )
            # Error-based signal, checked whenever the boolean-blind check
            # above doesn't fire: catches injection points where the value
            # is wrapped in a way (e.g. LIKE '%...%') that makes an
            # OR-based tautology/contradiction pair meaningless as a
            # true/false test (both sides of a wildcard-matched OR return
            # everything regardless of the injected predicate) -- verified
            # live, against Juice Shop's product search, that this is a
            # real gap the boolean-blind check alone misses even though
            # the underlying injection is genuine and produces a visible
            # raw DB error.
            if not baseline_already_errors and (_looks_like_db_error(resp_a) or _looks_like_db_error(resp_b)):
                return ValidationResult(
                    self.name, "confirmed", finding.vulnerability_class,
                    confidence=0.8, confirmed=True,
                    summary=f"Error-based probe confirmed SQL injection via the {label} "
                            f"parameter: an injected quote/comment payload produced a raw "
                            f"database error that the original, unmutated request did not.",
                    evidence=evidence, command=cmd_desc,
                )
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

        return ValidationResult(
            self.name, "not_confirmed", finding.vulnerability_class,
            confidence=0.1, confirmed=False,
            summary="Boolean-differential probe did not establish SQL injection "
                    f"(no truth-value-dependent response difference observed across "
                    f"{len(attempts)} parameter(s) tested)",
            evidence="; ".join(attempts) if attempts else "; ".join(errors),
        )
