from __future__ import annotations
import json as _json
import os
import secrets
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

import httpx

from harness.control_outcome import CONTROL_NOT_RUN
from harness.models import Finding, HttpExchange, TestPlan
from harness.planner import exchange_fingerprint, plan_key_fingerprint
from harness.categories import canonicalize
from .base import TOOL_REPORTED, Validator, ValidationResult
from harness.safety_gate import get_default_gate
# ARC-9: these helpers moved verbatim into sibling modules. The names below are what this
# module's own code reads, or what callers import from it.
from .sqlmap_policy import (
    create_endpoint_reason, DEFAULT_CREATE_ENDPOINT_MAX_REQUESTS, _ERROR_PROBE_SENDS, _light_note,
    LIGHT_TECHNIQUES, NO_SCAN_WRITE_METHODS, _TECHNIQUE_PROBE_CAPABILITY, _TOOL_CAPABILITY,
    _UNION_PROBE_MIN_SENDS, WRITE_ENDPOINT_MAX_REQUESTS, WRITE_METHODS,
)
from .sqlmap_params import (
    _addressable_params, _AUTH_REJECTION_CODES, _content_type_of, _csrf_field_name,
    _error_probe_values, _extract_token, _form_top_level_params, _inferred_content_type_for_body,
    _json_top_level_params, _looks_like_auth_request, _looks_like_json, _marked_path_url,
    _mutate_form_param, _mutate_json_param, _mutate_query_param, _named_input,
    _query_top_level_params, _responses_differ,
)
from .sqlmap_signals import (
    _blip_note, _connection_failure, _DB_ERROR_MARKERS, _looks_like_db_error,
    _looks_like_db_syntax_error, _PARAMETER_VERDICT_RE, _PROXY_STOP_WHY,
    _text_has_db_error_markers, _transient, _with_light_note,
)
from .sqlmap_report import (
    _DIFFERENTIAL_LOCATIONS, _MAX_REPRODUCED_POINTS, parse_injection_points, _payload_boundary,
    _point_label, _point_technique, _points_evidence, _union_column_count, _verdict_evidence,
    verdict_lines,
)


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
                 quick_only: bool = False,
                 create_endpoint_max_requests: int = DEFAULT_CREATE_ENDPOINT_MAX_REQUESTS,
                 endpoint_family_seconds: float | None = None):
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
        # Hard cap on the requests one light (create-endpoint) sqlmap scan may send.
        self.create_endpoint_max_requests = max(1, int(create_endpoint_max_requests))
        # R11-3: per-endpoint-family wall-time share (harness/sqlmap_targeting.py).
        # None reads validators.sqlmap.endpoint_family_seconds from the run's config.
        self.endpoint_family_seconds = endpoint_family_seconds

    def _targeting(self):
        from harness.sqlmap_targeting import targeting_for
        return targeting_for(self.run_context, self, self.endpoint_family_seconds)

    def full_scan_covers(self, finding: Finding, exchange: HttpExchange):
        """(location, name) of the parameter-only finding's input when a full scan
        of `exchange` (no -p) tests it as `-p` would: a query or urlencoded form
        parameter present in the request. None for any other input; the execution
        registry then runs the case on its own (r9: per-parameter cases re-ran
        sqlmap on one-parameter requests the worklist had already scanned)."""
        if not getattr(finding, "parameter_only", False):
            return None
        loc, name = _named_input(finding)
        return (loc, name) if name and name in _addressable_params(loc, exchange) else None

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
        if self._targeting().transport_reason(exchange):
            return None  # a long-polling transport endpoint is never queued (R11-3)
        return TestPlan(
            # The id ignores cache-buster parameters (planner.plan_key_fingerprint);
            # the binding below stays the exact capture.
            id=f"sqlmap:{finding.vulnerability_class}:{plan_key_fingerprint(exchange)[:20]}",
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
        light: dict = {}
        result = await self._validate(finding, exchange, light)
        if light.get("launched"):
            # Every verdict of a light scan says so, and why (create endpoint, cap).
            return _with_light_note(result, _light_note(light["reason"], light["cap"],
                                                        light.get("proxy")))
        return result

    async def _validate(self, finding: Finding, exchange: HttpExchange,
                        light: dict) -> ValidationResult:
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

        # R11-3: a long-polling transport endpoint's parameters are transport state
        # (protocol version, transport, session id, cache-buster), not application
        # input; nothing is sent to it. Past the endpoint family's time share the
        # next target waits; a started scan always finishes.
        targeting = self._targeting()
        transport = targeting.transport_reason(exchange)
        if transport:
            targeting.note_transport_skip(exchange)
            why = (f"{urlsplit(exchange.url).path or '/'} is a long-polling transport endpoint "
                   f"({transport}); its parameters are transport state, not application input")
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"sqlmap not launched: {why}",
                                    limitation=f"skipped: {why}; not a negative result")
        held = targeting.hold_reason(exchange.method, exchange.url)
        if held:
            return ValidationResult(self.name, "inconclusive", finding.vulnerability_class,
                                    summary=f"sqlmap held: {held}",
                                    limitation=f"held: {held}; not a negative result")
        token = targeting.start(exchange.method, exchange.url)
        try:
            return await self._validate_scoped(finding, exchange, light)
        finally:
            targeting.finish(token)

    async def _validate_scoped(self, finding: Finding, exchange: HttpExchange,
                               light: dict) -> ValidationResult:
        # Per-parameter dispatch (coverage case driver): test the named parameter
        # alone, so a clean result is bound to it and to nothing else.
        only = None
        if getattr(finding, "parameter_only", False):
            from .injection_targets import NAMED_PARAMETER_UNTESTED  # (cycle: it imports us)
            loc, name = _named_input(finding)
            if loc == "path" and _marked_path_url(exchange.url, name) is None:
                return ValidationResult(
                    self.name, "skipped", finding.vulnerability_class,
                    summary=f"the path input {name!r} is not an object id in the replayed "
                            "request's path, so it was not tested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
            if loc != "path" and name not in _addressable_params(loc, exchange):
                return ValidationResult(
                    self.name, "skipped", finding.vulnerability_class,
                    summary=f"the {loc or 'unnamed'} parameter {name!r} is not a query or form "
                            "parameter of the replayed request, so it was not tested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
            only = [(loc, name)]
        from .injection_targets import guessed_body  # (cycle: it imports us)
        if only is None and guessed_body(exchange):
            # R11-9: the crawler's guessed body names no parameter of the endpoint;
            # only the query string's parameters are inputs to test.
            queries = _query_top_level_params(exchange.url)
            if not queries:
                why = ("the request body is a harness-guessed placeholder, not the endpoint's "
                       "parameters, and the request has no query parameter")
                return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                        summary=f"sqlmap not launched: {why}",
                                        limitation=f"skipped: {why}; not a negative result")
            only = [("query", q) for q in queries]
        result = await self._validate_request(finding, exchange, only, light)
        if only and result is not None:
            # Every send below targets `only` (-p and the probes' only_params).
            from .injection_targets import tested_inputs
            result.tested_parameters = tested_inputs(finding, only)
        return result

    async def _validate_request(self, finding: Finding, exchange: HttpExchange,
                                only: list[tuple[str, str]] | None,
                                light: dict) -> ValidationResult:
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
            if self.quick_only and quick is None and only and only[0][0] == "path":
                # The preflight mutates query and body parameters only: a path input
                # it could not reach is untested, not a negative.
                from .injection_targets import NAMED_PARAMETER_UNTESTED
                return ValidationResult(
                    self.name, "skipped", finding.vulnerability_class,
                    summary="the bounded boolean preflight cannot inject into a path "
                            "segment, and sqlmap is not launched (quick_only); untested",
                    control_outcome=NAMED_PARAMETER_UNTESTED)
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
        write_endpoint = exchange.method.upper() in WRITE_METHODS
        write_case = ""
        if exchange.method.upper() in NO_SCAN_WRITE_METHODS:
            why = (f"{exchange.method.upper()} {urlsplit(exchange.url).path} is not scanned: "
                   "every sqlmap request may delete an object and a deletion has no restore")
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"sqlmap not launched: {why}",
                                    limitation=f"skipped: {why}; not a negative result")
        if write_endpoint:
            create_reason = f"write endpoint: {exchange.method.upper()} {urlsplit(exchange.url).path}"
            cap = min(self.create_endpoint_max_requests, WRITE_ENDPOINT_MAX_REQUESTS)
            if run is not None:
                # Every proxied write is counted against the case's mutating ceiling,
                # so the scan's cap is also what that ceiling has left.
                from harness.run_context import current_case_ref
                write_case = finding.finding_id or current_case_ref()
                left = (run.gate.mutating_headroom(write_case, _TOOL_CAPABILITY)[0]
                        if write_case else 0)
                if left <= 0:
                    why = ("the case's mutating-request ceiling is spent" if write_case
                           else "no case reference to count its writes against")
                    return ValidationResult(
                        self.name, "skipped", finding.vulnerability_class,
                        summary=f"sqlmap not launched on {create_reason}: {why}",
                        limitation=f"skipped: {why}; not a negative result")
                cap = min(cap, left)
        else:
            create = create_endpoint_reason(exchange)
            create_reason = f"create endpoint: {create}" if create else ""
            cap = self.create_endpoint_max_requests
        if create_reason and run is None:
            # The cap is enforced by the run's tool proxy; without a run nothing
            # would bound how many objects the scan creates.
            note = _light_note(create_reason, cap, None)
            return ValidationResult(
                self.name, "skipped", finding.vulnerability_class,
                summary=f"sqlmap not launched: {note} needs a run to enforce the cap",
                limitation=f"skipped: {note}; not launched without a run to enforce the cap")
        if create_reason:
            light.update(reason=create_reason, cap=cap)

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

            # A path input is marked in the URL itself (sqlmap has no `-p` name for it).
            path_point = bool(only) and only[0][0] == "path"
            target_url = _marked_path_url(exchange.url, only[0][1]) if path_point else exchange.url
            cmd = [self.binary, "-u", target_url, "--batch",
                   "--level", "1" if create_reason else str(self.level),
                   "--risk", "1" if create_reason else str(self.risk),
                   "--threads", "1", "--timeout", "10", "--retries", "1",
                   "--flush-session", "--disable-coloring",
                   # sqlmap's heuristic WAF/IPS probe sends one request with a random
                   # parameter carrying a UNION/xp_cmdshell/script payload; the run's
                   # gate hard-denies it as destructive (91 blocked sends in r7), so
                   # the probe only spends budget and never learns anything.
                   "--skip-waf"]
            if create_reason:
                cmd += ["--technique", LIGHT_TECHNIQUES]
            if path_point:
                cmd += ["--param-filter", "URI"]
            elif only:
                cmd += ["-p", ",".join(name for _, name in only)]
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
                proxy = await ToolProxy(run, exchange.url, capability=_TOOL_CAPABILITY,
                                        case_ref=write_case,
                                        **({"max_forwarded": cap, "cap_stops": True}
                                           if create_reason else {})).start()
                light["proxy"] = proxy
                launch_cmd = list(cmd)
                launch_cmd[launch_cmd.index("-u") + 1] = proxy.url_for(target_url)
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

            light["launched"] = bool(create_reason)
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
                                            summary=f"sqlmap stopped: {why}", command=cmd,
                                            transient_stop=_transient(proxy))
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
                    evidence=verdict_evidence, raw_output=output, command=cmd, limitation=verdict,
                    transient_stop=_transient(proxy))
            unreachable = _connection_failure(output, proxy)
            if unreachable:
                # sqlmap never got an answer to test: "we don't know", not a negative.
                return ValidationResult(
                    self.name, "error", finding.vulnerability_class,
                    summary=f"sqlmap could not reach the target ({unreachable}) -- not a negative result",
                    evidence=verdict_evidence, raw_output=output, command=cmd,
                    limitation=f"transport failure: {unreachable}; not a negative result")
            # Secondary confirmation for auth/login endpoints (HANDOVER_6 §3/§6.3):
            # sqlmap's own analysis is fragile on a valid-cred (2xx) login capture
            # even with --ignore-code, because it must infer the 2xx<->401 flip
            # through its heuristics. The dependency-free boolean-differential probe
            # reads that flip DIRECTLY (tautology -> 200, contradiction -> 401), so
            # run it as a fallback and prefer a real CONFIRMED over sqlmap's miss.
            # Bounded to auth-shaped requests so a normal not_confirmed doesn't pay
            # for extra probes. The mutating method (if any) was already authorised
            # by the safety gate above before sqlmap ran.
            if not write_endpoint and _looks_like_auth_request(exchange):
                secondary = await self._boolean_probe_fallback(finding, exchange, only_params=only)
                if secondary is not None and secondary.confirmed:
                    secondary.summary = ("sqlmap did not confirm, but a boolean-differential probe did "
                                         "(auth endpoint): " + secondary.summary)
                    secondary.raw_output = (secondary.raw_output or "") + "\n\n--- sqlmap output ---\n" + output
                    return secondary
            if only and "not present within" in lower:
                # A `-p` sqlmap could not find tested nothing: never a negative.
                from .injection_targets import NAMED_PARAMETER_UNTESTED
                return ValidationResult(
                    self.name, "inconclusive", finding.vulnerability_class,
                    summary=f"sqlmap did not find parameter {only[0][1]!r} to test "
                            "-- not a negative result",
                    evidence=verdict_evidence, raw_output=output, command=cmd,
                    control_outcome=NAMED_PARAMETER_UNTESTED, limitation=verdict)
            blips = _blip_note(output)
            if proc.returncode != 0 and not _PARAMETER_VERDICT_RE.search(output):
                # EFF-1: sqlmap exited nonzero WITHOUT reaching its own "not
                # injectable" verdict (a crash, a bad option, a tool error). Nothing
                # was compared, so this is "we don't know", never a negative. A
                # nonzero exit that carries the verdict is sqlmap's normal negative
                # (it exits 1 on "all tested parameters do not appear to be
                # injectable") and stays not_confirmed below.
                return ValidationResult(
                    self.name, "inconclusive", finding.vulnerability_class,
                    confidence=0.0, confirmed=False,
                    summary=f"sqlmap exited {proc.returncode} without its parameter verdict "
                            "-- not a negative result",
                    evidence=verdict_evidence, raw_output=output, command=cmd,
                    control_outcome=CONTROL_NOT_RUN,
                    limitation="; ".join(x for x in (
                        f"sqlmap exit code {proc.returncode} and no tested-parameter verdict",
                        blips, verdict) if x),
                )
            # Not a held control: sqlmap's "not injectable" is the absence of its
            # oracle signal, so control_outcome stays unset and the confirmation
            # gate reports the finding UNVERIFIED, not refuted (EFF-1 inventory).
            return ValidationResult(
                self.name, "not_confirmed", finding.vulnerability_class,
                confidence=0.2 if proc.returncode == 0 else 0.0,
                confirmed=False,
                summary="sqlmap did not establish SQL injection for the captured request"
                        + (f" ({verdict_lines(output)[-1]})" if verdict else ""),
                evidence=verdict_evidence, raw_output=output, command=cmd,
                limitation="; ".join(x for x in (blips, verdict) if x),
            )

    async def _sqlmap_confirmation(self, finding: Finding, exchange: HttpExchange,
                                   output: str, cmd: list[str]) -> ValidationResult:
        """The confirmation for a sqlmap that reported the target injectable (Ticket 2B).

        sqlmap stays the authority for the verdict. Its injection points lead the
        evidence, and each point the harness can mutate (up to _MAX_REPRODUCED_POINTS)
        is reproduced by the harness itself on that parameter alone, through the run's
        transport and with the harness's own payloads (never sqlmap's): a boolean point
        by the true/false differential, an error-based point by a breaking value
        against a balanced control, a UNION point by a fresh marker returned as a
        column value. The first one that reproduces gives the result its
        baseline/attack/control artifacts; otherwise the result is marked
        tool-reported and names no exchanges, so its proof stays a candidate.
        A write endpoint (PUT/PATCH/DELETE) is never replayed: every send may change
        state, and its scan already stopped at the write cap."""
        points = parse_injection_points(output)
        result = ValidationResult(
            self.name, "confirmed", finding.vulnerability_class,
            confidence=0.98, confirmed=True,
            summary="sqlmap independently reported the target as injectable",
            evidence=_points_evidence(points, output), raw_output=output, command=cmd,
            injection_points=tuple(points),
        )
        write = exchange.method.upper() in WRITE_METHODS
        eligible = [] if write else [p for p in points if p["place"] in _DIFFERENTIAL_LOCATIONS
                                     and _point_technique(p)]
        for point in eligible[:_MAX_REPRODUCED_POINTS]:
            technique = _point_technique(point)
            if technique == "boolean":
                repro = await self._boolean_probe_fallback(
                    finding, exchange, only_params=[(point["place"], point["parameter"])])
                how = "a true/false differential"
            else:
                repro = await self._technique_probe(finding, exchange, point, technique)
                how = ("a DB error for a breaking value that a balanced control did not produce"
                       if technique == "error" else "a fresh UNION marker returned as a column value")
            if repro is None or not repro.confirmed:
                continue
            result.summary = (f"sqlmap reported injection at {_point_label(point)} ({point['type']}); "
                              f"the harness reproduced {how} on the same parameter")
            result.evidence = _points_evidence(points, output, repro.evidence)
            return result.with_artifacts(
                baseline=repro.baseline_artifact_id, attack=repro.attack_artifact_id,
                controls=repro.control_artifact_ids)
        result.summary = "tool-reported, not reproduced by the harness: " + result.summary
        result.evidence_source = TOOL_REPORTED
        result.limitation = ("tool-reported: the harness did not reproduce the reported technique"
                             + (" (write endpoints are not replayed)" if write else ""))
        return result

    async def _technique_probe(self, finding: Finding, exchange: HttpExchange,
                               point: dict, technique: str) -> ValidationResult | None:
        """Harness-side reproduction of an error-based or UNION point on one parameter.

        The harness's own payloads only. sqlmap's reported payload is read for the
        injection context (the characters that close the value, e.g. ' or ') and,
        for UNION, the column count; it is never sent.

        error: a breaking value (an unbalanced quote) and a well-formed control that
          is not the original value (the quote doubled; in a numeric context the
          number minus zero), each sent twice. Confirmed only when a DB *syntax* error
          signature answers both breaking sends and no DB error answers either control
          or the baseline. A generic 500, or a driver/ORM type-conversion message that
          a parameterized query also gives, is no signature.
        union: one UNION SELECT per column carrying a fresh marker in that column.
          Confirmed when the marker comes back as a JSON value on two sends and an
          echo control (the marker sent as the plain value) does not return it.

        None when the point cannot be reproduced this way, the evidence is not there,
        or a send failed at the transport (the tool-reported lead stays)."""
        location, param = point["place"], point["parameter"]
        method = exchange.method.upper()
        body = exchange.request_body or ""
        if location == "query":
            values = dict(parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True))
        elif location == "body_json":
            try:
                values = _json.loads(body)
            except ValueError:
                return None
        else:
            values = dict(parse_qsl(body, keep_blank_values=True))
        if (not isinstance(values, dict) or param not in values
                or isinstance(values[param], (dict, list, bool))):
            return None
        original = "" if values[param] is None else str(values[param])
        boundary = _payload_boundary(point.get("payload", ""))
        if boundary is None:
            return None
        quote = "'" if "'" in boundary else '"' if '"' in boundary else ""
        values_for_error = _error_probe_values(original, quote) if technique == "error" else None
        if technique == "error" and values_for_error is None:
            return None

        # A mutating reproduction (a POST; writes never get here) counts against the
        # case's mutating ceiling (SafetyGate._reserve_mutating, keyed by the case).
        # Without the whole minimum sequence's headroom nothing is sent; a refusal
        # part-way is a transport refusal below (the tool-reported lead stays).
        case_key = ""
        if self.run_context is not None:
            from harness.run_context import current_case_ref
            from harness.safety_gate import ActionRiskTier
            case_key = finding.finding_id or current_case_ref()
            gate = self.run_context.gate
            if gate.classify(method) == ActionRiskTier.MUTATING:
                if not case_key:
                    return None
                needed = _ERROR_PROBE_SENDS if technique == "error" else _UNION_PROBE_MIN_SENDS
                if gate.mutating_headroom(case_key, _TECHNIQUE_PROBE_CAPABILITY)[0] < needed:
                    return None

        headers = {k: v for k, v in exchange.request_headers.items()
                   if k.lower() not in {"host", "content-length"}}
        inferred_ct = _inferred_content_type_for_body(body, _content_type_of(exchange))
        if inferred_ct is not None:
            headers["Content-Type"] = inferred_ct

        async def send(value=None):
            url, probe_body = exchange.url, body
            if value is not None:
                if location == "query":
                    url = _mutate_query_param(url, param, value)
                else:
                    mutate = _mutate_json_param if location == "body_json" else _mutate_form_param
                    probe_body = mutate(body, param, value)
                if url is None or probe_body is None:
                    raise ValueError("the parameter could not be mutated")
            if self.run_context is not None:
                from harness.run_context import TypedRequest
                from .transport import bind_session
                session, request_headers = bind_session(self.run_context, headers)
                answer = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=request_headers, body=probe_body or None),
                    capability=_TECHNIQUE_PROBE_CAPABILITY, session_ref=session,
                    case_ref=case_key)
                if not answer.ok:
                    raise httpx.TransportError(answer.error or answer.outcome)
                return answer.to_httpx_response(method, url)
            from harness.safety_gate import GatedAsyncClient
            async with GatedAsyncClient(get_default_gate(), self.name,
                                        timeout=10, follow_redirects=False) as client:
                return await client.request(method, url, headers=headers, content=probe_body or None)

        label = _point_label(point)
        try:
            baseline = await send()
            if (baseline.status_code >= 500 or _looks_like_db_error(baseline)
                    or _looks_like_db_syntax_error(baseline)):
                return None
            if technique == "error":
                breaking, balanced = values_for_error
                attack = await send(breaking)
                control = await send(balanced)
                repeat_control = await send(balanced)
                repeat_attack = await send(breaking)
                if not (_looks_like_db_syntax_error(attack)
                        and _looks_like_db_syntax_error(repeat_attack)
                        and not any(_looks_like_db_error(r) or _looks_like_db_syntax_error(r)
                                    for r in (control, repeat_control))
                        and control.status_code < 500 and repeat_control.status_code < 500):
                    return None
                evidence = (f"{label}: breaking value {breaking!r} answered a DB syntax error "
                            f"signature (HTTP {attack.status_code}) on both sends; the control "
                            f"{balanced!r} (HTTP {control.status_code}) and the baseline did not")
            else:
                columns = _union_column_count(point.get("payload", ""))
                if not columns:
                    return None
                marker = "hx" + secrets.token_hex(10)

                def returns_marker(response) -> bool:
                    def walk(value):
                        if isinstance(value, dict):
                            return any(walk(v) for v in value.values())
                        if isinstance(value, list):
                            return any(walk(v) for v in value)
                        return isinstance(value, str) and value == marker
                    try:
                        return response.status_code < 400 and walk(response.json())
                    except ValueError:
                        return False

                control = await send(marker)          # an endpoint that echoes its input
                if returns_marker(baseline) or returns_marker(control):
                    return None
                attack, hit = None, 0
                for column in range(columns):
                    exprs = ["NULL"] * columns
                    exprs[column] = f"'{marker}'"
                    value = f"{original}{boundary} UNION ALL SELECT {','.join(exprs)}-- "
                    trial = await send(value)
                    if returns_marker(trial):
                        if returns_marker(await send(value)):
                            attack, hit = trial, column + 1
                        break
                if attack is None:
                    return None
                evidence = (f"{label}: a fresh marker in UNION column {hit} of {columns} came back "
                            "as a column value on two sends; the echo control and the baseline "
                            "did not return it")
        except (httpx.HTTPError, ValueError, TypeError):
            return None
        return ValidationResult(
            self.name, "confirmed", finding.vulnerability_class, confirmed=True, confidence=0.9,
            summary=evidence, evidence=evidence,
            command=[f"{technique}-probe {method} {exchange.url} param={label}"],
        ).with_artifacts(baseline=baseline, attack=attack, controls=[control])

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
