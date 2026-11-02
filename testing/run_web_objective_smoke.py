"""Run one authorized URL-only web-objective smoke attempt.

The target-specific completion oracle stays outside this runner.  For Academy
labs, inspect the lab's own solved state after the attempt and then write the
benchmark run record; model output is never treated as proof of completion.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import subprocess
import time
import traceback
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _merge(dst: dict, src: dict) -> None:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _merge(dst[key], value)
        else:
            dst[key] = value


def _config(host: str, *, feature_crawl: bool = False,
            extra_allowed_hosts: list[str] | None = None) -> dict:
    config = yaml.safe_load((ROOT / "harness" / "config.yaml").read_text(encoding="utf-8")) or {}
    local_path = ROOT / "harness" / "config.local.yaml"
    if local_path.exists():
        _merge(config, yaml.safe_load(local_path.read_text(encoding="utf-8")) or {})
    config.setdefault("server", {})["allowed_hosts"] = [host] + list(extra_allowed_hosts or [])
    config.setdefault("validators", {})["active_enabled"] = True
    config["validators"]["allow_mutating_replay"] = True
    config.setdefault("iterative_agent", {})["enabled"] = True
    engagement = config.setdefault("engagement", {})
    engagement["driver_execute"] = True
    engagement["feature_crawl"] = feature_crawl
    engagement["coverage_drive_legs"] = False
    engagement["coverage_case_drive"] = False
    config.setdefault("business_context", {})["enabled"] = False
    config.setdefault("autonomous_discovery", {})["enabled"] = True
    return config


def _findings(result: dict) -> list[dict]:
    seen: set[str] = set()
    findings: list[dict] = []
    sources = []
    for outcome in result.get("outcomes", []) or []:
        sources.extend(outcome.get("findings_detail", []) or [])
    for endpoint in result.get("worklist", []) or []:
        sources.extend(endpoint.get("findings", []) or [])
    sources.extend(result.get("idor_findings", []) or [])
    for finding in sources:
        if not isinstance(finding, dict):
            continue
        rendered = json.dumps(finding, sort_keys=True, default=str)
        # The same persisted finding is exposed in both the per-node outcome
        # and the updated engagement worklist. Prefer its durable proof id so
        # harmless projection differences do not inflate the attempt count.
        digest = (finding.get("proof_id")
                  or hashlib.sha256(rendered.encode()).hexdigest())
        if digest not in seen:
            seen.add(digest)
            findings.append(finding)
    return findings


def _objective_declaration(spec: str | None):
    """LB-6: the typed objective profile from `--objective-profile` (a JSON file
    path or an inline JSON object), or None when the run declares no objective."""
    if not spec:
        return None
    from harness.objective_profiles import ObjectiveDeclaration
    text = spec if spec.lstrip().startswith("{") else Path(spec).read_text(encoding="utf-8")
    try:
        return ObjectiveDeclaration.from_mapping(json.loads(text))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid --objective-profile: {exc}") from exc


def _objective_summary(result: dict, declaration, task) -> dict:
    """The run's objective outcome. `objective_not_attempted` unless the
    completion stage itself reported a status for a declared objective."""
    from harness.objective_completion import NOT_ATTEMPTED
    summary = {"declared": declaration.describe() if declaration else None,
               "destructive_opt_in": bool(getattr(task, "destructive_opt_in", False)),
               "status": NOT_ATTEMPTED,
               "summary": ("no objective declared for this run" if declaration is None
                           else "no confirmed finding reached the objective stage")}
    for outcome in (result or {}).get("outcomes", []) or []:
        completion = outcome.get("objective_completion")
        if isinstance(completion, dict):
            summary["status"] = completion.get("status") or NOT_ATTEMPTED
            summary["summary"] = completion.get("summary", "")
            summary["requests_used"] = completion.get("requests_used", 0)
            summary["path"] = outcome.get("path")
            break
    return summary


def _login_form_data(html: str, page_url: str, username: str, password: str
                     ) -> tuple[str | None, str, dict]:
    """Pure part of the login flow: from a login page, pick the form that has a
    password field and build (action_url, method, form_data). Hidden tokens
    (CSRF/anti-forgery) keep their server-supplied value; the username/password
    fields are filled by name/type. Returns action=None when no password form is
    present so the caller can fall back to a bare credential POST."""
    from harness.feature_workflow import extract_forms
    for f in extract_forms(html or "", page_url):
        if not any((fld.type or "").lower() == "password" or "password" in (fld.name or "").lower()
                   for fld in f.fields):
            continue
        data: dict = {}
        for fld in f.fields:
            name = fld.name or ""
            if not name:
                continue
            t = (fld.type or "").lower()
            if t == "password" or "password" in name.lower():
                data[name] = password
            elif t == "email" or "email" in name.lower() or "user" in name.lower():
                data[name] = username
            else:
                data[name] = fld.value  # hidden CSRF/token kept at server value
        return f.action, (f.method or "POST").upper(), data
    return None, "POST", {"username": username, "password": password}


def _login_uses_json(html: str) -> bool:
    """Detect the common JS login helper that serializes form fields as JSON."""
    return bool(re.search(r"\bjsonSubmit\s*\(", html or "", re.I))


def _auth_info(requested: bool, ok: bool, login_status: int, cookie: str) -> dict:
    """Pure builder for the artifact's ``auth`` block.

    When auth was REQUESTED but never established (``ok`` is False), the
    authenticated RoleSession is silently dropped from the engagement -- the
    run continues anonymous. That must never pass as a quiet success: mark the
    block ``degraded`` with a ``hard_error`` so a dropped role is always
    visible in the artifact, never conflated with a run that legitimately
    never requested auth (``requested`` False) or one that established it
    fine (``ok`` True).
    """
    info = {"requested": requested, "login_status": login_status,
            "ok": ok, "cookie_present": bool(cookie)}
    if requested and not ok:
        info["degraded"] = True
        info["hard_error"] = "authentication requested but not established"
    return info


# A freshly-launched instance can intermittently drop the first connection
# (container/app still warming up) -- bound the retry so a cold login does not
# hang forever, but give it enough tries to ride out that warmup window.
_AUTH_MAX_ATTEMPTS = 3
_AUTH_RETRY_BACKOFF = 0.5


async def _authenticate(base: str, login_path: str, username: str, password: str,
                        timeout: float, *, transport=None):
    """Establish an authenticated session by driving the app's own login form,
    returning a Cookie header for the resulting session.

    This is treated as pre-attempt SETUP -- the equivalent of the tester's Burp
    session already holding the credentials it captured -- so it runs on a plain
    client and is not counted against the attempt's request budget. It is generic
    (no lab-specific knowledge): it fetches the login page, locates the form that
    carries a password field, preserves any hidden token (e.g. a CSRF field) at
    its server-supplied value, fills the username/password fields by name/type,
    submits, and returns whatever session cookies the app set.

    Both the login GET and the login POST are retried (bounded,
    ``_AUTH_MAX_ATTEMPTS``) on a transient failure -- a connection error or a
    0/5xx status -- since a freshly-launched instance can intermittently drop
    the very first request. The first attempt succeeding keeps the exact
    happy-path behavior (no added latency). ``transport`` is an optional
    injection seam (e.g. ``httpx.MockTransport``) for tests; when omitted the
    client is constructed exactly as before.
    """
    import httpx

    login_url = base.rstrip("/") + login_path
    client_kwargs: dict = {"timeout": timeout, "follow_redirects": True, "verify": False}
    if transport is not None:
        client_kwargs["transport"] = transport
    async with httpx.AsyncClient(**client_kwargs) as client:
        page = None
        for attempt in range(_AUTH_MAX_ATTEMPTS):
            try:
                page = await client.get(login_url)
            except httpx.HTTPError:
                page = None
            else:
                if page.status_code < 500:
                    break
            if attempt < _AUTH_MAX_ATTEMPTS - 1:
                await asyncio.sleep(_AUTH_RETRY_BACKOFF)
        if page is None:
            return "", 0, False, None
        action, method, data = _login_form_data(page.text or "", str(page.url), username, password)
        if action is None:
            action = login_url
        uses_json = _login_uses_json(page.text or "")
        resp = None
        for attempt in range(_AUTH_MAX_ATTEMPTS):
            try:
                kwargs = {"json": data} if uses_json else {"data": data}
                resp = await client.request(method, action, **kwargs)
            except httpx.HTTPError:
                resp = None
            else:
                if resp.status_code < 500:
                    break
            if attempt < _AUTH_MAX_ATTEMPTS - 1:
                await asyncio.sleep(_AUTH_RETRY_BACKOFF)
        if resp is None:
            return "", 0, False, None
        cookies = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
        # A session cookie that survived the login is our success signal; the app
        # sets one only when the credentials were accepted.
        ok = (bool(cookies) and resp.status_code < 400
              and urlsplit(str(resp.url)).path.rstrip("/") not in ("/login", "/signin"))
        # Keep the successfully exercised request SHAPE available to deterministic
        # validators without persisting credentials or the session-bound CSRF value.
        # Login forms are intentionally not auto-submitted by role crawl, so without
        # this seed auth-bypass validators never see the boundary at all.
        from harness.models import HttpExchange
        redacted = {}
        for key, value in data.items():
            low = str(key).lower()
            if any(mark in low for mark in ("user", "email", "login", "pass", "pwd",
                                             "csrf", "xsrf", "token", "nonce")):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        seed_body = json.dumps(redacted, separators=(",", ":")) if uses_json else urlencode(redacted)
        seed = HttpExchange(
            url=action, method=method,
            request_headers={"Content-Type": ("application/json" if uses_json else
                                               "application/x-www-form-urlencoded")},
            request_body=seed_body, response_status=resp.status_code,
            response_headers=dict(resp.headers), response_body=resp.text or "",
            analyst_note="successful login setup shape; sensitive values redacted")
        return cookies, resp.status_code, ok, seed


async def _run(args: argparse.Namespace) -> int:
    target = args.target.rstrip("/") + "/"
    host = urlsplit(target).hostname or ""
    if not host:
        raise SystemExit("target must include a URL hostname")
    declaration = _objective_declaration(args.objective_profile)
    objective_class = args.objective_class
    if declaration is not None:
        declared_class = declaration.profile.vulnerability_class
        if objective_class and objective_class != declared_class:
            raise SystemExit(f"--objective-class {objective_class!r} does not match the "
                             f"objective profile's class {declared_class!r}")
        objective_class = declared_class
    objective_class = objective_class or "sqli"
    objective_task = (declaration.to_task(allow_destructive=args.allow_destructive_objective)
                      if declaration is not None else None)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or f"smoke-{uuid.uuid4().hex[:12]}"
    extra_hosts = []
    if args.race_mailbox_url:
        mailbox_host = urlsplit(args.race_mailbox_url).hostname
        if mailbox_host:
            extra_hosts.append(mailbox_host)
    config = _config(host, feature_crawl=args.feature_crawl,
                     extra_allowed_hosts=extra_hosts)
    if args.race_target_email or args.race_mailbox_url:
        validators_cfg = config.setdefault("validators", {})
        # A race cannot exist with the global safe-default ceiling of one.  This
        # is an in-memory, objective-scoped opt-in; config.yaml remains passive.
        validators_cfg["max_burst_size"] = max(
            2, int(validators_cfg.get("max_burst_size", 1)))
        race_cfg = validators_cfg.setdefault("race_condition", {})
        race_cfg["target_email"] = args.race_target_email
        race_cfg["mailbox_url"] = args.race_mailbox_url
        config.setdefault("transport", {})["http2"] = True
    if args.idor_candidates:
        cands = [c.strip() for c in args.idor_candidates.split(",") if c.strip()]
        config.setdefault("validators", {}).setdefault("idor_read", {})["candidate_ids"] = cands

    from harness import cache, store
    store._DB_PATH = output / "state.db"
    cache.init_cache(db_path=str(output / "cache.db"))
    from harness.orchestrator import Orchestrator
    from harness.role_crawl import RoleSession
    from harness.run_context import RunContext

    orchestrator = Orchestrator(config)

    # Optional authenticated role. Login is pre-attempt setup (like a tester's
    # Burp session already holding the cookie), so it does not consume the
    # attempt's request budget. The authenticated surface is otherwise
    # unreachable for login-gated objectives (IDOR, JWT, 2FA, uploads, ...).
    roles = [RoleSession(role="anonymous", headers={})]
    seed_exchanges = []
    if args.auth:
        username, _, password = args.auth.partition(":")
        cookie, login_status, ok, login_seed = await _authenticate(
            target, args.login_path, username, password, args.request_timeout)
        if login_seed is not None:
            seed_exchanges.append(login_seed)
        auth_info = _auth_info(True, ok, login_status, cookie)
        auth_info["username"] = username
        if ok:
            roles.append(RoleSession(role="user", headers={"Cookie": cookie},
                                     name=username or "user"))
        else:
            print(json.dumps({"warning": "authentication failed; continuing "
                              "anonymous", "login_status": login_status}))
    else:
        auth_info = _auth_info(False, False, 0, "")

    started = time.time()
    ctx = RunContext.create(
        run_id=run_id,
        allowed_hosts=[host] + extra_hosts,
        gate_config=config.get("validators", {}),
        max_requests=args.max_requests,
        config=config,
        timeout=args.request_timeout,
        objective_task=objective_task,
    )
    status = "done"
    error = None
    timeout_stack: list[str] = []
    engagement_task = None
    try:
        async with ctx:
            engagement_task = asyncio.create_task(
                orchestrator.investigate_engagement(
                    target,
                    roles,
                    max_nodes=args.max_nodes,
                    step_budget=args.step_budget,
                    discovery_max_probes=args.discovery_max_probes,
                    discovery_max_endpoints=args.discovery_max_endpoints,
                    discovery_max_pages=args.discovery_max_pages,
                    active_discovery=args.active_discovery,
                    max_chain_rounds=0,
                    run_context=ctx,
                    stop_on_confirm=True,
                    objective_class=objective_class,
                    seed_exchanges=seed_exchanges,
                )
            )
            result = await asyncio.wait_for(
                asyncio.shield(engagement_task), timeout=args.wall_timeout)
    except asyncio.TimeoutError:
        status = "timeout"
        error = f"wall-clock limit exceeded ({args.wall_timeout:g}s)"
        if engagement_task is not None:
            for frame in engagement_task.get_stack():
                timeout_stack.extend(traceback.format_stack(frame, limit=1))
            engagement_task.cancel()
            await asyncio.gather(engagement_task, return_exceptions=True)
        result = {
            "errors": [{"phase": "runner", "error": error}],
            "degraded": True,
            "timeout_stack": timeout_stack,
        }
    except Exception as exc:  # artifact must survive a failed live attempt
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
        result = {"errors": [{"phase": "runner", "error": error}], "degraded": True}

    if auth_info.get("degraded") and isinstance(result, dict):
        # A requested-but-never-established role must never pass silently as
        # anonymous: surface it in the same top-level degraded signal the
        # printed summary and any artifact consumer already check.
        result["degraded"] = True

    duration = time.time() - started
    config_json = json.dumps(config, sort_keys=True, default=str)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=False,
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=ROOT, text=True,
        capture_output=True, check=False,
    ).stdout.strip())
    artifact = {
        "schema_version": "1.0.0",
        "kind": "web_objective_smoke_attempt",
        "run_id": run_id,
        "case_id": args.case_id,
        "target": target,
        "status": status,
        "error": error,
        "started_at": started,
        "duration_seconds": round(duration, 3),
        "requests": ctx.budget.used,
        "model": config.get("coordinator", {}).get("model", "unknown"),
        "checkout": f"{revision}{'-dirty' if dirty else ''}",
        "config_hash": hashlib.sha256(config_json.encode()).hexdigest(),
        "auth": auth_info,
        "findings": _findings(result),
        "objective": _objective_summary(result, declaration, objective_task),
        "result": result,
    }
    (output / "attempt.json").write_text(
        json.dumps(artifact, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "run_id": run_id,
        "status": status,
        "duration_seconds": artifact["duration_seconds"],
        "requests": artifact["requests"],
        "findings": len(artifact["findings"]),
        "objective_status": artifact["objective"]["status"],
        "degraded": bool(result.get("degraded")),
        "output": str(output / "attempt.json"),
        "error": error,
    }, indent=2))
    return 0 if status == "done" else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--case-id", default="ps-sqli-hidden-data")
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--max-nodes", type=int, default=6)
    parser.add_argument("--step-budget", type=int, default=8)
    parser.add_argument("--discovery-max-probes", type=int, default=80)
    parser.add_argument("--discovery-max-endpoints", type=int, default=30)
    parser.add_argument("--discovery-max-pages", type=int, default=2)
    parser.add_argument("--active-discovery", action="store_true")
    parser.add_argument("--feature-crawl", action="store_true",
                        help="Capture authenticated, stateful form request shapes before "
                             "objective validation. Off by default to preserve passive runs.")
    parser.add_argument("--max-requests", type=int, default=1200)
    parser.add_argument("--request-timeout", type=float, default=15.0)
    parser.add_argument("--wall-timeout", type=float, default=900.0)
    parser.add_argument("--objective-class", default=None,
                        help="Vulnerability class to confirm (default sqli, or the "
                             "--objective-profile's class).")
    parser.add_argument("--objective-profile", default=None,
                        help="Typed objective profile (JSON file or inline JSON): profile, "
                             "required_end_state {target_path, oracle_url, oracle_marker}, "
                             "action_class, mutation_level, oracle, ceilings. Without it the "
                             "objective is reported objective_not_attempted.")
    parser.add_argument("--allow-destructive-objective", action="store_true",
                        help="Explicit opt-in for a destructive objective profile. Without "
                             "it a destructive objective returns objective_not_attempted.")
    parser.add_argument("--auth", default=None,
                        help="USER:PASS to establish an authenticated session via the "
                             "app's own login form before the attempt (e.g. wiener:peter).")
    parser.add_argument("--login-path", default="/login",
                        help="Path of the login form used with --auth (default /login).")
    parser.add_argument("--idor-candidates", default=None,
                        help="Comma-separated target object ids to attempt in the IDOR "
                             "read differential (e.g. carlos), as a tester would declare a "
                             "known victim account. Read-only; never used for writes.")
    parser.add_argument("--race-target-email", default=None,
                        help="Operator-declared target address for an email-change race proof.")
    parser.add_argument("--race-mailbox-url", default=None,
                        help="Operator-controlled mailbox URL used for an email-change race proof.")
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
