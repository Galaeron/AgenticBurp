"""Session token survives a password change (R11-8 b, owner decision 2026-11-19).

Oracle: for a run-owned identity (one whose login the operator declared, see
validators/owned_login), log in and keep its token T1; change the password with
the captured change-password flow; then read the account with T1. If T1 is
still accepted, sessions are not revoked on a password change
(session_after_password_change; WSTG-ATHN-09, CWE-613). Then change the password
back and verify the original password logs in. A restore that fails is named in
the verdict, whatever it is.

A write. It sends only with validators.active_enabled,
validators.allow_mutating_replay and validators.mutating_ceiling_by_check
.password_change_session >= 2 (the change and its restore are each charged to
the check's ceiling). The shipped defaults send nothing. The account is always
the run's own; its passwords and tokens are never printed. Every send goes
through the run's gate-routed transport.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from harness import scope_lock
from harness.models import Finding, HttpExchange
from .base import Validator, ValidationResult

FINDING_CLASS = "session_after_password_change"

_CURRENT_KEY = re.compile(r"^(current|old|existing|previous)[-_]?(password|pass|passwd|pwd)?$", re.I)
_NEW_KEY = re.compile(r"^(new[-_]?(password|pass|passwd|pwd)?|(password|pass|pwd)[-_]?new)$", re.I)
_REPEAT_KEY = re.compile(r"repeat|confirm|verify|again|password2|new2", re.I)
_REJECTED = re.compile(r"\b(wrong|invalid|incorrect|failed|denied|mismatch|not match|error)\b", re.I)
_MAX_READS = 6


def change_shape(exchange: HttpExchange):
    """(where, kind, fields, current_key, new_key, repeat_key) of a captured
    change-password request, else None. `where` is "query" or "body"."""
    from .auth_sequence_validator import _parse_body
    candidates = [("query", "form", dict(parse_qsl(urlsplit(exchange.url).query,
                                                   keep_blank_values=True)))]
    fields, kind = _parse_body(exchange)
    candidates.append(("body", kind, fields))
    for where, kind, fields in candidates:
        current = next((k for k in fields if _CURRENT_KEY.match(k)), None)
        new = next((k for k in fields if _NEW_KEY.match(k)), None)
        if current and new:
            repeat = next((k for k in fields if k not in (current, new) and _REPEAT_KEY.search(k)),
                          None)
            return where, kind, fields, current, new, repeat
    return None


def _is_class(low: str) -> bool:
    from harness.categories import canonicalize
    return canonicalize(low) == FINDING_CLASS or "password change" in low or "password_change" in low


class PasswordChangeSessionValidator(Validator):
    name = "password_change_session"
    finding_classes = {
        FINDING_CLASS, "session after password change", "token survives password change",
        "session survives password change", "session not revoked on password change",
        "sessions not invalidated on password change",
    }
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 run_context=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.run_context = run_context

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        low = (finding.vulnerability_class or "").strip().lower()
        return ((super().applies(finding, exchange) or _is_class(low))
                and change_shape(exchange) is not None)

    def _result(self, status, summary, evidence="", *, confidence=0.0, raw=None, limitation=""):
        return ValidationResult(
            self.name, status, FINDING_CLASS, confidence=confidence,
            confirmed=status == "confirmed", summary=summary, evidence=evidence,
            raw_output=json.dumps(raw) if raw is not None else "", limitation=limitation,
            mechanism_classes=(FINDING_CLASS,) if status == "confirmed" else ())

    def _skip(self, why):
        return self._result("skipped", why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        from harness.run_context import ScopePolicy
        from .owned_login import owned_logins
        run = self.run_context
        if run is None:
            return self._skip("the password-change check needs a run context (run-owned identities)")
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._skip(f"host {urlsplit(exchange.url).hostname!r} out of scope")
        shape = change_shape(exchange)
        if shape is None:
            return self._skip("no captured change-password request (current and new password fields)")
        gate = run.gate
        if not gate.config.allow_mutating_replay:
            return self._skip("the password change is a write; needs validators.allow_mutating_replay. "
                              "Nothing was sent")
        _, _, ceiling = gate.mutating_headroom(None, self.name)
        if ceiling < 2:
            return self._skip(f"the change and its restore need 2 writes "
                              f"(validators.mutating_ceiling_by_check.{self.name} >= 2; ceiling is "
                              f"{ceiling}). Nothing was sent")
        origin = ScopePolicy.origin_of(exchange.url)
        login = next((l for l in owned_logins(run) if ScopePolicy.origin_of(l.url) == origin), None)
        if login is None:
            return self._skip("acts only on a run-owned identity with a declared login at this "
                              "origin; none is configured. Nothing was sent")
        return await self._run(exchange, shape, login)

    # --- sends ------------------------------------------------------------------
    async def _send(self, method, url, headers=None, body=None, case_ref=""):
        outcome = await self.run_context.target_transport().send_creds(
            method, url, capability=self.name, headers=dict(headers or {}), body=body,
            case_ref=case_ref)
        if not getattr(outcome, "executed", True) or not outcome.ok or outcome.status is None:
            return None, str(outcome.error or outcome.outcome or "not sent")
        return outcome, ""

    async def _login(self, login, password=None):
        """The credential headers from logging in as `login` (None on failure)."""
        request = login.request(password)
        outcome, _why = await self._send(request.method, request.url, request.headers, request.body)
        if outcome is None:
            return None
        return login.credential_headers(outcome.status, outcome.body, outcome.headers)

    async def _change(self, exchange, shape, creds, current, new, case_ref):
        where, kind, fields, ckey, nkey, rkey = shape
        fields = dict(fields)
        fields[ckey], fields[nkey] = current, new
        if rkey:
            fields[rkey] = new
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host", "authorization", "cookie")}
        headers.update(creds)
        parts = urlsplit(exchange.url)
        method = (exchange.method or "POST").upper()
        if where == "query":
            url, body = urlunsplit(parts._replace(query=urlencode(fields))), exchange.request_body
        else:
            url = exchange.url
            body = json.dumps(fields) if kind == "json" else urlencode(fields)
        outcome, why = await self._send(method, url, headers, body or None, case_ref=case_ref)
        if outcome is None:
            return False, why
        ok = 200 <= outcome.status < 300 and not _REJECTED.search(outcome.body or "")
        return ok, f"HTTP {outcome.status}"

    async def _read(self, url, creds, identifiers):
        from .auth_sequence_validator import _shows_account
        outcome, why = await self._send("GET", url, creds)
        if outcome is None:
            return None, why
        resp = _Resp(outcome)
        return _shows_account(resp, identifiers), resp

    async def _run(self, exchange, shape, login) -> ValidationResult:
        from .auth_sequence_validator import _self_read_urls, _token_denial
        account = login.label
        where = f"{(exchange.method or 'POST').upper()} {urlsplit(exchange.url).path}"
        identifiers = {str(login.fields.get(login.user_key) or "").strip().lower()} - {""}
        original = login.password
        temporary = "Av9!" + secrets.token_urlsafe(12)
        case_ref = f"{self.name}:{secrets.token_hex(4)}"
        raw = {"check": "password_change_session", "identity": account}

        t1 = await self._login(login)
        if not t1:
            return self._result("inconclusive", f"Password-change check not run: run identity "
                                f"{account!r}'s declared login did not return a token. Nothing "
                                f"was changed.")
        read_url = None
        for url in _self_read_urls(exchange, self.run_context)[:_MAX_READS]:
            shows, _resp = await self._read(url, t1, identifiers)
            if shows:
                read_url = url
                break
        if read_url is None:
            return self._result("inconclusive", f"Password-change check not run: no read of run "
                                f"identity {account!r}'s own account was found to test T1 on. "
                                f"Nothing was changed.")
        read_path = urlsplit(read_url).path
        changed, how = await self._change(exchange, shape, t1, original, temporary, case_ref)
        if not changed:
            # A refused change leaves the password as it was; check that it does.
            restored = await self._login(login) is not None
            note = "" if restored else (f" The original password no longer logs in: run identity "
                                        f"{account!r} may be left changed; reset it by hand.")
            return self._result("inconclusive", f"Password-change check stopped: the captured "
                                f"change flow at {where} refused the change ({how}).{note}",
                                raw=raw | {"changed": False, "restored": restored},
                                limitation="" if restored else f"run identity {account!r} may be "
                                f"left with a changed password")
        accepted, resp = await self._read(read_url, t1, identifiers)
        denial = _token_denial(resp, identifiers) if resp is not None and not isinstance(resp, str) else ""

        # Restore: with T1 if it still works, else with a fresh login on the new password.
        restore_creds = t1 if accepted else await self._login(login, temporary)
        restored, restore_how = False, "no token for the changed password"
        if restore_creds:
            put_back, restore_how = await self._change(exchange, shape, restore_creds, temporary,
                                                       original, case_ref)
            restored = put_back and await self._login(login) is not None
            if put_back and not restored:
                restore_how = "the change back was accepted but the original password does not log in"
        restore_note = ("Password restored and the original password verified to log in."
                        if restored else
                        f"RESTORE FAILED ({restore_how}): run identity {account!r} is left with a "
                        f"changed password (not recorded here); reset it by hand.")
        raw |= {"changed": True, "t1_accepted": bool(accepted), "denial": denial,
                "read": read_path, "restored": restored}
        limitation = "" if restored else f"run identity {account!r} is left with a changed password"
        evidence = (f"Logged in as run identity {account!r} (token T1), confirmed T1 reads its "
                    f"account at GET {read_path}, changed the password through {where}, then "
                    f"read GET {read_path} with T1 again: "
                    + ("accepted, the account still shown" if accepted else (denial or "no answer"))
                    + f". {restore_note} Passwords and tokens redacted.")
        if accepted:
            return self._result(
                "confirmed",
                f"Session token survives a password change at {where}: T1, issued before the "
                f"change, still reads run identity {account!r}'s account at GET {read_path}."
                + ("" if restored else f" {restore_note}"),
                evidence, confidence=0.85, raw=raw, limitation=limitation)
        if denial:
            return self._result(
                "not_confirmed",
                f"Sessions are revoked on a password change at {where}: T1 is refused after the "
                f"change ({denial})." + ("" if restored else f" {restore_note}"),
                evidence, raw=raw, limitation=limitation)
        return self._result(
            "inconclusive",
            f"Password-change check inconclusive at {where}: T1's read after the change neither "
            f"showed the account nor was denied." + ("" if restored else f" {restore_note}"),
            evidence, raw=raw, limitation=limitation)


class _Resp:
    """An ExecutionOutcome in the shape the auth_sequence helpers read."""

    def __init__(self, outcome):
        import httpx
        self.status_code = outcome.status
        self.text = outcome.body or ""
        self.headers = httpx.Headers(outcome.headers or {})
