"""A run-owned identity's declared login (R11-8 b).

Legs that must log in -- the failed-login burst, the password-change token check
-- act only on an identity the run owns: one whose login the operator declared
in the run's identity configuration (role.login, kept on its ManagedSession by
SessionManager.set_login). The credentials come from that declaration only and
stay in memory: nothing here logs, prints or returns a password or token in
text meant for a report. Every send goes through the run's gate-routed executor.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from urllib.parse import parse_qsl, urljoin, urlsplit

from harness.run_context import ScopePolicy, TypedRequest

_USER_KEYS = ("username", "user", "email", "login", "userid", "user_name")
_PASS_KEYS = ("password", "pass", "passwd", "pwd")


@dataclass
class OwnedLogin:
    session: object            # the ManagedSession that owns the login
    method: str
    url: str
    fields: dict
    kind: str                  # "json" or "form"
    content_type: str
    user_key: str
    pass_key: str
    token_pointer: str = ""
    header: str = "Authorization"
    scheme: str = "Bearer"
    cookie: str = ""

    @property
    def label(self) -> str:
        s = self.session
        return s.name or s.principal_id or s.session_id

    @property
    def password(self) -> str:
        return str(self.fields.get(self.pass_key) or "")

    def body(self, password: str | None = None) -> str:
        fields = dict(self.fields)
        if password is not None:
            fields[self.pass_key] = password
        if self.kind == "json":
            return json.dumps(fields)
        from urllib.parse import urlencode
        return urlencode(fields)

    def request(self, password: str | None = None) -> TypedRequest:
        return TypedRequest(self.method, self.url, headers={"Content-Type": self.content_type},
                            body=self.body(password))

    def credential_headers(self, status, body, headers) -> dict | None:
        """The credential headers a successful login response carries, by the
        declaration's token_pointer / cookie; None when it carries none."""
        from harness.session_freshness import _json_pointer, _set_cookies
        if status is None or not 200 <= status < 300:
            return None
        fresh: dict = {}
        if self.token_pointer:
            token = _json_pointer(body, self.token_pointer)
            if isinstance(token, str) and token:
                fresh[self.header] = f"{self.scheme} {token}" if self.scheme else token
        if self.cookie:
            for name, value in _set_cookies(headers):
                if name == self.cookie and value:
                    fresh["Cookie"] = f"{name}={value}"
        if not self.token_pointer and not self.cookie:
            from .auth_sequence_validator import _login_token
            import httpx
            minted = _login_token(SimpleNamespace(text=body or "",
                                                  headers=httpx.Headers(headers or {})))
            if minted is not None:
                fresh["Authorization"] = f"Bearer {minted[1]}"
        return fresh or None


def _fields(body, content_type: str):
    if body is None:
        return {}, "json"
    if isinstance(body, dict):
        return dict(body), "json"
    text = str(body)
    if "json" in content_type.lower() or text.strip().startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return dict(obj), "json"
        except ValueError:
            pass
    if "=" in text:
        return dict(parse_qsl(text, keep_blank_values=True)), "form"
    return {}, "form"


def _key(fields: dict, keys) -> str | None:
    low = {k.lower(): k for k in fields}
    return next((low[k] for k in keys if k in low), None)


def owned_logins(run) -> list[OwnedLogin]:
    """Every run identity with a declared login that names a user and a password."""
    out = []
    sessions = getattr(run, "sessions", None)
    for session in (sessions.identities() if sessions is not None else []):
        login = getattr(session, "login", None)
        if not login or getattr(session, "ephemeral", False):
            continue
        ctype = str(login.get("content_type") or "application/json")
        fields, kind = _fields(login.get("body"), ctype)
        ukey, pkey = _key(fields, _USER_KEYS), _key(fields, _PASS_KEYS)
        if not ukey or not pkey or not str(fields.get(pkey) or ""):
            continue
        out.append(OwnedLogin(
            session=session, method=str(login.get("method") or "POST").upper(),
            url=urljoin(session.login_base or "", str(login.get("path") or "/")),
            fields=fields, kind=kind, content_type=ctype, user_key=ukey, pass_key=pkey,
            token_pointer=str(login.get("token_pointer") or ""),
            header=str(login.get("header") or "Authorization"),
            scheme=login.get("scheme", "Bearer"), cookie=str(login.get("cookie") or "")))
    return out


def owned_login_for(run, exchange) -> OwnedLogin | None:
    """The run-owned identity's login whose origin and path are the captured
    exchange's own (the exchange is that login endpoint), else None. A leg sends
    the declared login's own method and body, never the capture's."""
    origin = ScopePolicy.origin_of(exchange.url)
    path = urlsplit(exchange.url).path.rstrip("/") or "/"
    for login in owned_logins(run):
        if (ScopePolicy.origin_of(login.url) == origin
                and (urlsplit(login.url).path.rstrip("/") or "/") == path):
            return login
    return None
