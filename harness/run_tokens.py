"""R11-6 (a): resolve a capture's credentials to the run identity that was issued them.

A capture made with a run identity's session token is that identity's request, even
when its credential headers are not byte-equal to the session's: a browser or crawl
adds the server's own cookies (a language or banner cookie) to the session cookie,
and a sign-in refresh replaces the token the capture carried (r11: 31 exposure checks
skipped with "the captured GET's principal is not a registered session").

A token counts as run-issued when the run's own session for an identity carries it
now, or carried it before a refresh (`ManagedSession.retired_credentials`). Only
digests are compared and kept; no token value is logged or returned.

Rules (`issued_identity`):
- every non-cookie identity credential header in the capture (Authorization, an API
  key header) must hold a value issued to the identity: a foreign bearer token is
  never mapped, whatever cookies ride with it;
- a cookie the identity's own headers name must hold a value issued to it; cookies
  it does not name are the server's (not this identity's credential) and are ignored;
- at least one value must match, and exactly one identity may match.
"""
from __future__ import annotations

import hashlib

from harness.security import is_identity_credential_header


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _cookies(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(";"):
        name, sep, val = part.partition("=")
        if sep and name.strip():
            out[name.strip()] = val.strip()
    return out


def _header_token(value: str) -> str:
    """The credential in a header value: an Authorization scheme ("Bearer ") dropped."""
    text = (value or "").strip()
    scheme, sep, rest = text.partition(" ")
    return rest.strip() if sep and rest.strip() and scheme.isalpha() else text


def credential_parts(headers: dict | None) -> tuple[dict[str, str], dict[str, str]]:
    """({header name: token digest}, {cookie name: value digest}) for the identity
    credentials in `headers`. Empty values are dropped."""
    plain: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for name, value in (headers or {}).items():
        lower = (name or "").lower()
        if not is_identity_credential_header(name) or not isinstance(value, str):
            continue
        if lower == "cookie":
            cookies.update({k: _digest(v) for k, v in _cookies(value).items() if v})
        else:
            token = _header_token(value)
            if token:
                plain[lower] = _digest(token)
    return plain, cookies


def issued_digests(headers: dict | None, retired=()) -> tuple[set[str], set[str]]:
    """(every token digest an identity was issued, the cookie names it uses): its
    current headers' values plus `retired` digests from before a refresh."""
    plain, cookies = credential_parts(headers)
    return set(plain.values()) | set(cookies.values()) | set(retired or ()), set(cookies)


def _matches(capture_plain: dict, capture_cookies: dict, issued: set, cookie_names: set) -> bool:
    if any(d not in issued for d in capture_plain.values()):
        return False   # a foreign bearer/API key: never this identity's request
    own = {name: d for name, d in capture_cookies.items() if name in cookie_names}
    if any(d not in issued for d in own.values()):
        return False   # this identity's session cookie, holding another value
    return bool(capture_plain) or bool(own)


def issued_identity(identities: list[dict], headers: dict | None, sessions=None) -> dict | None:
    """The one identity in `identities` (entries with "headers" and, in a run,
    "session_ref") whose run-issued tokens the capture `headers` carry, else None.
    `sessions` (a SessionManager) supplies each session's retired credentials."""
    capture_plain, capture_cookies = credential_parts(headers)
    if not capture_plain and not capture_cookies:
        return None
    found = []
    for ident in identities or ():
        retired = ()
        if sessions is not None and ident.get("session_ref"):
            session = sessions.get(ident.get("session_ref"))
            retired = getattr(session, "retired_credentials", ()) if session is not None else ()
        issued, cookie_names = issued_digests(ident.get("headers"), retired)
        if issued and _matches(capture_plain, capture_cookies, issued, cookie_names):
            found.append(ident)
    if len(found) != 1:
        return None   # none, or a token two identities share: no principal is asserted
    return found[0]
