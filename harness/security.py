"""
Shared security helpers for the harness.

This module centralizes security-sensitive policies (e.g., which headers
contain secrets that must never reach LLM prompts) so they can be
consistently applied across all prompt-construction code paths.
"""
from __future__ import annotations
import base64
import json
import logging
import re
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, unquote_plus, quote


# Header names whose VALUES are session-identifying secrets (bearer
# tokens, session cookies, API keys) and must never reach the model --
# only the fact that such a header is present matters for an agent's
# reasoning (e.g. "this request is authenticated"), never the value
# itself. Names only, matched case-insensitively; kept as a module-level
# constant so it's one reviewable list, not scattered inline logic.
SECRET_HEADER_NAMES: set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

# The redaction placeholder text. Kept as a constant so it's the same
# string everywhere, making it easier to search for in logs or model
# context dumps if needed.
REDACTED_PLACEHOLDER = "[REDACTED -- header present, value withheld from model]"
_SAFE_JWT_ALGORITHMS = {"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                        "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}


def _decode_jwt_header_only(token: str) -> dict | None:
    """Best-effort decode of ONLY a JWT's first segment (the algorithm/
    type header) -- never touches the second segment (claims/payload,
    which can carry user-identifying data) or the third (signature).

    Returns the decoded header dict if `token` is JWT-shaped (three
    dot-separated base64url segments) and the first segment decodes to
    JSON containing an "alg" key. Returns None for anything else --
    opaque API keys, non-JWT bearer tokens, or malformed input -- so
    callers fall back to full redaction by default, never partial
    disclosure on a guess.

    Why this exists: full redaction of Authorization made an entire
    vulnerability class (alg=none / algorithm-confusion JWT forgery)
    structurally invisible to every agent, since the evidence needed to
    catch it is the token's own header field -- see
    DISCOVERY_RUN_RESULTS.md, architecture finding #4. The algorithm
    name is metadata about how the token is supposed to be verified, not
    a credential; the payload (who the token is for) and signature (the
    actual secret-derived material) are the parts that must stay hidden,
    and this function never looks at either.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded)
    except Exception:
        return None
    if isinstance(header, dict) and "alg" in header:
        # A JWT header is untrusted and may itself contain credentials/PII.
        # Preserve only recognized algorithm/type metadata, never kid/jwk or
        # arbitrary extension fields (and never arbitrary strings as alg).
        algorithm = header["alg"]
        result = {"alg": algorithm if isinstance(algorithm, str) and algorithm in _SAFE_JWT_ALGORITHMS else "unrecognized"}
        if isinstance(header.get("typ"), str) and header.get("typ") in {"JWT", "at+jwt"}:
            result["typ"] = header["typ"]
        return result
    return None


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact the values of any headers whose names match SECRET_HEADER_NAMES.
    
    Returns a new dict with the same keys. Values for secret-bearing
    header names are replaced with REDACTED_PLACEHOLDER; all other
    headers are copied unchanged.

    One narrow exception: an `Authorization: Bearer <jwt>` value whose
    token is JWT-shaped gets its header segment (only) disclosed
    alongside the redaction notice -- e.g. `{"alg": "none"}` or
    `{"alg": "HS256", "typ": "JWT"}`. This never exposes the payload
    (claims) or signature. Anything that isn't JWT-shaped -- opaque API
    keys, Basic/Digest auth, malformed tokens -- gets the original full
    redaction with no exception.
    
    Matching is case-insensitive on the header name.
    """
    result = {}
    for k, v in headers.items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            jwt_header = _decode_jwt_header_only(v[len("Bearer "):].strip())
            if jwt_header is not None:
                result[k] = (
                    f"Bearer [REDACTED -- payload and signature withheld from model; "
                    f"JWT header only: {json.dumps(jwt_header, sort_keys=True)}]"
                )
                continue
        result[k] = REDACTED_PLACEHOLDER if k.lower() in SECRET_HEADER_NAMES else v
    return result


# PR-9 / R09: the header path above withholds secrets carried in HEADERS
# (Authorization, Cookie, ...). It does nothing for a secret carried in a
# URL query param (?token=...) or a JSON/form request or response BODY
# field (e.g. {"password": "..."}, including nested inside another
# object/list) -- both reach the model raw today. The functions below
# close that gap with the SAME philosophy as redact_headers: redaction is
# driven by the FIELD/PARAM NAME, never by scanning values, so it never
# touches an injection payload sitting in a non-secret field (e.g.
# ?q=1' OR '1'='1 or a <script> in a "search" field) -- the detector must
# still see those to do its job. This is deliberately SCHEMA-AWARE (key
# name), not content-aware: it is a best-effort secret-NAME redactor, not
# a guarantee that no secret of any shape ever reaches the model.
SECRET_FIELD_NAMES: set[str] = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "session",
    "sessionid",
    "authorization",
    "auth",
    "client_secret",
    "private_key",
    "cookie", "set_cookie", "proxy_authorization", "x_auth_token", "x_api_key",
    "id_token", "csrf", "csrf_token", "xsrf_token", "jsessionid", "session_id", "sid", "xsrf", "bearer",
}

# Placeholder used by the secret-NAME redactors below. Deliberately a
# different string than REDACTED_PLACEHOLDER (header redaction) so it's
# obvious from a prompt/log dump which code path withheld a given value.
SECRET_VALUE_PLACEHOLDER = "[REDACTED-SECRET]"


def _is_secret_field_name(name: str) -> bool:
    """Case/punctuation-insensitive EXACT match against SECRET_FIELD_NAMES.

    Normalizes '-' and ' ' to '_' so "api-key" / "API Key" match
    "api_key" the same as "api_key" itself. Deliberately EXACT match, not
    substring: a substring test would also catch "username" (contains no
    secret substring, fine) but could catch task-relevant fields like a
    "search" or "q" param that happens to contain injected text -- exact
    match on the whole (normalized) name is what keeps every non-secret
    field, and any injection payload it carries, intact.
    """
    if not isinstance(name, str):
        return False
    normalized = name.strip().lower().replace("-", "_").replace(" ", "_")
    return normalized in SECRET_FIELD_NAMES


def redact_secrets_in_url(url: str) -> str:
    """Redact the VALUES of secret-named query params in a URL.

    Splits the query string on '&' and, for each "key=value" pair, only
    REPLACES THE VALUE SUBSTRING when the key is secret-shaped (see
    _is_secret_field_name) -- it never fully re-parses/re-encodes the
    query string. This matters as much as the redaction itself: a naive
    parse-then-urlencode round trip would percent-re-encode every OTHER
    param too (e.g. turning a raw `?q=1' OR '1'='1` injection payload
    into `q=1%27+OR+%271%27%3D%271`), which would be just as damaging to
    detection as redacting it outright. Here, every param this function
    does not redact -- key, value, and original raw encoding -- is
    reproduced byte-for-byte, and if the URL has no secret-shaped param
    at all the URL is returned completely unchanged. Param order is
    preserved either way. Malformed input is returned unchanged rather
    than raising -- this is a best-effort prompt-hygiene helper, not a
    URL validator.
    """
    if not url or not isinstance(url, str):
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    def redact_pairs(query):
        result = []
        for pair in query.split("&"):
            key, separator, value = pair.partition("=")
            if separator and value and _is_secret_field_name(unquote_plus(key)) and unquote_plus(value) not in {
                    SECRET_VALUE_PLACEHOLDER, "<REDACTED>"}:
                pair = f"{key}={SECRET_VALUE_PLACEHOLDER}"
            elif separator and value:
                # Report API query parameters can contain an encoded captured
                # URL. Withhold its recognized secrets in diagnostic logs too.
                decoded = unquote_plus(value)
                if decoded.lower().startswith(("https://", "http://")):
                    clean = redact_secrets_in_url(decoded)
                    if clean != decoded:
                        pair = f"{key}={quote(clean, safe='')}"
            result.append(pair)
        return "&".join(result)

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = SECRET_VALUE_PLACEHOLDER + "@" + netloc.rsplit("@", 1)[1]
    query, fragment = redact_pairs(parsed.query), redact_pairs(parsed.fragment)
    if (netloc, query, fragment) == (parsed.netloc, parsed.query, parsed.fragment):
        return url
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def _redact_json_value(value):
    """Recursively redact secret-named keys in a parsed JSON value (dict
    or list), preserving every non-secret key and value -- including
    nested structures -- exactly. Only VALUES of secret-shaped keys are
    replaced; the key name itself is always kept, so the model still
    sees the field existed."""
    if isinstance(value, dict):
        return {
            k: (SECRET_VALUE_PLACEHOLDER if _is_secret_field_name(str(k)) else _redact_json_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(v) for v in value]
    return value


# Conservative fallback for a non-JSON body: matches a single "key=value"
# or "key: value" pair that spans an entire line, capturing the key, the
# separator, and the value. Anything that doesn't fit that shape on a
# line (prose, multi-pair lines without '&', etc.) is left completely
# untouched rather than guessed at.
_KV_LINE_RE = re.compile(r"^(?P<key>[^:=\r\n]+?)(?P<sep>[:=])\s?(?P<value>.*)$")


def _redact_kv_line(line: str) -> str:
    # application/x-www-form-urlencoded-shaped line: several "key=value"
    # pairs joined by '&' on one line, and no ':' (which would suggest a
    # header-style "key: value" line instead). A line with no secret-shaped
    # key at all is returned completely untouched -- byte for byte.
    if "&" in line and "=" in line:
        segments = line.split("&")
        if not any(
            "=" in seg and _is_secret_field_name(unquote_plus(seg.partition("=")[0].strip()))
            for seg in segments
        ):
            return line
        out = []
        for seg in segments:
            if "=" in seg:
                k, _, v = seg.partition("=")
                out.append(f"{k}={SECRET_VALUE_PLACEHOLDER}" if _is_secret_field_name(unquote_plus(k.strip())) else seg)
            else:
                out.append(seg)
        return "&".join(out)

    m = _KV_LINE_RE.match(line)
    if not m or not _is_secret_field_name(m.group("key").strip()):
        return line
    key, sep = m.group("key"), m.group("sep")
    pad = " " if sep == ":" else ""
    return f"{key}{sep}{pad}{SECRET_VALUE_PLACEHOLDER}"


def redact_secrets_in_body(body):
    """Redact secret-named fields from a request/response body before it
    reaches an LLM prompt.

    Accepts a JSON string, an already-parsed dict/list, or an arbitrary
    string body:
      - dict/list, or a string that parses as JSON -- recursively redact
        every secret-named key's VALUE (see _redact_json_value). If
        nothing was actually redacted (no secret-shaped key anywhere),
        a STRING input is returned completely unchanged, byte for byte,
        rather than a freshly re-serialized JSON string -- so formatting
        (whitespace, key order, number representation) is never altered
        when there is nothing to redact. Only when something WAS redacted
        is a fresh `json.dumps` of the result returned.
      - anything else -- a conservative, line-by-line "key=value" /
        "key: value" fallback (see _redact_kv_line) that only ever
        touches a line matching that exact shape with a secret-shaped
        key; everything else, including every injection payload in a
        non-secret field, is returned byte-for-byte unchanged.

    Best-effort only, same as redact_secrets_in_url: this recognizes
    secrets by FIELD NAME, not by scanning values for credential-shaped
    content, so it is not a guarantee that no secret of any form reaches
    the model -- see PR-9 / R09.
    """
    if body is None:
        return body
    if isinstance(body, (dict, list)):
        return json.dumps(_redact_json_value(body))
    if not isinstance(body, str):
        return body
    stripped = body.strip()
    if stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            redacted = _redact_json_value(parsed)
            if redacted == parsed:
                return body
            return json.dumps(redacted)
    return "\n".join(_redact_kv_line(line) for line in body.split("\n"))


_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SECRET_TEXT_KEYS = "|".join(re.escape(name).replace("_", "[_ -]?") for name in
                             sorted(SECRET_FIELD_NAMES | SECRET_HEADER_NAMES, key=len, reverse=True))
_QUOTED_SECRET_RE = re.compile(
    rf"(?i)([\"']?(?:{_SECRET_TEXT_KEYS})[\"']?\s*[:=]\s*)([\"'])(.*?)(\2)")
_INLINE_SECRET_RE = re.compile(
    rf"(?i)(\b(?:{_SECRET_TEXT_KEYS})\s*=\s*)(\[REDACTED-SECRET\]|[^\s&;,\"'\]}}]+)")
_HEADER_LINE_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)(.*)$")


def _safe_redacted_header(value):
    if value in {REDACTED_PLACEHOLDER, SECRET_VALUE_PLACEHOLDER}:
        return True
    prefix = "Bearer [REDACTED -- payload and signature withheld from model; JWT header only: "
    if not value.startswith(prefix) or not value.endswith("]"):
        return False
    try:
        metadata = json.loads(value[len(prefix):-1])
        return (isinstance(metadata, dict) and set(metadata) <= {"alg", "typ"}
                and metadata.get("alg") in _SAFE_JWT_ALGORITHMS | {"unrecognized"}
                and metadata.get("typ", "JWT") in {"JWT", "at+jwt"})
    except (ValueError, TypeError):
        return False


def sanitize_text(text, *, known_values=()):
    """Shared inference/export hygiene for recognized secret structures.

    Handles embedded JSON, URL userinfo/query/fragment, named quoted/inline
    assignments and header lines. Unknown unlabelled prose, binary encodings
    and application-specific secret names remain outside this contract.
    Explicit caller-supplied known_values can withhold opaque values; there is
    no global secret registry. Nonsecret text is preserved when untouched.
    """
    if not isinstance(text, str) or not text:
        return text
    result = redact_secrets_in_body(text)
    # Decode embedded JSON before matching inline forms, including nested
    # objects/lists whose secret-keyed values are not simple strings.
    decoder = json.JSONDecoder()
    replacements = []
    offset = 0
    while offset < len(result):
        brace = result.find("{", offset)
        if brace < 0:
            break
        try:
            parsed, length = decoder.raw_decode(result[brace:])
        except ValueError:
            offset = brace + 1
            continue
        clean = sanitize_data(parsed)
        if clean != parsed:
            replacements.append((brace, brace + length, json.dumps(clean)))
        offset = brace + length
    for start, end, clean in reversed(replacements):
        result = result[:start] + clean + result[end:]
    result = _TEXT_URL_RE.sub(lambda match: redact_secrets_in_url(match.group()), result)
    result = _QUOTED_SECRET_RE.sub(lambda match: match[1] + match[2] + SECRET_VALUE_PLACEHOLDER + match[4], result)
    result = _INLINE_SECRET_RE.sub(lambda match: match[0] if match[2] == "<REDACTED>"
                                  else match[1] + SECRET_VALUE_PLACEHOLDER, result)
    # Idempotence retains the restricted JWT metadata already emitted above.
    result = _HEADER_LINE_RE.sub(lambda match: match[0] if _safe_redacted_header(match[2])
                                 else match[1] + SECRET_VALUE_PLACEHOLDER, result)
    for value in known_values:
        if isinstance(value, str) and value:
            result = result.replace(value, SECRET_VALUE_PLACEHOLDER)
    return result


def sanitize_data(value, *, known_values=()):
    """Return a sanitized structural copy; never mutate authoritative input."""
    if isinstance(value, dict):
        return {key: SECRET_VALUE_PLACEHOLDER if _is_secret_field_name(str(key))
                else sanitize_data(child, known_values=known_values) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_data(child, known_values=known_values) for child in value]
    return sanitize_text(value, known_values=known_values) if isinstance(value, str) else value


def sanitized_exchange(exchange):
    """A prompt-only copy of captured traffic, retaining method/status/shape."""
    return exchange.model_copy(update={
        "url": redact_secrets_in_url(exchange.url),
        "request_headers": redact_headers(exchange.request_headers),
        "response_headers": redact_headers(exchange.response_headers),
        "request_body": sanitize_text(exchange.request_body),
        "response_body": sanitize_text(exchange.response_body),
        "analyst_note": sanitize_text(exchange.analyst_note),
    })


def sanitize_for_inference(system_prompt, user_prompt):
    """Final provider boundary; same policy for local and opt-in cloud roles."""
    return sanitize_text(system_prompt), sanitize_text(user_prompt)


def safe_error_summary(error):
    """Retain error type without arbitrary upstream body/URL/credential text."""
    return f"{type(error).__name__}: operation failed; sensitive upstream detail withheld"


class PrivacyLogFilter(logging.Filter):
    """Sanitize formatted diagnostics before handlers can persist them."""
    def filter(self, record):
        record.msg = sanitize_text(record.getMessage())
        record.args = ()
        return True


def install_privacy_log_filters():
    """Protect HTTP diagnostics and the harness server's existing handlers."""
    for destination in [logging.getLogger("httpx"), logging.getLogger("httpcore"),
                        *logging.getLogger().handlers]:
        if not any(isinstance(item, PrivacyLogFilter) for item in destination.filters):
            destination.addFilter(PrivacyLogFilter())


# Provider-only use may not import the server or configure root handlers.
install_privacy_log_filters()


def _restrict_windows_file_acl(path: Path) -> None:
    """Protect an empty disposable file with the current user's explicit DACL.

    The subprocess receives a path only, never credential bytes. Permission
    errors fail publication; chmod on Windows is not a confidentiality boundary.
    Administrators/SYSTEM can take ownership; this does not provide encryption.
    """
    script = r"""
    $ErrorActionPreference = 'Stop'
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    [System.IO.File]::SetAccessControl($env:AGENTIC_CREDENTIAL_TEMP_PATH, $acl)
    $actual = [System.IO.File]::GetAccessControl($env:AGENTIC_CREDENTIAL_TEMP_PATH)
    if (-not $actual.AreAccessRulesProtected) { throw 'DACL inheritance remains enabled' }
    $rules = @($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or
        $rules[0].AccessControlType -ne 'Allow' -or $rules[0].IsInherited) {
        throw 'Unexpected credential file DACL'
    }
    """
    environment = os.environ.copy()
    # Use Windows PowerShell's built-in .NET Framework ACL methods; no module
    # dependency or inherited custom module lookup is needed.
    environment.pop("PSModulePath", None)
    environment["AGENTIC_CREDENTIAL_TEMP_PATH"] = str(path.resolve())
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                       env=environment, capture_output=True, check=True, timeout=15,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as error:
        raise PermissionError("credential file DACL could not be established") from error


def write_private_credential_file(path: Path, value: str) -> None:
    """Publish a private credential atomically, restricting permissions first.

    Caller owns the containing directory. Existing file bytes are never read;
    replacement retains the newly protected file's permissions. On failure the
    old destination is untouched and the disposable file is removed. This is
    publication only, not token discovery, backup, retention or encryption.
    """
    path = Path(path)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise PermissionError("credential publication through symlinks is refused")
    fd, temporary_name = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if os.name == "nt":
            _restrict_windows_file_acl(temporary)
        else:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        temporary.unlink(missing_ok=True)
