"""Parameter enumeration, mutation and request-shape helpers for the sqlmap validator: moved
verbatim out of sqlmap.py (ARC-9). Pure functions over a captured request; nothing here sends."""

from __future__ import annotations

import httpx
import json as _json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from harness.engagement import leaf_object_id_index
from harness.models import HttpExchange


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


def _named_input(finding) -> tuple[str, str]:
    return ((getattr(finding, "parameter_location", "") or "").strip().lower(),
            (getattr(finding, "parameter_name", "") or "").strip())


def _addressable_params(loc: str, exchange) -> list[str]:
    """The parameters `-p` can name at case location `loc`: the query string's, or a
    urlencoded (not JSON) body's. Empty for any other location."""
    if loc == "query":
        return _query_top_level_params(exchange.url)
    body = exchange.request_body or ""
    if loc == "body_form" and not _looks_like_json(body, _content_type_of(exchange)):
        return _form_top_level_params(body)
    return []


# sqlmap's custom injection marker. A URL carrying it is tested at the marked point
# only: sqlmap then leaves the query string unparsed (lib/core/target.py), and
# `--param-filter URI` keeps a body's parameters out too.
_URI_MARK = "*"


def _marked_path_url(url: str, name: str) -> str | None:
    """`url` with sqlmap's marker after the path input a coverage case names: the
    leaf object id (CaseKey("path", "object_id")). None for any other path input,
    or a path without an object id: that input is not tested."""
    if name != "object_id":
        return None
    parts = urlsplit(url)
    segments = (parts.path or "").split("/")
    leaf = leaf_object_id_index(parts.path or "")
    if leaf is None:
        return None
    segments[leaf] += _URI_MARK
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, ""))


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


_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")


def _error_probe_values(original: str, quote: str) -> tuple[str, str] | None:
    """(breaking, control) for an error-based reproduction, or None.

    The control is well formed and NOT the original value, so it exercises the same
    path as the breaking value: in a quoted context the quote doubled, in a numeric
    one the number minus zero (a parameterized integer field rejects "5-0" exactly as
    it rejects "5'"; SQL text evaluates it to the original). A numeric context with a
    non-numeric value has no such control."""
    if quote:
        return original + quote, original + quote * 2
    if not _NUMBER.match(original):
        return None
    return original + "'", original + "-0"


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
