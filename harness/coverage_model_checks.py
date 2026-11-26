"""Check model: the applicability predicates, ExternalRef and the Check row type.

Part of the ARC-9 split of harness.coverage_model. Import these names from
harness.coverage_model, the facade, not from this module.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

from harness.categories import canonicalize
from harness.client_routes import (
    CLIENT_ROUTE_LEGS, route_params_of_template, route_segments_of_template,
)
from harness.coverage_model_cells import Phase, captured_parameter_names
from harness.wstg_ids import WSTG_RELEASE_LABEL


def _has_params(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path or "{" in path or re.search(r"/\d+(?:/|$)", path):
        return True, "endpoint has parameters or path variables"
    # The endpoint key's path is normalized without its query, so a GET whose
    # captures carry `?q=` (even blank) was never read as taking input: r7's search
    # endpoint got no injection cell at all. The captured request decides.
    captured = captured_parameter_names(endpoint)
    if captured:
        return True, f"a captured request carries parameter(s) {', '.join(captured[:3])}"
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "no parameters or body-bearing methods detected"

def _accepts_input(endpoint: dict) -> tuple[bool, str]:
    has, reason = _has_params(endpoint)
    if has:
        return True, reason
    return False, "endpoint does not accept user-controllable input"

def _is_authed(endpoint: dict) -> tuple[bool, str]:
    access = endpoint.get("access", {})
    reachable = endpoint.get("reachable_roles", [])
    if access or reachable:
        return True, "endpoint has role/access data"
    return False, "no role/access information available"

def _is_object_scoped(endpoint: dict) -> tuple[bool, str]:
    if endpoint.get("object_scoped"):
        return True, "endpoint is object-scoped (e.g. /resource/{id})"
    path = endpoint.get("path", "")
    if re.search(r"/\{?id\}?|/\d+(?:/|$)", path):
        return True, "path contains an object identifier"
    return False, "not object-scoped"

def _accepts_xml(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        path = (endpoint.get("path", "") or "").lower()
        if any(k in path for k in ("import", "xml", "upload", "feed", "rss", "soap")):
            return True, "body-bearing method on an XML-associated path"
    return False, "no XML-accepting indicators"

def _has_url_param(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path:
        return True, "endpoint has query parameters"
    lower = (path or "").lower()
    if any(k in lower for k in ("redirect", "url", "next", "return", "goto", "link",
                                 "forward", "continue", "callback", "proxy", "fetch")):
        return True, "path suggests URL/redirect parameter"
    return False, "no URL parameter indicators"

def _has_auth_endpoint(endpoint: dict) -> tuple[bool, str]:
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in ("login", "auth", "signin", "sign-in", "session",
                                "token", "oauth", "register", "signup", "sign-up",
                                "password", "reset", "mfa", "2fa", "verify")):
        return True, "authentication-related endpoint"
    return False, "not an authentication endpoint"

_LOOKUP_IDENTIFIERS = ("username", "user", "email", "login", "userid", "user_name")


def _has_auth_endpoint_or_lookup(endpoint: dict) -> tuple[bool, str]:
    """An auth endpoint, or a GET whose capture names an account in its query (a
    recovery lookup such as ?email=). R11-8 (c): r11 never opened the enumeration
    cell on a lookup whose path names no auth word."""
    hit, reason = _has_auth_endpoint(endpoint)
    if hit:
        return hit, reason
    if "GET" in (endpoint.get("methods") or ("GET",)) and any(
            name.lower() in {f"query:{k}" for k in _LOOKUP_IDENTIFIERS}
            for name in captured_parameter_names(endpoint)):
        return True, "a captured GET names an account identifier in its query"
    return False, reason


def _has_file_path_segment(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if re.search(r"/(upload|file|download|media|attachment|avatar|image|doc|asset)s?(/|$)", path, re.I):
        return True, "path suggests file handling"
    if re.search(r"/\d+(?:/|$)", path) and any(
            k in (path or "").lower() for k in ("upload", "file", "attachment", "media")):
        return True, "object-scoped file endpoint"
    return False, "no file-handling indicators"

def _always_applicable(_endpoint: dict) -> tuple[bool, str]:
    return True, "domain-level check (applies to all endpoints)"

def _has_cookie_or_session(endpoint: dict) -> tuple[bool, str]:
    if _has_auth_endpoint(endpoint)[0]:
        return True, "authentication endpoint likely involves sessions"
    access = endpoint.get("access", {})
    if access:
        return True, "endpoint has access-control data suggesting session use"
    return False, "no session/cookie indicators"

def _accepts_body(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "endpoint does not accept request bodies"


def _accepts_create(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if "POST" in methods:
        return True, "endpoint accepts POST (a create)"
    return False, "endpoint accepts no POST create"


# --- WG-2: narrow predicates for the rows of already-registered validators. Each
# fires only where the exchange shape fits the validator's own oracle, so a new row
# does not add coverage-drive work on endpoints its leg would decline anyway.

def _query_and_body_keys(endpoint: dict) -> set[str]:
    """Lower-cased parameter names visible on the endpoint: the path's own query
    string plus the captured template's query and (form or JSON top-level) body."""
    template = endpoint.get("template") or {}
    path = endpoint.get("path", "") or ""
    keys = {k.lower() for k, _ in parse_qsl(urlsplit(path).query, keep_blank_values=True)}
    keys |= {k.lower() for k, _ in parse_qsl(template.get("query", "") or "",
                                             keep_blank_values=True)}
    body = template.get("body", "") or ""
    if body:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            keys |= {k.lower() for k, _ in parse_qsl(body, keep_blank_values=True)}
        else:
            if isinstance(parsed, dict):
                keys |= {str(k).lower() for k in parsed}
    return keys

def _issues_session_cookie(endpoint: dict) -> tuple[bool, str]:
    headers = endpoint.get("response_headers") or {}
    if endpoint.get("sets_cookie") or any((k or "").lower() == "set-cookie" for k in headers):
        return True, "response sets a cookie"
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in ("login", "signin", "sign-in", "logon", "session")):
        return True, "login/session endpoint issues the session cookie"
    return False, "no Set-Cookie response or login/session endpoint"

def _is_websocket_endpoint(endpoint: dict) -> tuple[bool, str]:
    if endpoint.get("websocket") or (endpoint.get("upgrade") or "").lower() == "websocket":
        return True, "endpoint performs a WebSocket upgrade"
    path = (endpoint.get("path", "") or "").lower()
    if re.search(r"(^|/)(ws|wss|websockets?|socket\.io|sockjs|cable)(/|$|\?)", path):
        return True, "path is a WebSocket handshake endpoint"
    return False, "no WebSocket upgrade indicators"

_OAUTH_PARAMS = frozenset({"redirect_uri", "response_type", "client_id"})

def _has_oauth_params(endpoint: dict) -> tuple[bool, str]:
    if _query_and_body_keys(endpoint) & _OAUTH_PARAMS:
        return True, "request carries OAuth parameters (redirect_uri/response_type/client_id)"
    path = (endpoint.get("path", "") or "").lower()
    if "oauth" in path or re.search(r"/authorize(/|$|\?)", path):
        return True, "OAuth authorization endpoint"
    return False, "no OAuth parameters or authorization endpoint"

def _has_denied_role(endpoint: dict) -> tuple[bool, str]:
    access = endpoint.get("access") or {}
    if any(str(v) in ("401", "403", "405") for v in access.values()):
        return True, "a role is denied (401/403/405), so a verb alternate can be tested"
    return False, "no denied role recorded (verb tampering needs a denial to bypass)"

_CLIENT_VALUE_FIELD = re.compile(
    r"price|amount|total|cost|discount|quantity|qty|subtotal|fee|balance")
_CLIENT_VALUE_PATH = ("cart", "checkout", "basket", "order", "payment", "purchase")

def _flow_shape(kind: str):
    """A predicate: the endpoint's captured write has the business-flow shape `kind`."""
    def predicate(endpoint: dict) -> tuple[bool, str]:
        from harness.validators.business_flow_validator import endpoint_flow_kind
        got = endpoint_flow_kind(endpoint)
        if got == kind:
            return True, f"captured write has the {kind} flow shape"
        return False, f"no captured write with the {kind} flow shape"
    predicate.__name__ = f"_flow_shape_{kind}"
    return predicate


def _has_client_value_field(endpoint: dict) -> tuple[bool, str]:
    if not _accepts_body(endpoint)[0]:
        return False, "no body-bearing write to tamper"
    if any(_CLIENT_VALUE_FIELD.search(k) for k in _query_and_body_keys(endpoint)):
        return True, "write carries a client-supplied value field (price/amount/total)"
    body = (endpoint.get("template") or {}).get("body") or ""
    if body:
        # The leg's own recogniser (payment source, plan/tier, currency, coupon,
        # role/status flag), so the row applies wherever the leg has a field to tamper.
        from harness.validators.client_trust_validator import body_trust_fields
        found = body_trust_fields(body)
        if found:
            return True, f"write carries a server-owned {found[0].family} field ({found[0].key})"
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in _CLIENT_VALUE_PATH):
        return True, "write on a cart/checkout/order/payment path"
    return False, "no client-supplied value field on this write"

def _is_file_upload_write(endpoint: dict) -> tuple[bool, str]:
    # The file_upload leg skips any non-POST/PUT/PATCH exchange, so a file-handling
    # path alone (a GET /download/...) gives it nothing to run.
    if not _accepts_body(endpoint)[0]:
        return False, "no body-bearing write to upload through"
    has, reason = _has_file_path_segment(endpoint)
    if has:
        return True, f"body-bearing write; {reason}"
    return False, reason

def _is_get(endpoint: dict) -> tuple[bool, str]:
    if any(m in ("GET", "HEAD") for m in endpoint.get("methods", ())):
        return True, "GET response can be cached"
    return False, "not a GET/HEAD endpoint (not cached)"

def _is_authed_get(endpoint: dict) -> tuple[bool, str]:
    if not _is_get(endpoint)[0]:
        return False, "not a GET/HEAD endpoint (not cached)"
    if _is_authed(endpoint)[0]:
        return True, "authenticated GET content could be cached for another user"
    return False, "no role/access information (no per-user content to deceive a cache with)"


# Predicate type: endpoint dict → (applicable: bool, reason: str)
ApplicabilityPredicate = Callable[[dict], tuple[bool, str]]


# ---------------------------------------------------------------------------
# Check — one entry in the catalog
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExternalRef:
    """An independently-verified external reference for a check.

    Kept structured (not a bare string) so a report can distinguish a genuine WSTG
    test id from an OWASP-API entry or an Academy topic, and so we never encode a
    catalog id we cannot stand behind. `catalog` names the source (e.g. "WSTG",
    "OWASP API Security Top 10 2023", "PortSwigger Academy"); `ref` is the id within
    it (e.g. "WSTG-INJT-05", "API3:2023") or "" for a URL-only reference."""
    catalog: str
    ref: str = ""
    url: str = ""
    title: str = ""
    version: str = ""


@dataclass(frozen=True)
class Check:
    """A single security check in the catalog.

    The `id` is the check's PRIMARY identifier. For checks that map cleanly onto a
    WSTG test it is the current WSTG id (WG-1: checked against the vendored list in
    `harness/wstg_ids.py`; `wstg_version` names the release it is anchored to). For a
    scenario with NO clean WSTG mapping it is an INTERNAL `AV-*` id, and the real
    external sources live in `external_refs` -- so the catalog never falsely labels a
    scenario with a WSTG id that means something else. IDs the catalog used before
    WG-1 resolve through `LEGACY_CHECK_ID_ALIASES`. WSTG and Academy are *reference
    catalogs* here, not an exploitation runner.
    """
    id: str                              # e.g. "WSTG-INJT-05" or an internal "AV-*" id
    name: str                            # human-readable
    phase: Phase
    vulnerability_class: str             # maps to categories.canonicalize
    applicability: ApplicabilityPredicate
    confirmation: str                    # "sqlmap" | "cross_identity" | "agent" | "manual" | ...
    description: str = ""
    academy_ref: str = ""                # PortSwigger Academy topic name if applicable
    academy_url: str = ""                # optional full Academy topic URL (scenario reference)
    wstg_version: str = WSTG_RELEASE_LABEL   # the WSTG release a genuine WSTG id is anchored to
    external_refs: tuple[ExternalRef, ...] = ()   # independently-verified external sources
    origin_scoped: bool = False  # A transport/deployment fact, not a response policy.
    # WG-2 (4): finding-class tokens (lower-case; space and snake forms) that pick out
    # THIS row among the rows sharing its canonical class, so one finding is attributed
    # to the one cell it names, not to every sibling. Required on every row of a shared
    # class (`shared_class_specificity_problems`); no token may sit on two rows.
    specific_classes: tuple[str, ...] = ()
    # WG-2 (3): the class the coverage driver hands the leg. Empty = vulnerability_class.
    # Lets a shared-class row route to its own sub-check (e.g. auth_sequence's enum leg).
    leg_class: str = ""
    # R11-10: True when the check's verdict on an endpoint does not depend on who
    # sends the request (injection, error handling, client policy headers ...). Then
    # one identity's run of the check on an endpoint stands for every identity's
    # cell there, and an identity with no capture of that endpoint is not a gap
    # (CoverageTracker.credit_caller_independent). False (the default) keeps the cell
    # identity-bound: access control, sessions, authentication, exposure, and any
    # row where the caller's account or privilege can change the verdict. Set in
    # one place, `_CALLER_INDEPENDENT_CHECKS` below the catalog.
    caller_independent: bool = False

    def applies(self, endpoint: dict) -> tuple[bool, str]:
        """Deterministic applicability + the rationale for WHY it applies or doesn't.

        A client-side route input (client_routes.py) is loaded in a browser, so it
        applies to the browser XSS legs only. A route the run knows only from the
        page (no captured request of its own) is that leg's endpoint alone."""
        location, names = route_params_of_template(endpoint.get("template"))
        names = names + [":" + s for s in route_segments_of_template(endpoint.get("template"))]
        if endpoint.get("client_route_only"):
            if self.confirmation in CLIENT_ROUTE_LEGS and names:
                return True, (f"client-side route reads {location} parameter(s) "
                              f"{', '.join(names[:3])}")
            return False, "client-side route: only the browser XSS legs load it"
        applicable, reason = self.applicability(endpoint)
        if not applicable and self.confirmation in CLIENT_ROUTE_LEGS and names:
            return True, (f"client-side route reads {location} parameter(s) "
                          f"{', '.join(names[:3])}")
        return applicable, reason

    def canonical_class(self) -> str | None:
        return canonicalize(self.vulnerability_class)

    def is_wstg(self) -> bool:
        """Whether the primary id is a genuine WSTG test id."""
        return self.id.startswith("WSTG-")

    def reference_label(self) -> str:
        """A human label for the primary id: versioned for a genuine WSTG id, else the
        internal id marked as such (external sources are in `external_refs`)."""
        if self.is_wstg():
            # A numbered release reads "WSTG v4.2"; the unnumbered master set reads
            # "WSTG latest" (never "vlatest").
            version = self.wstg_version
            prefix = "v" if version[:1].isdigit() else ""
            return f"{self.id} (WSTG {prefix}{version})"
        return f"{self.id} (internal scenario)"

    # Back-compat alias; only meaningful for genuine WSTG ids.
    def wstg_ref(self) -> str:
        return self.reference_label()
