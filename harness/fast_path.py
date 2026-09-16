"""
Fast-path agent selection for token efficiency.

This module provides deterministic agent selection that bypasses the
coordinator LLM call for obvious cases, significantly reducing token usage.

Design principles:
1. Always safe: fast-path selection must be a subset of what the coordinator
   would select, never miss a relevant agent
2. Conservative: when in doubt, fall back to coordinator
3. Fast: all checks are O(1) or O(n) where n is small (number of agents)
4. Extensible: easy to add new patterns without modifying core logic

Token savings: skips the coordinator LLM call whenever a request matches a
deterministic pattern below; the magnitude depends on how many requests match and
is not a fixed figure (no maintained benchmark backs a specific percentage --
review weakness #19).

Pattern categories:
- URL/path patterns (e.g., /api/graphql, /admin, /login)
- HTTP method patterns (e.g., POST with JSON body)
- Response patterns (e.g., error messages, stack traces)
- Header patterns (e.g., Content-Type: application/json)
- Parameter patterns (e.g., ?id=, ?user=)
"""
from __future__ import annotations
import re
import json
import logging
from typing import Optional

from harness.models import HttpExchange

log = logging.getLogger("harness.fast_path")


# =============================================================================
# Pattern Definitions
# =============================================================================

# URL/Path patterns that strongly indicate specific vulnerability classes
# Format: (compiled_regex, [agent_names])
_URL_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    # GraphQL endpoints
    (re.compile(r'/graphql|/api/graphql|/gql', re.IGNORECASE), ['graphql', 'sqli', 'idor', 'business_logic']),
    
    # OAuth / OIDC endpoints
    (re.compile(r'/oauth|/authorize|/oidc|/openid|/\.well-known/openid-configuration', re.IGNORECASE), ['oauth']),

    # WebSocket-shaped paths (common conventions, actual protocol upgrade
    # is confirmed by the Upgrade request header, matched below)
    (re.compile(r'/ws/|/websocket|/socket\.io|/wss/', re.IGNORECASE), ['websocket']),

    # API endpoints likely to carry create/update bodies or list/paging params
    (re.compile(r'/api/', re.IGNORECASE), ['api_security']),
    
    # AI/LLM endpoints
    (re.compile(r'/ai|/llm|/chat|/assistant|/completion|/prompt|/agent|/copilot', re.IGNORECASE), ['ai_security', 'ai_llm']),
    
    # Admin/management endpoints - often have auth issues
    (re.compile(r'/admin|/administrator|/manage|/console|/panel', re.IGNORECASE), 
     ['auth', 'idor', 'misconfig']),
    
    # Login/authentication endpoints. Includes sqli: credential fields
    # (username/email/password) flowing into a login query are one of
    # the single most classic SQL-injection points there is. Found
    # missing during the testing/test-target/ scoring pass: a real
    # SQLi auth-bypass exchange (`{"username": "admin' -- ", ...}`)
    # dispatched auth/business_logic but never sqli, so the one agent
    # actually equipped to recognize the injection syntax never saw the
    # exchange at all -- confirmed live against both PixelMart's TP1
    # and (separately, earlier this session) a real Juice Shop
    # `admin@juice-sh.op' -- ` login bypass.
    # rate_limit added: a login/authentication endpoint with no
    # brute-force throttling is one of the most classic, universally
    # relevant checks there is here -- rate_limit had zero fast_path
    # entries anywhere in this file.
    (re.compile(r'/login|/logins|/auth|/authenticate|/signin|/sign_in|/sessions', re.IGNORECASE),
     ['auth', 'business_logic', 'sqli', 'rate_limit']),
    
    # Registration endpoints
    (re.compile(r'/register|/registration|/signup|/sign_up|/create_account', re.IGNORECASE), 
     ['auth', 'business_logic']),
    
    # Password reset endpoints
    (re.compile(r'/password|/pwd|/reset|/forgot|/recover', re.IGNORECASE), 
     ['auth', 'business_logic']),
    
    # API endpoints with version
    (re.compile(r'/api/v\d+|/rest/v\d+|/v\d+/api', re.IGNORECASE), 
     ['sqli', 'xss', 'idor', 'misconfig']),
    
    # File upload endpoints. file_upload added: found missing live against
    # a real Juice Shop /file-upload request -- this URL pattern already
    # matched (hence xss/misconfig/supply_chain firing), but never included
    # the one agent actually built to test file uploads.
    (re.compile(r'/upload|/uploads|/file|/files|/import|/export', re.IGNORECASE),
     ['xss', 'misconfig', 'supply_chain', 'file_upload']),
    
    # User/profile endpoints
    (re.compile(r'/user|/users|/profile|/account|/me', re.IGNORECASE), 
     ['idor', 'auth', 'misconfig']),

    # Order/transaction-shaped endpoints (found missing during the
    # PixelMart discovery run: /api/orders/<id> is a textbook IDOR
    # target -- sequential resource ids owned per-user -- but had no
    # matching URL pattern at all, so idor was never dispatched for it
    # unless something else incidentally fired. See DISCOVERY_RUN_RESULTS.md.
    # basket/cart added: found missing live against a real Juice Shop
    # `GET /rest/basket/<id>` request -- exactly the same per-user-owned,
    # sequential-id-in-the-URL shape as order/invoice/booking, just a
    # different noun. idor was not dispatched at all for it.)
    # track-order added: found missing during the Juice Shop full run --
    # `GET /rest/track-order/<id>` is the same per-user-owned, numeric-id-
    # in-the-path IDOR shape as basket/order/invoice, but `/track-order`
    # does not contain the `/order` substring the old regex required
    # (`-order`, not `/order`), so idor was never dispatched for it despite
    # /api/Users/<id> and /rest/basket/<id> triggering it correctly in the
    # same run. See "Harness vs. Juice Shop" §06 (dispatch-layer gaps).
    (re.compile(r'/order|/orders|/track-order|/track_order|/trackorder|'
                r'/invoice|/invoices|/booking|/bookings|'
                r'/ticket|/tickets|/transaction|/transactions|'
                r'/reservation|/reservations|/appointment|/appointments|'
                r'/basket|/baskets|/cart|/carts',
                re.IGNORECASE),
     ['idor', 'auth', 'misconfig']),

    # Exposed file-store / directory-listing endpoints. Found missing
    # during the Juice Shop full run: `GET /ftp` returns a browsable
    # directory listing (a real information-disclosure + misconfiguration
    # finding), but matched no pattern at all -- only cors/csp were
    # dispatched, so no misconfig/recon agent ever saw it. A bare `/ftp`,
    # `/files` static root, or `/backup` store carries no query string and
    # no "sensitive"-looking header, so nothing else fired. See
    # "Harness vs. Juice Shop" §06.
    (re.compile(r'/ftp(/|$)|/backup|/backups|/dump|/dumps|/filestore|/file-store',
                re.IGNORECASE),
     ['misconfig', 'recon', 'info_disclosure']),
    
    # Search endpoints
    (re.compile(r'/search|/find|/query|/lookup', re.IGNORECASE), 
     ['sqli', 'xss']),
    
    # Config/debug endpoints
    (re.compile(r'/config|/settings|/debug|/status|/health|/info', re.IGNORECASE), 
     ['misconfig', 'supply_chain']),
    
    # Webhook endpoints
    (re.compile(r'/webhook|/hooks|/callback|/notify', re.IGNORECASE), 
     ['ssrf', 'misconfig']),
    
    # Proxy endpoints
    (re.compile(r'/proxy|/forward', re.IGNORECASE), 
     ['ssrf', 'misconfig']),
    
    # Image/avatar endpoints (common SSRF vectors)
    (re.compile(r'/image|/img|/avatar|/photo|/picture|/profile_image|/profileImage', re.IGNORECASE), 
     ['ssrf', 'xss']),
    
    # Static asset endpoints (usually safe, but check for misconfig)
    (re.compile(r'/static|/assets|/css|/js|/images|/fonts', re.IGNORECASE), 
     ['misconfig']),
]

# Query parameter patterns
_QUERY_PARAM_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    # ID parameters (IDOR risk)
    (re.compile(r'id|user_id|account_id|customer_id|order_id|product_id', re.IGNORECASE), 
     ['idor', 'sqli']),
    
    # Search/query parameters (injection risk)
    (re.compile(r'q|query|search|keyword|term|filter', re.IGNORECASE), 
     ['sqli', 'xss']),
    
    # File/path/redirect-target parameters (path traversal, SSRF, open
    # redirect, header/response-splitting injection). Found missing during
    # a live audit against a real Juice Shop `/redirect?to=<url>` request
    # -- the textbook open-redirect shape -- which dispatched neither
    # open_redirect nor header_injection at all (both had ZERO fast_path
    # entries anywhere in this file), and fast_path was confident enough
    # on OTHER grounds (ssrf/misconfig still matched) that the coordinator
    # was never even consulted, so open_redirect had no chance regardless
    # of whether the coordinator would have picked it. `to` itself -- the
    # actual real-world parameter name here -- wasn't even in the old
    # regex; added alongside the other common redirect-target names.
    # header_injection is bundled at the same trigger because CRLF/
    # response-splitting into a Location header is the classic mechanism
    # BEHIND a redirect endpoint, not a separately-signaled precondition.
    (re.compile(r'file|path|url|uri|link|redirect|next|target|'
                r'\bto\b|\bout\b|dest|destination|return|return_to|returnurl|continue|goto|redir|forward',
                re.IGNORECASE),
     ['ssrf', 'misconfig', 'open_redirect', 'header_injection']),
    
    # Authentication tokens (sensitive, but also injection vectors)
    (re.compile(r'token|api_key|apikey|key|secret|password|credential', re.IGNORECASE), 
     ['auth', 'misconfig']),
    
    # Sort/pagination parameters (business logic)
    (re.compile(r'sort|order|page|limit|offset|per_page', re.IGNORECASE), 
     ['business_logic', 'sqli']),
    
    # Action/command parameters (command injection). Found missing during
    # a live audit: command_injection had zero fast_path entries anywhere
    # in this file, despite this exact parameter-name shape (cmd/exec/run)
    # being the textbook precondition for it.
    (re.compile(r'action|cmd|command|exec|run|do', re.IGNORECASE),
     ['misconfig', 'business_logic', 'command_injection']),
]

# Request header patterns
_REQUEST_HEADER_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    # CORS headers in requests
    (re.compile(r'Origin|Access-Control-Request-Method|Access-Control-Request-Headers', re.IGNORECASE), ['cors']),

    # JSON content type. nosql added: a JSON-bodied request is the
    # precondition for MongoDB-operator-style injection the same way a
    # SQL-shaped query string is for sqli -- nosql had zero fast_path
    # entries anywhere in this file.
    (re.compile(r'application/json', re.IGNORECASE),
     ['sqli', 'xss', 'idor', 'business_logic', 'nosql']),
    
    # Form data
    (re.compile(r'application/x-www-form-urlencoded', re.IGNORECASE),
     ['sqli', 'xss', 'idor']),

    # Multipart file uploads. Found missing during a live audit: this is
    # the single most reliable, near-zero-false-positive signal in this
    # entire file for a whole vulnerability class -- a request either IS
    # or ISN'T a file upload, and file_upload had zero fast_path entries
    # anywhere (URL, header, or body), reachable only via the coordinator.
    (re.compile(r'multipart/form-data', re.IGNORECASE),
     ['file_upload']),
    
    # XML content (XXE, injection). Found missing during a live audit:
    # an XML Content-Type is THE textbook precondition for XXE, yet xxe
    # was never in this list at all -- only xss/misconfig, so the one
    # agent actually equipped to test for XXE never saw XML-bodied
    # requests unless the coordinator happened to pick it (see fast_path's
    # own design principle: a confident fast_path match must be a
    # SUPERSET of what the coordinator would pick, not a narrower one).
    (re.compile(r'application/xml|text/xml', re.IGNORECASE),
     ['xss', 'misconfig', 'xxe']),
    
    # GraphQL
    (re.compile(r'application/graphql', re.IGNORECASE), 
     ['graphql', 'sqli', 'idor']),
    
    # JWT-shaped token (three dot-separated base64url segments, header
    # segment starting "eyJ" -- base64 of the literal `{"` that opens
    # every JWT header JSON object). Specific enough to carry very low
    # false-positive risk on its own. Found missing during the
    # testing/test-target/ discovery run: jwt had ZERO fast_path entries
    # anywhere, in the URL, header, or body tables -- it could only be
    # reached via the coordinator, which fast_path being confident on
    # nearly every real exchange meant essentially never happened in
    # practice (confirmed: never fired once across a full discovery
    # run). This can appear in an Authorization header OR a session
    # cookie, so it's checked against header values generically rather
    # than gated to one specific header name.
    #
    # MUST come before the generic bearer/basic/digest/token pattern
    # below: select_agents_by_request_headers stops at the first
    # matching pattern per header (see its own `break`), and a JWT
    # Authorization header always also contains the literal word
    # "bearer" -- so if the generic pattern were checked first, jwt
    # would never be reached even though this pattern also matches.
    #
    # Trailing boundary is a negative lookahead, not `\b`: an alg:none
    # forged token -- the single highest-value real case this pattern
    # exists to catch (see security.py's JWT-header-disclosure fix and
    # testing/test-target/'s TP11) -- has an EMPTY signature segment, so
    # the match ends immediately after a `.` with nothing following.
    # `\b` requires a word/non-word transition and fails there (both
    # neighbors are non-word); confirmed directly before landing this.
    (re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])'),
     ['jwt', 'auth']),

    # Authorization headers (auth issues)
    (re.compile(r'bearer|basic|digest|token', re.IGNORECASE),
     ['auth']),

    # HTTP Request Smuggling - conflicting headers
    (re.compile(r'Content-Length|Transfer-Encoding', re.IGNORECASE), ['http_request_smuggling']),

    # OAuth / OIDC request parameters
    (re.compile(r'response_type=|client_id=|redirect_uri=|code_challenge=|grant_type=', re.IGNORECASE), ['oauth']),

    # WebSocket handshake
    (re.compile(r'^Upgrade$', re.IGNORECASE), ['websocket']),
    (re.compile(r'^websocket$', re.IGNORECASE), ['websocket']),
    (re.compile(r'^Sec-WebSocket-Key$|^Sec-WebSocket-Version$', re.IGNORECASE), ['websocket']),
]

# Response patterns that indicate specific issues
_RESPONSE_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    # SQL errors
    (re.compile(r'SQL syntax|syntax error|mysql|postgresql|sqlite|oracle|mssql', re.IGNORECASE), 
     ['sqli']),
    
    # Stack traces (information disclosure)
    (re.compile(r'at com\.|at org\.|File "|line \d+|Traceback|Stack Trace', re.IGNORECASE),
     ['misconfig', 'supply_chain', 'info_disclosure']),
    
    # Version banners
    (re.compile(r'Apache/|nginx/|Node\.js|Python/|PHP/|Tomcat|JBoss|IHS', re.IGNORECASE), 
     ['misconfig', 'supply_chain']),
    
    # Server/technology headers
    (re.compile(r'Server:|X-Powered-By:|X-AspNet-Version:|X-Generator:', re.IGNORECASE), 
     ['misconfig', 'supply_chain']),
    
    # Error messages (debug mode)
    (re.compile(r'Exception|Error:|Failed|Invalid|Unauthorized|Forbidden', re.IGNORECASE), 
     ['misconfig', 'auth']),
    
    # HTML in response (XSS potential)
    (re.compile(r'<html|<body|<script|<img|<div|<input|<form', re.IGNORECASE), 
     ['xss', 'misconfig']),
    
    # JSON errors
    (re.compile(r'"error"|"message"|"status":\s*"error"', re.IGNORECASE), 
     ['misconfig', 'business_logic']),
    
    # GraphQL-specific response patterns
    (re.compile(r'"data":\s*\{|"errors":\s*\[', re.IGNORECASE), ['graphql']),
    (re.compile(r'__schema|__type|introspection|"query":', re.IGNORECASE), ['graphql']),
    (re.compile(r'"__typename"|GraphQL|graphql', re.IGNORECASE), ['graphql']),
    
    # CORS-related patterns
    (re.compile(r'Access-Control-Allow-Origin|Access-Control-Allow-Credentials|Access-Control-Allow-Headers|Access-Control-Allow-Methods|Access-Control-Expose-Headers|Access-Control-Max-Age|Vary: Origin', re.IGNORECASE), ['cors']),
    (re.compile(r'origin.*\*|allow-origin.*null|credentials.*true', re.IGNORECASE), ['cors']),
    
    # Recon patterns - discovery files and endpoints. info_disclosure added
    # alongside recon: an exposed .git/.env/README isn't just "attack
    # surface to map", it's itself a real information-disclosure finding
    # -- info_disclosure had zero fast_path entries anywhere in this file.
    (re.compile(r'robots\.txt|sitemap\.xml|\.git/|\.env|README|CHANGELOG|package\.json|pom\.xml|build\.gradle', re.IGNORECASE), ['recon', 'info_disclosure']),
    (re.compile(r'/api|/swagger|/openapi|/redoc|/graphql|/admin|/login|/auth|/administrator', re.IGNORECASE), ['recon']),

    # Web Cache Poisoning - caching layer indicators (matches header
    # NAMES like X-Cache/Age/CF-Cache-Status via the name-matching pass,
    # and Cache-Control VALUES containing public/s-maxage via the
    # value-matching pass -- see select_agents_by_response_headers)
    (re.compile(r'^(Age|X-Cache|X-Cache-Status|CF-Cache-Status|X-Varnish|X-Served-By|Surrogate-Control)$|public|s-maxage', re.IGNORECASE), ['web_cache_poisoning']),

    # Subdomain Takeover - unclaimed-resource fingerprints from common providers
    (re.compile(
        r"There isn't a GitHub Pages site here|NoSuchBucket|No such app|"
        r"herokucdn\.com/error-pages/no-such-app|Repository not found|"
        r"project not found|Sorry, this shop is currently unavailable|"
        r"do not know of this page|The specified bucket does not exist",
        re.IGNORECASE), ['subdomain_takeover']),

    # HTTP Request Smuggling patterns (also in request headers)
]

# Additional response header-NAME-based patterns (now correctly matched
# against header names too, per the fast_path.py fix earlier this session)
_RESPONSE_PATTERNS.extend([
    (re.compile(r'^Strict-Transport-Security$', re.IGNORECASE), ['crypto']),
    (re.compile(r'^Content-Security-Policy$|^Content-Security-Policy-Report-Only$|^X-Frame-Options$', re.IGNORECASE), ['csp']),
    (re.compile(r'^Sec-WebSocket-Accept$', re.IGNORECASE), ['websocket']),
])

# Response BODY patterns for deserialization format fingerprints and
# race-condition-suggestive business language
_RESPONSE_PATTERNS.append(
    (re.compile(r'rO0AB|__VIEWSTATE|O:\d+:"[A-Za-z_]', re.IGNORECASE), ['deserialization'])
)
_RESPONSE_PATTERNS.append(
    (re.compile(r'already[^.]{0,20}(used|redeemed|claimed|applied)|one[- ]time use|limit(ed)? to \d+ (per|use)', re.IGNORECASE), ['race_condition'])
)

# HTTP method patterns.
#
# NOTE ON DESIGN (read before "restoring" the old blanket lists):
# GET and POST are so common that mapping them to a broad agent list makes
# this table fire on nearly every exchange regardless of content -- it stops
# being a *signal* and becomes an unconditional floor, which is exactly the
# over-dispatch bug this table used to cause (see FAST_PATH_EFFICIENCY.md).
# GET/POST therefore carry no independent agents here: whatever they'd imply
# (sqli/xss/idor/etc.) is already covered by the URL/query/header/body tables
# above, which are actually evidence-based. What's kept is the one narrow,
# well-established heuristic that IS discriminating: state-mutating verbs
# (PUT/DELETE/PATCH) warrant an authorization check (idor+auth) even absent
# any other signal, because broken object/function-level authorization is
# the single most under-signaled vulnerability class -- there is rarely a
# textual "signature" for it the way there is for injection classes.
_METHOD_PATTERNS: dict[str, list[str]] = {
    'GET': [],
    'POST': [],
    'PUT': ['idor', 'auth'],
    'DELETE': ['idor', 'auth'],
    'PATCH': ['idor', 'auth'],
    'HEAD': ['misconfig'],
    'OPTIONS': ['misconfig'],
}

# Response status code patterns.
#
# Same reasoning as _METHOD_PATTERNS above: 200/201 are the overwhelming
# majority of responses and carry no discriminating information on their
# own, so they no longer contribute agents (see FAST_PATH_EFFICIENCY.md).
# Every status code left mapped below is one that is itself informative
# (redirect, client error, auth failure, server error) -- those are kept
# unchanged.
_STATUS_PATTERNS: dict[int, list[str]] = {
    301: ['misconfig'],
    302: ['ssrf', 'misconfig'],
    307: ['ssrf', 'misconfig'],
    400: ['misconfig', 'business_logic'],
    401: ['auth', 'misconfig'],
    403: ['auth', 'idor', 'misconfig'],
    404: ['misconfig'],
    405: ['misconfig'],
    500: ['misconfig', 'supply_chain'],
    502: ['misconfig'],
    503: ['misconfig'],
}


# =============================================================================
# Fast-Path Selection Logic
# =============================================================================

def select_agents_by_url(url: str) -> set[str]:
    """Select agents based on URL/path patterns."""
    agents = set()
    for pattern, agent_list in _URL_PATTERNS:
        if pattern.search(url):
            agents.update(agent_list)
    return agents


def select_agents_by_query_params(query_string: str) -> set[str]:
    """Select agents based on query parameter names.

    Any parameter at all -- regardless of its name -- is a potential
    injection point, so `sqli`/`xss` are a floor for every non-empty query
    string. This is intentionally narrower than the old GET-method-blanket
    it replaces: it only fires when a request actually carries a
    parameter value, not on every GET regardless of content. It exists
    specifically to catch search/filter features that don't use one of
    the recognized names below (real examples: `?s=`, `?text=`, `?k=` --
    see FAST_PATH_EFFICIENCY.md, "known-param-name gap").
    """
    agents = set()
    if not query_string:
        return agents

    # Extract parameter names from query string
    params = re.findall(r'([^=&]+)=', query_string)
    if not params:
        return agents

    # Baseline: any parameter value is untrusted input and a potential
    # injection point, independent of what the parameter is named.
    # `anomaly` is included here too -- unlike every other agent in this
    # file, it costs nothing extra to dispatch: its run() bypasses the
    # LLM pipeline entirely and runs a deterministic regex pass (see
    # anomaly_detector.py's suspicious_patterns, which already lists
    # path-traversal markers among others). Found missing during a real
    # scoring pass against testing/test-target/: a path-traversal
    # exchange (`?file=../app.py`) dispatched 8 LLM-backed agents, none
    # of which correctly named the vulnerability, while `anomaly` --
    # never dispatched at all -- would have matched `\.\./ ` in the URL
    # deterministically, at zero additional Ollama cost.
    agents.update({'sqli', 'xss', 'anomaly'})

    for param in params:
        for pattern, agent_list in _QUERY_PARAM_PATTERNS:
            if pattern.search(param):
                agents.update(agent_list)
    return agents


def select_agents_by_request_headers(headers: dict[str, str]) -> set[str]:
    """Select agents based on request header patterns."""
    agents = set()
    for header_name, header_value in headers.items():
        # Match on header name
        for pattern, agent_list in _REQUEST_HEADER_PATTERNS:
            if pattern.search(header_name):
                agents.update(agent_list)
                break
        # Match on header value
        for pattern, agent_list in _REQUEST_HEADER_PATTERNS:
            if pattern.search(header_value):
                agents.update(agent_list)
                break
    return agents


def select_agents_by_method(method: str) -> set[str]:
    """Select agents based on HTTP method."""
    return set(_METHOD_PATTERNS.get(method.upper(), []))


def select_agents_by_status(status: int | None) -> set[str]:
    """Select agents based on response status code."""
    if status is None:
        return set()
    return set(_STATUS_PATTERNS.get(status, []))


def select_agents_by_response_body(body: str) -> set[str]:
    """Select agents based on response body patterns."""
    agents = set()
    if not body:
        return agents
    
    for pattern, agent_list in _RESPONSE_PATTERNS:
        if pattern.search(body):
            agents.update(agent_list)
    return agents


# Field names where a NEGATIVE numeric value is itself the signal --
# distinct from every other table above, which is text/regex matching.
# Found missing during the PixelMart discovery run: a business-logic
# price/quantity manipulation exploit (a negative quantity producing a
# negative total, credited instead of charged) shows up in the response
# as a structural JSON anomaly, not as any matchable text pattern -- no
# regex over "total_price": -399.95 will ever fire. See
# DISCOVERY_RUN_RESULTS.md, architecture finding #3.
_MONEY_OR_QUANTITY_FIELD = re.compile(
    r'\b(price|total|amount|balance|quantity|qty|cost|subtotal|discount|refund|payment|fee)\b',
    re.IGNORECASE,
)


def _has_negative_money_or_quantity_field(text: str) -> bool:
    """Best-effort structural check: does this JSON body contain a
    negative number in a field whose name suggests money or quantity?
    Silently returns False for non-JSON or unparseable input -- this is
    a bonus signal on top of the text patterns, not a replacement for
    them, so failing closed here just means falling back to whatever
    else fires."""
    if not text:
        return False
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False

    found = False

    def walk(obj):
        nonlocal found
        if found:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                if (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and value < 0
                    and _MONEY_OR_QUANTITY_FIELD.search(str(key))
                ):
                    found = True
                    return
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return found


# State-changing HTTP methods -- the precondition for CSRF being
# possible at all is that the request both (a) changes state and (b) is
# authenticated via a cookie the browser attaches automatically (bearer/
# API-key auth isn't cookie-based and isn't in CSRF's threat model --
# see the Burp extension's CsrfLogic, which scopes itself the same way).
_STATE_CHANGING_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


def select_agents_by_csrf_signal(method: str, request_headers: dict[str, str]) -> set[str]:
    """CSRF has no text signature to match the way injection classes do
    -- the exposure IS the absence of a token, not the presence of any
    string. What's observable instead is the precondition: a
    state-changing request carrying a Cookie header. Found missing
    during the testing/test-target/ discovery run: csrf had ZERO
    fast_path entries anywhere (same gap as jwt, see
    _REQUEST_HEADER_PATTERNS above) and could only be reached via the
    coordinator, which never actually fired in a full discovery run."""
    if method.upper() not in _STATE_CHANGING_METHODS:
        return set()
    if any(name.lower() == 'cookie' for name in request_headers):
        return {'csrf'}
    return set()


def select_agents_by_body_anomalies(request_body: str, response_body: str) -> set[str]:
    """Structural (not text/regex) check for a negative value in a
    money- or quantity-shaped field, in either the request or response
    body. Catches business-logic price/quantity manipulation that no
    text pattern in _RESPONSE_PATTERNS can match, since the signal is a
    numeric property of a JSON value, not a string to search for."""
    if _has_negative_money_or_quantity_field(request_body) or _has_negative_money_or_quantity_field(response_body):
        return {'business_logic'}
    return set()


def select_agents_by_response_headers(headers: dict[str, str]) -> set[str]:
    """Select agents based on response header patterns."""
    agents = set()
    for header_name, header_value in headers.items():
        # Match on header name (e.g. presence of Access-Control-Allow-Origin,
        # X-Cache, CF-Cache-Status -- these are signals regardless of value)
        for pattern, agent_list in _RESPONSE_PATTERNS:
            if pattern.search(header_name):
                agents.update(agent_list)
                break
        # Match on header value
        for pattern, agent_list in _RESPONSE_PATTERNS:
            if pattern.search(header_value):
                agents.update(agent_list)
                break
    return agents


def select_fast_path_agents(exchange: HttpExchange, available_agents: set[str]) -> tuple[list[str] | None, str]:
    """
    Select agents using deterministic fast-path logic.
    
    This function analyzes the exchange using various patterns to determine
    which agents should be dispatched, WITHOUT using the coordinator LLM.
    
    Returns:
        tuple of (selected_agents, reason) where:
        - selected_agents: list of agent names to dispatch
        - reason: human-readable explanation of why these agents were selected
        
    The selection is conservative: we require at least one strong signal
    (URL pattern, query params, or response body pattern) to confidently
    select agents. If we can't confidently determine the agents, we return
    None to indicate the coordinator should be used.
    
    Args:
        exchange: The HTTP exchange to analyze
        available_agents: Set of agent names that are available
    """
    selected = set()
    reasons = []
    has_strong_signal = False
    
    # Strong signals (URL, query params, response body) - these are specific indicators
    
    # 1. Check URL patterns (strong signal)
    url_agents = select_agents_by_url(exchange.url)
    if url_agents:
        selected.update(url_agents & available_agents)
        reasons.append(f"URL pattern: {exchange.url}")
        has_strong_signal = True
    
    # 2. Check query parameters (strong signal)
    if exchange.url and '?' in exchange.url:
        query_string = exchange.url.split('?', 1)[1].split('#', 1)[0]
        query_agents = select_agents_by_query_params(query_string)
        if query_agents:
            selected.update(query_agents & available_agents)
            reasons.append(f"Query params: {query_string[:50]}...")
            has_strong_signal = True
    
    # 3. Check request headers (medium signal)
    req_header_agents = select_agents_by_request_headers(exchange.request_headers)
    if req_header_agents:
        selected.update(req_header_agents & available_agents)
        reasons.append(f"Request headers: {list(exchange.request_headers.keys())[:3]}...")
        has_strong_signal = True  # Headers can be strong indicators (e.g., Content-Type)
    
    # 4. Check response headers (medium signal)
    resp_header_agents = select_agents_by_response_headers(exchange.response_headers)
    if resp_header_agents:
        selected.update(resp_header_agents & available_agents)
        reasons.append(f"Response headers: {list(exchange.response_headers.keys())[:3]}...")
        has_strong_signal = True
    
    # 5. Check response body (strong signal - only if small)
    if exchange.response_body and len(exchange.response_body) < 10000:
        body_agents = select_agents_by_response_body(exchange.response_body)
        if body_agents:
            selected.update(body_agents & available_agents)
            reasons.append("Response body patterns")
            has_strong_signal = True

    # 6. Check for structural body anomalies -- negative money/quantity
    # values in either body. Independent of the text-pattern checks
    # above and of body size (a manipulated total is a strong signal
    # regardless of how large the surrounding response is).
    anomaly_agents = select_agents_by_body_anomalies(exchange.request_body, exchange.response_body)
    if anomaly_agents:
        selected.update(anomaly_agents & available_agents)
        reasons.append("Body anomaly: negative money/quantity field")
        has_strong_signal = True

    # 7. Check for CSRF precondition -- state-changing method + cookie auth
    csrf_agents = select_agents_by_csrf_signal(exchange.method, exchange.request_headers)
    if csrf_agents:
        selected.update(csrf_agents & available_agents)
        reasons.append("State-changing request with cookie auth")
        has_strong_signal = True

    # If we have a strong signal, add method and status agents (weak signals)
    # These expand the selection but don't provide confidence on their own
    if has_strong_signal:
        method_agents = select_agents_by_method(exchange.method)
        if method_agents:
            selected.update(method_agents & available_agents)
            reasons.append(f"Method: {exchange.method}")
        
        status_agents = select_agents_by_status(exchange.response_status)
        if status_agents:
            selected.update(status_agents & available_agents)
            reasons.append(f"Status: {exchange.response_status}")
    
    # Return selected agents if we have a strong signal, otherwise use coordinator
    if selected and has_strong_signal:
        # Sort for deterministic output
        sorted_agents = sorted(selected)
        reason_str = f"Fast-path: {'; '.join(reasons[:3])}"
        return sorted_agents, reason_str
    
    # Otherwise, fall back to coordinator
    return None, ""
# Confidence-Based Early Termination
# =============================================================================

class EarlyTerminationConfig:
    """Configuration for confidence-based early termination.

    Default min_severity narrowed from {"critical", "high"} to {"critical"}
    only -- found live, root-caused precisely via the orchestrator's own
    "Early termination: ..." log line: a real Juice Shop CORS misconfiguration
    finding (confidence 0.95, severity "high" -- and CORS fires at that
    exact confidence/severity on nearly every exchange against this
    particular target, since it has a genuinely permissive CORS policy
    everywhere) was triggering this on the FIRST 3-agent batch and silently
    cancelling the remaining batch outright -- confirmed directly, twice,
    with `sqli`/`idor`/`xss`/`csp`/`misconfig`/`nosql`/`rate_limit` never
    even receiving an AgentReport at all (not an empty one, not an error --
    literally never dispatched). The underlying premise ("a confident,
    severe finding means checking OTHER, unrelated vulnerability classes is
    unnecessary") doesn't hold for "high" severity in practice: CORS/XSS/
    header-based findings routinely reach "high" independent of whether
    sqli/idor/business_logic also exist on the same exchange -- unlike a
    genuinely "critical" finding (e.g. a confirmed RCE), which is a much
    stronger, rarer signal that further probing has lower marginal value.
    """

    def __init__(
        self,
        enabled: bool = True,
        min_confidence: float = 0.9,
        min_severity: set[str] = None,
        max_agents_before_check: int = 3,
    ):
        self.enabled = enabled
        self.min_confidence = min_confidence
        self.min_severity = min_severity or {"critical"}
        self.max_agents_before_check = max_agents_before_check


def should_terminate_early(
    reports_so_far: list['AgentReport'],
    remaining_agents: list[str],
    config: EarlyTerminationConfig,
) -> tuple[bool, str]:
    """
    Determine if analysis should terminate early.
    
    This checks if we've already found high-confidence, high-severity findings
    that make further analysis unnecessary.
    
    Returns:
        tuple of (should_terminate, reason)
    """
    if not config.enabled:
        return False, ""
    
    if len(reports_so_far) < config.max_agents_before_check:
        return False, ""
    
    # Check all findings from completed reports
    for report in reports_so_far:
        for finding in report.findings:
            if (finding.confidence >= config.min_confidence and 
                finding.severity in config.min_severity):
                return True, (f"Early termination: {finding.severity} severity "
                            f"finding with {finding.confidence:.1f} confidence "
                            f"({finding.vulnerability_class}) detected early")
    
    return False, ""


# =============================================================================
# Combined Fast-Path + Early Termination
# =============================================================================

class FastPathSelector:
    """
    Combined fast-path agent selection and early termination logic.
    
    This class provides a unified interface for both fast-path selection
    (bypassing coordinator LLM) and early termination (stopping analysis
    once high-confidence findings are detected).
    """
    
    def __init__(self, available_agents: set[str]):
        self.available_agents = available_agents
        self.early_term_config = EarlyTerminationConfig()
        self._stats = {
            'fast_path_hits': 0,
            'fast_path_misses': 0,
            'early_terminations': 0,
        }
    
    def select_agents(self, exchange: HttpExchange) -> tuple[list[str] | None, str]:
        """
        Select agents using fast-path logic.
        
        Returns:
            tuple of (selected_agents, reason) or (None, "") if coordinator should be used
        """
        result = select_fast_path_agents(exchange, self.available_agents)
        
        if result[0]:
            self._stats['fast_path_hits'] += 1
            return result
        else:
            self._stats['fast_path_misses'] += 1
            return None, ""
    
    def check_early_termination(
        self, reports_so_far: list['AgentReport'], remaining_agents: list[str]
    ) -> tuple[bool, str]:
        """
        Check if analysis should terminate early.
        
        Returns:
            tuple of (should_terminate, reason)
        """
        result = should_terminate_early(
            reports_so_far, remaining_agents, self.early_term_config
        )
        
        if result[0]:
            self._stats['early_terminations'] += 1
        
        return result
    
    def get_stats(self) -> dict:
        """Get fast-path statistics."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset fast-path statistics."""
        self._stats = {
            'fast_path_hits': 0,
            'fast_path_misses': 0,
            'early_terminations': 0,
        }
