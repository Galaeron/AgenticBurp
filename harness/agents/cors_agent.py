from .base_agent import BaseAgent


class CorsAgent(BaseAgent):
    """
    CORS (Cross-Origin Resource Sharing) Misconfiguration Agent
    
    Detects CORS misconfigurations that can lead to:
    - Account takeover via CSRF
    - Token theft via XSS
    - Internal network scanning
    - Data exfiltration
    
    CORS is #3 most reported vulnerability on HackerOne.
    Average payout: $1,500-$8,000
    
    Coverage includes:
    - Wildcard origin (Access-Control-Allow-Origin: *)
    - Null origin (Access-Control-Allow-Origin: null)
    - Credentials + wildcard origin
    - Missing Vary: Origin header
    - Preflight bypass (missing OPTIONS handling)
    - Cache-Control: no-store missing on sensitive endpoints
    - Allow-Headers: * with sensitive headers
    - Exposed sensitive headers in Allow-Headers
    """
    name = "cors"

    tactical_guide = """
1. Read the Access-Control-Allow-Origin value literally: `*` with
   credentials disallowed is normal; a REFLECTED Origin (the response
   echoes back whatever Origin was sent) combined with
   Access-Control-Allow-Credentials: true is the actual vulnerable shape.
2. Check whether Access-Control-Allow-Origin is null-accepting or matches an
   overly broad suffix/regex (e.g. any *.trusted.com subdomain, including
   ones an attacker could register).
3. A permissive CORS header alone is not a finding without a credentialed
   endpoint behind it -- note what data/action the reflected origin would
   actually be able to reach.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Cross-Origin Resource Sharing (CORS) misconfigurations. CORS is a
critical security mechanism that can be misconfigured in ways that
allow attackers to bypass same-origin policy and access resources
from other domains. Look for:

CORS HEADER ANALYSIS:
- Access-Control-Allow-Origin: * (wildcard origin) - this allows ANY
  website to access the response. Particularly dangerous when combined
  with credentials or sensitive data.
- Access-Control-Allow-Origin: null - this allows requests from
  "privileged" contexts (like iframes with sandbox attributes) and
  can be exploited.
- Access-Control-Allow-Credentials: true combined with wildcard
  origin - this is INVALID per spec but some browsers allow it, creating
  a critical vulnerability.
- Vary: Origin header missing - without this, responses may be cached
  and shared across different origins, leaking sensitive data.
- Access-Control-Allow-Headers: * - this allows ANY header to be
  included in the actual request, which can bypass header-based security.
- Access-Control-Allow-Methods: * or including non-safe methods
  (PUT, DELETE, etc.) without proper validation.
- Access-Control-Expose-Headers: * or exposing sensitive headers
  like Authorization, Cookie, Set-Cookie.
- Access-Control-Max-Age: very high values (allows preflight cache
  poisoning for extended periods).

PREFLIGHT BYPASS:
- Missing OPTIONS method handling - if a server doesn't properly
  handle OPTIONS requests, attackers may bypass CORS checks.
- Inconsistent preflight vs actual request handling - different
  CORS headers between preflight and actual response.
- CORS headers present without preflight - some servers return CORS
  headers on actual requests without requiring preflight.

COMBINED ATTACKS:
- CORS + CSRF: When CORS is misconfigured with credentials, it can
  enable CSRF attacks even with anti-CSRF tokens.
- CORS + XSS: CORS misconfigurations can amplify XSS impact by
  allowing token theft from other domains.
- CORS + Information Disclosure: Wildcard CORS on sensitive endpoints
  allows any website to read the response.

SENSITIVE ENDPOINTS:
- Pay special attention to endpoints that return:
  * User data (profile, settings, PII)
  * Authentication tokens (JWT, session cookies)
  * API keys or credentials
  * Financial data
  * Administrative functions

For suggested_test, propose:
- Test with Origin: https://evil.com and check if it's reflected
- Test with Origin: null and check response
- Test with credentials and wildcard origin
- Test preflight (OPTIONS) vs actual request consistency
- Test cache poisoning by sending multiple different Origin headers

REMINDER: CORS misconfigurations are particularly valuable because
they often affect ALL users of the application, not just the
reporting researcher. A single CORS vulnerability can expose every
user's session to theft.
"""
