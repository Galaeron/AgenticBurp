from .base_agent import BaseAgent


class CsrfAgent(BaseAgent):
    """Agent for detecting Cross-Site Request Forgery vulnerabilities."""
    name = "csrf"

    tactical_guide = """
1. Identify whether this is a STATE-CHANGING request (POST/PUT/PATCH/DELETE,
   or a GET that clearly mutates data) -- CSRF only matters for those.
2. Check for an anti-CSRF token in the body/header AND whether SameSite is
   set on the session cookie (Lax/Strict materially reduces classic CSRF
   even without a token) -- report what's actually present, not assumed.
3. A CSRF finding on a request authenticated ONLY by a custom header (never
   sent automatically by a browser) is not exploitable the normal way --
   say so rather than reporting it at the same severity as a cookie-only
   endpoint.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Cross-Site Request Forgery (CSRF). Look for:

STATE-CHANGING REQUESTS WITHOUT PROTECTION:
- POST, PUT, PATCH, DELETE requests without CSRF tokens
- GET requests that modify state (should be POST)
- Form submissions without anti-CSRF mechanisms
- AJAX requests without CSRF headers

MISSING CSRF PROTECTION INDICATORS:
- No CSRF token in form hidden fields
- No CSRF token in request headers (X-CSRF-Token, X-CSRF, CSRF-Token)
- No CSRF cookie present
- No SameSite cookie attribute on session cookies
- No Origin header validation
- No Referer header validation
- Predictable or missing CSRF token values

CSRF TOKEN ANALYSIS:
- Token present in form but not validated server-side
- Token tied to session but not validated properly
- Token predictable or guessable
- Token not rotated after use
- Token transmitted over HTTP
- Token in URL parameters

RESPONSE INDICATORS:
- State changes successful without CSRF validation
- Missing CSRF token in response forms
- CSRF token in HTML comments or JavaScript (predictable)
- Error messages indicating missing CSRF token (when it should be required)

SESSION COOKIE ANALYSIS:
- Session cookies without SameSite=Lax or SameSite=Strict
- Session cookies without Secure flag
- Session cookies without HttpOnly flag
- Session cookies accessible via JavaScript

For suggested_test, propose:
- Remove CSRF token from request and test if state change succeeds
- Submit request with missing CSRF header
- Test with CSRF token from different session
- Test with CSRF token from different user
- Test cross-origin submission (different Origin header)
- Test with missing Referer header

suggested_test MUST be concrete and testable in Burp Repeater:
- "Remove CSRF token parameter and re-submit form"
- "Submit with empty X-CSRF-Token header"
- "Submit with CSRF token from different session"
- "Submit with Origin: http://evil.com header"
- "Remove Referer header and re-submit"

CONTEXT MATTERS:
- SameSite=Lax provides some protection against CSRF from external sites
- SameSite=Strict provides stronger protection
- But SameSite is NOT a complete CSRF defense (can be bypassed in some cases)
- CSRF tokens in headers are stronger than in cookies (custom headers not accessible to attacker)
"""
