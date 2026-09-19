from .base_agent import BaseAgent


class OpenRedirectAgent(BaseAgent):
    """Agent for detecting open redirect vulnerabilities."""
    name = "open_redirect"

    tactical_guide = """
1. Find a parameter that plausibly feeds a redirect (`next`, `return`,
   `redirect`, `url`, `continue`) and note the exact response mechanism
   (Location header vs a client-side `window.location` in the body).
2. Check whether validation looks like a naive prefix/substring check
   (`startswith("/")`, `contains("trusted.com")`) that a
   `//evil.com`-shaped or `trusted.com.evil.com`-shaped value could defeat.
3. Note whether this redirect sits in an auth flow (post-login redirect) --
   that raises impact from nuisance to phishing/token-leak territory.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Open redirect vulnerabilities. Look for:

REDIRECT PARAMETER INDICATORS:
- URL parameters: url, redirect, redirect_url, next, return_to, callback, return
- Destination parameters: dest, destination, target, endpoint, uri, link
- Location parameters: location, path, goto, forward, r, u
- Short parameter names: r, u, n, t, d

REDIRECT RESPONSE INDICATORS:
- HTTP 301 (Moved Permanently) or 302 (Found) status codes
- Location header in response
- Content-Location header
- Refresh header (HTTP meta refresh)
- JavaScript-based redirects (window.location, window.location.href)
- Meta refresh tags in HTML: <meta http-equiv="refresh" content="0;url=...">

ALLOWLIST BYPASS PATTERNS:
- URL-encoded characters: %2f%2f (//), %3a (:), %2e (.)
- Double URL encoding: %252f%252f
- Case variation: hTtP://evil.com
- Protocol variation: //evil.com, \\\\evil.com, hTtP:s://evil.com
- IP address formats: 192.168.1.1, 0xC0A80101, 3232235777 (decimal)
- URL fragments: #@evil.com, #//evil.com
- Data URIs: data:text/html, data:application/x-html
- JavaScript URIs: javascript:alert(1)
- Relative paths: //evil.com, /\\evil.com

COMMON VULNERABLE PATTERNS:
- Redirect to user-supplied URL without validation
- Redirect to URL from untrusted source
- Open redirect via Referer header
- Open redirect via Origin header
- Redirect after login/logout
- OAuth callback redirects
- Password reset redirects

RESPONSE ANALYSIS:
- Location header contains user input
- Redirect URL matches user-supplied parameter
- Redirect to external domain
- Redirect to different protocol
- Multiple redirects (redirect chain)

For suggested_test, propose:
- Test with external domain: ?redirect=http://evil.com
- Test with javascript URI: ?redirect=javascript:alert(1)
- Test with data URI: ?redirect=data:text/html,<script>alert(1)</script>
- Test with URL encoding: ?redirect=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
- Test with protocol variation: ?redirect=//evil.com
- Test with IP address: ?redirect=http://192.168.1.1

suggested_test MUST be concrete and testable in Burp Repeater:
- "Test with redirect=http://evil.com"
- "Test with redirect=javascript:alert(1)"
- "Test with URL-encoded redirect parameter"
- "Test with redirect=//evil.com (protocol-relative)"

CONTEXT MATTERS:
- Some applications use allowlists for redirect targets
- Allowlist bypass requires creativity with encoding and formats
- Redirect chains may involve multiple hops
- Some redirects are intentional (OAuth, SAML)
- Same-origin redirects are generally safe
"""
