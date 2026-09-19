from .base_agent import BaseAgent


class JwtAgent(BaseAgent):
    """Agent for detecting JWT and token-based authentication vulnerabilities."""
    name = "jwt"

    tactical_guide = """
1. Decode the JWT header (never the signature) and check `alg`: `none` is
   an immediate critical finding; HS256 where the app might actually expect
   RS256 is the classic algorithm-confusion candidate.
2. Check the payload for missing/expired-but-still-accepted `exp`, and for
   authorization data (role, user_id) that lives in a token an end user
   could plausibly re-sign if a weak/guessable secret is used.
3. This agent can only observe the token's SHAPE -- forging and replaying it
   is the deterministic jwt_forge leg's job; name the exact fields (alg,
   claims) that make it worth trying, not a generic "JWT looks weak".
"""

    @property
    def specialty_prompt(self) -> str:
        return """
JWT and token-based authentication vulnerabilities. Look for:

TOKEN IDENTIFICATION:
- Authorization headers with Bearer tokens (Authorization: Bearer <token>)
- JWT tokens in cookies (typically named: jwt, token, session, auth, access_token)
- Tokens in URL parameters (dangerous pattern, tokens in logs/referrers)
- Tokens in request body fields (token, jwt, access_token, etc.)
- Base64-encoded strings that look like JWTs (three dot-separated parts)

VULNERABILITY SIGNALS:
- alg: none in JWT header (unsigned tokens - CRITICAL)
- Weak signing algorithms: HS256 when RS256 is expected (algorithm confusion)
- Missing or predictable kid (key ID) parameter
- Tokens without exp (expiration) claim
- Tokens with excessive privileges in claims (admin: true, role: admin)
- Tokens transmitted over HTTP (not HTTPS)
- Short or predictable token values (low entropy)
- Tokens that decode to reveal sensitive data in payload
- Missing or weak token validation in responses

ALGORITHM CONFUSION:
- Server accepts HS256-signed tokens when it expects RS256
- Server accepts RS256-signed tokens when it expects HS256
- Server accepts tokens with alg: none
- Key ID (kid) parameter manipulation possible

CLAIM MANIPULATION:
- User-controllable claims (user_id, email, role, permissions)
- Missing signature validation
- Weak signature verification
- JWT header injection possibilities

TOKEN STORAGE ISSUES:
- Tokens in URL parameters (logged in server logs, referrer headers)
- Tokens in localStorage (XSS vulnerable)
- Tokens without Secure flag in cookies
- Tokens without HttpOnly flag in cookies
- Tokens without SameSite attribute in cookies

For suggested_test, propose:
- If alg: none is present: Remove signature entirely and test
- If HS256/RS256 confusion possible: Change alg header and re-sign with different key
- For claim manipulation: Modify role/admin claims and re-sign
- For storage issues: Test token theft via XSS or log access
- For weak entropy: Test brute-force or prediction

suggested_test MUST be concrete and testable in Burp Repeater:
- "Change alg from RS256 to HS256 and re-sign with public key"
- "Set alg to 'none' and remove signature"
- "Modify role claim to 'admin' and re-sign"
- "Move token from header to URL parameter"
"""
