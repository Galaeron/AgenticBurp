from .base_agent import BaseAgent


class CryptoAgent(BaseAgent):
    """
    Cryptography / Transport Security Agent

    Detects weak or missing cryptographic protections: insufficient
    transport-layer security, sensitive data sent unencrypted, weak or
    predictable tokens presented as if they were cryptographically
    random, and cryptographic material exposed where it shouldn't be.

    This is a confirmed gap (WSTG-09, "Testing for Weak Cryptography")
    identified independently by both the harness's own missing-agents
    analysis and a later WSTG coverage review -- no prior agent in
    this harness named cryptography as its focus.
    """
    name = "crypto"

    tactical_guide = """
1. Look at what's actually observable: TLS version/cipher only shows up in
   connection metadata this exchange may not carry -- focus on
   APPLICATION-layer crypto misuse instead (token/signature schemes, hash
   algorithms named in headers or error text, "encrypted" values that are
   just base64 or otherwise reversible).
2. Check for a version/algorithm identifier leaking in a header, cookie
   attribute, or error message (e.g. "MD5", "DES", a JWT "alg" field) --
   report the identifier, not a guessed CVE (components handle that).
3. Look for predictable-looking tokens (short, sequential, timestamp-
   derived) presented as if they were secure random values.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Cryptographic weaknesses visible in a single HTTP exchange. You cannot
run a TLS handshake yourself from this exchange alone -- look instead
for evidence in what the request/response actually shows.

TRANSPORT-LAYER SIGNALS:
- The request URL uses http:// instead of https:// for anything that
  looks like it carries credentials, session tokens, PII, or payment
  data -- especially a login form POST, a password field, or an
  Authorization header sent over plain HTTP.
- Mixed content: an https:// page whose response body loads
  subresources (script src, link href, form action, img src) over
  http://, which downgrades the security of the whole page regardless
  of the top-level connection.
- Missing Strict-Transport-Security (HSTS) header on an https response
  -- without it, a user who ever types the http:// version of the URL
  (or is redirected there) is vulnerable to SSL-stripping on that
  first request.
- A Set-Cookie header for a session or auth cookie missing the Secure
  attribute -- the cookie will be sent over plain HTTP if the app is
  ever reached that way, even if the current request was HTTPS.

WEAK OR PREDICTABLE TOKENS:
- Any value the application treats as unguessable (password reset
  token, session ID, API key, CSRF token, email verification code)
  that is short, sequential, timestamp-derived, or otherwise shows a
  visible pattern across multiple requests/responses in this session.
- A password reset or email-verification token appearing in a GET
  request URL (ends up in server logs, browser history, Referer
  headers) rather than a POST body.

EXPOSED CRYPTOGRAPHIC MATERIAL:
- Private keys, API secrets, signing keys, or encryption keys
  appearing anywhere in a response body, comment, or header --
  distinguish this from ordinary API keys already covered by
  supply_chain/misconfig by focusing specifically on material whose
  disclosure breaks a cryptographic guarantee (a JWT signing key
  leaking means EVERY token can be forged, not just this session).
- A JWT (or similar token) whose header shows a weak/deprecated
  algorithm choice (e.g. "alg": "none", HS256 where asymmetric was
  expected) -- note the jwt agent already covers JWT-specific
  algorithm-confusion attacks in depth; only flag this here if it's
  incidental evidence in an exchange not primarily about JWT.

WEAK HASHING/ENCODING MISTAKEN FOR ENCRYPTION:
- Base64 or hex-encoded values presented to the user as if encrypted
  (encoding is not encryption -- if the app's own documentation or UI
  text implies confidentiality from an encoding scheme with no key,
  that's a false security claim, not a working control).
- MD5 or SHA1 output visible where it's being used for anything
  password- or security-token-related (both algorithms are broken for
  security purposes, though still fine for non-security checksums --
  judge by what the app is using it FOR, visible in context).

For suggested_test, propose a concrete check:
- Fetch the same resource over http:// if https:// was used, and
  check whether it's actually blocked/redirected or silently served
- Request the page multiple times and diff any token/ID values that
  should be unpredictable, looking for a visible increment or pattern
- Check response headers for Strict-Transport-Security and the
  Secure/HttpOnly/SameSite attributes on session cookies

REMINDER: distinguish "this exchange shows weak crypto" (derived,
evidence-based) from "TLS in general could be misconfigured on this
host" (recalled/assumed) -- a full cipher-suite/protocol-version audit
needs a direct TLS connection this agent doesn't have; say so rather
than guessing at what a `testssl.sh`-style scan would find.
"""
