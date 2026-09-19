from .base_agent import BaseAgent


class AuthAgent(BaseAgent):
    name = "auth"

    tactical_guide = """
1. Separate AUTHENTICATION (who are you) from AUTHORIZATION (what can you
   do) explicitly in your findings -- they are different bugs with different
   fixes, and conflating them produces a useless suggested_test.
2. Look at how the session/token is transported (cookie vs bearer vs custom
   header) and whether it's the kind of thing the client-side could read.
3. If this is a login/registration/password-reset flow, look for account
   enumeration (different error text/timing for "user exists" vs not) and
   missing lockout/backoff -- both need a MULTI-request differential to
   confirm, which a single exchange cannot do; say so explicitly.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Authentication and session management. Look for:
- No authentication present at all on a request that returns sensitive
  or privileged data (config values, secrets, another user's data,
  admin-only functionality) -- check the REQUEST for any Authorization
  header, session cookie, or API key before looking at anything else.
  This is the single most basic and severe form of broken
  authentication, easy to miss when your attention is drawn to more
  sophisticated issues below (token entropy, CSRF, fixation) -- an
  endpoint with NO credentials required at all should be flagged
  before, not instead of, those.
  IMPORTANT -- do not confuse "redacted" with "absent": this harness
  strips the VALUE of Authorization/Cookie/API-key headers before you
  see them, for your safety, but always keeps the header NAME and marks
  it explicitly (e.g. "Authorization: [REDACTED -- header present,
  value withheld from model]", or a JWT's decoded alg/typ shown next to
  a redaction notice for its payload/signature). Seeing that header
  listed at all -- redacted or not -- means a credential WAS supplied on
  this request; only report "no authentication present" when the
  Authorization/Cookie/API-key header is genuinely missing from the
  request headers shown to you, never merely because its value is
  masked.
- Session tokens/cookies missing Secure, HttpOnly, or SameSite attributes
  (only assess what's actually visible in the response headers shown).
- Predictable-looking tokens (short, sequential, low-entropy, timestamp-
  based) versus opaque high-entropy ones.
- Sensitive actions (login, password reset, MFA, account changes) that
  appear to lack CSRF protection (no token/nonce field visible in a
  state-changing form/request).
- Verbose authentication error responses that could support username
  enumeration (different messages/timing/status for "user not found" vs
  "wrong password" -- note if this exchange alone can't establish that,
  since it requires comparing two different login attempts).
- Password reset or token endpoints where the token appears in the URL
  (and therefore in logs/referrer headers) rather than the body.
- Trust-boundary bypasses involving security-sensitive headers or middleware:
  Referer/Origin/Host-derived authorization assumptions, internal-only
  headers such as X-Forwarded-For/X-Original-URL/X-Rewrite-URL, and route
  middleware that appears to make an authorization decision from client-
  supplied metadata. Do not claim a bypass from the header's presence alone;
  suggest removing/spoofing the header and comparing the authorization result.
- Session fixation: if you can see both a pre-login response (with its
  session cookie) and a post-login response (with its session cookie) for
  the same browser/session, check whether the session identifier value
  is the SAME across that boundary. A server that doesn't issue a new
  session ID on successful login is vulnerable to fixation -- an
  attacker who can plant a known session ID in the victim's browser
  before they log in (via a URL parameter, a non-HttpOnly cookie write,
  or any pre-auth session-initialization behavior) inherits the
  victim's authenticated session once they log in with it. Report
  vulnerability_class "session_fixation" when this pattern is visible
  across two exchanges; note in the finding that it needs the
  before/after pair to confirm if you only have one side of it.
- Session timeout / logout invalidation: does a logout request's
  response give any indication the session was actually invalidated
  server-side (a Set-Cookie clearing/expiring the session cookie is a
  good sign; its absence, or a logout that's purely client-side
  redirect with no Set-Cookie change, is worth flagging as a gap worth
  testing). Report vulnerability_class "session_timeout" for this
  pattern. Confirming whether an old session ID still works AFTER
  logout needs a second, later exchange reusing the same cookie --
  say so explicitly if you can't see that second exchange.

Be explicit when a finding requires a second exchange to confirm (e.g.
enumeration requires comparing two different usernames) versus when it's
visible in this exchange alone (e.g. missing Secure flag on a cookie over
HTTPS).
"""
