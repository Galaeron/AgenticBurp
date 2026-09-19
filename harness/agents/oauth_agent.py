from .base_agent import BaseAgent


class OAuthAgent(BaseAgent):
    """
    OAuth / OpenID Connect Security Agent

    Detects flaws in OAuth 2.0 / OIDC authorization flows visible from
    a single captured exchange: the authorization request, the
    redirect back from the authorization server, or the token
    exchange. Distinct from the generic `auth` agent, which covers
    session/authorization-boundary issues -- this agent is specific to
    the OAuth/OIDC protocol mechanics themselves.

    Coverage includes:
    - redirect_uri validation bypass (open redirect / auth code theft)
    - Missing or predictable state parameter (CSRF on the OAuth flow)
    - Missing PKCE on public/native clients
    - Authorization code or access token leakage via Referer, browser
      history, or logs (implicit flow, code-in-URL)
    - Scope escalation / over-broad scope grants
    - client_secret exposure in a public (browser/mobile) client
    """
    name = "oauth"

    tactical_guide = """
1. Identify which OAuth/OIDC step this exchange represents (authorization
   request, redirect callback, token exchange) -- the vulnerable shape is
   different at each step.
2. On a callback/redirect, check whether `state` is present and looks
   unpredictable, and whether `redirect_uri` appears to be validated by
   exact match vs a loose prefix/substring check.
3. On a token response, check whether the access token or id_token is
   exposed somewhere it shouldn't be (URL query string, Referer-leaking
   context) rather than only in a POST body/fragment.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
OAuth 2.0 and OpenID Connect authorization flow vulnerabilities. You
are shown ONE exchange, which may be any step of the flow: the
authorization request to /authorize or /oauth/authorize, the redirect
back to the client's redirect_uri, or a token exchange against a
/token endpoint. Judge only what this specific step shows you.

REDIRECT_URI VALIDATION -- look for:
- redirect_uri that isn't an exact match against what you'd expect a
  registered client to use (path added, different subdomain, open
  wildcard-looking pattern like redirect_uri=https://client.com.evil.com
  or redirect_uri=https://client.com/../evil).
- Any indication the authorization server does prefix/substring
  matching rather than exact match (e.g. it accepted a redirect_uri
  with an extra path segment or query string appended).
- redirect_uri pointing to a path on the legitimate domain that is
  itself an open redirect (chains an OAuth code leak into an
  unrelated redirect vulnerability).

STATE PARAMETER (CSRF on the OAuth flow):
- Is `state` present at all in the authorization request? Its absence
  means the flow has no CSRF protection -- an attacker can start their
  own OAuth flow, capture the resulting code, and trick a victim into
  completing it with the attacker's code, linking the victim's session
  to the attacker's account (login CSRF).
- If present, does it look like a genuinely random, per-request token,
  or something predictable/static/short?

PKCE (Proof Key for Code Exchange):
- For public clients (SPA, mobile, anything that can't keep a
  client_secret confidential), is `code_challenge` present on the
  authorization request? Its absence on a public client's
  authorization_code flow means a leaked/intercepted code can be
  redeemed by anyone, since there is no verifier binding the code to
  the original requester.

TOKEN LEAKAGE:
- Implicit flow (response_type=token) putting an access token directly
  in the URL fragment -- fragments end up in browser history, Referer
  headers (if any script on the page makes further requests), and
  server logs of any intermediate redirect.
- Authorization code appearing in a full (non-fragment) redirect URL
  -- ends up in Referer headers and access logs along the redirect
  chain, and is a bigger problem than usual if PKCE is also missing.

SCOPE AND CLIENT ISSUES:
- Requested scope broader than what the client plausibly needs
  (e.g. a simple "login with X" button requesting full account/write
  access).
- A client_secret value appearing anywhere in a request/response that
  originates from a browser or mobile app context (public clients
  should never hold a confidential secret).

For suggested_test, propose a concrete probe:
- Modify redirect_uri to a variant (subdomain, extra path, different
  TLD suffix) and see whether the authorization server still redirects
  there or errors
- Strip the state parameter entirely and see whether the flow still
  completes
- For a public client's authorization_code request, check whether
  omitting code_challenge still results in a valid code being issued

REMINDER: OAuth findings are protocol-mechanics findings, not generic
auth findings -- justify each one by naming which OAuth/OIDC guarantee
is broken (CSRF protection via state, authorization code binding via
PKCE, redirect target integrity via exact redirect_uri matching), not
just "this looks like an auth issue."
"""
