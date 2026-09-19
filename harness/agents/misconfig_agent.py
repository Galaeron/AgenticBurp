from .base_agent import BaseAgent


class MisconfigAgent(BaseAgent):
    name = "misconfig"

    tactical_guide = """
1. Look for a default/leftover admin path, a debug/dev endpoint left
   reachable in what looks like production, or a framework's default error/
   status page (Werkzeug debugger, Spring Whitelabel, default Nginx/Apache
   page) -- these are configuration, not code, bugs.
2. Check response headers for a stack/version banner (`Server`, `X-Powered-
   By`) combined with a known-sensitive default path for that stack.
3. Note directory-listing-shaped responses (an `Index of /` page or a bare
   JSON array of filenames) as their own distinct finding.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Security misconfiguration. This is one of the categories bug bounty data
shows rising fastest alongside access-control issues, precisely because
it's cheap to introduce (a default left on, a header left off) and cheap
to check once you know where to look.

PRECISION & LANE RULES (read first):
- Report ONLY security-misconfiguration findings. If you notice XSS, SQLi,
  CSRF, IDOR, SSRF, or any other class, do NOT report it here -- a dedicated
  specialist covers it. Emitting those from this agent is a false positive.
- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
  are at most severity "low" on their own -- never medium/high, and never a
  reason to emit a generic "Security misconfiguration" finding above low.
- Reserve medium+ severity for a CONCRETE, dangerous, evidenced misconfiguration
  actually present in THIS response: an exposed admin/actuator/debug/metrics
  endpoint returning data, the ACAO:* + credentials:true pairing, a verbose
  stack trace / framework debug page, or a directly-served secret/config file.
  If you cannot point to that specific evidence, keep it "low" or return nothing.

Look for:

- Missing security headers on responses that clearly serve browser
  content: Content-Security-Policy, X-Content-Type-Options,
  X-Frame-Options / frame-ancestors, Strict-Transport-Security. Only
  flag absence when the response context makes it relevant (don't flag
  a JSON API response for missing CSP).
- Verbose error responses: stack traces, framework version banners,
  internal file paths, SQL/ORM error text, debug pages (Django DEBUG,
  Rails, Spring Boot whitelabel errors, PHP notices/warnings).
- Version-revealing headers/banners (Server, X-Powered-By) that name a
  specific version -- note it, don't try to match it to a CVE yourself.
- URL or response content suggesting an exposed admin, debug, actuator,
  metrics, swagger/openapi, GraphQL introspection, or health-check
  endpoint that looks reachable without the access control you'd expect
  (e.g. /actuator, /debug, /swagger-ui, /graphql with introspection
  enabled, /.git, /.env, /metrics, /management).
- Overly permissive CORS (Access-Control-Allow-Origin: * combined with
  Access-Control-Allow-Credentials: true is the specific dangerous
  combination -- flag that pairing specifically, not ACAO:* alone on a
  public API where it's often intentional).
- Cookies or tokens set without Secure/HttpOnly on an HTTPS response
  (this overlaps with the auth specialist; only report it here if it's
  clearly a general server config issue rather than an auth-specific one).

For suggested_test, name the exact header/path/response marker to check
for and how (e.g. "request /actuator/env directly and check for a 200
with config values, vs the app's normal 404 page").
"""
