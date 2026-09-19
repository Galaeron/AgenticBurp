from .base_agent import BaseAgent


class CspAgent(BaseAgent):
    """
    Content Security Policy / Clickjacking Agent

    Detects missing or weak Content-Security-Policy headers, and
    clickjacking exposure (framing protection). These are grouped in
    one agent because clickjacking protection IS a CSP directive
    (frame-ancestors) or its older equivalent (X-Frame-Options) --
    they're the same defensive mechanism viewed from two angles, not
    two unrelated checks.

    Coverage includes:
    - Missing or overly permissive CSP
    - unsafe-inline / unsafe-eval in script-src
    - Wildcard or overly broad source lists
    - Missing frame-ancestors / X-Frame-Options (clickjacking)
    - CSP present but not actually enforced (report-only without an
      enforcing companion policy)
    """
    name = "csp"

    tactical_guide = """
1. Read the actual Content-Security-Policy header (or its absence) on THIS
   response -- don't assume a site-wide policy from one exchange.
2. If present, check for the classic weak directives: `unsafe-inline`,
   `unsafe-eval`, a wildcard `*` source, or a missing `object-src`/
   `frame-ancestors` -- each has a different practical impact, name which.
3. If ABSENT entirely on an HTML response, that's the finding itself (no
   clickjacking/XSS-mitigation baseline) -- don't wait for a policy to
   analyze before reporting a missing one.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Content Security Policy (CSP) weaknesses and clickjacking exposure.
Both come from analyzing the same set of response headers.

CSP ANALYSIS -- look at the Content-Security-Policy header (or its
absence):
- No CSP header at all on an HTML response -- the page has no
  defense-in-depth against XSS even if input validation elsewhere is
  solid; treat this as a gap to report, with severity scaled by
  whether other XSS-relevant findings exist on this host (a missing
  CSP is more urgent evidence there's already a confirmed/suspected
  XSS elsewhere than it is standalone).
- script-src (or default-src, if script-src is absent) containing
  'unsafe-inline' -- defeats CSP's core XSS mitigation, since it
  permits exactly the inline <script> tags that reflected/stored XSS
  payloads use.
- script-src containing 'unsafe-eval' -- permits eval()/Function()/
  setTimeout-with-string, which is a common XSS gadget even without
  markup injection.
- A wildcard (*) or overly broad source (https:, data:) in script-src
  -- effectively allows loading a script from anywhere, including an
  attacker-controlled or compromised third-party host.
- Content-Security-Policy-Report-Only present WITHOUT a corresponding
  enforcing Content-Security-Policy header -- report-only policies
  don't block anything, they only log; a report-only-only setup gives
  a false sense of protection.
- object-src not restricted to 'none' -- Flash/plugin-based content
  can be an XSS vector CSP's script-src alone doesn't cover.

CLICKJACKING ANALYSIS -- look at framing controls:
- No X-Frame-Options header AND no frame-ancestors directive in CSP
  -- the page can be framed by any site, enabling classic clickjacking
  (invisible iframe overlay tricking a user into clicking something
  they didn't intend to).
- X-Frame-Options set to ALLOW-FROM with a value that's itself
  attacker-influenceable, or a frame-ancestors list that's too broad
  (e.g. frame-ancestors https: instead of a specific trusted origin).
- Prioritize this finding on pages with sensitive state-changing
  actions (account settings, payment, admin actions) -- clickjacking
  on a purely informational page is lower impact.

For suggested_test, propose:
- Load the URL in a simple test iframe (or note this needs the
  analyst to actually try it in a browser) and see if it renders,
  when no X-Frame-Options/frame-ancestors is present
- Inject a distinctive inline <script>alert(1)</script>-style marker
  via any existing input point and check whether CSP actually blocks
  it from executing (if unsafe-inline is present, it won't)

REMINDER: a CSP finding is about the DEFENSE being absent or weak, not
proof that XSS itself exists -- keep basis honest ("derived" that the
header is missing/weak, not a claim that XSS is exploitable here
unless there's separate evidence of that).
"""
