from .base_agent import BaseAgent


class HeaderInjectionAgent(BaseAgent):
    """
    HTTP Header / CRLF Injection Agent

    Detects user-controlled input reaching an HTTP response header or
    an email header without proper sanitization -- classic CRLF/header
    injection. This agent deliberately covers BOTH targets (HTTP
    response headers and outbound email headers like To/Cc/Bcc/Subject)
    because they're the same underlying flaw: unsanitized
    newline-containing input reaching a header-structured output. The
    email-header variant (SMTP header injection) is what the harness's
    missing-agents analysis called "email security" -- covering it
    here, in the header-injection agent that actually matches the
    technique, rather than as a separate DNS/SPF-DKIM-DMARC-focused
    agent, since DNS mail-authentication records aren't something a
    captured HTTP exchange can show at all.
    """
    name = "header_injection"

    tactical_guide = """
1. Find any response header whose value is clearly echoed from a request
   parameter (Location, a custom header, a cache-control directive) --
   that's the injection point to name explicitly.
2. Check whether CRLF sequences (`\r\n`, or their URL-encoded forms) in
   that parameter could reach the raw header block -- note the encoding
   context (is the value URL-decoded before being placed in the header?).
3. Distinguish response-splitting (forging a whole second response/header)
   from a simple single-header value injection -- they have different
   impact and need different suggested_test payloads.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
HTTP header injection (CRLF injection / response splitting) and its
email-header variant (SMTP header injection). Both come from the same
root cause: user input reaching a header-structured output without the
newline characters being stripped or encoded.

HTTP RESPONSE HEADER INJECTION -- look for:
- A request parameter, header, or path segment whose value is
  reflected into a response header (Location on a redirect, a custom
  header, Set-Cookie) -- if you can see the exact input value appear
  in a header, ask whether %0d%0a (CRLF) in that input would land
  literally in the header rather than being decoded/stripped first.
- Redirect endpoints specifically (parameters like `url=`, `next=`,
  `redirect=`, `returnUrl=` feeding a Location header) are the highest
  -yield target, since redirect logic often does less input validation
  than the rest of the app.
- Evidence the framework/language in use is an OLDER stack known for
  weaker default header-injection protections (very old Java servlet
  containers, some legacy PHP header() usage) -- modern frameworks
  usually strip control characters automatically, so this is now a
  less common bug than it once was; don't assume it's present just
  because reflection exists, look for it actually reaching output
  unencoded.
- If successful, CRLF injection into a response can: set arbitrary
  additional headers, split the response into two (response
  splitting, enabling response-based cache poisoning -- note the
  overlap with the web_cache_poisoning agent if a cache sits in
  front), or inject a fake response body.

EMAIL/SMTP HEADER INJECTION -- look for:
- Any form field whose value plausibly ends up in an outbound email:
  a "contact us" form's from-address or subject line, a
  "share/invite a friend" feature's recipient field, a password-reset
  or notification email's dynamic subject/body content built from
  user input.
- If that field's value could contain %0d%0a (CRLF) and isn't
  obviously sanitized, an attacker can inject additional headers
  (Bcc:, Cc:, additional To:) into the outbound email -- turning a
  contact form into an open mail relay, or adding themselves as a
  silent Bcc recipient of emails meant for someone else.
- Evidence of which mail-sending mechanism is in play (a
  library/header pattern visible in error messages, e.g. PHPMailer,
  Nodemailer, SendGrid API usage) is useful context but not required
  to raise the finding -- the input-reaches-header-unsanitized pattern
  is the core evidence regardless of which library eventually sends it.

For suggested_test, propose a concrete probe:
- Resend the request with %0d%0a (or literal CRLF if the transport
  layer permits raw bytes) appended to the suspect parameter, followed
  by a made-up header name, and check whether that header appears
  in the raw response
- For email-adjacent fields: submit a value containing
  "attacker@evil.example%0d%0aBcc:attacker@evil.example" and note
  this needs the analyst's own mailbox/logging to fully confirm
  delivery -- the harness can only confirm the value passed through
  unsanitized to whatever handles it next, not that an email was
  actually sent with the injected header

REMINDER: reflection of the raw value alone isn't the finding --
that's true of nearly every parameter. The finding is specifically
that newline characters in that value are NOT being stripped/encoded
before reaching a header-structured output.
"""
