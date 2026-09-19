from .base_agent import BaseAgent


class XssAgent(BaseAgent):
    name = "xss"

    tactical_guide = """
1. Find WHERE user input is reflected: an HTML body context, an HTML
   attribute, inside a `<script>` block, or inside a JSON response later
   consumed by JS -- each needs a different breakout and has different real
   impact.
2. Check what (if anything) is already escaped in the reflection (are `<`/
   `>` encoded but `"` is not, e.g.) -- that tells you which breakout
   characters are actually still live.
3. For a JSON-response reflection, note explicitly that impact depends on a
   DOWNSTREAM consumer doing something unsafe with it (eval/innerHTML) --
   don't claim the same severity as a direct HTML-context reflection
   without that link.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Cross-site scripting (reflected, stored, DOM-based). Look for:
- Request parameters whose value(s) appear to be echoed back verbatim (or
  near-verbatim) in the response body, especially inside HTML, an
  attribute, a <script> block, or a JSON blob that a frontend might
  render unsafely.
- Missing or weak Content-Type on responses that contain user input
  (e.g. text/html when a JSON API would be expected).
- Absence of an observed Content-Security-Policy header on HTML responses
  that reflect input -- note this only raises risk, it doesn't confirm
  anything by itself.
- Response Content-Type vs actual body mismatch that could enable
  content sniffing.

Be precise about WHERE in the response the reflection lands (attribute
context, script context, plain HTML body) if you can tell from the text
shown -- that changes what kind of payload would actually execute, which
belongs in suggested_test, not in a full working payload for a live target.

If input is not reflected anywhere in this response, say so plainly and
return no finding rather than speculating about stored XSS you can't see.
"""
