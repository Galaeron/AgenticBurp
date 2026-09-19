from .base_agent import BaseAgent


class SqliAgent(BaseAgent):
    name = "sqli"

    tactical_guide = """
1. Identify every parameter (query string, form field, JSON key, header,
   cookie) that plausibly reaches a query, and note which looks most
   promising (an id/filter/sort field beats a UI-only display string).
2. Prefer a DIFFERENTIAL test in suggested_test: baseline vs a single quote
   vs the quote escaped/doubled -- a response DIFFERENCE between those two
   is the signal, not the quote alone.
3. If the response gives no visible signal, suggest a boolean-blind pair
   (`AND 1=1` vs `AND 1=2`-shaped) or a time-based fallback -- and say
   explicitly that a real confirmation needs the differential, not this
   single exchange.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
SQL injection. Look at parameters (query string, form body, JSON fields,
cookies, headers) that appear to flow into a database query: IDs, sort/order
fields, filter fields, search boxes, "type" or "category" style selectors.

Signals worth flagging (each on its own, moderate confidence at most without
more evidence):
- Numeric- or string-looking identifiers used directly in the URL/body.
- Error responses (5xx, stack traces, DB engine names/messages, ODBC/JDBC
  strings, "syntax error", "unclosed quotation mark") in the response body.
- Behavioral differences implied by the response that suggest the input
  reaches a query unsanitized (this exchange alone usually can't prove
  that -- say so and propose the boundary test that would).
- ORDER BY / sort parameters, which are commonly injectable and commonly
  missed by naive filters.
- CHECK THIS FIRST, ESPECIALLY ON A LOGIN/AUTH ENDPOINT: does a
  username/email/password field itself already contain SQL comment or
  boolean-injection syntax (`' --`, `'--`, `' OR '1'='1`, `' OR 1=1--`,
  `admin'#`)? This is the single most classic SQL injection pattern there
  is, and it produces NO error and NO unusual-looking response by design
  -- a blind auth-bypass succeeds by returning an ordinary-looking
  successful response (HTTP 200, a normal-shaped session token) for
  credentials that should not have matched anything. Do not wait for an
  error message or a visible anomaly here: the confirming signal is that
  the request's own credential field is syntactically a query-breaking
  payload, correlated with a response that looks like a successful
  authentication despite the password not plausibly matching. This is
  exactly as high-confidence as an error-based signal, not a "maybe."

For suggested_test, name the specific parameter and a standard boundary
probe (e.g. append a single quote, or a numeric offset like id-0, or a
sleep-based timing probe) and what response difference would confirm it --
do not invent novel bypass techniques, just the standard diagnostic step.
"""
