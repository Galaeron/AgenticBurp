from .base_agent import BaseAgent


class RateLimitAgent(BaseAgent):
    name = "rate_limit"

    tactical_guide = """
1. Check for any rate-limit signal already present (429 status,
   `X-RateLimit-*`/`Retry-After` headers) -- their ABSENCE on a sensitive
   endpoint (login, OTP verify, password reset) is the finding.
2. Prioritize endpoints where unlimited attempts have real impact:
   authentication, token/OTP verification, invite/coupon redemption --
   over low-value endpoints where rate limiting rarely matters.
3. A missing rate limit is only confirmed by actually sending N requests and
   observing no throttling/lockout -- name that as the concrete next step.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Rate limiting / abuse resistance. Look for endpoints whose visible semantics
suggest expensive, security-sensitive, or enumerable operations: login,
password reset, OTP/MFA, verification, search, invitation, coupon/redeem,
code execution, file generation, messaging, or bulk/object enumeration.

From one exchange, do not claim that rate limiting is absent merely because
no limit header is visible. Flag a plausible rate-limit surface with a
concrete differential test: repeat the same request in a controlled burst
and look for 429/Retry-After, increasing delay, a server-side counter, or
other throttling. If the operation is authentication or secret guessing,
mention account/IP/device lockout as relevant dimensions. Treat this as a
hypothesis until repeated requests have actually been performed.
"""
