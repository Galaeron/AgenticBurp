from .base_agent import BaseAgent


class RaceConditionAgent(BaseAgent):
    """
    Race Condition Agent

    Detects endpoints whose behavior suggests a check and a
    subsequent action aren't atomic -- the classic time-of-check to
    time-of-use (TOCTOU) gap that lets an attacker send the same
    request many times in a tight burst and have more of them succeed
    than the business logic should allow (redeem a coupon twice, apply
    a discount code multiple times, withdraw more than the account
    balance, create more than one account with the same invite code).

    This was not named in either prior backlog for this project (the
    original handover's P1 list or the missing-agents analysis doc) --
    it's a finding from the later WSTG/PortSwigger coverage review,
    cross-checked against PortSwigger's own published topic list.
    """
    name = "race_condition"

    tactical_guide = """
1. Look for a check-then-act shape: a balance/inventory/coupon/limit check
   followed by a write, where nothing in the exchange suggests atomicity
   (no visible idempotency key, no optimistic-lock version field).
2. Name the SPECIFIC resource that could be over-spent/over-redeemed/
   double-applied if this exact request were fired concurrently -- a race
   condition finding needs a concrete resource, not a generic "might race".
3. This can only be CONFIRMED by firing genuinely concurrent requests and
   observing the resource end in an inconsistent state -- say that's the
   required next step rather than implying single-request evidence proves it.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Race conditions from a single captured exchange. You can't directly
observe concurrent behavior from one request/response pair -- your job
is to identify CANDIDATE endpoints where a race condition is plausible
given the operation's shape, for the validator to actually test by
firing the same request many times in a burst.

WHAT MAKES AN ENDPOINT A GOOD CANDIDATE:
- Any operation that both CHECKS a limited resource/state and then
  ACTS on it, where the check-then-act isn't obviously wrapped in a
  single atomic operation: redeeming a coupon/promo code, applying a
  one-time discount, withdrawing funds/spending points/credits,
  claiming a limited-quantity item, using an invite/referral code,
  submitting a vote, rating/reviewing something once per user,
  transferring funds between accounts.
- The distinguishing signal is "once per X" or "limited to N"
  business logic visible in the response text, error messages, or
  the endpoint's apparent purpose -- "you have already redeemed this
  code," "one entry per customer," "insufficient balance" are the
  kind of messages whose ENFORCEMENT is worth stress-testing for a
  race, since the message proves a check exists, but says nothing
  about whether that check and the resulting state change happen
  atomically.
- Multi-step flows are especially interesting: if redeeming a
  discount requires (1) validate code -> (2) apply code -> (3) confirm
  order, and each step is a separate request, the gap between
  validate and apply is exactly where a race condition lives.
- Account/session creation flows using a single-use token (password
  reset, email verification, invite acceptance) are also candidates:
  can the same token be consumed by two near-simultaneous requests
  before either one has a chance to mark it "used"?

WHAT'S NOT A GOOD CANDIDATE:
- Purely idempotent operations (GET requests, or any operation that
  produces the same end state no matter how many times or how fast
  it's repeated) -- there's no race to exploit if repeating the
  request changes nothing.
- Operations already rate-limited so aggressively that a meaningful
  burst isn't achievable (though note this as a reason NOT to flag,
  rather than silently skipping -- the rate_limit agent's findings on
  the same endpoint are relevant context here).

For suggested_test, propose the concrete burst test:
- Fire N copies (a number like 10-20 is typical) of the exact same
  request simultaneously (not sequentially -- the whole point is
  overlapping the check-then-act window) and count how many
  "succeeded" according to the response, comparing against the
  business rule the app claims to enforce (e.g. "used this code 6
  times when it should allow exactly 1")
- Note whether the request needs any per-request-unique value (CSRF
  token, nonce) that would need to be captured once and reused across
  all N burst requests, since single-use tokens on the request itself
  (not the resource being raced) would prevent a naive burst test from
  working and need a different approach

REMINDER: this agent's job is CANDIDATE IDENTIFICATION -- basis should
almost always be "derived" (the check-then-act shape is visible) or
"assumed" (you're inferring atomicity isn't guaranteed, which you
can't actually see from one exchange), essentially never "recalled,"
since race conditions are structural, not signature-based like most
other vulnerability classes.
"""
