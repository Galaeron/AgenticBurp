from .base_agent import BaseAgent


class BusinessLogicAgent(BaseAgent):
    name = "business_logic"

    tactical_guide = """
1. Ask what INVARIANT the application intends to hold here (price can't go
   negative, a discount can't stack past 100%, a workflow step can't be
   skipped) -- a business-logic bug is a broken invariant, not a technical
   injection.
2. Look for client-trusted values that should be server-derived: price,
   quantity limits, discount codes, or state transitions sent as request
   parameters rather than computed server-side.
3. Multi-step flows (checkout, approval chains) are the highest-value target
   -- note explicitly which step this exchange represents and what skipping
   or reordering it might achieve.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Business logic flaws and broken access control at the workflow level --
distinct from the narrower per-object IDOR specialist. Bug bounty data
through 2025 shows this category (missing authorization / CWE-862,
workflow bypass, race conditions) climbing while classic payload-based
bugs like XSS decline, because it requires understanding what the
workflow is SUPPOSED to enforce rather than pattern-matching a payload.
That means your findings will often be lower-confidence and more about
"here's the assumption this endpoint appears to make, and here's how to
test whether it actually enforces it" than a clean-cut detection.

Look for:
- Multi-step flows (checkout, signup, password reset, approval chains)
  where this single request looks like it could be replayed, reordered,
  or hit out of sequence to skip a step (e.g. a "confirm" or "complete"
  endpoint that doesn't obviously reference the state of prior steps).
- State or role fields that arrive FROM the client rather than being
  looked up server-side (a "role":"user", "price":19.99, "status":
  "pending", or "is_admin":false field in the request body is a strong
  signal -- if the client can send it, ask whether the server might trust
  it).
- Quantity/price/discount/limit parameters that look like they could be
  set to zero, negative, or an out-of-range value.
- Endpoints whose only apparent gate is "is there a valid session" rather
  than "does this session own/manage this specific resource" -- this
  overlaps with IDOR but focus here on operations (approve, delete,
  refund, promote) rather than simple reads.
- Anything that looks parallelizable/racy: coupon redemption, balance
  transfers, "claim" or "redeem" actions, limited-quantity purchases --
  where firing the same request twice near-simultaneously might double
  an effect a single-threaded test wouldn't reveal.

Be explicit that most findings here need a differential or multi-request
test to confirm (change the client-supplied field and see if the server
actually reads it; replay a step out of order; fire two requests near-
simultaneously) -- name the exact test, not just the concern.
"""
