from .base_agent import BaseAgent


class BusinessLogicEnhancedAgent(BaseAgent):
    """Enhanced agent for detecting business logic vulnerabilities."""
    name = "business_logic_enhanced"

    tactical_guide = """
1. Build on the basic business-logic lens: look specifically for RACE-prone
   sequences (check-then-act on a balance/inventory/coupon) and workflow
   state that a client could resubmit or replay out of order.
2. Look for numeric bounds that are enforced client-side only (a quantity
   field with a UI max but no visible server-side re-validation signal).
3. Flag multi-tenant boundary logic (an org/account id in the body vs the
   session) as a business-logic-flavored IDOR that also needs a cross-
   identity differential to confirm.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Enhanced business logic vulnerability detection. Look for flaws in:

PRICE AND QUANTITY MANIPULATION:
- Negative prices or quantities (price=-100, quantity=-500)
- Zero prices (price=0)
- Extremely high or low values (price=999999999, quantity=999999)
- Decimal values where integers expected (quantity=1.5)
- Price calculation errors (total != price * quantity)
- Tax/shipping manipulation (tax=0, shipping=0)
- Discount abuse (discount=100, discount=-100)
- Currency manipulation (currency=XXX)
- Price ID manipulation (priceId=premium when user has basic)

WORKFLOW AND STATE MANIPULATION:
- Step skipping in multi-step processes
- State machine manipulation (force transition to completed state)
- Replay attacks (submit same request multiple times)
- Race conditions (concurrent requests for same resource)
- Missing workflow validation (skip payment, skip authentication)
- State desynchronization (client vs server state mismatch)
- Missing nonces or tokens for state-changing operations

ACCOUNT AND PRIVILEGE MANIPULATION:
- Role escalation (change role from user to admin)
- Permission manipulation (add permissions not granted)
- Account balance manipulation (balance=999999)
- Reward points manipulation (points=999999)
- Subscription level manipulation (premium=true)
- Trial period extension
- Account creation without validation

ORDER AND TRANSACTION MANIPULATION:
- Order ID manipulation (access other users' orders)
- Order modification after submission
- Order cancellation abuse
- Refund manipulation
- Payment method manipulation
- Shipping address manipulation
- Order status manipulation (force to shipped/completed)

REVIEW AND FEEDBACK MANIPULATION:
- Post reviews as other users
- Edit other users' reviews
- Delete other users' reviews
- Like/unlike manipulation
- Rating manipulation (rate=10 when max is 5)
- Review spam (post multiple identical reviews)
- Review content manipulation

COUPON AND PROMOTION ABUSE:
- Coupon code manipulation
- Coupon reuse (use same coupon multiple times)
- Expired coupon usage
- Coupon value manipulation (discount=100)
- Coupon stacking (use multiple coupons)
- Promotion code brute forcing
- Free item exploitation

TIME-BASED MANIPULATION:
- Time window abuse (use expired tokens before they expire)
- Rate limit bypass (submit requests faster than allowed)
- Timing attacks (measure response times for information)
- Session timeout manipulation
- Cache manipulation

FORGED DATA:
- Forged JWT tokens (already covered by jwt_agent)
- Forged session data
- Forged cookies
- Forged form data
- Forged API responses
- Forged user identifiers

For suggested_test, propose:
- Test with negative quantity: quantity=-500
- Test with price=0
- Test with discount=100
- Test with negative balance: balance=-1000
- Test step skipping: go directly to final step
- Test replay: submit same request twice
- Test role escalation: change role to admin
- Test order ID manipulation: use another user's order ID

suggested_test MUST be concrete and testable in Burp Repeater:
- "Change quantity parameter to -500"
- "Set price parameter to 0"
- "Modify discount parameter to 100"
- "Change role claim in JWT to admin"
- "Use another user's order ID"
- "Skip payment step in workflow"

CONTEXT MATTERS:
- Business logic flaws are application-specific
- Requires understanding of the application's intended workflow
- Often involves multiple requests (workflow testing)
- May require session state manipulation
- Can be hard to detect without application knowledge
- Often high impact when exploited
"""
