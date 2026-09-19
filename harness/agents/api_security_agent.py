from .base_agent import BaseAgent


class ApiSecurityAgent(BaseAgent):
    """
    API Security Agent

    Detects API-specific issues that the general-purpose agents don't
    target even when they fire on the same endpoint: the OWASP API
    Security Top 10 concerns that are about API DESIGN, not about a
    specific injection point (mass assignment, excessive data
    exposure, lack of resource-consumption limits, missing API-level
    versioning/deprecation hygiene). idor/auth/sqli/etc. already fire
    on API endpoints just like any other endpoint -- this agent covers
    what's left over that's specific to APIs as a category.
    """
    name = "api_security"

    tactical_guide = """
1. Identify the API style (REST/GraphQL/RPC) and whether this endpoint
   exposes an OpenAPI/GraphQL schema anywhere -- schema over-exposure itself
   is worth flagging.
2. Check for classic API misconfig: excessive data exposure (response fields
   far beyond what the request needed), missing pagination/rate limiting on
   a list endpoint, and mass-assignment-shaped request bodies (a write body
   with far more fields than the response ever needed).
3. Note whether versioning is visible (/v1/, /v2/) -- an old, still-live
   version is a common place authz fixes never got backported.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
API-specific security issues (OWASP API Security Top 10), distinct
from the general injection/access-control classes other agents in
this harness already cover on any endpoint including API ones. Only
report something here if it's about API DESIGN, not a straightforward
sqli/idor/auth finding that belongs to a different agent.

MASS ASSIGNMENT / EXCESSIVE DATA BINDING:
- A request body (typically JSON) where the response reflects back
  MORE fields than what was sent, especially fields that look
  privileged (role, isAdmin, permissions, accountBalance, verified,
  internal IDs) -- if the API blindly binds request JSON to an
  internal object, an attacker can potentially set fields they were
  never shown a form field for.
- Look specifically for object-shaped request bodies on
  create/update endpoints (POST/PUT/PATCH) where you can't tell from
  the visible fields alone whether server-side allowlisting of
  bindable fields exists.

EXCESSIVE DATA EXPOSURE:
- A response returning MORE data than the endpoint's apparent purpose
  needs -- e.g. a "list users" endpoint returning full user objects
  (password hashes, internal notes, email, phone) when the UI only
  displays a name and avatar. This is a distinct pattern from IDOR:
  IDOR is about accessing another user's record you shouldn't reach
  at all; excessive data exposure is about your OWN legitimately
  -reached response containing fields that should never be
  serialized to any client, full stop.

LACK OF RESOURCE / RATE LIMITING AT THE API LAYER:
- Endpoints that accept an unbounded or very large page size /
  limit / count parameter (e.g. ?limit=1000000) with no visible cap
  enforced, risking resource exhaustion. Distinct from the harness's
  rate_limit agent, which is about repeated-request abuse
  (brute force, enumeration) -- this is about a SINGLE request being
  able to demand unbounded work.
- Batch/bulk endpoints (bulk delete, bulk export, batch operations)
  with no visible limit on how many items can be requested in one
  call.

API VERSIONING / INVENTORY ISSUES:
- Evidence of an old/deprecated API version still being reachable
  (e.g. /api/v1/ still live alongside /api/v3/, especially if v1
  responses look less carefully secured -- missing auth checks, more
  verbose errors, or missing fields the newer version redacts).
- Undocumented or debug-looking endpoints visible in this exchange
  (an endpoint the app's own client code doesn't appear to call, or
  one with an obviously internal-sounding name like /api/internal/,
  /api/_debug/, /api/admin/v0/).

FUNCTION-LEVEL AUTHORIZATION AT THE API LAYER:
- An API endpoint whose HTTP method alone changes the operation's
  privilege level (GET works unauthenticated but PUT/DELETE on the
  same path should require auth) -- check whether the same
  authorization check that's visible on one method is actually
  present on the others, which you can only partially judge from a
  single captured exchange; flag it as worth checking across methods
  if you only saw one.

For suggested_test, propose a concrete probe:
- Resend a create/update request with an extra unexpected field
  (e.g. "role": "admin") added to the JSON body and check whether the
  response reflects it back as accepted
- Request the same "list" endpoint and diff which fields appear in
  the response against what the application's UI actually displays
- Request a large limit/count parameter and observe whether the
  server caps it or returns everything requested

REMINDER: this agent's findings are about API DESIGN choices, so
"suggested_test" should describe a DESIGN verification, not a generic
injection payload -- e.g. "add an unexpected field and see if it's
accepted," not "try ' OR 1=1--".
"""
