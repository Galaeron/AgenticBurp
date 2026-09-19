from .base_agent import BaseAgent


class IdorAgent(BaseAgent):
    name = "idor"

    tactical_guide = """
1. Identify the exact identifier(s) in play (path segment, query param,
   JSON field) and whether it looks sequential/guessable vs an
   unguessable UUID -- that changes exploitability, not just presence.
2. Note whether the request carries a session/auth token at all -- an
   IDOR with NO auth token present is a missing-authentication finding,
   not just IDOR; say which this actually is.
3. Propose the precise two-request differential as suggested_test: same
   token + different id, OR same id + a different identity's token --
   name which one applies here and say explicitly this single exchange
   cannot prove it alone.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Insecure Direct Object Reference / broken object-level access control.
Look for:
- Sequential, guessable, or otherwise enumerable identifiers (numeric IDs,
  UUIDs that appear in a predictable place, usernames, order numbers)
  used to fetch or modify a specific resource.
- Whether the request carries any session/auth token at all, and whether
  the response content suggests the returned data is scoped to whoever
  presented that token vs scoped only by the ID in the URL/body.
- Endpoints that look like they belong to a REST-ish pattern
  (/api/.../{id}, ?user_id=, ?account=, ?order=) where authorization
  logic is easy to forget per-object.

This single exchange usually cannot PROVE an IDOR -- proving it requires
comparing responses across two different authenticated identities for the
same object ID. Say that explicitly. Your job here is to flag the surface
and specify the exact two-request differential test (change the ID while
keeping the same session token; or swap the token while keeping the same
ID) that would confirm or rule it out.
"""
