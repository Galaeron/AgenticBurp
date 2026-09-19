from .base_agent import BaseAgent


class GraphQLAgent(BaseAgent):
    """
    GraphQL API Security Agent
    
    Detects vulnerabilities specific to GraphQL APIs, which have unique
    attack surfaces not covered by traditional REST API testing.
    
    GraphQL adoption has exploded in 2026, with >80% of web traffic now
    using APIs. GraphQL introduces specific risks that require specialized
    detection.
    
    Coverage includes:
    - Introspection exposure (schema disclosure)
    - Broken Object-Level Authorization (BOLA/IDOR)
    - Broken Function-Level Authorization (BFLA)
    - Mass assignment / BOPLA vulnerabilities
    - Query depth and complexity DoS
    - Batch operations abuse
    - CSRF on GraphQL endpoints
    - Field-suggestion information disclosure
    - GraphQL injection (SQLi/NoSQLi via resolvers)
    - Persisted-query allowlist bypass
    """
    name = "graphql"

    tactical_guide = """
1. If this is a GraphQL endpoint, check whether introspection
   (`__schema`/`__type`) is reachable -- that alone is a significant
   over-exposure finding on its own.
2. Look at the query/mutation shape for missing per-field authorization
   (a query that nests into another user's data via a relation) and for
   batching/aliasing that could bypass simple rate limiting.
3. Note query depth/complexity: an unbounded nested query is a resource-
   exhaustion (DoS-shaped) finding distinct from a data-exposure one --
   don't conflate them.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
GraphQL API vulnerabilities. GraphQL endpoints (/graphql, /api/graphql, /gql)
and responses have distinct attack surfaces from REST APIs. Look for:

INTROSPECTION EXPOSURE (High Severity):
- Introspection enabled in production environments (schema disclosure).
  Look for responses containing GraphQL schema information, type
  definitions, query/mutation definitions, or field lists. Introspection
  should NEVER be enabled in production -- it reveals the entire API
  surface to attackers.
- GraphiQL or other interactive IDEs exposed in production.
- "Did you mean...?" field suggestion errors that can reconstruct schemas
  even when introspection is disabled (Clairvoyance attack).

AUTHORIZATION FLAWS:
- Broken Object-Level Authorization (BOLA/IDOR): GraphQL queries using
  "id" arguments that don't verify the requesting user owns the resource.
  Look for queries like `{ user(id: "123") { email } }` where the id is
  user-supplied without access control.
- Broken Function-Level Authorization (BFLA): Mutations accessible to
  unauthorized users. Look for create/update/delete mutations that
  should require admin privileges but don't enforce them.
- Mass assignment / BOPLA (Batch Object Property Level Authorization):
  GraphQL's flexible input allows attackers to set fields they shouldn't
  be able to modify. Look for mutations accepting arbitrary input objects.

DENIAL OF SERVICE:
- Query depth and complexity DoS: Unbounded recursion in GraphQL queries
  can exhaust server resources. Look for deeply nested queries or queries
  with excessive complexity. CVE-2023-28867 (graphql-java), CVE-2026-40324
  (Hot Chocolate), CVE-2025-32032 (Apollo Router) are real examples.
- Batch operations abuse: Single HTTP request triggering N resolver calls.
  Look for queries using aliases to multiply database load (Directus
  CVE-2024-39895).

INJECTION ATTACKS:
- GraphQL injection: SQLi/NoSQLi via resolver functions. Look for
  user input flowing into database queries without parameterization.
- Persisted-query allowlist bypass: Attempts to execute queries not in
  the allowlist.

CSRF AND OTHER:
- CSRF on GraphQL endpoints: Apollo Server 2's graphql-upload library
  was vulnerable via multipart/form-data (GHSA-2p3c-p3qw-69r4). Look for
  missing CSRF tokens on state-changing mutations.
- Exposed debug endpoints or Playground/GraphiQL in production.

RESPONSE PATTERNS:
- Look for JSON responses with "data" and "errors" keys (GraphQL format).
- Error messages revealing internal details (stack traces, resolver paths).
- Responses containing schema information or type definitions.
- Query/mutation definitions in responses.

For suggested_test, propose specific GraphQL queries that would confirm
or exploit the vulnerability, e.g.: { __schema { types { name } } } for
introspection, or { user(id: "1") { ... } } with another user's ID for BOLA.
"""
