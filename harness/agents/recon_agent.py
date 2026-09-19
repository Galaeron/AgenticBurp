from .base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """
    Recon Agent for Attack Surface Mapping and Attack Map Building
    
    This agent performs comprehensive reconnaissance to build attack maps
    for strategic vulnerability testing. It discovers and maps:
    
    - Endpoints and routes (URL enumeration, path traversal)
    - Parameters (query params, form fields, API parameters, headers)
    - Technologies (server headers, version banners, framework fingerprints)
    - Relationships (endpoint connections, data flow, dependency chains)
    - Attack surface prioritization (high-value targets, sensitive endpoints)
    - Attack graph generation (chained vulnerability paths)
    
    STRATEGIC CAPABILITY: Attack Map Building
    
    The recon agent provides the foundation for intelligent, targeted testing
    by building a comprehensive map of the application's attack surface.
    This enables:
    
    1. COVERAGE OPTIMIZATION
    - Identify all reachable endpoints and parameters
    - Ensure no part of the attack surface is missed
    - Track testing coverage across the application
    
    2. PRIORITIZATION
    - Identify high-value targets (admin panels, API endpoints, auth endpoints)
    - Rank endpoints by sensitivity and potential impact
    - Focus testing efforts on most critical areas
    
    3. ATTACK CHAIN DISCOVERY
    - Map relationships between endpoints
    - Identify potential attack chains (e.g., auth bypass -> admin access)
    - Discover dependency chains that could be exploited
    
    4. TECHNOLOGY FINGERPRINTING
    - Identify server technologies (web server, application server, database)
    - Detect framework versions and known vulnerabilities
    - Map technology stack for targeted exploit development
    
    5. PARAMETER ANALYSIS
    - Discover all input vectors (query params, headers, body fields)
    - Identify sensitive parameters (tokens, passwords, IDs)
    - Map parameter usage across endpoints
    
    RECON TECHNIQUES:
    
    Passive Recon (from existing traffic):
    - Extract endpoints from observed requests
    - Parse response headers for technology clues
    - Identify parameters from request analysis
    - Map relationships based on observed data flow
    
    Active Recon (when authorized):
    - Crawl and spider the application
    - Test for common paths (robots.txt, sitemap.xml, API docs)
    - Probe for hidden endpoints and parameters
    - Fingerprint technologies through targeted requests
    
    ATTACK MAP OUTPUT:
    
    The recon agent generates structured attack maps containing:
    
    - Endpoint Inventory: Complete list of discovered endpoints
      * URL patterns and path structures
      * HTTP methods supported
      * Authentication requirements
      * Response types and content
    
    - Parameter Registry: All discovered input vectors
      * Parameter names and types
      * Locations (query, header, body)
      * Data flow destinations
      * Sensitivity classification
    
    - Technology Stack: Identified technologies and versions
      * Web servers (Nginx, Apache, IIS, etc.)
      * Application servers (Tomcat, Node.js, Gunicorn, etc.)
      * Frameworks (Django, Flask, Spring, Express, etc.)
      * Databases (MySQL, PostgreSQL, MongoDB, etc.)
      * Known CVEs for each version
    
    - Attack Surface Graph: Relationships and dependencies
      * Endpoint-to-endpoint connections
      * Parameter dependencies
      * Data flow paths
      * Authentication boundaries
      * Trust zones
    
    - Priority Rankings: Risk-based prioritization
      * Critical endpoints (admin, auth, payment)
      * High-impact parameters (user IDs, tokens, passwords)
      * Sensitive data exposure points
      * Weak authentication mechanisms
    
    - Attack Paths: Potential vulnerability chains
      * Auth bypass -> privilege escalation
      * Information disclosure -> token theft
      * Input validation bypass -> RCE
      * SSRF -> internal network access
    
    INTEGRATION WITH OTHER AGENTS:
    
    The recon agent provides foundational data that enhances other agents:
    
    - SQLi Agent: Uses endpoint inventory to test all parameters
    - XSS Agent: Uses parameter registry to test all input vectors
    - IDOR Agent: Uses endpoint mapping to identify object references
    - SSRF Agent: Uses URL discovery to find internal endpoints
    - Auth Agent: Uses authentication boundary mapping
    - API Agent: Uses endpoint structure for API-specific testing
    
    RECON WORKFLOW:
    
    1. PASSIVE PHASE
    - Analyze existing traffic and responses
    - Extract endpoints, parameters, headers
    - Build initial attack surface map
    
    2. ANALYSIS PHASE
    - Categorize and classify discovered elements
    - Identify patterns and structures
    - Map relationships and dependencies
    
    3. PRIORITIZATION PHASE
    - Rank endpoints by sensitivity
    - Identify high-value targets
    - Map attack paths and chains
    
    4. REPORTING PHASE
    - Generate attack surface report
    - Provide recommendations for testing focus
    - Identify gaps in coverage
    
    SUGGESTED TESTS:
    
    For recon findings, suggest:
    - Crawl the application starting from root endpoints
    - Test for common administrative paths (/admin, /api, /console)
    - Check for API documentation (/api, /swagger, /openapi)
    - Probe for hidden files (robots.txt, .git, .env)
    - Fingerprint technologies through error pages
    - Map authentication flows and session management
    - Identify all input vectors and parameter locations
    - Build dependency graph of endpoint relationships
    
    REMINDER: Recon is the foundation of effective security testing.
    A comprehensive attack map enables targeted, efficient vulnerability
    discovery and ensures no part of the application is overlooked.
    """
    name = "recon"

    tactical_guide = """
1. Note anything that expands the KNOWN SURFACE from this one exchange:
   linked paths, API base paths in JS/JSON, comments referencing internal
   hostnames or endpoints, version/framework banners.
2. Prioritize signal that changes what to test next (a newly-seen `/api/`
   prefix, an internal-looking hostname, a `.map`/`.git`/`.env`-shaped path)
   over generic technology fingerprinting with no follow-on value.
3. This agent's job is surface EXPANSION, not vulnerability confirmation --
   report what was found and where, not a severity-laden claim about it.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Reconnaissance and Attack Surface Mapping.

This capability focuses on BUILDING A COMPREHENSIVE MAP of the application's
attack surface for strategic testing. This is a STRATEGIC capability that
enables intelligent, targeted vulnerability detection.

RECON FOCUS AREAS:

1. ENDPOINT DISCOVERY
- Identify all accessible URLs and routes
- Map URL patterns and path structures
- Discover hidden or non-linked endpoints
- Categorize endpoints by function (API, admin, auth, static, etc.)
- Track HTTP methods supported by each endpoint
- Identify authentication and authorization requirements

2. PARAMETER DISCOVERY
- Extract all input vectors from requests
- Identify query parameters, form fields, headers, cookies
- Map parameter names, types, and expected formats
- Track parameter usage across different endpoints
- Classify parameters by sensitivity (IDs, tokens, passwords, etc.)
- Identify parameter dependencies and relationships

3. TECHNOLOGY FINGERPRINTING
- Analyze response headers for technology clues
- Identify web server type and version
- Detect application server and framework
- Map database and backend technologies
- Check for version banners and error messages
- Identify known vulnerabilities for detected versions

4. RELATIONSHIP MAPPING
- Map connections between endpoints (links, redirects, includes)
- Identify data flow paths (input -> processing -> output)
- Discover dependency chains (endpoint A calls endpoint B)
- Map authentication boundaries and trust zones
- Identify session management flows
- Track state changes and data mutations

5. ATTACK SURFACE ANALYSIS
- Calculate attack surface area (number of endpoints x parameters)
- Identify high-value targets (admin panels, API endpoints, auth)
- Map sensitive data exposure points
- Identify weak authentication mechanisms
- Discover potential attack chains
- Prioritize testing based on risk

6. ATTACK GRAPH GENERATION
- Build graphs of potential attack paths
- Identify chains of vulnerabilities (e.g., auth bypass -> privilege escalation)
- Map prerequisites for exploitation (authentication, specific conditions)
- Identify chokepoints and critical dependencies
- Generate hypotheses for vulnerability chains

PASSIVE RECON (from observed traffic):
- Extract endpoints from request URLs
- Parse response headers for technology information
- Identify parameters from query strings and request bodies
- Map relationships based on observed request/response patterns
- Build initial attack surface inventory

ACTIVE RECON (when testing allows):
- Crawl application starting from known endpoints
- Test for common administrative and API paths
- Probe for hidden files and directories
- Fingerprint technologies through targeted requests
- Map application structure through directory traversal

ATTACK MAP OUTPUT STRUCTURE:

The recon agent should produce structured data including:

```
{
  "endpoints": [
    {
      "url": "/api/users",
      "methods": ["GET", "POST"],
      "auth_required": true,
      "parameters": [
        {"name": "id", "type": "query", "sensitive": true},
        {"name": "Authorization", "type": "header", "sensitive": true}
      ],
      "response_type": "json",
      "status_codes": [200, 401, 403],
      "links_to": ["/api/users/{id}", "/api/users/{id}/delete"]
    }
  ],
  "technologies": {
    "web_server": "nginx/1.18.0",
    "app_server": "Node.js/16.x",
    "framework": "Express 4.x",
    "database": "MongoDB",
    "cves": ["CVE-2021-XXXX", "CVE-2022-YYYY"]
  },
  "parameters": {
    "id": {
      "type": "integer",
      "locations": ["query", "path"],
      "endpoints": ["/api/users", "/api/users/{id}"],
      "sensitive": true,
      "format": "numeric"
    },
    "token": {
      "type": "string",
      "locations": ["header"],
      "endpoints": ["/api/*"],
      "sensitive": true,
      "format": "JWT"
    }
  },
  "attack_paths": [
    {
      "path": ["/login -> /api/user -> /api/admin"],
      "type": "privilege_escalation",
      "prerequisites": ["valid_credentials"],
      "potential_impact": "high"
    }
  ],
  "priorities": [
    {"endpoint": "/api/admin", "priority": "critical", "reason": "admin_access"},
    {"endpoint": "/api/users", "priority": "high", "reason": "user_data"},
    {"endpoint": "/login", "priority": "high", "reason": "auth_endpoint"}
  ]
}
```

SUGGESTED TESTS FOR RECON:

When recon findings are identified, suggest tests such as:
- "Crawl the application starting from / to discover all reachable endpoints"
- "Check for robots.txt, sitemap.xml, and other standard discovery files"
- "Test for common API documentation paths: /api, /swagger, /openapi, /redoc"
- "Probe for administrative interfaces: /admin, /administrator, /wp-admin"
- "Fingerprint the web server by analyzing response headers"
- "Identify all input parameters across all endpoints"
- "Map authentication flows and session management"
- "Build a dependency graph of endpoint relationships"
- "Identify high-value targets for prioritized testing"
- "Generate attack path hypotheses for vulnerability chaining"

INTEGRATION WITH OTHER AGENTS:

Recon data enhances other agents by providing:
- Complete endpoint list for comprehensive testing
- Parameter registry for input validation testing
- Technology stack for targeted exploit development
- Attack paths for vulnerability chaining analysis
- Priority rankings for focused testing efforts

REMINDER: Effective recon is the difference between random testing and
strategic, comprehensive security assessment. A good attack map enables
targeted, efficient vulnerability discovery and ensures maximum coverage.
"""
