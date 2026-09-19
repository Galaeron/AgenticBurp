from .base_agent import BaseAgent


class HttpRequestSmugglingAgent(BaseAgent):
    """
    HTTP Request Smuggling Agent
    
    Detects HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).
    
    HTTP Request Smuggling (HRS) is a critical vulnerability that allows
    attackers to smuggle malicious requests through a front-end server
    to a back-end server, potentially leading to:
    
    - Cache poisoning
    - Session hijacking
    - Credential theft
    - Bypassing security controls
    - Accessing other users' data
    
    P0 Priority - High ROI
    Average payout: $5,000-$20,000+
    HackerOne: Critical severity, high impact
    
    VULNERABILITY TYPES:
    
    1. CL.TE (Content-Length vs Transfer-Encoding)
    - Front-end uses Content-Length
    - Back-end uses Transfer-Encoding
    - Attacker sends ambiguous request with both headers
    - Front-end processes first request, back-end sees second request
    
    2. TE.CL (Transfer-Encoding vs Content-Length)
    - Front-end uses Transfer-Encoding
    - Back-end uses Content-Length
    - Attacker sends request with Transfer-Encoding: chunked
    - Back-end interprets Content-Length differently
    
    3. TE.TE (Transfer-Encoding obfuscation)
    - Both servers use Transfer-Encoding but handle it differently
    - Attacker sends obfuscated Transfer-Encoding header
    - Front-end normalizes, back-end doesn't
    
    EXPLOITATION:
    
    CL.TE Exploitation:
    POST / HTTP/1.1
    Host: vulnerable.com
    Content-Length: 6
    Transfer-Encoding: chunked
    
    0
    
    GET /admin HTTP/1.1
    Host: vulnerable.com
    
    The front-end sees Content-Length: 6 and processes the first request
    as complete (0\r\n\r\n is 6 bytes). The back-end sees Transfer-Encoding:
    chunked and processes the second request (GET /admin).
    
    TE.CL Exploitation:
    POST / HTTP/1.1
    Host: vulnerable.com
    Content-Length: 4
    Transfer-Encoding: chunked
    
    5c
    GET /admin HTTP/1.1
    Host: vulnerable.com
    0
    
    The front-end processes the chunked body (5c = 92 bytes), while the
    back-end uses Content-Length: 4 and processes only the first part.
    
    TE.TE Exploitation:
    POST / HTTP/1.1
    Host: vulnerable.com
    Transfer-Encoding: chunked
    Transfer-Encoding: identity
    
    0
    
    GET /admin HTTP/1.1
    Host: vulnerable.com
    
    Some front-ends concatenate Transfer-Encoding headers, while back-ends
    may use only the first or last one.
    
    DETECTION SIGNALS:
    
    Response-Based Detection:
    - Time delays between requests (queuing)
    - Unexpected responses (404, 500, or other users' data)
    - Response contains data from other users' requests
    - Inconsistent behavior between front-end and back-end
    
    Timing-Based Detection:
    - Requests appear to be queued or delayed
    - Subsequent requests return responses for earlier requests
    - Time gaps between sending and receiving
    
    Header-Based Detection:
    - Inconsistent handling of Content-Length vs Transfer-Encoding
    - Multiple Transfer-Encoding headers
    - Obfuscated Transfer-Encoding headers
    - Connection: keep-alive with pipelining
    
    IMPACT:
    
    - Cache Poisoning: Smuggled requests can poison caches with malicious content
    - Session Hijacking: Steal session cookies and authentication tokens
    - Credential Theft: Capture user credentials and sensitive data
    - Security Bypass: Bypass WAF, rate limiting, and authentication
    - Data Theft: Access other users' private data
    - RCE: In some cases, achieve remote code execution
    
    REAL-WORLD EXAMPLES:
    
    - Uber: $10,000 bounty for HRS leading to account takeover
    - PayPal: $18,000 bounty for HRS leading to payment manipulation
    - Tesla: $15,000 bounty for HRS leading to internal network access
    - Shopify: $20,000 bounty for HRS leading to store compromise
    
    TESTING METHODOLOGY:
    
    1. Identify Front-End/Back-End Architecture
    - Determine if the application uses a reverse proxy or load balancer
    - Identify front-end (CDN, WAF, load balancer) and back-end servers
    
    2. Test for CL.TE Vulnerability
    - Send requests with both Content-Length and Transfer-Encoding
    - Observe if back-end processes additional requests
    
    3. Test for TE.CL Vulnerability
    - Send chunked requests with Content-Length
    - Observe if front-end and back-end interpret differently
    
    4. Test for TE.TE Vulnerability
    - Send requests with multiple Transfer-Encoding headers
    - Observe if obfuscation is successful
    
    5. Confirm Exploitation
    - Send smuggled requests to sensitive endpoints
    - Verify if other users' data is accessible
    - Confirm cache poisoning is possible
    
    SUGGESTED TESTS:
    
    For HTTP Request Smuggling, suggest:
    - "Test for CL.TE vulnerability by sending request with both Content-Length and Transfer-Encoding headers"
    - "Test for TE.CL vulnerability by sending chunked request with Content-Length"
    - "Test for TE.TE vulnerability by sending obfuscated Transfer-Encoding headers"
    - "Send smuggled GET request to /admin and observe if it's processed"
    - "Send smuggled POST request with malicious payload and check for queuing"
    - "Test cache poisoning by smuggling requests to cacheable endpoints"
    - "Attempt session hijacking by smuggling requests to session endpoints"
    - "Check for time delays that indicate request queuing"
    
    DETECTION TECHNIQUES:
    
    1. Same-Connection Testing:
    - Send two requests on the same connection
    - First request: smuggled request
    - Second request: benign request
    - Observe if second request returns response from first
    
    2. Cross-Connection Testing:
    - Send smuggled request from one connection
    - Send benign request from another connection
    - Observe if benign request is affected
    
    3. Timing Analysis:
    - Measure time between requests
    - Look for queuing delays
    - Detect request interference
    
    4. Response Analysis:
    - Check for unexpected responses
    - Look for other users' data
    - Detect error responses indicating smuggling
    
    MITIGATION:
    
    - Normalize headers (reject requests with both Content-Length and Transfer-Encoding)
    - Use consistent header parsing across front-end and back-end
    - Disable connection reuse (Connection: close)
    - Implement request validation and sanitization
    - Keep servers updated with latest patches
    
    REFERENCES:
    
    - PortSwigger: https://portswigger.net/web-security/request-smuggling
    - OWASP: https://owasp.org/www-community/vulnerabilities/HTTP_Request_Smuggling
    - CVE-2019-11043: PHP-FPM request smuggling
    - CVE-2020-1938: Apache Traffic Server request smuggling
    - CVE-2021-41773: Path traversal + request smuggling (Log4Shell related)
    """
    name = "http_request_smuggling"

    tactical_guide = """
1. Look for the CL.TE/TE.CL precondition: does this response's headers show
   BOTH a Content-Length and a Transfer-Encoding, or hints of a front-end
   proxy plus a distinct backend (Server header mismatch, unusual latency
   pattern)?
2. Smuggling cannot be confirmed from a single exchange -- it requires a
   crafted request that desyncs the connection and a SECOND request that
   observes the effect. Say that explicitly rather than implying this one
   exchange proves anything.
3. Note any obfuscated Transfer-Encoding variant (extra whitespace, wrong
   case, duplicate header) -- that's the specific parser-disagreement signal
   worth flagging over a generic "might smuggle" claim.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
HTTP Request Smuggling (HRS) vulnerabilities.

HTTP Request Smuggling is a CRITICAL vulnerability that occurs when a
front-end server (reverse proxy, load balancer, CDN) and a back-end server
interpret HTTP requests differently, allowing attackers to smuggle malicious
requests through the front-end to the back-end.

THREE MAIN TYPES:

1. CL.TE (Content-Length vs Transfer-Encoding)
   Front-end: Content-Length
   Back-end: Transfer-Encoding
   
   Attack: Send request with BOTH headers
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 6
   Transfer-Encoding: chunked
   
   0
   
   GET /admin HTTP/1.1
   Host: target.com
   
   Front-end sees Content-Length=6, processes first request as complete.
   Back-end sees Transfer-Encoding: chunked, processes the smuggled GET /admin.

2. TE.CL (Transfer-Encoding vs Content-Length)
   Front-end: Transfer-Encoding
   Back-end: Content-Length
   
   Attack: Send chunked request with Content-Length
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 4
   Transfer-Encoding: chunked
   
   5c
   GET /admin HTTP/1.1
   Host: target.com
   0
   
   Front-end processes chunked body, back-end uses Content-Length.

3. TE.TE (Transfer-Encoding obfuscation)
   Both use Transfer-Encoding but handle it differently
   
   Attack: Send obfuscated Transfer-Encoding
   POST / HTTP/1.1
   Host: target.com
   Transfer-Encoding: chunked
   Transfer-Encoding: identity
   
   0
   
   GET /admin HTTP/1.1
   Host: target.com
   
   Front-end may concatenate headers, back-end may use only one.

DETECTION SIGNALS:

- Time delays between requests (request queuing)
- Unexpected responses (404, 500, or other users' data)
- Responses containing data from other users' requests
- Inconsistent behavior between consecutive requests
- Connection: keep-alive with HTTP pipelining enabled

EXPLOITATION IMPACT:

- Cache Poisoning: Poison web caches with malicious content
- Session Hijacking: Steal session cookies and authentication tokens
- Credential Theft: Capture user credentials and sensitive data
- Security Bypass: Bypass WAF, rate limiting, authentication controls
- Data Theft: Access other users' private data
- Remote Code Execution: In some configurations

TESTING METHODOLOGY:

1. IDENTIFY ARCHITECTURE
   - Determine if application uses reverse proxy/load balancer
   - Identify front-end and back-end servers
   - Check for Connection: keep-alive support

2. TEST CL.TE VULNERABILITY
   Send: POST with Content-Length AND Transfer-Encoding
   Observe: Does back-end process additional requests?
   
3. TEST TE.CL VULNERABILITY
   Send: Chunked POST with Content-Length
   Observe: Do front-end and back-end interpret differently?
   
4. TEST TE.TE VULNERABILITY
   Send: Multiple Transfer-Encoding headers
   Observe: Does obfuscation work?

5. CONFIRM EXPLOITATION
   - Send smuggled requests to sensitive endpoints (/admin, /api, etc.)
   - Verify access to other users' data
   - Confirm cache poisoning is possible
   - Test session hijacking potential

SUGGESTED TESTS FOR HRS:

- "Test for CL.TE: Send POST with Content-Length: 6 and Transfer-Encoding: chunked, body: 0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n"
- "Test for TE.CL: Send POST with Content-Length: 4 and Transfer-Encoding: chunked, body: 5c\\r\\nGET /admin HTTP/1.1\\r\\nHost: target\\r\\n0\\r\\n\\r\\n"
- "Test for TE.TE: Send POST with Transfer-Encoding: chunked and Transfer-Encoding: identity"
- "Send smuggled GET request to /admin and observe if processed by back-end"
- "Send smuggled POST to sensitive endpoint and check for data leakage"
- "Test cache poisoning by smuggling requests to cacheable endpoints"
- "Attempt session hijacking by smuggling to /login or /session endpoints"
- "Check for timing delays indicating request queuing"
- "Send multiple smuggled requests to test for persistent vulnerabilities"

PAYLOAD EXAMPLES:

CL.TE Payload:
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com


TE.CL Payload:
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: target.com
0


TE.TE Payload:
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

GET /admin HTTP/1.1
Host: target.com


HEADER OBFUSCATION:

Try various obfuscations of Transfer-Encoding:
- Transfer-Encoding: chunked
- Transfer-Encoding: chunked, identity
- Transfer-Encoding: identity, chunked
- transfer-encoding: chunked (case variation)
- Transfer-Encoding: chunked\r\nX: ignore (header injection)
- Transfer-Encoding: chunked\r\nX-Ignore: (header injection)

DETECTION TECHNIQUES:

1. Same-Connection Test:
   - Open persistent connection
   - Send smuggled request
   - Send benign request on same connection
   - Observe if benign request returns smuggled response

2. Cross-Connection Test:
   - Send smuggled request from connection A
   - Send benign request from connection B
   - Observe if connection B is affected

3. Timing Test:
   - Send smuggled request
   - Measure time for subsequent requests
   - Delays indicate queuing/processing

4. Response Analysis:
   - Check for unexpected status codes
   - Look for other users' data in responses
   - Detect error messages indicating smuggling

FRONT-END/BACK-END INDICATORS:

Front-end servers (common):
- Nginx
- Apache Traffic Server
- Varnish
- Cloudflare
- AWS ALB/ELB
- HAProxy
- Squid
- CDN77
- Fastly
- Akamai

Back-end servers (common):
- Apache HTTP Server
- IIS
- Tomcat
- Node.js/Express
- Django/Flask
- Spring Boot
- .NET Core
- PHP-FPM
- Gunicorn
- uWSGI

TESTING TOOLS:

- Burp Suite: Built-in request smuggling detection
- curl: Manual testing with -H headers
- python: Custom scripts with httpx/requests
- smuggler: Automated HRS detection tool
- Turbo Intruder: For mass testing

IMPACT ASSESSMENT:

Critical: Can lead to complete account takeover, data breach
High: Can lead to significant data exposure or security bypass
Medium: Can lead to limited data exposure or minor security bypass
Low: Theoretical vulnerability with no practical exploitation

REMINDER: HTTP Request Smuggling is one of the most impactful
vulnerabilities. A single HRS vulnerability can compromise an entire
application and all its users. Always test thoroughly and report
responsibly.

REFERENCES:
- PortSwigger Labs: https://portswigger.net/web-security/request-smuggling
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CVE-2019-11043 (PHP-FPM)
- CVE-2020-1938 (Apache Traffic Server)
- CVE-2021-41773 (Path traversal + HRS)
"""
