from .base_agent import BaseAgent
from harness.anomaly_detector import detector, Anomaly
from harness.models import Finding


class AnomalyAgent(BaseAgent):
    """
    Agent for detecting unknown vulnerabilities through behavioral anomaly detection.
    
    This agent doesn't look for specific vulnerability patterns. Instead, it:
    1. Builds a baseline profile of normal application behavior
    2. Detects deviations from that baseline
    3. Clusters similar anomalies to identify new vulnerability classes
    4. Flags suspicious behavior that may indicate unknown vulnerabilities
    """
    name = "anomaly"

    tactical_guide = """
1. Compare this exchange's shape (status code, header set, response size,
   timing markers if present) against what a well-behaved response for this
   route would look like -- an anomaly is a DEVIATION, not a bug in itself.
2. Look specifically for signals no single-purpose agent would flag: an
   unusual header combination, a response that doesn't match its declared
   Content-Type, or a status/body mismatch (200 with an error-shaped body).
3. State the baseline you're comparing against explicitly in evidence -- an
   anomaly claim with no stated baseline is not falsifiable and should not
   be reported.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Anomaly detection for unknown vulnerabilities. This agent looks for:

BEHAVIORAL DEVIATIONS:
- Statistical outliers in response sizes, parameter counts, URL depths
- Unusual status codes for HTTP methods
- Rare content types
- Missing or unexpected security headers
- Information disclosure in headers

SUSPICIOUS PATTERNS:
- Path traversal patterns (../, ..\\)
- Command injection patterns (;, |, &&, $())
- SQL injection patterns (', ", OR, UNION)
- XSS patterns (<script>, javascript:, onerror=)
- SSRF patterns (localhost, 127.0.0.1, internal IPs)
- NoSQL injection patterns ($ne, $gt, $regex)
- JWT patterns (eyJ...)
- File upload patterns (.php, .asp, .jsp)

PARAMETER ANOMALIES:
- Sensitive parameter names (password, token, api_key, etc.)
- Unusually long parameter values (>1000 chars)
- Parameter values with repeated characters (potential DoS)

TEMPORAL ANOMALIES:
- Unusually slow responses (may indicate processing delays)
- Rapid sequences of similar requests (may indicate scanning)
- Request timing patterns that suggest automation

CLUSTERING:
- Groups similar anomalies together
- Identifies new vulnerability classes from clusters
- Flags repeated anomalous behavior

This agent works differently from other specialists:
- It builds a profile of normal behavior over time
- It detects deviations from that profile
- It can discover vulnerabilities that don't match known patterns
- It improves as it sees more exchanges

For suggested_test, propose:
- Investigate the specific anomaly type
- Check for the suspicious pattern in other requests
- Test with variations of the anomalous input
- Look for similar anomalies in the same session

Note: This agent requires multiple exchanges to build a baseline.
The first few exchanges may not produce useful findings.
"""

    def __init__(self, ollama, model: str, temperature: float = 0.1):
        super().__init__(ollama, model, temperature)
        # Initialize anomaly detector if not already done
        # The detector is a singleton that builds up over time
    
    async def run(self, exchange, max_body_chars: int, prior_context: str, ledger):
        """
        Run anomaly detection on an exchange.
        
        This overrides the base run method to use the anomaly detector.
        """
        # Update the detector's profile with this exchange
        detector.update_profile(exchange)
        
        # Detect anomalies
        anomalies = detector.detect_anomalies(exchange)
        
        # Convert anomalies to findings
        findings = detector.generate_findings(anomalies)
        
        # Return as an agent report
        from harness.models import AgentReport
        return AgentReport(
            agent=self.name,
            model=self.model,
            findings=findings,
            components=[],
            raw_error=None,
            prompt_version=""
        )
