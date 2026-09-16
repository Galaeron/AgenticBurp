"""
Anomaly Detection System for Unknown Vulnerability Discovery

This module implements behavioral anomaly detection to identify potential
security issues that don't match known vulnerability patterns. It uses
statistical analysis, machine learning-inspired heuristics, and behavioral
patterns to flag suspicious application behavior.

The detector works by:
1. Building a baseline profile of "normal" application behavior
2. Comparing each exchange against the baseline
3. Flagging deviations that may indicate security issues
4. Grouping similar anomalies to identify new vulnerability classes
"""

from __future__ import annotations
import re
from urllib.parse import urlsplit as _urlsplit
import json
import hashlib
import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from harness.models import HttpExchange, Finding


@dataclass
class BehaviorProfile:
    """Profile of normal application behavior."""
    # Response characteristics
    avg_response_size: float = 0
    response_size_stddev: float = 0
    common_status_codes: Counter = field(default_factory=Counter)
    
    # Parameter characteristics
    avg_param_count: float = 0
    param_name_length_avg: float = 0
    param_value_length_avg: float = 0
    
    # Header characteristics
    common_headers: Counter = field(default_factory=Counter)
    header_count_avg: float = 0
    
    # URL characteristics
    url_length_avg: float = 0
    url_depth_avg: float = 0  # Number of path segments
    common_path_patterns: Counter = field(default_factory=Counter)
    
    # Content type distribution
    content_types: Counter = field(default_factory=Counter)
    
    # Timing characteristics (if available)
    avg_response_time: float = 0
    
    # Method distribution
    method_counts: Counter = field(default_factory=Counter)
    
    # Exchange count
    exchange_count: int = 0


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: str
    severity: str = "medium"
    confidence: float = 0.5
    description: str = ""
    evidence: str = ""
    exchange_fingerprint: str = ""
    affected_field: str = ""
    expected_value: Any = None
    actual_value: Any = None
    deviation_score: float = 0.0


@dataclass
class AnomalyCluster:
    """Group of similar anomalies that may represent a new vulnerability class."""
    cluster_id: str
    anomalies: list[Anomaly] = field(default_factory=list)
    common_patterns: list[str] = field(default_factory=list)
    suggested_vulnerability_class: str = ""
    confidence: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    host: str = ""


class AnomalyDetector:
    """
    Detects anomalous behavior that may indicate unknown vulnerabilities.
    
    This detector uses multiple detection strategies:
    1. Statistical outliers (response sizes, timing, etc.)
    2. Pattern matching (suspicious input patterns)
    3. Behavioral deviations (unexpected parameter usage)
    4. Temporal anomalies (unusual sequences)
    5. Clustering (grouping similar anomalies)
    """
    
    def __init__(self, min_exchanges_for_baseline: int = 10):
        self.min_exchanges = min_exchanges_for_baseline
        self.profiles: dict[str, BehaviorProfile] = {}
        self.anomalies: list[Anomaly] = []
        self.clusters: list[AnomalyCluster] = []
        self.exchange_history: list[HttpExchange] = []
        
        # Pattern-based detectors
        self.suspicious_patterns = [
            # Path traversal
            r'\.\./',
            r'\.\.\\',
            r'/etc/passwd',
            r'/etc/shadow',
            r'\.git/',
            r'\.svn/',
            r'\.hg/',
            r'\.env',
            r'config\.(json|yml|yaml|ini)',
            r'\.bak$',
            r'\.old$',
            r'\.swp$',
            r'~$',
            
            # Command injection
            r';\s*\w+',
            r'\|\s*\w+',
            r'&&\s*\w+',
            r'\$\(',
            r'`\w+`',
            r'\b(sh|bash|cmd|powershell|python|php|perl|ruby)\b',
            
            # SQL injection
            r"'\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)",
            r'"\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)',
            r'\b(DROP|TRUNCATE|ALTER)\b',
            r'\b(WAITFOR\s+DELAY|SLEEP\()',
            r'\b(BENCHMARK\()',
            
            # XSS
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'javascript:',
            r'data:text/html',
            r'<iframe[^>]*>',
            r'<img[^>]*src\s*=\s*["\']?\s*data:',
            
            # SSRF
            r'http(s)?://(localhost|127\.0\.0\.1|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))',
            r'file://',
            r'gopher://',
            r'dict://',
            
            # NoSQL
            r'\$\w+',
            r'\b(ne|gt|lt|gte|lte|in|nin|regex|where)\b',

            # File upload
            r'\.(php|asp|aspx|jsp|js|py|pl|rb|sh|bat|cmd|exe|dll|so)$',
            r'Content-Type:\s*application/octet-stream',
            
            # Information disclosure
            r'stack\s*trace',
            r'at\s+\w+\.\w+\s*\(',
            r'Exception\s*:',
            r'Error\s*:',
            r'Warning\s*:',
            r'Fatal\s*:',
        ]

        # Patterns safe to match against a RESPONSE (evidence of a successful
        # attack or a real disclosure). The attack-INPUT syntax above
        # (command/SQL/NoSQL injection, SSRF URLs, upload extensions) is
        # deliberately NOT here: matching it against response text flagged
        # nearly every benign response as suspicious -- a "Server: Werkzeug
        # Python" header (the command-injection word list matches "Python"),
        # the English words "in"/"where" (NoSQL operators), an ordinary
        # "Error:" string. Request fields still scan the full
        # suspicious_patterns list; only responses use this narrower set, which
        # keeps genuine evidence (disclosed files/config, stack traces,
        # reflected/stored XSS) while dropping the input-syntax noise.
        self.response_evidence_patterns = [
            r'\.\./', r'\.\.\\', r'/etc/passwd', r'/etc/shadow',
            r'\.git/', r'\.svn/', r'\.hg/', r'\.env', r'config\.(json|yml|yaml|ini)',
            r'<script[^>]*>', r'on\w+\s*=', r'javascript:', r'data:text/html',
            r'<iframe[^>]*>', r'<img[^>]*src\s*=\s*["\']?\s*data:',
            r'stack\s*trace', r'at\s+\w+\.\w+\s*\(', r'Exception\s*:',
            r'Error\s*:', r'Warning\s*:', r'Fatal\s*:',
        ]

        # Header-based anomalies
        self.suspicious_headers = [
            'server',
            'x-powered-by',
            'x-aspnet-version',
            'x-php-version',
            'x-generator',
        ]
        
        # Parameter-based anomalies
        self.sensitive_param_names = [
            'password',
            'passwd',
            'pwd',
            'secret',
            'token',
            'api_key',
            'apikey',
            'api-key',
            'access_token',
            'auth',
            'authorization',
            'session',
            'sessionid',
            'cookie',
            'credit_card',
            'creditcard',
            'cc_number',
            'ssn',
            'social_security',
        ]
        
        # Status code anomalies
        self.unexpected_status_for_method = {
            'GET': [500, 400, 403],  # GET should rarely cause server errors
            'POST': [200],  # POST usually returns 201 for creation
            'PUT': [200],   # PUT usually returns 200 or 204
            'DELETE': [200],  # DELETE usually returns 200 or 204
        }
    
    def update_profile(self, exchange: HttpExchange) -> None:
        """Update the behavior profile with a new exchange."""
        host = self._get_host(exchange.url)
        
        if host not in self.profiles:
            self.profiles[host] = BehaviorProfile()
        
        profile = self.profiles[host]
        
        # Update response statistics
        response_size = len(exchange.response_body) if exchange.response_body else 0
        if profile.exchange_count > 0:
            profile.avg_response_size = (
                profile.avg_response_size * (profile.exchange_count - 1) + response_size
            ) / profile.exchange_count
        else:
            profile.avg_response_size = response_size
        
        # Update status code counts
        if exchange.response_status:
            profile.common_status_codes[str(exchange.response_status)] += 1
        
        # Update parameter statistics
        params = self._extract_parameters(exchange)
        profile.avg_param_count = (
            profile.avg_param_count * (profile.exchange_count - 1) + len(params)
        ) / profile.exchange_count if profile.exchange_count > 0 else len(params)
        
        # Update URL statistics
        url_length = len(exchange.url)
        url_depth = len([p for p in exchange.url.split('/') if p])
        profile.url_length_avg = (
            profile.url_length_avg * (profile.exchange_count - 1) + url_length
        ) / profile.exchange_count if profile.exchange_count > 0 else url_length
        profile.url_depth_avg = (
            profile.url_depth_avg * (profile.exchange_count - 1) + url_depth
        ) / profile.exchange_count if profile.exchange_count > 0 else url_depth
        
        # Update content type statistics
        content_type = exchange.response_headers.get('content-type', '').lower().split(';')[0]
        if content_type:
            profile.content_types[content_type] += 1
        
        # Update method statistics
        profile.method_counts[exchange.method.upper()] += 1
        
        profile.exchange_count += 1
        self.exchange_history.append(exchange)
    
    def detect_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in a single exchange.

        Found live, during a real scoring pass against
        testing/test-target/: a path-traversal exchange containing a
        blatant `../` in a query parameter produced ZERO findings from
        this detector, even after fast_path.py was fixed to dispatch
        `anomaly` for it. Root cause: EVERY check here, including the
        deterministic, baseline-independent suspicious_patterns regex
        match (which already lists path traversal explicitly), was
        gated behind `exchange_count >= min_exchanges` (10) for the
        host -- a threshold that makes sense for genuinely
        baseline-dependent statistical checks (is this response size
        an outlier relative to history?) but has no logical connection
        to "does this URL contain `../`", which is suspicious on the
        very first exchange for a host just as much as the hundredth.
        Confirmed by inspecting each check's own signature: only
        _detect_statistical_anomalies, _detect_status_anomalies, and
        _detect_content_type_anomalies actually take a `profile`
        parameter -- _detect_pattern_anomalies, _detect_parameter_
        anomalies, and _detect_header_anomalies do not, and now run
        unconditionally below.
        """
        anomalies = []
        host = self._get_host(exchange.url)

        # Baseline-INDEPENDENT checks: run on every exchange, from the
        # very first one, regardless of how much history exists for
        # this host.
        anomalies.extend(self._detect_pattern_anomalies(exchange))
        anomalies.extend(self._detect_parameter_anomalies(exchange))
        anomalies.extend(self._detect_header_anomalies(exchange))
        anomalies.extend(self._detect_temporal_anomalies(exchange))

        # Baseline-DEPENDENT checks: genuinely need enough prior history
        # for this host to know what "normal" looks like.
        if host in self.profiles and self.profiles[host].exchange_count >= self.min_exchanges:
            profile = self.profiles[host]
            anomalies.extend(self._detect_statistical_anomalies(exchange, profile))
            anomalies.extend(self._detect_status_anomalies(exchange, profile))
            anomalies.extend(self._detect_content_type_anomalies(exchange, profile))

        # Store anomalies
        self.anomalies.extend(anomalies)

        return anomalies
    
    def _detect_statistical_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect statistical outliers."""
        anomalies = []
        
        # Response size anomaly (3+ standard deviations)
        response_size = len(exchange.response_body) if exchange.response_body else 0
        if profile.exchange_count > 1:
            if response_size > profile.avg_response_size * 3:
                anomalies.append(Anomaly(
                    anomaly_type="response_size_outlier",
                    severity="low",
                    confidence=0.7,
                    description="Response size is significantly larger than average",
                    evidence=f"Response size: {response_size}, Average: {profile.avg_response_size:.0f}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_body",
                    expected_value=profile.avg_response_size,
                    actual_value=response_size,
                    deviation_score=response_size / profile.avg_response_size if profile.avg_response_size > 0 else 0
                ))
            elif response_size < profile.avg_response_size * 0.1:
                anomalies.append(Anomaly(
                    anomaly_type="response_size_outlier",
                    severity="low",
                    confidence=0.6,
                    description="Response size is significantly smaller than average",
                    evidence=f"Response size: {response_size}, Average: {profile.avg_response_size:.0f}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_body",
                    expected_value=profile.avg_response_size,
                    actual_value=response_size,
                    deviation_score=profile.avg_response_size / response_size if response_size > 0 else 0
                ))
        
        # Parameter count anomaly
        params = self._extract_parameters(exchange)
        if profile.exchange_count > 1 and len(params) > profile.avg_param_count * 3:
            anomalies.append(Anomaly(
                anomaly_type="parameter_count_outlier",
                severity="low",
                confidence=0.6,
                description="Number of parameters is significantly higher than average",
                evidence=f"Parameter count: {len(params)}, Average: {profile.avg_param_count:.1f}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="parameters",
                expected_value=profile.avg_param_count,
                actual_value=len(params),
                deviation_score=len(params) / profile.avg_param_count if profile.avg_param_count > 0 else 0
            ))
        
        # URL depth anomaly
        url_depth = len([p for p in exchange.url.split('/') if p])
        if profile.exchange_count > 1 and url_depth > profile.url_depth_avg * 2:
            anomalies.append(Anomaly(
                anomaly_type="url_depth_outlier",
                severity="low",
                confidence=0.5,
                description="URL depth is significantly higher than average",
                evidence=f"URL depth: {url_depth}, Average: {profile.url_depth_avg:.1f}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="url",
                expected_value=profile.url_depth_avg,
                actual_value=url_depth,
                deviation_score=url_depth / profile.url_depth_avg if profile.url_depth_avg > 0 else 0
            ))
        
        return anomalies
    
    def _detect_pattern_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect suspicious patterns in request/response."""
        anomalies = []
        
        # Check request URL PATH + QUERY only -- NOT scheme/host/port, which is
        # the target you are testing, not attacker-controlled surface. Found
        # live: scanning the full URL flagged the harness's own target host
        # (e.g. http://127.0.0.1:5001) against the localhost/SSRF pattern on
        # EVERY exchange -- a systematic false positive. Path and query, where
        # real path-traversal / injection payloads live, are unchanged, so this
        # costs no recall.
        _split = _urlsplit(exchange.url)
        _url_scan = _split.path + (("?" + _split.query) if _split.query else "")
        anomalies.extend(self._check_patterns(
            _url_scan,
            "url",
            exchange,
            severity="high"
        ))
        
        # Check request headers
        for header_name, header_value in exchange.request_headers.items():
            anomalies.extend(self._check_patterns(
                header_value,
                f"request_header_{header_name}",
                exchange,
                severity="high"
            ))
        
        # Check request body
        if exchange.request_body:
            anomalies.extend(self._check_patterns(
                exchange.request_body,
                "request_body",
                exchange,
                severity="high"
            ))
        
        # Check response headers
        for header_name, header_value in exchange.response_headers.items():
            # Skip content-length and similar
            if header_name.lower() in ['content-length', 'date', 'cache-control']:
                continue
            anomalies.extend(self._check_patterns(
                header_value,
                f"response_header_{header_name}",
                exchange,
                severity="medium"
            ))
        
        # Check response body
        if exchange.response_body:
            anomalies.extend(self._check_patterns(
                exchange.response_body,
                "response_body",
                exchange,
                severity="medium"
            ))
        
        return anomalies
    
    def _check_patterns(self, text: str, field: str, exchange: HttpExchange, 
                        severity: str = "medium") -> list[Anomaly]:
        """Check text against suspicious patterns.

        Request fields (url, request_body, request headers) are scanned with the
        full attack-input pattern list. Response fields are scanned only with
        response_evidence_patterns -- attack-INPUT syntax is meaningless in a
        response and matching it there produced a false positive on nearly every
        benign exchange (see response_evidence_patterns' comment).
        """
        anomalies = []
        request_side = (field == "url" or field == "request_body"
                        or field.startswith("request_header"))
        patterns = self.suspicious_patterns if request_side else self.response_evidence_patterns

        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                # Calculate confidence based on pattern specificity
                confidence = 0.8 if any(c.isalpha() for c in pattern) else 0.6
                
                anomalies.append(Anomaly(
                    anomaly_type="suspicious_pattern",
                    severity=severity,
                    confidence=confidence,
                    description=f"Suspicious pattern detected: {pattern[:50]}",
                    evidence=f"Pattern '{pattern}' found in {field}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field=field,
                    expected_value="No suspicious patterns",
                    actual_value=f"Pattern: {pattern}",
                    deviation_score=1.0
                ))
        
        return anomalies
    
    def _detect_parameter_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in request parameters."""
        anomalies = []
        params = self._extract_parameters(exchange)
        
        # Check for sensitive parameter names -- but only for names in the URL
        # QUERY STRING or request BODY. Credentials belong in the
        # Authorization/Cookie (and similar) request HEADERS: that is the
        # correct transport, not a vulnerability. The real exposure this check
        # exists for is a sensitive name in the query/body (e.g. `?api_key=...`,
        # `?password=...`), where it gets logged, cached, and referer-leaked.
        # Found live via fp_benchmark.py: scanning header names too flagged the
        # normal `Authorization` header as a high-severity finding on every
        # authenticated request (TN3/TN5) -- a systematic false positive.
        request_side_names = self._query_and_body_param_names(exchange)
        for param_name, param_values in params.items():
            if param_name not in request_side_names:
                continue
            if any(sensitive in param_name.lower() for sensitive in self.sensitive_param_names):
                anomalies.append(Anomaly(
                    anomaly_type="sensitive_parameter",
                    severity="high",
                    confidence=0.9,
                    description=f"Sensitive parameter name detected: {param_name}",
                    evidence=f"Parameter '{param_name}' may contain sensitive data",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field=f"parameter_{param_name}",
                    expected_value="No sensitive parameter names",
                    actual_value=param_name,
                    deviation_score=1.0
                ))

        # Check for unusual parameter values
        for param_name, param_values in params.items():
            for param_value in param_values:
                if param_value:
                    # Check for long values (potential DoS)
                    if len(param_value) > 1000:
                        anomalies.append(Anomaly(
                            anomaly_type="long_parameter_value",
                            severity="medium",
                            confidence=0.7,
                            description=f"Unusually long parameter value: {param_name}",
                            evidence=f"Parameter '{param_name}' has value of length {len(param_value)}",
                            exchange_fingerprint=self._fingerprint(exchange),
                            affected_field=f"parameter_{param_name}",
                            expected_value="< 1000 characters",
                            actual_value=len(param_value),
                            deviation_score=len(param_value) / 1000
                        ))
                    
                    # Check for repeated characters (potential DoS)
                    if len(param_value) > 100:
                        char_counts = Counter(param_value)
                        max_count = max(char_counts.values()) if char_counts else 0
                        if max_count > len(param_value) * 0.9:
                            anomalies.append(Anomaly(
                                anomaly_type="repeated_characters",
                                severity="medium",
                                confidence=0.7,
                                description=f"Parameter value contains mostly repeated characters: {param_name}",
                                evidence=f"Parameter '{param_name}' has {max_count}/{len(param_value)} of one character",
                                exchange_fingerprint=self._fingerprint(exchange),
                                affected_field=f"parameter_{param_name}",
                                expected_value="Diverse characters",
                                actual_value=f"{max_count}/{len(param_value)} repeated",
                                deviation_score=max_count / len(param_value)
                            ))
        
        return anomalies
    
    def _detect_header_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in HTTP headers."""
        anomalies = []
        
        # Check for information disclosure in headers
        for header_name, header_value in exchange.response_headers.items():
            if header_name.lower() in self.suspicious_headers:
                anomalies.append(Anomaly(
                    # A version/technology banner (Server, X-Powered-By, ...) is
                    # a real but minor, universally-info-level disclosure -- and
                    # it fires on EVERY response from a given server. Kept as a
                    # low-confidence, info-severity note so it sits below the
                    # reporting gate instead of reading as a medium finding on
                    # every single exchange (found live via fp_benchmark.py).
                    anomaly_type="information_disclosure_header",
                    severity="info",
                    confidence=0.3,
                    description=f"Information disclosure in header: {header_name}",
                    evidence=f"Header '{header_name}': {header_value}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field=f"response_header_{header_name}",
                    expected_value="No version information",
                    actual_value=header_value,
                    deviation_score=1.0
                ))
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection', 
                           'content-security-policy', 'strict-transport-security', 'referrer-policy']
        for header in security_headers:
            if header not in exchange.response_headers:
                anomalies.append(Anomaly(
                    anomaly_type="missing_security_header",
                    severity="low",
                    confidence=0.5,
                    description=f"Missing security header: {header}",
                    evidence=f"Security header '{header}' is not present in response",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_headers",
                    expected_value=f"{header} present",
                    actual_value="Missing",
                    deviation_score=0.5
                ))
        
        return anomalies
    
    def _detect_status_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect anomalies in HTTP status codes."""
        anomalies = []
        
        if exchange.response_status is None:
            return anomalies
        
        status_str = str(exchange.response_status)
        
        # Check for unexpected status codes for method
        expected_statuses = self.unexpected_status_for_method.get(exchange.method.upper(), [])
        if status_str.startswith('5') and exchange.method.upper() == 'GET':
            anomalies.append(Anomaly(
                anomaly_type="unexpected_server_error",
                severity="medium",
                confidence=0.7,
                description=f"GET request returned server error: {exchange.response_status}",
                evidence=f"Method: {exchange.method}, Status: {exchange.response_status}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="response_status",
                expected_value="200 or 404",
                actual_value=exchange.response_status,
                deviation_score=1.0
            ))
        
        # Check for rare status codes
        total = sum(profile.common_status_codes.values())
        if total > 0:
            status_frequency = profile.common_status_codes.get(status_str, 0) / total
            if status_frequency < 0.01:  # Less than 1% of requests
                anomalies.append(Anomaly(
                    anomaly_type="rare_status_code",
                    severity="low",
                    confidence=0.6,
                    description=f"Rare status code: {exchange.response_status}",
                    evidence=f"Status code {exchange.response_status} appears in {status_frequency*100:.2f}% of requests",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_status",
                    expected_value="Common status code",
                    actual_value=exchange.response_status,
                    deviation_score=1.0 - status_frequency
                ))
        
        return anomalies
    
    def _detect_content_type_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect anomalies in content types."""
        anomalies = []
        
        if 'content-type' not in exchange.response_headers:
            return anomalies
        
        content_type = exchange.response_headers['content-type'].lower().split(';')[0]
        
        # Check for unexpected content types
        total = sum(profile.content_types.values())
        if total > 0:
            ct_frequency = profile.content_types.get(content_type, 0) / total
            if ct_frequency < 0.05:  # Less than 5% of requests
                anomalies.append(Anomaly(
                    anomaly_type="rare_content_type",
                    severity="low",
                    confidence=0.5,
                    description=f"Rare content type: {content_type}",
                    evidence=f"Content type {content_type} appears in {ct_frequency*100:.2f}% of responses",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="Common content type",
                    actual_value=content_type,
                    deviation_score=1.0 - ct_frequency
                ))
        
        # Check for plain text responses that look like JSON
        if content_type == 'text/plain' and exchange.response_body:
            try:
                json.loads(exchange.response_body)
                anomalies.append(Anomaly(
                    anomaly_type="json_as_plain_text",
                    severity="medium",
                    confidence=0.8,
                    description="JSON data returned with text/plain content type",
                    evidence=f"Response body appears to be JSON but content type is text/plain",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="application/json",
                    actual_value="text/plain",
                    deviation_score=1.0
                ))
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Check for HTML responses that look like JSON
        if 'html' in content_type and exchange.response_body:
            try:
                json.loads(exchange.response_body)
                anomalies.append(Anomaly(
                    anomaly_type="json_as_html",
                    severity="medium",
                    confidence=0.7,
                    description="JSON data returned with HTML content type",
                    evidence=f"Response body appears to be JSON but content type is {content_type}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="application/json",
                    actual_value=content_type,
                    deviation_score=1.0
                ))
            except (json.JSONDecodeError, ValueError):
                pass
        
        return anomalies
    
    def _detect_temporal_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect temporal anomalies (if we have timing data)."""
        anomalies = []
        
        # This would require timing data to be available
        # For now, we'll skip temporal detection
        # In a real implementation, we would compare response times
        # against the average for similar requests
        
        return anomalies
    
    def cluster_anomalies(self, anomalies: Optional[list[Anomaly]] = None) -> list[AnomalyCluster]:
        """Cluster similar anomalies to identify new vulnerability classes.

        Found live: generate_findings() used to call this with no
        argument, which defaulted to clustering over self.anomalies --
        the GLOBAL, ever-growing accumulator across the entire session
        for a host, not just the current exchange being analyzed. In
        this harness, analyze() processes one exchange at a time with
        no later step that ever reviews session-wide clusters, so that
        cross-exchange accumulation provided no real value while
        actively causing two confirmed problems: (1) a cluster reported
        against exchange N could silently include anomaly types
        contributed by an EARLIER, unrelated exchange, occasionally
        landing on a (type, field) combination the vulnerability-class
        mapping didn't cover and reporting a vague, low-information
        'unknown_anomaly'; (2) the same accumulating cluster got
        re-reported, with a growing count, on every subsequent exchange
        that contributed to it, rather than being scoped to the one
        exchange it's actually evidence for. Callers now pass the
        current exchange's own anomaly list explicitly; `self.anomalies`
        remains the default only for any other/future caller that
        genuinely wants the full session history.
        """
        if anomalies is None:
            anomalies = self.anomalies
        # Group anomalies by host
        by_host = defaultdict(list)
        for anomaly in anomalies:
            host = self._get_host_from_fingerprint(anomaly.exchange_fingerprint)
            by_host[host].append(anomaly)
        
        clusters = []
        
        for host, host_anomalies in by_host.items():
            # Group by anomaly type and affected field
            groups = defaultdict(list)
            for anomaly in host_anomalies:
                key = (anomaly.anomaly_type, anomaly.affected_field)
                groups[key].append(anomaly)
            
            # Create clusters from groups with multiple anomalies
            for (anomaly_type, affected_field), group_anomalies in groups.items():
                if len(group_anomalies) >= 3:  # At least 3 similar anomalies
                    # Calculate cluster properties
                    timestamps = []
                    for a in group_anomalies:
                        # In a real implementation, we'd have timestamps
                        # For now, we'll use the order in the list
                        pass
                    
                    # Suggest vulnerability class based on anomaly type
                    suggested_class = self._suggest_vulnerability_class(anomaly_type, affected_field)
                    
                    cluster = AnomalyCluster(
                        cluster_id=hashlib.sha256(f"{host}:{anomaly_type}:{affected_field}".encode()).hexdigest()[:16],
                        anomalies=group_anomalies,
                        suggested_vulnerability_class=suggested_class,
                        confidence=min(0.9, 0.5 + len(group_anomalies) * 0.1),
                        host=host
                    )
                    clusters.append(cluster)
        
        self.clusters = clusters
        return clusters
    
    def _suggest_vulnerability_class(self, anomaly_type: str, affected_field: str) -> str:
        """Suggest a vulnerability class based on anomaly type and field.

        Found live: every entry below except the three `suspicious_pattern`
        ones used `''` as a placeholder `affected_field`, which never
        equals a REAL anomaly's affected_field (always a genuine value
        like 'response_headers', 'parameters', 'url' -- see each
        _detect_*_anomalies method, none of which ever sets
        affected_field to an empty string). That meant every one of
        those mappings was permanently unreachable: a real
        missing_security_header cluster (affected_field=
        'response_headers') always fell through to 'unknown_anomaly'
        instead of the correctly-mapped 'security_misconfiguration'.
        Fixed with a two-tier lookup: try the exact (type, field) match
        first (still needed for suspicious_pattern, whose real
        vulnerability class genuinely depends on WHERE the pattern
        matched -- a `../` in the URL is path traversal, the same
        pattern in a response body is information disclosure), then
        fall back to (type, '') as a field-agnostic default for
        anomaly types where the field doesn't change the classification.
        """
        mappings = {
            ('suspicious_pattern', 'url'): 'path_traversal',
            ('suspicious_pattern', 'request_body'): 'injection',
            ('suspicious_pattern', 'response_body'): 'information_disclosure',
            ('sensitive_parameter', ''): 'sensitive_data_exposure',
            ('long_parameter_value', ''): 'denial_of_service',
            ('repeated_characters', ''): 'denial_of_service',
            ('information_disclosure_header', ''): 'information_disclosure',
            ('missing_security_header', ''): 'security_misconfiguration',
            ('unexpected_server_error', ''): 'server_error',
            ('rare_status_code', ''): 'unusual_behavior',
            ('rare_content_type', ''): 'content_type_mismatch',
            ('json_as_plain_text', ''): 'content_type_mismatch',
            ('json_as_html', ''): 'content_type_mismatch',
            ('response_size_outlier', ''): 'information_disclosure',
            ('parameter_count_outlier', ''): 'unusual_behavior',
            ('url_depth_outlier', ''): 'unusual_behavior',
        }

        if (anomaly_type, affected_field) in mappings:
            return mappings[(anomaly_type, affected_field)]
        return mappings.get((anomaly_type, ''), 'unknown_anomaly')
    
    def generate_findings(self, anomalies: list[Anomaly]) -> list[Finding]:
        """Convert anomalies to Finding objects.

        Found live, on the very first real exchange this fix was tested
        against: a path-traversal URL ALSO happened to be missing 3+
        security headers (extremely common -- most responses are).
        `clustered_anomalies` used to track `exchange_fingerprint`, which
        is the SAME value for every anomaly from a single exchange
        regardless of type. The instant ANY anomaly type from that
        exchange clustered (here: 6 missing_security_header anomalies),
        every OTHER anomaly from the same exchange -- including the
        completely unrelated, specific, high-value suspicious_pattern
        (path traversal) one -- got silently treated as "already
        reported" and dropped, even though it was never actually part of
        that cluster. The only finding that survived was the generic
        cluster summary ("Multiple anomalies detected: unknown_anomaly"),
        losing the one piece of evidence that actually mattered. Fixed
        by tracking clustered anomalies by object identity (Anomaly is a
        non-frozen dataclass, so not natively hashable/set-safe) instead
        of by exchange fingerprint.
        """
        findings = []

        # Cluster anomalies first -- scoped to just the anomalies passed
        # in (this exchange's own), not the global session accumulator.
        # See cluster_anomalies()'s own docstring for why.
        clusters = self.cluster_anomalies(anomalies)

        # Group anomalies by cluster
        clustered_anomaly_ids = set()
        for cluster in clusters:
            if len(cluster.anomalies) >= 3:
                # A cluster's severity is capped at its strongest MEMBER's
                # severity. Clustering many low-severity observations (e.g. 6
                # missing security headers -- true of almost every response)
                # does not create a high-severity vulnerability; a real
                # multi-signal attack (whose members are themselves high) still
                # clusters to high. Without this cap the count-based confidence
                # (min(0.9, 0.5 + n*0.1)) alone pushed every 4+-item cluster to
                # "high" -- a high-severity false positive on every benign
                # exchange (found live via fp_benchmark.py).
                _sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                _sev_name = ["info", "low", "medium", "high", "critical"]
                _member_max = max((_sev_rank.get(a.severity, 2) for a in cluster.anomalies), default=2)
                _proposed = 3 if cluster.confidence > 0.8 else 2
                _cluster_severity = _sev_name[min(_proposed, _member_max)]
                # Create a finding for the cluster
                findings.append(Finding(
                    vulnerability_class=cluster.suggested_vulnerability_class,
                    severity=_cluster_severity,
                    confidence=cluster.confidence,
                    summary=f"Multiple anomalies detected: {cluster.suggested_vulnerability_class}",
                    evidence=f"Cluster of {len(cluster.anomalies)} similar anomalies on {cluster.host}",
                    suggested_test=f"Investigate {cluster.suggested_vulnerability_class} on {cluster.host}",
                    basis="derived",
                    validation_hints=[]
                ))
                clustered_anomaly_ids.update(id(a) for a in cluster.anomalies)

        # Create findings for unclustered anomalies
        for anomaly in anomalies:
            if id(anomaly) not in clustered_anomaly_ids:
                findings.append(Finding(
                    vulnerability_class=anomaly.anomaly_type,
                    severity=anomaly.severity,
                    confidence=anomaly.confidence,
                    summary=anomaly.description,
                    evidence=anomaly.evidence,
                    suggested_test=f"Investigate {anomaly.anomaly_type} in {anomaly.affected_field}",
                    basis="derived",
                    validation_hints=[]
                ))
        
        return findings
    
    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0] or "unknown"
        except Exception:
            return "unknown"
    
    def _get_host_from_fingerprint(self, fingerprint: str) -> str:
        """Extract host from exchange fingerprint."""
        # Fingerprint contains URL, so we can extract host from it
        # This is a simplified approach
        for exchange in self.exchange_history:
            if self._fingerprint(exchange) == fingerprint:
                return self._get_host(exchange.url)
        return "unknown"
    
    def _query_and_body_param_names(self, exchange: HttpExchange) -> set[str]:
        """Parameter names present in the URL query string or (form) request
        body -- i.e. NOT request headers. A credential in a header is correct
        transport; a credential here is the actual exposure the sensitive-name
        check exists to catch."""
        names: set[str] = set()
        try:
            names.update(parse_qs(urlparse(exchange.url).query).keys())
        except Exception:
            pass
        if exchange.request_body and 'application/x-www-form-urlencoded' in exchange.request_headers.get('content-type', ''):
            try:
                names.update(parse_qs(exchange.request_body).keys())
            except Exception:
                pass
        return names

    def _extract_parameters(self, exchange: HttpExchange) -> dict[str, list[str]]:
        """Extract all parameters from an exchange."""
        params = defaultdict(list)
        
        # URL query parameters
        try:
            parsed = urlparse(exchange.url)
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                params[param].extend(values)
        except Exception:
            pass
        
        # Request body parameters (for form data)
        if exchange.request_body:
            try:
                if 'application/x-www-form-urlencoded' in exchange.request_headers.get('content-type', ''):
                    body_params = parse_qs(exchange.request_body)
                    for param, values in body_params.items():
                        params[param].extend(values)
            except Exception:
                pass
        
        # Request header parameters
        for header, value in exchange.request_headers.items():
            params[header].append(value)
        
        return dict(params)
    
    def _fingerprint(self, exchange: HttpExchange) -> str:
        """Create a fingerprint for an exchange."""
        material = f"{exchange.method}:{exchange.url}".encode()
        return hashlib.sha256(material).hexdigest()[:16]


# Global detector instance for convenience
detector = AnomalyDetector()
