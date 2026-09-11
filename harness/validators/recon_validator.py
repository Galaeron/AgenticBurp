"""
Recon Validator for Attack Surface Mapping

This validator performs active reconnaissance to build comprehensive
attack maps of the target application.
"""

from __future__ import annotations
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

import security
from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from models import Finding, HttpExchange

log = logging.getLogger("harness.validators.recon")


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""
    url: str
    methods: set[str] = field(default_factory=set)
    status_codes: set[int] = field(default_factory=set)
    parameters: dict[str, list[str]] = field(default_factory=dict)  # param -> locations
    headers: dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    response_type: str = ""
    links: list[str] = field(default_factory=list)
    sensitive: bool = False


@dataclass
class ParameterInfo:
    """Information about a discovered parameter."""
    name: str
    type_hint: str = ""
    locations: set[str] = field(default_factory=set)  # query, header, body, cookie
    endpoints: set[str] = field(default_factory=set)
    sensitive: bool = False
    format_hint: str = ""


@dataclass
class TechnologyInfo:
    """Information about detected technologies."""
    category: str  # web_server, app_server, framework, database, etc.
    name: str
    version: str = ""
    confidence: float = 0.0
    cves: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """A potential attack path through the application."""
    path: list[str]  # Sequence of endpoints
    type: str  # privilege_escalation, data_exfiltration, rce, etc.
    prerequisites: list[str] = field(default_factory=list)
    potential_impact: str = ""


@dataclass
class ReconResult:
    """Complete recon result."""
    endpoints: dict[str, EndpointInfo] = field(default_factory=dict)
    parameters: dict[str, ParameterInfo] = field(default_factory=dict)
    technologies: list[TechnologyInfo] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    priorities: list[tuple[str, str, str]] = field(default_factory=list)  # (endpoint, priority, reason)
    coverage: float = 0.0  # Percentage of attack surface covered


class ReconValidator(Validator):
    """
    Validator for reconnaissance and attack surface mapping.
    
    Performs active recon to build comprehensive attack maps.
    """
    
    name = "recon_validator"
    finding_classes = {"recon", "reconnaissance", "attack surface mapping", "attack map"}
    active = True
    
    def __init__(self, timeout: float = 15.0, max_redirects: int = 10,
                 max_depth: int = 5, run_context=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_depth = max_depth  # Crawl depth
        self.run_context = run_context
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.client: httpx.AsyncClient | None = None
        self.visited_urls: set[str] = set()
        self.discovered_urls: set[str] = set()
    
    async def __aenter__(self):
        if self.run_context is None:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                max_redirects=self.max_redirects,
            )
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    def get_name(self) -> str:
        return self.name
    
    def get_capability(self) -> str:
        return "attack_surface_mapping"
    
    def get_execution_plane(self) -> str:
        return "local_tool"
    
    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        """Generate a test plan for recon validation."""
        from models import TestPlan
        from categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"recon_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            mutation={"max_depth": str(self.max_depth), "timeout": str(self.timeout)},
            rationale=f"Attack surface mapping for {exchange.url}",
            success_signals=["Comprehensive attack map including endpoints, parameters, technologies, and attack paths"],
            source_exchange_hash=exchange_hash,
        )
    
    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        """
        Validate a recon finding by performing active reconnaissance.
        
        Builds a comprehensive attack map of the target application.
        """
        try:
            # Initialize
            base_url = self._get_base_url(exchange.url)
            if not base_url:
                return ValidationResult(
                    validator=self.name,
                    status="error",
                    finding_class=finding.vulnerability_class,
                    confidence=0.0,
                    confirmed=False,
                    summary=f"Could not determine base URL from {exchange.url}",
                    evidence="",
                    raw_output="",
                )
            
            # Perform recon
            recon_result = await self._perform_recon(base_url, exchange)
            
            # Build summary
            summary_parts = [
                f"Discovered {len(recon_result.endpoints)} endpoints",
                f"Identified {len(recon_result.parameters)} parameters",
                f"Detected {len(recon_result.technologies)} technologies",
                f"Mapped {len(recon_result.attack_paths)} attack paths",
                f"Coverage: {recon_result.coverage:.1%}",
            ]
            
            # Check for sensitive findings
            sensitive_endpoints = [e for e, info in recon_result.endpoints.items() if info.sensitive]
            sensitive_params = [p for p, info in recon_result.parameters.items() if info.sensitive]
            
            if sensitive_endpoints or sensitive_params:
                summary_parts.append(f"Found {len(sensitive_endpoints)} sensitive endpoints, {len(sensitive_params)} sensitive parameters")
            
            return ValidationResult(
                validator=self.name,
                status="confirmed",
                finding_class=finding.vulnerability_class,
                confidence=0.95,
                confirmed=True,
                summary=" | ".join(summary_parts),
                evidence=self._build_evidence(recon_result),
                raw_output=self._build_raw_output(recon_result),
            )
            
        except Exception as e:
            log.error(f"Recon validation error: {e}")
            import traceback
            return ValidationResult(
                validator=self.name,
                status="error",
                finding_class=finding.vulnerability_class,
                confidence=0.0,
                confirmed=False,
                summary=f"Recon validation failed: {e}",
                evidence="",
                raw_output=traceback.format_exc(),
            )
    
    def _get_base_url(self, url: str) -> str:
        """Extract base URL from a full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _perform_recon(self, base_url: str, exchange: HttpExchange) -> ReconResult:
        """Perform comprehensive reconnaissance."""
        result = ReconResult()
        
        # Clear state
        self.visited_urls = set()
        self.discovered_urls = set()
        
        # Start with the exchange URL
        start_url = exchange.url
        
        # Phase 1: Passive recon from the exchange
        self._analyze_exchange(exchange, result)
        
        # Phase 2: Active recon - crawl from the starting point
        await self._crawl(base_url, start_url, depth=0, max_depth=self.max_depth, result=result)
        
        # Phase 3: Check for common discovery files
        await self._check_common_files(base_url, result)
        
        # Phase 4: Technology fingerprinting
        await self._fingerprint_technologies(base_url, result)
        
        # Phase 5: Build attack paths
        self._build_attack_paths(result)
        
        # Phase 6: Prioritize endpoints
        self._prioritize_endpoints(result)
        
        # Calculate coverage
        result.coverage = self._calculate_coverage(result)
        
        return result
    
    def _analyze_exchange(self, exchange: HttpExchange, result: ReconResult):
        """Analyze an HTTP exchange for recon data."""
        url = exchange.url
        
        # Add endpoint
        if url not in result.endpoints:
            result.endpoints[url] = EndpointInfo(url=url)
        
        endpoint = result.endpoints[url]
        endpoint.methods.add(exchange.method)
        endpoint.status_codes.add(exchange.response_status)
        
        # Extract parameters from URL
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    endpoint.parameters[name] = endpoint.parameters.get(name, []) + ['query']
                    self._add_parameter(result, name, 'query', url)
        
        # Extract parameters from request body (simple parsing)
        if exchange.request_body:
            self._extract_body_parameters(exchange.request_body, endpoint, result, url)
        
        # Extract headers. Sensitive header VALUES (Authorization,
        # Cookie, etc.) are redacted at collection time via the same
        # security.redact_headers() used everywhere else in this project
        # that handles headers -- not because a leak was ever found
        # downstream (the audit that flagged this traced every consumer
        # of endpoint.headers and confirmed none of them serialize it
        # into a Finding/ValidationResult field), but because redacting
        # here means it's structurally impossible for a *future* change
        # (e.g. a new debug-dump feature, a raw_output field that starts
        # including more detail) to accidentally leak a credential this
        # validator was never supposed to need in the first place. The
        # header NAME (needed for endpoint.auth_required/sensitive
        # classification below) is preserved; only the value is redacted.
        redacted_request_headers = security.redact_headers(exchange.request_headers)
        for header, value in redacted_request_headers.items():
            endpoint.headers[header.lower()] = value
            # Check for sensitive headers
            if header.lower() in ['authorization', 'cookie', 'x-api-key', 'x-auth-token']:
                endpoint.auth_required = True
                endpoint.sensitive = True
        
        # Analyze response headers for technology clues. Values are
        # scanned for tech fingerprints (server banners, framework
        # versions) using the REAL value -- fingerprinting doesn't need
        # or want a redacted Set-Cookie value, and tech-fingerprint
        # values are never sensitive. What gets STORED into
        # endpoint.headers, however, uses the redacted value -- same
        # reasoning as the request-header redaction above.
        redacted_response_headers = security.redact_headers(exchange.response_headers)
        for header, value in exchange.response_headers.items():
            endpoint.headers[f"response_{header.lower()}"] = redacted_response_headers.get(header, value)
            self._analyze_header_for_tech(header, value, result)
        
        # Determine response type
        content_type = exchange.response_headers.get('Content-Type', '').lower()
        if content_type:
            if 'json' in content_type:
                endpoint.response_type = 'json'
            elif 'html' in content_type:
                endpoint.response_type = 'html'
            elif 'xml' in content_type:
                endpoint.response_type = 'xml'
        
        # Extract links from response (if HTML or JSON)
        self._extract_links(exchange.response_body, url, result)
    
    def _extract_body_parameters(self, body: str, endpoint: EndpointInfo, result: ReconResult, url: str):
        """Extract parameters from request body."""
        # Try JSON
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict):
                for key in data.keys():
                    endpoint.parameters[key] = endpoint.parameters.get(key, []) + ['body']
                    self._add_parameter(result, key, 'body', url)
            return
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Try form data (URL-encoded)
        if '&' in body:
            for param in body.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    endpoint.parameters[name] = endpoint.parameters.get(name, []) + ['body']
                    self._add_parameter(result, name, 'body', url)
    
    def _add_parameter(self, result: ReconResult, name: str, location: str, url: str):
        """Add a parameter to the recon result."""
        if name not in result.parameters:
            result.parameters[name] = ParameterInfo(name=name)
        
        param = result.parameters[name]
        param.locations.add(location)
        param.endpoints.add(url)
        
        # Classify sensitivity
        sensitive_keywords = ['token', 'password', 'secret', 'key', 'auth', 'session', 'cookie', 'jwt', 'bearer']
        if any(kw in name.lower() for kw in sensitive_keywords):
            param.sensitive = True
        
        # Try to infer type
        if name.lower() in ['id', 'user_id', 'account_id', 'order_id']:
            param.type_hint = 'integer'
            param.format_hint = 'numeric'
        elif name.lower() in ['email', 'username', 'name']:
            param.type_hint = 'string'
        elif name.lower() in ['active', 'enabled', 'admin']:
            param.type_hint = 'boolean'
    
    def _analyze_header_for_tech(self, header: str, value: str, result: ReconResult):
        """Analyze a response header for technology clues."""
        header_lower = header.lower()
        
        if header_lower == 'server':
            self._add_technology(result, 'web_server', value)
        elif header_lower == 'x-powered-by':
            self._add_technology(result, 'framework', value)
        elif header_lower == 'x-aspnet-version':
            self._add_technology(result, 'app_server', f"ASP.NET {value}")
        elif header_lower == 'x-generator':
            self._add_technology(result, 'framework', value)
        elif header_lower == 'via':
            self._add_technology(result, 'proxy', value)
    
    def _add_technology(self, result: ReconResult, category: str, name: str):
        """Add a detected technology."""
        # Check if already added
        for tech in result.technologies:
            if tech.category == category and tech.name == name:
                return
        
        # Parse version if present
        version = ""
        name_lower = name.lower()
        
        # Common patterns for version extraction
        patterns = [
            (r'([\w\-]+)/([\d\.]+)', 2),  # Name/Version
            (r'([\w\-]+) ([\d\.]+)', 2),  # Name Version
        ]
        
        for pattern, group in patterns:
            match = re.search(pattern, name)
            if match:
                name = match.group(1)
                version = match.group(group)
                break
        
        # Determine confidence
        confidence = 0.9 if version else 0.7
        
        result.technologies.append(TechnologyInfo(
            category=category,
            name=name,
            version=version,
            confidence=confidence,
        ))
    
    async def _crawl(self, base_url: str, url: str, depth: int, max_depth: int, result: ReconResult):
        """Crawl the application starting from a URL."""
        if depth > max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            response = await self._send_request(url, method='GET')
            if response is None:
                return
            
            # Analyze the response
            await self._analyze_response(base_url, url, response, result)
            
            # Extract and follow links if HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'html' in content_type:
                links = self._extract_links_from_html(response.text, url)
                for link in links:
                    if link not in self.visited_urls and link not in self.discovered_urls:
                        self.discovered_urls.add(link)
                        await self._crawl(base_url, link, depth + 1, max_depth, result)
            
        except Exception as e:
            log.debug(f"Error crawling {url}: {e}")
    
    async def _send_request(self, url: str, method: str = 'GET', headers: dict = None) -> httpx.Response | None:
        """Send an HTTP request."""
        headers = headers or {}
        headers['User-Agent'] = self.user_agent
        
        try:
            if self.run_context is not None:
                from run_context import TypedRequest
                outcome = await self.run_context.executor().execute(
                    TypedRequest(method, url, headers=headers),
                    capability=self.get_name(), max_redirects=self.max_redirects)
                if not outcome.ok:
                    return None
                return httpx.Response(
                    outcome.status or 0, content=(outcome.body or "").encode(),
                    headers=outcome.headers, request=httpx.Request(method, url))
            if not self.client:
                self.client = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,
                    max_redirects=self.max_redirects,
                )
            
            import global_throttle
            await global_throttle.acquire()
            response = await self.client.request(method, url, headers=headers)
            return response
        except Exception as e:
            log.debug(f"Request to {url} failed: {e}")
            return None
    
    async def _analyze_response(self, base_url: str, url: str, response: httpx.Response, result: ReconResult):
        """Analyze a response for recon data."""
        # Add endpoint
        if url not in result.endpoints:
            result.endpoints[url] = EndpointInfo(url=url)
        
        endpoint = result.endpoints[url]
        endpoint.methods.add('GET')
        endpoint.status_codes.add(response.status_code)
        
        # Store headers. Values redacted at storage time (same
        # discipline as the other header-collection sites in this file)
        # -- a live crawl response's Set-Cookie is exactly the kind of
        # value that shouldn't sit in memory longer than needed.
        redacted_headers = security.redact_headers(dict(response.headers))
        for header, value in response.headers.items():
            endpoint.headers[header.lower()] = redacted_headers.get(header, value)
        
        # Analyze headers for tech (uses the REAL value -- fingerprinting
        # needs it, and fingerprint values are never sensitive)
        for header, value in response.headers.items():
            self._analyze_header_for_tech(header, value, result)
        
        # Determine response type
        content_type = response.headers.get('Content-Type', '').lower()
        if content_type:
            if 'json' in content_type:
                endpoint.response_type = 'json'
            elif 'html' in content_type:
                endpoint.response_type = 'html'
            elif 'xml' in content_type:
                endpoint.response_type = 'xml'
        
        # Check for sensitive content
        if response.status_code in [401, 403]:
            endpoint.auth_required = True
        
        # Extract parameters from URL
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    endpoint.parameters[name] = endpoint.parameters.get(name, []) + ['query']
                    self._add_parameter(result, name, 'query', url)
    
    def _extract_links_from_html(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML content."""
        links = []
        
        # Simple regex for href and src attributes
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                # Resolve relative URLs
                if not url.startswith(('http://', 'https://', 'javascript:', 'mailto:', '#')):
                    full_url = urljoin(base_url, url)
                    links.append(full_url)
        
        return list(set(links))  # Deduplicate
    
    def _extract_links(self, body: str, base_url: str, result: ReconResult):
        """Extract links from response body."""
        # Try JSON
        try:
            import json
            data = json.loads(body)
            self._extract_links_from_json(data, base_url, result)
            return
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Try HTML
        if '<html' in body.lower() or '<a ' in body.lower():
            links = self._extract_links_from_html(body, base_url)
            for link in links:
                if link not in result.endpoints:
                    result.endpoints[link] = EndpointInfo(url=link)
                    # Mark as discovered but not visited
                    if link not in self.visited_urls:
                        self.discovered_urls.add(link)
    
    def _extract_links_from_json(self, data: Any, base_url: str, result: ReconResult):
        """Extract links from JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                # Check for URL-like values
                if isinstance(value, str) and (value.startswith('/') or '://' in value):
                    if not value.startswith(('http://', 'https://')):
                        full_url = urljoin(base_url, value)
                    else:
                        full_url = value
                    
                    if full_url not in result.endpoints:
                        result.endpoints[full_url] = EndpointInfo(url=full_url)
                        self.discovered_urls.add(full_url)
                
                # Recurse
                self._extract_links_from_json(value, base_url, result)
        elif isinstance(data, list):
            for item in data:
                self._extract_links_from_json(item, base_url, result)
    
    async def _check_common_files(self, base_url: str, result: ReconResult):
        """Check for common discovery files."""
        common_files = [
            'robots.txt',
            'sitemap.xml',
            '.git/HEAD',
            '.env',
            'README.md',
            'CHANGELOG.md',
            'package.json',
            'pom.xml',
            'build.gradle',
            'composer.json',
            'requirements.txt',
            'Dockerfile',
            '.dockerignore',
            '.gitignore',
        ]
        
        api_docs = [
            'api',
            'api/',
            'swagger',
            'swagger/',
            'swagger-ui',
            'swagger-ui/',
            'openapi',
            'openapi/',
            'redoc',
            'redoc/',
            'api-docs',
            'api-docs/',
            'docs',
            'docs/',
        ]
        
        admin_paths = [
            'admin',
            'admin/',
            'administrator',
            'administrator/',
            'wp-admin',
            'wp-admin/',
            'manager',
            'manager/',
            'console',
            'console/',
            'login',
            'login/',
            'auth',
            'auth/',
        ]
        
        all_checks = common_files + api_docs + admin_paths
        
        for path in all_checks:
            url = urljoin(base_url, path)
            if url in self.visited_urls:
                continue
            
            response = await self._send_request(url, method='GET')
            if response and response.status_code == 200:
                # Add to endpoints
                if url not in result.endpoints:
                    result.endpoints[url] = EndpointInfo(url=url)
                
                endpoint = result.endpoints[url]
                endpoint.methods.add('GET')
                endpoint.status_codes.add(200)
                
                # Analyze the response. Same request/response header
                # redaction-at-storage discipline as _analyze_exchange
                # above -- this is a live probe response, not the
                # passively captured exchange, but the same "don't
                # retain a raw credential value longer than needed"
                # reasoning applies equally to it.
                redacted_headers = security.redact_headers(dict(response.headers))
                for header, value in response.headers.items():
                    endpoint.headers[header.lower()] = redacted_headers.get(header, value)
                    self._analyze_header_for_tech(header, value, result)
                
                # Extract links
                self._extract_links(response.text, url, result)
                
                # Mark as visited
                self.visited_urls.add(url)
    
    async def _fingerprint_technologies(self, base_url: str, result: ReconResult):
        """Perform technology fingerprinting."""
        # Check for common framework-specific files
        framework_files = {
            'django': ['/static/admin/css/base.css', '/static/admin/js/base.js'],
            'flask': ['/static/style.css'],
            'laravel': ['/vendor/composer/installed.json', '/laravel.js'],
            'rails': ['/assets/application.js', '/packs/js/application.js'],
            'spring': ['/WEB-INF/web.xml', '/resources/static/js/main.js'],
            'express': ['/js/main.js', '/styles/main.css'],
            'php': ['/index.php', '/wp-login.php'],
            'wordpress': ['/wp-includes/js/jquery/jquery.js', '/wp-content/themes/'],
            'joomla': ['/administrator/manifests/files/joomla.xml'],
            'drupal': ['/core/assets/vendor/jquery.once/jquery.once.js'],
        }
        
        for tech, files in framework_files.items():
            for file_path in files:
                url = urljoin(base_url, file_path.lstrip('/'))
                if url in self.visited_urls:
                    continue
                
                response = await self._send_request(url, method='GET')
                if response and response.status_code == 200:
                    # Found a framework file
                    self._add_technology(result, 'framework', tech)
                    break
    
    def _build_attack_paths(self, result: ReconResult):
        """Build potential attack paths."""
        # Simple path building based on endpoint relationships
        
        # Group endpoints by path segments
        endpoints_by_path = {}
        for url, endpoint in result.endpoints.items():
            parsed = urlparse(url)
            path = parsed.path
            segments = [s for s in path.split('/') if s]
            
            if segments:
                if segments[0] not in endpoints_by_path:
                    endpoints_by_path[segments[0]] = []
                endpoints_by_path[segments[0]].append(url)
        
        # Build paths from common entry points
        entry_points = ['', '/', '/api', '/admin', '/login', '/auth']
        
        for entry in entry_points:
            # Find endpoints that might be accessible after authentication
            auth_endpoints = [
                url for url, ep in result.endpoints.items()
                if ep.auth_required and any(
                    seg in urlparse(url).path.split('/')
                    for seg in ['admin', 'user', 'account', 'api']
                )
            ]
            
            if auth_endpoints:
                for auth_ep in auth_endpoints:
                    # Build path: entry -> auth -> admin
                    result.attack_paths.append(AttackPath(
                        path=[entry, '/login', auth_ep],
                        type='privilege_escalation',
                        prerequisites=['valid_credentials', 'auth_bypass'],
                        potential_impact='high',
                    ))
        
        # Add generic attack paths
        if '/api' in endpoints_by_path:
            result.attack_paths.append(AttackPath(
                path=['/', '/api', '/api/users', '/api/admin'],
                type='api_abuse',
                prerequisites=['api_access'],
                potential_impact='high',
            ))
    
    def _prioritize_endpoints(self, result: ReconResult):
        """Prioritize endpoints based on sensitivity and value."""
        # Define priority rules
        priority_rules = [
            (['admin', 'administrator', 'manager'], 'critical', 'admin_access'),
            (['login', 'auth', 'signin', 'signup'], 'critical', 'auth_endpoint'),
            (['api', 'rest', 'graphql'], 'high', 'api_endpoint'),
            (['user', 'account', 'profile'], 'high', 'user_data'),
            (['payment', 'billing', 'checkout'], 'critical', 'financial_data'),
            (['config', 'settings', 'preferences'], 'high', 'configuration'),
            (['file', 'upload', 'download'], 'medium', 'file_handling'),
            (['search', 'query'], 'low', 'search_functionality'),
        ]
        
        for url, endpoint in result.endpoints.items():
            path = urlparse(url).path.lower()
            
            for patterns, priority, reason in priority_rules:
                if any(p in path for p in patterns):
                    result.priorities.append((url, priority, reason))
                    break
            else:
                # Default priority
                result.priorities.append((url, 'low', 'standard_endpoint'))
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        result.priorities.sort(key=lambda x: priority_order.get(x[1], 3))
    
    def _calculate_coverage(self, result: ReconResult) -> float:
        """Calculate coverage percentage."""
        if not result.endpoints:
            return 0.0
        
        visited = len([url for url in result.endpoints.keys() if url in self.visited_urls])
        total = len(result.endpoints)
        
        return visited / total if total > 0 else 0.0
    
    def _build_evidence(self, result: ReconResult) -> str:
        """Build evidence string."""
        parts = []
        
        if result.endpoints:
            parts.append(f"{len(result.endpoints)} endpoints")
        if result.parameters:
            parts.append(f"{len(result.parameters)} parameters")
        if result.technologies:
            tech_names = [t.name for t in result.technologies]
            parts.append(f"Technologies: {', '.join(tech_names)}")
        if result.attack_paths:
            parts.append(f"{len(result.attack_paths)} attack paths")
        
        return " | ".join(parts)
    
    def _build_raw_output(self, result: ReconResult) -> str:
        """Build raw output."""
        import json
        
        output = {
            'endpoints': {url: {
                'methods': list(ep.methods),
                'status_codes': list(ep.status_codes),
                'parameters': ep.parameters,
                'sensitive': ep.sensitive,
                'auth_required': ep.auth_required,
                'response_type': ep.response_type,
            } for url, ep in result.endpoints.items()},
            'parameters': {name: {
                'type_hint': p.type_hint,
                'locations': list(p.locations),
                'sensitive': p.sensitive,
            } for name, p in result.parameters.items()},
            'technologies': [{
                'category': t.category,
                'name': t.name,
                'version': t.version,
                'confidence': t.confidence,
            } for t in result.technologies],
            'attack_paths': [{
                'path': p.path,
                'type': p.type,
                'prerequisites': p.prerequisites,
                'potential_impact': p.potential_impact,
            } for p in result.attack_paths],
            'priorities': [{'url': p[0], 'priority': p[1], 'reason': p[2]} for p in result.priorities],
            'coverage': result.coverage,
        }
        
        return json.dumps(output, indent=2)
