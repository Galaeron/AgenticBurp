"""
WebSocket Security Validator

Active validator: performs a real WebSocket handshake (raw HTTP
Upgrade request over a socket -- no external WebSocket library needed
for just the handshake) using a deliberately wrong, attacker-looking
Origin header, and checks whether the server completes the upgrade
(101 Switching Protocols) anyway. A server that authenticates
WebSocket connections purely by cookie and doesn't check Origin will
upgrade regardless of what Origin was sent -- that's a real,
independently-obtained confirmation of Cross-Site WebSocket Hijacking
exposure, not a rephrasing of what the agent already inferred from
the handshake headers alone.

This validator only handles the CSWSH/Origin-validation check.
Message-level findings (injection via message content, missing
per-message authorization) stay agent-only, since confirming those
needs a live, stateful WebSocket session this harness doesn't hold.
"""

from __future__ import annotations
import base64
import logging
import os
import socket
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

log = logging.getLogger("harness.validators.websocket")

_SPOOFED_ORIGIN = "https://attacker-controlled-cswsh-probe.example"


@dataclass
class WebsocketTestResult:
    test_name: str
    passed: bool
    severity: str
    detail: str
    evidence: str
    vulnerable: bool = False
    checked: bool = True

    def to_dict(self) -> dict:
        return {
            "test": self.test_name, "passed": self.passed, "severity": self.severity,
            "detail": self.detail, "evidence": self.evidence,
            "vulnerable": self.vulnerable, "checked": self.checked,
        }


class WebsocketValidator(Validator):
    """Validator for Cross-Site WebSocket Hijacking (CSWSH) exposure."""

    name = "websocket_validator"
    finding_classes = {"websocket", "websockets", "cswsh", "cross-site websocket hijacking",
                        "cross site websocket hijacking"}
    active = True

    def __init__(self, timeout: float = 10.0, max_redirects: int = 0,
                 run_context=None):
        self.timeout = timeout
        self.run_context = run_context

    def get_name(self) -> str:
        return "websocket_validator"

    def get_capability(self) -> str:
        return "websocket_cswsh_validation"

    def get_execution_plane(self) -> str:
        return "local_tool"

    def plan(self, finding: Finding, exchange: HttpExchange) -> Any:
        from harness.models import TestPlan
        from harness.categories import canonicalize
        import hashlib
        import json

        # Plan ID must incorporate the FULL exchange, not just the URL --
        # see cors_validator.py's plan() for the real, live-reproduced
        # collision this fixes (two different real requests to the same
        # URL producing the same plan_id and clobbering each other).
        exchange_hash = hashlib.sha256(
            json.dumps(exchange.model_dump(), sort_keys=True).encode()
        ).hexdigest()[:16]
        plan_id = f"ws_test_{finding.vulnerability_class}_{exchange_hash}"

        return TestPlan(
            id=plan_id,
            capability=self.get_capability(),
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class),
            source_exchange_url=exchange.url,
            execution_plane=self.get_execution_plane(),
            rationale=f"WebSocket CSWSH validation for {finding.vulnerability_class}",
            success_signals=["Confirm the server upgrades a WebSocket connection despite a spoofed Origin"],
            source_exchange_hash=exchange_hash,
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> Any:
        try:
            ws_url = self._to_ws_url(exchange.url)
            if ws_url is None:
                return ValidationResult(
                    validator=self.get_name(), status="skipped",
                    finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                    summary="This exchange's URL scheme isn't http(s)/ws(s) -- nothing to probe",
                    evidence="", raw_output="[]",
                )

            cookie_header = (exchange.request_headers or {}).get("Cookie") or \
                             (exchange.request_headers or {}).get("cookie")

            result = self._attempt_handshake(ws_url, cookie_header)
            tests = [result]

            summary = (result.detail if result.checked else
                       "Could not complete a handshake attempt (see detail) -- inconclusive")
            return ValidationResult(
                validator=self.get_name(),
                status="confirmed" if result.vulnerable else ("not_confirmed" if result.checked else "error"),
                finding_class=finding.vulnerability_class,
                confidence=0.85 if result.vulnerable else (0.2 if result.checked else 0.0),
                confirmed=result.vulnerable,
                summary=summary,
                evidence=result.evidence,
                raw_output=self._build_raw_output(tests),
            )
        except Exception as e:
            log.error(f"WebSocket validation error: {e}")
            return ValidationResult(
                validator=self.get_name(), status="error",
                finding_class=finding.vulnerability_class, confidence=0.0, confirmed=False,
                summary=f"WebSocket validation failed: {e}", evidence="", raw_output=str(e),
            )

    def _to_ws_url(self, url: str) -> str | None:
        parsed = urlparse(url)
        if parsed.scheme in ("ws", "wss"):
            return url
        if parsed.scheme == "http":
            return url.replace("http://", "ws://", 1)
        if parsed.scheme == "https":
            return url.replace("https://", "wss://", 1)
        return None

    def _attempt_handshake(self, ws_url: str, cookie_header: str | None) -> WebsocketTestResult:
        parsed = urlparse(ws_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        ws_key = base64.b64encode(os.urandom(16)).decode()
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {_SPOOFED_ORIGIN}",
        ]
        if cookie_header:
            request_lines.append(f"Cookie: {cookie_header}")
        request_lines.append("")
        request_lines.append("")
        raw_request = "\r\n".join(request_lines).encode()

        try:
            policy_error = self._authorize_raw_handshake(ws_url, cookie_header)
            if policy_error:
                return WebsocketTestResult(
                    "CSWSH Handshake Probe", True, "low",
                    f"Handshake blocked before transport: {policy_error}", "",
                    checked=False, vulnerable=False)
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if parsed.scheme == "wss":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw_request)
            response = sock.recv(4096).decode(errors="replace")
            sock.close()
        except Exception as e:
            log.debug(f"WebSocket handshake attempt failed for {ws_url}: {e}")
            return WebsocketTestResult(
                "CSWSH Handshake Probe", True, "low",
                f"Could not attempt handshake: {e}", "", checked=False, vulnerable=False,
            )

        status_line = response.split("\r\n", 1)[0]
        upgraded = "101" in status_line and "witching" in status_line.lower()

        if upgraded:
            return WebsocketTestResult(
                "CSWSH Handshake Probe", False, "high",
                f"Server completed the WebSocket upgrade (101 Switching Protocols) despite a "
                f"handshake sent with Origin: {_SPOOFED_ORIGIN} -- if the connection was "
                f"authenticated by cookie alone, this confirms Cross-Site WebSocket Hijacking "
                f"exposure: any site the victim visits can open this same connection as them",
                f"Response status line: {status_line}", vulnerable=True,
            )
        return WebsocketTestResult(
            "CSWSH Handshake Probe", True, "low",
            f"Server did not upgrade the connection with a spoofed Origin (status line: {status_line}) "
            "-- consistent with Origin validation being enforced, though this doesn't rule out other "
            "handshake requirements (e.g. a required custom header/token) also being the reason",
            f"Response status line: {status_line}", vulnerable=False,
        )

    def _authorize_raw_handshake(self, ws_url: str, cookie_header: str | None) -> str:
        """Apply RunContext policy before the capability-specific raw socket send."""
        if self.run_context is None:
            return ""
        http_url = (ws_url.replace("ws://", "http://", 1)
                    if ws_url.startswith("ws://")
                    else ws_url.replace("wss://", "https://", 1))
        ctx = self.run_context
        if ctx.cancel.cancelled:
            return "run cancelled"
        if not ctx.scope.in_scope(http_url):
            return "destination is out of scope"
        if cookie_header:
            session_ref, _ = ctx.sessions.bind_headers({"Cookie": cookie_header})
            session = ctx.sessions.get(session_ref)
            if session is None:
                return "credential-bearing handshake requires a registered session"
            if ctx.scope.origin_of(http_url) not in session.allowed_origins:
                return "session is not authorized for the requested destination"
        decision = ctx.gate.authorize(
            validator_name=self.get_name(), method="GET", url=http_url)
        if not decision.allowed:
            return decision.reason
        if not ctx.budget.reserve(1):
            return "request budget exhausted"
        return ""

    def _build_raw_output(self, tests: list[WebsocketTestResult]) -> str:
        import json
        return json.dumps([t.to_dict() for t in tests], indent=2)
