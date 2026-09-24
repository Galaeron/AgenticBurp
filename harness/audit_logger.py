"""
Audit logging for security testing harness.

This module provides comprehensive audit logging for all security-relevant
events, including:
- LLM prompt submissions
- API calls to external services
- Finding detections and validations
- Configuration changes
- Authentication events
- Errors and warnings

Design principles:
1. Immutable: Audit logs cannot be modified or deleted
2. Tamper-evident: Any attempt to modify logs should be detectable
3. Comprehensive: Log all security-relevant events
4. Structured: Use structured logging for easy analysis
5. Privacy-aware: Redact sensitive data from logs

Log Levels:
- DEBUG: Detailed information for debugging
- INFO: Normal operational events
- WARNING: Potentially problematic situations
- ERROR: Errors that need investigation
- CRITICAL: Critical security events

Log Categories:
- llm: LLM prompt submissions and responses
- api: External API calls
- finding: Vulnerability findings
- validation: Validation results
- config: Configuration changes
- auth: Authentication events
- security: Security-relevant events
"""
from __future__ import annotations
import json
import logging
import logging.handlers
import hashlib
import time
import os
from typing import Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import Lock


class AuditEventType(Enum):
    """Types of audit events."""
    
    # LLM events
    LLM_PROMPT = "llm.prompt"
    LLM_RESPONSE = "llm.response"
    LLM_ERROR = "llm.error"
    LLM_TOKEN_USAGE = "llm.token_usage"
    
    # API events
    API_REQUEST = "api.request"
    API_RESPONSE = "api.response"
    API_ERROR = "api.error"
    
    # Finding events
    FINDING_DETECTED = "finding.detected"
    FINDING_VALIDATED = "finding.validated"
    FINDING_REJECTED = "finding.rejected"
    FINDING_CONFIRMED = "finding.confirmed"
    
    # Validation events
    VALIDATION_STARTED = "validation.started"
    VALIDATION_COMPLETED = "validation.completed"
    VALIDATION_ERROR = "validation.error"
    
    # Configuration events
    CONFIG_CHANGED = "config.changed"
    CONFIG_LOADED = "config.loaded"
    
    # Authentication events
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_TOKEN_CREATED = "auth.token_created"
    
    # Security events
    SECURITY_WARNING = "security.warning"
    SECURITY_VIOLATION = "security.violation"
    CIRCUIT_BREAKER_TRIPPED = "circuit_breaker.tripped"
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    
    # System events
    STARTUP = "system.startup"
    SHUTDOWN = "system.shutdown"
    ERROR = "system.error"


class AuditLogLevel(Enum):
    """Audit log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class AuditEvent:
    """
    Represents an audit log event.
    
    This is the base data structure for all audit events. It contains
    all the common fields and can be extended with additional data.
    """
    
    # Event type (required)
    event_type: AuditEventType
    
    # Log level
    level: AuditLogLevel = AuditLogLevel.INFO
    
    # Timestamp
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    # Unique event ID
    event_id: str = field(default_factory=lambda: f"{int(time.time() * 1000000):016x}")
    
    # Session/Request ID for correlation
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # User/Service identifier
    user_id: Optional[str] = None
    service: Optional[str] = None
    
    # Event data (structured)
    data: dict = field(default_factory=dict)
    
    # Additional context
    context: dict = field(default_factory=dict)
    
    # Source IP (if applicable)
    source_ip: Optional[str] = None
    
    # Success/failure status
    success: bool = True
    
    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    # Previous event hash (for chain integrity)
    previous_hash: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = asdict(self)
        result['event_type'] = self.event_type.value
        result['level'] = self.level.value
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)
    
    def compute_hash(self) -> str:
        """Compute a hash of this event for integrity verification."""
        # Exclude previous_hash from the hash computation
        event_dict = self.to_dict()
        event_dict.pop('previous_hash', None)
        event_json = json.dumps(event_dict, sort_keys=True)
        return hashlib.sha256(event_json.encode('utf-8')).hexdigest()


class AuditStorageUnavailable(RuntimeError):
    """Raised when `require_file=True` and the audit file sink cannot be opened.

    By default (require_file=False) the same condition degrades to a warning
    instead of raising — see AuditLogger._disable_file_logging.
    """


def _default_audit_log_path(name: str) -> str:
    """Platform-appropriate, per-user default audit log path.

    Dependency-free (no platformdirs). Never defaults under `/var/log` or an
    equivalent admin-owned location, so construction does not require
    elevated privileges. `log_file` (constructor arg) or the `log_file`
    setter still override this default; only the default itself changes.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.environ.get("XDG_DATA_HOME")
        if not base:
            base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, name, "audit.log")


class AuditLogger:
    """
    Audit logger for security-relevant events.

    This class provides a centralized interface for logging audit events.
    It supports multiple backends (file, syslog, external service) and
    ensures that logs are tamper-evident.
    """

    def __init__(
        self,
        name: str = "agentic_burp",
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        enable_console: bool = False,
        enable_file: bool = True,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        max_backups: int = 5,
        require_file: bool = False,
    ):
        self.name = name
        self.log_file = log_file or _default_audit_log_path(name)
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.max_file_size = max_file_size
        self.max_backups = max_backups
        # Policy for "required audit storage unavailable": default is
        # degrade-with-warning (construction must never block on unwritable
        # audit storage); require_file=True opts into failing loudly instead.
        self.require_file = require_file

        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(self.log_file)
        if log_dir and self.enable_file:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except (OSError, PermissionError) as e:
                self._disable_file_logging(f"could not create log directory {log_dir}", e)

        # Initialize Python logger
        self._logger = logging.getLogger(f"{name}.audit")
        self._logger.setLevel(self.log_level)

        # Remove existing handlers
        for handler in self._logger.handlers[:]:
            self._logger.removeHandler(handler)

        # Add console handler
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(console_handler)

        # Add file handler. Opening the file itself (not just creating its
        # parent directory) can also fail — e.g. an existing-but-unwritable
        # file, or a path whose parent segment is itself a file — so guard
        # the open too. Construction of AuditLogger (and therefore anything
        # that builds one, like OllamaClient/the pipeline) must not raise
        # just because audit storage happens to be unwritable.
        if self.enable_file:
            try:
                file_handler = logging.handlers.RotatingFileHandler(
                    self.log_file,
                    maxBytes=self.max_file_size,
                    backupCount=self.max_backups,
                )
            except (OSError, PermissionError) as e:
                self._disable_file_logging(f"could not open log file {self.log_file}", e)
            else:
                file_handler.setLevel(self.log_level)
                file_handler.setFormatter(logging.Formatter('%(message)s'))
                self._logger.addHandler(file_handler)

        # Track the last event hash for chaining
        self._last_hash: Optional[str] = None
        self._lock = Lock()

        # Track statistics
        self._stats = {
            'total_events': 0,
            'events_by_type': {},
            'events_by_level': {},
        }

    def _disable_file_logging(self, message: str, error: Exception) -> None:
        """Apply the require_file policy when audit file storage fails.

        Default (require_file=False): emit one explicit warning and continue
        with enable_file=False — construction must not raise. When
        require_file=True, raise AuditStorageUnavailable instead, for a
        caller that has opted into failing loudly on unavailable audit
        storage.
        """
        if self.require_file:
            raise AuditStorageUnavailable(f"{message}: {error}") from error
        logging.getLogger("harness.audit_logger").warning(
            f"Audit file logging disabled: {message}: {error}"
        )
        self.enable_file = False
    
    # List of keys that should be redacted (exact match or substring).
    # Module-level-equivalent constant kept as a class attribute so
    # _sanitize_data and _sanitize_value (its recursive helper) share the
    # exact same list at every depth.
    _REDACTED_KEY_PATTERNS = [
        'password', 'secret', 'api_key', 'auth_token', 'access_token',
        'refresh_token', 'cookie', 'authorization', 'bearer',
    ]

    def _sanitize_value(self, value: Any) -> Any:
        """Recursively apply the same key/value redaction _sanitize_data
        applies at the top level, to nested dicts AND lists at every
        depth. PR-9 / R09: a top-level-only sanitizer let a nested
        credential (e.g. {"creds": {"password": "x"}}) survive into a
        persisted audit event -- this closes that gap. Audit logs are not
        model input (no detection-recall concern here), so this stays
        thorough rather than narrow."""
        if isinstance(value, dict):
            return self._sanitize_data(value)
        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        return value

    def _sanitize_data(self, data: dict) -> dict:
        """Sanitize sensitive data from the event, recursing into nested
        dicts and lists (see _sanitize_value) so a secret buried at any
        depth is redacted, not only ones at the top level."""
        sanitized = {}

        for key, value in data.items():
            # Check if key contains sensitive information
            # Be careful: 'token' appears in 'prompt_tokens', 'completion_tokens'
            # So we need exact matches for those
            key_lower = key.lower()
            should_redact = False

            # Check for exact matches first
            if key_lower in ['token', 'tokens']:
                # Only redact if it's not prompt_tokens or completion_tokens
                if key_lower not in ['prompt_tokens', 'completion_tokens', 'total_tokens']:
                    should_redact = True
            else:
                # Check for substrings
                for pattern in self._REDACTED_KEY_PATTERNS:
                    if pattern in key_lower:
                        should_redact = True
                        break

            if should_redact:
                sanitized[key] = "[REDACTED]"
            # Check if value is a string that might contain sensitive info
            elif isinstance(value, str):
                if any(redacted in value.lower() for redacted in ['password=', 'token=', 'key=', 'secret=']):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = value
            elif isinstance(value, (dict, list)):
                sanitized[key] = self._sanitize_value(value)
            else:
                sanitized[key] = value

        return sanitized
    
    def _log_event(self, event: AuditEvent) -> None:
        """Log an audit event."""
        with self._lock:
            # Sanitize data
            event.data = self._sanitize_data(event.data)
            event.context = self._sanitize_data(event.context)
            
            # Compute hash
            event_hash = event.compute_hash()
            event.previous_hash = self._last_hash
            
            # Update last hash
            self._last_hash = event_hash
            
            # Update statistics
            self._stats['total_events'] += 1
            event_type_str = event.event_type.value
            level_str = event.level.value
            
            if event_type_str not in self._stats['events_by_type']:
                self._stats['events_by_type'][event_type_str] = 0
            self._stats['events_by_type'][event_type_str] += 1
            
            if level_str not in self._stats['events_by_level']:
                self._stats['events_by_level'][level_str] = 0
            self._stats['events_by_level'][level_str] += 1
            
            # Log the event
            log_message = f"[{event.timestamp}] [{event.event_type.value}] [{event.level.value}] {event.to_json()}"
            
            # Log based on level
            if event.level == AuditLogLevel.DEBUG:
                self._logger.debug(log_message)
            elif event.level == AuditLogLevel.INFO:
                self._logger.info(log_message)
            elif event.level == AuditLogLevel.WARNING:
                self._logger.warning(log_message)
            elif event.level == AuditLogLevel.ERROR:
                self._logger.error(log_message)
            elif event.level == AuditLogLevel.CRITICAL:
                self._logger.critical(log_message)
    
    def log(
        self,
        event_type: AuditEventType,
        level: AuditLogLevel = AuditLogLevel.INFO,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        service: Optional[str] = None,
        data: dict = None,
        context: dict = None,
        source_ip: Optional[str] = None,
        success: bool = True,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> str:
        """
        Log an audit event.
        
        Args:
            event_type: Type of the audit event
            level: Log level
            session_id: Session ID for correlation
            request_id: Request ID for correlation
            user_id: User ID
            service: Service name
            data: Event data (structured)
            context: Additional context
            source_ip: Source IP address
            success: Whether the event was successful
            error_code: Error code (if applicable)
            error_message: Error message (if applicable)
            
        Returns:
            The event ID
        """
        event = AuditEvent(
            event_type=event_type,
            level=level,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            service=service,
            data=data or {},
            context=context or {},
            source_ip=source_ip,
            success=success,
            error_code=error_code,
            error_message=error_message,
        )
        
        self._log_event(event)
        
        return event.event_id
    
    # Convenience methods for common event types
    
    def log_llm_prompt(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Log an LLM prompt submission."""
        return self.log(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            service="llm",
            data={
                'model': model,
                'system_prompt_length': len(system_prompt),
                'user_prompt_length': len(user_prompt),
            },
            context={
                'system_prompt_hash': hashlib.sha256(system_prompt.encode()).hexdigest()[:16],
                'user_prompt_hash': hashlib.sha256(user_prompt.encode()).hexdigest()[:16],
            },
        )
    
    def log_llm_response(
        self,
        model: str,
        response: str,
        prompt_tokens: int,
        completion_tokens: int,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Log an LLM response."""
        return self.log(
            event_type=AuditEventType.LLM_RESPONSE,
            level=AuditLogLevel.INFO,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            service="llm",
            data={
                'model': model,
                'response_length': len(response),
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': prompt_tokens + completion_tokens,
            },
            context={
                'response_hash': hashlib.sha256(response.encode()).hexdigest()[:16],
            },
        )
    
    def log_llm_error(
        self,
        model: str,
        error: Exception,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Log an LLM error."""
        return self.log(
            event_type=AuditEventType.LLM_ERROR,
            level=AuditLogLevel.ERROR,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            service="llm",
            data={
                'model': model,
                'error_type': type(error).__name__,
            },
            context={
                'error_message': str(error),
            },
            success=False,
            error_code=type(error).__name__,
            error_message=str(error),
        )
    
    def log_finding(
        self,
        finding_type: str,
        severity: str,
        confidence: float,
        summary: str,
        exchange_url: str,
        agent: str,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> str:
        """Log a vulnerability finding."""
        return self.log(
            event_type=AuditEventType.FINDING_DETECTED,
            level=AuditLogLevel.WARNING,
            session_id=session_id,
            request_id=request_id,
            service="analysis",
            data={
                'finding_type': finding_type,
                'severity': severity,
                'confidence': confidence,
                'summary': summary[:200],  # Truncate long summaries
                'exchange_url': exchange_url,
                'agent': agent,
            },
        )
    
    def log_validation(
        self,
        validator: str,
        finding_type: str,
        result: str,
        confirmed: bool,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> str:
        """Log a validation result."""
        event_type = (
            AuditEventType.FINDING_CONFIRMED if confirmed
            else AuditEventType.FINDING_REJECTED
        )
        level = AuditLogLevel.INFO if confirmed else AuditLogLevel.WARNING
        
        return self.log(
            event_type=event_type,
            level=level,
            session_id=session_id,
            request_id=request_id,
            service="validation",
            data={
                'validator': validator,
                'finding_type': finding_type,
                'result': result,
                'confirmed': confirmed,
            },
        )
    
    def log_api_call(
        self,
        method: str,
        url: str,
        status_code: int,
        response_time: float,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> str:
        """Log an API call."""
        level = (
            AuditLogLevel.INFO if 200 <= status_code < 400
            else AuditLogLevel.WARNING if 400 <= status_code < 500
            else AuditLogLevel.ERROR
        )
        
        return self.log(
            event_type=AuditEventType.API_REQUEST,
            level=level,
            session_id=session_id,
            request_id=request_id,
            service="api",
            data={
                'method': method,
                'url': url,
                'status_code': status_code,
                'response_time_ms': response_time * 1000,
            },
            success=200 <= status_code < 400,
        )
    
    def log_security_event(
        self,
        event_type: str,
        message: str,
        severity: str = "warning",
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> str:
        """Log a security-relevant event."""
        level_map = {
            'debug': AuditLogLevel.DEBUG,
            'info': AuditLogLevel.INFO,
            'warning': AuditLogLevel.WARNING,
            'error': AuditLogLevel.ERROR,
            'critical': AuditLogLevel.CRITICAL,
        }
        
        return self.log(
            event_type=AuditEventType.SECURITY_WARNING,
            level=level_map.get(severity.lower(), AuditLogLevel.WARNING),
            session_id=session_id,
            request_id=request_id,
            service="security",
            data={
                'event_type': event_type,
                'message': message,
                'severity': severity,
            },
        )
    
    def log_config_change(
        self,
        config_name: str,
        old_value: Any,
        new_value: Any,
        changed_by: Optional[str] = None,
    ) -> str:
        """Log a configuration change."""
        return self.log(
            event_type=AuditEventType.CONFIG_CHANGED,
            level=AuditLogLevel.INFO,
            user_id=changed_by,
            service="config",
            data={
                'config_name': config_name,
                'old_value': str(old_value)[:100],
                'new_value': str(new_value)[:100],
            },
        )
    
    def get_stats(self) -> dict:
        """Get audit logging statistics."""
        with self._lock:
            return {
                **self._stats,
                'last_event_hash': self._last_hash,
            }
    
    def reset_stats(self) -> None:
        """Reset audit logging statistics."""
        with self._lock:
            self._stats = {
                'total_events': 0,
                'events_by_type': {},
                'events_by_level': {},
            }


# =============================================================================
# Global Audit Logger
# =============================================================================

_default_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the default audit logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger()
    return _default_logger


def set_default_audit_logger(logger: AuditLogger) -> None:
    """Set the default audit logger."""
    global _default_logger
    _default_logger = logger


def log_audit_event(
    event_type: AuditEventType,
    level: AuditLogLevel = AuditLogLevel.INFO,
    **kwargs,
) -> str:
    """Log an audit event using the default logger."""
    return get_audit_logger().log(event_type, level, **kwargs)


# =============================================================================
# Convenience Functions
# =============================================================================

def log_llm_prompt(model: str, system_prompt: str, user_prompt: str, **kwargs) -> str:
    """Log an LLM prompt using the default logger."""
    return get_audit_logger().log_llm_prompt(model, system_prompt, user_prompt, **kwargs)


def log_llm_response(model: str, response: str, prompt_tokens: int, completion_tokens: int, **kwargs) -> str:
    """Log an LLM response using the default logger."""
    return get_audit_logger().log_llm_response(model, response, prompt_tokens, completion_tokens, **kwargs)


def log_llm_error(model: str, error: Exception, **kwargs) -> str:
    """Log an LLM error using the default logger."""
    return get_audit_logger().log_llm_error(model, error, **kwargs)


def log_finding(finding_type: str, severity: str, confidence: float, summary: str, exchange_url: str, agent: str, **kwargs) -> str:
    """Log a vulnerability finding using the default logger."""
    return get_audit_logger().log_finding(finding_type, severity, confidence, summary, exchange_url, agent, **kwargs)


def log_validation(validator: str, finding_type: str, result: str, confirmed: bool, **kwargs) -> str:
    """Log a validation result using the default logger."""
    return get_audit_logger().log_validation(validator, finding_type, result, confirmed, **kwargs)


def log_api_call(method: str, url: str, status_code: int, response_time: float, **kwargs) -> str:
    """Log an API call using the default logger."""
    return get_audit_logger().log_api_call(method, url, status_code, response_time, **kwargs)


def log_security_event(event_type: str, message: str, severity: str = "warning", **kwargs) -> str:
    """Log a security event using the default logger."""
    return get_audit_logger().log_security_event(event_type, message, severity, **kwargs)


def log_config_change(config_name: str, old_value: Any, new_value: Any, changed_by: Optional[str] = None) -> str:
    """Log a configuration change using the default logger."""
    return get_audit_logger().log_config_change(config_name, old_value, new_value, changed_by)
