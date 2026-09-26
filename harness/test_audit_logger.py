"""
Tests for the audit logger module.
"""
import unittest
import tempfile
import os
import shutil
import json
import logging
import logging.handlers
from harness.audit_logger import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditLogLevel,
    AuditStorageUnavailable,
    _default_audit_log_path,
    get_audit_logger,
    set_default_audit_logger,
    log_audit_event,
    log_llm_prompt,
    log_llm_response,
    log_llm_error,
    log_finding,
    log_validation,
    log_api_call,
    log_security_event,
    log_config_change,
)


class TestAuditEvent(unittest.TestCase):
    """Test the AuditEvent class."""
    
    def test_event_creation(self):
        """AuditEvent should be created with default values."""
        event = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        
        self.assertEqual(event.event_type, AuditEventType.LLM_PROMPT)
        self.assertEqual(event.level, AuditLogLevel.INFO)
        self.assertIsNotNone(event.timestamp)
        self.assertIsNotNone(event.event_id)
    
    def test_to_dict(self):
        """to_dict should convert event to dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            session_id="session123",
            data={"model": "llama3"},
        )
        
        result = event.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['event_type'], AuditEventType.LLM_PROMPT.value)
        self.assertEqual(result['level'], AuditLogLevel.INFO.value)
        self.assertEqual(result['session_id'], "session123")
        self.assertEqual(result['data'], {"model": "llama3"})
    
    def test_to_json(self):
        """to_json should convert event to JSON string."""
        event = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        
        result = event.to_json()
        
        self.assertIsInstance(result, str)
        # Should be valid JSON
        parsed = json.loads(result)
        self.assertIn('event_type', parsed)
    
    def test_compute_hash(self):
        """compute_hash should return a consistent hash."""
        event = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            data={"test": "data"},
            timestamp="2024-01-01T00:00:00Z",  # Fixed timestamp for consistent hash
        )
        
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 hex digest
    
    def test_hash_excludes_previous_hash(self):
        """Hash should not include previous_hash field."""
        # Use the same event_id for both events
        event_id = "00065a1bb21faae9"
        
        event1 = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            data={"test": "data"},
            timestamp="2024-01-01T00:00:00Z",
            event_id=event_id,
        )
        
        event2 = AuditEvent(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            data={"test": "data"},
            timestamp="2024-01-01T00:00:00Z",
            event_id=event_id,
            previous_hash="some_hash",
        )
        
        # Both should have the same hash since previous_hash is excluded
        self.assertEqual(event1.compute_hash(), event2.compute_hash())


class TestAuditLogger(unittest.TestCase):
    """Test the AuditLogger class."""
    
    def setUp(self):
        """Set up test logger with temporary file."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "audit.log")
        self.logger = AuditLogger(
            name="test",
            log_file=self.log_file,
            enable_console=False,
            enable_file=True,
        )
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_event(self):
        """log should create and log an event."""
        event_id = self.logger.log(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
            session_id="session123",
            data={"model": "llama3"},
        )
        
        self.assertIsNotNone(event_id)
        
        # Check that the event was logged to file
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(event_id, content)
            self.assertIn(AuditEventType.LLM_PROMPT.value, content)
    
    def test_log_llm_prompt(self):
        """log_llm_prompt should log LLM prompt events."""
        event_id = self.logger.log_llm_prompt(
            model="llama3",
            system_prompt="You are a helpful assistant",
            user_prompt="Please help me",
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.LLM_PROMPT.value, content)
            self.assertIn("llama3", content)
    
    def test_log_llm_response(self):
        """log_llm_response should log LLM response events."""
        event_id = self.logger.log_llm_response(
            model="llama3",
            response="This is the response",
            prompt_tokens=10,
            completion_tokens=20,
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.LLM_RESPONSE.value, content)
            self.assertIn("30", content)  # total tokens
    
    def test_log_llm_error(self):
        """log_llm_error should log LLM error events."""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            event_id = self.logger.log_llm_error(
                model="llama3",
                error=e,
                session_id="session123",
            )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.LLM_ERROR.value, content)
            self.assertIn("ValueError", content)
    
    def test_log_finding(self):
        """log_finding should log vulnerability findings."""
        event_id = self.logger.log_finding(
            finding_type="sqli",
            severity="high",
            confidence=0.95,
            summary="SQL injection vulnerability detected",
            exchange_url="https://example.com/api",
            agent="sqli_agent",
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.FINDING_DETECTED.value, content)
            self.assertIn("sqli", content)
            self.assertIn("high", content)
    
    def test_log_validation(self):
        """log_validation should log validation results."""
        event_id = self.logger.log_validation(
            validator="sqlmap",
            finding_type="sqli",
            result="Confirmed via sqlmap",
            confirmed=True,
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.FINDING_CONFIRMED.value, content)
            self.assertIn("sqlmap", content)
    
    def test_log_api_call(self):
        """log_api_call should log API calls."""
        event_id = self.logger.log_api_call(
            method="GET",
            url="https://api.example.com/data",
            status_code=200,
            response_time=0.5,
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.API_REQUEST.value, content)
            self.assertIn("GET", content)
    
    def test_log_security_event(self):
        """log_security_event should log security events."""
        event_id = self.logger.log_security_event(
            event_type="circuit_breaker_tripped",
            message="Ollama circuit breaker tripped",
            severity="warning",
            session_id="session123",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.SECURITY_WARNING.value, content)
            self.assertIn("circuit_breaker_tripped", content)
    
    def test_log_config_change(self):
        """log_config_change should log configuration changes."""
        event_id = self.logger.log_config_change(
            config_name="ollama.timeout",
            old_value=120,
            new_value=60,
            changed_by="admin",
        )
        
        self.assertIsNotNone(event_id)
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn(AuditEventType.CONFIG_CHANGED.value, content)
            self.assertIn("ollama.timeout", content)
    
    def test_sensitive_data_redaction(self):
        """Sensitive data should be redacted in logs."""
        self.logger.log(
            event_type=AuditEventType.API_REQUEST,
            data={
                'password': 'secret123',
                'api_key': 'abc123',
                'username': 'test',
            },
            context={
                'authorization': 'Bearer token123',
            },
        )
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertNotIn("secret123", content)
            self.assertNotIn("abc123", content)
            self.assertNotIn("token123", content)
            self.assertIn("[REDACTED]", content)

    def test_nested_dict_secret_redacted_R09(self):
        """PR-9 / R09: _sanitize_data only sanitized TOP-LEVEL keys, so a
        credential nested inside another dict (e.g. {"creds": {"password":
        "x"}}) survived into the persisted audit event. It must now be
        redacted at any depth."""
        self.logger.log(
            event_type=AuditEventType.API_REQUEST,
            data={
                'endpoint': '/login',
                'creds': {'api_key': 'CANARY-AUDIT-NESTED-9f3a1b'},
            },
        )

        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertNotIn("CANARY-AUDIT-NESTED-9f3a1b", content)
            self.assertIn('"api_key": "[REDACTED]"', content)
            # non-secret sibling data at every depth is preserved
            self.assertIn("/login", content)
            self.assertIn('"creds"', content)

    def test_nested_list_of_dicts_secret_redacted_R09(self):
        """Recursion must also apply to dicts nested inside a LIST, not
        only inside another dict."""
        self.logger.log(
            event_type=AuditEventType.API_REQUEST,
            data={
                'requests': [
                    {'url': 'https://a.test/x', 'password': 'CANARY-AUDIT-LIST-77aa'},
                    {'url': 'https://a.test/y', 'note': 'benign'},
                ],
            },
        )

        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertNotIn("CANARY-AUDIT-LIST-77aa", content)
            self.assertIn("https://a.test/x", content)
            self.assertIn("https://a.test/y", content)
            self.assertIn("benign", content)

    def test_deeply_nested_secret_redacted_R09(self):
        """Multiple levels of nesting (dict-in-dict-in-dict) are all
        covered, not just one level down."""
        self.logger.log(
            event_type=AuditEventType.API_REQUEST,
            data={'a': {'b': {'c': {'token': 'CANARY-AUDIT-DEEP-42'}}}},
        )
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertNotIn("CANARY-AUDIT-DEEP-42", content)

    def test_non_secret_nested_field_and_key_name_preserved_R09(self):
        """Structure-preservation negative control: a task-relevant
        non-secret nested field is preserved verbatim, and the secret
        field's NAME stays visible in the sanitized output -- redaction
        replaces only the value, never the whole record."""
        self.logger.log(
            event_type=AuditEventType.API_REQUEST,
            data={
                'user': {'username': 'alice_doe', 'product_id': 4471, 'password': 'CANARY-AUDIT-STRUCT'},
            },
        )
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn("alice_doe", content)
            self.assertIn("4471", content)
            self.assertIn('"password": "[REDACTED]"', content)
            self.assertNotIn("CANARY-AUDIT-STRUCT", content)

    def test_stats_tracking(self):
        """Statistics should be tracked."""
        self.logger.log(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        self.logger.log(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        self.logger.log(
            event_type=AuditEventType.FINDING_DETECTED,
            level=AuditLogLevel.WARNING,
        )
        
        stats = self.logger.get_stats()
        
        self.assertEqual(stats['total_events'], 3)
        self.assertEqual(stats['events_by_type'][AuditEventType.LLM_PROMPT.value], 2)
        self.assertEqual(stats['events_by_type'][AuditEventType.FINDING_DETECTED.value], 1)
        self.assertEqual(stats['events_by_level'][AuditLogLevel.INFO.value], 2)
        self.assertEqual(stats['events_by_level'][AuditLogLevel.WARNING.value], 1)
    
    def test_reset_stats(self):
        """reset_stats should reset all statistics."""
        self.logger.log(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        
        self.logger.reset_stats()
        
        stats = self.logger.get_stats()
        self.assertEqual(stats['total_events'], 0)


class TestAuditLoggerUnwritableStorage(unittest.TestCase):
    """Construction must never raise merely because audit storage is unwritable.

    Covers both guarded failure points: os.makedirs (directory creation) and
    the RotatingFileHandler open (the file itself), which are distinct calls
    that can each fail independently.
    """

    def setUp(self):
        self.tmp_root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_root, ignore_errors=True)

    def test_unwritable_directory_degrades_without_exception(self):
        """(a) A log_file whose DIRECTORY cannot be created/written degrades
        to enable_file=False, with no exception raised."""
        # blocker is a FILE, so a directory cannot be created underneath it -
        # forces os.makedirs(log_dir, exist_ok=True) to fail.
        blocker = os.path.join(self.tmp_root, "blocker_file")
        with open(blocker, "w") as f:
            f.write("not a directory")
        log_dir = os.path.join(blocker, "nested")
        log_file = os.path.join(log_dir, "audit.log")

        logger = AuditLogger(name="test_unwritable_dir", log_file=log_file, enable_file=True)

        self.assertFalse(logger.enable_file)
        self.assertFalse(any(
            isinstance(h, logging.handlers.RotatingFileHandler) for h in logger._logger.handlers
        ))
        # Construction must not have raised, and logging afterwards is still safe.
        logger.log(event_type=AuditEventType.LLM_PROMPT, level=AuditLogLevel.INFO)

    def test_unwritable_existing_file_degrades_without_exception(self):
        """(b) A log_file path that already exists but cannot be opened as a
        file (here: it exists as a directory) degrades to enable_file=False,
        with no exception raised. This exercises the RotatingFileHandler
        open guard specifically (its parent directory already exists, so
        os.makedirs succeeds trivially; only the file open fails)."""
        log_file = os.path.join(self.tmp_root, "audit.log")
        os.makedirs(log_file)  # log_file path exists, but as a directory, not a file

        logger = AuditLogger(name="test_unwritable_file", log_file=log_file, enable_file=True)

        self.assertFalse(logger.enable_file)
        self.assertFalse(any(
            isinstance(h, logging.handlers.RotatingFileHandler) for h in logger._logger.handlers
        ))
        logger.log(event_type=AuditEventType.LLM_PROMPT, level=AuditLogLevel.INFO)

    def test_require_file_raises_on_unwritable_path(self):
        """require_file=True opts into failing loudly instead of degrading."""
        log_file = os.path.join(self.tmp_root, "audit.log")
        os.makedirs(log_file)

        with self.assertRaises(AuditStorageUnavailable):
            AuditLogger(
                name="test_require_file",
                log_file=log_file,
                enable_file=True,
                require_file=True,
            )

    def test_writable_path_negative_control(self):
        """NEGATIVE CONTROL: a writable tmp path still attaches the file
        handler (enable_file stays True) and an emitted record actually
        lands in the file."""
        log_file = os.path.join(self.tmp_root, "writable_subdir", "audit.log")

        logger = AuditLogger(name="test_writable", log_file=log_file, enable_file=True)

        self.assertTrue(logger.enable_file)
        self.assertTrue(any(
            isinstance(h, logging.handlers.RotatingFileHandler) for h in logger._logger.handlers
        ))

        event_id = logger.log(event_type=AuditEventType.LLM_PROMPT, level=AuditLogLevel.INFO)

        self.assertTrue(os.path.exists(log_file))
        with open(log_file, "r") as f:
            content = f.read()
        self.assertIn(event_id, content)


class TestDefaultAuditLogPath(unittest.TestCase):
    """The default audit log path must be a per-user location, never /var/log."""

    def test_default_path_is_not_var_log(self):
        path = _default_audit_log_path("agentic_burp_test")
        self.assertNotIn("var/log", path.replace("\\", "/"))

    def test_default_path_is_platform_appropriate(self):
        path = _default_audit_log_path("agentic_burp_test")
        normalized = path.replace("\\", "/")
        self.assertTrue(normalized.endswith("agentic_burp_test/audit.log"))

        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
        else:
            xdg = os.environ.get("XDG_STATE_HOME") or os.environ.get("XDG_DATA_HOME")
            base = xdg or os.path.join(os.path.expanduser("~"), ".local", "state")
        self.assertTrue(path.startswith(base))

    def test_constructing_without_log_file_uses_default(self):
        """Constructing without an explicit log_file uses the per-user
        default (the constructor arg / setter still override it)."""
        logger = AuditLogger(name="agentic_burp_default_test", enable_file=False)
        normalized = logger.log_file.replace("\\", "/")
        self.assertNotIn("var/log", normalized)
        self.assertIn("agentic_burp_default_test/audit.log", normalized)


class TestGlobalAuditLogger(unittest.TestCase):
    """Test the global audit logger functions."""
    
    def test_get_audit_logger(self):
        """get_audit_logger should return a logger instance."""
        logger = get_audit_logger()
        self.assertIsInstance(logger, AuditLogger)
    
    def test_set_default_audit_logger(self):
        """set_default_audit_logger should set the global logger."""
        original = get_audit_logger()
        custom = AuditLogger(enable_console=False, enable_file=False)
        set_default_audit_logger(custom)
        
        self.assertIs(get_audit_logger(), custom)
        
        # Restore original
        set_default_audit_logger(original)
    
    def test_log_audit_event(self):
        """log_audit_event should log events using the default logger."""
        event_id = log_audit_event(
            event_type=AuditEventType.LLM_PROMPT,
            level=AuditLogLevel.INFO,
        )
        
        self.assertIsNotNone(event_id)
    
    def test_convenience_functions(self):
        """Convenience functions should work."""
        # Test a few convenience functions
        event_id1 = log_llm_prompt("llama3", "system", "user")
        event_id2 = log_finding("sqli", "high", 0.95, "Test", "https://example.com", "agent")
        event_id3 = log_security_event("test", "Test message")
        
        self.assertIsNotNone(event_id1)
        self.assertIsNotNone(event_id2)
        self.assertIsNotNone(event_id3)


if __name__ == "__main__":
    unittest.main()
