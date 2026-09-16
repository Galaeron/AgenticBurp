import unittest
from harness.safety_gate import (
    SafetyGate, SafetyGateConfig, ActionRiskTier, GatedAsyncClient,
    SafetyGateBlocked, HARD_MAX_BURST_SIZE, get_default_gate, reset_default_gate,
)


class TestSafetyGateConfigFromDict(unittest.TestCase):
    """R01: config validation parsed a typed view but `from_dict` re-read the
    ORIGINAL untyped dict with Python's naive bool(value) -- where bool("false")
    is True, since any nonempty string is truthy. A quoted `active_enabled:
    "false"` in config.local.yaml was therefore interpreted as enabled."""

    def test_quoted_false_string_is_not_interpreted_as_enabled(self):
        cfg = SafetyGateConfig.from_dict({"active_enabled": "false", "allow_mutating_replay": "false"})
        self.assertFalse(cfg.active_enabled)
        self.assertFalse(cfg.allow_mutating_replay)

    def test_quoted_true_string_is_interpreted_as_enabled(self):
        cfg = SafetyGateConfig.from_dict({"active_enabled": "true", "allow_mutating_replay": "true"})
        self.assertTrue(cfg.active_enabled)
        self.assertTrue(cfg.allow_mutating_replay)

    def test_real_booleans_pass_through_unchanged(self):
        cfg = SafetyGateConfig.from_dict({"active_enabled": True, "allow_mutating_replay": False})
        self.assertTrue(cfg.active_enabled)
        self.assertFalse(cfg.allow_mutating_replay)

    def test_missing_flags_default_to_disabled(self):
        cfg = SafetyGateConfig.from_dict({})
        self.assertFalse(cfg.active_enabled)
        self.assertFalse(cfg.allow_mutating_replay)

    def test_ambiguous_string_value_raises_instead_of_guessing(self):
        with self.assertRaises(ValueError):
            SafetyGateConfig.from_dict({"active_enabled": "disabled"})

    def test_numeric_and_extended_vocabulary_strings_are_coerced(self):
        # yes/no/on/off/1/0 are the same vocabulary an operator plausibly
        # writes by hand and that pydantic's own lax bool validation accepts.
        self.assertFalse(SafetyGateConfig.from_dict({"active_enabled": "no"}).active_enabled)
        self.assertTrue(SafetyGateConfig.from_dict({"active_enabled": "yes"}).active_enabled)
        self.assertFalse(SafetyGateConfig.from_dict({"active_enabled": "0"}).active_enabled)
        self.assertTrue(SafetyGateConfig.from_dict({"active_enabled": "1"}).active_enabled)

    def test_numeric_thresholds_still_come_from_raw_dict(self):
        cfg = SafetyGateConfig.from_dict({"max_burst_size": 5, "max_mutating_requests_per_finding": 3})
        self.assertEqual(cfg.max_burst_size, 5)
        self.assertEqual(cfg.max_mutating_requests_per_finding, 3)


class TestSafetyGateClassification(unittest.TestCase):
    def setUp(self):
        self.gate = SafetyGate(SafetyGateConfig())

    def test_get_is_safe(self):
        self.assertEqual(self.gate.classify("GET"), ActionRiskTier.SAFE)

    def test_head_options_trace_are_safe(self):
        for m in ("HEAD", "OPTIONS", "TRACE"):
            self.assertEqual(self.gate.classify(m), ActionRiskTier.SAFE, m)

    def test_post_put_patch_delete_are_mutating(self):
        for m in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertEqual(self.gate.classify(m), ActionRiskTier.MUTATING, m)

    def test_case_insensitive_method(self):
        self.assertEqual(self.gate.classify("get"), ActionRiskTier.SAFE)
        self.assertEqual(self.gate.classify("Post"), ActionRiskTier.MUTATING)

    def test_unrecognized_method_fails_closed_as_mutating(self):
        # Fail-closed: an unknown/malformed method string must never be
        # treated as safe by default.
        self.assertEqual(self.gate.classify("FROBNICATE"), ActionRiskTier.MUTATING)
        self.assertEqual(self.gate.classify(""), ActionRiskTier.MUTATING)
        self.assertEqual(self.gate.classify(None), ActionRiskTier.MUTATING)


class TestHardDenyPatterns(unittest.TestCase):
    def setUp(self):
        self.gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True, max_burst_size=99))

    def test_drop_table_in_body_is_hard_denied(self):
        tier = self.gate.classify("GET", body="'; DROP TABLE users; --")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_drop_table_denied_even_when_everything_else_authorized(self):
        # This is the critical property: even with active_enabled AND
        # allow_mutating_replay both True, a hard-denied pattern still blocks.
        decision = self.gate.authorize(validator_name="test", method="POST",
                                        url="https://example.com/x", body="DROP TABLE users")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.tier, ActionRiskTier.HARD_DENIED)

    def test_delete_from_without_where_is_denied(self):
        tier = self.gate.classify("POST", body="DELETE FROM users")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_delete_from_with_where_is_not_denied_by_this_pattern(self):
        # A scoped DELETE (with a WHERE clause) is not what this specific
        # hard-deny pattern targets -- it's the unscoped, whole-table form
        # that's denied. (It may still require normal mutating-method
        # authorization -- this test only checks it isn't HARD_DENIED.)
        tier = self.gate.classify("POST", body="DELETE FROM sessions WHERE id = 5")
        self.assertNotEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_update_set_without_where_is_denied(self):
        tier = self.gate.classify("POST", body="UPDATE users SET is_admin = 1")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_rm_rf_is_denied(self):
        tier = self.gate.classify("POST", body="cmd=rm -rf /var/www")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_benign_body_is_not_denied(self):
        tier = self.gate.classify("POST", body='{"name": "test product", "price": 9.99}')
        self.assertNotEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_deny_pattern_checked_in_url_too(self):
        tier = self.gate.classify("GET", url="https://example.com/exec?cmd=rm -rf /")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_plus_encoded_space_does_not_evade_the_url_check(self):
        """
        Regression test for a real gap found while building
        safety_proxy_addon.py: a destructive pattern with its spaces
        encoded as '+' (the application/x-www-form-urlencoded space
        convention, extremely common in real query strings) previously
        classified as SAFE, because the hard-deny regexes only matched
        literal whitespace. The target server decodes '+' back to a
        space before acting on it regardless of what this gate saw, so
        this was a real evasion, not a theoretical one.
        """
        tier = self.gate.classify("GET", url="https://example.com/exec?cmd=rm+-rf+/")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_percent_encoded_space_does_not_evade_the_url_check(self):
        tier = self.gate.classify("GET", url="https://example.com/exec?cmd=rm%20-rf%20/")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_percent_encoded_space_does_not_evade_the_body_check(self):
        tier = self.gate.classify("POST", body="cmd=DROP%20TABLE%20users")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_plus_in_legitimate_content_is_not_a_false_positive(self):
        """
        The fix must not turn '+' or '%XX' appearing in ordinary,
        non-destructive content into a false hard-deny -- only content
        that decodes to an actual hard-deny pattern should trip this.
        """
        tier = self.gate.classify("GET", url="https://example.com/products?category=drop+shipping")
        self.assertNotEqual(tier, ActionRiskTier.HARD_DENIED)

    def test_raw_unencoded_pattern_is_still_denied_after_the_fix(self):
        # Guards against a fix that only checks the decoded form and
        # accidentally stops checking the raw form.
        tier = self.gate.classify("POST", body="'; DROP TABLE users; --")
        self.assertEqual(tier, ActionRiskTier.HARD_DENIED)


class TestMutatingMethodGating(unittest.TestCase):
    def test_mutating_denied_when_active_testing_disabled(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=False))
        decision = gate.authorize(validator_name="t", method="POST", url="https://x.example/")
        self.assertFalse(decision.allowed)
        self.assertIn("active", decision.reason.lower())

    def test_mutating_denied_when_active_enabled_but_mutating_replay_off(self):
        # This is the core new protection: active_enabled alone is NOT
        # enough to authorize a mutating replay -- a second, separate
        # flag is required.
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=False))
        decision = gate.authorize(validator_name="t", method="DELETE", url="https://x.example/")
        self.assertFalse(decision.allowed)
        self.assertIn("allow_mutating_replay", decision.reason)

    def test_mutating_allowed_when_both_flags_on(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True))
        decision = gate.authorize(validator_name="t", method="POST", url="https://x.example/")
        self.assertTrue(decision.allowed)

    def test_safe_method_allowed_even_with_everything_off(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=False, allow_mutating_replay=False))
        decision = gate.authorize(validator_name="t", method="GET", url="https://x.example/")
        self.assertTrue(decision.allowed)


class TestBurstCeilings(unittest.TestCase):
    def test_burst_capped_by_hard_ceiling_regardless_of_config(self):
        # Config asks for far more than the hard ceiling allows.
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                            max_burst_size=999999))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=999999)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.allowed_burst_size, HARD_MAX_BURST_SIZE)
        self.assertLessEqual(decision.allowed_burst_size, HARD_MAX_BURST_SIZE)

    def test_burst_capped_by_config_when_stricter_than_hard_ceiling(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                            max_burst_size=3))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=12)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.allowed_burst_size, 3)

    def test_burst_capped_by_validators_own_request_when_smallest(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                            max_burst_size=50))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=5)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.allowed_burst_size, 5)

    def test_burst_denied_entirely_if_mutating_replay_off(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=False,
                                            max_burst_size=50))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=12)
        self.assertFalse(decision.allowed)

    def test_hard_deny_pattern_blocks_burst_too(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                            max_burst_size=50))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=12, body="DROP TABLE orders")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.tier, ActionRiskTier.HARD_DENIED)

    def test_zero_or_negative_burst_size_disables_burst(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True, max_burst_size=0))
        decision = gate.authorize_burst(validator_name="race", method="POST", url="https://x.example/",
                                         requested_burst_size=12)
        self.assertFalse(decision.allowed)


class TestAuditLog(unittest.TestCase):
    def test_every_decision_is_logged_allowed_and_denied(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=False))
        gate.authorize(validator_name="v1", method="GET", url="https://a.example/")
        gate.authorize(validator_name="v2", method="POST", url="https://b.example/")
        self.assertEqual(len(gate.audit_log), 2)
        self.assertTrue(gate.audit_log[0].allowed)
        self.assertFalse(gate.audit_log[1].allowed)

    def test_audit_entries_have_validator_name_and_url(self):
        gate = SafetyGate(SafetyGateConfig())
        gate.authorize(validator_name="my_validator", method="GET", url="https://example.com/path")
        entry = gate.audit_log[0]
        self.assertEqual(entry.validator_name, "my_validator")
        self.assertEqual(entry.url, "https://example.com/path")
        self.assertEqual(entry.method, "GET")


class TestGatedAsyncClient(unittest.IsolatedAsyncioTestCase):
    async def test_denied_request_raises_and_never_reaches_httpx(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=False))
        async with GatedAsyncClient(gate, "test_validator") as client:
            with self.assertRaises(SafetyGateBlocked):
                await client.request("DELETE", "https://example.com/account")

    async def test_denied_request_is_audited(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=False))
        async with GatedAsyncClient(gate, "test_validator") as client:
            try:
                await client.request("POST", "https://example.com/x")
            except SafetyGateBlocked:
                pass
        self.assertEqual(len(gate.audit_log), 1)
        self.assertFalse(gate.audit_log[0].allowed)

    async def test_hard_denied_body_raises_even_with_everything_else_on(self):
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True))
        async with GatedAsyncClient(gate, "test_validator") as client:
            with self.assertRaises(SafetyGateBlocked) as ctx:
                await client.request("POST", "https://example.com/x", content="DROP TABLE users")
            self.assertEqual(ctx.exception.decision.tier, ActionRiskTier.HARD_DENIED)


class TestDefaultGateSingleton(unittest.TestCase):
    def setUp(self):
        reset_default_gate()

    def tearDown(self):
        reset_default_gate()

    def test_get_default_gate_is_a_singleton(self):
        g1 = get_default_gate({"active_enabled": True})
        g2 = get_default_gate({"active_enabled": False})  # ignored on second call
        self.assertIs(g1, g2)
        self.assertTrue(g1.config.active_enabled)

    def test_reset_default_gate_allows_reinitialization(self):
        g1 = get_default_gate({"active_enabled": True})
        reset_default_gate()
        g2 = get_default_gate({"active_enabled": False})
        self.assertIsNot(g1, g2)
        self.assertFalse(g2.config.active_enabled)


# Validator source files verified to route any mutating-capable live send
# through the SafetyGate (GatedAsyncClient / authorize_burst) or sqlmap's own
# gate call. Shared by the exchange.method check and the hardcoded-mutating-
# method-literal check below. Membership here is a claim that the file's
# mutating sends are gate-routed -- most are re-verified in
# test_the_gate_routed_exceptions_actually_route_through_the_gate.
_GATE_ROUTED_EXCEPTIONS = {
    "api_security_validator.py", "race_condition_validator.py", "sqlmap.py",
    # ssrf/xxe replay the request as a live (possibly mutating) send but
    # route it through GatedAsyncClient -- verified in
    # test_the_gate_routed_exceptions_actually_route_through_the_gate.
    "ssrf_validator.py", "xxe_validator.py",
    # command_injection/ssti replay the captured method for their
    # injection payload but likewise route through GatedAsyncClient.
    "command_injection_validator.py", "ssti_validator.py",
    # path_traversal/open_redirect replay the captured method for their
    # file-read / redirect-follow probe, gate-routed.
    "path_traversal_validator.py", "open_redirect_validator.py",
    # sequence replays the captured mutating method for its write step
    # (bracketed by GET reads), gate-routed.
    "sequence_validator.py",
    # deserialization_oob replays the captured method carrying the pickle
    # beacon, gate-routed + self-gated on allow_mutating_replay.
    "deserialization_oob_validator.py",
    # auth_sequence replays the captured auth method (login/register) for
    # its multi-request flow, gate-routed + self-gated.
    "auth_sequence_validator.py",
    # stored_xss replays the captured write method to plant the payload,
    # gate-routed + self-gated on allow_mutating_replay.
    "stored_xss_validator.py",
    # verb_tamper sends alternate safe methods + override headers, gate-routed.
    "verb_tamper_validator.py",
    # csrf replays the mutating request without the CSRF token, gate-routed
    # + self-gated on allow_mutating_replay.
    "csrf_validator.py",
    # file_upload sends a POST upload, gate-routed + self-gated.
    "file_upload_validator.py",
    # rate_limit replays the captured auth method N times via authorize_burst.
    "rate_limit_validator.py",
    # toctou fires a concurrent burst of the captured mutating method via
    # authorize_burst.
    "toctou_validator.py",
    # reset_token hardcodes method="POST" for its reset trigger but sends it
    # through GatedAsyncClient (self-gated on allow_mutating_replay) -- it
    # matches the mutating-method-literal check below, not the exchange.method
    # one, and is verified gate-routed there.
    "reset_token_validator.py",
}


class TestNoValidatorBypassesTheGate(unittest.TestCase):
    """
    These tests read the actual validator source files and fail the
    build if a validator sends a live mutating-capable request without
    going through this module. This is what makes the gate an
    enforced control rather than a convention a future edit could
    quietly stop following.
    """

    def _validator_files(self):
        import pathlib
        here = pathlib.Path(__file__).parent
        return sorted((here / "validators").glob("*.py"))

    def test_no_validator_passes_exchange_method_directly_to_a_live_send(self):
        """
        Every validator that used to reuse the captured exchange's
        method for a live request has been fixed to either hardcode a
        safe method or route through the gate. This test greps for the
        dangerous pattern reappearing and fails loudly if it does --
        a future edit that adds `exchange.method` back into a live
        `client.request(`/`client.get(`/etc. call, outside of the two
        gate-routed exceptions, should break this test.
        """
        import re
        # Files allowed to reference exchange.method for a live send,
        # because they route it through SafetyGate first (shared module set).
        gate_routed_exceptions = _GATE_ROUTED_EXCEPTIONS
        # Files whose exchange.method reference is provably not a live
        # send at all -- verified by reading the code, not assumed.
        inert_usage_exceptions = {
            # endpoint.methods.add(exchange.method): records the observed
            # method into an attack-surface-map data structure for
            # reporting. Never passed to a network call.
            "recon_validator.py",
            # _raw_request() builds descriptive text written to a
            # (deleted-on-exit) temp file for audit purposes; that text
            # is never passed to sqlmap's actual invocation, which uses
            # -u/--data/-H instead (see the comment above cmd = [...]
            # explaining why -r <file> is deliberately not used). The
            # mutating-method sqlmap.py:114-115 case is covered by
            # gate_routed_exceptions above, not this one.
            "sqlmap.py",
            # The only exchange.method reference is a DEFENSIVE GUARD:
            #   if (exchange.method or "GET").upper() != "GET": return skipped
            # i.e. it refuses to proceed for anything but GET. The validator's
            # own live send (_probe) hardcodes client.get(); the captured method
            # is never passed to a request. This is the opposite of the danger
            # this test guards against.
            "cross_identity_validator.py",
            # Same defensive-guard shape: the only exchange.method reference is
            # `if (exchange.method or "GET").upper() != "GET": return skipped`, and
            # the live send (_probe) hardcodes client.get(). Never sent.
            "jwt_forge_validator.py",
        }

        violations = []
        for path in self._validator_files():
            if path.name == "__init__.py":
                continue
            text = path.read_text()
            # Matches e.g. "exchange.method, exchange.url" or
            # "method=exchange.method" appearing anywhere near a live
            # send call. Deliberately broad/simple (a real security
            # control should be easy to verify by inspection, not
            # itself be a fragile piece of clever parsing).
            for match in re.finditer(r'exchange\.method', text):
                line_no = text[:match.start()].count("\n") + 1
                line = text.splitlines()[line_no - 1]
                if "target_method=" in line:
                    continue  # metadata field only, not a live send -- harmless
                if path.name in gate_routed_exceptions:
                    continue  # verified gate-routed above; test_the_two/three_exceptions checks this
                if path.name in inert_usage_exceptions:
                    continue  # verified never sent, per the comments above
                violations.append(f"{path.name}:{line_no}: {line.strip()}")

        self.assertEqual(violations, [],
                          "Found validator(s) using exchange.method outside the two "
                          "gate-routed exceptions -- this is the exact pattern that let "
                          "13 validators blindly replay a captured mutating method:\n" +
                          "\n".join(violations))

    def test_no_validator_hardcodes_a_mutating_method_for_an_ungated_send(self):
        """
        The exchange.method grep above is blind to a HARDCODED mutating
        method: a literal `method="POST"` for a live send sails straight
        past it -- which is exactly how the CORS preflight-bypass POST
        (W-1) shipped an ungated state-changing request to the target and
        was not caught. This flags any hardcoded POST/PUT/PATCH/DELETE in a
        validator outside the set of files verified to route such sends
        through the SafetyGate. On the pre-W-1 tree cors_validator.py
        (raw httpx, not gate-routed) would be the violation.
        """
        import re
        pat = re.compile(r'method\s*=\s*["\'](POST|PUT|PATCH|DELETE)', re.IGNORECASE)
        violations = []
        for path in self._validator_files():
            if path.name == "__init__.py" or path.name in _GATE_ROUTED_EXCEPTIONS:
                continue
            text = path.read_text()
            for match in pat.finditer(text):
                line_no = text[:match.start()].count("\n") + 1
                violations.append(f"{path.name}:{line_no}: {text.splitlines()[line_no - 1].strip()}")
        self.assertEqual(
            violations, [],
            "Found validator(s) hardcoding a mutating HTTP method for a live send outside "
            "the gate-routed allowlist. A literal method=\"POST\"/\"PUT\"/\"PATCH\"/\"DELETE\" "
            "must either be sent through GatedAsyncClient/authorize_burst (then added to "
            "_GATE_ROUTED_EXCEPTIONS with a note) or replaced with a safe read-only probe:\n" +
            "\n".join(violations))

    def test_the_gate_routed_exceptions_actually_route_through_the_gate(self):
        import pathlib
        here = pathlib.Path(__file__).parent
        api_sec = (here / "validators" / "api_security_validator.py").read_text()
        race = (here / "validators" / "race_condition_validator.py").read_text()
        sqlmap_src = (here / "validators" / "sqlmap.py").read_text()

        self.assertIn("GatedAsyncClient", api_sec,
                       "api_security_validator.py uses exchange.method but doesn't import GatedAsyncClient")
        self.assertIn("get_default_gate", api_sec)

        self.assertIn("authorize_burst", race,
                       "race_condition_validator.py uses exchange.method but doesn't call authorize_burst")
        self.assertIn("get_default_gate", race)

        rate = (here / "validators" / "rate_limit_validator.py").read_text()
        self.assertIn("authorize_burst", rate,
                       "rate_limit_validator.py replays the captured method but doesn't call authorize_burst")
        self.assertIn("get_default_gate", rate)

        toctou = (here / "validators" / "toctou_validator.py").read_text()
        self.assertIn("authorize_burst", toctou,
                       "toctou_validator.py fires a burst but doesn't call authorize_burst")
        self.assertIn("get_default_gate", toctou)

        self.assertIn("get_default_gate", sqlmap_src,
                       "sqlmap.py uses exchange.method for --method but doesn't call the safety gate")
        self.assertIn(".authorize(", sqlmap_src)

        for name in ("ssrf_validator.py", "xxe_validator.py",
                     "command_injection_validator.py", "ssti_validator.py",
                     "path_traversal_validator.py", "open_redirect_validator.py",
                     "sequence_validator.py", "deserialization_oob_validator.py",
                     "auth_sequence_validator.py", "stored_xss_validator.py",
                     # reset_token hardcodes method="POST" (mutating-literal
                     # check), so verify it too routes through the gate.
                     "reset_token_validator.py"):
            src = (here / "validators" / name).read_text()
            self.assertIn("GatedAsyncClient", src,
                          f"{name} replays exchange.method but doesn't route through GatedAsyncClient")
            self.assertIn("get_default_gate", src)

    def test_sqlmap_command_never_contains_destructive_flags(self):
        import pathlib
        here = pathlib.Path(__file__).parent
        sqlmap_src = (here / "validators" / "sqlmap.py").read_text()
        for flag in ("--dump", "--os-shell", "--os-pwn", "--os-cmd", "--sql-shell",
                     "--file-write", "--reg-add", "--reg-del", "--privesc"):
            # The flag must not appear anywhere in the source as a
            # string literal that could end up in cmd -- the only
            # acceptable appearance is inside the _DENIED_SQLMAP_FLAGS
            # tuple itself (the denylist), not as something actually added to cmd.
            for line_no, line in enumerate(sqlmap_src.splitlines(), start=1):
                if flag in line and "_DENIED_SQLMAP_FLAGS" not in sqlmap_src.splitlines()[
                        max(0, line_no - 5):line_no][0] and "cmd +=" in line:
                    self.fail(f"sqlmap.py line {line_no} adds denied flag {flag} to cmd: {line.strip()}")

    def test_sqlmap_has_hard_ceiling_assertions(self):
        import pathlib
        here = pathlib.Path(__file__).parent
        sqlmap_src = (here / "validators" / "sqlmap.py").read_text()
        self.assertIn("assert self.risk <= 2", sqlmap_src)
        self.assertIn("assert self.level <= 2", sqlmap_src)


class PerFindingMutationCeilingTests(unittest.TestCase):
    """R16: max_mutating_requests_per_finding must actually be ENFORCED. Before
    the fix it was declared in config but never counted, so N separate POSTs for
    one finding all passed with a configured ceiling of one."""

    def _gate(self, ceiling=1):
        return SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                           max_burst_size=99,
                                           max_mutating_requests_per_finding=ceiling))

    def test_third_post_denied_with_ceiling_of_one(self):
        gate = self._gate(ceiling=1)
        d1 = gate.authorize(validator_name="seq", method="POST", url="https://x.example/a",
                            finding_id="F1")
        d2 = gate.authorize(validator_name="seq", method="POST", url="https://x.example/a",
                            finding_id="F1")
        self.assertTrue(d1.allowed)
        self.assertFalse(d2.allowed)                     # ceiling of 1 reached
        self.assertIn("ceiling", d2.reason.lower())

    def test_ceiling_of_three_allows_three_denies_fourth(self):
        gate = self._gate(ceiling=3)
        allowed = [gate.authorize(validator_name="seq", method="POST",
                                  url="https://x.example/a", finding_id="F1").allowed
                   for _ in range(4)]
        self.assertEqual(allowed, [True, True, True, False])

    def test_no_finding_id_is_not_counted_backcompat(self):
        # Existing callers that pass no finding_id keep the old behaviour.
        gate = self._gate(ceiling=1)
        for _ in range(5):
            self.assertTrue(gate.authorize(validator_name="seq", method="POST",
                                           url="https://x.example/a").allowed)

    def test_distinct_findings_have_independent_budgets(self):
        gate = self._gate(ceiling=1)
        self.assertTrue(gate.authorize(validator_name="s", method="POST",
                                       url="https://x/a", finding_id="F1").allowed)
        self.assertTrue(gate.authorize(validator_name="s", method="POST",
                                       url="https://x/a", finding_id="F2").allowed)

    def test_burst_reserves_whole_burst_against_finding(self):
        gate = self._gate(ceiling=3)
        first = gate.authorize_burst(validator_name="race", method="POST",
                                     url="https://x/a", requested_burst_size=3, finding_id="F1")
        self.assertTrue(first.allowed)
        self.assertEqual(first.allowed_burst_size, 3)
        # budget now exhausted -> a second mutating send for F1 is denied
        second = gate.authorize(validator_name="race", method="POST",
                                url="https://x/a", finding_id="F1")
        self.assertFalse(second.allowed)

    def test_reset_finding_budget_clears(self):
        gate = self._gate(ceiling=1)
        self.assertTrue(gate.authorize(validator_name="s", method="POST",
                                       url="https://x/a", finding_id="F1").allowed)
        self.assertFalse(gate.authorize(validator_name="s", method="POST",
                                        url="https://x/a", finding_id="F1").allowed)
        gate.reset_finding_budget("F1")
        self.assertTrue(gate.authorize(validator_name="s", method="POST",
                                       url="https://x/a", finding_id="F1").allowed)

    def test_safe_methods_never_counted(self):
        gate = self._gate(ceiling=1)
        for _ in range(10):
            self.assertTrue(gate.authorize(validator_name="s", method="GET",
                                           url="https://x/a", finding_id="F1").allowed)


if __name__ == "__main__":
    unittest.main()



