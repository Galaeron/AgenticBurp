import unittest
from harness.chaining import detect, _tags_for
from harness.categories import CANONICAL_CATEGORIES


def finding(url, vulnerability_class, summary="", severity="medium", confidence=0.8):
    return {"url": url, "vulnerability_class": vulnerability_class,
            "severity": severity, "confidence": confidence, "summary": summary}


class TestEveryCanonicalCategoryHasChainParticipation(unittest.TestCase):
    """
    Regression test for the coverage audit this session: 30 of 36
    canonical categories, including sqli itself, had zero path into
    any chain rule before the canonicalize()-based auto-tagging fix.
    """
    def test_no_canonical_category_is_untaggable(self):
        untaggable = [cat for cat in CANONICAL_CATEGORIES if not _tags_for(cat, "")]
        self.assertEqual(untaggable, [],
                          f"These canonical categories can never participate in any "
                          f"chain rule: {untaggable}")


class TestRealisticFreeTextTagging(unittest.TestCase):
    """
    vulnerability_class is genuinely free text from the LLM (no enum
    constraint in the JSON schema) -- these test realistic phrasing,
    not clean canonical strings, since that's the actual failure mode.
    """
    def test_race_condition_realistic_phrasing_tags_correctly(self):
        tags = _tags_for("Race Condition (TOCTOU) on coupon redemption", "")
        self.assertIn("race_condition", tags)

    def test_oauth_realistic_phrasing_tags_correctly(self):
        tags = _tags_for("OAuth2 authorization flow issue", "")
        self.assertIn("oauth", tags)

    def test_subdomain_takeover_realistic_phrasing_now_tags_via_fallback(self):
        tags = _tags_for("Subdomain Takeover - GitHub Pages", "")
        self.assertIn("subdomain_takeover", tags)

    def test_short_category_name_does_not_match_inside_unrelated_word(self):
        # "auth" is a canonical category; naive substring matching would
        # incorrectly fire on "unauthorized" or "author". Word-boundary
        # matching must not.
        self.assertNotIn("auth", _tags_for("Missing authorization on admin panel", ""))
        self.assertNotIn("auth", _tags_for("Book author field XSS", ""))

    def test_short_category_name_does_match_as_a_standalone_word(self):
        self.assertIn("auth", _tags_for("Weak auth mechanism observed", ""))

    def test_cors_does_not_match_inside_unrelated_word(self):
        # "cors" as a substring shouldn't fire inside an unrelated token.
        self.assertNotIn("cors", _tags_for("Incorrect cursor position in UI", ""))

    def test_exact_canonical_name_always_tags(self):
        for cat in ("sqli", "oauth", "race_condition", "subdomain_takeover",
                    "web_cache_poisoning", "deserialization", "session_fixation"):
            self.assertIn(cat, _tags_for(cat, ""), f"{cat} should tag itself exactly")


class TestNewChainRules(unittest.TestCase):
    def test_subdomain_takeover_plus_oauth_fires(self):
        findings = [
            finding("https://old-blog.example.com/", "subdomain_takeover", "Unclaimed GitHub Pages"),
            finding("https://app.example.com/oauth/authorize", "oauth", "Weak redirect_uri validation"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("subdomain_takeover+oauth" in s for s in sigs), sigs)

    def test_cache_poisoning_plus_xss_fires(self):
        findings = [
            finding("https://example.com/profile", "web_cache_poisoning", "Unkeyed header reflected, cacheable"),
            finding("https://example.com/profile", "xss", "Reflected XSS via name parameter"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("web_cache_poisoning+xss" in s for s in sigs), sigs)

    def test_header_injection_plus_cache_poisoning_fires(self):
        findings = [
            finding("https://example.com/redirect", "header_injection", "CRLF injection confirmed"),
            finding("https://example.com/redirect", "web_cache_poisoning", "Cacheable response"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("header_injection+web_cache_poisoning" in s for s in sigs), sigs)

    def test_deserialization_plus_known_vuln_fires(self):
        findings = [
            finding("https://example.com/state", "deserialization", "Java serialized object confirmed"),
            finding("https://example.com/", "known-vulnerable-dependency", "Advisory GHSA-xxxx confirmed"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("deserialization+known_vuln" in s for s in sigs), sigs)

    def test_session_fixation_plus_xss_fires(self):
        findings = [
            finding("https://example.com/login", "session_fixation", "Session ID unchanged after login"),
            finding("https://example.com/search", "xss", "Reflected XSS"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("session_fixation+xss" in s for s in sigs), sigs)

    def test_websocket_plus_access_control_fires(self):
        findings = [
            finding("https://example.com/ws/chat", "websocket", "No Origin validation on handshake"),
            finding("https://example.com/ws/chat", "idor", "Per-message authorization gap"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("websocket+access_control" in s for s in sigs), sigs)

    def test_open_redirect_plus_oauth_fires_after_the_unreachable_rule_fix(self):
        """
        Regression test: the original rule referenced tag 'oauth_redirect',
        a string the real oauth_agent never emits (it emits 'oauth') --
        making the rule permanently unreachable. Confirms the fix.
        """
        findings = [
            finding("https://example.com/go?url=evil.com", "open_redirect", "Open redirect"),
            finding("https://example.com/oauth/authorize", "oauth", "redirect_uri validation gap"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("open_redirect+oauth" in s and "oauth_redirect" not in s for s in sigs), sigs)

    def test_sqli_plus_idor_fires(self):
        findings = [
            finding("https://example.com/report?id=1", "sqli", "Boolean-blind SQLi confirmed"),
            finding("https://example.com/report?id=1", "idor", "Any user ID accepted regardless of owner"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("sqli+idor" in s for s in sigs), sigs)

    def test_csrf_plus_weak_auth_fires(self):
        findings = [
            finding("https://example.com/change-email", "csrf", "No anti-CSRF token on state change"),
            finding("https://example.com/login", "weak_auth", "Session never expires, survives password reset"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("csrf+weak_auth" in s for s in sigs), sigs)

    def test_xxe_plus_ssrf_fires(self):
        findings = [
            finding("https://example.com/upload", "xxe", "External entity resolution confirmed"),
            finding("https://example.com/upload", "ssrf", "Internal metadata endpoint reachable via entity"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("xxe+ssrf" in s for s in sigs), sigs)

    def test_command_injection_plus_known_vuln_fires(self):
        findings = [
            finding("https://example.com/convert", "command_injection", "Blind command injection via filename param"),
            finding("https://example.com/", "known-vulnerable-dependency", "Advisory GHSA-yyyy confirmed for imagemagick"),
        ]
        chains = detect(findings)
        sigs = [c.vulnerability_class for c in chains]
        self.assertTrue(any("command_injection+known_vuln" in s for s in sigs), sigs)


class TestChainRuleCoverageIsDocumented(unittest.TestCase):
    """
    Follow-up to the audit's chaining.py finding: 24 of 36 canonical
    categories had zero chain-rule path, and the handover's "audited and
    fixed" framing was easy to misread as full coverage when it wasn't.
    Four of the highest-value categories (sqli, csrf, xxe,
    command_injection) were closed as a direct result of that finding.

    This test does NOT assert full coverage -- writing a rule for every
    category would mean inventing escalation narratives with no real
    security basis, which is worse than an honest gap. Instead it pins
    down the *exact* set of categories that remain uncovered, so the
    next session sees a deliberate, named list instead of having to
    recount it from scratch -- and so an accidental change to this list
    (e.g. a rule quietly stops matching due to a tag typo) fails a test
    instead of going unnoticed.
    """

    # Intentionally not chain-covered as of this session. If you add a
    # rule for one of these, remove it from this set as part of that
    # change -- don't let this list silently drift from reality.
    KNOWN_UNCOVERED = frozenset({
        "ai_llm", "anomaly", "api_security", "auth", "business_logic_enhanced",
        "cors", "crypto", "csp", "file_upload", "http_request_smuggling",
        "info_disclosure", "jwt", "misconfig", "nosql", "path_traversal",
        "race_condition", "recon", "session_timeout", "ssti", "supply_chain",
        # session-16: reset_token is a standalone auth-hardening finding, not an
        # escalation primitive that composes into a chain -> intentionally no rule.
        "reset_token",
        # dom_xss composes like xss but has no dedicated chain rule of its own yet.
        "dom_xss",
        # toctou is a standalone atomicity finding; no dedicated chain rule yet.
        "toctou",
    })

    def test_categories_with_no_chain_rule_are_the_known_documented_set(self):
        from harness.chaining import _RULES
        tags_in_rules = set()
        for rule in _RULES:
            tags_in_rules.add(rule.tag_a)
            tags_in_rules.add(rule.tag_b)

        # A category counts as "covered" if its own canonical name (or a
        # _CLASS_TAGS umbrella it belongs to) is used as a tag by some
        # rule -- i.e. a finding of exactly that category, with no
        # special-cased free text, could ever participate in a chain.
        uncovered = {
            cat for cat in CANONICAL_CATEGORIES
            if not (_tags_for(cat, "") & tags_in_rules)
        }

        self.assertEqual(
            uncovered, set(self.KNOWN_UNCOVERED),
            "The set of chain-rule-uncovered categories changed. If you "
            "added a rule, update KNOWN_UNCOVERED to match (that's "
            "progress, not a failure). If this shrank unexpectedly "
            "(fewer categories covered than before), a rule likely "
            "stopped matching -- investigate before updating the "
            "constant."
        )


class TestChainDetectionBasics(unittest.TestCase):
    def test_no_chain_from_unrelated_findings(self):
        findings = [
            finding("https://example.com/a", "info_disclosure", "Verbose error"),
            finding("https://example.com/b", "misconfig", "Missing header"),
        ]
        chains = detect(findings)
        self.assertEqual(chains, [])

    def test_chain_confidence_is_always_capped_at_hypothesis_level(self):
        findings = [
            finding("https://example.com/a", "open_redirect"),
            finding("https://example.com/b", "ssrf"),
        ]
        chains = detect(findings)
        self.assertTrue(chains)
        for c in chains:
            self.assertLessEqual(c.confidence, 0.5,
                                  "chain findings must never claim higher confidence than "
                                  "a rule match on category labels actually supports")
            self.assertEqual(c.basis, "derived")

    def test_same_url_same_tag_does_not_self_chain(self):
        findings = [finding("https://example.com/a", "xss")]
        chains = detect(findings)
        self.assertEqual(chains, [])


class TestDiscoveryChainCandidates(unittest.TestCase):
    def test_post_write_plus_get_read_produces_candidate(self):
        from harness.chaining import discovery_chain_candidates
        exchanges = [
            {"method": "POST", "url": "http://t/api/comments", "request_body": '{"text":"hi"}',
             "response_status": 200, "response_headers": {}},
            {"method": "GET", "url": "http://t/api/posts/1", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "text/html"}},
        ]
        pairs = discovery_chain_candidates(exchanges)
        self.assertTrue(len(pairs) >= 1)
        self.assertEqual(pairs[0]["write_url"], "http://t/api/comments")
        self.assertEqual(pairs[0]["read_url"], "http://t/api/posts/1")

    def test_same_url_not_paired(self):
        from harness.chaining import discovery_chain_candidates
        exchanges = [
            {"method": "POST", "url": "http://t/api/x", "request_body": '{"a":1}',
             "response_status": 200, "response_headers": {}},
            {"method": "GET", "url": "http://t/api/x", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "application/json"}},
        ]
        pairs = discovery_chain_candidates(exchanges)
        self.assertEqual(pairs, [])

    def test_get_only_no_candidates(self):
        from harness.chaining import discovery_chain_candidates
        exchanges = [
            {"method": "GET", "url": "http://t/a", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "text/html"}},
            {"method": "GET", "url": "http://t/b", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "text/html"}},
        ]
        pairs = discovery_chain_candidates(exchanges)
        self.assertEqual(pairs, [])

    def test_kind_is_typed_by_read_content_type(self):
        """R14: the candidate's kind must reflect the read's content-type -- an
        html read is a stored-XSS candidate, a json read a generic second-order
        one -- so the consumer can route each to the RIGHT oracle instead of
        force-routing everything to SQLi (which the previous code did)."""
        from harness.chaining import discovery_chain_candidates
        html = discovery_chain_candidates([
            {"method": "POST", "url": "http://t/api/comments", "request_body": '{"t":"x"}',
             "response_status": 200, "response_headers": {}},
            {"method": "GET", "url": "http://t/page", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "text/html"}},
        ])
        self.assertEqual(html[0]["kind"], "stored_xss")
        js = discovery_chain_candidates([
            {"method": "POST", "url": "http://t/api/comments", "request_body": '{"t":"x"}',
             "response_status": 200, "response_headers": {}},
            {"method": "GET", "url": "http://t/api/search", "request_body": "",
             "response_status": 200, "response_headers": {"Content-Type": "application/json"}},
        ])
        self.assertEqual(js[0]["kind"], "second_order")


if __name__ == "__main__":
    unittest.main()
