"""
Tests for anomaly_detector.py -- no test file existed for this module
before this one, which is part of why the bug these tests exist to
catch went unnoticed for so long.

Regression tests for a real bug found during a live scoring pass
against testing/test-target/: a path-traversal exchange (a blatant
`../` in a query parameter) produced ZERO findings from this detector,
even after fast_path.py was fixed to dispatch the `anomaly` agent for
it. Root cause: detect_anomalies() gated EVERY check -- including the
deterministic, baseline-independent suspicious_patterns regex match,
which already explicitly lists path traversal -- behind having seen
min_exchanges_for_baseline (10) prior exchanges for the host. That
threshold makes sense for genuinely baseline-dependent statistical
checks (is this response size an outlier relative to history?), but a
`../` in a URL is exactly as suspicious on the very first exchange for
a host as on the hundredth.
"""
import unittest

from harness.anomaly_detector import AnomalyDetector
from harness.agents.anomaly_agent import AnomalyAgent
from harness.models import HttpExchange


def _exchange(url="https://example.test/api/x", method="GET", **kwargs):
    defaults = dict(
        url=url, method=method, request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="",
    )
    defaults.update(kwargs)
    return HttpExchange(**defaults)


class TestPatternDetectionIsBaselineIndependent(unittest.TestCase):
    """The core regression: pattern-based checks must fire on the very
    first exchange for a host, with no prior history at all."""

    def test_path_traversal_detected_on_first_exchange_no_baseline(self):
        detector = AnomalyDetector(min_exchanges_for_baseline=10)
        exchange = _exchange(url="https://example.test/api/invoices/download?file=../app.py")

        detector.update_profile(exchange)
        anomalies = detector.detect_anomalies(exchange)

        self.assertTrue(
            any("\\.\\./" in a.evidence or ".." in a.evidence for a in anomalies),
            f"Expected a path-traversal pattern match on the first exchange, got: {anomalies}",
        )

    def test_sensitive_parameter_name_detected_on_first_exchange(self):
        """_detect_parameter_anomalies also takes no `profile` argument
        -- confirm it's genuinely baseline-independent too, not just
        the pattern check."""
        detector = AnomalyDetector(min_exchanges_for_baseline=10)
        exchange = _exchange(
            url="https://example.test/api/reset?api_key=abc123",
            request_headers={}, request_body="",
        )
        detector.update_profile(exchange)
        anomalies = detector.detect_anomalies(exchange)
        self.assertTrue(
            any(a.anomaly_type == "sensitive_parameter" for a in anomalies),
            f"Expected a sensitive-parameter anomaly, got: {anomalies}",
        )

    def test_statistical_anomaly_still_requires_a_real_baseline(self):
        """The fix must not remove the baseline requirement for checks
        that genuinely need it -- a response-size outlier is
        meaningless without a real average to compare against."""
        detector = AnomalyDetector(min_exchanges_for_baseline=10)
        exchange = _exchange(response_body="x" * 100000)  # huge, but no history yet

        detector.update_profile(exchange)
        anomalies = detector.detect_anomalies(exchange)

        self.assertFalse(
            any(a.anomaly_type == "response_size_outlier" for a in anomalies),
            "Statistical anomalies should not fire before a real baseline exists",
        )


class TestClusteringDoesNotSwallowUnclusteredAnomalies(unittest.TestCase):
    """
    Regression test for the most severe of the three bugs found in this
    file during the same live scoring pass: a single real exchange
    (path traversal in the URL, which ALSO happens to be missing 3+
    security headers -- true of almost every response) produced only
    ONE generic finding ("Multiple anomalies detected: unknown_anomaly")
    and completely lost the specific, valuable path-traversal evidence.
    generate_findings() tracked "already reported" anomalies by
    exchange_fingerprint, which is identical for every anomaly from one
    exchange regardless of type -- so the instant the 6 unrelated
    missing_security_header anomalies clustered, the 2 completely
    different suspicious_pattern anomalies from the SAME exchange got
    silently treated as already-covered and dropped, even though they
    were never part of that cluster. Fixed by tracking clustered
    anomalies by object identity instead.
    """

    def test_unclustered_anomaly_from_a_partially_clustered_exchange_still_gets_a_finding(self):
        detector = AnomalyDetector(min_exchanges_for_baseline=10)
        exchange = _exchange(
            url="https://test-clustering-fix.invalid/api/invoices/download?file=../app.py",
            response_headers={},  # no security headers at all -> 6 missing_security_header anomalies
        )
        detector.update_profile(exchange)
        anomalies = detector.detect_anomalies(exchange)
        findings = detector.generate_findings(anomalies)

        classes = [f.vulnerability_class for f in findings]
        self.assertIn(
            "suspicious_pattern", classes,
            f"The path-traversal finding must survive even though a different "
            f"anomaly type from the same exchange clustered. Got: {classes}",
        )
        # The cluster's own finding should also still be present, correctly
        # classified now (see _suggest_vulnerability_class's field-agnostic
        # fallback) rather than falling through to 'unknown_anomaly'.
        self.assertIn("security_misconfiguration", classes)


class TestVulnerabilityClassMappingIsComplete(unittest.TestCase):
    """Every anomaly_type the codebase can actually produce must resolve
    to something other than 'unknown_anomaly' -- found live: two real
    types (parameter_count_outlier, url_depth_outlier) were missing
    from the mapping table entirely."""

    def test_every_real_anomaly_type_has_a_mapping(self):
        detector = AnomalyDetector()
        # Every anomaly_type= string literal actually used anywhere in
        # anomaly_detector.py (confirmed by grep, not guessed).
        real_types = [
            "information_disclosure_header", "json_as_html", "json_as_plain_text",
            "long_parameter_value", "missing_security_header", "parameter_count_outlier",
            "rare_content_type", "rare_status_code", "repeated_characters",
            "response_size_outlier", "sensitive_parameter", "unexpected_server_error",
            "url_depth_outlier",
            # suspicious_pattern is intentionally field-specific -- checked separately below.
        ]
        for t in real_types:
            with self.subTest(anomaly_type=t):
                self.assertNotEqual(
                    detector._suggest_vulnerability_class(t, "some_field"), "unknown_anomaly",
                    f"'{t}' has no mapping -- add one to _suggest_vulnerability_class",
                )

    def test_suspicious_pattern_still_resolves_per_field(self):
        detector = AnomalyDetector()
        self.assertEqual(detector._suggest_vulnerability_class("suspicious_pattern", "url"), "path_traversal")
        self.assertEqual(detector._suggest_vulnerability_class("suspicious_pattern", "request_body"), "injection")
        self.assertEqual(detector._suggest_vulnerability_class("suspicious_pattern", "response_body"), "information_disclosure")


class TestClusteringIsScopedPerExchange(unittest.TestCase):
    """
    Regression test for the real architectural bug behind TN4's
    "unknown_anomaly" false signal during a live scoring pass:
    cluster_anomalies() used to default to self.anomalies, the GLOBAL
    accumulator across the entire session for a host -- so a cluster
    reported for exchange N could silently include anomaly types
    contributed by an earlier, unrelated exchange. Since this harness
    analyzes one exchange per call with nothing ever reviewing
    session-wide clusters, that cross-exchange leakage had no offsetting
    benefit. Fixed by scoping clustering to the anomalies list passed
    into generate_findings(), not the growing session history.
    """

    def test_a_later_exchanges_findings_are_not_polluted_by_an_earlier_one(self):
        detector = AnomalyDetector(min_exchanges_for_baseline=10)

        # First exchange: contributes a distinctive anomaly type/field
        # combo that is NOT in the mapping table on its own (simulated
        # directly, since the point is to test the SCOPING, not to find
        # a real second unmapped type).
        first = _exchange(url="https://test-clustering-scope.invalid/a")
        detector.update_profile(first)
        first_anomalies = detector.detect_anomalies(first)
        detector.generate_findings(first_anomalies)  # populates self.anomalies

        # Second, later exchange: a genuine path-traversal case.
        second = _exchange(url="https://test-clustering-scope.invalid/b?file=../app.py")
        detector.update_profile(second)
        second_anomalies = detector.detect_anomalies(second)
        second_findings = detector.generate_findings(second_anomalies)

        # The second exchange's OWN findings must only reflect its own
        # anomalies -- not a cluster inflated by counts left over from
        # the first exchange. Unclustered anomalies (this pair of
        # suspicious_pattern hits, only 2 -- below the 3-item cluster
        # threshold) keep their raw anomaly_type rather than going
        # through _suggest_vulnerability_class, which only applies to
        # clustered findings; the real assertion is that nothing here
        # is the generic 'unknown_anomaly' fallback that cross-exchange
        # leakage used to produce.
        classes = [f.vulnerability_class for f in second_findings]
        self.assertIn("suspicious_pattern", classes)
        self.assertNotIn("unknown_anomaly", classes)


class TestUrlPatternScanExcludesTargetHost(unittest.TestCase):
    """Regression test: _detect_pattern_anomalies used to scan the FULL
    exchange.url (scheme://host:port included), which flagged the
    target's own host (e.g. http://127.0.0.1:5001) against the
    localhost/SSRF pattern on every single exchange -- a systematic
    false positive found live via fp_benchmark.py. Fixed by scanning
    only the URL path + query, where real payloads actually live."""

    def test_target_host_not_flagged_but_path_payload_still_is(self):
        detector = AnomalyDetector()
        # benign request to a localhost target -- must NOT flag the host itself
        benign = _exchange(url="http://127.0.0.1:5001/api/products", response_body="[]")
        a1 = detector._detect_pattern_anomalies(benign)
        self.assertFalse(
            any(a.anomaly_type == "suspicious_pattern" for a in a1),
            f"The target's own host should never be flagged, got: {a1}",
        )
        # a real path-traversal payload in the path MUST still be flagged
        evil = _exchange(
            url="http://127.0.0.1:5001/download?file=../../etc/passwd",
            response_body="root:x:0:0",
        )
        a2 = detector._detect_pattern_anomalies(evil)
        self.assertTrue(
            any(a.anomaly_type == "suspicious_pattern" for a in a2),
            f"Expected a path-traversal pattern match in the URL path/query, got: {a2}",
        )


class TestResponseScanExcludesAttackInputSyntax(unittest.TestCase):
    """Regression test: _check_patterns used to scan RESPONSE bodies/headers
    with the full attack-INPUT pattern list (command/SQL/NoSQL injection). That
    matched ordinary response text -- a 'Server: Werkzeug Python' header (the
    command-injection word list matches 'Python'), the words 'in'/'where'
    (NoSQL operators) -- as suspicious on nearly every benign exchange, a
    systematic false positive found live. Fixed by scanning responses only with
    response_evidence_patterns. Request-side scanning and genuine response
    evidence (XSS output, disclosure) are unchanged."""

    def test_python_server_header_no_longer_flagged(self):
        detector = AnomalyDetector()
        ex = _exchange(url="http://127.0.0.1:5001/api/products", response_body="[]",
                       response_headers={"Server": "Werkzeug/3.1.7 Python/3.12.3"})
        a = detector._detect_pattern_anomalies(ex)
        self.assertFalse(
            any(x.anomaly_type == "suspicious_pattern" for x in a),
            f"A benign 'Server: ... Python' header must not be a suspicious pattern, got: {a}",
        )

    def test_command_injection_in_request_still_flagged(self):
        detector = AnomalyDetector()
        ex = _exchange(url="http://127.0.0.1:5001/run?cmd=;bash")
        a = detector._detect_pattern_anomalies(ex)
        self.assertTrue(
            any(x.anomaly_type == "suspicious_pattern" for x in a),
            "A command-injection payload in the request URL must still be flagged.",
        )

    def test_xss_evidence_in_response_still_flagged(self):
        detector = AnomalyDetector()
        ex = _exchange(url="http://127.0.0.1:5001/comments",
                       response_body="<div><script>alert(1)</script></div>")
        a = detector._detect_pattern_anomalies(ex)
        self.assertTrue(
            any(x.anomaly_type == "suspicious_pattern" for x in a),
            "Reflected/stored <script> in the response is real evidence and must still be flagged.",
        )


class TestAnomalyAgentEndToEnd(unittest.IsolatedAsyncioTestCase):
    """Exercises the real dispatch path (AnomalyAgent.run(), which
    bypasses the LLM entirely) rather than the detector in isolation --
    this is the path fast_path.py's own dispatch fix relies on."""

    async def test_agent_produces_a_finding_for_path_traversal_on_first_call(self):
        agent = AnomalyAgent(None, "n/a")
        # Distinctive host: AnomalyAgent.run() uses the module-level
        # singleton detector, whose per-host profiles persist across
        # every test in the process -- a shared host name could pick up
        # baseline state left behind by another test.
        exchange = _exchange(url="https://test-anomaly-agent-e2e.invalid/api/invoices/download?file=../app.py")

        report = await agent.run(exchange, 6000, "", None)

        self.assertGreater(len(report.findings), 0)
        self.assertTrue(any("\\.\\./" in f.evidence for f in report.findings))


if __name__ == "__main__":
    unittest.main()
