import unittest

from harness.identity_compare import Probe, Verdict, MATCH_THRESHOLD, evaluate, similarity


class IdentityCompareLogicTests(unittest.TestCase):
    """Ported 1:1 from IdentityCompareLogicTest.java (the 12 cases that
    exercise evaluate()/similarity() -- the 4 UrlIdentifierDiff cases in
    that file are out of scope, see the implementation plan)."""

    def test_public_resource_is_not_confirmed(self):
        source = Probe(200, "<html>home page A</html>")
        candidate = Probe(200, "<html>home page B</html>")
        attempt = Probe(200, "<html>home page B</html>")
        anon = Probe(200, "<html>home page B</html>")  # anon sees the same thing -> public
        ev = evaluate("cross_identity_compare", True, source, candidate, attempt, anon)
        self.assertEqual(ev.verdict, Verdict.INCONCLUSIVE)
        self.assertFalse(ev.confirmed, "a public resource must never be confirmed")

    def test_genuine_access_is_confirmed(self):
        source = Probe(200, '{"basket":1,"items":["identity A\'s own item"]}')
        candidate = Probe(200, '{"basket":4,"items":["identity B\'s private item"]}')
        attempt = Probe(200, '{"basket":4,"items":["identity B\'s private item"]}')  # A's session got B's data
        anon = Probe(401, '{"error":"authentication required"}')
        ev = evaluate("cross_identity_compare", True, source, candidate, attempt, anon)
        self.assertEqual(ev.verdict, Verdict.CONFIRMED)
        self.assertTrue(ev.confirmed)
        self.assertGreater(ev.confidence, 0.85)

    def test_denied_attempt_is_rejected(self):
        source = Probe(200, '{"basket":1,"items":["identity A\'s own item"]}')
        candidate = Probe(200, '{"basket":4,"items":["identity B\'s private item"]}')
        attempt = Probe(403, '{"error":"forbidden"}')  # access control worked correctly
        anon = Probe(403, '{"error":"forbidden"}')
        ev = evaluate("cross_identity_compare", True, source, candidate, attempt, anon)
        self.assertEqual(ev.verdict, Verdict.REJECTED)
        self.assertFalse(ev.confirmed)

    def test_missing_anon_baseline_cannot_confirm(self):
        source = Probe(200, '{"basket":1,"items":["A\'s item"]}')
        candidate = Probe(200, '{"basket":4,"items":["B\'s item"]}')
        attempt = Probe(200, '{"basket":4,"items":["B\'s item"]}')
        ev = evaluate("cross_identity_compare", True, source, candidate, attempt, None)
        self.assertNotEqual(ev.verdict, Verdict.CONFIRMED)
        self.assertFalse(ev.confirmed)
        self.assertEqual(ev.verdict, Verdict.SUPPORTED)

    def test_idor_requires_identifier_change(self):
        source = Probe(200, "same")
        candidate = Probe(200, "same")
        attempt = Probe(200, "same")
        anon = Probe(403, "denied")
        ev = evaluate("cross_identity_compare", False, source, candidate, attempt, anon)
        self.assertEqual(ev.verdict, Verdict.INVALID)

    def test_boundary_compare_ignores_identifier_flag(self):
        source = Probe(200, "regular user's own view")
        candidate = Probe(200, "admin-only panel contents")
        attempt = Probe(200, "admin-only panel contents")  # same URL replayed with A's session
        anon = Probe(302, "redirect to login")
        ev = evaluate("authorization_boundary_compare", False, source, candidate, attempt, anon)
        self.assertEqual(ev.verdict, Verdict.CONFIRMED)

    def test_status_mismatch_prevents_confirmation(self):
        # Bodies coincidentally match (e.g. both near-empty), but status differs.
        source = Probe(200, "")
        candidate = Probe(200, "")
        attempt = Probe(500, "")  # server error, not real access
        anon = Probe(403, "denied")
        ev = evaluate("cross_identity_compare", True, source, candidate, attempt, anon)
        self.assertNotEqual(ev.verdict, Verdict.CONFIRMED)

    def test_similarity_identical(self):
        self.assertEqual(similarity("abcdef", "abcdef"), 1.0)

    def test_similarity_disjoint(self):
        s = similarity("aaaaaa", "zzzzzz")
        self.assertEqual(s, 0.0)

    def test_similarity_near_identical(self):
        a = '{"user":"alice","csrf":"AAAAAAAAAA","balance":100}'
        b = '{"user":"alice","csrf":"BBBBBBBBBB","balance":100}'
        s = similarity(a, b)
        self.assertGreaterEqual(s, MATCH_THRESHOLD)

    def test_similarity_different_content_same_shape(self):
        # Two genuinely different resources that happen to share JSON
        # boilerplate must NOT score above threshold -- the false-positive
        # direction, checked alongside the false-negative one above.
        a = '{"user":"alice","csrf":"AAAAAAAAAA","balance":100}'
        b = '{"user":"carol","csrf":"CCCCCCCCCC","balance":250}'
        s = similarity(a, b)
        self.assertLess(s, MATCH_THRESHOLD)

    def test_similarity_realistic_length_token(self):
        big1 = ('{"basketId":4,"userId":9,"csrfToken":"AAAAAAAAAAAAAAAAAAAA","items":'
                '[{"id":1,"name":"Widget","price":19.99,"qty":2},{"id":2,"name":"Gadget",'
                '"price":9.99,"qty":1}],"total":49.97}')
        big2 = big1.replace("AAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBB")
        s = similarity(big1, big2)
        self.assertGreaterEqual(s, MATCH_THRESHOLD)


if __name__ == "__main__":
    unittest.main()
