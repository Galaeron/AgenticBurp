"""Tests for the flag-only hand-off (V2/V37): a finding whose class has no
automated confirmation leg is surfaced for human verification -- never
fake-confirmed, never dropped."""
import unittest

from harness import engagement
from harness.engagement import needs_human_review, EngagementState


class NeedsHumanReviewTests(unittest.TestCase):
    def test_no_leg_class_is_flagged(self):
        # information_disclosure has no deterministic confirmation leg -> flag.
        spec = needs_human_review("information_disclosure", "https://t.test/api/debug")
        self.assertIsNotNone(spec)
        self.assertIn("human verification", spec["needs"])
        self.assertIn("no automated confirmation leg", spec["reason"])

    def test_class_with_a_leg_is_not_flagged(self):
        # sqli has a live leg -> the confirmation path owns it, not the hand-off.
        self.assertIsNone(needs_human_review("sqli", "https://t.test/api/x"))
        self.assertIsNone(needs_human_review("idor", "https://t.test/api/x/1"))
        # a provisional-leg class also has a leg -> not flag-only.
        self.assertIsNone(needs_human_review("rate_limit", "https://t.test/login"))

    def test_business_logic_deferred_to_its_own_handoff(self):
        # business logic has a richer hand-off; needs_human_review must NOT also
        # claim it (no double-flag).
        self.assertIsNone(needs_human_review("business_logic", "https://t.test/checkout"))


class FlagUnconfirmableTests(unittest.TestCase):
    def test_flags_add_a_blocked_verify_task(self):
        st = EngagementState(host="t.test")
        added = st.flag_unconfirmable("information_disclosure", "https://t.test/api/debug")
        self.assertTrue(added)
        blocked = st.blocked()
        self.assertTrue(any(t.get("kind") == "verify" for t in blocked),
                        "no blocked 'verify' task was surfaced for the no-leg finding")

    def test_no_task_for_confirmable_class(self):
        st = EngagementState(host="t.test")
        self.assertFalse(st.flag_unconfirmable("sqli", "https://t.test/api/x"))

    def test_dedup_same_target(self):
        st = EngagementState(host="t.test")
        st.flag_unconfirmable("information_disclosure", "https://t.test/api/debug")
        st.flag_unconfirmable("information_disclosure", "https://t.test/api/debug")
        verify = [t for t in st.blocked() if t.get("kind") == "verify"]
        self.assertEqual(len(verify), 1)


if __name__ == "__main__":
    unittest.main()
