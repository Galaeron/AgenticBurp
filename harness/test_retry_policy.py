import unittest
from harness.retry_policy import RetryPolicy, Attempt, AttemptStatus, Action


def default_attempt(status, payload="p", confidence=0.0):
    return Attempt(status=status, model="llama3.1:8b", escalated=False, payload=payload, confidence=confidence)


def escalated_attempt(status, confidence=0.0):
    return Attempt(status=status, model="llama3.1:70b", escalated=True, payload="p", confidence=confidence)


class RetryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = RetryPolicy(max_default_attempts=3)

    def test_first_call_with_no_attempts_retries(self):
        self.assertEqual(self.policy.decide([], 0.5, "medium"), Action.RETRY_DEFAULT)

    def test_confirmed_stops_immediately_regardless_of_history_length(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED), default_attempt(AttemptStatus.CONFIRMED)]
        self.assertEqual(self.policy.decide(attempts, 0.9, "critical"), Action.STOP_CONFIRMED)

    def test_retries_on_default_model_up_to_max_attempts(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED)]
        self.assertEqual(self.policy.decide(attempts, 0.3, "low"), Action.RETRY_DEFAULT)
        attempts.append(default_attempt(AttemptStatus.NOT_CONFIRMED))
        self.assertEqual(self.policy.decide(attempts, 0.3, "low"), Action.RETRY_DEFAULT)

    def test_escalates_exactly_once_after_max_default_attempts(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED) for _ in range(3)]
        self.assertEqual(self.policy.decide(attempts, 0.3, "low"), Action.ESCALATE)

    def test_never_escalates_twice_even_if_called_again_after_escalation(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED) for _ in range(3)]
        attempts.append(escalated_attempt(AttemptStatus.NOT_CONFIRMED))
        action = self.policy.decide(attempts, 0.3, "low")
        self.assertIn(action, (Action.STOP_INCONCLUSIVE, Action.HANDOVER_MANUAL))
        self.assertNotEqual(action, Action.ESCALATE)

    def test_low_suspicion_after_escalation_stops_inconclusive_silently(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED) for _ in range(3)]
        attempts.append(escalated_attempt(AttemptStatus.NOT_CONFIRMED))
        # low original confidence, low severity, no SUPPORTED signal anywhere
        self.assertEqual(self.policy.decide(attempts, 0.2, "low"), Action.STOP_INCONCLUSIVE)

    def test_high_confidence_high_severity_after_escalation_hands_over_to_operator(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED) for _ in range(3)]
        attempts.append(escalated_attempt(AttemptStatus.NOT_CONFIRMED))
        self.assertEqual(self.policy.decide(attempts, 0.8, "critical"), Action.HANDOVER_MANUAL)

    def test_partial_supported_signal_hands_over_even_with_low_original_confidence(self):
        attempts = [default_attempt(AttemptStatus.NOT_CONFIRMED),
                    default_attempt(AttemptStatus.SUPPORTED),
                    default_attempt(AttemptStatus.NOT_CONFIRMED)]
        attempts.append(escalated_attempt(AttemptStatus.NOT_CONFIRMED))
        # low original confidence/severity, but a real partial signal was seen mid-attempt
        self.assertEqual(self.policy.decide(attempts, 0.2, "low"), Action.HANDOVER_MANUAL)

    def test_is_suspicious_directly(self):
        attempts_with_signal = [default_attempt(AttemptStatus.SUPPORTED)]
        self.assertTrue(self.policy.is_suspicious(attempts_with_signal, 0.1, "info"))
        attempts_without_signal = [default_attempt(AttemptStatus.NOT_CONFIRMED)]
        self.assertFalse(self.policy.is_suspicious(attempts_without_signal, 0.1, "info"))
        self.assertTrue(self.policy.is_suspicious(attempts_without_signal, 0.9, "critical"))


if __name__ == "__main__":
    unittest.main()
