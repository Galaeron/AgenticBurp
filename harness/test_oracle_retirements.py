"""
Negative controls for the confirmation-oracle RETIREMENTS (review 2026-09-09).

Each leg here used to emit confirmed=True from evidence that does not exclude a
benign explanation. The retirement stands the verdict down to a not_confirmed
OBSERVATION while keeping the detector. These tests assert the leg no longer
confirms from the previously-overconfirming input. See ORACLE_RETIREMENTS.md.
"""
import asyncio
import unittest

from harness.models import Finding, HttpExchange


def _f(cls, sev="high"):
    return Finding(vulnerability_class=cls, confidence=0.5, severity=sev, summary="s",
                   evidence="e", suggested_test="t", basis="derived")


class PassiveDeserializationRetired(unittest.TestCase):
    def test_format_signature_is_observation_not_confirmation(self):
        from harness.validators.deserialization_validator import DeserializationValidator
        ex = HttpExchange(url="http://t/api", method="POST", request_headers={},
                          request_body='a:1:{i:0;s:3:"foo";}',  # PHP serialized format
                          response_status=200, response_headers={}, response_body="")
        r = asyncio.run(DeserializationValidator().validate(_f("deserialization"), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("observed", r.summary.lower())   # kept as an informational lead


if __name__ == "__main__":
    unittest.main()
