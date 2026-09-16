"""
Tests for active_verification.py -- the first caller of retry_policy.py
and payload_library.py since both modules were written (confirmed by
grep: no other file references either name before this one existed).

Uses a real sqlite store (module-level _DB_PATH, same pattern
test_coverage.py and others already use) rather than mocking store.py,
since the whole point of this module is the read-after-write lineage
query in store.get_lineage_attempts.
"""
import os
import tempfile
import unittest
from unittest.mock import AsyncMock

from harness import store
from harness import active_verification
from harness.models import TestPlan, ValidationSubmission
from harness.ollama_client import OllamaError


def _make_plan(category="xss", severity="high", confidence=0.7, escalated=False,
                plan_suffix="1"):
    return TestPlan(
        id=f"plan-{plan_suffix}",
        capability="reflection_context_validation",
        finding_class="xss",
        category=category,
        source_exchange_url="https://active-verification-test.invalid/search?q=x",
        mutation={"strategy": "validator-defined"},
        execution_plane="burp",
        source_exchange_hash="hash-abc",
        severity=severity,
        confidence=confidence,
        escalated=escalated,
    )


def _submission(plan_id, status, confirmed=False, context_tags=None):
    return ValidationSubmission(
        plan_id=plan_id, status=status, confirmed=confirmed,
        executor="burp:reflection_context_validation",
        source_exchange_hash="hash-abc",
        context_tags=context_tags or [],
    )


class ActiveVerificationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = store._DB_PATH
        store._DB_PATH = os.path.join(self._tmp.name, "test.db")

    def tearDown(self):
        store._DB_PATH = self._orig_db_path
        self._tmp.cleanup()

    def _persist_and_submit(self, plan, submission):
        store.persist_retry_plan(plan)
        ok, reason = store.persist_validation_submission(submission)
        self.assertTrue(ok, reason)

    async def test_confirmed_submission_produces_no_next_step(self):
        # status == "confirmed" alone (without the confirmed flag) is what
        # decide_next_step actually treats as "done, stop" here -- this
        # test deliberately uses confirmed=False to isolate that from
        # store.py's separate confirmation_capabilities allowlist check
        # (reflection_context_validation IS on that allowlist as of this
        # session's B2 audit -- see store.py's own comment -- but that's
        # a persistence-layer concern, not what this test exercises).
        plan = _make_plan()
        submission = _submission(plan.id, "confirmed", confirmed=False)
        self._persist_and_submit(plan, submission)
        plan_row = store.get_test_plan(plan.id)

        step = await active_verification.decide_next_step(plan_row, submission)

        self.assertIsNone(step.next_plan)
        self.assertFalse(step.handover_required)

    async def test_non_retryable_category_produces_no_next_step(self):
        """sqlmap's capability isn't in payload_library-backed categories
        the same way -- and more importantly it's local_tool, not burp."""
        plan = _make_plan(category="sqli")
        plan.execution_plane = "local_tool"
        submission = _submission(plan.id, "not_confirmed")
        submission.executor = "local_tool:reflection_context_validation"
        self._persist_and_submit(plan, submission)
        plan_row = store.get_test_plan(plan.id)

        step = await active_verification.decide_next_step(plan_row, submission)

        self.assertIsNone(step.next_plan)

    async def test_not_confirmed_retryable_finding_gets_a_new_payload(self):
        plan = _make_plan()
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)
        plan_row = store.get_test_plan(plan.id)

        step = await active_verification.decide_next_step(plan_row, submission)

        self.assertIsNotNone(step.next_plan)
        self.assertEqual(step.next_plan.category, "xss")
        self.assertFalse(step.next_plan.escalated)
        self.assertTrue(step.next_plan.mutation["payload"])

    async def test_retry_never_reoffers_an_already_tried_payload(self):
        plan = _make_plan()
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)
        plan_row = store.get_test_plan(plan.id)
        first_step = await active_verification.decide_next_step(plan_row, submission)
        first_payload = first_step.next_plan.mutation["payload"]

        # Simulate the execution plane trying the new plan and it also failing.
        second_submission = _submission(first_step.next_plan.id, "not_confirmed")
        self._persist_and_submit(first_step.next_plan, second_submission)
        second_plan_row = store.get_test_plan(first_step.next_plan.id)

        second_step = await active_verification.decide_next_step(second_plan_row, second_submission)

        self.assertIsNotNone(second_step.next_plan)
        self.assertNotEqual(second_step.next_plan.mutation["payload"], first_payload)

    async def test_library_exhaustion_escalates_via_llm(self):
        plan = _make_plan(severity="critical", confidence=0.9)
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)

        # RetryPolicy's default max_default_attempts=3 counts the ORIGINAL
        # attempt as #1, so exactly 2 RETRY_DEFAULT decisions follow (using
        # 2 of the xss library's 4 curated payloads) before attempt #3
        # trips ESCALATE -- retry_policy.py bounds attempts on the default
        # model, it does not promise to exhaust the curated library first.
        current_plan_row = store.get_test_plan(plan.id)
        current_submission = submission
        for _ in range(2):
            step = await active_verification.decide_next_step(current_plan_row, current_submission)
            self.assertIsNotNone(step.next_plan, "expected a curated candidate at this stage")
            current_plan_row_id = step.next_plan.id
            current_submission = _submission(current_plan_row_id, "not_confirmed")
            self._persist_and_submit(step.next_plan, current_submission)
            current_plan_row = store.get_test_plan(current_plan_row_id)

        mock_client = AsyncMock()
        mock_client.chat_json.return_value = {
            "payload": "<svg/onload=__CANARY__>", "rationale": "no tag-based payload tried yet",
        }
        final_step = await active_verification.decide_next_step(
            current_plan_row, current_submission, ollama_client=mock_client,
        )

        self.assertIsNotNone(final_step.next_plan)
        self.assertTrue(final_step.next_plan.escalated)
        self.assertEqual(final_step.next_plan.mutation["payload"], "<svg/onload=__CANARY__>")
        mock_client.chat_json.assert_awaited_once()

    async def test_escalation_llm_failure_degrades_gracefully(self):
        plan = _make_plan(severity="critical", confidence=0.9)
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)
        current_plan_row = store.get_test_plan(plan.id)
        current_submission = submission
        for _ in range(2):
            step = await active_verification.decide_next_step(current_plan_row, current_submission)
            current_plan_row_id = step.next_plan.id
            current_submission = _submission(current_plan_row_id, "not_confirmed")
            self._persist_and_submit(step.next_plan, current_submission)
            current_plan_row = store.get_test_plan(current_plan_row_id)

        mock_client = AsyncMock()
        mock_client.chat_json.side_effect = OllamaError("model unreachable")

        final_step = await active_verification.decide_next_step(
            current_plan_row, current_submission, ollama_client=mock_client,
        )

        self.assertIsNone(final_step.next_plan)
        self.assertFalse(final_step.handover_required)
        self.assertIn("escalation LLM call failed", final_step.note)

    async def test_high_suspicion_after_escalation_requires_handover(self):
        plan = _make_plan(severity="critical", confidence=0.9)
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)
        current_plan_row = store.get_test_plan(plan.id)
        current_submission = submission
        for _ in range(2):
            step = await active_verification.decide_next_step(current_plan_row, current_submission)
            current_plan_row_id = step.next_plan.id
            current_submission = _submission(current_plan_row_id, "not_confirmed")
            self._persist_and_submit(step.next_plan, current_submission)
            current_plan_row = store.get_test_plan(current_plan_row_id)

        mock_client = AsyncMock()
        mock_client.chat_json.return_value = {"payload": "<svg/onload=__CANARY__>", "rationale": "r"}
        escalated_step = await active_verification.decide_next_step(
            current_plan_row, current_submission, ollama_client=mock_client,
        )
        escalated_submission = _submission(escalated_step.next_plan.id, "not_confirmed")
        self._persist_and_submit(escalated_step.next_plan, escalated_submission)
        escalated_plan_row = store.get_test_plan(escalated_step.next_plan.id)

        final_step = await active_verification.decide_next_step(escalated_plan_row, escalated_submission)

        self.assertIsNone(final_step.next_plan)
        self.assertTrue(final_step.handover_required)

    async def test_no_ollama_client_at_escalation_time_stops_without_crashing(self):
        plan = _make_plan(severity="critical", confidence=0.9)
        submission = _submission(plan.id, "not_confirmed")
        self._persist_and_submit(plan, submission)
        current_plan_row = store.get_test_plan(plan.id)
        current_submission = submission
        for _ in range(2):
            step = await active_verification.decide_next_step(current_plan_row, current_submission)
            current_plan_row_id = step.next_plan.id
            current_submission = _submission(current_plan_row_id, "not_confirmed")
            self._persist_and_submit(step.next_plan, current_submission)
            current_plan_row = store.get_test_plan(current_plan_row_id)

        final_step = await active_verification.decide_next_step(current_plan_row, current_submission)

        self.assertIsNone(final_step.next_plan)
        self.assertFalse(final_step.handover_required)


if __name__ == "__main__":
    unittest.main()
