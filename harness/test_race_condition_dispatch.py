"""SKL-1: the race burst is prepared before one shared release, and its dispatch is timed."""
import ast
import asyncio
import re
import unittest
from types import SimpleNamespace
from unittest import mock

from harness.models import Finding, HttpExchange
from harness.validators import race_condition_validator as rcv
from harness.validators.race_condition_validator import RaceConditionValidator


def _finding():
    return Finding(vulnerability_class="race_condition", severity="medium", confidence=0.5,
                   summary="race", evidence="candidate", suggested_test="burst",
                   basis="derived")


def _exchange():
    return HttpExchange(url="https://app.test/claim", method="POST",
                        request_headers={"Authorization": "Bearer racer"},
                        request_body='{"claim":true}', response_status=200,
                        response_body="posted")


class _Gate:
    def __init__(self, allowed_burst_size, allowed=True):
        self.allowed_burst_size = allowed_burst_size
        self.allowed = allowed
        self.requested = None

    def authorize_burst(self, **kwargs):
        self.requested = kwargs["requested_burst_size"]
        return SimpleNamespace(allowed=self.allowed, allowed_burst_size=self.allowed_burst_size,
                               reason="test gate")


class _Sessions:
    def __init__(self, log):
        self.log = log

    def bind_headers(self, headers):
        self.log.append("prepare")
        return "user", dict(headers)


class _RecordingExecutor:
    """Records call order; every execute() parks until all expected copies are in flight."""

    def __init__(self, log, responses, expected_concurrent):
        self.log = log
        self.responses = list(responses)
        self.expected = expected_concurrent
        self.in_flight = 0
        self.all_in = asyncio.Event()
        self.calls = 0

    async def execute(self, req, capability, session_ref=None):
        self.log.append("execute")
        self.calls += 1
        self.in_flight += 1
        if self.in_flight >= self.expected:
            self.all_in.set()
        # A serialised burst never reaches `expected` and times out here.
        await asyncio.wait_for(self.all_in.wait(), timeout=2.0)
        status, body, ok = self.responses.pop(0) if self.responses else (200, "ok", True)
        return SimpleNamespace(ok=ok, executed=True, outcome="ok" if ok else "transport_error",
                               status=status, body=body, headers={})


class _Context:
    def __init__(self, gate, executor, log):
        self.gate = gate
        self.sessions = _Sessions(log)
        self._executor = executor

    def executor(self):
        return self._executor


class _StepClock:
    """Deterministic clock: each read advances 1 ms."""

    def __init__(self):
        self.t = 100.0

    def __call__(self):
        self.t += 0.001
        return self.t


def _run(n_allowed, responses, burst_size=None, clock=None, expected=None):
    log = []
    gate = _Gate(n_allowed)
    executor = _RecordingExecutor(log, responses, expected or n_allowed)
    ctx = _Context(gate, executor, log)
    validator = RaceConditionValidator(burst_size=burst_size or n_allowed, run_context=ctx,
                                       clock=clock)
    result = asyncio.run(validator.validate(_finding(), _exchange()))
    return result, log, executor, gate


def _raw(result):
    return ast.literal_eval(result.raw_output)


def _pre_change_verdict(statuses_bodies_ok, original_status=200):
    """The verdict logic as it stood before SKL-1, applied to a fixed response set:
    repeated success is a lead only (no state read-back), and unanswered sends
    make the result inconclusive rather than a negative."""
    responses = [(s, b) for s, b, ok in statuses_bodies_ok if ok]
    failed = len(statuses_bodies_ok) - len(responses)
    if len(responses) < 2:
        if responses and failed:
            return "inconclusive", False, 0.0
        return "error", False, 0.0
    clean = sum(1 for s, b in responses
                if (original_status is None or s == original_status) and s < 400
                and not rcv._REJECTION_MARKERS.search(b or ""))
    repeated = clean >= 2
    if failed and not repeated:
        return "inconclusive", False, 0.0
    return "not_confirmed", False, (0.3 if repeated else 0.2)


class RaceDispatchTests(unittest.TestCase):
    def test_no_copy_sends_before_every_copy_is_prepared_and_spread_is_recorded(self):
        result, log, executor, _ = _run(3, [], clock=_StepClock())
        # Repeated success without a state read-back stays a lead.
        self.assertEqual(result.status, "not_confirmed")
        self.assertFalse(result.confirmed)
        self.assertTrue(result.summary.startswith("Lead, not confirmed"))
        self.assertEqual(log, ["prepare"] * 3 + ["execute"] * 3)
        self.assertEqual(executor.calls, 3)
        dispatch = _raw(result)["dispatch"]
        self.assertEqual(dispatch["copies"], 3)
        self.assertEqual(dispatch["sent"], 3)
        # Clock reads: release, then one send-start per copy back to back, so
        # the copies start 1 ms apart and the spread is (3 - 1) ms.
        self.assertEqual(dispatch["send_start_ms"], [1.0, 2.0, 3.0])
        self.assertEqual(dispatch["spread_ms"], 2.0)
        self.assertTrue(all(c is not None for c in dispatch["complete_ms"]))
        self.assertIn("Status code distribution across burst: {200: 3}", result.evidence)
        self.assertIn("dispatch spread 2.000 ms across 3/3 sends", result.evidence)

    def test_real_clock_spread_is_recorded_and_non_negative(self):
        result, _, _, _ = _run(4, [])
        dispatch = _raw(result)["dispatch"]
        self.assertIsInstance(dispatch["spread_ms"], float)
        self.assertGreaterEqual(dispatch["spread_ms"], 0.0)
        self.assertRegex(result.evidence, r"dispatch spread \d+\.\d{3} ms across 4/4 sends")

    def test_gate_clamped_burst_sends_exactly_the_allowed_count(self):
        result, log, executor, gate = _run(2, [], burst_size=12)
        self.assertEqual(gate.requested, 12)
        self.assertEqual(executor.calls, 2)
        self.assertEqual(log.count("prepare"), 2)
        raw = _raw(result)
        self.assertEqual(raw["burst_size"], 2)
        self.assertEqual(raw["requested_burst_size"], 12)
        self.assertEqual(raw["dispatch"]["copies"], 2)

    def test_blocked_burst_prepares_and_sends_nothing(self):
        log = []
        executor = _RecordingExecutor(log, [], 1)
        ctx = _Context(_Gate(0, allowed=False), executor, log)
        validator = RaceConditionValidator(burst_size=3, run_context=ctx)
        result = asyncio.run(validator.validate(_finding(), _exchange()))
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.raw_output, "[]")
        self.assertEqual(log, [])

    def test_negative_control_fixed_responses_keep_pre_change_verdict(self):
        cases = {
            "all clean": [(200, "ok", True)] * 4,
            "one clean, rest rejected": [(200, "ok", True)] + [(200, "Coupon already used", True)] * 3,
            "all conflict": [(409, "conflict", True)] * 4,
            "status differs from original": [(201, "ok", True)] * 4,
            "two clean among failures": [(200, "ok", True), (200, "ok", True),
                                         (500, "", False), (200, "", False)],
            "too few completed": [(200, "ok", True)] + [(200, "", False)] * 3,
            "one clean among failures": [(200, "ok", True), (409, "conflict", True),
                                         (500, "", False), (200, "", False)],
        }
        for name, responses in cases.items():
            with self.subTest(name):
                result, _, _, _ = _run(4, responses)
                status, confirmed, confidence = _pre_change_verdict(responses)
                self.assertEqual(result.status, status)
                self.assertEqual(result.confirmed, confirmed)
                self.assertEqual(result.confidence, confidence)
                if status == "error":
                    self.assertEqual(result.raw_output, "[]")
                    self.assertIn("Only 1/4 burst requests completed", result.summary)
                if status == "inconclusive":
                    failed = sum(1 for _, _, ok in responses if not ok)
                    self.assertIn(f"Race burst incomplete: {failed} of 4 send(s) got no response",
                                  result.summary)

    def test_fallback_path_shares_one_client_sized_for_the_burst(self):
        created = []

        class _Client:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.requests = 0
                self.in_flight = 0
                self.all_in = asyncio.Event()
                created.append(self)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def request(self, method, url, headers=None, content=None):
                self.requests += 1
                self.in_flight += 1
                if self.in_flight >= 3:
                    self.all_in.set()
                await asyncio.wait_for(self.all_in.wait(), timeout=2.0)
                return SimpleNamespace(status_code=200, text="ok", headers={})

        gate = _Gate(3)
        validator = RaceConditionValidator(burst_size=3, run_context=None, clock=_StepClock())
        with mock.patch.object(rcv.httpx, "AsyncClient", _Client), \
                mock.patch.object(rcv, "get_default_gate", return_value=gate):
            result = asyncio.run(validator.validate(_finding(), _exchange()))
        self.assertEqual(result.status, "not_confirmed")
        self.assertEqual(result.confidence, 0.3)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].requests, 3)
        limits = created[0].kwargs["limits"]
        self.assertEqual(limits.max_connections, 3)
        self.assertEqual(_raw(result)["dispatch"]["spread_ms"], 2.0)

    def test_email_pair_is_released_together_and_spread_recorded(self):
        from harness.test_race_email_validator import _Context as EmailContext
        from harness.test_race_email_validator import _exchange as email_exchange
        validator = RaceConditionValidator(
            run_context=EmailContext(False), target_email="carlos@example.test",
            mailbox_url="https://mail.test/email", email_race_rounds=1, clock=_StepClock())
        result = asyncio.run(validator.validate(_finding(), email_exchange()))
        self.assertEqual(result.status, "not_confirmed")
        # This fake executor never suspends, so copy 0 completes (one clock
        # read) before copy 1 starts: release, start0, complete0, start1 -> 2 ms.
        self.assertEqual(_raw(result)["pair_spread_ms"], [2.0])
        self.assertTrue(re.search(r"Max pair dispatch spread 2\.000 ms", result.evidence))


if __name__ == "__main__":
    unittest.main()
