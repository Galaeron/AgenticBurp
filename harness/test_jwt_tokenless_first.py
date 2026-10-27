"""Ticket E10: jwt_forge asks the cheap question first -- does the token gate this route?

One tokenless request, then (only when that got a real payload) one replay of the
captured token. The same answer for both means the token does not gate access, so
no forged or invalid-signature token can show a signature bug and the probes are
not sent. Anything else runs the flow as before.

Caller-level: JwtForgeValidator.validate() inside an entered RunContext, against a
127.0.0.1 ThreadingHTTPServer that counts the requests it receives per
Authorization value. Each negative control patches the new logic out and proves the
same assertion helper then fails, so the test depends on the logic.
"""
from __future__ import annotations

import asyncio
import base64
import http.server
import json
import threading
import unittest
from collections import Counter
from unittest.mock import patch

from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators import jwt_forge_validator as jfv
from harness.validators.jwt_forge_validator import JwtForgeValidator, _answers_materially_same


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_TOKEN = (_b64url(b'{"alg":"HS256","typ":"JWT"}') + "." + _b64url(b'{"sub":"1","role":"user"}')
          + "." + _b64url(b"signature-not-real"))
_VALID = f"Bearer {_TOKEN}"
_GARBAGE_SIG = _b64url(b"not-a-valid-signature-xxxx")
_PRIVATE = '{"items": [{"id": 1, "email": "alice@example.com", "balance": 1200}]}'
_FORGERY_PROBES = 6   # alg:none, payload-tamper, kid direct, three kid -> empty key


class _Counting:
    """Loopback app. `respond(auth)` -> (status, body); `auth` is "" with no token.
    `counts` is the number of requests received per Authorization value."""

    def __init__(self, respond):
        counts = self.counts = Counter()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                counts[auth] += 1
                status, text = respond(auth)
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/items"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


def _garbage(auth: str) -> bool:
    return auth.startswith("Bearer ") and auth.endswith("." + _GARBAGE_SIG)


class TokenlessFirstTests(unittest.TestCase):
    def _run(self, respond, *, patches=()):
        target = _Counting(respond)
        self.addCleanup(target.close)
        exchange = HttpExchange(url=target.url, method="GET",
                                request_headers={"Authorization": _VALID},
                                response_status=200, response_body=_PRIVATE)

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                         gate_config={"active_enabled": True}) as run:
                validator = JwtForgeValidator(allowed_hosts=["127.0.0.1"], timeout=5.0,
                                              run_context=run)
                return await validator.validate(
                    Finding(vulnerability_class="jwt", confidence=0.5, summary="jwt",
                            evidence="", suggested_test="", basis="assumed"), exchange)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return asyncio.run(go()), target

    # -- the public route: two requests, then skip --------------------------------
    @staticmethod
    def _public_route(auth):
        return 200, _PRIVATE     # the token changes nothing

    def _assert_public_route_skipped_in_three(self, result, target):
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("token does not gate this route", result.summary)
        self.assertEqual((target.counts[""], target.counts[_VALID]), (1, 1),
                         "exactly one tokenless and one replay request may reach the server")
        self.assertEqual(target.total, 3, "plus one forged alg:none token")
        self.assertIn("probes sent: 3", result.evidence)

    def test_public_route_is_skipped_after_three_requests(self):
        result, target = self._run(self._public_route)
        self._assert_public_route_skipped_in_three(result, target)

    def test_public_route_negative_control_fails_without_the_new_logic(self):
        # The skip is the new logic: with the comparison patched to "never the same",
        # the flow runs on (garbage control, then the tokenless control) and the very
        # assertion above must fail.
        result, target = self._run(
            self._public_route,
            patches=[patch.object(jfv, "_answers_materially_same", return_value=False)])
        with self.assertRaises(AssertionError):
            self._assert_public_route_skipped_in_three(result, target)
        self.assertIn("does not gate on the token", result.summary)  # the old, later skip

    def test_public_route_that_rejects_bad_tokens_costs_three_requests_not_seven(self):
        # The measured shape (job 383f0ebff8e8): anonymous already gets the page, a
        # malformed token is refused. Before E10: garbage control + 6 forgeries = 7.
        result, target = self._run(
            lambda auth: (401, '{"error": "bad token"}') if auth and auth != _VALID else (200, _PRIVATE))
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(target.total, 3)
        print(f"\n[E10] public route that rejects bad tokens: {1 + _FORGERY_PROBES} probes before, "
              f"{target.total} now")

    def test_noise_only_difference_still_counts_as_the_same_answer(self):
        stamp = iter(range(10, 99))
        result, target = self._run(
            lambda auth: (200, '{"ts": "2026-10-27T10:00:%02dZ", "items": [1,2,3,4,5,6,7,8]}'
                          % next(stamp)))
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(target.total, 3)

    # -- optional auth: anonymous is served, a forged admin token sees more --------
    @staticmethod
    def _optional_auth_route(auth):
        if not auth or auth == _VALID:
            return 200, _PRIVATE
        if auth.endswith("."):                  # alg:none, escalated to admin
            return 200, '{"items": ["every order", "admin panel"], "role": "admin"}'
        return 401, '{"error": "bad signature"}'

    def test_forged_admin_token_on_a_public_route_is_not_skipped(self):
        result, target = self._run(self._optional_auth_route)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("alg:none", result.summary)

    def test_forged_admin_control_without_the_pre_skip_probe_it_is_skipped(self):
        result, target = self._run(
            self._optional_auth_route,
            patches=[patch.object(jfv, "_FORGED_PROBE_BEFORE_SKIP", False)])
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertEqual(target.total, 2)

    # -- a gated route that accepts any signature: still confirmed ----------------
    @staticmethod
    def _gated_unverified_route(auth):
        if not auth:
            return 401, '{"error": "login required"}'
        return 200, _PRIVATE     # any "Bearer x.y.z" is accepted: nothing verifies it

    def test_gated_route_accepting_an_invalid_signature_is_still_confirmed(self):
        result, target = self._run(self._gated_unverified_route)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertTrue(result.confirmed)
        # Before E10 this flow sent garbage, tokenless and the proof baseline: also 3.
        self.assertEqual(target.total, 3)
        self.assertEqual(target.counts[""], 1, "the tokenless control is reused, not resent")
        self.assertEqual(target.counts[_VALID], 1, "the replay is the proof baseline, sent once")
        self.assertIn("probes sent: 3", result.evidence)
        # baseline (captured token), attack (garbage token), control (tokenless): distinct.
        roles = [result.baseline_artifact_id, result.attack_artifact_id,
                 *result.control_artifact_ids]
        self.assertEqual(len(roles), 3, roles)
        self.assertTrue(all(roles), roles)
        self.assertEqual(len(set(roles)), 3, roles)

    # -- public view versus private view: the skip needs materially equal answers -
    @staticmethod
    def _public_vs_private_route(auth):
        if not auth:
            return 200, '{"items": []}'
        if auth == _VALID:
            return 200, _PRIVATE
        return 401, '{"error": "bad signature"}'

    def _assert_public_vs_private_not_skipped(self, result, target):
        self.assertNotEqual(result.status, "skipped", result.summary)
        self.assertGreater(target.total, 2, "the flow must continue past the discriminator")
        self.assertTrue(any(_garbage(a) for a in target.counts),
                        "the garbage-signature control must be sent")

    def test_public_vs_private_route_is_not_skipped(self):
        result, target = self._run(self._public_vs_private_route)
        self._assert_public_vs_private_not_skipped(result, target)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(target.total, 3 + _FORGERY_PROBES,
                         "tokenless + replay + garbage + the forgery probes")

    def test_public_vs_private_negative_control_fails_if_everything_is_the_same(self):
        # The skip must hinge on the comparison: were any two substantive answers
        # "the same", this route would be skipped after three requests.
        result, target = self._run(
            self._public_vs_private_route,
            patches=[patch.object(jfv, "_answers_materially_same", return_value=True)])
        with self.assertRaises(AssertionError):
            self._assert_public_vs_private_not_skipped(result, target)
        self.assertEqual(result.status, "skipped")
        self.assertEqual(target.total, 3)

    def test_public_route_that_accepts_garbage_reuses_the_tokenless_answer(self):
        # Public view for no token, private for any token (valid or not): the
        # answers differ so the discriminator does not skip; the old "accepts garbage
        # AND tokenless" skip fires, with the tokenless request sent exactly once.
        result, target = self._run(
            lambda auth: (200, '{"items": []}') if not auth else (200, _PRIVATE))
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("does not gate on the token", result.summary)
        self.assertEqual(target.counts[""], 1)
        self.assertEqual(target.total, 3)

    # -- a verifier that works --------------------------------------------------
    def test_correctly_verifying_route_is_not_confirmed(self):
        def route(auth):
            return (200, _PRIVATE) if auth == _VALID else (401, '{"error": "denied"}')
        result, target = self._run(route)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(target.counts[""], 1)
        self.assertEqual(target.total, 2 + _FORGERY_PROBES)   # tokenless + garbage + forgeries
        self.assertIn(f"probes sent: {2 + _FORGERY_PROBES}", result.evidence)

    def test_forged_token_accepted_where_garbage_is_rejected_is_confirmed(self):
        # The forgery leg still confirms behind a tokenless-denied route.
        def route(auth):
            if not auth:
                return 401, '{"error": "login required"}'
            if auth == _VALID or auth.endswith("."):    # the original, or alg:none (empty signature)
                return 200, _PRIVATE
            return 401, '{"error": "bad signature"}'
        result, target = self._run(route)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("alg:none", result.summary)
        self.assertEqual(target.counts[""], 1)


class MaterialSameAnswerTests(unittest.TestCase):
    def test_equal_after_whitespace_normalisation(self):
        self.assertTrue(_answers_materially_same((200, '{"a": 1,\n "b": 2}'), (200, '{"a": 1, "b": 2}')))

    def test_status_class_must_match(self):
        self.assertFalse(_answers_materially_same((200, "x" * 40), (404, "x" * 40)))

    def test_no_answer_is_never_the_same(self):
        self.assertFalse(_answers_materially_same((None, "boom"), (200, "boom")))

    def test_same_size_but_different_content_is_not_the_same(self):
        self.assertFalse(_answers_materially_same(
            (200, '{"owner": "public-1"}'), (200, '{"owner": "alice-99"}')))

    def test_lengths_more_than_two_percent_apart_are_not_the_same(self):
        self.assertFalse(_answers_materially_same((200, "a" * 100), (200, "a" * 100 + "b" * 5)))


if __name__ == "__main__":
    unittest.main()
