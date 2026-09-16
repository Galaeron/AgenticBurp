"""Tests for the new deterministic confirmation legs: jwt-forge, ssrf, xxe, and
the OOB collaborator. Network is stubbed; the collaborator test uses a real
loopback listener (no external network)."""
import asyncio
import json
import unittest
import urllib.request
from unittest.mock import patch

from harness import collaborator
from harness.models import Finding, HttpExchange
from harness.validators.jwt_forge_validator import (JwtForgeValidator, _JWT_RE, _b64url_decode,
                                            _b64url_encode, _forge_alg_none)
from harness.validators.ssrf_validator import SsrfValidator
from harness.validators.xxe_validator import XxeValidator


def _f(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high", summary=vc,
                   evidence="e", suggested_test="t", basis="derived")


def _real_token():
    hdr = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pl = _b64url_encode(json.dumps({"user_id": 1, "role": "user"}).encode())
    return f"{hdr}.{pl}.c2lnbmF0dXJl"


class CollaboratorTests(unittest.TestCase):
    def test_records_a_callback_hit(self):
        c = collaborator.Collaborator()
        try:
            tok = c.token()
            urllib.request.urlopen(c.url(tok), timeout=5).read()
            self.assertTrue(c.was_hit(tok))
            self.assertFalse(c.was_hit("oob-never-hit"))
        finally:
            c.stop()

    def test_wait_for_hit_times_out_cleanly(self):
        c = collaborator.Collaborator()
        try:
            self.assertFalse(asyncio.run(c.wait_for_hit("nope", timeout=0.4)))
        finally:
            c.stop()


class _StubJwt(JwtForgeValidator):
    """Replaces the network probe with a canned responder keyed on the token's
    alg / signature, so the confirm logic is tested without a server."""
    def __init__(self, responder, **kw):
        super().__init__(**kw)
        self._responder = responder

    async def _probe(self, url, headers):
        return self._responder(headers.get("Authorization", ""))


def _alg_of(auth):
    # Extract permissively -- the alg:none forgery has an EMPTY signature, which
    # _JWT_RE deliberately won't match, so split off "Bearer " instead.
    tok = auth.split()[-1] if auth else ""
    parts = tok.split(".")
    if len(parts) < 3:
        return None, ""
    try:
        return json.loads(_b64url_decode(parts[0])).get("alg"), parts[2]
    except Exception:
        return None, parts[2]


class JwtForgeTests(unittest.TestCase):
    def _exchange(self):
        return HttpExchange(url="http://t.test/api/mine", method="GET",
                            request_headers={"Authorization": f"Bearer {_real_token()}"},
                            response_status=200, response_body="[]")

    def test_confirms_when_alg_none_accepted_and_garbage_rejected(self):
        def responder(auth):
            alg, sig = _alg_of(auth)
            if "not-a-valid" in (_b64url_decode(sig).decode("latin1", "ignore") if sig else ""):
                return 401, ""              # garbage rejected -> control holds
            if alg == "none":
                return 200, '{"ok":1}'      # forged alg:none accepted -> vuln
            return 200, "orig"
        r = asyncio.run(_StubJwt(responder, allowed_hosts=["t.test"]).validate(_f("jwt"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_skips_when_garbage_token_also_accepted(self):
        r = asyncio.run(_StubJwt(lambda a: (200, "always ok"), allowed_hosts=["t.test"])
                        .validate(_f("jwt"), self._exchange()))
        self.assertEqual(r.status, "skipped")  # endpoint ignores the token entirely

    def test_not_confirmed_when_forgeries_rejected(self):
        # A proper verifier: only the untampered, properly-signed original passes;
        # both forgeries escalate role->admin, so both are rejected.
        def responder(auth):
            tok = auth.split()[-1]
            parts = tok.split(".")
            try:
                payload = json.loads(_b64url_decode(parts[1]))
            except Exception:
                payload = {}
            alg, sig = _alg_of(auth)
            if alg == "HS256" and payload.get("role") == "user" and sig == "c2lnbmF0dXJl":
                return 200, "original ok"
            return 401, ""
        r = asyncio.run(_StubJwt(responder, allowed_hosts=["t.test"]).validate(_f("jwt"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")

    def test_forge_alg_none_is_unsigned_and_elevates_role(self):
        forged = _forge_alg_none({"alg": "HS256"}, {"role": "user"})
        h, p, s = forged.split(".")
        self.assertEqual(s, "")  # no signature
        self.assertEqual(json.loads(_b64url_decode(h))["alg"], "none")
        self.assertEqual(json.loads(_b64url_decode(p))["role"], "admin")  # escalated


class _FakeCollab:
    def __init__(self, hit): self._hit = hit; self._n = 0
    def token(self): self._n += 1; return f"oob{self._n}"
    def url(self, t): return f"http://collab.test/{t}"
    async def wait_for_hit(self, t, timeout=6.0): return self._hit


async def _noop_request(self, method, url, headers=None, content=None):
    class _R:
        status_code = 200
        text = "ok"
    return _R()


class _GateAllowsMutating(unittest.TestCase):
    """The ssrf/xxe sends are mutating POSTs -> the safety gate must be armed to
    allow a mutating replay, else it (correctly) blocks them."""
    def setUp(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    def tearDown(self):
        from harness import safety_gate
        safety_gate.reset_default_gate()


class SsrfTests(_GateAllowsMutating):
    def _exchange(self):
        return HttpExchange(url="http://t.test/api/fetch", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"url":"http://example.com"}', response_status=200, response_body="{}")

    def test_confirms_on_callback(self):
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("ssrf"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_not_confirmed_without_callback(self):
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("ssrf"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")

    def test_skips_without_url_param(self):
        ex = HttpExchange(url="http://t.test/api/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="{}")
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        self.assertFalse(v.applies(_f("ssrf"), ex))


class XxeTests(_GateAllowsMutating):
    def _exchange(self):
        return HttpExchange(url="http://t.test/api/import", method="POST",
                            request_headers={"Content-Type": "application/xml"},
                            request_body="<?xml version='1.0'?><r>x</r>", response_status=200, response_body="{}")

    def test_confirms_on_callback(self):
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("xxe"), self._exchange()))
        self.assertEqual(r.status, "confirmed")

    def test_not_confirmed_without_callback(self):
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        with patch("httpx.AsyncClient.request", _noop_request):
            r = asyncio.run(v.validate(_f("xxe"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")

    def test_skips_non_xml_endpoint(self):
        ex = HttpExchange(url="http://t.test/api/x", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"a":1}', response_status=200, response_body="{}")
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        r = asyncio.run(v.validate(_f("xxe"), ex))
        self.assertEqual(r.status, "skipped")


if __name__ == "__main__":
    unittest.main()
