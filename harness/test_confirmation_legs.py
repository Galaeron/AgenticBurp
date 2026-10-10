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
                                            _b64url_encode, _forge_alg_none,
                                            _forge_keep_sig, _rsa_jwks_to_pem)
from harness.validators.ssrf_validator import SsrfValidator
from harness.validators.xxe_validator import XxeValidator
from harness.testing_fixtures.sent_probe import CountingResponder


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
    alg / signature, so the confirm logic is tested without a server.

    NOTE (review 2026-10): this overrides `_probe` -- the method that performs the
    send -- so the safety gate is NEVER consulted on this path. These tests are a
    pure test of the confirmation LOGIC and are deliberately excluded from the
    sent-count condition. End-to-end JWT proof over the gated transport (with a
    real server-side request count) lives in test_leg_live_verification."""
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

    def test_reused_signature_forgery_always_changes_payload(self):
        original = {"iat": 1, "custom": "unchanged"}
        forged = _forge_keep_sig({"alg": "RS256"}, original, "sig")
        payload = json.loads(_b64url_decode(forged.split(".")[1]))
        self.assertNotEqual(payload, original)
        self.assertEqual(payload["harness_probe"], "signature-must-change")

    def test_rsa_jwk_is_converted_to_public_key_pem(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
        jwks = json.dumps({"keys": [{
            "kty": "RSA", "kid": "k1",
            "n": _b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }]})
        converted = _rsa_jwks_to_pem(jwks, "k1")
        self.assertEqual(converted[0][0], "k1")
        self.assertIn(b"BEGIN PUBLIC KEY", converted[0][1])


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
        # Seed scope: the gate fails closed on an empty active scope (3c622c3), so
        # without this the mutating ssrf/xxe POST is refused before the leg runs.
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["t.test"]})

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
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssrf"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_without_callback(self):
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssrf"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())  # probed; no OOB hit

    def test_skips_without_url_param(self):
        ex = HttpExchange(url="http://t.test/api/x", method="GET", request_headers={},
                          request_body="", response_status=200, response_body="{}")
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        self.assertFalse(v.applies(_f("ssrf"), ex))

    def _stock_form_exchange(self):
        # The real PortSwigger stock-check form: a urlencoded body whose only
        # parameter (stockApi) is NOT a known URL-name but whose VALUE is an
        # (encoded) http:// URL. Regression for form-body value-shape targeting.
        return HttpExchange(
            url="http://t.test/product/stock", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body=("stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080"
                          "%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1"),
            response_status=200, response_body="10 units")

    def test_targets_form_body_url_value_by_shape(self):
        from harness.validators.ssrf_validator import _candidate_params
        cands = _candidate_params(self._stock_form_exchange())
        self.assertIn(("body", "stockApi"), cands)

    def test_applies_and_confirms_on_stock_form_callback(self):
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        ex = self._stock_form_exchange()
        self.assertTrue(v.applies(_f("ssrf"), ex))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssrf"), ex))
        self.assertEqual(r.status, "confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_inband_differential_confirms_without_collaborator(self):
        # A server that actually FETCHES the URL: the reachable loopback port
        # serves content; the closed port yields a connection error. No OOB hit.
        async def fetching_app(self, method, url, headers=None, content=None):
            blob = (url or "") + " " + (content or "")
            class _R: pass
            r = _R()
            r.status_code = 200
            if "%3A1%2F" in blob or ":1/" in blob or "127.0.0.1:1" in blob:
                r.text = "Error: connection refused while fetching upstream"
            else:
                r.text = "<html><body>Internal service dashboard: 42 widgets</body></html>"
            return r
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(fetching_app)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssrf"), self._stock_form_exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("in-band", r.summary)
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_inband_echo_only_app_is_not_confirmed(self):
        # Negative control: the app only REFLECTS the submitted URL (no fetch).
        # After stripping the echoed URL/host the two responses are identical, so
        # no fetch-outcome differential exists -> not confirmed.
        async def echo_app(self, method, url, headers=None, content=None):
            class _R: pass
            r = _R()
            r.status_code = 200
            r.text = f"No stock information for URL {url} body {content}"
            return r
        v = SsrfValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(echo_app)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("ssrf"), self._stock_form_exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())  # fetched; only reflected

    def test_form_body_non_url_value_still_skipped(self):
        # Negative control: a urlencoded body whose value is NOT a URL and whose
        # name is not a URL-name must not become an SSRF candidate.
        from harness.validators.ssrf_validator import _candidate_params
        ex = HttpExchange(url="http://t.test/product/stock", method="POST",
                          request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                          request_body="quantity=5&storeId=2", response_status=200, response_body="ok")
        self.assertEqual(_candidate_params(ex), [])


class XxeTests(_GateAllowsMutating):
    def _exchange(self):
        return HttpExchange(url="http://t.test/api/import", method="POST",
                            request_headers={"Content-Type": "application/xml"},
                            request_body="<?xml version='1.0'?><r>x</r>", response_status=200, response_body="{}")

    def test_confirms_on_callback(self):
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("xxe"), self._exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())

    def test_not_confirmed_without_callback(self):
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("xxe"), self._exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertGreaterEqual(responder.count, 1, responder.why())  # probed; no OOB hit

    def test_skips_non_xml_endpoint(self):
        ex = HttpExchange(url="http://t.test/api/x", method="POST",
                          request_headers={"Content-Type": "application/json"},
                          request_body='{"a":1}', response_status=200, response_body="{}")
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=True))
        r = asyncio.run(v.validate(_f("xxe"), ex))
        self.assertEqual(r.status, "skipped")

    def _stock_xml_exchange(self):
        return HttpExchange(
            url="http://t.test/product/stock", method="POST",
            request_headers={"Content-Type": "application/xml"},
            request_body=("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                          "<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"),
            response_status=200, response_body="452")

    def test_inject_file_entity_declares_system_entity_and_substitutes(self):
        from harness.validators.xxe_validator import _inject_file_entity
        payload = _inject_file_entity(self._stock_xml_exchange().request_body)
        self.assertIn('<!ENTITY xxe SYSTEM "file:///etc/passwd">', payload)
        self.assertIn("<!DOCTYPE stockCheck", payload)
        self.assertIn("<productId>&xxe;</productId>", payload)
        # The benign literal value is gone from the injected element.
        self.assertNotIn("<productId>1</productId>", payload)

    def test_inband_file_read_confirms_without_collaborator(self):
        # The app resolves the entity and reflects the file -> the passwd
        # signature appears in the response. No OOB callback needed.
        async def reading_app(self, method, url, headers=None, content=None):
            class _R: pass
            r = _R()
            r.status_code = 200
            if content and "file:///etc/passwd" in content and "&xxe;" in content:
                r.text = "Invalid product ID: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
            else:
                r.text = "ok"
            return r
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(reading_app)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("xxe"), self._stock_xml_exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("in-band", r.summary)
        # The file contents must NOT be dumped into the finding.
        self.assertNotIn("daemon:x:1:1:", r.evidence)
        self.assertGreaterEqual(responder.count, 1, responder.why())  # the in-band read was actually sent

    def test_inband_no_reflection_and_no_oob_is_not_confirmed(self):
        # Entities disabled: no passwd signature reflected and no OOB hit.
        v = XxeValidator(allowed_hosts=["t.test"], collaborator=_FakeCollab(hit=False))
        responder = CountingResponder(_noop_request)
        with patch("httpx.AsyncClient.request", responder):
            r = asyncio.run(v.validate(_f("xxe"), self._stock_xml_exchange()))
        self.assertEqual(r.status, "not_confirmed")
        # Non-vacuous: "not_confirmed" must mean the probe was sent and saw
        # nothing, NOT that a mis-seeded scope sent nothing at all.
        self.assertGreaterEqual(responder.count, 1, responder.why())


if __name__ == "__main__":
    unittest.main()
