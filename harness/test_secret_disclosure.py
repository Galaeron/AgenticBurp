"""Tests for the Phase 3.1 secret-disclosure confirmation (secret_disclosure.py).

The confirmation is a real HMAC verification, so the "confirmed" cases sign a JWT
with a known secret and leak that exact secret in the response; the negative
controls change exactly one thing (different string / no token / non-HMAC alg)."""
import base64
import hashlib
import hmac
import json
import unittest

from harness import secret_disclosure
from harness.models import HttpExchange


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _make_jwt(secret: str, alg: str = "HS256", payload=None) -> str:
    h = _b64({"alg": alg, "typ": "JWT"})
    p = _b64(payload or {"sub": "1", "role": "user"})
    signing = f"{h}.{p}".encode()
    algfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if algfn is not None:
        sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing, algfn).digest()).rstrip(b"=").decode()
    else:
        sig = "bm90LWFuLWhtYWMtc2ln"  # RS256 etc. -- not an HMAC we could verify
    return f"{h}.{p}.{sig}"


_SECRET = "sup3r-secret-signing-key-2024"


def _ex(*, req_headers=None, resp_body=""):
    return HttpExchange(url="http://target.test/admin/debug", method="GET",
                        request_headers=req_headers or {}, request_body="",
                        response_status=200, response_headers={}, response_body=resp_body)


class SecretDisclosureTests(unittest.TestCase):
    def test_confirms_when_response_leaks_the_signing_secret(self):
        jwt = _make_jwt(_SECRET)
        ex = _ex(req_headers={"Authorization": f"Bearer {jwt}"},
                 resp_body=json.dumps({"config": {"jwt_secret": _SECRET, "env": "prod"}}))
        findings = secret_disclosure.findings_from_exchange(ex)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.confirmed)
        self.assertEqual(f.vulnerability_class, "jwt")
        self.assertEqual(f.severity, "critical")
        # The raw secret must NEVER appear in the finding -- redacted only.
        self.assertNotIn(_SECRET, f.evidence)
        self.assertNotIn(_SECRET, f.summary)

    def test_confirms_from_bare_token_in_plain_text_response(self):
        # Non-JSON response: the secret as a bare whitespace-delimited token.
        jwt = _make_jwt(_SECRET)
        ex = _ex(req_headers={"Cookie": f"session={jwt}"},
                 resp_body=f"DEBUG signing_key = {_SECRET} (do not log)")
        self.assertEqual(len(secret_disclosure.findings_from_exchange(ex)), 1)

    def test_negative_control_different_string_not_confirmed(self):
        jwt = _make_jwt(_SECRET)
        ex = _ex(req_headers={"Authorization": f"Bearer {jwt}"},
                 resp_body=json.dumps({"config": {"note": "nothing sensitive here", "env": "prod"}}))
        self.assertEqual(secret_disclosure.findings_from_exchange(ex), [])

    def test_no_jwt_in_request_not_confirmed(self):
        ex = _ex(req_headers={}, resp_body=json.dumps({"jwt_secret": _SECRET}))
        self.assertEqual(secret_disclosure.findings_from_exchange(ex), [])

    def test_non_hmac_alg_not_confirmed(self):
        # An RS256 token can't be confirmed by a symmetric-key match.
        jwt = _make_jwt(_SECRET, alg="RS256")
        ex = _ex(req_headers={"Authorization": f"Bearer {jwt}"},
                 resp_body=json.dumps({"jwt_secret": _SECRET}))
        self.assertEqual(secret_disclosure.findings_from_exchange(ex), [])


if __name__ == "__main__":
    unittest.main()
