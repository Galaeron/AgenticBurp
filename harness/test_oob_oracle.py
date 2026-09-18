"""P0.3: prove the OOB oracle promotes blind SSRF to VERIFIED only on a real
collaborator callback -- never on a request that never calls back.

No new production code: collaborator.py + SsrfValidator are already OOB and
already registered self-controlling in negative_controls.SELF_CONTROLLING
(no negative-control builder required to reach VERIFIED -- a callback
carrying our unique token cannot be a benign coincidence). This test proves
that end to end against the SAME real disposable Flask fixture
test_leg_live_verification.py uses, through the real Oracle/OracleRegistry
(not a scripted validator), so it verifies the oracle layer specifically,
not just the leg.

Hermetic and self-contained: the only "network" is loopback -- this test's
own fixture server plus the collaborator's own loopback listener, torn down
in tearDownClass. No second collaborator listener is started; SsrfValidator
uses the process-shared one (collaborator.shared()).
"""
from __future__ import annotations

import asyncio
import importlib.util
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from werkzeug.serving import make_server

from harness import global_throttle, safety_gate
from harness.models import Finding, HttpExchange
from harness.oracle_framework import OracleRegistry
from harness.validators.ssrf_validator import SsrfValidator

_FIXTURE = (Path(__file__).resolve().parent.parent
            / "testing" / "leg-verification" / "vuln_fixture.py")


def _load_make_app():
    spec = importlib.util.spec_from_file_location("vuln_fixture", _FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_app


def _finding():
    return Finding(vulnerability_class="ssrf", confidence=0.5, severity="high",
                   summary="ssrf hypothesis", evidence="", suggested_test="", basis="derived")


class FakeSsrfOnlyRegistry:
    """Minimal ValidatorRegistry stand-in exposing only what OracleRegistry
    needs (for_finding), so the oracle is driven against exactly ONE real
    validator instance without pulling in the full production registry."""

    def __init__(self, validator):
        self._validator = validator

    def for_finding(self, finding, exchange):
        return [self._validator]


class OobOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        global_throttle.configure(0)
        app = _load_make_app()()
        cls._server = make_server("127.0.0.1", 0, app, threaded=True)
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{cls._port}"
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{cls._base}/health", timeout=0.5).read()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("leg-verification fixture did not come up")
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._thread.join(timeout=5.0)
        safety_gate.reset_default_gate()

    def test_real_callback_reaches_verified(self):
        """The vulnerable endpoint really fetches the URL param server-side --
        the collaborator really receives the callback -- the oracle reproduces
        N-of-N with no negative control required (self-controlling OOB) ->
        VERIFIED."""
        validator = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=2.0)
        registry = OracleRegistry(FakeSsrfOnlyRegistry(validator), n_required=2)
        exchange = HttpExchange(
            url=f"{self._base}/ssrf/fetch?url=http://example.invalid/x", method="GET",
            request_headers={}, request_body="")
        capsule = asyncio.run(registry.verify(_finding(), exchange))
        self.assertIsNotNone(capsule)
        self.assertTrue(capsule.reproduced, capsule.reason)
        self.assertFalse(capsule.negative_control_available)  # self-controlling
        self.assertTrue(capsule.verified, capsule.reason)

    def test_no_callback_stays_candidate(self):
        """Negative control: the /ssrf/safe endpoint never performs the
        server-side fetch, so the collaborator never sees a callback -- the
        oracle must NOT reproduce, and the finding must stay a CANDIDATE, not
        be fake-verified."""
        validator = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=2.0)
        registry = OracleRegistry(FakeSsrfOnlyRegistry(validator), n_required=2)
        exchange = HttpExchange(
            url=f"{self._base}/ssrf/safe?url=http://example.invalid/x", method="GET",
            request_headers={}, request_body="")
        capsule = asyncio.run(registry.verify(_finding(), exchange))
        self.assertIsNotNone(capsule)
        self.assertFalse(capsule.reproduced)
        self.assertFalse(capsule.verified)


if __name__ == "__main__":
    unittest.main()
