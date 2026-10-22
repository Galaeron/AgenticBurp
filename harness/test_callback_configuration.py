"""Ticket 5: registry -> production OOB validators -> real owned listener."""
import asyncio
import os
import socket
import unittest
import urllib.request
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import httpx
from harness import collaborator
from harness.models import Finding, HttpExchange
from harness.validators.registry import ValidatorRegistry


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CallbackConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                          if not k.startswith("AGENTICVIBE_OOB_")}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def registry(self, config=None):
        registry = ValidatorRegistry(config or {})
        self.addCleanup(registry.collaborator.stop)
        return registry

    def test_default_is_lazy_ephemeral_loopback(self):
        reg = self.registry()
        self.assertIsNone(reg.collaborator._listener)
        listener = reg.collaborator.start()
        self.assertEqual(listener.host, "127.0.0.1")
        self.assertGreater(listener.port, 0)
        self.assertTrue(listener.url("check").startswith("http://127.0.0.1:"))

    def test_launcher_environment_reaches_registry_and_all_oob_validators(self):
        port = free_port()
        with patch.dict(os.environ, {
            "AGENTICVIBE_OOB_BIND_HOST": "0.0.0.0",
            "AGENTICVIBE_OOB_ADVERTISE_HOST": "host.docker.internal",
            "AGENTICVIBE_OOB_PORT": str(port),
            "AGENTICVIBE_OOB_APPROVED_ORIGIN": f"http://host.docker.internal:{port}",
        }):
            reg = self.registry()
            for name in ("ssrf", "command_injection", "xxe", "deserialization_oob"):
                listener = reg.validators[name].collab()
                self.assertIs(listener, reg.collaborator.start())
                self.assertEqual(listener.url("check"), f"http://host.docker.internal:{port}/check")
            self.assertEqual(listener.health()["verified_target_origins"], [])

    def test_malformed_or_unapproved_config_fails_before_any_send(self):
        for settings in (
            {"port": -1}, {"port": True}, {"port": 65536},
            {"advertise_host": "http://example.test"},
            {"bind_host": "0.0.0.0"},
            {"advertise_host": "host.docker.internal", "port": 1234},
            {"advertise_host": "host.docker.internal", "port": 1234,
             "approved_origin": "http://host.docker.internal:1235"},
            {"advertise_host": "0.0.0.0", "port": 1234,
             "approved_origin": "http://0.0.0.0:1234"},
        ):
            with self.subTest(settings=settings), patch("httpx.AsyncClient.request") as send:
                with self.assertRaises(ValueError):
                    self.registry({"collaborator": settings})
                send.assert_not_called()

    def test_exact_registered_tokens_only(self):
        listener = self.registry().collaborator.start()
        token = listener.token()
        for path in ("prefix" + token, token + "suffix", "unregistered", "other?token=" + token):
            with urllib.request.urlopen(listener.url(path), timeout=3):
                pass
        self.assertFalse(listener.was_hit(token))
        self.assertFalse(listener.was_hit("unregistered"))
        with urllib.request.urlopen(listener.url(token), timeout=3):
            pass
        self.assertTrue(listener.was_hit(token))

    def test_occupied_port_never_falls_back_and_second_owner_cannot_stop_first(self):
        port = free_port()
        cfg = {"collaborator": {"port": port}}
        first, second = self.registry(cfg), self.registry(cfg)
        listener = first.collaborator.start()
        with self.assertRaises(OSError):
            second.collaborator.start()
        second.collaborator.stop()
        token = listener.token()
        with urllib.request.urlopen(listener.url(token), timeout=3):
            pass
        self.assertTrue(listener.was_hit(token))
        listener.stop()
        listener.stop()
        self.assertEqual(listener._srv.socket.fileno(), -1)
        self.assertFalse(listener.health()["available"])

    def test_preflight_requires_the_exact_callback(self):
        listener = self.registry().collaborator.start()
        token = listener.token()
        self.assertFalse(listener.record_preflight(token, "http://target.test:3002"))
        with urllib.request.urlopen(listener.url(token), timeout=3):
            pass
        self.assertTrue(listener.record_preflight(token, "http://target.test:3002"))
        self.assertEqual(listener.health()["verified_target_origins"], ["http://target.test:3002"])
        self.assertEqual(listener.unavailable_reason("http://target.test:3002/path"), "")
        self.assertTrue(listener.unavailable_reason("http://target.test:3003/path"))
        self.assertTrue(listener.unavailable_reason("http://other.test:3002/path"))

    def test_loopback_target_address_does_not_prove_callback_reachability(self):
        listener = self.registry().collaborator.start()
        self.assertTrue(listener.unavailable_reason("http://127.0.0.1:3002"))

    def run_ssrf(self, callback):
        reg = self.registry({"server": {"allowed_hosts": ["target.test"]},
                             "validators": {"active_enabled": True, "ssrf": {"timeout": 0.01}}})
        validator = reg.validators["ssrf"]
        sent = []

        async def send(client, method, url, **kwargs):
            sent.append(str(url))
            destination = parse_qs(urlsplit(str(url)).query).get("url", [""])[0]
            if "/oob" in destination and callback:
                destination += "suffix" if callback == "wrong" else ""
                with urllib.request.urlopen(destination, timeout=3):
                    pass
            return httpx.Response(200, text="ordinary unchanged response", request=httpx.Request(method, url))

        finding = Finding(vulnerability_class="ssrf", summary="synthetic", confidence=0.5,
                          severity="low", evidence="synthetic", suggested_test="", basis="derived")
        exchange = HttpExchange(url="http://target.test/fetch?url=http://example.invalid/", method="GET")
        with patch("httpx.AsyncClient.request", new=send):
            result = asyncio.run(validator.validate(finding, exchange))
        self.assertTrue(sent)
        return result

    def test_production_ssrf_confirms_exact_callback(self):
        self.assertTrue(self.run_ssrf("exact").confirmed)

    def test_unverified_network_without_callback_is_incomplete(self):
        result = self.run_ssrf(None)
        self.assertEqual(result.status, "inconclusive")
        self.assertFalse(result.confirmed)

    def test_wrong_token_cannot_confirm_production_ssrf(self):
        self.assertFalse(self.run_ssrf("wrong").confirmed)

    def test_defect_injection_dropped_callback_breaks_positive(self):
        with patch.object(collaborator.Collaborator, "was_hit", return_value=False):
            self.assertFalse(self.run_ssrf("exact").confirmed)


if __name__ == "__main__":
    unittest.main()
