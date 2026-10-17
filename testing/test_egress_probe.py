"""Tests for the NC-O1 egress-containment probe (offline half).

Positive: no connection => contained. Negative control: any connection => a leak
that ``assert_contained`` refuses to pass. The listener binds to loopback so no
real external port is opened.
"""
from __future__ import annotations

import socket
import unittest

from testing.egress_probe import EgressLeak, EgressProbe


class EgressProbeTests(unittest.TestCase):
    def test_no_connection_is_contained(self):  # positive
        with EgressProbe() as probe:
            pass  # nothing connects to the sentinel
        self.assertEqual(probe.connections(), [])
        probe.assert_contained()  # must not raise
        summary = probe.summary()
        self.assertTrue(summary["contained"])
        self.assertEqual(summary["connection_count"], 0)

    def test_a_connection_is_a_leak(self):  # negative control
        probe = EgressProbe().start()
        try:
            host, port = probe.address
            sock = socket.create_connection((host, port), timeout=1)
            sock.sendall(b"leaked-egress")
            sock.close()
            self.assertTrue(probe.wait_for_connection(2.0))
        finally:
            probe.stop()
        with self.assertRaises(EgressLeak):
            probe.assert_contained()
        summary = probe.summary()
        self.assertFalse(summary["contained"])
        self.assertEqual(summary["connection_count"], 1)
        self.assertIn("leaked-egress", summary["connections"][0]["preview"])

    def test_summary_reports_bound_address(self):
        with EgressProbe() as probe:
            host, port = probe.address
            self.assertGreater(port, 0)
            self.assertIn(str(port), probe.summary()["listen_address"])


if __name__ == "__main__":
    unittest.main()
