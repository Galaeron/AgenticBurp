"""Tests for the NC-O1 egress-containment probe (offline half).

Positive: no connection => contained. Negative control: any connection => a leak
that ``assert_contained`` refuses to pass. The listener binds to loopback so no
real external port is opened.
"""
from __future__ import annotations

import io
import json
import socket
import socketserver
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from testing import egress_probe
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

    def test_stop_right_after_a_connection_counts_it(self):
        """Stopped without waiting: the connection is counted whether the serve loop
        accepted it or it was still in the listen backlog."""
        probe = EgressProbe().start()
        try:
            with socket.create_connection(probe.address, timeout=1) as sock:
                sock.sendall(b"leaked-at-stop")
        finally:
            probe.stop()
        self.assertEqual(probe.summary()["connection_count"], 1)

    def test_connection_left_in_the_backlog_is_counted(self):
        probe = EgressProbe().start()
        try:
            probe._server.shutdown()      # the serve loop ends; the socket still listens
            with socket.create_connection(probe.address, timeout=1) as sock:
                sock.sendall(b"never accepted by the loop")
        finally:
            probe.stop()
        self.assertFalse(probe.summary()["contained"])
        self.assertEqual(probe.summary()["connection_count"], 1)


# --- R37: the CLI's final verdict counts a connection whose handler still runs ----------
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _json_objects(text: str) -> list:
    decoder, objects, i = json.JSONDecoder(), [], 0
    while (i := text.find("{", i)) >= 0:
        obj, i = decoder.raw_decode(text, i)
        objects.append(obj)
    return objects


class EgressProbeCliTests(unittest.TestCase):
    """`python -m testing.egress_probe` (main) is how the owner's live proof runs."""

    def _cli(self, *, connect: bool, duration: float = 0.6):
        entered, release = threading.Event(), threading.Event()
        original = egress_probe._Handler.handle

        def paused(handler):          # a handler that has not read yet when the run ends
            entered.set()
            release.wait(10)
            original(handler)

        port, box, out = _free_port(), {}, io.StringIO()
        with patch.object(egress_probe._Handler, "handle", paused), redirect_stdout(out):
            cli = threading.Thread(target=lambda: box.setdefault("rc", egress_probe.main(
                ["--host", "127.0.0.1", "--port", str(port), "--duration", str(duration)])),
                daemon=True)
            cli.start()
            end = time.monotonic() + 5
            while "listening" not in out.getvalue() and time.monotonic() < end:
                time.sleep(0.01)
            try:
                if connect:
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                        sock.sendall(b"leaked during the run")
                        self.assertTrue(entered.wait(5))
                        cli.join(15)
                else:
                    cli.join(15)
            finally:
                release.set()
                cli.join(15)
        return box.get("rc"), _json_objects(out.getvalue())[-1]

    def test_connection_with_a_pending_handler_fails_the_proof(self):
        rc, summary = self._cli(connect=True)
        self.assertEqual(rc, 2, summary)
        self.assertFalse(summary["contained"])
        self.assertEqual(summary["connection_count"], 1)

    def test_nothing_connecting_passes_the_proof(self):
        """Control: no connection -> contained, exit 0."""
        rc, summary = self._cli(connect=False)
        self.assertEqual(rc, 0, summary)
        self.assertTrue(summary["contained"])

    def test_recording_only_after_recv_is_detected(self):
        """Fault injection: the pre-R37 probe (record after recv, no drain or backlog)
        certifies containment although a connection was accepted."""
        with patch.object(egress_probe._Server, "process_request",
                          socketserver.ThreadingMixIn.process_request), \
                patch.object(egress_probe.EgressProbe, "_accept_backlog", lambda self: None):
            rc, summary = self._cli(connect=True)
        self.assertEqual((rc, summary["connection_count"]), (0, 0),
                         "late recording no longer certifies a leak -- the control is vacuous")


if __name__ == "__main__":
    unittest.main()
