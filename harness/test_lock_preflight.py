"""OPS-3: the installed-versus-lock preflight and the places that call it.

The exact environment the audit found (mitmproxy 12.2.3 and brotli 1.2.0 against a lock
pinning 12.3.1 and 1.2.1) is the positive case; the same environment at the locked
versions is the negative control. The wiring tests drive the real callers (server startup
and GET /health/details, verification_snapshot.preflight) with the check patched to those
versions, so deleting a call site fails them.
"""
import contextlib
import importlib
import importlib.metadata
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import lock_preflight as lp
from harness import store
from harness import verification_snapshot as snapshot

ROOT = Path(__file__).resolve().parent.parent
E08_LOCK = (
    "# frozen from CI\n"
    "brotli==1.2.1\n"
    "Flask==3.1.3\n"
    "mitmproxy==12.3.1\n"
    "backports.zstd==1.7.0; python_version < \"3.14\"\n"
)
E08_HOST = {"mitmproxy": "12.2.3", "brotli": "1.2.0", "flask": "3.1.3"}


def _lookup(table):
    return lambda name: table.get(lp.canonical(name))


def _mismatching_report():
    return lp.LockReport(
        "harness/requirements.lock", True, checked=3,
        mismatches=[lp.Mismatch("mitmproxy", "12.2.3", "12.3.1"),
                    lp.Mismatch("brotli", "1.2.0", "1.2.1")])


def _clean_report():
    return lp.LockReport("harness/requirements.lock", True, checked=3)


class ParseLockTests(unittest.TestCase):
    def test_pins_markers_comments_and_options(self):
        pins = lp.parse_lock(
            "# comment\n\n-r other.txt\nuvicorn[standard]==0.52.4\n"
            "backports.zstd==1.7.0; python_version < \"3.14\"  # tail\n"
            "not a pin line\nFlask==3.1.3\n")
        self.assertEqual([(p.name, p.version, p.marker) for p in pins], [
            ("uvicorn", "0.52.4", None),
            ("backports.zstd", "1.7.0", 'python_version < "3.14"'),
            ("Flask", "3.1.3", None),
        ])

    def test_canonical_name_matches_pep_503(self):
        self.assertEqual(lp.canonical("Flask"), "flask")
        self.assertEqual(lp.canonical("ruamel.yaml"), lp.canonical("ruamel_yaml"))
        self.assertEqual(lp.canonical("mitmproxy_rs"), "mitmproxy-rs")


class CheckLockTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.lock = Path(self._tmp.name) / "requirements.lock"
        self.lock.write_text(E08_LOCK, encoding="utf-8")

    def check(self, host, **kw):
        return lp.check_lock(self.lock, installed=_lookup(host), **kw)

    def test_audit_environment_reports_both_mismatches(self):
        # E08: mitmproxy 12.2.3 and brotli 1.2.0 against the lock's 12.3.1 and 1.2.1.
        report = self.check(E08_HOST, marker_applies=lambda m: False)
        self.assertFalse(report.ok)
        self.assertEqual(
            sorted((m.name, m.installed, m.pinned) for m in report.mismatches),
            [("brotli", "1.2.0", "1.2.1"), ("mitmproxy", "12.2.3", "12.3.1")])
        text = "\n".join(report.warnings())
        self.assertIn("mitmproxy: installed 12.2.3, lock pins 12.3.1", text)
        self.assertIn("brotli: installed 1.2.0, lock pins 1.2.1", text)
        self.assertIn("pip install -r harness/requirements.lock", text)

    def test_matching_versions_report_nothing(self):
        # Negative control for the test above: the same host at the locked versions.
        host = dict(E08_HOST, mitmproxy="12.3.1", brotli="1.2.1")
        report = self.check(host, marker_applies=lambda m: False)
        self.assertTrue(report.ok)
        self.assertEqual(report.mismatches, [])
        self.assertEqual(report.warnings(), [])
        self.assertEqual(report.checked, 3)

    def test_an_uninstalled_pin_is_missing_not_a_mismatch(self):
        # A core-only install lacks Flask, pytest and mitmproxy; that is not drift.
        report = self.check({"brotli": "1.2.1"}, marker_applies=lambda m: False)
        self.assertTrue(report.ok)
        self.assertEqual(sorted(report.missing), ["Flask", "mitmproxy"])

    def test_marker_pins_are_checked_only_when_the_marker_applies(self):
        host = dict(E08_HOST, mitmproxy="12.3.1", brotli="1.2.1", **{"backports-zstd": "0.0.1"})
        skipped = self.check(host, marker_applies=lambda m: False)
        self.assertTrue(skipped.ok)
        self.assertEqual(skipped.skipped, ["backports.zstd"])
        applied = self.check(host, marker_applies=lambda m: True)
        self.assertEqual([m.name for m in applied.mismatches], ["backports.zstd"])
        unknown = self.check(host, marker_applies=lambda m: None)
        self.assertEqual(unknown.skipped, ["backports.zstd"])

    def test_a_missing_lock_file_is_reported_not_raised(self):
        report = lp.check_lock(Path(self._tmp.name) / "absent.lock", installed=_lookup({}))
        self.assertFalse(report.lock_found)
        self.assertTrue(report.ok)

    def test_real_importlib_metadata_lookup(self):
        have = importlib.metadata.version("PyYAML")
        self.lock.write_text(f"PyYAML=={have}\nnot-installed-xyz==1.0\n", encoding="utf-8")
        clean = lp.check_lock(self.lock)
        self.assertTrue(clean.ok)
        self.assertEqual(clean.missing, ["not-installed-xyz"])
        self.lock.write_text("PyYAML==0.0.1\n", encoding="utf-8")
        drift = lp.check_lock(self.lock)
        self.assertEqual([(m.name, m.pinned) for m in drift.mismatches], [("PyYAML", "0.0.1")])
        self.assertEqual(drift.mismatches[0].installed, have)


class CommittedLockTests(unittest.TestCase):
    """The committed lock, version-agnostic: the preflight tracks whatever it pins."""

    def setUp(self):
        self.pins = {lp.canonical(p.name): p for p in lp.parse_lock(lp.LOCK_PATH.read_text(encoding="utf-8"))
                     if p.marker is None}

    def test_the_lock_pins_the_packages_the_audit_named(self):
        self.assertIn("mitmproxy", self.pins)
        self.assertIn("brotli", self.pins)
        self.assertGreater(len(self.pins), 50)

    def test_host_at_the_lock_is_clean_and_one_drifted_pin_is_found(self):
        host = {name: pin.version for name, pin in self.pins.items()}
        clean = lp.check_lock(installed=_lookup(host), marker_applies=lambda m: False)
        self.assertTrue(clean.ok, clean.warnings())
        host["mitmproxy"] = "0.0.1"
        drift = lp.check_lock(installed=_lookup(host), marker_applies=lambda m: False)
        self.assertEqual([m.name for m in drift.mismatches], ["mitmproxy"])


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.lock = Path(self._tmp.name) / "requirements.lock"
        self.lock.write_text("PyYAML==0.0.1\n", encoding="utf-8")

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = lp.main(["--lock", str(self.lock), *args])
        return code, out.getvalue(), err.getvalue()

    def test_default_is_advisory_and_strict_is_blocking(self):
        code, _, err = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("PyYAML: installed", err)
        strict_code, _, _ = self.run_main("--strict")
        self.assertEqual(strict_code, 1)

    def test_clean_environment_is_zero_even_when_strict(self):
        self.lock.write_text(f"PyYAML=={importlib.metadata.version('PyYAML')}\n", encoding="utf-8")
        code, out, err = self.run_main("--strict")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("match the lock", out)


class SnapshotPreflightWiringTests(unittest.TestCase):
    """verification_snapshot.preflight reports drift from the snapshot's own lock."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for name in snapshot.REQUIRED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"")

    def preflight(self):
        with patch.object(snapshot.importlib.util, "find_spec", return_value=object()):
            return snapshot.preflight(self.root)

    def test_a_drifted_lock_pin_is_logged_not_refused(self):
        (self.root / "harness/requirements.lock").write_text("PyYAML==0.0.1\n", encoding="utf-8")
        with self.assertLogs("harness.verification_snapshot", "WARNING") as logs:
            self.preflight()
        self.assertIn("PyYAML: installed", "\n".join(logs.output))

    def test_a_matching_lock_logs_nothing(self):
        # Negative control: no WARNING when installed == pinned.
        have = importlib.metadata.version("PyYAML")
        (self.root / "harness/requirements.lock").write_text(f"PyYAML=={have}\n", encoding="utf-8")
        with self.assertNoLogs("harness.verification_snapshot", "WARNING"):
            self.preflight()


class ServerWiringTests(unittest.TestCase):
    """server.py logs the mismatch at startup and serves it at GET /health/details."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        original_db = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"
        self.addCleanup(setattr, store, "_DB_PATH", original_db)

    def start_server(self, report):
        import harness.server as server_module
        with patch.object(lp, "check_lock", return_value=report):
            with self.assertLogs("harness.server", "INFO") as logs:
                importlib.reload(server_module)
        from fastapi.testclient import TestClient

        async def _probe(timeout=3.0):
            return {"reachable": True, "models": [], "error": None}

        server_module.orchestrator.ollama.health_check = _probe
        client = TestClient(server_module.app, base_url="http://localhost",
                            headers={"Authorization": f"Bearer {server_module._mutation_token()}"})
        return client, logs.output

    def test_mismatch_is_logged_at_startup_and_served_by_health_details(self):
        client, logs = self.start_server(_mismatching_report())
        text = "\n".join(logs)
        self.assertIn("WARNING:harness.server:dependency lock mismatch: mitmproxy: installed 12.2.3, "
                      "lock pins 12.3.1", text)
        self.assertIn("brotli: installed 1.2.0, lock pins 1.2.1", text)
        body = client.get("/health/details").json()["dependency_lock"]
        self.assertFalse(body["ok"])
        self.assertEqual(sorted((m["package"], m["installed"], m["pinned"]) for m in body["mismatches"]),
                         [("brotli", "1.2.0", "1.2.1"), ("mitmproxy", "12.2.3", "12.3.1")])

    def test_a_clean_environment_is_silent_and_reports_ok(self):
        # Negative control: matching versions log no mismatch and report ok.
        client, logs = self.start_server(_clean_report())
        self.assertNotIn("dependency lock mismatch", "\n".join(logs))
        body = client.get("/health/details").json()["dependency_lock"]
        self.assertTrue(body["ok"])
        self.assertEqual(body["mismatches"], [])

    def test_the_unauthenticated_health_route_does_not_carry_it(self):
        from fastapi.testclient import TestClient
        client, _ = self.start_server(_mismatching_report())
        import harness.server as server_module
        anonymous = TestClient(server_module.app, base_url="http://localhost")
        self.assertEqual(anonymous.get("/health").json(), {"status": "ok"})
        self.assertEqual(anonymous.get("/health/details").status_code, 401)


if __name__ == "__main__":
    unittest.main()
