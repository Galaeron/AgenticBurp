"""R14 real SQLite/CLI controls, all paths disposable and data synthetic."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness import data_maintenance as maintenance


class MaintenanceCallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "synthetic.db"
        self.backup = self.root / "backup.db"
        self.conn = sqlite3.connect(self.source)
        self.addCleanup(self.conn.close)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
          CREATE TABLE identities(identity_id TEXT PRIMARY KEY, label TEXT);
          CREATE TABLE state_metadata(name TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE ledger_events(data_json TEXT);
          CREATE TABLE evidence_blobs(sha256 TEXT PRIMARY KEY, data BLOB, created_at REAL);
        """)
        self.digest = hashlib.sha256(b"synthetic raw traffic").hexdigest()
        self.conn.execute("INSERT INTO identities VALUES ('synthetic-id', 'synthetic-label')")
        self.conn.execute("INSERT INTO state_metadata VALUES ('principal-hmac-v1', 'synthetic-key')")
        self.conn.execute("INSERT INTO evidence_blobs VALUES (?, ?, 1)", (self.digest, b"synthetic raw traffic"))
        self.conn.execute("INSERT INTO ledger_events VALUES (?)", (json.dumps({"response_blob": self.digest}),))
        self.conn.commit()

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = maintenance.main(list(args))
        return code, json.loads(output.getvalue())

    def backup_cli(self):
        return self.call("backup", "--source", str(self.source), "--destination", str(self.backup))

    def test_plan_reads_no_database_and_exposes_unsupported_scope(self):
        with patch.object(maintenance, "_open_readonly", side_effect=AssertionError("unexpected read")):
            code, plan = self.call("plan")
        self.assertEqual(code, 0)
        self.assertFalse(plan["automatic_retention"])
        self.assertFalse(plan["secure_erasure"])
        self.assertEqual(len(plan["actions"]), 5)

    def test_module_entrypoint_backup_and_negative_restore(self):
        result = subprocess.run([sys.executable, "-m", "harness.data_maintenance", "backup",
                                 "--source", str(self.source), "--destination", str(self.backup)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ok")
        result = subprocess.run([sys.executable, "-m", "harness.data_maintenance", "restore",
                                 "--source", str(self.backup), "--destination", str(self.root / "restore.db"),
                                 "--expected-sha256", "0" * 64], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "failed")

    def test_live_wal_backup_restore_preserves_every_table_and_resolves_blob(self):
        self.assertTrue(Path(str(self.source) + "-wal").exists())
        code, report = self.backup_cli()
        self.assertEqual(code, 0)
        self.assertEqual(report["unavailable_reference_count"], 0)
        restored = self.root / "restored.db"
        code, _ = self.call("restore", "--source", str(self.backup), "--destination", str(restored),
                            "--expected-sha256", report["sha256"])
        self.assertEqual(code, 0)
        with contextlib.closing(sqlite3.connect(restored)) as actual:
            for table in report["tables"]:
                self.assertEqual(actual.execute(f"SELECT * FROM {table}").fetchall(),
                                 self.conn.execute(f"SELECT * FROM {table}").fetchall())
        self.assertNotIn("synthetic-key", json.dumps(report))

    def test_production_store_schema_snapshot_preserves_all_tables(self):
        from harness import store
        production = self.root / "synthetic-production.db"
        with patch.object(store, "_DB_PATH", production):
            connection = store._connect()
            connection.close()
        destination = self.root / "production-backup.db"
        code, report = self.call("backup", "--source", str(production), "--destination", str(destination))
        self.assertEqual(code, 0)
        self.assertIn("findings", report["tables"])
        self.assertIn("state_metadata", report["tables"])
        with contextlib.closing(sqlite3.connect(production)) as original, contextlib.closing(sqlite3.connect(destination)) as copied:
            self.assertEqual(original.execute("SELECT * FROM state_metadata").fetchall(),
                             copied.execute("SELECT * FROM state_metadata").fetchall())

    def test_backup_has_actual_private_acl(self):
        self.assertEqual(self.backup_cli()[0], 0)
        if os.name == "nt":
            from harness.test_token_file_permissions import acl
            actual = acl(self.backup)
            self.assertTrue(actual["protected"])
            self.assertEqual(len(actual["rules"]), 1)
            self.assertEqual(actual["rules"][0]["sid"], actual["current_sid"])
        else:
            self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)

    def test_corrupted_blob_is_rejected_and_destination_never_published(self):
        self.conn.execute("UPDATE evidence_blobs SET data = ?", (b"synthetic corruption",))
        self.conn.commit()
        self.assertEqual(self.backup_cli()[0], 1)
        self.assertFalse(self.backup.exists())
        self.assertEqual(list(self.root.glob(".sqlite-snapshot-*")), [])

    def test_missing_expired_reference_reported_without_fabricated_resolution(self):
        self.conn.execute("DELETE FROM evidence_blobs")
        self.conn.commit()
        code, report = self.backup_cli()
        self.assertEqual(code, 0)
        self.assertEqual(report["unavailable_reference_count"], 1)

    def test_malformed_ledger_negative_control(self):
        self.conn.execute("UPDATE ledger_events SET data_json='[\"synthetic\"]'")
        self.conn.commit()
        self.assertEqual(self.backup_cli()[0], 1)
        self.assertFalse(self.backup.exists())

    def test_wrong_digest_restore_negative_control(self):
        self.assertEqual(self.backup_cli()[0], 0)
        restored = self.root / "restored.db"
        self.assertEqual(self.call("restore", "--source", str(self.backup), "--destination", str(restored),
                                  "--expected-sha256", "0" * 64)[0], 1)
        self.assertFalse(restored.exists())

    def test_existing_destination_preserved(self):
        self.backup.write_bytes(b"synthetic existing destination")
        self.assertEqual(self.backup_cli()[0], 1)
        self.assertEqual(self.backup.read_bytes(), b"synthetic existing destination")

    def test_permission_failure_before_sensitive_bytes(self):
        def fail(path):
            self.assertEqual(path.read_bytes(), b"")
            raise PermissionError("synthetic denial")
        boundary = "_restrict_windows_file_acl" if os.name == "nt" else None
        if boundary:
            with patch.object(maintenance, boundary, side_effect=fail):
                self.assertEqual(self.backup_cli()[0], 1)
            self.assertFalse(self.backup.exists())
        else:
            with patch.object(Path, "chmod", side_effect=PermissionError("synthetic denial")):
                self.assertEqual(self.backup_cli()[0], 1)
            self.assertFalse(self.backup.exists())

    def test_restore_rejects_unsealed_backup_sidecars(self):
        _, report = self.backup_cli()
        Path(str(self.backup) + "-wal").write_bytes(b"synthetic sidecar")
        self.assertEqual(self.call("restore", "--source", str(self.backup), "--destination", str(self.root / "restore.db"),
                                  "--expected-sha256", report["sha256"])[0], 1)


if __name__ == "__main__":
    unittest.main()
