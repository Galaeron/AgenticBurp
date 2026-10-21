"""I02 batch C (C1): migration and rollback of the observation tables.

The "old" database is built from testing_fixtures/state_schema_pre_i02c.sql, the
schema the previous build created (frozen, not regenerated), plus legacy rows.
The new store then opens it. Positive: both tables appear, legacy tables and
rows are unchanged, and nothing legacy becomes an observation. Rollback: the old
build's statements still work on a migrated database, and dropping the two
tables restores the legacy schema exactly. Faults: a migration that altered a
legacy table or bumped PRAGMA user_version is caught by the identity checks.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from harness import store
from harness.models import HttpExchange

_LEGACY_SQL = Path(__file__).resolve().parent / "testing_fixtures" / "state_schema_pre_i02c.sql"
_NEW_OBJECTS = {"exchange_observations", "observation_attributions",
                "idx_exchange_observations_scope", "idx_exchange_observations_endpoint"}
_LEGACY_URL = "https://legacy.example/api/orders/7"


def _schema(conn: sqlite3.Connection) -> dict[str, str]:
    return {name: sql for name, sql in conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")}


def _legacy_identity(conn: sqlite3.Connection) -> dict:
    """Legacy schema text, every legacy row and the fingerprint-version pragma."""
    schema = {n: s for n, s in _schema(conn).items() if n not in _NEW_OBJECTS}
    rows = {name: sorted(map(repr, conn.execute(f'SELECT * FROM "{name}"')))
            for name, sql in schema.items() if sql.lstrip().upper().startswith("CREATE TABLE")}
    return {"schema": schema, "rows": rows,
            "user_version": conn.execute("PRAGMA user_version").fetchone()[0]}


class ObservationMigrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i02c_migration_")
        self._orig = store._DB_PATH
        self.db = Path(self._tmp) / "legacy.db"
        conn = sqlite3.connect(self.db)
        try:
            conn.executescript(_LEGACY_SQL.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO state_metadata VALUES ('principal-hmac-v1', ?)", ("11" * 32,))
            # Legacy default-pile finding: empty captured principal, as before I02-B.
            conn.execute(
                "INSERT INTO findings (host, url, method, agent, vulnerability_class, severity, confidence, "
                "summary, basis, fingerprint, exchange_id, run_id, created_at) VALUES "
                "('legacy.example', ?, 'GET', 'idor', 'idor', 'low', 0.4, 'legacy finding', 'assumed', "
                "'fp-legacy', 'ex-legacy', 'run-legacy', 1.0)", (_LEGACY_URL,))
            conn.execute("INSERT INTO finding_observations VALUES ('fp-legacy', 'run-legacy', 'ex-legacy', 1.0)")
            conn.execute("INSERT INTO identities (id, name, role, created_at, tenant) "
                         "VALUES ('id-legacy', 'legacy user', 'user', 1.0, NULL)")
            conn.commit()
            self.before = _legacy_identity(conn)
        finally:
            conn.close()
        store._DB_PATH = self.db

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _open(self) -> sqlite3.Connection:
        conn = store._connect()
        conn.close()
        return sqlite3.connect(self.db)

    def test_new_build_adds_tables_and_leaves_legacy_data_unchanged(self):
        conn = self._open()
        try:
            self.assertTrue(_NEW_OBJECTS <= set(_schema(conn)))
            self.assertEqual(_legacy_identity(conn)["schema"], self.before["schema"])
            self.assertEqual(_legacy_identity(conn)["user_version"], 3)
            rows = _legacy_identity(conn)["rows"]
            marker = rows.pop("state_metadata")
            expected = dict(self.before["rows"])
            self.assertEqual(sorted(set(marker) - set(expected.pop("state_metadata"))),
                             [repr(("observation-schema", "1"))])
            self.assertEqual(rows, expected)
            self.assertEqual(conn.execute("SELECT count(*) FROM exchange_observations").fetchone()[0], 0,
                             "nothing is backfilled from legacy findings")
        finally:
            conn.close()

    def test_legacy_rows_are_not_reinterpreted_as_observations(self):
        self._open().close()
        for principal in ("", "anonymous"):
            selection = store.select_observations(_LEGACY_URL, captured_principal=principal)
            self.assertEqual((selection["selected"], selection["excluded_counts"]), ([], {}))
        # Legacy prior-findings context keeps its I02-B behaviour: the empty-principal
        # default-pile row stays out of a computed principal's history.
        self.assertEqual(store.prior_findings_summary(_LEGACY_URL, captured_principal="anonymous"), "")
        self.assertEqual(store.finding_observations(["fp-legacy"]), {"fp-legacy": ["ex-legacy"]})

    def test_reopening_is_idempotent(self):
        first_conn = self._open()
        try:
            first = _schema(first_conn)
        finally:
            first_conn.close()
        second_conn = self._open()
        try:
            self.assertEqual(_schema(second_conn), first)
            self.assertEqual(second_conn.execute(
                "SELECT count(*) FROM state_metadata WHERE name = 'observation-schema'").fetchone()[0], 1)
        finally:
            second_conn.close()

    def test_old_build_statements_still_work_on_a_migrated_database(self):
        exchange = HttpExchange(url="https://legacy.example/api/orders/8", method="GET",
                                response_status=200, response_body="{}")
        store.record_observation(exchange)
        conn = sqlite3.connect(self.db)
        try:
            # The previous build's schema script is CREATE ... IF NOT EXISTS-safe here.
            conn.executescript(_LEGACY_SQL.read_text(encoding="utf-8")
                               .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
                               .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
                               .replace("CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ")
                               .replace("PRAGMA user_version = 3;", ""))
            conn.execute("INSERT INTO finding_observations VALUES ('fp-new', 'run-new', 'ex-new', 2.0)")
            conn.execute(
                "INSERT INTO findings (host, url, method, agent, vulnerability_class, severity, confidence, "
                "summary, basis, fingerprint, created_at) VALUES ('legacy.example', ?, 'GET', 'a', 'xss', "
                "'low', 0.1, 's', 'assumed', 'fp-new', 2.0)", (_LEGACY_URL,))
            conn.commit()
            self.assertEqual(conn.execute("SELECT count(*) FROM exchange_observations").fetchone()[0], 1)
        finally:
            conn.close()

    def test_rollback_by_dropping_the_new_tables_restores_the_legacy_store(self):
        store.record_observation(HttpExchange(url="https://legacy.example/x", method="GET"))
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("DROP TABLE exchange_observations")
            conn.execute("DROP TABLE observation_attributions")
            conn.execute("DELETE FROM state_metadata WHERE name = 'observation-schema'")
            conn.commit()
            after = _legacy_identity(conn)
        finally:
            conn.close()
        self.assertEqual(after["schema"], self.before["schema"])
        self.assertEqual(after["user_version"], self.before["user_version"])
        # The rollback leaves the observation's evidence blob behind (removed by
        # retention or a wipe later); every other legacy row is unchanged.
        after["rows"].pop("evidence_blobs")
        before_rows = dict(self.before["rows"])
        before_rows.pop("evidence_blobs")
        self.assertEqual(after["rows"], before_rows)

    def test_fault_altering_a_legacy_table_is_detected(self):
        conn = self._open()
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN observation_id TEXT NOT NULL DEFAULT ''")
            self.assertNotEqual(_legacy_identity(conn)["schema"], self.before["schema"])
        finally:
            conn.close()

    def test_fault_bumping_user_version_is_detected(self):
        conn = self._open()
        try:
            conn.execute("PRAGMA user_version = 4")
            self.assertNotEqual(_legacy_identity(conn)["user_version"], self.before["user_version"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
