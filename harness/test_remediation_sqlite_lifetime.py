"""R09 caller controls with ordinary data and exclusively temporary databases."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from harness.cache import ExchangeCache
from harness import store
from harness.models import HttpExchange, AnalysisResponse


class TrackedConnection(sqlite3.Connection):
    closed = False
    fail_sql = None

    def close(self):
        self.closed = True
        return super().close()

    def execute(self, sql, *args, **kwargs):
        if self.fail_sql and self.fail_sql in sql:
            raise sqlite3.OperationalError('synthetic statement failure')
        return super().execute(sql, *args, **kwargs)


class SQLiteLifetimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'ordinary.db'
        self.connections = []
        original = sqlite3.connect

        def tracked(*args, **kwargs):
            kwargs['factory'] = TrackedConnection
            conn = original(*args, **kwargs)
            self.connections.append(conn)
            return conn

        handle = patch('sqlite3.connect', side_effect=tracked)
        handle.start()
        self.addCleanup(handle.stop)
        # Keep handles alive to prove deterministic close, independent of GC.
        self.addCleanup(lambda: [c.close() for c in self.connections if not c.closed])

    def assert_closed(self):
        self.assertTrue(self.connections)
        self.assertTrue(all(c.closed for c in self.connections))

    def test_cache_public_write_read_stats_clear_close_connections(self):
        cache = ExchangeCache(self.path)
        self.assert_closed()
        exchange = HttpExchange(url='https://ordinary.invalid/status', method='GET',
                                response_status=200, response_body='Available')
        response = AnalysisResponse(coordinator_model='fake', dispatched_agents=[],
                                    agent_reports=[], summary='Ordinary response')
        cache.put(exchange, response, 'fake', {})
        actual = cache.get(exchange, 'fake', {})
        self.assertEqual(actual.summary, response.summary)
        self.assertEqual(cache.size(), 1)
        self.assertEqual(cache.stats().hits, 1)
        cache.clear()
        self.assertEqual(cache.size(), 0)
        self.assert_closed()

    def test_cache_public_error_path_closes_connection(self):
        cache = ExchangeCache(self.path)
        original = cache._get_connection

        def failing():
            conn = original()
            conn.fail_sql = 'SELECT COUNT'
            return conn

        with patch.object(cache, '_get_connection', side_effect=failing):
            with self.assertLogs('harness.cache', level='WARNING'):
                self.assertEqual(cache.exchange_size(), 0)
        self.assert_closed()

    def test_connection_context_preserves_commit_and_rollback(self):
        cache = ExchangeCache(self.path)
        original = cache._get_connection

        def transactional():
            conn = original()
            conn.isolation_level = 'DEFERRED'
            return conn

        with patch.object(cache, '_get_connection', side_effect=transactional):
            with cache._connection() as conn:
                conn.execute('CREATE TABLE ordinary (value TEXT)')
                conn.execute("INSERT INTO ordinary VALUES ('kept')")
            with self.assertRaisesRegex(ValueError, 'synthetic'):
                with cache._connection() as conn:
                    conn.execute("INSERT INTO ordinary VALUES ('rolled back')")
                    raise ValueError('synthetic failure')
            with cache._connection() as conn:
                self.assertEqual([r[0] for r in conn.execute('SELECT value FROM ordinary')], ['kept'])
        self.assert_closed()

    def test_public_caller_detects_original_nonclosing_defect(self):
        cache = ExchangeCache(self.path)

        @contextmanager
        def original_nonclosing():
            with cache._get_connection() as conn:
                yield conn

        with patch.object(cache, '_connection', original_nonclosing):
            self.assertEqual(cache.exchange_size(), 0)
        self.assertFalse(self.connections[-1].closed)

    def test_store_public_read_closes_owned_connection(self):
        with patch.object(store, '_DB_PATH', self.path):
            self.assertEqual(store.all_host_findings('https://ordinary.invalid'), [])
        self.assert_closed()

    def test_store_setup_failures_close_before_ownership_transfer(self):
        for error in (sqlite3.OperationalError('synthetic setup failure'),
                      ValueError('synthetic setup failure'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), patch.object(store, '_DB_PATH', self.path), \
                    patch.object(store, '_initialise_connection', side_effect=error):
                with self.assertRaises(type(error)):
                    store.all_host_findings('https://ordinary.invalid')
            self.assert_closed()

    def test_store_begin_failure_closes_before_caller_receives_connection(self):
        original = store._connect

        def failing_begin():
            conn = original()
            conn.fail_sql = 'BEGIN IMMEDIATE'
            return conn

        with patch.object(store, '_DB_PATH', self.path), \
                patch.object(store, '_connect', side_effect=failing_begin):
            with self.assertRaises(sqlite3.OperationalError):
                store.reclaim_expired_leases(engagement_id='synthetic-empty')
        self.assert_closed()

    def test_store_borrowed_blob_connection_remains_owned_by_caller(self):
        with patch.object(store, '_DB_PATH', self.path):
            conn = store._connect()
            try:
                self.assertIsNone(store.get_evidence_blob('synthetic-missing', conn=conn))
                self.assertFalse(conn.closed)
                self.assertEqual(conn.execute('SELECT 1').fetchone()[0], 1)
            finally:
                conn.close()
        self.assert_closed()


if __name__ == '__main__':
    unittest.main()
