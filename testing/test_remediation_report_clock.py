"""R18 report-only controls: no analysis, providers, target sends or corpus reads."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from harness import cache, store
from harness.models import Finding, HttpExchange
from testing.test_blind_eval_harness import _load_runner_module


class ReportClockCallerTests(unittest.TestCase):
    def setUp(self):
        self.runner = _load_runner_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        db = patch.object(store, '_DB_PATH', self.root / 'state.db')
        db.start()
        self.addCleanup(db.stop)
        original_cache = cache._cache
        self.addCleanup(lambda: setattr(cache, '_cache', original_cache))
        self.exchanges = [{'url': 'https://ordinary.invalid/status', 'method': 'GET'}]
        self.before = datetime(2026, 10, 5, 12, 59, 59, tzinfo=timezone.utc)
        self.after = datetime(2026, 10, 5, 13, 0, 0, tzinfo=timezone.utc)

    def score(self, generated_at=None):
        return self.runner.build_scorecard([], self.exchanges, quarantine_leads=False,
            fail_open_mode='none', config_fingerprint_value='synthetic',
            fail_open_stats_before={}, fail_open_stats_final={}, generated_at=generated_at)['markdown_reports']

    def test_injected_clock_keeps_content_equal_across_minute_boundary(self):
        with patch('harness.report_generator.datetime') as clock:
            clock.now.side_effect = [self.before, self.after]
            first, second = self.score(self.before), self.score(self.before)
            self.assertEqual(first, second)
            clock.now.assert_not_called()
        self.assertIn('Generated: 2026-10-05 12:59 UTC', first['ordinary.invalid'])

    def test_default_clock_still_renders_real_timestamp_change(self):
        with patch('harness.report_generator.datetime') as clock:
            clock.now.side_effect = [self.before, self.after]
            first, second = self.score(), self.score()
        self.assertNotEqual(first, second)
        self.assertIn('Generated: 2026-10-05 13:00 UTC', second['ordinary.invalid'])

    def test_real_content_difference_remains_visible_with_fixed_clock(self):
        before = self.score(self.before)
        store.persist_findings(HttpExchange(url=self.exchanges[0]['url'], method='GET'),
            'ordinary', [Finding(vulnerability_class='passive_observation', severity='info',
                confidence=0.5, summary='Ordinary observation', evidence='Captured text',
                suggested_test='', basis='derived')])
        after = self.score(self.before)
        self.assertNotEqual(before, after)
        self.assertIn('Ordinary observation', after['ordinary.invalid'])

    def test_run_once_passes_report_timestamp_without_running_analysis(self):
        with patch.object(self.runner, 'run_exchanges', new=AsyncMock(return_value=[])), \
                patch('harness.report_generator.datetime') as clock:
            result = self.runner.run_once(self.exchanges, config={}, state_db=self.root / 'state.db',
                cache_db=self.root / 'cache.db', orchestrator_factory=lambda _: SimpleNamespace(),
                generated_at=self.after)
            clock.now.assert_not_called()
        self.assertIn('Generated: 2026-10-05 13:00 UTC', result['markdown_reports']['ordinary.invalid'])


if __name__ == '__main__':
    unittest.main()
