"""Caller checks for bounded, resumable deterministic coverage."""
import unittest
from types import SimpleNamespace
from harness.coverage_tracker import build_coverage_driven, build_coverage_cases_driven
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession


class CoverageRepairTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        state = EngagementState('shop.test')
        roles = [RoleSession('user', {}, name='alice'), RoleSession('user', {}, name='bob')]
        for path in ['/api/orders/1', '/api/profile/2']:
            state.record_template('http://shop.test' + path, 'GET',
                                  HttpExchange(url='http://shop.test' + path,
                                               method='GET', response_status=200))
        for ep in state.endpoints.values():
            ep.reachable_roles = ['user']
            ep.object_scoped = True
        return state, roles

    async def test_small_budget_resume_preserves_denominator_and_avoids_completed_cells(self):
        state, roles = self.fixture()
        calls = []
        async def run(identity, method, path, check):
            calls.append((identity, method, path, check.id))
            return SimpleNamespace(status='not_confirmed', sent_count=2, summary='controls held')
        first = await build_coverage_driven(state, roles, run, driveable={'cross_identity'}, budget=1,
                                           context_key='same-source-and-policy')
        self.assertEqual(len(calls), 1)
        completed = calls[0]
        calls.clear()
        second = await build_coverage_driven(state, roles, run, driveable={'cross_identity'}, budget=100,
                                            checkpoint=first['checkpoint'], context_key='same-source-and-policy')
        self.assertNotIn(completed, calls)
        self.assertEqual(second['phase_ledger']['counts']['resumed'], 1)
        self.assertEqual(first['audited']['applicable'], second['audited']['applicable'])
        self.assertTrue(any(r['terminal_reason'] == 'unsupported_or_manual'
                            for r in second['phase_ledger']['cells']))
        self.assertTrue(all(r['terminal_reason'] for r in second['phase_ledger']['cells']))

    async def test_changed_source_or_capture_does_not_reuse_checkpoint(self):
        state, roles = self.fixture()
        calls = []
        async def run(*args):
            calls.append(args[:3])
            return SimpleNamespace(status='not_confirmed', sent_count=1)
        first = await build_coverage_driven(state, roles, run, driveable={'cross_identity'}, budget=1, context_key='old')
        second = await build_coverage_driven(state, roles, run, driveable={'cross_identity'}, budget=1,
                                            checkpoint=first['checkpoint'], context_key='new')
        self.assertEqual(second['phase_ledger']['counts']['resumed'], 0)
        self.assertEqual(len(calls), 2)

    async def test_case_driver_never_counts_no_send_or_dispatch_error_as_execution(self):
        for mode in ['blocked', 'error', 'not_confirmed']:
            with self.subTest(mode=mode):
                state, roles = self.fixture()
                async def run(*args):
                    if mode == 'error':
                        raise RuntimeError('failed before transport')
                    return SimpleNamespace(status=mode, sent_count=0)
                result = await build_coverage_cases_driven(state, roles, run,
                                                          driveable={'cross_identity'}, budget=1)
                self.assertEqual(result['cases_driven'], 1)
                self.assertEqual(result['phase_ledger']['counts']['attempted'], 1)
                self.assertEqual(result['phase_ledger']['counts']['sent'], 0)
