"""v8 capability reconciliation: exercise both the tracker and engagement caller."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import cache, store
from harness.coverage_model import CellStatus, CHECKS_BY_ID
from harness.coverage_tracker import CoverageTracker


class CoverageCapabilityTests(unittest.IsolatedAsyncioTestCase):
    def tracker(self):
        tracker = CoverageTracker()
        tracker.build({
            'GET /a': {'path': '/a', 'method': 'GET', 'reachable_roles': ['anonymous'],
                       'template': {'method': 'GET'}},
            'GET /b': {'path': '/b', 'method': 'GET', 'reachable_roles': ['anonymous'],
                       'template': {'method': 'GET'}},
        }, ['anonymous', 'user'])
        return tracker

    async def test_empty_driver_is_unavailable_not_supported_or_manual(self):
        tracker = self.tracker()
        callback = AsyncMock()
        await tracker.drive_coverage_legs(callback, driveable=set())
        callback.assert_not_called()
        rows = tracker.phase_ledger()['cells']
        def row(check):
            return next(r for r in rows if r['check'] == check and r['identity'] == 'anonymous')
        self.assertEqual(row('WSTG-CONF-05')['terminal_reason'], 'validator_unavailable')
        self.assertEqual(row('WSTG-CONF-09')['terminal_reason'], 'manual_required')
        self.assertEqual(row('WSTG-CONF-02')['terminal_reason'], 'check_adapter_missing')
        self.assertFalse(row('WSTG-CONF-05')['eligible'])
        self.assertTrue(any(r['terminal_reason'] == 'unreachable_identity' for r in rows))

    async def test_dispatch_and_policy_block_are_visible(self):
        tracker = self.tracker()
        callback = AsyncMock(return_value=SimpleNamespace(status='blocked', sent_count=0))
        await tracker.drive_coverage_legs(callback, driveable={'csp', 'cors'})
        self.assertEqual(callback.await_count, 4)
        rows = [r for r in tracker.phase_ledger()['cells'] if r['attempted']]
        self.assertEqual({r['terminal_reason'] for r in rows}, {'policy_blocked'})
        self.assertTrue(all(not r['sent'] for r in rows))

    def test_host_checks_once_response_checks_remain_distinct(self):
        tracker = self.tracker()
        for cid in ('WSTG-CRYP-01', 'WSTG-CONF-09'):
            applicable = [(k, v) for k, v in tracker.matrix.cells().items()
                          if k[2] == cid and v.status != CellStatus.NOT_APPLICABLE]
            self.assertEqual(len(applicable), 1)
            # An inferred route finding must not recreate the duplicated count.
            tracker.matrix.record('user', 'GET /b', cid, status=CellStatus.DETECTED)
            self.assertEqual(tracker.matrix.get('user', 'GET /b', cid).status,
                             CellStatus.NOT_APPLICABLE)
        for cid in ('WSTG-CONF-05', 'WSTG-CONF-07', 'WSTG-CONF-08'):
            self.assertEqual(sum(k[2] == cid and v.status != CellStatus.NOT_APPLICABLE
                                 for k, v in tracker.matrix.cells().items()), 4)

    def test_catalog_routes_available_oracles_and_preserves_manual_csrf(self):
        self.assertEqual(CHECKS_BY_ID['WSTG-INPV-06'].confirmation, 'nosql')
        self.assertEqual(CHECKS_BY_ID['WSTG-BUSL-09'].confirmation, 'file_upload')
        self.assertEqual(CHECKS_BY_ID['WSTG-SESS-05'].confirmation, 'manual')


class EngagementCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old = store._DB_PATH, cache._cache
        self.addCleanup(self.restore, old)
        store._DB_PATH = Path(self.temp.name) / 'state.db'
        cache.init_cache(db_path=str(Path(self.temp.name) / 'cache.db'))

    @staticmethod
    def restore(old):
        store._DB_PATH, cache._cache = old

    def run_caller(self, enabled, case_drive):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.validators.base import ValidationResult
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg['validators'].setdefault(name, {})['enabled'] = False
        cfg['validators']['csp']['enabled'] = enabled
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = case_drive
        orch.run_active_probe = AsyncMock(return_value={
            'iterative_result': {'stop_reason': 'gave_up', 'findings': []}, 'integration': {}})
        validator = orch.validator_registry.validators.get('csp')
        calls = AsyncMock(return_value=ValidationResult('csp_validator', 'blocked', 'csp'))
        if validator:
            validator.validate = calls
        with patch('harness.engagement_builder.build_engagement', side_effect=smoke._canned_engagement), \
                patch('httpx.AsyncClient.get', new_callable=AsyncMock,
                      side_effect=smoke._responder(False)):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=0, step_budget=1, max_chain_rounds=0))
        return calls, [r for r in result['coverage']['phase_ledger']['cells']
                       if r['check'] == 'WSTG-CONF-05' and r['identity'] != 'anonymous']

    def test_registered_csp_reaches_driver_and_disabled_control_does_not(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                calls, rows = self.run_caller(True, case_drive)
                self.assertGreater(calls.await_count, 0)
                self.assertTrue(rows)
                self.assertTrue(all(r['terminal_reason'] == 'policy_blocked' for r in rows), rows)
                calls, rows = self.run_caller(False, case_drive)
                calls.assert_not_called()
                self.assertTrue(all(r['terminal_reason'] == 'validator_unavailable' for r in rows), rows)

    def test_catalog_aliases_and_registered_families_reach_engagement_dispatch(self):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_chain import _ConfirmationCache
        from harness.engagement import EngagementState
        from harness.role_crawl import RoleCrawlResult
        from harness.validators.base import ValidationResult
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        expected = {'csp', 'cors', 'header_injection', 'http_request_smuggling',
                    'race_condition', 'nosql', 'file_upload'}
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg['validators'].setdefault(name, {})['enabled'] = name in expected
        seen = set()
        async def dispatch(self_, validator, finding, exchange, case_ref=None):
            seen.add(validator.name)
            return ValidationResult(validator.name, 'blocked', finding.vulnerability_class)
        def build(*args, **kwargs):
            state = EngagementState('localhost')
            state.ingest_role_crawl({'endpoints': [{
                'method': 'POST', 'path': '/upload', 'reachable_roles': ['anonymous'],
                'by_role': {'anonymous': 200},
                'template': {'method': 'POST', 'query': 'name=test',
                             'body': '{"username":"user","password":"password"}',
                             'content_type': 'application/json'},
            }]})
            return state, RoleCrawlResult(base_url=smoke.BASE_URL)
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(return_value={'iterative_result': {'findings': []}, 'integration': {}})
        with patch('harness.engagement_builder.build_engagement', side_effect=build), \
                patch.object(_ConfirmationCache, 'validate', dispatch):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, [smoke.ROLES[0]], max_nodes=0, step_budget=1, max_chain_rounds=0))
        rows = result['coverage']['phase_ledger']['cells']
        # The engagement's cross-identity leg is not switched off by the registry's
        # arming flag (see the test below), so it is driven alongside these.
        self.assertEqual({r['confirmation'] for r in rows if r['attempted']}, expected | {'cross_identity'})
        self.assertTrue({'csp_validator', 'cors_validator', 'header_injection_validator',
                         'http_request_smuggling_validator', 'race_condition_validator',
                         'nosql', 'file_upload'} <= seen, seen)
        csrf = next(r for r in rows if r['check'] == 'WSTG-SESS-05')
        self.assertEqual(csrf['terminal_reason'], 'manual_required')
        self.assertFalse(csrf['attempted'])

    def test_cross_identity_leg_is_not_gated_by_the_registry_arming_flag(self):
        """validators.cross_identity.enabled arms the registry's tester-fed instance and
        is off in the committed config. The engagement builds its own leg from its
        identities, so that flag must not drop IDOR/BOLA from the drive. Control: an
        explicit disable of another driven family still removes it."""
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_chain import _ConfirmationCache
        from harness.validators.base import ValidationResult
        cfg = smoke._test_config()
        self.assertFalse(cfg['validators']['cross_identity']['enabled'])
        cfg['validators'].setdefault('jwt_forge', {})['enabled'] = False
        async def dispatch(self_, validator, finding, exchange, case_ref=None):
            return ValidationResult(validator.name, 'blocked', finding.vulnerability_class)
        orch = Orchestrator(cfg)
        orch.engagement_coverage_drive = True
        orch.run_active_probe = AsyncMock(return_value={'iterative_result': {'findings': []}, 'integration': {}})
        with patch('harness.engagement_builder.build_engagement', side_effect=smoke._canned_engagement), \
                patch('httpx.AsyncClient.get', new_callable=AsyncMock,
                      side_effect=smoke._responder(False)), \
                patch.object(_ConfirmationCache, 'validate', dispatch):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=0, step_budget=1, max_chain_rounds=0))
        rows = result['coverage']['phase_ledger']['cells']
        signed_in = [r for r in rows if r['confirmation'] == 'cross_identity' and r['identity'] != 'anonymous']
        self.assertTrue(signed_in)
        self.assertTrue(all(r['attempted'] and r['terminal_reason'] == 'policy_blocked'
                            for r in signed_in), signed_in)
        jwt = [r for r in rows if r['confirmation'] == 'jwt_forge' and r['shape_applicable']]
        self.assertFalse([r for r in jwt if r['attempted']])
        self.assertIn('validator_unavailable', {r['terminal_reason'] for r in jwt})
