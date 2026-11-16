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


def _declared_html_state(base, roles, *, path='/api/tickets/7', **kwargs):
    """Observed fixture requests carry the input/media-type prerequisites."""
    from harness.engagement import EngagementState
    from harness.models import HttpExchange
    from harness.role_crawl import RoleCrawlResult
    state=EngagementState('localhost')
    for role in roles:
        state.record_template(base+path,'GET',HttpExchange(url=base+path,method='GET',
            request_headers=role.headers,response_status=200,
            response_headers={'Content-Type':'text/html'},response_body='<html>fixture</html>'))
    for ep in state.endpoints.values():
        ep.reachable_roles=sorted({r.role for r in roles});ep.object_scoped=True
    return state,RoleCrawlResult(base_url=base)


def _controlled_model(orch):
    from harness.test_default_history_caller import _RecordingModel
    model=_RecordingModel();orch.ollama=model
    for agent in orch.agent_manager.agents.values(): agent.ollama=model
    if hasattr(orch,'coordinator'): orch.coordinator.ollama=model
    orch.capture_review_limit=0


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
        self.assertEqual(row('WSTG-CONF-12')['terminal_reason'], 'validator_unavailable')
        self.assertEqual(row('WSTG-CONF-09')['terminal_reason'], 'manual_required')
        self.assertEqual(row('WSTG-INFO-02')['terminal_reason'], 'check_adapter_missing')
        # CONF-02 has an adapter now; an empty driver leaves it unavailable, not missing.
        self.assertEqual(row('WSTG-CONF-14')['terminal_reason'], 'validator_unavailable')
        self.assertFalse(row('WSTG-CONF-12')['eligible'])
        self.assertTrue(any(r['terminal_reason'] == 'unreachable_identity' for r in rows))

    async def test_dispatch_and_policy_block_are_visible(self):
        tracker = self.tracker()
        callback = AsyncMock(return_value=SimpleNamespace(status='blocked', sent_count=0))
        await tracker.drive_coverage_legs(callback, driveable={'csp', 'cors'})
        # CONF-12 (csp), CLNT-07 (cors) and WG-1's CLNT-09 framing row (csp) on
        # two endpoints each.
        self.assertEqual(callback.await_count, 6)
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
        for cid in ('WSTG-CONF-12', 'WSTG-CONF-07', 'WSTG-CLNT-07'):
            self.assertEqual(sum(k[2] == cid and v.status != CellStatus.NOT_APPLICABLE
                                 for k, v in tracker.matrix.cells().items()), 4)

    def test_catalog_routes_available_oracles_including_csrf(self):
        self.assertEqual(CHECKS_BY_ID['WSTG-INJT-05.6'].confirmation, 'nosql')
        # WG-1: BUSL-09 (malicious files) is operator-judged; the extension-bypass
        # leg is BUSL-08 (unexpected file types).
        self.assertEqual(CHECKS_BY_ID['WSTG-BUSL-09'].confirmation, 'manual')
        self.assertEqual(CHECKS_BY_ID['WSTG-BUSL-08'].confirmation, 'file_upload')
        # WG-2 routes CSRF to its registered leg; a confirmation still needs the
        # browser PoC (ORACLE_RETIREMENTS.md).
        self.assertEqual(CHECKS_BY_ID['WSTG-SESS-05'].confirmation, 'csrf')


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

    def run_caller(self, enabled, case_drive, status='blocked'):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.validators.base import ValidationResult
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg['validators'].setdefault(name, {})['enabled'] = False
        cfg['validators']['csp']['enabled'] = enabled
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = case_drive
        orch.run_active_probe = AsyncMock(return_value={
            'iterative_result': {'stop_reason': 'gave_up', 'findings': []}, 'integration': {}})
        validator = orch.validator_registry.validators.get('csp')
        calls = AsyncMock(return_value=ValidationResult('csp_validator', status, 'csp'))
        if validator:
            validator.validate = calls
        with patch('harness.engagement_builder.build_engagement', side_effect=_declared_html_state), \
                patch('httpx.AsyncClient.get', new_callable=AsyncMock,
                      side_effect=smoke._responder(False)):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=0, step_budget=1, max_chain_rounds=0))
        return calls, [r for r in result['coverage']['phase_ledger']['cells']
                       if r['check'] == 'WSTG-CONF-12' and r['identity'] != 'anonymous']

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

    def test_leg_precondition_refusal_is_not_an_incomplete_attempt(self):
        """live-v8 f2a78499593e: 1068 of 1270 `incomplete_attempt` cells were legs that
        ran and declined on their own precondition (no JWT, no object id, ...). The
        drive had dispatched every queued cell, so the label misread as throughput.
        Control: a leg that answers without a verdict stays an incomplete attempt,
        and neither outcome is a clean negative."""
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                calls, rows = self.run_caller(True, case_drive, status='skipped')
                self.assertGreater(calls.await_count, 0)
                self.assertTrue(rows)
                self.assertTrue(all(r['attempted'] and r['terminal_reason'] == 'leg_precondition_unmet'
                                    for r in rows), rows)
                self.assertFalse(any(r['sent'] or r['conclusive'] for r in rows), rows)
                calls, rows = self.run_caller(True, case_drive, status='inconclusive')
                self.assertGreater(calls.await_count, 0)
                self.assertTrue(all(r['attempted'] and r['terminal_reason'] == 'incomplete_attempt'
                                    for r in rows), rows)
                self.assertFalse(any(r['sent'] or r['conclusive'] for r in rows), rows)

    def test_catalog_aliases_and_registered_families_reach_engagement_dispatch(self):
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_chain import _ConfirmationCache
        from harness.engagement import EngagementState
        from harness.role_crawl import RoleCrawlResult
        from harness.validators.base import ValidationResult
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        # file_upload reaches dispatch through the WSTG-BUSL-08 row (WG-2 item 1);
        # BUSL-09 is operator-judged.
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
            from harness.models import HttpExchange
            for method,path,body in [('POST','/login','{"username":"user","password":"password"}'),
                                     ('GET','/api/items/7','')]:
                state.record_template(smoke.BASE_URL+path,method,HttpExchange(url=smoke.BASE_URL+path,
                    method=method,request_headers={'Content-Type':'application/json'} if body else {},
                    request_body=body,response_status=200,response_headers={'Content-Type':'text/html'},
                    response_body='<html>fixture</html>'))
            for ep in state.endpoints.values(): ep.reachable_roles=['anonymous']
            return state, RoleCrawlResult(base_url=smoke.BASE_URL)
        orch = Orchestrator(cfg)
        _controlled_model(orch)
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
        # WG-2: SESS-05 names the registered csrf leg (its verdict stays a retired
        # observation, and its replays stay behind allow_mutating_replay). Disabled
        # here, it is unavailable rather than manual, and is never attempted.
        csrf = next(r for r in rows if r['check'] == 'WSTG-SESS-05')
        self.assertEqual(csrf['terminal_reason'], 'validator_unavailable')
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
        _controlled_model(orch)
        orch.engagement_coverage_drive = True
        orch.run_active_probe = AsyncMock(return_value={'iterative_result': {'findings': []}, 'integration': {}})
        with patch('harness.engagement_builder.build_engagement', side_effect=_declared_html_state), \
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

class AddedDriveLegCallerTests(unittest.TestCase):
    """WG-2 item 5: client_trust (BUSL-02), websocket (CLNT-10) and oauth (ATHZ-05)
    are in _LEG_CONFIRMATIONS, so investigate_engagement drives each applicable
    cell with no agent label, and a clean answer leaves it attempted -> not_detected.
    Negatives: a write with no server-owned field, an OAuth path with no OAuth
    parameters, a long-poll capture and a Bearer-only handshake are never
    dispatched; client_trust stays inert without allow_mutating_replay.

    Only the coverage drive's dispatches count here: it always passes a case_ref,
    while the label chain (shape_precondition_legs routes a trust-shaped write to
    its own client_trust instance, which skips itself without mutating permission)
    calls the cache with none."""
    setUp = EngagementCapabilityTests.setUp
    restore = staticmethod(EngagementCapabilityTests.restore)

    ADDED = ('client_trust', 'websocket', 'oauth')
    OAUTH_QUERY = 'response_type=code&client_id=fixture&redirect_uri=http://localhost/cb&state=abcdefgh1234'

    def drive(self, *, mutating, case_drive=False):
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.engagement import EngagementState
        from harness.models import HttpExchange
        from harness.orchestrator import Orchestrator
        from harness.orchestrator_chain import _ConfirmationCache
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.run_context import RunContext
        from harness.validators.base import ValidationResult
        base = smoke.BASE_URL
        roles = [RoleSession('user', {'Cookie': 'sid=fixture-cookie'}, name='cookie-user'),
                 RoleSession('user', {'Authorization': 'Bearer fixture'}, name='bearer-user')]
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg['validators'].setdefault(name, {})['enabled'] = name in self.ADDED
        seen = []
        async def dispatch(self_, validator, finding, exchange, case_ref=None):
            if case_ref is not None:
                seen.append((validator.name, exchange.method, exchange.url,
                             dict(exchange.request_headers or {})))
            return ValidationResult(validator.name, 'not_confirmed', finding.vulnerability_class,
                                    summary='fixture: nothing found')
        captures = [
            ('POST', '/api/basket/items', '{"productId": 3, "quantity": 2}', 'application/json'),
            ('POST', '/api/notes', '{"title": "t", "text": "x"}', 'application/json'),
            ('GET', '/ws', '', ''),
            ('GET', '/socket.io/?EIO=4&transport=polling', '', ''),
            ('GET', '/oauth/authorize?' + self.OAUTH_QUERY, '', ''),
            ('GET', '/oauth/callback', '', ''),
        ]
        def build(*args, **kwargs):
            state = EngagementState('localhost')
            for role in roles:
                for method, path, body, ctype in captures:
                    headers = dict(role.headers, **({'Content-Type': ctype} if ctype else {}))
                    state.record_template(base + path, method, HttpExchange(
                        url=base + path, method=method, request_headers=headers, request_body=body,
                        response_status=200, response_headers={'Content-Type': 'application/json'},
                        response_body='{}'))
            for ep in state.endpoints.values():
                ep.reachable_roles = ['user']
            return state, RoleCrawlResult(base_url=base)
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.business_context_enabled = False
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = case_drive
        orch.run_active_probe = AsyncMock(return_value={'iterative_result': {'findings': []}, 'integration': {}})
        async def run():
            async with RunContext.create(allowed_hosts=['localhost'], max_requests=50, config=cfg,
                    gate_config={'active_enabled': True, 'allow_mutating_replay': mutating}) as ctx:
                return await orch.investigate_engagement(base, roles, max_nodes=0, step_budget=1,
                    max_chain_rounds=0, active_discovery=False, run_context=ctx)
        with patch('harness.engagement_builder.build_engagement', side_effect=build), \
                patch('httpx.AsyncClient.get', new_callable=AsyncMock, side_effect=smoke._responder(False)), \
                patch.object(_ConfirmationCache, 'validate', dispatch):
            result = asyncio.run(run())
        return seen, result['coverage']['phase_ledger']['cells']

    @staticmethod
    def cells(rows, check, endpoint):
        return [r for r in rows if r['check'] == check and r['endpoint'] == endpoint]

    def assert_driven_not_detected(self, rows, check, endpoint, identities=None):
        cells = self.cells(rows, check, endpoint)
        if identities is not None:
            cells = [r for r in cells if r['identity'] in identities]
        self.assertTrue(cells, (check, endpoint))
        for row in cells:
            self.assertTrue(row['shape_applicable'] and row['attempted'] and row['conclusive'], row)
            self.assertEqual(row['observation_status'], 'not_detected', row)

    def assert_never_dispatched(self, rows, check, endpoint, code=None):
        cells = self.cells(rows, check, endpoint)
        self.assertTrue(cells, (check, endpoint))
        for row in cells:
            self.assertFalse(row['attempted'] or row['sent'], row)
            if code is not None:
                self.assertEqual(row['readiness'].get('reason_code'), code, row)

    def test_added_legs_are_driven_and_a_clean_answer_is_not_detected(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                seen, rows = self.drive(mutating=True, case_drive=case_drive)
                names = {(name, method, url.split('?', 1)[0]) for name, method, url, _ in seen}
                self.assertIn(('client_trust', 'POST', 'http://localhost/api/basket/items'), names)
                self.assertIn(('websocket_validator', 'GET', 'http://localhost/ws'), names)
                self.assertIn(('oauth_validator', 'GET', 'http://localhost/oauth/authorize'), names)
                # Both identities may tamper the basket write and read the OAuth URL.
                self.assert_driven_not_detected(rows, 'WSTG-BUSL-02', 'POST /api/basket/items')
                self.assert_driven_not_detected(rows, 'WSTG-ATHZ-05', 'GET /oauth/authorize')
                ws_ids = {r['identity'] for r in self.cells(rows, 'WSTG-CLNT-10', 'GET /ws')
                          if r['attempted']}
                self.assertEqual(len(ws_ids), 1, ws_ids)
                self.assert_driven_not_detected(rows, 'WSTG-CLNT-10', 'GET /ws', ws_ids)
                # Every handshake the drive sent carried the identity's cookie.
                self.assertTrue(all('Cookie' in headers for name, _, _, headers in seen
                                    if name == 'websocket_validator'), seen)

    def test_shapes_that_do_not_fit_are_never_dispatched(self):
        seen, rows = self.drive(mutating=True)
        urls = {(name, url.split('?', 1)[0]) for name, _, url, _ in seen}
        # A write with no server-owned field: the row does not apply at all.
        self.assertTrue([r for r in rows if r['endpoint'] == 'POST /api/notes'])
        notes = self.cells(rows, 'WSTG-BUSL-02', 'POST /api/notes')
        self.assertFalse(any(r['shape_applicable'] or r['attempted'] for r in notes), notes)
        self.assertNotIn(('client_trust', 'http://localhost/api/notes'), urls)
        # The OAuth row applies to the path, but the capture carries no OAuth parameter.
        self.assert_never_dispatched(rows, 'WSTG-ATHZ-05', 'GET /oauth/callback', 'not_an_oauth_request')
        self.assertNotIn(('oauth_validator', 'http://localhost/oauth/callback'), urls)
        # A long-poll capture is not a WebSocket handshake.
        self.assert_never_dispatched(rows, 'WSTG-CLNT-10', 'GET /socket.io', 'polling_transport')
        # A Bearer-only identity has no cookie for a cross-site page to ride.
        bearer = [r for r in self.cells(rows, 'WSTG-CLNT-10', 'GET /ws') if not r['attempted']]
        self.assertEqual(len(bearer), 1, bearer)
        self.assertEqual(bearer[0]['readiness'].get('reason_code'), 'no_ambient_credential')

    def test_client_trust_stays_inert_without_mutating_permission(self):
        seen, rows = self.drive(mutating=False)
        self.assertNotIn('client_trust', {name for name, *_ in seen})
        cells = self.cells(rows, 'WSTG-BUSL-02', 'POST /api/basket/items')
        self.assertTrue(cells)
        for row in cells:
            self.assertFalse(row['attempted'] or row['sent'], row)
            self.assertEqual(row['terminal_reason'], 'policy_blocked', row)
        # The read-only legs are unaffected by the write permission.
        self.assertIn('oauth_validator', {name for name, *_ in seen})
        self.assertIn('websocket_validator', {name for name, *_ in seen})

    def test_disabled_added_legs_are_unavailable_not_driven(self):
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        self.assertTrue(set(self.ADDED) <= _LEG_CONFIRMATIONS)
        saved = self.ADDED
        self.ADDED = ()
        try:
            seen, rows = self.drive(mutating=True)
        finally:
            self.ADDED = saved
        self.assertFalse({name for name, *_ in seen} & {'client_trust', 'websocket_validator',
                                                       'oauth_validator'}, seen)
        for check, endpoint in (('WSTG-BUSL-02', 'POST /api/basket/items'),
                                ('WSTG-ATHZ-05', 'GET /oauth/authorize'), ('WSTG-CLNT-10', 'GET /ws')):
            for row in self.cells(rows, check, endpoint):
                self.assertFalse(row['attempted'], row)
                self.assertEqual(row['terminal_reason'], 'validator_unavailable', row)


class AddedLegReadinessTests(unittest.TestCase):
    """capability_for_check for the WG-2 item 5 legs: each declines a wrong-shape
    capture before dispatch, and client_trust needs mutating permission."""

    def decide(self, check, url, *, method='GET', body='', headers=None, mutating=True,
               run_context=True):
        from harness.models import HttpExchange
        from harness.validators.registry import ValidatorRegistry
        registry = ValidatorRegistry.__new__(ValidatorRegistry)
        registry.enabled = True; registry.active_enabled = True; registry._disabled_capabilities = set()
        registry.validators = {name: SimpleNamespace(active=True)
                               for name in ('client_trust', 'websocket', 'oauth')}
        ctx = SimpleNamespace(scope=SimpleNamespace(in_scope=lambda _url: True),
                              gate=SimpleNamespace(config=SimpleNamespace(allow_mutating_replay=mutating)))
        exchange = HttpExchange(url=url, method=method, request_body=body,
                                request_headers=headers or {})
        return registry.capability_for_check(CHECKS_BY_ID[check], exchange,
                                             run_context=ctx if run_context else None)

    def test_client_trust(self):
        url = 'http://fixture.invalid/api/membership'
        ready = self.decide('WSTG-BUSL-02', url, method='POST', body='{"paymentMode": "wallet"}')
        self.assertEqual((ready['status'], ready['mechanism_id']), ('ready', 'client_trust.tamper'))
        self.assertEqual(ready['finding_class'], 'business_logic')
        for body in ('{"quantity": 2}', '{"plan": "basic"}', 'price=1000&item=3', '{"role": "user"}'):
            self.assertEqual(self.decide('WSTG-BUSL-02', url, method='POST', body=body)['status'],
                             'ready', body)
        self.assertEqual(self.decide('WSTG-BUSL-02', url, method='POST', body='{"title": "t"}')['reason_code'],
                         'no_trust_field')
        # A quantity that is not a positive integer has nothing to tamper with.
        self.assertEqual(self.decide('WSTG-BUSL-02', url, method='POST', body='{"quantity": "many"}')['reason_code'],
                         'no_trust_field')
        self.assertEqual(self.decide('WSTG-BUSL-02', url, body='')['reason_code'], 'unsupported_method')
        for kwargs in ({'mutating': False}, {'run_context': False}):
            denied = self.decide('WSTG-BUSL-02', url, method='POST', body='{"quantity": 2}', **kwargs)
            self.assertEqual((denied['status'], denied['reason_code']),
                             ('policy_denied', 'mutating_policy_denied'), kwargs)

    def test_websocket(self):
        cookie = {'Cookie': 'sid=x'}
        ready = self.decide('WSTG-CLNT-10', 'http://fixture.invalid/ws', headers=cookie)
        self.assertEqual((ready['status'], ready['mechanism_id']),
                         ('ready', 'websocket.cross_origin_handshake'))
        self.assertEqual(self.decide('WSTG-CLNT-10', 'http://fixture.invalid/ws',
                                     headers={'Authorization': 'Bearer t'})['reason_code'],
                         'no_ambient_credential')
        self.assertEqual(self.decide('WSTG-CLNT-10', 'http://fixture.invalid/socket.io/?EIO=4&transport=polling&t=x',
                                     headers=cookie)['reason_code'], 'polling_transport')
        self.assertEqual(self.decide('WSTG-CLNT-10', 'http://fixture.invalid/socket.io/?EIO=4&transport=websocket',
                                     headers=cookie)['status'], 'ready')

    def test_oauth(self):
        base = 'http://fixture.invalid/oauth/authorize'
        for query in ('response_type=code&client_id=c', 'client_id=c&redirect_uri=https://x/cb',
                      'response_type=code', 'code=abc', 'access_token=t'):
            self.assertEqual(self.decide('WSTG-ATHZ-05', base + '?' + query)['status'], 'ready', query)
        self.assertEqual(self.decide('WSTG-ATHZ-05', 'http://fixture.invalid/cb#access_token=t')['status'],
                         'ready')
        for url in (base, base + '?client_id=c', base + '?response_type=token'):
            self.assertEqual(self.decide('WSTG-ATHZ-05', url)['reason_code'], 'not_an_oauth_request', url)

    def test_readiness_agrees_with_each_validators_own_skip(self):
        """The readiness predicates are the validators' own: a capture they decline is
        one the validator itself would skip (a check, not a send)."""
        from harness.models import Finding, HttpExchange
        from harness.validators.oauth_validator import OAuthValidator
        from harness.validators.websocket_validator import ambient_cookie
        finding = Finding(vulnerability_class='oauth', confidence=0.5, summary='x',
                          evidence='capture', suggested_test='probe', basis='derived')
        skipped = asyncio.run(OAuthValidator().validate(
            finding, HttpExchange(url='http://fixture.invalid/oauth/authorize?client_id=c', method='GET')))
        self.assertEqual(skipped.status, 'skipped')
        self.assertIsNone(ambient_cookie(HttpExchange(url='http://x/ws', method='GET',
                                                      request_headers={'Authorization': 'Bearer t'})))
        self.assertEqual(ambient_cookie(HttpExchange(url='http://x/ws', method='GET',
                                                     request_headers={'cookie': 'a=b'})), 'a=b')


class ExactProcedureCallerTests(unittest.TestCase):
    setUp = EngagementCapabilityTests.setUp
    restore = staticmethod(EngagementCapabilityTests.restore)

    def run_registration(self, *, enabled=True, bad_first=False):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from harness import test_smoke_investigate as smoke
        from harness.orchestrator import Orchestrator
        from harness.engagement import EngagementState
        from harness.models import HttpExchange
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        received, classes = [], []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length','0')))
                received.append((self.command,self.path))
                body=b'{"created":true}'
                self.send_response(201); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        base=f'http://127.0.0.1:{server.server_port}'
        cfg=smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg['validators'].setdefault(name,{})['enabled']=False
        cfg['validators']['auth_sequence']={'enabled':enabled}
        cfg['validators']['allow_mutating_replay']=True
        orch=Orchestrator(cfg); orch.business_context_enabled=False
        from harness.test_default_history_caller import _RecordingModel
        controlled_model=_RecordingModel(); orch.ollama=controlled_model
        for agent in orch.agent_manager.agents.values(): agent.ollama=controlled_model
        if hasattr(orch,'coordinator'): orch.coordinator.ollama=controlled_model
        orch.engagement_coverage_drive=True; orch.engagement_coverage_case_drive=True
        orch.coverage_leg_budget=1
        orch.coverage_request_reserve=1
        orch.capture_review_limit=0  # isolate the real coverage caller from earlier active review
        orch.run_active_probe=AsyncMock(return_value={'iterative_result':{'findings':[]},'integration':{}})
        def build(*args,**kwargs):
            state=EngagementState('127.0.0.1')
            if bad_first:
                state.record_template(base+'/login','GET',HttpExchange(url=base+'/login',method='GET',response_status=200))
            state.record_template(base+'/register','POST',HttpExchange(url=base+'/register',method='POST',
                request_headers={'Content-Type':'application/json'},request_body='{"username":"fixture","password":"Strong1!"}',
                response_status=201,response_headers={'Content-Type':'application/json'}))
            for ep in state.endpoints.values(): ep.reachable_roles=['anonymous']
            return state,RoleCrawlResult(base_url=base)
        from harness.run_context import RunContext
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'],max_requests=1,config=cfg,
            gate_config={'active_enabled':True,'allow_mutating_replay':True})
        original=AuthSequenceValidator._which_checks
        def observe(validator,cls,exchange):
            if ctx.budget.remaining: classes.append(cls)
            return original(validator,cls,exchange)
        async def run():
            async with ctx:
                return await orch.investigate_engagement(base,[RoleSession('anonymous',{})],
                    max_nodes=0,step_budget=1,max_chain_rounds=0,active_discovery=False,run_context=ctx)
        try:
            with patch('harness.engagement_builder.build_engagement',side_effect=build), \
                 patch.object(AuthSequenceValidator,'_which_checks',observe):
                result=asyncio.run(run())
            return received,classes,result
        finally:
            server.shutdown();server.server_close()

    def assert_registration(self, *, bad_first=False):
        received,classes,result=self.run_registration(bad_first=bad_first)
        self.assertEqual(received,[('POST','/register')],{'classes':classes,'cases_driven':result.get('coverage',{}).get('cases_driven')})
        self.assertEqual(classes,['weak_password_policy'])
        self.assertEqual(result['coverage']['cases_driven'],1)
        return result

    def test_actual_catalog_dispatch_reaches_exact_weak_password_procedure(self):
        self.assert_registration()

    def test_unsupported_and_wrong_shape_checks_do_not_spend_dispatch_budget(self):
        result=self.assert_registration(bad_first=True)
        rows=result['coverage']['phase_ledger']['cells']
        self.assertFalse(any(r['attempted'] for r in rows if r['check'] in ('WSTG-ATHN-04','WSTG-SESS-01')))

    def test_disabled_procedure_has_zero_sends(self):
        received,classes,result=self.run_registration(enabled=False)
        self.assertEqual(received,[]);self.assertEqual(classes,[])
        rows=[r for r in result['coverage']['phase_ledger']['cells'] if r['check']=='WSTG-ATHN-07']
        self.assertTrue(rows);self.assertTrue(all(not r['attempted'] for r in rows))

    def test_unplugged_exact_mapping_is_detected_by_positive_caller(self):
        from harness.validators.registry import ValidatorRegistry
        def legacy(self_,check,exchange,**kwargs):
            return {'status':'ready','reason':'legacy taxonomy','finding_class':check.vulnerability_class,
                    'mechanism_id':'legacy:'+check.confirmation,'reason_code':'ready'}
        with patch.object(ValidatorRegistry,'capability_for_check',legacy,create=True):
            with self.assertRaises(AssertionError): self.assert_registration()


class ReadinessInputTests(unittest.TestCase):
    def registry(self):
        from harness.validators.registry import ValidatorRegistry
        registry=ValidatorRegistry.__new__(ValidatorRegistry)
        registry.enabled=True;registry.active_enabled=True;registry._disabled_capabilities=set()
        registry.validators={name:SimpleNamespace(active=True) for name in
            ('auth_sequence','csp','jwt_forge','nosql','cross_identity')}
        return registry

    def decide(self,check,url='http://fixture.invalid/register',method='POST',body='{"username":"u","password":"p"}',headers=None,request_headers=None):
        from harness.models import HttpExchange
        exchange=HttpExchange(url=url,method=method,request_body=body,response_headers=headers or {},request_headers=request_headers or {})
        return self.registry().capability_for_check(CHECKS_BY_ID[check],exchange)

    def test_exact_auth_classes_and_unrelated_catalog_claims(self):
        self.assertEqual(self.decide('WSTG-ATHN-07')['finding_class'],'weak_password_policy')
        self.assertEqual(self.decide('WSTG-SESS-03',url='http://fixture.invalid/login')['finding_class'],'session_fixation')
        for check in ('WSTG-ATHN-04','WSTG-SESS-01'):
            result=self.decide(check)
            self.assertEqual(result['status'],'unsupported');self.assertIsNone(result['finding_class'])
        self.assertEqual(self.decide('WSTG-ATHN-07',method='GET')['reason_code'],'unsupported_method')
        self.assertEqual(self.decide('WSTG-ATHN-07',body='{}')['reason_code'],'missing_credentials')
        self.assertEqual(self.decide('WSTG-SESS-03')['reason_code'],'unsupported_boundary')

    def test_wg_auth_rows_are_gated_on_request_shape(self):
        """The rows WG-2/WG-3 added to auth_sequence (IDNT-04, ATHN-11, SESS-06)
        decline a wrong-shape capture before dispatch, as ATHN-07/SESS-03 do."""
        login='http://fixture.invalid/login'
        ready=self.decide('WSTG-IDNT-04',url=login)
        self.assertEqual((ready['status'],ready['finding_class']),('ready','username_enumeration'))
        self.assertEqual(ready['mechanism_id'],'auth.username_enumeration')
        # Enumeration swaps the username only; a password is not required.
        self.assertEqual(self.decide('WSTG-IDNT-04',url=login,body='{"email":"a@b.c"}')['status'],'ready')
        self.assertEqual(self.decide('WSTG-IDNT-04',url=login,body='{"email":""}')['reason_code'],'missing_credentials')
        self.assertEqual(self.decide('WSTG-IDNT-04',url=login,method='GET')['reason_code'],'unsupported_method')
        mfa=self.decide('WSTG-ATHN-11',url=login)
        self.assertEqual((mfa['status'],mfa['finding_class']),('ready','2fa_bypass'))
        self.assertEqual(self.decide('WSTG-ATHN-11')['reason_code'],'unsupported_boundary')  # /register
        self.assertEqual(self.decide('WSTG-ATHN-11',url=login,body='{"username":"u"}')['reason_code'],'missing_credentials')
        logout=self.decide('WSTG-SESS-06',url=login)
        self.assertEqual((logout['status'],logout['finding_class']),('ready','session_timeout'))
        self.assertEqual(logout['mechanism_id'],'auth.logout_invalidation')
        self.assertEqual(self.decide('WSTG-SESS-06')['reason_code'],'unsupported_boundary')
        self.assertEqual(self.decide('WSTG-SESS-06',url=login,method='GET')['reason_code'],'unsupported_method')

    def test_missing_inputs_are_not_security_negatives(self):
        self.assertEqual(self.decide('WSTG-CONF-12',headers={'Content-Type':'application/json'})['reason_code'],'non_html_response')
        self.assertEqual(self.decide('WSTG-CONF-12')['status'],'needs_prerequisite')
        self.assertEqual(self.decide('WSTG-CONF-12',headers={'Content-Type':'text/html'})['status'],'ready')
        self.assertEqual(self.decide('WSTG-SESS-10',method='GET')['reason_code'],'missing_jwt')
        self.assertEqual(self.decide('WSTG-ATHZ-04',method='GET')['reason_code'],'missing_object_id')
        self.assertEqual(self.decide('WSTG-ATHZ-04',url='http://fixture.invalid/objects/7',method='GET')['status'],'ready')
        # r7: a non-login request is tested on its own parameters, not refused.
        self.assertEqual(self.decide('WSTG-INJT-05.6')['mechanism_id'],'nosql.operator_differential')
        self.assertEqual(self.decide('WSTG-INJT-05.6',body='{}')['reason_code'],'missing_parameter')
        self.assertEqual(self.decide('WSTG-INJT-05.6',url='http://fixture.invalid/login',method='GET')['reason_code'],'missing_parameter')
        self.assertEqual(self.decide('WSTG-INJT-05.6',url='http://fixture.invalid/login?u=a',method='GET')['status'],'ready')
        self.assertEqual(self.decide('WSTG-INJT-05.6',url='http://fixture.invalid/login')['mechanism_id'],'nosql.login_operator')

    def test_unavailable_adapter_protocol_and_disable_dispositions(self):
        for check in ('WSTG-CONF-06','WSTG-INFO-02','WSTG-INFO-05'):
            result=self.decide(check)
            self.assertEqual(result['reason_code'],'check_adapter_missing');self.assertIsNone(result['finding_class'])
        # CONF-02 and ERRH-01 are bound to passive adapters: unavailable until registered.
        for check in ('WSTG-CONF-14','WSTG-ERRH-01'):
            self.assertEqual(self.decide(check)['reason_code'],'validator_unavailable')
        registry=self.registry();registry.validators['security_headers']=SimpleNamespace(active=False)
        registry.active_enabled=False
        from harness.models import HttpExchange
        result=registry.capability_for_check(CHECKS_BY_ID['WSTG-CONF-14'],HttpExchange(url='http://fixture.invalid',method='GET'))
        self.assertEqual(result['status'],'ready');self.assertIsNotNone(result['finding_class'])
        self.assertEqual(self.decide('WSTG-CRYP-01')['reason_code'],'protocol_inapplicable')
        # HSTS is ignored over plain HTTP (RFC 6797 8.1); over HTTPS its adapter is missing.
        self.assertEqual(self.decide('WSTG-CONF-07')['reason_code'],'protocol_inapplicable')
        self.assertEqual(self.decide('WSTG-CONF-07',url='https://fixture.invalid/register')['reason_code'],
                         'check_adapter_missing')
        registry=self.registry();registry.active_enabled=False
        from harness.models import HttpExchange
        result=registry.capability_for_check(CHECKS_BY_ID['WSTG-CONF-12'],HttpExchange(url='http://fixture.invalid',method='GET'))
        self.assertEqual(result['status'],'disabled')

    def test_readiness_decline_does_not_spend_one_dispatch_budget(self):
        checks=tuple(CHECKS_BY_ID[k] for k in ('WSTG-ATHN-04','WSTG-ATHN-07'))
        tracker=CoverageTracker(checks)
        tracker.build({'POST /register':{'path':'/register','method':'POST','reachable_roles':['anonymous']}},['anonymous'])
        calls=[]
        def ready(identity,method,path,check):
            return self.decide(check.id)
        async def dispatch(identity,method,path,check):
            calls.append(check.id);return SimpleNamespace(status='blocked',sent_count=0)
        asyncio.run(tracker.drive_coverage_legs(dispatch,driveable={'auth_sequence'},budget=1,readiness=ready))
        self.assertEqual(calls,['WSTG-ATHN-07'])
        row=next(r for r in tracker.phase_ledger()['cells'] if r['check']=='WSTG-ATHN-04')
        self.assertFalse(row['attempted']);self.assertFalse(row['eligible'])
        self.assertEqual(row['readiness']['status'],'unsupported')


class ReviewReadinessRegressionTests(unittest.TestCase):
    registry = ReadinessInputTests.registry

    def test_jwt_invalid_method_and_json_decline_before_valid_dispatch(self):
        from harness.models import HttpExchange
        from harness.test_smoke_investigate import ORIGINAL_TOKEN
        check=CHECKS_BY_ID['WSTG-SESS-10'];registry=self.registry()
        tracker=CoverageTracker((check,))
        endpoints={key:{'path':key.split(' ',1)[1],'method':key.split(' ',1)[0],
                        'reachable_roles':['user']} for key in ('POST /bad-method','GET /bad-token','GET /good')}
        tracker.build(endpoints,['user'])
        def readiness(identity,method,path,check):
            token='eyJub3QtanNvbg.eyJub3QtanNvbg.sig' if path=='/bad-token' else ORIGINAL_TOKEN
            return registry.capability_for_check(check,HttpExchange(url='http://fixture.invalid'+path,
                method=method,request_headers={'Authorization':'Bearer '+token}))
        calls=[]
        async def dispatch(identity,method,path,check):
            calls.append(path);return SimpleNamespace(status='blocked',sent_count=0)
        asyncio.run(tracker.drive_coverage_legs(dispatch,driveable={'jwt_forge'},budget=1,readiness=readiness))
        self.assertEqual(calls,['/good'])
        self.assertEqual(tracker.readiness[('user','POST /bad-method',check.id)]['status'],'unsupported')
        self.assertEqual(tracker.readiness[('user','GET /bad-token',check.id)]['reason_code'],'undecodable_jwt')

    def test_disabled_export_is_unavailable_and_never_eligible(self):
        from harness.models import HttpExchange
        registry=self.registry();registry.active_enabled=False
        check=CHECKS_BY_ID['WSTG-CONF-12'];tracker=CoverageTracker((check,))
        tracker.build({'GET /page':{'path':'/page','method':'GET','reachable_roles':['anonymous']}},['anonymous'])
        def readiness(*args):
            return registry.capability_for_check(check,HttpExchange(url='http://fixture.invalid/page',method='GET',
                response_headers={'Content-Type':'text/html'}))
        dispatch=AsyncMock()
        asyncio.run(tracker.drive_coverage_legs(dispatch,driveable={'csp'},readiness=readiness))
        dispatch.assert_not_called()
        row=tracker.report()['phase_ledger']['cells'][0]
        self.assertFalse(row['implemented']);self.assertFalse(row['eligible'])
        self.assertEqual(row['terminal_reason'],'validator_unavailable')


class ObservedIdCallerTests(unittest.TestCase):
    setUp=EngagementCapabilityTests.setUp
    restore=staticmethod(EngagementCapabilityTests.restore)

    def test_unobserved_template_does_not_spend_budget_before_observed_object(self):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        import threading
        from harness import engagement_builder,test_smoke_investigate as smoke
        from harness.engagement import EngagementState,SurfaceEndpoint
        from harness.models import HttpExchange
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleSession,RoleCrawlResult
        from harness.run_context import RunContext
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        received=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                received.append(self.path)
                status=401 if not self.headers.get('Authorization') else 200 if self.path=='/objects/7' else 404
                body=b'{"id":7,"owner":"alice","content":"private fixture object"}' if status==200 else b'denied'
                self.send_response(status);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        base=f'http://127.0.0.1:{server.server_port}'
        roles=[RoleSession('user',{'Authorization':'Bearer alice'},name='alice'),
               RoleSession('user',{'Authorization':'Bearer bob'},name='bob')]
        cfg=smoke._test_config()
        for name in _LEG_CONFIRMATIONS: cfg['validators'].setdefault(name,{})['enabled']=False
        orch=Orchestrator(cfg);_controlled_model(orch);orch.business_context_enabled=False
        orch.engagement_coverage_drive=True;orch.engagement_coverage_case_drive=True
        orch.coverage_leg_budget=1;orch.coverage_request_reserve=20
        orch.run_active_probe=AsyncMock(return_value={'iterative_result':{'findings':[]},'integration':{}})
        def build(*args,**kwargs):
            engagement_builder.register_role_sessions(kwargs.get('run_context'),base,roles)
            kwargs['run_context'].sessions.register('anonymous','anonymous',{},allowed_origins=[base])
            state=EngagementState('127.0.0.1')
            state.endpoints['GET /unobserved/{id}']=SurfaceEndpoint('GET','/unobserved/{id}',
                reachable_roles=['user'],object_scoped=True,template={'method':'GET'})
            for role in roles:
                state.record_template(base+'/objects/7','GET',HttpExchange(url=base+'/objects/7',method='GET',
                    request_headers=role.headers,response_status=200,response_headers={'Content-Type':'application/json'},
                    response_body='{"id":7,"owner":"alice","content":"private fixture object"}'))
            for ep in state.endpoints.values():ep.reachable_roles=['user'];ep.object_scoped=True
            return state,RoleCrawlResult(base_url=base)
        async def run():
            async with RunContext.create(allowed_hosts=['127.0.0.1'],max_requests=20,config=cfg,
                    gate_config={'active_enabled':True}) as ctx:
                return await orch.investigate_engagement(base,roles,max_nodes=0,max_chain_rounds=0,
                    active_discovery=False,run_context=ctx)
        try:
            with patch('harness.engagement_builder.build_engagement',side_effect=build):result=asyncio.run(run())
            self.assertTrue(received,'observed object was never dispatched')
            self.assertFalse(any(path.startswith('/unobserved/') for path in received),received)
            rows=result['coverage']['phase_ledger']['cells']
            missing=[r for r in rows if r['endpoint']=='GET /unobserved/{id}' and r['confirmation']=='cross_identity']
            self.assertTrue(missing);self.assertFalse(any(r['attempted'] for r in missing))
            self.assertTrue(any(r['attempted'] for r in rows if r['endpoint']=='GET /objects/{id}' and r['confirmation']=='cross_identity'))
            self.assertEqual(result['coverage']['cases_driven'],1)
        finally:server.shutdown();server.server_close()
