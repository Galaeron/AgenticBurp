"""R05 no-I/O caller controls; no target, provider or active fixture."""
import unittest
import socket
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from harness.run_context import RunContext, TypedRequest
from harness.target_request_policy import TargetRequestPolicy


def completed_without_await(coro):
    try:
        try:
            coro.send(None)
        except StopIteration as stopped:
            return stopped.value
        raise AssertionError("denial unexpectedly reached an await")
    finally:
        coro.close()


class CapturedOnlyPolicyTests(unittest.TestCase):
    def test_passive_only_direct_get_is_blocked_before_client_or_budget(self):
        ctx = RunContext.create(allowed_hosts=['target.test'],
                                config={'operating_profile': 'passive-only'})
        with patch.object(ctx, 'default_client', side_effect=AssertionError('client forbidden')) as client:
            out = completed_without_await(ctx.target_transport().execute(
                TypedRequest('GET', 'https://target.test/ordinary'), capability='benign'))
        self.assertEqual(out.outcome, 'blocked')
        self.assertIn('captured-only', out.error)
        self.assertEqual(ctx.budget.used, 0)
        client.assert_not_called()

    def test_profile_cannot_be_overridden_by_transport_flag_or_active_gate(self):
        ctx = RunContext.create(allowed_hosts=['target.test'],
                                gate_config={'active_enabled': True, 'allow_mutating_replay': True},
                                config={'operating_profile': ' PASSIVE-ONLY ',
                                        'transport': {'captured_only': False}})
        for method in ('GET', 'HEAD', 'OPTIONS', 'TRACE', 'POST', 'DELETE'):
            decision = ctx.gate.authorize(validator_name='benign', method=method,
                                          url='https://target.test/ordinary')
            self.assertFalse(decision.allowed)
            self.assertIn('captured-only', decision.reason)

    def test_endpoint_exclusions_deny_nominally_safe_methods_before_io(self):
        ctx = RunContext.create(allowed_hosts=['target.test'], config={
            'transport': {'excluded_path_prefixes': ['/logout']}})
        for suffix in ('/logout', '/logout/child', '/%6cogout', '/%256cogout',
                       '/ordinary/../logout', '/logout?confirm=1'):
            with self.subTest(path=suffix), patch.object(ctx, 'default_client',
                    side_effect=AssertionError('client forbidden')):
                out = completed_without_await(ctx.target_transport().execute(
                    TypedRequest('GET', 'https://target.test' + suffix), capability='benign'))
                self.assertEqual(out.outcome, 'blocked')
                self.assertIn('excluded', out.error)
                self.assertEqual(ctx.budget.used, 0)
        # Meaningful negative control: nearby path remains eligible at the gate,
        # without issuing a request; exclusions have a segment boundary.
        self.assertTrue(ctx.gate.authorize(validator_name='benign', method='GET',
                                          url='https://target.test/logout-help').allowed)

    def test_malformed_policy_fails_before_client_and_snapshot_is_immutable(self):
        for transport in ({'captured_only': 'false'}, {'excluded_path_prefixes': '/logout'},
                          {'excluded_path_prefixes': ['/bad%zz']},
                          {'excluded_path_prefixes': [None]}, False):
            with self.subTest(policy=transport), self.assertRaises(ValueError):
                RunContext.create(config={'transport': transport})
        source = {'transport': {'captured_only': True, 'excluded_path_prefixes': ['/logout']}}
        ctx = RunContext.create(config=source)
        source['transport']['captured_only'] = False
        source['transport']['excluded_path_prefixes'].clear()
        self.assertTrue(ctx.target_policy.captured_only)
        self.assertEqual(ctx.target_policy.excluded_path_prefixes, ('/logout',))

    def test_status_distinguishes_blocked_fetching_from_untested_capture(self):
        status = TargetRequestPolicy.from_config({'operating_profile': 'passive-only'}).status()
        self.assertEqual(status['target_fetching'], 'blocked')
        self.assertIn('not a negative test result', status['capture_analysis'])

    def test_passive_profile_keeps_active_and_capture_features_disabled(self):
        from harness.config_schema import resolve_operating_profile
        source = {'operating_profile': 'passive-only',
                  'validators': {'active_enabled': True, 'allow_mutating_replay': True},
                  'driver_capture': {'enabled': True}, 'iterative_agent': {'enabled': True},
                  'autonomous_discovery': {'enabled': True}}
        with self.assertLogs('harness.config_schema', level='WARNING'):
            resolved = resolve_operating_profile(source, 'passive-only')
        for section, key in (('validators', 'active_enabled'), ('validators', 'allow_mutating_replay'),
                             ('driver_capture', 'enabled'), ('iterative_agent', 'enabled'),
                             ('autonomous_discovery', 'enabled')):
            self.assertIs(resolved[section][key], False)


class CapturedAnalysisCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_orchestrator_analyzes_supplied_response_with_zero_target_transports(self):
        from harness import cache, store
        from harness.models import HttpExchange
        from harness.run_context import TargetTransport
        from harness.test_smoke_phase0_capture_review import _build
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(store, '_DB_PATH', Path(tmp) / 'state.db'), \
                 patch.object(cache, '_cache', cache.ExchangeCache(db_path=str(Path(tmp) / 'cache.db'))):
                orch = _build()  # actual orchestrator with silent synthetic provider
                orch.config['operating_profile'] = 'passive-only'
                exchange = HttpExchange(url='http://localhost/ordinary', method='GET',
                                        response_status=200, response_body='ordinary supplied content')
                with patch.object(TargetTransport, 'execute', new_callable=AsyncMock,
                                  side_effect=AssertionError('target transport forbidden')) as target, \
                     patch.object(httpx.AsyncClient, 'request', side_effect=AssertionError('raw target client forbidden')), \
                     patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                     patch.object(socket.socket, 'connect', side_effect=AssertionError('connect forbidden')):
                    result = await orch.analyze(exchange, force_agents=['csp'], bypass_cache=True)
                target.assert_not_called()
                self.assertEqual(result.dispatched_agents, ['csp'])
                self.assertTrue(any(r.agent == 'csp' and not r.raw_error for r in result.agent_reports))

    async def test_raw_discovery_captured_only_stops_before_client(self):
        from harness import scope_discovery
        from harness.models import HttpExchange
        with patch.object(httpx, 'AsyncClient', side_effect=AssertionError('client forbidden')) as client:
            out = await scope_discovery.discover_from_scope_change(
                HttpExchange(url='https://target.test/ordinary', method='GET'), [],
                {'operating_profile': 'passive-only', 'autonomous_discovery': {'enabled': True}},
                ['target.test'])
        self.assertEqual(out, [])
        client.assert_not_called()

    async def test_excluded_redirect_is_denied_before_second_mock_hop(self):
        ctx = RunContext.create(allowed_hosts=['target.test'], config={
            'transport': {'excluded_path_prefixes': ['/logout']}})
        sent = []
        def ordinary_redirect(request):
            sent.append(str(request.url))
            return httpx.Response(302, headers={'Location': '/logout'})
        ctx._default_client = httpx.AsyncClient(transport=httpx.MockTransport(ordinary_redirect))
        try:
            with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                 patch.object(socket.socket, 'connect', side_effect=AssertionError('connect forbidden')):
                out = await ctx.target_transport().execute(
                    TypedRequest('GET', 'https://target.test/ordinary'), capability='benign')
            self.assertEqual(out.outcome, 'blocked')
            self.assertIn('excluded', out.error)
            self.assertEqual(sent, ['https://target.test/ordinary'])
            self.assertEqual(ctx.budget.used, 1)
        finally:
            await ctx.aclose()


class CapturedOnlyServerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import actual server without consuming local operator overrides.
        original_exists = Path.exists
        def no_local_override(path):
            return False if path.name == 'config.local.yaml' else original_exists(path)
        with patch.object(Path, 'exists', no_local_override), \
             patch.dict(os.environ, {'HARNESS_BEARER_TOKEN': 'r05-fixture'}):
            from harness import server
        cls.server = server

    def test_actual_target_fetch_endpoints_reject_before_adapters(self):
        from harness.models import HttpExchange
        s = self.server
        calls = [
            lambda: s.crawl_endpoint(s.CrawlRequest(base_url='https://target.test/'), 'Bearer r05-fixture'),
            lambda: s.crawl_roles_endpoint(s.RoleCrawlRequest(base_url='https://target.test/', roles=[]), 'Bearer r05-fixture'),
            lambda: s.probe_missing_auth_endpoint(s.MissingAuthRequest(base_url='https://target.test/'), 'Bearer r05-fixture'),
            lambda: s.active_probe(s.ActiveProbeRequest(exchange=HttpExchange(url='https://target.test/', method='GET'),
                                                        hypothesis='ordinary', specialty='csp'), 'Bearer r05-fixture'),
            lambda: s.engagement_advance('target.test', s.AdvanceRequest(base_url='https://target.test/', roles=[]), 'Bearer r05-fixture'),
            lambda: s.engagement_investigate('target.test', s.InvestigateRequest(base_url='https://target.test/'), 'Bearer r05-fixture'),
            lambda: s.engagement_run('target.test', s.RunEngagementRequest(base_url='https://target.test/', execute=True), 'Bearer r05-fixture'),
        ]
        with patch.object(s, '_BEARER_TOKEN', 'r05-fixture'), \
             patch.object(s.orchestrator, 'config', {'operating_profile': 'passive-only'}), \
             patch.object(httpx, 'AsyncClient', side_effect=AssertionError('client forbidden')):
            for call in calls:
                with self.subTest(endpoint=call):
                    with self.assertRaises(s.HTTPException) as error:
                        completed_without_await(call())
                    self.assertEqual(error.exception.status_code, 403)
                    self.assertIn('captured-only', error.exception.detail)

    def test_bulk_adapter_with_exclusions_is_conservatively_blocked(self):
        s = self.server
        with patch.object(s.orchestrator, 'config', {'transport': {'excluded_path_prefixes': ['/logout']}}):
            with self.assertRaises(s.HTTPException) as error:
                s._require_target_fetch('https://target.test/ordinary', bulk=True)
            self.assertIn('cannot enforce', error.exception.detail)
            # Non-bulk admission is allowed without invoking target transport.
            s._require_target_fetch('https://target.test/ordinary')


if __name__ == '__main__':
    unittest.main()
