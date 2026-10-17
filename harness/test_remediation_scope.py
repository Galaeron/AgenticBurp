"""R04 benign policy/caller controls. MockTransport only; no target fixtures."""
import socket
import unittest
from unittest.mock import patch

import httpx

from harness import scope_discovery, scope_lock
from harness.run_context import HostAllowScope, RunContext, ScopePolicy, TypedRequest, standalone_context
from harness.safety_gate import ActionRiskTier, SafetyGate, SafetyGateConfig


class ScopeContractTests(unittest.TestCase):
    def decisions(self, url, entries, *, active=True):
        return {
            'ScopePolicy': ScopePolicy(allowed_hosts=frozenset(entries)).in_scope(url),
            'HostAllowScope': HostAllowScope(hosts=tuple(entries), active_mode=active).in_scope(url),
            'scope_lock': scope_lock.host_in_scope(url, entries, active_mode=active),
            'scope_discovery': scope_discovery.is_host_allowed(url, entries, active_mode=active),
            'SafetyGate': SafetyGate(SafetyGateConfig(active_enabled=active, allowed_hosts=frozenset(entries))).authorize(
                validator_name='benign-policy', method='GET', url=url).allowed,
        }

    def test_common_exact_host_table_across_actual_adapters(self):
        cases = [
            ('https://TARGET.test/a', ['target.test'], True),
            ('http://target.test:8080/a', ['target.test'], True),
            ('http://api.target.test/a', ['target.test'], False),
            ('http://other.test/a', ['target.test'], False),
            ('http://target.test./a', ['target.test'], False),
            ('http://127.0.0.1/a', ['localhost'], False),
            ('http://[::1]:8080/a', ['::1'], True),
            ('http://[::2]/a', ['::1'], False),
        ]
        for url, entries, expected in cases:
            with self.subTest(url=url, entries=entries):
                actual = self.decisions(url, entries)
                self.assertEqual(actual, dict.fromkeys(actual, expected))

    def test_empty_and_malformed_active_scope_fail_closed(self):
        for entries in ([], [''], [' '], ['target.test:invalid'], ['http://'], ['target.test/path'], [None]):
            with self.subTest(entries=entries):
                self.assertFalse(any(self.decisions('http://target.test/a', entries).values()))

    def test_malformed_urls_and_userinfo_fail_closed_everywhere(self):
        urls = [
            'not-a-url', '//target.test/a', 'ftp://target.test/a', 'ws://target.test/a',
            'http://user@target.test/a', 'http://user:password@target.test/a',
            'http://target.test:invalid/a', 'http://target.test:65536/a', 'http://target.test:0/a',
            'http://target.test:/a', 'http://[bad]/a', 'http://target.test\\@other.test/a',
            'http://target.test\n/a', 'http://tar get.test/a', 'http://target.test%2f.other.test/a',
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertFalse(any(self.decisions(url, ['target.test']).values()))
                self.assertFalse(scope_lock.host_in_scope(url, []))
                self.assertFalse(scope_discovery.is_host_allowed(url, []))

    def test_extended_entries_are_denied_uniformly_by_authorizing_adapters(self):
        # The conservative intersection preserves every strict caller denial;
        # discovery cannot admit a destination the transport gate rejects.
        cases = [
            ('https://target.test/a', ['target.test:443']),
            ('https://target.test:8443/a', ['https://target.test:8443']),
            ('http://api.target.test/a', ['*.target.test']),
            ('http://10.0.0.7/a', ['10.0.0.0/24']),
        ]
        for url, entries in cases:
            with self.subTest(url=url, entries=entries):
                actual = self.decisions(url, entries)
                self.assertEqual(actual, dict.fromkeys(actual, False))

    def test_explicit_discovery_constraints_deny_different_scheme_port_host(self):
        for url in ('http://target.test:8443/a', 'https://target.test/a', 'https://other.test:8443/a',
                    'https://api.target.test:8443/a'):
            with self.subTest(url=url):
                self.assertFalse(any(self.decisions(url, ['https://target.test:8443']).values()))

    def test_wildcard_parser_does_not_grant_caller_authority(self):
        # Parser compatibility is retained, but caller authorization is stricter.
        for url in ('http://api.target.test/a', 'http://target.test/a'):
            self.assertTrue(scope_lock.scope_matches(url, ['*.target.test'], extended=True))
            self.assertFalse(scope_discovery.is_host_allowed(url, ['*.target.test']))
        for url in ('http://target.test.other.test/a', 'http://other-target.test/a'):
            self.assertFalse(scope_discovery.is_host_allowed(url, ['*.target.test']))
        for entries in (['.target.test'], ['*target.test'], ['[::1]:8080'], ['http://[::1]']):
            self.assertFalse(scope_discovery.is_host_allowed('http://[::1]:8080/a', entries))

    def test_passive_unset_compatibility_is_explicit_and_not_strict_authority(self):
        self.assertEqual(self.decisions('https://target.test/a', [], active=False), {
            'ScopePolicy': False, 'HostAllowScope': True, 'scope_lock': True,
            'scope_discovery': True, 'SafetyGate': True})

    def test_invalid_collection_does_not_authorize_character_hosts(self):
        self.assertFalse(scope_lock.host_in_scope('http://t/a', 'target.test'))
        self.assertFalse(scope_discovery.is_host_allowed('http://t/a', 'target.test'))
        for malformed in ('target.test', {'t': True}, 3, [None]):
            with self.subTest(scope=malformed):
                ctx = RunContext.create(allowed_hosts=malformed, gate_config={'active_enabled': True})
                self.assertFalse(ctx.scope.in_scope('http://t/a'))
                self.assertFalse(ctx.gate.authorize(validator_name='benign', method='GET', url='http://t/a').allowed)
                standalone = standalone_context(malformed, active_mode=True)
                self.assertFalse(standalone.scope.in_scope('http://t/a'))

    def test_direct_adapters_reject_mapping_and_falsey_malformed_scope(self):
        for malformed in ({'target.test': True}, 0, False, b'target.test', 'target.test'):
            with self.subTest(scope=malformed):
                self.assertFalse(scope_lock.host_in_scope('http://target.test/a', malformed))
                self.assertFalse(scope_discovery.is_host_allowed('http://target.test/a', malformed))
                self.assertFalse(HostAllowScope(hosts=malformed).in_scope('http://target.test/a'))
                self.assertFalse(ScopePolicy(allowed_hosts=malformed).in_scope('http://target.test/a'))

    def test_origin_normalization_preserves_port_ipv6_and_invalid_denial(self):
        self.assertEqual(ScopePolicy.origin_of('https://TARGET.test/a'), 'https://target.test')
        self.assertEqual(ScopePolicy.origin_of('https://target.test:443/a'), 'https://target.test')
        self.assertEqual(ScopePolicy.origin_of('http://[::1]:8080/a'), 'http://[::1]:8080')
        scope = ScopePolicy()
        self.assertFalse(scope.same_origin('not-url', 'another-bad-url'))
        self.assertFalse(scope.same_origin('https://target.test/a', 'https://target.test:444/a'))

    def test_invalid_session_origins_are_rejected_before_credentials_can_bind(self):
        ctx = RunContext.create(allowed_hosts=['target.test'])
        for origin in ('http://user:synthetic@target.test/a', 'http://target.test:bad/a', 'not-url'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                ctx.sessions.register('id', 'principal', headers={'Authorization': 'Bearer synthetic'}, allowed_origins=[origin])
        self.assertEqual(ctx.sessions.all(), [])

    def test_standalone_extended_scope_is_denied_before_any_await_or_io(self):
        for entries, url in ((['target.test:443'], 'https://target.test/a'),
                             (['https://target.test:8443'], 'https://target.test:8443/a'),
                             (['*.target.test'], 'http://api.target.test/a'),
                             (['10.0.0.0/24'], 'http://10.0.0.7/a')):
            with self.subTest(entries=entries):
                ctx = standalone_context(entries, active_mode=True)
                with patch.object(ctx, 'default_client', side_effect=AssertionError('client forbidden')), \
                     patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                     patch.object(socket.socket, 'connect', side_effect=AssertionError('connect forbidden')):
                    coro = ctx.target_transport().execute(TypedRequest('GET', url), capability='benign-policy')
                    try:
                        with self.assertRaises(StopIteration) as stopped:
                            coro.send(None)  # a denial completes before the first await
                    finally:
                        coro.close()
                self.assertEqual(stopped.exception.value.outcome, 'out_of_scope')
                self.assertEqual(ctx.budget.used, 0)
                self.assertEqual(ctx.gate.audit_log, [])


class _ScopeSpy:
    def __init__(self, scope):
        self.scope = scope
        self.checked = []

    def in_scope(self, url):
        self.checked.append(url)
        return self.scope.in_scope(url)

    def same_origin(self, a, b):
        return self.scope.same_origin(a, b)


class ScopeTransportCallerTests(unittest.IsolatedAsyncioTestCase):
    async def run_request(self, url, *, locations=None, entries=None, session=False, bypass=False):
        sent = []
        entries = ['target.test'] if entries is None else entries
        ctx = RunContext.create(allowed_hosts=entries, gate_config={'active_enabled': True})
        spy = _ScopeSpy(ctx.scope)
        ctx.scope = spy

        def ordinary_response(request):
            sent.append({'url': str(request.url), 'authorization': request.headers.get('Authorization')})
            destination = (locations or {}).get(str(request.url))
            return httpx.Response(302, headers={'Location': destination}) if destination else httpx.Response(200, text='ordinary result')

        client = httpx.AsyncClient(transport=httpx.MockTransport(ordinary_response), follow_redirects=False)
        ctx._default_client = client
        session_id = None
        if session:
            managed = ctx.sessions.register('synthetic', 'one', headers={'Authorization': 'Bearer synthetic'}, allowed_origins=['http://target.test'])
            managed._client = client
            session_id = managed.session_id
        try:
            # Any accidental socket/DNS use is a test failure, independent of
            # recorded request counts. The only client is the MockTransport.
            with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('real DNS forbidden')), \
                 patch.object(socket.socket, 'connect', side_effect=AssertionError('real connect forbidden')):
                if bypass:
                    with patch.object(scope_lock, 'scope_matches', return_value=True):
                        outcome = await ctx.target_transport().execute(TypedRequest('GET', url), capability='benign-policy', session_ref=session_id)
                else:
                    outcome = await ctx.target_transport().execute(TypedRequest('GET', url), capability='benign-policy', session_ref=session_id)
            return outcome, sent, spy.checked, ctx.gate.audit_log, ctx.budget.used
        finally:
            await ctx.aclose()

    async def test_allowed_ordinary_redirect_checks_every_hop_before_send(self):
        first, second, third = ['http://target.test/'+p for p in ('one','two','three')]
        outcome, sent, checked, audits, used = await self.run_request(first, locations={first:second, second:third})
        self.assertEqual(outcome.outcome, 'ok')
        self.assertEqual(checked, [first, second, third])
        self.assertEqual([row['url'] for row in sent], checked)
        self.assertEqual([entry.url for entry in audits], checked)
        self.assertEqual(used, 3)

    async def test_offscope_redirect_denied_before_second_send(self):
        first, denied = 'http://target.test/one', 'http://api.target.test/two'
        outcome, sent, checked, audits, used = await self.run_request(first, locations={first:denied})
        self.assertEqual(outcome.outcome, 'out_of_scope')
        self.assertEqual(checked, [first, denied])
        self.assertEqual([row['url'] for row in sent], [first])
        self.assertEqual(len(audits), 1)
        self.assertEqual(used, 1)

    async def test_malformed_redirect_is_visible_denial_and_not_exception(self):
        first, denied = 'http://target.test/one', 'http://user:synthetic@target.test/two'
        outcome, sent, checked, _, used = await self.run_request(first, locations={first:denied})
        self.assertEqual(outcome.outcome, 'out_of_scope')
        self.assertEqual(checked, [first, denied])
        self.assertEqual(len(sent), 1)
        self.assertEqual(used, 1)

    async def test_invalid_port_redirect_is_visible_client_error_without_second_send(self):
        # httpx parses next_request even with follow_redirects=False. It rejects
        # the invalid port before returning the response to the manual loop;
        # the transport must preserve that explicit error and make no next send.
        first, denied = 'http://target.test/one', 'http://target.test:bad/two'
        outcome, sent, checked, _, used = await self.run_request(first, locations={first:denied})
        self.assertEqual(outcome.outcome, 'error')
        self.assertIn('port', outcome.error.lower())
        self.assertEqual(checked, [first])
        self.assertEqual(len(sent), 1)
        self.assertEqual(used, 1)

    async def test_bad_input_and_empty_scope_never_reach_transport(self):
        for url, entries in (('http://user:synthetic@target.test/a', ['target.test']),
                             ('http://target.test:bad/a', ['target.test']),
                             ('http://target.test/a', [])):
            with self.subTest(url=url, entries=entries):
                outcome, sent, _, _, used = await self.run_request(url, entries=entries)
                self.assertEqual(outcome.outcome, 'out_of_scope')
                self.assertEqual(sent, [])
                self.assertEqual(used, 0)

    async def test_cross_origin_allowed_hop_strips_session_credential(self):
        first, second = 'http://target.test/one', 'http://other.test/two'
        outcome, sent, checked, audits, used = await self.run_request(first, locations={first:second}, entries=['target.test','other.test'], session=True)
        self.assertEqual(outcome.outcome, 'ok')
        self.assertEqual([row['authorization'] for row in sent], ['Bearer synthetic', None])
        self.assertEqual(checked, [first, second])
        self.assertEqual(len(audits), 2)
        self.assertEqual(used, 2)

    async def test_defect_injection_removing_scope_checks_defeats_negative_control(self):
        url = 'http://other.test/a'
        normal, sent, _, _, _ = await self.run_request(url)
        self.assertEqual(normal.outcome, 'out_of_scope')
        self.assertEqual(sent, [])
        injected, reopened, _, _, _ = await self.run_request(url, bypass=True)
        self.assertEqual(injected.outcome, 'ok')
        self.assertEqual([row['url'] for row in reopened], [url])


if __name__ == '__main__':
    unittest.main()
