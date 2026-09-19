"""Real loopback executor contract across validator adapters.

Each case retains its own adapter/result assertions. Scope denial must produce
zero requests and consume zero budget. These are transport tests, not exploit
confirmation proofs; class-specific oracle tests remain in their own modules.
"""
import asyncio
import unittest

from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_run_context import _Fixture
from harness.validators.cors_validator import CorsValidator
from harness.validators.csp_validator import CspValidator
from harness.validators.oauth_validator import OAuthValidator
from harness.validators.header_injection_validator import HeaderInjectionValidator
from harness.validators.subdomain_takeover_validator import SubdomainTakeoverValidator
from harness.validators.web_cache_poisoning_validator import WebCachePoisoningValidator
from harness.validators.recon_validator import ReconValidator


class _LoopbackTakeover(SubdomainTakeoverValidator):
    def __init__(self, url, **kwargs):
        super().__init__(**kwargs)
        self.url = url

    def _fingerprint_url(self, host):
        return self.url


async def _probe(name, ctx, base, allowed):
    if name == 'cors':
        return await CorsValidator(run_context=ctx)._send_request(
            base + '/cors', **({'headers': {'Origin': 'https://evil.test'}} if allowed else {}))
    if name == 'csp':
        return await CspValidator(run_context=ctx)._fetch_fresh_headers(
            HttpExchange(url=base + '/page', method='GET'))
    if name == 'oauth':
        exchange = HttpExchange(url=base + '/authorize?response_type=code&client_id=web&state=abcdefgh'
                                '&redirect_uri=' + base + '%2Fcallback', method='GET')
        return await OAuthValidator(run_context=ctx)._check_redirect_uri_validation(exchange)
    if name == 'header_injection':
        return await HeaderInjectionValidator(run_context=ctx)._probe_param(
            HttpExchange(url=base + '/redirect?next=home', method='GET'), 'next')
    if name == 'takeover':
        return await _LoopbackTakeover(base + '/', run_context=ctx)._check_fingerprint('unused.github.io')
    if name == 'web_cache':
        return await WebCachePoisoningValidator(run_context=ctx)._send(base + '/account')
    if name == 'recon':
        return await ReconValidator(run_context=ctx)._send_request(base + ('/robots.txt' if allowed else '/.env'))
    raise AssertionError(f'Unknown validator case: {name}')


CASES = ('cors', 'csp', 'oauth', 'header_injection', 'takeover', 'web_cache', 'recon')


class ValidatorTransportContractTests(unittest.TestCase):
    def _scenario(self, name, allowed):
        fixture = _Fixture()
        self.addCleanup(fixture.close)
        ctx = RunContext.create(allowed_hosts=['127.0.0.1' if allowed else 'elsewhere.test'],
                                max_requests=1, gate_config={'active_enabled': True})

        async def run():
            try:
                return await _probe(name, ctx, fixture.base, allowed)
            finally:
                await ctx.aclose()

        result = asyncio.run(run())
        self.assertEqual(ctx.budget.used, int(allowed), name)
        self.assertEqual(len(fixture.httpd.received), int(allowed), name)
        if name in ('cors', 'web_cache', 'recon'):
            if allowed:
                self.assertEqual(result.status_code, 200)
            else:
                self.assertIsNone(result)
        elif name == 'csp':
            if allowed:
                self.assertIsInstance(result, dict)
            else:
                self.assertIsNone(result)
        else:
            self.assertFalse(result.vulnerable)
            if name == 'oauth' and allowed:
                self.assertTrue(result.checked)
            if name == 'takeover' and not allowed:
                self.assertFalse(result.checked)

    def test_allowed_requests_use_exactly_one_send_and_budget(self):
        for name in CASES:
            with self.subTest(validator=name):
                self._scenario(name, True)

    def test_off_scope_controls_use_zero_sends_and_budget(self):
        for name in CASES:
            with self.subTest(validator=name):
                self._scenario(name, False)


if __name__ == '__main__':
    unittest.main()
