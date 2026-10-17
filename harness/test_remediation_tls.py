"""R06 trust controls: client factory spies and in-memory TLS, no sockets.

The appended certificates/key are public synthetic fixtures, not credentials.
They are deliberately fixed so test execution only needs the Python stdlib.
They carry the key-identifier/basic-constraint extensions that strict X.509
verification (Python 3.13+ default) requires.
"""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

import httpx
import yaml

from harness.run_context import RunContext, TypedRequest
from harness.tls_policy import TLSPolicy


def handshake(client_context, server_context, hostname):
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        try:
            client.do_handshake()
            client_done = True
        except ssl.SSLWantReadError:
            pass
        if client_out.pending:
            server_in.write(client_out.read())
        try:
            server.do_handshake()
            server_done = True
        except ssl.SSLWantReadError:
            pass
        if server_out.pending:
            client_in.write(server_out.read())
        if client_done and server_done:
            return True
    raise AssertionError('in-memory TLS handshake did not finish')


class CertificateTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='r06-synthetic-tls-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.ca = root/'synthetic-ca.pem'
        self.ca.write_text(_TRUSTED_CA,encoding='ascii')
        leaf = root/'synthetic-leaf.pem'
        key = root/'synthetic-leaf-key.pem'
        leaf.write_text(_LEAF_CERT,encoding='ascii')
        key.write_text(_LEAF_KEY,encoding='ascii')
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(str(leaf),str(key))

    def trusted_policy(self):
        return TLSPolicy.from_config({'transport': {'tls': {'ca_bundle': str(self.ca)}}})

    def test_declared_synthetic_ca_accepts_chain_and_correct_hostname(self):
        policy = self.trusted_policy()
        with patch.object(socket.socket,'connect',side_effect=AssertionError('no socket')):
            self.assertTrue(handshake(policy.profile_for().context,self.server_context,'fixture.test'))
        self.assertEqual(policy.provenance()['ca_bundle_sha256'],hashlib.sha256(self.ca.read_bytes()).hexdigest())

    def test_system_default_rejects_unknown_synthetic_ca(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(TLSPolicy.from_config().profile_for().context,self.server_context,'fixture.test')

    def test_disabling_verification_defeats_unknown_ca_negative_control(self):
        context = TLSPolicy.from_config().profile_for().context
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(context,self.server_context,'fixture.test')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.assertTrue(handshake(context,self.server_context,'fixture.test'))

    def test_trusted_chain_wrong_hostname_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(self.trusted_policy().profile_for().context,self.server_context,'other.test')

    def test_isolated_fixture_bypass_is_local_to_declared_origin(self):
        policy = TLSPolicy.from_config({'transport': {'tls': {
            'fixture_insecure_origins': ['https://127.0.0.1:9443'],
            'fixture_insecure_reason': 'isolated synthetic fixture'}}})
        insecure = policy.profile_for('https://127.0.0.1:9443/a')
        self.assertTrue(handshake(insecure.context,self.server_context,'127.0.0.1'))
        for url in ('https://127.0.0.1:9444/a','https://fixture.test:9443/a'):
            with self.subTest(url=url), self.assertRaises(ssl.SSLCertVerificationError):
                handshake(policy.profile_for(url).context,self.server_context,'fixture.test')

    def test_missing_or_invalid_bundle_fails_without_insecure_fallback(self):
        self.ca.write_text('not a PEM certificate',encoding='ascii')
        for value in (str(self.ca),str(self.ca.parent/'missing.pem'),'relative.pem'):
            with self.subTest(bundle=value), self.assertRaises(ValueError):
                TLSPolicy.from_config({'transport': {'tls': {'ca_bundle':value}}})


class _FakeClient:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.closed = False

    async def aclose(self):
        self.closed = True


class TrustClientCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_shipped_config_requires_verification_without_fixture_exceptions(self):
        config = yaml.safe_load((Path(__file__).parent/'config.yaml').read_text(encoding='utf-8'))
        policy = TLSPolicy.from_config(config)
        self.assertEqual(policy.provenance()['fixture_insecure_origins'],[])
        self.assertEqual(policy.profile_for('https://127.0.0.1:9443/a').context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(policy.profile_for().context.check_hostname)

    async def test_actual_transport_default_and_session_caller_enforce_trust_and_hostname(self):
        with tempfile.TemporaryDirectory(prefix='r06-caller-tls-') as directory:
            folder = Path(directory)
            ca, cert, key = (folder/name for name in ('ca.pem','leaf.pem','key.pem'))
            ca.write_text(_TRUSTED_CA,encoding='ascii')
            cert.write_text(_LEAF_CERT,encoding='ascii')
            key.write_text(_LEAF_KEY,encoding='ascii')
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(str(cert),str(key))

            class HandshakeClient(_FakeClient):
                async def request(self, method, url, **kwargs):
                    try:
                        handshake(self.options['verify'],server,httpx.URL(url).host)
                    except ssl.SSLCertVerificationError:
                        raise httpx.ConnectError('synthetic TLS certificate verification failed') from None
                    return httpx.Response(200,text='ordinary synthetic response')

            for trusted, hostname, expected in ((True,'fixture.test','ok'),(False,'fixture.test','error'),
                                                (True,'other.test','error')):
                for authenticated in (False,True):
                    with self.subTest(trusted=trusted,hostname=hostname,session=authenticated):
                        settings = {'transport':{'tls':{'ca_bundle':str(ca)}}} if trusted else {}
                        ctx = RunContext.create(allowed_hosts=[hostname],config=settings)
                        session_id = None
                        if authenticated:
                            session_id = 'synthetic'
                            ctx.sessions.register(session_id,'one',headers={'Authorization':'Bearer synthetic'},
                                                  allowed_origins=[f'https://{hostname}'])
                        try:
                            with patch('harness.run_context.httpx.AsyncClient',HandshakeClient), \
                                 patch.object(socket,'getaddrinfo',side_effect=AssertionError('no DNS')), \
                                 patch.object(socket.socket,'connect',side_effect=AssertionError('no socket')):
                                outcome = await ctx.target_transport().execute(TypedRequest('GET',f'https://{hostname}/a'),
                                                                               capability='benign-tls',session_ref=session_id)
                            self.assertEqual(outcome.outcome,expected)
                            self.assertEqual(ctx.budget.used,1)
                            if expected == 'error':
                                self.assertIsNone(outcome.status)
                                self.assertIn('verification failed',outcome.error)
                        finally:
                            await ctx.aclose()

    async def test_denied_caller_records_declared_tls_profile_without_claiming_applied_client(self):
        from harness import evidence_ledger
        ctx = RunContext.create(allowed_hosts=['fixture.test'])
        emitted = []
        with patch.object(evidence_ledger.Provenance,'capture',return_value=None), \
             patch.object(evidence_ledger,'emit',side_effect=lambda *args,**kwargs: emitted.append(kwargs.get('data',{}))):
            outcome = await ctx.target_transport().execute(TypedRequest('GET','https://other.test/a'),
                                                          capability='benign-tls',case_ref='synthetic-case')
        self.assertEqual(outcome.outcome,'out_of_scope')
        trust_events = [event['tls_trust'] for event in emitted if 'tls_trust' in event]
        self.assertEqual(len(trust_events),1)
        self.assertTrue(trust_events[0]['verification_required'])
        self.assertFalse(trust_events[0]['client_profile_applied'])
        await ctx.aclose()

    async def test_both_clients_use_same_verified_run_context_and_ca_identity(self):
        ctx = RunContext.create(allowed_hosts=['fixture.test'])
        managed = ctx.sessions.register('one','one',allowed_origins=['https://fixture.test'])
        with patch('harness.run_context.httpx.AsyncClient',_FakeClient):
            anonymous = ctx.default_client(destination='https://fixture.test/a')
            authenticated = managed.client(ctx.timeout,trust_policy=ctx.tls_policy,destination='https://fixture.test/a')
        self.assertIs(anonymous.options['verify'],authenticated.options['verify'])
        self.assertEqual(anonymous.options['verify'].verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(anonymous.options['verify'].check_hostname)
        self.assertTrue(ctx.config['transport_tls_provenance']['verification_required'])
        await ctx.aclose()
        self.assertTrue(anonymous.closed)
        self.assertTrue(authenticated.closed)

    async def test_fixture_pool_cannot_contaminate_verified_client_in_either_direction(self):
        reason = 'synthetic reason with never-log-me'
        config = {'transport': {'tls': {'fixture_insecure_origins':['https://127.0.0.1:9443'],
                                       'fixture_insecure_reason':reason}}}
        ctx = RunContext.create(allowed_hosts=['127.0.0.1'],config=config)
        managed = ctx.sessions.register('one','one',headers={'Authorization':'Bearer synthetic-private'},
                                       allowed_origins=['https://127.0.0.1:9443','https://127.0.0.1:9444'])
        with patch('harness.run_context.httpx.AsyncClient',_FakeClient), self.assertLogs('harness.tls_policy',level='WARNING') as logs:
            insecure_default = ctx.default_client(destination='https://127.0.0.1:9443/a')
            verified_default = ctx.default_client(destination='https://127.0.0.1:9444/a')
            insecure_session = managed.client(ctx.timeout,trust_policy=ctx.tls_policy,destination='https://127.0.0.1:9443/a')
            verified_session = managed.client(ctx.timeout,trust_policy=ctx.tls_policy,destination='https://127.0.0.1:9444/a')
        self.assertIs(insecure_default.options['verify'],insecure_session.options['verify'])
        self.assertIs(verified_default.options['verify'],verified_session.options['verify'])
        self.assertIsNot(insecure_default,verified_default)
        self.assertIsNot(insecure_session,verified_session)
        self.assertEqual(insecure_default.options['verify'].verify_mode,ssl.CERT_NONE)
        self.assertEqual(verified_default.options['verify'].verify_mode,ssl.CERT_REQUIRED)
        for secret in (reason,'synthetic-private'):
            self.assertNotIn(secret,' '.join(logs.output))
            self.assertNotIn(secret,json.dumps(ctx.tls_policy.provenance('https://127.0.0.1:9443/a')))
        self.assertFalse(ctx.tls_policy.provenance('https://127.0.0.1:9443/a')['verification_required'])
        await ctx.aclose()
        self.assertTrue(all(client.closed for client in (insecure_default,verified_default,insecure_session,verified_session)))

    async def test_exception_config_rejects_nonloopback_userinfo_and_global_disable(self):
        for origin in ('https://remote.test:9443','https://localhost:9443','http://127.0.0.1:9443',
                       'https://u:p@127.0.0.1:9443','https://127.0.0.1:9443/path'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                RunContext.create(config={'transport': {'tls':{'fixture_insecure_origins':[origin],
                                                             'fixture_insecure_reason':'synthetic'}}})
        for settings in ({'verify':False},{'fixture_insecure_origins':['https://127.0.0.1:9443']},
                         {'fixture_insecure_origins':'https://127.0.0.1:9443'}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                RunContext.create(config={'transport': {'tls':settings}})


_TRUSTED_CA = '-----BEGIN CERTIFICATE-----\nMIIDNzCCAh+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9SMDYg\ncHVibGljIHN5bnRoZXRpYyBmaXh0dXJlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIx\nMDAwMTAxMDAwMDAwWjAqMSgwJgYDVQQDDB9SMDYgcHVibGljIHN5bnRoZXRpYyBm\naXh0dXJlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDCVbdUo\nBBPZ0vxB8sV4rcpFehuZCcf46fKBZV2woS/qpF39naaVQd7QUb4kkY4xfJnAn9ll\nvDzrHqDUd+61GwnFdfhohzM1yzCWOIHOAKrjYn22+UXYbJuMxs3ldy0tmHT29ms7\n1tQO0WIpRy/68Tv9VwbzONhnqOhJ5lTXmqqfQL09az6n8cRE2q319NY/O/u5vjFv\nnybjh4Lhh7gO3tdAl91FupyD3kFt1lxRJ47yJU7QugX7XOGWMrUnQyIaPsHx4cP8\nAfhkesJVc9SFdX4lil9Hah2qwKplYnwvFLj9ow5p7R+rWtdH8qvPY+L7IjDgOPt7\n8QMm1GKFrh3DBwIDAQABo2YwZDAfBgNVHSMEGDAWgBTSLqpaYhekfMkdLmgWu1V0\nRIoE7zASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E\nFgQU0i6qWmIXpHzJHS5oFrtVdESKBO8wDQYJKoZIhvcNAQELBQADggEBAGhNJkeq\nS9Y6ypm1N3euLwpULYsypE1xbfZkOe39QtKy7YO6DcUOFB5zibdYZaLvjDkUkyR+\n6B9QKdnYYH1M5n7E+nHeOye6r/eBUPRCfYkw5XO8W3IC8Eq/023RKAlqPbPRWvnp\ntAMLDwwJnZjSjyfGtJuPtqLmuUzM135JWtUoOAmAeQ/hWk8lOjO81genhi/UKy/o\nSeYmc/o6wU/Qr5pBbRYKpkGM8FPWXTWNLRnptYoCdGaB11TJwby6f30aTxIteXLZ\nviuBLqZFzQi/08xT9ukT3dATowMCtKGNMuALGP6hLMztI8bjjOW6FInVfXoLSMhy\noBJd22HxCPDGr9Y=\n-----END CERTIFICATE-----\n'

_LEAF_CERT = '-----BEGIN CERTIFICATE-----\nMIIDTjCCAjagAwIBAgIBAjANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9SMDYg\ncHVibGljIHN5bnRoZXRpYyBmaXh0dXJlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIx\nMDAwMTAxMDAwMDAwWjAXMRUwEwYDVQQDDAxmaXh0dXJlLnRlc3QwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDmdKq7UsMSGFMV+XVF/M/jneQ+t7Oj14Vc\nEIXjzFkiLWaGUWvHbiZQMsn7GsluZLhFLJPWHgJTzJVfqSE8mQMS+idrSLzuPwDf\n/MGPoFfA9idc8H0UIwg5Xfm9SW0CKQeRSzsA8mKIrGPRrA5cJhj/hVYLUSmJxkNF\nYewxPnFUZwNxgRwNfzj7GxOUeFSLEfEl3ezUZvhDtdcLj7n30h4s5kRP2Rhq5Y8h\n1mCNWUqxLYNjHPOdPaDsV+AleBJjGQOoU4z/zjkQjiHRQ2IAVEwE0aN0zhc4MUNh\nTSjDMoByHbSlPRbBl6kHpyIBYR5sYpBz0+lbY7DZP1S/WQEmzNx7AgMBAAGjgY8w\ngYwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB\nBQUHAwEwFwYDVR0RBBAwDoIMZml4dHVyZS50ZXN0MB0GA1UdDgQWBBQoDu4y7hNY\nMVKs6t/8AStWndU29jAfBgNVHSMEGDAWgBTSLqpaYhekfMkdLmgWu1V0RIoE7zAN\nBgkqhkiG9w0BAQsFAAOCAQEAND5eieF0nBNryPf6wMdhynxVbxOvzh/i5susq6N3\n8TP6s6aAsD9X4Nomk2o7rAVAeMhOkNLmIbRhdavhtmPx+GXrvQ2PiLSFuRdvruv0\ni4qY0mgLdfXVPqUZM0LsIEC0O/nx3LhBKeSzE3hLCOd/uBSQ78bmieVErWbiqLOC\n0b0TY1Ofmd6s5OhQuDpYOZv5EwrltGLwipGhFlcCODlSL+hXlO9Kzg8QzY5g4foz\nLwFJqXUE5cHKOZtsiTiXrqxIT90okKQPPFCybSA7zJYl8BkRCBbb3guSDFHVsHgw\nC9IVeNQOqMXcw8dbpa54X3Iot1ehzyLb/PA6V3nlXybs0Q==\n-----END CERTIFICATE-----\n'

_LEAF_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDmdKq7UsMSGFMV\n+XVF/M/jneQ+t7Oj14VcEIXjzFkiLWaGUWvHbiZQMsn7GsluZLhFLJPWHgJTzJVf\nqSE8mQMS+idrSLzuPwDf/MGPoFfA9idc8H0UIwg5Xfm9SW0CKQeRSzsA8mKIrGPR\nrA5cJhj/hVYLUSmJxkNFYewxPnFUZwNxgRwNfzj7GxOUeFSLEfEl3ezUZvhDtdcL\nj7n30h4s5kRP2Rhq5Y8h1mCNWUqxLYNjHPOdPaDsV+AleBJjGQOoU4z/zjkQjiHR\nQ2IAVEwE0aN0zhc4MUNhTSjDMoByHbSlPRbBl6kHpyIBYR5sYpBz0+lbY7DZP1S/\nWQEmzNx7AgMBAAECggEAFdKqcD6wFkCTbZtHza7ZCNbkzEOdEUDRchxmcWHidugR\ns1p2eFYn7qRAmDS7KmcDRBmqjjYdRk4zPvHHIfPjZKKnpPMoYO86Z/uJYM5wQOeO\nZrCnR4bhunz5r0EKv4+fFdUn6zkIt6SLd0lxuqwo5dl8gmnXIyLRL/rL4QXmuXUx\nzDZzCTvu2F74rhcL3V5LqtK2E5ZXL27u5aeR7ka2cRwSR5nOZ3zINB7qyK9smRA7\nULIFpvJsEDTODC0CwdlqtNwDsbS+ZSeewET9ic0bWzsq1/6Fd5Mav0ZwKGxYbqr/\ns0/WLtsligDlZohFaBk33EHJnHwsI2UAbtHnRfOncQKBgQD49h4tJDC4Z5l+jp0R\nIc/wAPwjQMTEwwoRy5BlE+59tO5T3XvGSojHGfxHMzUXLY69A4EOELlHRGdhCfob\nH57SYuY6GBahSvrSgY5KyTZiVtAac2IS6p2sg+yS42kucPvLk27o5wf2g1AgWHnh\nEFvtXvbU+RbizYUSMCS/XvRgZwKBgQDs+JzMG+wTVSSkkl3dLPFw4vK+1trDzkyi\nKbPxZos9JR3VEerkWNOYY/WI070v8k1Uu0txrYOmBp1TQk5oK/UYgnKp313T60cV\nPD9z1L/Qa6db1GcWx3035ALOL8qa5LFyVowzBdHDoTJ7s7l0Si4S+WfE14rm+ppW\n3KiUSZTGzQKBgEWtbEiqBlC1/gmjlGYFFpNPU0HykJ+ZDqpoVKNVbrwT9VfXdxrK\nJXnD1g1/UW6JO5e+8VGkcJZ3mI9aIXuR3/t13oWH1F2UBJsB03cu1V+0eE3O2TX+\nH972lTGPIBL1YCNbwgDBGENwAO7slD/fOjs3BtIYXMVhS8sJWl+NDcwlAoGAYMrX\nuOM61Va0xefnIR1nbTW1809tQgd089PW5SZ+fzY27j4IVMcXfqptszrRjtEI1zA9\ni6xVFq6i+kweHJy/2wgFb++FsrbqbPkT7esbgjVGwdKLXRmUwwyGPNP2jLgW5t4F\nHB4nZSHlrfNmL+LQ2P04boWf/eKkwhAVZ6R6eY0CgYEApshLMu+ruCf0hEIwxKxj\nWdv+Q6eMzwGVvRTpfhnbeJb80DY8C0Xfka+iCDA0Ru0BcMOEbek39kPew4qU2lB2\nV4cAH5z8wOIchXnQ03GGfytsdBKwJ0ZqcS8Gc+RveE8OVxXu39Hg2xtEm1DIgWZs\nmevOyLZjRy8tl+XW6P7ct54=\n-----END PRIVATE KEY-----\n'

if __name__ == '__main__':
    unittest.main()
