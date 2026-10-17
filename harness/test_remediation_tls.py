"""R06 trust controls: client factory spies and in-memory TLS, no sockets.

The appended certificates/key are public synthetic fixtures, not credentials.
They are deliberately fixed so test execution only needs the Python stdlib.
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


_TRUSTED_CA = '-----BEGIN CERTIFICATE-----\nMIIC9zCCAd+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9SMDYg\ncHVibGljIHN5bnRoZXRpYyBmaXh0dXJlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIx\nMDAwMTAxMDAwMDAwWjAqMSgwJgYDVQQDDB9SMDYgcHVibGljIHN5bnRoZXRpYyBm\naXh0dXJlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ADnk3rR\nFStfVq5BSXGEJXuelsaro4djH+ipVvU37f/ZkrVC6an1IzrpePzHPbr3Ho75o5Cm\n8TLPcRO5u1b5EMUGwGPDNmgy60nVS6YZShBE35wL+JX4EvVQ2gy1PBHzAKUQAMbA\nCssk8dicySHDzmXHk5dbZ7PmZAFAA1wGgaOxOOPeEHHbvAGuRSR/IJP1Bo7vTCqe\n84yr2lxYRtwOyX2l8ueG8BXn7satbbci2H1pCgG8tyeTIizGfRekHe5N1ayP4EfV\nd6oOrIYsr1N0t9Sw369mzoxyu4Pn9z/6LA203Cu0TQ+CEs0XlkmjdJ0AyR1ml/cV\njlU+8PnLOdZH4wIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB\n/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAvo0U4YLb5PQci0UMcurcqbRVwkO8\nvwNkCIgO7tTGLYnSjGb3MgSrt4TUvEYcgAGpxorZGb8albBMhxPE0hddPopzdoNG\n6qNpeel3ArzsOV8NF+cip2nmhNRgD7IJuAsET6hyN+b1BYA9Njtb/k+Q7CHC42yV\nDuearqiBn4Z6dpUo3D4g8K/Vz1Nd4XKAlKe+vNHEmE5hsMAUgVV5u7CBRxkQiW6r\n6hrXHohez/kb1DE+83jB2YcyjXOFk+NQc8XrZ6NjXx1xPzbwIW0c37CVFDWNtnVl\nQSfh26prN+ePEhjVvTgz73GqX0gqc9fQqHMgLxwJijDoHoXcsxN+A1eogg==\n-----END CERTIFICATE-----\n'

_LEAF_CERT = '-----BEGIN CERTIFICATE-----\nMIIC5zCCAc+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9SMDYg\ncHVibGljIHN5bnRoZXRpYyBmaXh0dXJlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIx\nMDAwMTAxMDAwMDAwWjAXMRUwEwYDVQQDDAxmaXh0dXJlLnRlc3QwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCokJ2gvcgO+HBVUuBd3qN9aeW34aPAlWqe\nRKotsszF02Br4saGNnH0Np3QQgcgrAQpdZjO2jLMsBtNbEqhfHKn37svB69/ej8e\nXJFadwJPxd7NSBlT71Pj9uczUlW4uJcr5xm9mEksl3GuSTHxI4qdTXxo0+I3Pi/p\nFBtMrGp1u9EytDi1u83MeVMks7walSnB05BLr36seVoWrUcAOgkTQDY4tIi5lLQW\nXbSW3s0sc28wj2xFK5SwBxk0QKYvgfwr0qNk/1nYWQXt5sWI2+xZKI+RaXoc1WzJ\n3ZGUhlzMkovLbfmsVOXm7s3oKtUqA6h0CPvV0/f58DaKc4MzxxF1AgMBAAGjKTAn\nMAwGA1UdEwEB/wQCMAAwFwYDVR0RBBAwDoIMZml4dHVyZS50ZXN0MA0GCSqGSIb3\nDQEBCwUAA4IBAQAZ0NlugMWCpwp+NSVESut/eGEF4dqzqZZ7Gm4/DIEL1BLbvX1F\n5NGzBQBg+l9bt3Cb2NHnAzCEjynmmSQADK3uomOsrXS6vrrOKH7pgI9GXyOVoBth\nFiSUiM+gdfPTTZtFkfbD1zX9IbzPCcpELCeoVsvvyBnwSkEBUoB0EV8LcTXoszTl\na4y/KcwGRg/AcFNdEkIbByGdS9j3HeyeFcZAZSdJSmbX7EPjOhk5BqOtY5+fBzRf\nzawu2LtTi2vdokhYxHsCeEndQjyNuJsgu6GENNfHxoBWemTmjmnWQqbZ1gdL1KLH\nEpBcv4bNX++aYdgKqg4ztheiMAvibVGqM8yl\n-----END CERTIFICATE-----\n'

_LEAF_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCokJ2gvcgO+HBV\nUuBd3qN9aeW34aPAlWqeRKotsszF02Br4saGNnH0Np3QQgcgrAQpdZjO2jLMsBtN\nbEqhfHKn37svB69/ej8eXJFadwJPxd7NSBlT71Pj9uczUlW4uJcr5xm9mEksl3Gu\nSTHxI4qdTXxo0+I3Pi/pFBtMrGp1u9EytDi1u83MeVMks7walSnB05BLr36seVoW\nrUcAOgkTQDY4tIi5lLQWXbSW3s0sc28wj2xFK5SwBxk0QKYvgfwr0qNk/1nYWQXt\n5sWI2+xZKI+RaXoc1WzJ3ZGUhlzMkovLbfmsVOXm7s3oKtUqA6h0CPvV0/f58DaK\nc4MzxxF1AgMBAAECggEABRW/u46eD12NPfWvEQXbVrgwFtj2sKORQM7/dztyk/Ep\ncne312qjC2PuZM7pGiI2Se3jOzI34Bbb6/z9T1vKtae5JNUNhUHxz3+pXtpCNpfY\nfcbUBMUuea0EEndEYLsozEk/bInAg1jaNBC/MfAJiW9B9oOVymbU2SojHLAC0iRY\nvMxzQKD2LEPVfbDeC6m/1wYGb7T7vPu3/uuiaWDUAqGoqr7Il99Ykh4YjTYAnvgm\naqMCEd6vAm5AbcJ0Hw74REAou+V1983ZkAOGuIrnDjERmbAF9Xol2sqd58kXck1p\n3gkRDzQb0t9b+nKwpAYFnSrU5gELaN+kaaDA9/ckYQKBgQDf0nc9aNDNOl8yhpCo\nZe5aQG6ahds0FdDxXo7LXbznx1IDaI/aAo83BWcOKnz2PazSZjxSQpzN4pmYugxs\nEHqQjfThUQsR1EBaKAzIHUmOK5V4NHZ6VN8I8W4TCsERtoRn5NANw7bOivxMU1yq\nlve9l1+A49m1EaToDLPqar9dyQKBgQDAzHeBDXDKSRG+Ai+KxFip2oAX3PQWicd9\nOaf1GAirRcIBCXLZntCZfmzJeaXX18GkVAvKhPw146qCaxGrOngIqI8H3YsnWbZX\nXRVUjrZJ1gYawufoqtBG+ivPi9fHu7Cgim3eaCR/V2Q3idd6YHXByhZfQX3Ey6uc\nBSwpM7b8TQKBgQCe2s/KhAP+RPmf8KXm/0FmSOi3P13O39UGGqiaahNTJcJtrN68\nSqi+0lTMVxeN5UQtqGYTtDd6YOPG4/VBFYkH49jzugNzSgPKeTZpKXA1OXXCdOnJ\n9Ua/ICuR1EYnfjUHT/ziaA/tE/PxcBEK+k8m/rLH1e+Eddtm3u0q6UydEQKBgQCw\n1hm6feh5MeIbJIgUwJkOWgJpYNllHsSiAFMkhAHXjmkuaEs2feuZDhOcDH7n5daP\n8iLKg4WNrB9F9gzDwCI+1tQyA6tR0YBky1T4NNnQCYWZ4DGz/5B/uZCbkgm+AlI0\nPiQd/emT/0VFh6HjdjwsHj686iYAbkseFMR3mh55dQKBgQDP3Iyl2MzqenOifiXa\nWJCQcWpnpEk/9oXKDG+5ldopRE74d8Eg4/rnAti1RWarS8mB3Iv7p2o1H3YM6ZIJ\naw3UdD8q/qNg/iLmxp80EJnoKfEOmhwVR48ZCOrupqkvhMoegiKBU6Fv4LYXGgEi\n7mdBQXAqABYzr13AL0Seq9gtng==\n-----END PRIVATE KEY-----\n'

if __name__ == '__main__':
    unittest.main()
