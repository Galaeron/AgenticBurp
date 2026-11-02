"""Replay audit truth: claim routing, per-class procedures and totals (batch 08, AR-08c).

Loads the script named by REPLAY_AUDIT (default: the copy beside this file) and
drives its main() with an inventory of claims. Unsupported claims run against a
stub Target that refuses to send. The WebSocket and error-disclosure procedures run
caller-level: main() with the real Target, sending real HTTP requests and raw
handshakes to an owned loopback server, each with a negative control the procedure
must refute or leave unconfirmed.
"""
import importlib.util
import itertools
import json
import os
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = pathlib.Path(os.environ.get('REPLAY_AUDIT') or HERE / 'replay_audit.py')


def _load():
    spec = importlib.util.spec_from_file_location('replay_audit_under_test', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _claim(validator, cls, url='http://127.0.0.1:3002/', method='GET'):
    return {'validator': validator, 'class': cls, 'method': method, 'url': url, 'resolved_from': 'finding',
            'accounting_kind': 'hardening', 'principal': '', 'proof_ids': ['p-' + cls], 'observed': ''}


class _NoSend:
    count = 0

    def __init__(self, *_):
        pass

    def send(self, *a, **k):
        raise AssertionError('an unsupported claim must not be sent')

    handshake = send

    def close(self):
        pass


# An Express-style HTML error page: the stack is HTML-escaped, as finalhandler sends it.
_TRACE_PAGE = ('<html><body><pre>Error: lookup failed<br> &nbsp; &nbsp;at Object.handler '
               '(/srv/owned-app/routes/lookup.js:12:7)<br> &nbsp; &nbsp;at Layer.handle '
               '(/srv/owned-app/node_modules/express/lib/router/layer.js:95:5)</pre></body></html>')


class _Owned(BaseHTTPRequestHandler):
    """Owned loopback target. /api/* are HTTP routes; /ws/* are WebSocket endpoints."""
    counter = itertools.count()

    def log_message(self, *_):
        pass

    def _reply(self, status, body, ctype='application/json', extra=()):
        data = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _upgrade(self):
        self.send_response(101, 'Switching Protocols')
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path.startswith('/ws/'):
            if self.headers.get('Upgrade', '').lower() != 'websocket':
                return self._reply(400, '{"error": "upgrade required"}')
            version_ok = self.headers.get('Sec-WebSocket-Version') == '13'
            same_origin = self.headers.get('Origin') == self.server.origin
            if path == '/ws/any':
                return self._upgrade()
            if not version_ok:
                return self._reply(426, '{"error": "unsupported version"}', extra=[('Sec-WebSocket-Version', '13')])
            if path == '/ws/open' or (path == '/ws/strict' and same_origin):
                return self._upgrade()
            if path == '/ws/strict':
                return self._reply(403, '{"error": "origin not allowed"}')
            return self._reply(401, '{"error": "login required"}')
        if path == '/api/trace':
            return self._reply(500, _TRACE_PAGE, 'text/html; charset=utf-8')
        if path == '/api/clean':
            return self._reply(200, '{"status": "ok"}', extra=[('X-Powered-By', 'Express 4.17.1')])
        if path == '/api/varying':
            return self._reply(200, '{"n": %d}' % next(self.counter))
        return self._reply(404, '{"error": "not found"}')

    do_POST = do_GET


class ReplayAuditTruthTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def _run(self, claims, target=None):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(self.mod, 'inventory', return_value=claims), \
                patch.object(self.mod, 'Target', target or _NoSend), \
                patch.object(self.mod, 'register', return_value={'tag': 'a', 'token': 'audit-token'}):
            self.mod.main(pathlib.Path(tmp), False)
            text = (pathlib.Path(tmp) / 'replay-audit.json').read_text(encoding='utf-8')
            trace = pathlib.Path(tmp) / 'replay-audit-trace.jsonl'
            self.trace = [json.loads(line) for line in trace.read_text(encoding='utf-8').splitlines()] \
                if trace.exists() else []
            self.text = text
            return json.loads(text)

    def test_generic_conf05_claim_is_not_judged_by_a_csp_rule(self):
        self.assertIsNone(self.mod.audit_for(_claim('csp_validator', 'conf-05 security misconfiguration')))
        self.assertIsNotNone(self.mod.audit_for(_claim('csp_validator', 'missing content security policy')))

    def test_websocket_and_error_claims_have_procedures(self):
        self.assertIs(self.mod.audit_for(_claim('websocket_validator', 'cswsh')), self.mod.audit_websocket)
        self.assertIs(self.mod.audit_for(_claim('verbose_error_validator', 'verbose_error_disclosure')),
                      self.mod.audit_error_disclosure)

    def test_race_claims_stay_unsupported_with_the_reason_recorded(self):
        out = self._run([_claim('race_condition_validator', 'race condition'),
                         _claim('toctou_validator', 'race_condition'), _claim('csp_validator', 'conf-05')])
        self.assertEqual({c['audit_state'] for c in out['claims']}, {'unsupported_audit'})
        self.assertEqual({c['verdict'] for c in out['claims']}, {'unsupported_audit'})
        race = out['claims'][:2]
        for claim in race:
            self.assertIn('mutat', claim['reason'])
            self.assertIn('burst', claim['reason'])
        self.assertEqual(out['claims'][2]['reason'], 'no independent audit procedure for this claim')
        totals = out['audit_totals']
        self.assertEqual((totals['audited'], totals['unsupported_audit']), (0, 3))
        self.assertIsNone(totals['false_positives'])
        self.assertIsNone(totals['false_positive_rate'])
        self.assertFalse(totals['all_claims_audited'])

    def test_missing_audit_support_is_never_zero_false_positives(self):
        out = self._run([_claim('race_condition_validator', 'race condition'), _claim('sqlmap', 'sqli', url=None)])
        totals = out['audit_totals']
        self.assertEqual((totals['audited'], totals['unsupported_audit'], totals['not_audited']), (0, 1, 1))
        self.assertIsNone(totals['false_positives'])
        self.assertIsNone(totals['false_positive_rate'])
        self.assertFalse(totals['all_claims_audited'])


class ReplayAuditProcedureCallerTests(unittest.TestCase):
    """main() with the real Target against an owned loopback server."""

    def setUp(self):
        self.mod = _load()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _Owned)
        self.server.origin = 'http://127.0.0.1:%d' % self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        base = patch.object(self.mod, 'BASE', self.server.origin)
        base.start()
        self.addCleanup(base.stop)

    def _run(self, claims):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(self.mod, 'inventory', return_value=claims), \
                patch.object(self.mod, 'register', return_value={'tag': 'a', 'token': 'audit-token'}):
            self.mod.main(pathlib.Path(tmp), False)
            self.text = (pathlib.Path(tmp) / 'replay-audit.json').read_text(encoding='utf-8')
            trace = pathlib.Path(tmp) / 'replay-audit-trace.jsonl'
            self.trace = [json.loads(line) for line in trace.read_text(encoding='utf-8').splitlines()] \
                if trace.exists() else []
            return json.loads(self.text)

    def _one(self, validator, cls, path, method='GET'):
        out = self._run([_claim(validator, cls, self.server.origin + path, method)])
        self.assertEqual(len(out['claims']), 1)
        return out, out['claims'][0]

    # ---- WebSocket (CSWSH)

    def test_websocket_upgrading_a_foreign_origin_is_audited(self):
        out, claim = self._one('websocket_validator', 'cswsh', '/ws/open?EIO=4&transport=websocket')
        self.assertEqual(claim['verdict'], 'confirmed_hardening', claim['reason'])
        self.assertEqual(claim['audit_state'], 'audited')
        labels = [row['label'] for row in self.trace]
        self.assertEqual(len(labels), 3, labels)
        self.assertEqual([row['upgraded'] for row in claim['checks']], [True, True, False])
        self.assertEqual(out['audit_totals']['false_positives'], 0)
        self.assertTrue(out['audit_totals']['all_claims_audited'])

    def test_websocket_enforcing_origin_refutes_the_claim(self):
        out, claim = self._one('websocket_validator', 'cswsh', '/ws/strict')
        self.assertEqual(claim['verdict'], 'false_positive', claim['reason'])
        self.assertEqual([row['status'] for row in claim['checks']], [101, 403, 426])
        self.assertEqual(out['audit_totals']['false_positives'], 1)

    def test_websocket_needing_credentials_stays_unconfirmed(self):
        out, claim = self._one('websocket_validator', 'cswsh', '/ws/auth')
        self.assertEqual(claim['verdict'], 'inconclusive', claim['reason'])
        self.assertEqual(claim['audit_state'], 'not_audited')
        self.assertIsNone(out['audit_totals']['false_positives'])

    def test_websocket_upgrading_an_invalid_handshake_proves_nothing(self):
        _, claim = self._one('websocket_validator', 'cswsh', '/ws/any')
        self.assertEqual(claim['verdict'], 'inconclusive', claim['reason'])
        self.assertIn('invalid', claim['reason'])

    # ---- Error disclosure

    def test_replayed_stack_trace_is_confirmed_without_storing_the_body(self):
        out, claim = self._one('verbose_error_validator', 'verbose_error_disclosure', '/api/trace')
        self.assertEqual(claim['verdict'], 'confirmed_observation', claim['reason'])
        self.assertEqual([row['error_signatures'] for row in claim['checks']],
                         [['node_stack_frame'], ['node_stack_frame']])
        # Signature names only: no body text in the report or the trace.
        self.assertNotIn('/srv/owned-app', self.text)
        self.assertNotIn('/srv/owned-app', json.dumps(self.trace))
        self.assertEqual(out['audit_totals']['false_positives'], 0)

    def test_error_claim_on_a_clean_route_is_refuted(self):
        # A version banner header is not an error disclosure.
        out, claim = self._one('verbose_error_validator', 'verbose_error_disclosure', '/api/clean')
        self.assertEqual(claim['verdict'], 'false_positive', claim['reason'])
        self.assertEqual(out['audit_totals']['false_positives'], 1)
        self.assertEqual(out['audit_totals']['false_positive_rate'], 1.0)

    def test_clean_replay_does_not_refute_a_claim_made_as_another_principal(self):
        claim = _claim('verbose_error_validator', 'verbose_error_disclosure', self.server.origin + '/api/clean')
        claim['principal'] = 'session-alice'
        out = self._run([claim])
        self.assertEqual(out['claims'][0]['verdict'], 'inconclusive', out['claims'][0]['reason'])
        self.assertIsNone(out['audit_totals']['false_positives'])

    def test_error_claim_on_a_varying_route_stays_unconfirmed(self):
        out, claim = self._one('verbose_error_validator', 'verbose_error_disclosure', '/api/varying')
        self.assertEqual(claim['verdict'], 'inconclusive', claim['reason'])
        self.assertEqual(claim['audit_state'], 'not_audited')
        self.assertIsNone(out['audit_totals']['false_positives'])

    def test_error_claim_with_an_unrecorded_body_is_not_replayed(self):
        _, claim = self._one('verbose_error_validator', 'verbose_error_disclosure', '/api/trace', method='POST')
        self.assertEqual(claim['verdict'], 'inconclusive', claim['reason'])
        self.assertEqual(self.trace, [])

    def test_unsupported_race_claim_does_not_dilute_the_rate(self):
        out = self._run([_claim('race_condition_validator', 'race condition', self.server.origin + '/api/clean'),
                         _claim('verbose_error_validator', 'verbose_error_disclosure',
                                self.server.origin + '/api/clean')])
        totals = out['audit_totals']
        self.assertEqual((totals['audited'], totals['unsupported_audit'], totals['false_positives']), (1, 1, 1))
        self.assertEqual(totals['false_positive_rate'], 1.0)
        self.assertFalse(totals['all_claims_audited'])
        self.assertEqual([row['url'] for row in self.trace], [self.server.origin + '/api/clean'] * 2)


if __name__ == '__main__':
    unittest.main()
