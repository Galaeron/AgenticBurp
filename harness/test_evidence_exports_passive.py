"""R15 authenticated evidence/report callers; synthetic SQLite, no target I/O."""
import unittest
from unittest.mock import patch

from harness import evidence_ledger as ledger, store
from harness.models import Finding, HttpExchange
from harness.test_pairing_contract import PairingCallerTests


class EvidenceExportCallerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PairingCallerTests('test_health_is_liveness_and_pairing_requires_credential')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(ledger.reset_default_ledger)
        status = patch.object(ledger, '_PERSISTENCE_FAILURES', 0)
        status.start()
        self.addCleanup(status.stop)
        ledger.reset_default_ledger()
        for name in ('httpx.HTTPTransport.handle_request', 'httpx.AsyncHTTPTransport.handle_async_request'):
            guard = patch(name, side_effect=AssertionError('no external HTTP'))
            guard.start()
            self.addCleanup(guard.stop)
        self.finding = Finding(finding_id='r15-synthetic-observation', vulnerability_class='information_disclosure', confidence=0.2,
                               summary='Ordinary captured observation', evidence='ordinary metadata',
                               suggested_test='review capture', severity='info', basis='observed')
        self.url = 'https://captured.example/ordinary'
        store.persist_findings(HttpExchange(url=self.url, method='GET', response_status=200),
                               'synthetic-passive', [self.finding])
        ledger.emit(ledger.EventType.OBSERVATION, self.finding.finding_id, 'ordinary capture')
        ledger.emit(ledger.EventType.FINDING_REVISION, self.finding.finding_id, 'passive review concluded')

    def evidence(self):
        reply = self.fixture.client.get(f'/findings/{self.finding.finding_id}/evidence', headers=self.fixture.auth)
        self.assertEqual(reply.status_code, 200)
        return reply.json()

    def report(self):
        reply = self.fixture.client.get('/report', params={'url': self.url}, headers=self.fixture.auth)
        self.assertEqual(reply.status_code, 200)
        return reply.text

    def test_durable_loss_downgrades_real_authenticated_api_and_markdown(self):
        before = self.evidence()
        self.assertTrue(before['reconstruction']['complete'])
        self.assertFalse(before['reconstruction']['completeness']['persistence_degraded'])
        self.assertIn('complete verdict', self.report())
        with patch.object(store, 'persist_ledger_event', side_effect=OSError('synthetic private error')):
            with self.assertLogs('harness.evidence_ledger', level='WARNING') as logs:
                ledger.emit(ledger.EventType.OBSERVATION, self.finding.finding_id, 'lost ordinary update')
        self.assertNotIn('synthetic private error', ' '.join(logs.output))
        after = self.evidence()
        self.assertFalse(after['reconstruction']['complete'])
        self.assertTrue(after['reconstruction']['completeness']['persistence_degraded'])
        self.assertFalse(after['reproduction_recipe']['resolvable'])
        rendered = self.report()
        self.assertIn('partial verdict', rendered)
        self.assertIn('ledger persistence failed', rendered)
        self.assertNotIn('complete verdict', rendered)
        # Inject the old silent-loss defect: removing both in-memory status
        # signals makes the same real consumers falsely advertise completion.
        ledger.reset_default_ledger()
        with patch.object(ledger, '_PERSISTENCE_FAILURES', 0):
            self.assertTrue(self.evidence()['reconstruction']['complete'])
            self.assertIn('complete verdict', self.report())
