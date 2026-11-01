"""R14 authenticated host deletion and expiry consumers; synthetic temp-only."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from harness import data_maintenance as maintenance, evidence_ledger as ledger, store
from harness.models import Finding, HttpExchange
from harness import test_pairing_contract as pairing


class LifecycleCallerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = pairing.PairingCallerTests('test_health_is_liveness_and_pairing_requires_credential')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        ledger.reset_default_ledger()
        self.addCleanup(ledger.reset_default_ledger)
        for name in ('httpx.HTTPTransport.handle_request', 'httpx.AsyncHTTPTransport.handle_async_request'):
            guard = patch(name, side_effect=AssertionError('no external HTTP'))
            guard.start()
            self.addCleanup(guard.stop)

    def seed(self, marker, host, engagement_id=''):
        finding = Finding(finding_id='synthetic-' + marker, case_id='synthetic-case-' + marker,
                          vulnerability_class='information_disclosure', severity='info', confidence=0.1,
                          summary='Ordinary capture', evidence='ordinary metadata', suggested_test='', basis='observed')
        url = f'https://{host}/ordinary'
        store.persist_findings(HttpExchange(url=url, method='GET', response_status=200), 'synthetic', [finding], engagement_id=engagement_id)
        blob = store.put_evidence_blob(b'ordinary shared synthetic capture')
        token = store._CURRENT_ENGAGEMENT.set(engagement_id)
        try:
            ledger.emit(ledger.EventType.EXECUTION, finding.finding_id, 'captured ordinary bytes',
                        data={'request_blob': blob, 'response_blob': blob}, provenance=ledger.Provenance())
        finally:
            store._CURRENT_ENGAGEMENT.reset(token)
        return finding, url, blob

    def evidence(self, finding):
        response = self.fixture.client.get(f'/findings/{finding.finding_id}/evidence', headers=self.fixture.auth)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_authenticated_host_wipe_preserves_other_hosts_shared_blob_and_default_denies(self):
        a, _, blob = self.seed('A', 'a.synthetic.invalid')
        b, _, same = self.seed('B', 'b.synthetic.invalid')
        self.assertEqual(blob, same)
        route = '/engagement/a.synthetic.invalid/evidence'
        self.assertEqual(self.fixture.client.delete(route, headers=self.fixture.auth).status_code, 403)
        self.assertTrue(store.evidence_blob_resolves(blob))
        self.fixture.server._WIPE_ENDPOINT_ENABLED = True
        self.assertEqual(self.fixture.client.delete(route).status_code, 401)
        response = self.fixture.client.delete(route, headers=self.fixture.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['wiped']['evidence_blobs'], 0)
        self.assertTrue(store.evidence_blob_resolves(blob))
        self.assertTrue(self.evidence(b)['reconstruction']['completeness']['has_request_blob'])
        self.assertEqual(store.all_host_findings('https://a.synthetic.invalid/ordinary'), [])
        self.assertEqual(len(store.all_host_findings('https://b.synthetic.invalid/ordinary')), 1)

    def test_explicit_configured_expiry_is_visible_to_authenticated_evidence_and_report(self):
        finding, url, blob = self.seed('expiry', 'expiry.synthetic.invalid')
        self.assertTrue(self.evidence(finding)['reconstruction']['completeness']['has_request_blob'])
        with contextlib.closing(store._connect()) as connection:
            connection.execute('UPDATE evidence_blobs SET created_at=1 WHERE sha256=?', (blob,))
            connection.commit()
        self.assertEqual(store.apply_retention_from_config({}, now=2000000000), 0)
        self.assertTrue(store.evidence_blob_resolves(blob))
        self.assertEqual(store.apply_retention_from_config({'store': {'evidence_retention_days': 30}}, now=2000000000), 1)
        actual = self.evidence(finding)
        self.assertFalse(actual['reconstruction']['completeness']['has_request_blob'])
        self.assertFalse(actual['reproduction_recipe']['resolvable'])
        report = self.fixture.client.get('/report', params={'url': url}, headers=self.fixture.auth)
        self.assertEqual(report.status_code, 200)
        self.assertIn('partial verdict', report.text)
        self.assertNotIn('complete verdict', report.text)

    def wipe(self, owner):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = maintenance.main(['wipe-context', '--source', str(store._DB_PATH), '--engagement-id', owner])
        return code, json.loads(output.getvalue())

    def test_same_host_context_wipe_preserves_other_context_shared_blob_and_legacy_rows(self):
        a, url, shared = self.seed('context-A', 'same.synthetic.invalid', 'context-A')
        b, _, _ = self.seed('context-B', 'same.synthetic.invalid', 'context-B')
        self.seed('legacy', 'same.synthetic.invalid')
        only_a = store.put_evidence_blob(b'ordinary A-only synthetic capture')
        token = store._CURRENT_ENGAGEMENT.set('context-A')
        try:
            ledger.emit(ledger.EventType.EXECUTION, a.finding_id, 'A-only bytes',
                        data={'response_blob': only_a}, provenance=ledger.Provenance())
        finally:
            store._CURRENT_ENGAGEMENT.reset(token)
        for owner in ('context-A', 'context-B'):
            store.save_engagement('same.synthetic.invalid', {'ordinary': owner}, engagement_id=owner)
        with contextlib.closing(store._connect()) as connection:
            for owner in ('context-A', 'context-B', ''):
                connection.execute('INSERT INTO knowledge_notes(fingerprint,note,created_at,engagement_id) VALUES(?,?,1,?)',
                                   ('synthetic-note-' + owner, 'ordinary synthetic note', owner))
                connection.execute('INSERT INTO work_items(item_id,engagement_id,created_at,updated_at) VALUES(?,?,1,1)',
                                   ('synthetic-work-' + owner, owner))
            connection.execute("INSERT INTO proof_records(proof_id,run_id,case_id,created_at) VALUES('synthetic-unowned-proof','','synthetic-case-context-A',1)")
            connection.commit()
        code, report = self.wipe('context-A')
        self.assertEqual(code, 0)
        self.assertEqual(report['deleted']['findings'], 1)
        self.assertEqual(report['deleted']['evidence_blobs'], 1)
        self.assertEqual(report['deleted']['knowledge_notes'], 1)
        self.assertEqual(report['deleted']['work_items'], 1)
        with contextlib.closing(store._connect()) as connection:
            self.assertEqual(connection.execute('SELECT engagement_id FROM knowledge_notes ORDER BY engagement_id').fetchall(),
                             [('',), ('context-B',)])
            self.assertEqual(connection.execute('SELECT engagement_id FROM work_items ORDER BY engagement_id').fetchall(),
                             [('',), ('context-B',)])
            self.assertEqual(connection.execute('SELECT count(*) FROM proof_records').fetchone()[0], 1)
        self.assertEqual(store.all_host_findings(url, engagement_id='context-A'), [])
        self.assertEqual(len(store.all_host_findings(url, engagement_id='context-B')), 1)
        self.assertEqual(len(store.all_host_findings(url)), 1)
        self.assertTrue(store.evidence_blob_resolves(shared))
        self.assertFalse(store.evidence_blob_resolves(only_a))
        self.assertIsNone(store.load_engagement('same.synthetic.invalid', engagement_id='context-A'))
        self.assertIsNotNone(store.load_engagement('same.synthetic.invalid', engagement_id='context-B'))
        response = self.fixture.client.get(f'/findings/{b.finding_id}/evidence',
                                          params={'engagement_id': 'context-B'}, headers=self.fixture.auth)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['reconstruction']['completeness']['has_response_blob'])

    def test_context_wipe_empty_owner_and_malformed_survivor_abort_without_deletion(self):
        _, url, shared = self.seed('context-A', 'same.synthetic.invalid', 'context-A')
        self.seed('context-B', 'same.synthetic.invalid', 'context-B')
        self.assertEqual(self.wipe('')[0], 1)
        code, report = self.wipe('synthetic-unknown-owner')
        self.assertEqual(code, 0)
        self.assertTrue(all(count == 0 for count in report['deleted'].values()))
        with contextlib.closing(store._connect()) as connection:
            connection.execute("UPDATE ledger_events SET data_json='[]' WHERE engagement_id='context-B'")
            connection.commit()
        self.assertEqual(self.wipe('context-A')[0], 1)
        self.assertEqual(len(store.all_host_findings(url, engagement_id='context-A')), 1)
        self.assertTrue(store.evidence_blob_resolves(shared))

    def test_surviving_orphan_ledger_row_protects_shared_blob(self):
        a, url, shared = self.seed('context-A', 'same.synthetic.invalid', 'context-A')
        store.persist_ledger_event({'event_id': 'synthetic-orphan', 'event_type': 'execution',
                                    'finding_ref': 'synthetic-missing-finding',
                                    'data': {'response_blob': shared}, 'created_at': 1})
        code, report = self.wipe('context-A')
        self.assertEqual(code, 0)
        self.assertEqual(report['deleted']['evidence_blobs'], 0)
        self.assertTrue(store.evidence_blob_resolves(shared))
        self.assertEqual(store.all_host_findings(url, engagement_id='context-A'), [])


if __name__ == '__main__':
    unittest.main()
