"""R23 actual SQLite persistence/export callers with synthetic passive findings."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harness import report_generator, store
from harness.models import Finding, HttpExchange


class PassiveIssueCallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = patch.object(store, '_DB_PATH', Path(self.tmp.name) / 'synthetic.db')
        db.start()
        self.addCleanup(db.stop)
        for target in ('httpx.HTTPTransport.handle_request', 'httpx.AsyncHTTPTransport.handle_async_request',
                       'harness.run_context.TargetTransport.execute'):
            guard = patch(target, side_effect=AssertionError('no target or provider I/O'))
            guard.start()
            self.addCleanup(guard.stop)

    def persist(self, run, *, parameter='q', credential='synthetic-A', engagement='eng-A',
                finding_id=None, principal='user-A', case=True, confidence=.7):
        exchange = HttpExchange(url='https://captured.example/ordinary', method='GET',
                                request_headers={'Authorization': 'Bearer ' + credential},
                                response_status=200, response_body='Ordinary metadata',
                                capture_id='capture-' + run)
        finding = Finding(vulnerability_class='information_disclosure', confidence=confidence,
                          severity='info', summary='Ordinary observation ' + run,
                          evidence='Ordinary evidence ' + run, suggested_test='Review capture',
                          basis='derived', finding_id=finding_id or 'finding-' + run,
                          case_id=case if isinstance(case, str) else 'case-' + run if case else '', parameter_location='query',
                          parameter_name=parameter, principal_id=principal)
        with patch('harness.telemetry.current_run_id', return_value=run):
            store.persist_findings(exchange, 'synthetic-passive', [finding], engagement_id=engagement)

    def exports(self, engagement='eng-A', **kwargs):
        return report_generator.export_issues_for_host('https://captured.example',
                                                       engagement_id=engagement, **kwargs)

    def test_two_passive_runs_link_and_keep_both_case_evidence_records(self):
        self.persist('run-1')
        first = self.exports()[0]['issue_id']
        self.persist('run-2')
        exported = self.exports()
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]['issue_id'], first)
        self.assertEqual(len(exported[0]['member_evidence']), 2)
        self.assertEqual({row['case_id'] for row in exported[0]['member_evidence']},
                         {'case-run-1', 'case-run-2'})

    def test_passive_parameter_coordinates_survive_storage_and_export(self):
        self.persist('run-1', parameter='q')
        self.persist('run-2', parameter='other')
        rows = store.all_host_findings('https://captured.example', engagement_id='eng-A')
        self.assertEqual({row['parameter_name'] for row in rows}, {'q', 'other'})
        self.assertEqual({row['affected_input'] for row in self.exports()}, {'query:q', 'query:other'})

    def test_distinct_captured_principals_never_collapse_in_structured_export(self):
        self.persist('run-1', credential='synthetic-A', finding_id='same-origin-coordinate')
        self.persist('run-2', credential='synthetic-B', finding_id='same-origin-coordinate')
        rows = store.all_host_findings('https://captured.example', engagement_id='eng-A')
        self.assertEqual(len({row['captured_principal_id'] for row in rows}), 2)
        self.assertEqual(len(self.exports()), 2)

    def test_distinct_engagements_have_distinct_stable_issue_identity(self):
        self.persist('run-1', engagement='eng-A', finding_id='same-origin-coordinate')
        self.persist('run-2', engagement='eng-B', finding_id='same-origin-coordinate')
        self.assertNotEqual(self.exports('eng-A')[0]['issue_id'], self.exports('eng-B')[0]['issue_id'])

    def test_distinct_explicit_principals_survive_same_capture_identity(self):
        self.persist('run-1', principal='user-A')
        self.persist('run-2', principal='user-B')
        rows = store.all_host_findings('https://captured.example', engagement_id='eng-A')
        self.assertEqual({row['principal_id'] for row in rows}, {'user-A', 'user-B'})
        self.assertEqual(len({row['fingerprint'] for row in rows}), 2)
        self.assertEqual(len(self.exports()), 2)

    def test_no_proof_passive_repeat_retains_run_observation_history(self):
        self.persist('run-1', case=False)
        self.persist('run-2', case=False)
        exported = self.exports()
        self.assertEqual(len(exported), 1)
        self.assertEqual(len(exported[0]['member_evidence']), 1)
        observations = exported[0]['member_evidence'][0]['observations']
        self.assertEqual({row['run_id'] for row in observations}, {'run-1', 'run-2'})
        self.assertEqual({row['exchange_id'] for row in observations}, {'capture-run-1', 'capture-run-2'})
        self.assertFalse(exported[0]['confirmed'])
        self.assertEqual(exported[0]['proof_references'], [])
        with patch.object(store, 'finding_observation_history', return_value={}):
            missing = self.exports()[0]['member_evidence'][0]['observations']
        self.assertEqual(missing, [])
        self.assertEqual(len(self.exports()[0]['member_evidence'][0]['observations']), 2)

    def test_unverified_reporting_filter_never_erases_passive_observation_history(self):
        self.persist('run-1', case=False, confidence=.3)
        self.persist('run-2', case=False, confidence=.3)
        original = self.exports()
        self.assertEqual(self.exports(config={'reporting': {'gate_low_confidence_generic': True}}), [])
        self.assertEqual(self.exports(), original)
        self.assertEqual(len(original[0]['member_evidence'][0]['observations']), 2)

    def test_suppressed_export_does_not_erase_repeated_observations(self):
        self.persist('run-1', case=False)
        self.persist('run-2', case=False)
        first = self.exports()[0]
        fp = store.all_host_findings('https://captured.example', engagement_id='eng-A')[0]['fingerprint']
        store.suppress_finding(fp, 'synthetic review decision')
        self.assertEqual(self.exports(), [])
        self.assertEqual(len(store.all_host_findings('https://captured.example',
                         include_suppressed=True, engagement_id='eng-A')), 1)
        store.unsuppress_finding(fp)
        self.assertEqual(self.exports()[0], first)

    def test_markdown_keeps_explicit_principal_boundaries_like_structured_export(self):
        self.persist('run-1', principal='user-A')
        self.persist('run-2', principal='user-B')
        exported = self.exports()
        markdown = report_generator.generate_report_for_host('https://captured.example', engagement_id='eng-A')
        for issue in exported:
            self.assertIn(issue['issue_id'], markdown)
        self.assertEqual(len(exported), 2)

    def test_negative_control_dropping_ownership_collapses_actual_export(self):
        from harness import issues
        self.persist('run-1', credential='synthetic-A')
        self.persist('run-2', credential='synthetic-B')
        original = issues.issue_key
        def broken_key(finding):
            return original({**finding, 'engagement_id': ''})
        with patch.object(issues, 'issue_key', side_effect=broken_key):
            self.assertEqual(len(self.exports()), 1)
        self.assertEqual(len(self.exports()), 2)

    def test_scoped_export_retains_nested_run_proof_attempts(self):
        from harness import evidence
        case = evidence.TestCaseRef.make(run_id='run-1', request_template_id='synthetic-template',
            check_id='synthetic-check', principal_id='user-A', parameter_location='query', parameter_name='q')
        proof = evidence.ProofRecord.from_validation_result(case=case, validator='synthetic-inert',
            status='error', confirmed=False, observed_result='synthetic unavailable evidence')
        self.assertTrue(store.persist_proof_record(proof)[0])
        self.persist('run-1', case=case.case_id)
        exported = self.exports()[0]
        self.assertEqual({row['proof_id'] for row in exported['proof_references']}, {proof.proof_id})
        self.assertEqual(exported['proof_references'][0]['verdict'], 'error')
        self.assertFalse(exported['confirmed'])
        self.assertFalse(exported['oracle_verified'])

    def test_two_scoped_proof_cases_keep_both_attempts_under_one_issue(self):
        from harness import evidence
        proofs = []
        cases = []
        for run in ('run-1', 'run-2'):
            case = evidence.TestCaseRef.make(run_id=run, request_template_id='synthetic-template',
                check_id='synthetic-check', principal_id='user-A', parameter_location='query', parameter_name='q')
            proof = evidence.ProofRecord.from_validation_result(case=case, validator='synthetic-inert',
                status='error', confirmed=False, observed_result='synthetic unavailable evidence ' + run)
            self.assertTrue(store.persist_proof_record(proof)[0])
            self.persist(run, case=case.case_id)
            proofs.append(proof.proof_id)
            cases.append(case.case_id)
        rows = store.all_host_findings('https://captured.example', engagement_id='eng-A')
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row['fingerprint'] for row in rows}), 1)
        self.assertEqual({row['case_id'] for row in rows}, set(cases))
        exported = self.exports()
        self.assertEqual(len(exported), 1)
        self.assertEqual({row['proof_id'] for row in exported[0]['proof_references']}, set(proofs))
        self.assertEqual({row['case_id'] for row in exported[0]['proof_references']}, set(cases))
        self.assertEqual(len(exported[0]['member_evidence']), 2)
        self.assertFalse(exported[0]['confirmed'])
        self.assertFalse(exported[0]['oracle_verified'])
