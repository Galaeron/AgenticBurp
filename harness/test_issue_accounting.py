"""Ticket6 accounting and SQL-oracle caller controls, synthetic evidence only."""
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
import httpx
from harness.assessment_health import confirmed_issue_accounting, stored_proof_artifacts_resolve
from harness.run_manifest import RunManifest
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.test_default_history_caller import _exchange
from harness.validators.sqlmap import SqlmapValidator


def proof(pid='p', case='c', validator='sqlmap', principal='alice', legacy=False):
    return {'proof_id': pid, 'case': {'case_id': case, 'run_id': 'run', 'principal_id': principal,
            'request_template_id': 'request-'+case, 'check_id': validator},
            'validator': validator, 'verdict': 'confirmed', 'executed': True, 'legacy': legacy,
            'baseline_artifact_id': 'b-'+pid, 'attack_artifact_id': 'a-'+pid,
            'control_artifact_ids': ['control-'+pid]}


def finding(p, route='/a'):
    return {'confirmed': True, 'proof_id': p['proof_id'], 'case_id': p['case']['case_id'],
            'url': 'https://shop.invalid'+route, 'vulnerability_class': p['validator']}


class IssueAccountingTests(unittest.TestCase):
    def account(self, findings, proofs, resolver=lambda p: True):
        return confirmed_issue_accounting(findings, 'run',
            lambda cid: [p for p in proofs if p['case']['case_id'] == cid],
            run_proofs=proofs, artifact_resolver=resolver)

    def test_repeated_csp_is_observation_group_with_all_proofs_not_vulnerabilities(self):
        proofs = [proof(str(n), str(n), 'csp_validator', legacy=True) for n in range(20)]
        result = self.account([finding(p, '/route/'+p['proof_id']) for p in proofs], proofs)
        self.assertEqual(result['counts']['proof_bound_cases'], 20)
        self.assertEqual(result['counts']['hardening_observations'], 1)
        self.assertEqual(result['counts']['vulnerabilities'], 0)
        self.assertEqual(len(result['proof_instances']), 20)
        self.assertEqual(len(result['groups'][0]['routes']), 20)

    def test_shared_root_never_merges_principal_boundaries_and_retains_retests(self):
        proofs = [proof('a','one'), proof('b','two',principal='bob'), proof('again','one')]
        findings = [dict(finding(p), root_cause_id='same-root') for p in proofs]
        result = self.account(findings*2, proofs)
        self.assertEqual(result['counts']['vulnerabilities'], 2)
        self.assertEqual(result['counts']['proof_bound_cases'], 2)
        self.assertEqual(len(result['proof_instances']), 3)

    def test_legacy_and_unresolved_proofs_remain_candidates(self):
        p=proof(legacy=True)
        self.assertEqual(self.account([finding(p)],[p])['counts']['vulnerabilities'],0)
        p['legacy']=False
        result=self.account([finding(p)],[p],lambda p: False)
        self.assertEqual(result['counts']['candidate_cases'],1)
        self.assertEqual(result['counts']['vulnerabilities'],0)

    def test_wrong_run_missing_refs_and_unreferenced_ledger_proofs_are_explained(self):
        p=proof(); other=proof('other','other'); old=proof('old','old'); old['case']['run_id']='prior'
        result=self.account([finding(p), finding(old),dict(finding(p),proof_id='absent')],[p,other,old])
        self.assertEqual(result['counts']['vulnerabilities'],1)
        self.assertEqual(result['counts']['unreferenced_confirmed_proof_instances'],1)
        self.assertEqual({r['reason'] for r in result['excluded']},
                         {'proof belongs to another run','proof not found for case'})

    def test_exact_case_artifacts_and_intact_blobs_required(self):
        p=proof()
        events=[{'case_ref':'c','event_type':'execution','data':{'artifact_id':ref,
                 'outcome':'ok','request':'req','response':'resp','request_blob':'r','response_blob':'s'}}
                for ref in ['b-p','a-p','control-p']]
        with patch('harness.store.ledger_events_for',return_value=events), \
             patch('harness.store.evidence_blob_resolves',return_value=True):
            self.assertTrue(stored_proof_artifacts_resolve(p))
            events[-1]['case_ref']='other'
            self.assertFalse(stored_proof_artifacts_resolve(p))
            events[-1]['case_ref']='c'
            with patch('harness.store.evidence_blob_resolves',return_value=False):
                self.assertFalse(stored_proof_artifacts_resolve(p))

    def test_reused_artifact_is_not_an_independent_control_and_negative_is_not_candidate(self):
        p=proof(); p['attack_artifact_id']=p['baseline_artifact_id']
        p['control_artifact_ids']=[p['baseline_artifact_id']]
        result=self.account([finding(p), {'confirmed':False,'case_id':'negative',
                                        'verification_state':'controlled_negative'}],[p])
        self.assertEqual(result['counts']['vulnerabilities'],0)
        self.assertEqual(result['counts']['candidate_cases'],1)
        self.assertFalse(stored_proof_artifacts_resolve(p))

    def test_manifest_retains_accounting_units_and_exact_refs(self):
        p=proof(legacy=True); accounting=self.account([finding(p)],[p])
        with tempfile.TemporaryDirectory() as td:
            run=RunManifest.start(run_id='run',target_identifier='fixture',config={},output_dir=td)
            run.finish('done',result={'confirmed_issues':1,'issue_accounting':accounting})
            data=json.loads(run.path.read_text())
        self.assertEqual(data['confirmed_issues'],1)
        self.assertEqual(data['confirmed_issues_unit'],'proof_bound_cases')
        self.assertEqual(data['confirmed_vulnerabilities'],0)
        self.assertEqual(data['issue_accounting']['proof_instances'][0]['proof_id'],'p')


class SqlErrorOnlyCallerTests(_CallerBase, unittest.TestCase):
    def run_probe(self, responses):
        ex=_exchange('http://shop.invalid/search?q=ordinary')
        ex.response_body='ordinary search results'
        remaining=iter(responses)
        async def request(client, method, url, **kwargs):
            status, body=next(remaining)
            return httpx.Response(status,text=body,request=httpx.Request(method,url))
        return self._validate('sqlmap',SqlmapValidator(allowed_hosts=['shop.invalid'],quick_only=True),
                              _finding('sqli'),ex,request)

    def test_identical_database_errors_cannot_confirm_injection(self):
        reports=self.run_probe([(500,'SQLITE_ERROR: incomplete input')]*2)
        self.assertEqual(reports[0].status,'inconclusive')
        self.assertFalse(reports[0].confirmed)
        self.assertIn('independent controlled evidence',reports[0].summary)

    def test_differing_database_error_pages_cannot_confirm_injection(self):
        reports=self.run_probe([(500,'SQLITE_ERROR: incomplete input'),
                                (500,'SQLITE_ERROR: incomplete input '+ 'details '*100)])
        self.assertEqual(reports[0].status,'inconclusive')
        self.assertFalse(reports[0].confirmed)

    def test_ordinary_identical_answers_stay_negative(self):
        reports=self.run_probe([(200,'ordinary answer')]*2)
        self.assertEqual(reports[0].status,'not_confirmed')
        self.assertFalse(reports[0].confirmed)

    def test_true_false_differential_still_confirms(self):
        reports=self.run_probe([(200,'matching rows '*80),(200,'no matching rows')])
        self.assertEqual(reports[0].status,'confirmed')
        self.assertTrue(reports[0].confirmed)


class IssueAccountingServerTests(unittest.TestCase):
    def test_server_and_manifest_separate_repeated_csp_from_vulnerabilities(self):
        from pathlib import Path
        from harness import store
        from harness.test_job_status_passive import DurableJobCallerTests
        fixture = DurableJobCallerTests('test_completed_job_survives_registry_loss_without_reexecution')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        proofs = [proof(str(n), str(n), 'csp_validator', legacy=True) for n in range(3)]
        async def investigate(*args, **kwargs):
            for p in proofs:
                p['case']['run_id'] = kwargs['run_context'].run_id
            return {'findings': [finding(p, '/route/'+p['proof_id']) for p in proofs]}
        fixture.server.orchestrator.investigate_engagement = investigate
        with patch.object(store, 'proofs_for_case', side_effect=lambda c: [p for p in proofs if p['case']['case_id']==c]), \
             patch.object(store, 'proofs_for_run', return_value=proofs):
            done = fixture.poll(fixture.start(), 'done')
        manifest = json.loads(Path(done['manifest_path']).read_text())
        for result in (done['result'], manifest):
            self.assertEqual(result['confirmed_issues'], 3)
            self.assertEqual(result['confirmed_issues_unit'], 'proof_bound_cases')
            self.assertEqual(result['confirmed_vulnerabilities'], 0)
            self.assertEqual(result['issue_accounting']['counts']['hardening_observations'], 1)
            self.assertEqual(len(result['issue_accounting']['proof_instances']), 3)
