"""Outer engagement export regression for migrated experiment proofs."""
from unittest.mock import patch, AsyncMock
from harness import store
from harness import test_experiment_cycle as cycle
from harness.assessment_health import confirmed_issue_accounting, stored_proof_artifacts_resolve

class ExperimentExportCallerTests(cycle.InvestigateWiringTests):
    def assert_projection(self, run_id, result, *, vulnerable):
        proofs=store.proofs_for_run(run_id)
        self.assertEqual(len(proofs),1)
        self.assertTrue(stored_proof_artifacts_resolve(proofs[0]))
        cases=result['coverage'].get('experiment_cases',[])
        self.assertEqual([c['proof_id'] for c in cases],[proofs[0]['proof_id']])
        self.assertTrue(cases[0]['executed'])
        self.assertEqual(cases[0]['status'],'confirmed' if vulnerable else 'controlled_negative')
        accounting=confirmed_issue_accounting(result['findings'],run_id,store.proofs_for_case,
            run_proofs=proofs,artifact_resolver=stored_proof_artifacts_resolve)
        self.assertEqual(accounting['counts']['vulnerabilities'],int(vulnerable))
        self.assertEqual(accounting['counts']['unreferenced_confirmed_proof_instances'],0)
        return proofs[0]

    def test_outer_nonce_proof_reaches_issue_and_case_exports(self):
        app=self._app(allow_cross=True)
        expectation=cycle._tagged_expectation()
        with patch.object(cycle,'_note_expectation',return_value=expectation):
            run_id,result=self._investigate(app)
        self.assert_projection(run_id,result,vulnerable=True)

    def test_outer_secure_controls_reach_case_export_without_issue(self):
        app=self._app()
        run_id,result=self._investigate(app)
        self.assert_projection(run_id,result,vulnerable=False)

    def test_unplugged_outer_controller_fails_export_acceptance(self):
        app=self._app(allow_cross=True)
        from harness.orchestrator import Orchestrator
        with patch.object(Orchestrator,'_run_experiments',AsyncMock(return_value=None)):
            run_id,result=self._investigate(app)
        self.assertEqual(app.requests,[])
        with self.assertRaises(AssertionError):self.assert_projection(run_id,result,vulnerable=True)

    def test_projection_read_failure_preserves_outer_result_as_degraded(self):
        from harness import experiment
        app=self._app(allow_cross=True)
        with patch.object(experiment,'project_proofs',side_effect=RuntimeError('owned read failure')):
            run_id,result=self._investigate(app)
        self.assertTrue(result['degraded'])
        self.assertTrue(any(e['phase']=='experiment_projection' for e in result['errors']))
        self.assertEqual(result['coverage']['experiment_cases'][0]['status'],'unresolved')
        self.assertFalse(any(f.get('confirmed') for f in result['findings']))

    def test_corrupt_required_artifact_excludes_confirmation_and_remains_visible(self):
        app=self._app(allow_cross=True)
        with patch('harness.assessment_health.stored_proof_artifacts_resolve',return_value=False):
            run_id,result=self._investigate(app)
        self.assertFalse(any(f.get('confirmed') for f in result['findings']))
        cases=result['coverage']['experiment_cases']
        self.assertEqual(cases[0]['status'],'inconclusive')
        self.assertFalse(cases[0]['artifacts_resolved'])

    def test_missing_referenced_attempt_is_an_explicit_unresolved_case(self):
        from harness import experiment
        from harness.engagement import EngagementState
        from harness.run_context import RunContext
        state=EngagementState('127.0.0.1')
        task=state.graph.add('experiment','declared',reason='missing proof')
        task.evidence_ref='missing-own-attempt'
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'])
        projection=experiment.project_proofs(state,ctx)
        self.assertEqual(projection['findings'],[])
        self.assertEqual(projection['cases'][0]['proof_id'],'missing-own-attempt')
        self.assertEqual(projection['cases'][0]['status'],'unresolved')
