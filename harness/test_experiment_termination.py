"""Finite caller controls for the migrated experiment queue and final dispositions."""
from harness import experiment,store
from harness.test_experiment_cycle import _CycleCase,_asm,_note_expectation,_comment_expectation

class BoundedExperimentTerminationTests(_CycleCase):
    def run_queue(self, *, expectations=None, max_runs=4, cancel=False, comments=True, other_class=False, high_blocked=False):
        app=self._app()
        observed={}
        def prepare(state,asm,ctx):
            observed['ctx']=ctx
            if cancel:ctx.cancel.cancel()
        asm=_asm(comments=comments,other_class=other_class)
        if high_blocked:
            next(h for h in asm.chaining_hypotheses if h.id=='bch:comment-idor').rank=1.0
        bundle=self._cycle(app,expectations=expectations if expectations is not None else [_note_expectation(),_comment_expectation()],
            asm=asm,max_runs=max_runs,prepare=prepare)
        ctx=observed['ctx']
        projection=experiment.task_dispositions(bundle.state,ctx,enabled=True,max_runs=max_runs)
        return bundle,ctx,projection

    def test_blocked_high_rank_task_does_not_starve_ready_procedure(self):
        # Missing Comment declaration ranks above Note; it must not starve ready Note.
        bundle,ctx,projection=self.run_queue(expectations=[_note_expectation()],high_blocked=True)
        self.assertEqual(bundle.result['runs'],1)
        states={t['hypothesis_id']:t for t in projection['tasks']}
        self.assertEqual(states['bch:note-idor']['status'],'completed')
        self.assertEqual(states['bch:comment-idor']['status'],'missing_prerequisite')
        self.assertIn('no declared access expectation',states['bch:comment-idor']['reason'])
        self.assertEqual(len(bundle.app.requests),5)
        self.assertEqual(projection['attempts_reserved'],1)

    def test_observed_setup_values_release_dependent_work_with_same_finite_bound(self):
        bundle,ctx,projection=self.run_queue()
        self.assertEqual(bundle.result['runs'],2)
        self.assertEqual(projection['attempts_reserved'],2)
        self.assertTrue(all(t['status']=='completed' for t in projection['tasks']))
        self.assertTrue(any('/comments' in path for method,path,who in bundle.app.requests))
        self.assertEqual(len(store.proofs_for_run(bundle.run_id)),2)
        self.assertIn('note_id',bundle.state.observed_values)

    def test_named_max_runs_defers_unlocked_task_without_extending_budget(self):
        bundle,ctx,projection=self.run_queue(max_runs=1)
        self.assertEqual(bundle.result['runs'],1)
        self.assertIn('max_runs',bundle.result['stopped_by'])
        deferred=[t for t in projection['tasks'] if t['status']=='deferred']
        self.assertEqual(len(deferred),1)
        self.assertIn('max_runs',deferred[0]['reason'])
        self.assertEqual(ctx.budget.used,5)
        self.assertFalse(any('/comments' in path for method,path,who in bundle.app.requests))

    def test_cancellation_stops_before_attempt_and_names_remaining_work(self):
        bundle,ctx,projection=self.run_queue(cancel=True)
        self.assertEqual(bundle.app.requests,[])
        self.assertEqual(store.proofs_for_run(bundle.run_id),[])
        self.assertEqual(projection['attempts_reserved'],0)
        self.assertIn('cancelled',bundle.result['stopped_by'])
        self.assertTrue(any(t['status']=='deferred' and 'cancelled' in t['reason'] for t in projection['tasks']))

    def test_preflight_discloses_advisory_and_disabled_planner_without_execution_authority(self):
        bundle,ctx,projection=self.run_queue(comments=False,other_class=True)
        self.assertFalse(projection['planner_enabled'])
        self.assertEqual(set(projection['supported_mechanisms']),set(experiment.SUPPORTED_KINDS))
        self.assertTrue(projection['advisory_tasks'])
        self.assertTrue(all(t['status']=='advisory' for t in projection['advisory_tasks']))
        self.assertTrue(all(t['cost']['minimum_requests'] > 0 for t in projection['tasks']))
        disabled=experiment.task_dispositions(bundle.state,ctx,enabled=False,max_runs=4)
        self.assertFalse(disabled['enabled'])
        self.assertTrue(all(t['status']=='disabled' for t in disabled['tasks']))

    def test_actual_outer_attempt_failure_is_inconclusive_not_unselected_advisory(self):
        from unittest.mock import patch
        from harness.test_experiment_cycle import InvestigateWiringTests
        app=self._app(allow_cross=True)
        with patch.object(store,'persist_proof_record',side_effect=RuntimeError('SECRET_SENTINEL')):
            run_id,result=InvestigateWiringTests._investigate(self,app)
        self.assertTrue(any(method=='POST' for method,path,who in app.requests))
        self.assertEqual(store.proofs_for_run(run_id),[])
        status=result['experiment_preflight']
        self.assertEqual(status['attempts_reserved'],1)
        self.assertEqual(status['tasks'][0]['status'],'inconclusive')
        self.assertIn('RuntimeError',status['tasks'][0]['reason'])
        self.assertNotIn('SECRET_SENTINEL',str(status))
        self.assertTrue(result['degraded'])
        self.assertTrue(any(e['phase']=='experiments' for e in result['errors']))
