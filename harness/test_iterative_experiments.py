"""I0 production active-probe -> existing experiment controller caller controls."""
import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import store
from harness.assessment_health import stored_proof_artifacts_resolve
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_experiment_cycle import (_CycleCase, _asm, _note_expectation,
                                           _comment_expectation, _register_sessions)
from harness.test_iterative_agent import _ScriptedOllama

VALID={'action':'experiment','kind':'cross_account_private_object','hypothesis':'bch:note-idor'}
STOP={'action':'stop','verdict':'gave_up'}


class IterativeExperimentCallerTests(_CycleCase):
    def probe(self, actions, *, comments=False, declaration=True, second=True,
              expired=False, scope=True, context=True, enabled=True, unplug=False, hook=None, max_runs=4, wrong_origin=False):
        app=self._app(allow_cross=True)
        orch=self._orch(hosts=('127.0.0.1',))
        orch.iterative_agent_enabled=True;orch.iterative_agent_max_steps=10
        eng=orch.config.setdefault('engagement',{})
        eng['experiments']={'enabled':enabled,'max_runs':max_runs}
        eng['access_expectations']=([_note_expectation(),_comment_expectation()] if comments else [_note_expectation()]) if declaration else []
        state=EngagementState('127.0.0.1');asm=_asm(comments=comments);state.apply_semantic_model(asm)
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'] if scope else ['denied.invalid'],max_requests=50,
            config=orch.config,gate_config={'active_enabled':True,'allow_mutating_replay':True, 'mutating_ceiling_by_check':{'cross_account_experiment':2}})
        class Model(_ScriptedOllama):
            async def chat_json(script, *args, **kwargs):
                if hook and script.calls==1: hook(ctx,state,orch)
                return await super().chat_json(*args,**kwargs)
            async def chat_json_metered(script,*args,**kwargs):
                from harness.ollama_client import OllamaResult
                return OllamaResult(data=await script.chat_json(*args,**kwargs),prompt_tokens=1,completion_tokens=1)
        model=Model([*actions,STOP]);orch.ollama=model
        if context: ctx.experiment_context={'state':state,'asm':asm,'base_url':app.base,'captured':[]}
        async def run():
            async with ctx:
                _register_sessions(ctx,app.base,second=second)
                if wrong_origin:ctx.sessions.get('principal:2:bob').allowed_origins=frozenset({'http://wrong.invalid'})
                if expired:ctx.sessions.get('principal:2:bob').health='expired'
                result=await orch.run_active_probe(HttpExchange(url=app.base+'/api/notes',method='POST',
                    request_headers={'Content-Type':'application/json'},request_body='{"title":"initial"}'),
                    'Select the declared experiment, then its supported dependent read','idor',
                    step_budget=10,model='scripted',run_context=ctx)
                self.assertNotEqual(result['iterative_result']['stop_reason'],'error',
                                    result['iterative_result']['handoff_note'])
                proofs=store.proofs_for_run(ctx.run_id)
                resolved=[stored_proof_artifacts_resolve(p) for p in proofs]
                return result,proofs,resolved
        if unplug:
            with patch.object(orch,'_run_experiments',AsyncMock(return_value=None)):
                result,proofs,resolved=asyncio.run(run())
        else:result,proofs,resolved=asyncio.run(run())
        return SimpleNamespace(result=result,proofs=proofs,resolved=resolved,requests=list(app.requests),
            state=state,run_id=ctx.run_id,model=model)

    def assert_completed(self,bundle,count=1):
        self.assertEqual(len(bundle.proofs),count,bundle.result)
        self.assertTrue(all(bundle.resolved))
        self.assertTrue(all(p['verdict']=='confirmed' for p in bundle.proofs))
        self.assertTrue(bundle.requests)
        self.assertFalse(bundle.result['iterative_result']['findings'],'model text is not confirmation authority')
        return bundle.result['iterative_result'].get('mechanism_results',[])

    def test_active_probe_handoff_reaches_real_proof_and_duplicate_sends_nothing(self):
        bundle=self.probe([VALID,VALID])
        records=self.assert_completed(bundle)
        self.assertEqual([r['status'] for r in records],['completed','reused'])
        self.assertEqual(sum(method=='POST' for method,path,who in bundle.requests),2)
        self.assertEqual(records[1]['budget_spent'],0)
        self.assertEqual(records[1]['referenced_attempt_ids'],[bundle.proofs[0]['proof_id']])
        self.assertEqual(records[1]['fresh_attempt_ids'],[])

    def test_setup_extraction_then_selected_dependent_experiment_uses_observed_id(self):
        dependent=dict(VALID,hypothesis='bch:comment-idor')
        bundle=self.probe([VALID,dependent],comments=True)
        records=self.assert_completed(bundle,2)
        self.assertEqual([r['status'] for r in records],['completed','completed'])
        self.assertIn('note_id',bundle.model.prompts[1])
        self.assertTrue(any('/comments' in path for method,path,who in bundle.requests))
        self.assertEqual(sum(method=='POST' for method,path,who in bundle.requests),4)

    def test_unplugged_controller_is_detected_by_real_proof_assertion(self):
        with self.assertRaises(AssertionError):self.assert_completed(self.probe([VALID],unplug=True))

    def test_invalid_policy_identity_context_and_prerequisite_controls(self):
        cases=[([dict(VALID,kind='unknown')],{}),([dict(VALID,principal='Bearer SECRET_SENTINEL')],{}),
               ([dict(VALID,url='http://outside.invalid/')],{}),([VALID],{'declaration':False}),
               ([VALID],{'second':False}),([VALID],{'expired':True}),([VALID],{'scope':False}),
               ([VALID],{'context':False}),([VALID],{'enabled':False})]
        for actions,options in cases:
            with self.subTest(options=options,kind=actions[0].get('kind')):
                bundle=self.probe(actions,**options)
                self.assertEqual(bundle.requests,[]);self.assertEqual(bundle.proofs,[])
                self.assertNotIn('SECRET_SENTINEL',json.dumps(bundle.result))
                records=bundle.result['iterative_result'].get('mechanism_results',[])
                self.assertTrue(records,'unavailability must be explicit')
                self.assertTrue(all(r['status'] not in ('completed','reused') for r in records))

    def test_refreshed_session_same_reference_invalidates_completed_selection(self):
        def refresh(ctx,state,orch):
            session=ctx.sessions.get('principal:2:bob')
            ctx.sessions.replace_headers(session.session_id,session.headers)
        bundle=self.probe([VALID,VALID],hook=refresh)
        records=self.assert_completed(bundle,2)
        self.assertEqual([r['status'] for r in records],['completed','completed'])
        self.assertEqual(sum(method=='POST' for method,path,who in bundle.requests),4)
        attempts=[p['proof_id'] for p in bundle.proofs]
        task=next(t for t in bundle.state.graph.tasks.values() if t.kind=='experiment')
        self.assertTrue(set(attempts)<=set(task.meta.get('attempt_ids',[])))

    def test_removed_declaration_cannot_reuse_previous_confirmation(self):
        def withdraw(ctx,state,orch):orch.config['engagement']['access_expectations']=[]
        bundle=self.probe([VALID,VALID],hook=withdraw)
        records=self.assert_completed(bundle)
        self.assertEqual(records[1]['status'],'needs_prerequisite')
        self.assertEqual(sum(method=='POST' for method,path,who in bundle.requests),2)

    def test_found_string_without_experiment_execution_does_not_create_proof(self):
        bundle=self.probe([{'action':'stop','verdict':'found'}])
        self.assertEqual(bundle.proofs,[]);self.assertEqual(bundle.requests,[])
        self.assertEqual(bundle.result['iterative_result'].get('mechanism_results',[]),[])

    def test_wrong_origin_identity_blocks_before_owner_setup(self):
        bundle=self.probe([VALID],wrong_origin=True)
        self.assertEqual(bundle.requests,[])
        self.assertEqual(bundle.proofs,[])
        self.assertEqual(bundle.result['iterative_result']['mechanism_results'][0]['status'],'needs_prerequisite')

    def test_engagement_attempt_bound_survives_multiple_worker_selections(self):
        bundle=self.probe([VALID,dict(VALID,hypothesis='bch:comment-idor')],comments=True,max_runs=1)
        records=self.assert_completed(bundle)
        self.assertEqual(records[1]['status'],'deferred')
        self.assertIn('max_runs',records[1]['readiness'])
        self.assertEqual(sum(m=='POST' for m,p,w in bundle.requests),2)

    def test_unrelated_policy_and_values_do_not_replant_completed_selection(self):
        def update(ctx,state,orch):
            state.observed_values['unrelated']='changed'
            orch.config['authz']={'owners':{'unrelated.invalid':[{'path':'/anything','owner':'bob'}]}}
        bundle=self.probe([VALID,VALID],hook=update)
        records=self.assert_completed(bundle)
        self.assertEqual(records[1]['status'],'reused')

    def test_failed_proof_persistence_cannot_reset_engagement_attempt_bound(self):
        with patch.object(store,'persist_proof_record',side_effect=RuntimeError('owned persistence failure')):
            bundle=self.probe([VALID,VALID],max_runs=1)
        self.assertEqual(sum(m=='POST' for m,p,w in bundle.requests),2)
        self.assertEqual(bundle.proofs,[])
        records=bundle.result['iterative_result']['mechanism_results']
        self.assertEqual([r['status'] for r in records],['inconclusive','deferred'])

    def test_selected_ready_task_does_not_consult_unrelated_blocked_planner(self):
        from harness import experiment, experiment_planner
        from harness.test_experiment_cycle import _comment_expectation
        original=experiment.run_experiment_loop
        captured=[]
        async def selected(*args,**kwargs):
            planner=SimpleNamespace(plan=AsyncMock())
            captured.append(planner)
            kwargs['planner']=planner
            return await original(*args,**kwargs)
        with patch.object(experiment,'run_experiment_loop',selected):
            bundle=self.probe([VALID],comments=True)
        self.assert_completed(bundle)
        self.assertTrue(captured)
        for planner in captured:planner.plan.assert_not_awaited()

class OuterWorkerHandoffTests(_CycleCase):
    def outer(self, *, unplug_context=False):
        from harness import business_context_agent, role_crawl, worklist_investigator
        from harness.role_crawl import RoleSession
        app=self._app(allow_cross=True)
        orch=self._orch(hosts=('127.0.0.1',))
        orch.iterative_agent_enabled=True;orch.iterative_agent_max_steps=3;orch.business_context_enabled=True
        eng=orch.config.setdefault('engagement',{})
        eng['experiments']={'enabled':True,'max_runs':2};eng['access_expectations']=[_note_expectation()]
        class Model(_ScriptedOllama):
            async def chat_json_metered(script,**kwargs):
                from harness.ollama_client import OllamaResult
                return OllamaResult(data=await script.chat_json(**kwargs),prompt_tokens=1,completion_tokens=1)
        orch.ollama=Model([VALID,STOP])
        roles=[RoleSession('anonymous',{}),RoleSession('user',{'Authorization':'Bearer tok-alice'},name='alice'),RoleSession('user',{'Authorization':'Bearer tok-bob'},name='bob')]
        captured=[]
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'],max_requests=100,config=orch.config,
            gate_config={'active_enabled':True,'allow_mutating_replay':True})
        async def invoke_worker(probe_fn,*args,**kwargs):
            if unplug_context:ctx.experiment_context=None
            captured.append(await probe_fn(HttpExchange(url=app.base+'/api/notes',method='POST',request_body='{"title":"initial"}'),
                'Select declared experiment','idor',3))
            return []
        async def run():
            async with ctx:
                with patch.object(role_crawl,'crawl_roles',AsyncMock(return_value=role_crawl.RoleCrawlResult(base_url=app.base))), \
                     patch.object(business_context_agent.BusinessContextAgent,'build_model',return_value=_asm()), \
                     patch.object(worklist_investigator,'investigate_worklist',invoke_worker):
                    result=await orch.investigate_engagement(app.base,roles,max_nodes=0,max_chain_rounds=0,active_discovery=False,run_context=ctx)
                return result,store.proofs_for_run(ctx.run_id)
        result,proofs=asyncio.run(run())
        return captured,result,proofs,app.requests

    def test_outer_engagement_installs_context_for_real_worker_completed_reuse(self):
        calls,result,proofs,requests=self.outer()
        records=calls[0]['iterative_result']['mechanism_results']
        self.assertEqual(records[0]['status'],'reused')
        self.assertEqual(records[0]['referenced_attempt_ids'],[proofs[0]['proof_id']])
        self.assertEqual(records[0]['budget_spent'],0)
        self.assertEqual(sum(m=='POST' for m,p,w in requests),2)
        self.assertEqual(result['coverage']['experiment_cases'][0]['proof_id'],proofs[0]['proof_id'])

    def test_unplugging_outer_context_is_detected_by_same_reuse_expectation(self):
        calls,result,proofs,requests=self.outer(unplug_context=True)
        records=calls[0]['iterative_result']['mechanism_results']
        self.assertEqual(records[0]['status'],'needs_prerequisite')
        with self.assertRaises(AssertionError):self.assertEqual(records[0]['status'],'reused')
