"""Real Chromium controller tests for explicit browser bindings."""
import asyncio
from unittest.mock import patch
from harness import experiment, store, evidence_ledger
from harness.application_semantic_model import ApplicationSemanticModel, ChainingHypothesis
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_experiment_cycle import _CycleCase
from harness.testing_fixtures.browser_experiment_app import App
from harness.assessment_health import stored_proof_artifacts_resolve
from harness.workflow_engine import Workflow, WorkflowStep, workflow_from_dict, ENGINE_VERSION

class BrowserExperimentCallerTests(_CycleCase):
    def assert_positive_browser(self,proofs,resolved):
        self.assertEqual(proofs[0]['verdict'],'confirmed')
        self.assertEqual(resolved,[True])

    def scenario(self, kind, *, secure=False, modify=None, budget=30, unplug=False, mode="", iterative=False, iterative_hook=None):
        app=App(secure,mode);self.addCleanup(app.close)
        if mode == "crossorigin":
            app.peer=App();app.peer_url=app.peer.base;self.addCleanup(app.peer.close)
        orch=self._orch(hosts=('127.0.0.1',))
        binding={'mechanism':kind,'hypothesis_id':'browser:input','session_ref':'browser:user'}
        if kind==experiment.BROWSER_HASH:
            binding.update(route=app.base+'/dom#/search?q=initial',location='fragment_query',parameter='q')
        else:binding.update(write_capture=0,pointer='/text',consumer_url=app.base+'/messages/board')
        eng=orch.config.setdefault('engagement',{});eng.update(experiments={'enabled':True,'max_runs':2},browser_bindings=[binding])
        state=EngagementState('127.0.0.1')
        asm=ApplicationSemanticModel(chaining_hypotheses=[ChainingHypothesis(id='browser:input',source='declared input',target='browser',rationale='observed input',rank=.8,classes=['dom_xss' if kind==experiment.BROWSER_HASH else 'stored_xss'])])
        state.apply_semantic_model(asm)
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'],max_requests=budget,config=orch.config,
            gate_config={'active_enabled':True,'allow_mutating_replay':True,'mutating_ceiling_by_check':{'browser_stored_experiment':3}})
        captured=[HttpExchange(url=app.base+'/api/messages',method='POST',request_headers={'Content-Type':'application/json'},request_body='{"text":"initial"}')]
        ctx.experiment_context={'state':state,'asm':asm,'base_url':app.base,'captured':captured}
        async def run():
            async with ctx:
                ctx.sessions.register('browser:user','alice',{},allowed_origins=[app.base])
                if modify:modify(ctx.config['engagement']['browser_bindings'][0],ctx,captured)
                if iterative:
                    from harness.test_iterative_experiments import STOP
                    from harness.test_iterative_agent import _ScriptedOllama
                    class Model(_ScriptedOllama):
                        async def chat_json_metered(script,**kwargs):
                            if iterative_hook and script.calls == 1:iterative_hook(ctx,orch)
                            from harness.ollama_client import OllamaResult
                            return OllamaResult(data=await script.chat_json(**kwargs),prompt_tokens=1,completion_tokens=1)
                    orch.iterative_agent_enabled=True
                    orch.ollama=Model([{'action':'experiment','kind':kind,'hypothesis':'browser:input'}]*2+[STOP])
                    result=await orch.run_active_probe(captured[0],'select declared browser check','xss',step_budget=4,model='scripted',run_context=ctx)
                else:
                    result=await orch._run_experiments(state,asm,ctx,base_url=app.base,captured=captured)
                proofs=store.proofs_for_run(ctx.run_id)
                resolved=[stored_proof_artifacts_resolve(p) for p in proofs]
                return result,proofs,resolved
        result,proofs,resolved=asyncio.run(run())
        return app,result,proofs,resolved,state

    def test_hash_route_computed_execution_and_secure_text_sink(self):
        for secure in (False,True):
            with self.subTest(secure=secure):
                app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,secure=secure)
                self.assertEqual(result['runs'],1,result)
                if not secure:self.assert_positive_browser(proofs,resolved)
                self.assertEqual(proofs[0]['verdict'],'controlled_negative' if secure else 'confirmed',result)
                self.assertEqual(resolved,[True])
                self.assertTrue(app.requests)

    def test_json_write_explicit_consumer_and_encoded_secure_sink(self):
        for secure in (False,True):
            with self.subTest(secure=secure):
                app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,secure=secure)
                self.assertEqual(proofs[0]['verdict'],'controlled_negative' if secure else 'confirmed',result)
                self.assertEqual(resolved,[True])
                self.assertEqual(sum(m=='POST' for m,p in app.requests),3)
                self.assertIn('&lt;img',app.message)
                self.assertIn('final stored state is escaped control',proofs[0]['limitation'])
                self.assertEqual(result['completed'][0]['cleanup'],'none declared; final stored state is escaped control')

    def test_missing_binding_identity_pointer_scope_and_policy_send_nothing(self):
        controls=[lambda b,c,x:b.pop('consumer_url'),lambda b,c,x:b.update(pointer='/missing'),
                  lambda b,c,x:b.update(consumer_url='http://outside.invalid/render'),
                  lambda b,c,x:setattr(c.sessions.get('browser:user'),'health','expired'),
                  lambda b,c,x:c.gate.config.mutating_ceiling_by_check.update(browser_stored_experiment=1)]
        for control in controls:
            with self.subTest(control=control):
                app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,modify=control)
                self.assertEqual(app.requests,[]);self.assertEqual(proofs,[])
                self.assertTrue(result['blocked'],result)

    def test_budget_exhaustion_is_inconclusive_and_cannot_confirm(self):
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,budget=1)
        self.assertEqual(proofs,[])
        self.assertEqual(result['completed'],[])
        self.assertEqual(app.requests,[])
        self.assertIn('insufficient request budget',str(result['blocked']))

    def test_insufficient_same_case_mutating_allowance_blocks_before_any_plant(self):
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,
            modify=lambda b,c,x:setattr(c.gate,'mutating_headroom',lambda *a:(2,1,3)))
        self.assertEqual(proofs,[])
        self.assertEqual(result['completed'],[])
        self.assertEqual(app.requests,[])
        self.assertIn('insufficient same-case mutating allowance',str(result['blocked']))

    def test_v1_http_compatibility_and_browser_rejection(self):
        self.assertEqual(ENGINE_VERSION,1)
        data={'id':'legacy','steps':[{'id':'read','url_template':'http://t.test/','session_ref':'s'}]}
        wf=workflow_from_dict(data)
        self.assertEqual(wf.version,1);self.assertEqual(wf.steps[0].action,'http')
        with self.assertRaises(ValueError):Workflow('invalid',(WorkflowStep('b','GET','http://t.test/','s',action='browser_visit'),))
        data['version']=2;data['steps'][0]['action']='browser_visit'
        self.assertEqual(workflow_from_dict(data).steps[0].action,'browser_visit')

    def test_console_execution_channel_and_unmatched_control_signal(self):
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,mode='console')
        self.assertEqual(proofs[0]['verdict'],'confirmed',result)
        self.assertEqual(resolved,[True])
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,mode='contaminated')
        self.assertEqual(proofs[0]['verdict'],'inconclusive')

    def test_blocked_resources_and_changed_consumer_navigation_are_inconclusive(self):
        for mode in ('blocked','redirect'):
            with self.subTest(mode=mode):
                app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,mode=mode)
                self.assertEqual(proofs[0]['verdict'],'inconclusive',result)
                self.assertEqual(resolved,[False])

    def test_only_exact_declared_json_pointer_changes(self):
        import json
        original={'text':'initial','sentinel':'__AGENTIC_BROWSER_INPUT__','literal':'{{browser_attack}}','private':'SECRET_SENTINEL'}
        def capture(b,c,x):x[0].request_body=json.dumps(original)
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,modify=capture)
        self.assertEqual(proofs[0]['verdict'],'confirmed',result)
        self.assertEqual(len(app.writes),3)
        for body in app.writes:
            self.assertEqual(body['sentinel'],original['sentinel'])
            self.assertEqual(body['literal'],original['literal'])
            self.assertEqual(body['private'],'SECRET_SENTINEL')
        self.assertNotIn('SECRET_SENTINEL',json.dumps(state.graph.to_dict()))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(result))

    def test_noncanonical_array_pointer_is_rejected_before_any_plant(self):
        for pointer in ('/items/-1','/items/01'):
            def capture(b,c,x):
                x[0].request_body='{"items":["one","two"]}'
                b['pointer']=pointer
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,modify=capture)
            self.assertEqual(app.requests,[])
            self.assertEqual(proofs,[])

    def test_browser_evidence_persistence_failure_retains_incomplete_attempt(self):
        with patch.object(store,'put_evidence_blob',side_effect=RuntimeError('owned blob failure')):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH)
        self.assertTrue(app.requests)
        self.assertEqual(proofs[0]['verdict'],'inconclusive')
        self.assertTrue(proofs[0]['executed'])
        self.assertEqual(resolved,[False])

    def test_iterative_selection_executes_browser_then_reuses_resolved_attempt(self):
        for kind in experiment.BROWSER_KINDS:
            app,result,proofs,resolved,state=self.scenario(kind,iterative=True)
            self.assertEqual(len(proofs),1,result)
            self.assertEqual(proofs[0]['verdict'],'confirmed',result)
            self.assertEqual(resolved,[True])
            self.assertEqual([r['status'] for r in result['iterative_result']['mechanism_results']],['completed','reused'])

    def test_service_worker_and_websocket_cannot_bypass_interception(self):
        for mode,forbidden in [('serviceworker','/worker.js'),('websocket','/socket')]:
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,mode=mode)
            self.assertNotIn(('GET',forbidden),app.requests)
            self.assertEqual(proofs[0]['verdict'],'inconclusive',result)

    def test_registered_cookie_identity_never_leaks_to_other_allowed_port(self):
        def credentials(b,c,x):c.sessions.get('browser:user').headers={'Cookie':'session=OWNED_COOKIE_SECRET'}
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,mode='crossorigin',modify=credentials)
        self.assertEqual(app.peer.requests,[])
        self.assertTrue(any('OWNED_COOKIE_SECRET' in cookie for cookie in app.cookies))
        self.assertEqual(proofs[0]['verdict'],'inconclusive')

    def outer(self, kind, *, secure=False, unplug=False):
        from harness import business_context_agent, role_crawl
        from harness.role_crawl import RoleSession
        from unittest.mock import AsyncMock
        app=App(secure);self.addCleanup(app.close)
        orch=self._orch(hosts=('127.0.0.1',));orch.business_context_enabled=True
        orch.capture_review_limit=0
        orch.validator_registry.validators={}  # this fixture isolates declared experiment dispatch, not legacy families
        binding={'mechanism':kind,'hypothesis_id':'browser:input','session_ref':'principal:1:alice'}
        if kind==experiment.BROWSER_HASH:binding.update(route=app.base+'/dom#/search?q=initial',location='fragment_query',parameter='q')
        else:binding.update(write_capture=0,pointer='/text',consumer_url=app.base+'/messages/board')
        orch.config['engagement'].update(experiments={'enabled':True,'max_runs':1},browser_bindings=[binding])
        asm=ApplicationSemanticModel(chaining_hypotheses=[ChainingHypothesis(id='browser:input',source='explicit input',target='browser',rationale='observed input',rank=.8,classes=['dom_xss' if kind==experiment.BROWSER_HASH else 'stored_xss'])])
        roles=[RoleSession('anonymous',{}),RoleSession('user',{'Authorization':'Bearer owned-alice'},name='alice')]
        capture=HttpExchange(url=app.base+'/api/messages',method='POST',request_headers={'Content-Type':'application/json'},request_body='{"text":"initial"}')
        ctx=RunContext.create(allowed_hosts=['127.0.0.1'],max_requests=100,config=orch.config,
            gate_config={'active_enabled':True,'allow_mutating_replay':True,'mutating_ceiling_by_check':{'browser_stored_experiment':3}})
        async def run():
            async with ctx:
                with patch.object(role_crawl,'crawl_roles',AsyncMock(return_value=role_crawl.RoleCrawlResult(base_url=app.base))), \
                     patch.object(business_context_agent.BusinessContextAgent,'build_model',return_value=asm):
                    result=await orch.investigate_engagement(app.base,roles,max_nodes=0,max_chain_rounds=0,
                        active_discovery=False,seed_exchanges=[capture],run_context=ctx)
                return result,[p for p in store.proofs_for_run(ctx.run_id) if p['validator'] in experiment.BROWSER_KINDS]
        if unplug:
            with patch.object(orch,'_run_experiments',AsyncMock(return_value=None)):result,proofs=asyncio.run(run())
        else:result,proofs=asyncio.run(run())
        return app,result,proofs

    def assert_outer_browser_export(self,result,proofs,secure):
        from harness.assessment_health import confirmed_issue_accounting
        self.assertEqual(len(proofs),1,result.get('errors'))
        proof=proofs[0]
        self.assertTrue(stored_proof_artifacts_resolve(proof))
        self.assertEqual(proof['verdict'],'controlled_negative' if secure else 'confirmed')
        self.assertEqual([c['proof_id'] for c in result['coverage']['experiment_cases']],[proof['proof_id']])
        accounting=confirmed_issue_accounting(result['findings'],proof['case']['run_id'],store.proofs_for_case,
            run_proofs=proofs,artifact_resolver=stored_proof_artifacts_resolve)
        self.assertEqual(accounting['counts']['vulnerabilities'],int(not secure))
        self.assertEqual(result['experiment_preflight']['attempts_reserved'],1)
        self.assertTrue(all(t['status'] not in ('running','ready') for t in result['experiment_preflight']['tasks']))

    def test_actual_outer_browser_proofs_reach_case_issue_and_disposition_exports(self):
        for kind in experiment.BROWSER_KINDS:
            for secure in (False,True):
                with self.subTest(kind=kind,secure=secure):
                    app,result,proofs=self.outer(kind,secure=secure)
                    self.assert_outer_browser_export(result,proofs,secure)

    def test_unplugged_outer_browser_controller_fails_same_acceptance(self):
        app,result,proofs=self.outer(experiment.BROWSER_HASH,unplug=True)
        self.assertFalse(any(m=='POST' for m,p in app.requests))
        with self.assertRaises(AssertionError):self.assert_outer_browser_export(result,proofs,False)

    def test_successful_writes_and_consumer_propagation_are_required(self):
        for mode in ('write404','write500','write302','swallowed','wrongconsumer','swallow_attack','swallow_control','stale_baseline'):
            with self.subTest(mode=mode):
                app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,mode=mode)
                self.assertEqual(proofs[0]['verdict'],'inconclusive',result)
                self.assertEqual(result['completed'],[])
                if mode.startswith('write'):
                    self.assertEqual(len(app.writes),1)
                    self.assertNotIn('final stored state is escaped control',proofs[0]['limitation'])

    def test_durable_ledger_failure_cannot_create_a_completed_browser_proof(self):
        before = evidence_ledger.evidence_write_status()
        # Failure status is intentionally sticky in production. Scope the
        # injected outage to this test without changing that fail-closed rule.
        with patch.object(evidence_ledger, '_PERSISTENCE_FAILURES', 0), \
             patch.object(evidence_ledger, '_DEFAULT_LEDGER', evidence_ledger.EvidenceLedger()), \
             patch.object(store,'persist_ledger_event',side_effect=RuntimeError('owned ledger failure')):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH)
            self.assertTrue(evidence_ledger.evidence_write_status()['persistence_degraded'])
        self.assertEqual(evidence_ledger.evidence_write_status(), before)
        self.assertTrue(app.requests)
        self.assertEqual(proofs[0]['verdict'],'inconclusive')
        self.assertEqual(result['completed'],[])
        self.assertEqual(resolved,[False])
        self.assertIn('durable browser evidence',proofs[0]['observed_result'])

    def test_dict_capture_and_private_query_replay_are_safe_public_exports(self):
        import json
        def capture(b,c,x):
            x[0].url += '?access_token=SECRET_SENTINEL'
            b['consumer_url'] += '?access_token=SECRET_SENTINEL'
            x[0]=x[0].model_dump()
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,modify=capture)
        self.assertEqual(proofs[0]['verdict'],'confirmed',result)
        self.assertEqual(resolved,[True])
        self.assertTrue(any('access_token=SECRET_SENTINEL' in target for target in app.targets))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(state.graph.to_dict()))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(result))
        for proof in proofs:self.assertNotIn('SECRET_SENTINEL',json.dumps(proof))

    def test_hash_non_target_uri_literals_are_not_bound_as_engine_variables(self):
        import json
        from harness.browser_driver import PlaywrightDriver
        visits=[]
        visit=PlaywrightDriver.visit
        async def observed(driver,url,**kwargs):
            visits.append(url)
            return await visit(driver,url,**kwargs)
        def binding(b,c,x):b['route']=b['route'].replace('#','?keep={{browser_attack}}#')+'&other={{browser_attack}}&access_token=SECRET_SENTINEL'
        with patch.object(PlaywrightDriver,'visit',observed):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,modify=binding)
        self.assertEqual(proofs[0]['verdict'],'confirmed',result)
        self.assertTrue(all('keep={{browser_attack}}' in url and 'other={{browser_attack}}' in url for url in visits))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(state.graph.to_dict()))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(result))

    def test_unknown_binding_fields_do_not_leak_or_execute(self):
        def extra(b,c,x):b['private']='SECRET_SENTINEL'
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,modify=extra)
        self.assertEqual(app.requests,[])
        self.assertEqual(proofs,[])
        import json
        self.assertNotIn('SECRET_SENTINEL',json.dumps(state.graph.to_dict()))

    def test_browser_unavailable_is_an_explicit_incomplete_attempt_without_sends(self):
        from harness.browser_driver import PlaywrightDriver,ExecutionObservation
        from unittest.mock import AsyncMock
        with patch.object(PlaywrightDriver,'visit',AsyncMock(return_value=ExecutionObservation(url='unavailable',load_error='browser unavailable'))):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH)
        self.assertEqual(app.requests,[])
        self.assertEqual(proofs[0]['verdict'],'inconclusive')
        self.assertFalse(proofs[0]['executed'])
        self.assertEqual(result['completed'],[])
        self.assertTrue(result['failed'])

    def test_answered_baseline_write_is_retained_when_browser_is_unavailable(self):
        from harness.browser_driver import PlaywrightDriver, ExecutionObservation
        from unittest.mock import AsyncMock
        observation = ExecutionObservation(url='unavailable', load_error='browser unavailable')
        with patch.object(PlaywrightDriver, 'visit', AsyncMock(return_value=observation)):
            app, result, proofs, resolved, state = self.scenario(experiment.BROWSER_STORED)
        self.assertEqual(len(app.writes), 1)
        self.assertEqual(observation.requests_sent, 0)
        self.assertEqual(proofs[0]['verdict'], 'inconclusive')
        self.assertTrue(proofs[0]['executed'])
        self.assertEqual(result['completed'], [])
        self.assertTrue(result['failed'])

    def test_canonical_array_pointer_is_supported_and_keeps_other_elements(self):
        def capture(b,c,x):
            x[0].request_body='{"text":"initial","items":["one","two"]}'
            b['pointer']='/items/1'
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,modify=capture)
        self.assertEqual(len(app.writes),3)
        self.assertTrue(all(w['items'][0]=='one' and w['text']=='initial' for w in app.writes))
        # This declared consumer renders /text, not /items/1: propagation fails honestly.
        self.assertEqual(proofs[0]['verdict'],'inconclusive')

    def test_reuse_tracks_only_mechanism_relevant_execution_policy(self):
        def unrelated(ctx,orch):
            ctx.gate.config.mutating_ceiling_by_check['cross_account_experiment']=7
            ctx.config['authz']={'owners':{'127.0.0.1':[{'path':'/anything','owner':'alice'}]}}
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,iterative=True,iterative_hook=unrelated)
        self.assertEqual(len(proofs),1,result)
        self.assertEqual([r['status'] for r in result['iterative_result']['mechanism_results']],['completed','reused'])
        self.assertEqual(len(app.writes),3)
        def relevant(ctx,orch):ctx.gate.config.mutating_ceiling_by_check['browser_stored_experiment']=6
        app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_STORED,iterative=True,iterative_hook=relevant)
        self.assertEqual(len(proofs),2,result)
        self.assertEqual([r['status'] for r in result['iterative_result']['mechanism_results']],['completed','completed'])
        self.assertEqual(len(app.writes),6)
        self.assertEqual(resolved,[True,True])

    def test_first_fragment_secret_is_redacted_in_real_durable_tool_evidence(self):
        import json
        checked=[]
        original=store.persist_proof_record
        def observe(proof):
            value=original(proof)
            events=store.ledger_events_for(proof.case.case_id)
            for event in events:
                self.assertNotIn('SECRET_SENTINEL',json.dumps(event))
                data=event.get('data') or {}
                for key in ('request_blob','response_blob'):
                    if data.get(key):self.assertNotIn(b'SECRET_SENTINEL',store.get_evidence_blob(data[key]))
            checked.append(True)
            return value
        def binding(b,c,x):b['route']=b['route'].replace('#/search?q=', '#/search?access_token=SECRET_SENTINEL&q=')
        with patch.object(store,'persist_proof_record',observe):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,modify=binding)
        self.assertEqual(proofs[0]['verdict'],'confirmed',result)
        self.assertTrue(checked)

    def test_hash_missing_route_parameter_identity_and_policy_are_explicit(self):
        for change in (lambda b,c,x:b.pop('route'),lambda b,c,x:b.update(parameter='missing'),
                       lambda b,c,x:setattr(c.sessions.get('browser:user'),'health','expired'),
                       lambda b,c,x:b.update(session_ref='unregistered'),
                       lambda b,c,x:setattr(c.gate.config,'active_enabled',False)):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH,modify=change)
            self.assertEqual(app.requests,[])
            self.assertEqual(proofs,[])
            self.assertTrue(result['blocked'])

    def test_broken_hash_route_binding_is_detected_by_the_positive_acceptance(self):
        from harness.browser_driver import PlaywrightDriver
        visit=PlaywrightDriver.visit
        async def break_route(driver,url,**kwargs):
            return await visit(driver,url.replace('#/search?','#/wrong?'),**kwargs)
        with patch.object(PlaywrightDriver,'visit',break_route):
            app,result,proofs,resolved,state=self.scenario(experiment.BROWSER_HASH)
        self.assertTrue(app.requests)
        self.assertEqual(proofs[0]['verdict'],'inconclusive')
        with self.assertRaises(AssertionError):self.assert_positive_browser(proofs,resolved)
