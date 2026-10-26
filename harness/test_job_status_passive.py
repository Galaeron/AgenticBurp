"""Durable polling through real HTTP routes; only inert jobs and temporary data."""
import asyncio
import base64
import hashlib
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import store
from harness.job_status import JobStatusStore
from harness.test_pairing_contract import PairingCallerTests


class DurableJobCallerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PairingCallerTests('test_health_is_liveness_and_pairing_requires_credential')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server = self.fixture.server
        self.server.orchestrator.allowed_hosts = ['captured.example']
        self.server.orchestrator.config = self.server.config
        self.server.orchestrator.validator_registry = SimpleNamespace(active_enabled=False)
        self.server.orchestrator.agent_manager.agents = {}
        self.server.config['runs'] = {'output_dir': self.fixture.tmp.name}
        self.client = self.fixture.client
        self.client.headers.update(self.fixture.auth)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        for target in ('httpx.HTTPTransport.handle_request', 'httpx.AsyncHTTPTransport.handle_async_request',
                       'harness.run_context.TargetTransport.execute'):
            guard = patch(target, side_effect=AssertionError('no target or provider I/O'))
            guard.start()
            self.addCleanup(guard.stop)
        git = patch.object(self.server._run_manifest, '_git_state', return_value=(None, None))
        git.start()
        self.addCleanup(git.stop)
        self.calls = 0

        async def ordinary(*args, **kwargs):
            self.calls += 1
            return {'summary': {'ordinary_captures': 1}}
        self.server.orchestrator.investigate_engagement = ordinary

    def start(self):
        response = self.client.post('/engagement/captured.example/investigate',
                                    json={'base_url': 'https://captured.example/ordinary'})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['job_id']

    def poll(self, job_id, expected):
        for _ in range(50):
            reply = self.client.get(f'/engagement/captured.example/investigate/{job_id}')
            self.assertEqual(reply.status_code, 200, reply.text)
            if reply.json()['status'] == expected:
                return reply.json()
            time.sleep(0.01)
        self.fail(f'job did not reach {expected}: {reply.text}')

    def test_completed_job_survives_registry_loss_without_reexecution(self):
        job_id = self.start()
        completed = self.poll(job_id, 'done')
        artifact = Path(completed['manifest_path'])
        original = artifact.read_bytes()
        self.server._INVESTIGATE_JOBS.clear()
        durable = self.poll(job_id, 'done')
        self.assertEqual(durable['result'], completed['result'])
        self.assertTrue(durable['result_available'])
        self.assertEqual(self.calls, 1)
        self.assertEqual(artifact.read_bytes(), original)
        # Disable durable lookup: the old memory-only route loses the result.
        with patch.object(JobStatusStore, 'get', return_value=None):
            self.assertEqual(self.client.get(f'/engagement/captured.example/investigate/{job_id}').status_code, 404)

    def test_live_and_durable_polling_share_secret_redaction_and_result_limit(self):
        async def sensitive_fixture(*args, **kwargs):
            self.calls += 1
            return {'authorization': 'LIVE_SECRET_SENTINEL',
                    'nested': {'url': 'https://captured.example/?token=QUERY_SECRET_SENTINEL'},
                    'errors': [{'error': 'https://captured.example/?token=MANIFEST_SECRET_SENTINEL'}]}
        self.server.orchestrator.investigate_engagement = sensitive_fixture
        response = self.client.post('/engagement/captured.example/investigate', json={
            'base_url': 'https://captured.example/ordinary?token=BASE_SECRET_SENTINEL'})
        self.assertEqual(response.status_code, 200)
        job_id = response.json()['job_id']
        completed = self.poll(job_id, 'done')
        listed = self.client.get('/engagement/captured.example/investigate').text
        serialized = (json.dumps(completed) + response.text + listed
                      + Path(completed['manifest_path']).read_text(encoding='utf-8'))
        for sentinel in ('LIVE_SECRET_SENTINEL', 'QUERY_SECRET_SENTINEL', 'BASE_SECRET_SENTINEL', 'MANIFEST_SECRET_SENTINEL'):
            self.assertNotIn(sentinel, serialized)
        self.server._INVESTIGATE_JOBS.clear()
        durable = self.poll(job_id, 'done')
        self.assertEqual(completed, durable)

    def test_job_exception_detail_is_not_returned_or_persisted(self):
        async def failed_fixture(*args, **kwargs):
            self.calls += 1
            raise RuntimeError('ARBITRARY_UPSTREAM_SECRET_SENTINEL')
        self.server.orchestrator.investigate_engagement = failed_fixture
        job_id = self.start()
        failed = self.poll(job_id, 'error')
        manifest = Path(failed['manifest_path']).read_text(encoding='utf-8')
        self.assertNotIn('ARBITRARY_UPSTREAM_SECRET_SENTINEL', json.dumps(failed) + manifest)
        self.server._INVESTIGATE_JOBS.clear()
        self.assertNotIn('ARBITRARY_UPSTREAM_SECRET_SENTINEL', json.dumps(self.poll(job_id, 'error')))

    def test_live_redaction_negative_control_reaches_actual_polling_route(self):
        async def sensitive_fixture(*args, **kwargs):
            self.calls += 1
            return {'authorization': 'SYNTHETIC_REDACTION_CONTROL_SENTINEL'}
        self.server.orchestrator.investigate_engagement = sensitive_fixture
        job_id = self.start()
        normal = self.poll(job_id, 'done')
        self.assertNotIn('SYNTHETIC_REDACTION_CONTROL_SENTINEL', json.dumps(normal))
        # Inject the original raw live-view defect at the shared public boundary.
        # The HTTP caller must detect it; testing sanitizer helpers alone would
        # not establish that this route actually uses the public-view contract.
        with patch.object(JobStatusStore, 'public_snapshot', side_effect=lambda job: dict(job)):
            broken = self.client.get(f'/engagement/captured.example/investigate/{job_id}')
        self.assertEqual(broken.status_code, 200)
        self.assertIn('SYNTHETIC_REDACTION_CONTROL_SENTINEL', broken.text)
        self.assertEqual(self.calls, 1)

    def test_duplicate_admission_preserves_existing_manifest_and_does_not_execute(self):
        job_id = self.start()
        completed = self.poll(job_id, 'done')
        artifact = Path(completed['manifest_path'])
        original = artifact.read_bytes()
        with patch.object(self.server._uuid, 'uuid4', return_value=SimpleNamespace(hex=job_id)):
            denied = self.client.post('/engagement/captured.example/investigate',
                                     json={'base_url': 'https://captured.example/ordinary'})
        self.assertEqual(denied.status_code, 503)
        self.assertEqual(self.calls, 1)
        self.assertEqual(artifact.read_bytes(), original)

    def test_oversized_result_is_durable_authenticated_chunked_and_restart_readable(self):
        async def oversized_fixture(*args, **kwargs):
            self.calls += 1
            return {'ordinary': 'x' * 2_000_001, 'items': list(range(2000))}
        self.server.orchestrator.investigate_engagement = oversized_fixture
        job_id = self.start()
        completed = self.poll(job_id, 'done')
        self.assertIsNone(completed['result'])
        self.assertTrue(completed['result_available'])
        self.assertIsNone(completed['error'])
        ref = completed['result_ref']
        self.assertNotIn(str(self.fixture.tmp.name), ref)
        self.assertLess(len(json.dumps(completed)), 10000)
        self.assertEqual(self.client.get(ref, headers={'Authorization': 'Bearer wrong'}).status_code, 401)
        self.assertEqual(self.client.get(ref.replace('captured.example', 'other.example')).status_code, 404)
        self.assertEqual(self.client.get(ref, params={'limit': 262145}).status_code, 422)
        chunks, offset = [], 0
        while offset is not None:
            reply = self.client.get(ref, params={'offset': offset, 'limit': 200000})
            self.assertEqual(reply.status_code, 200, reply.text)
            page = reply.json()
            chunks.append(base64.b64decode(page['data']))
            self.assertLessEqual(len(chunks[-1]), 200000)
            offset = page['next_offset']
        raw = b''.join(chunks)
        self.assertEqual(len(raw), completed['result_size_bytes'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), completed['result_sha256'])
        self.assertEqual(json.loads(raw)['items'], list(range(2000)))
        self.server._INVESTIGATE_JOBS.clear()
        self.assertEqual(self.poll(job_id, 'done'), completed)
        # A fresh process imports the actual API with an inert provider and
        # reopens this journal. No inherited task, registry or provider exists.
        code = '''import sys,json,base64,hashlib
from pathlib import Path
from harness.test_pairing_contract import PairingCallerTests
from harness import store
fixture=PairingCallerTests('test_health_is_liveness_and_pairing_requires_credential')
fixture.setUp()
try:
 store._DB_PATH=Path(sys.argv[1])
 client=fixture.client
 poll=client.get(sys.argv[2],headers=fixture.auth).json()
 offset=0; chunks=[]
 while offset is not None:
  page=client.get(poll['result_ref'],params={'offset':offset},headers=fixture.auth).json()
  chunks.append(base64.b64decode(page['data']));offset=page['next_offset']
 raw=b''.join(chunks)
 print(json.dumps({'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'count':len(json.loads(raw)['items'])}))
finally: fixture.doCleanups()
'''
        restarted = subprocess.run([sys.executable, '-c', code, str(store._DB_PATH),
            f'/engagement/captured.example/investigate/{job_id}'], capture_output=True, text=True, timeout=40, check=True)
        recovered = json.loads(restarted.stdout.strip().splitlines()[-1])
        self.assertEqual(recovered, {'sha256': completed['result_sha256'], 'size': len(raw), 'count': 2000})
        self.assertEqual(self.calls, 1)
        journal = self.server._job_store()
        from contextlib import closing
        with closing(journal._connect()) as conn, conn:
            conn.execute('UPDATE job_results SET content=? WHERE job_id=?', (b'corrupt', job_id))
        self.assertEqual(self.client.get(ref).status_code, 503)
        corrupt = self.poll(job_id, 'done')
        self.assertFalse(corrupt['result_available'])
        self.assertIn('corrupt', corrupt['delivery_error'])
        self.assertIsNone(corrupt['error'])
        with closing(journal._connect()) as conn, conn:
            conn.execute('DELETE FROM job_results WHERE job_id=?', (job_id,))
        self.assertEqual(self.client.get(ref).status_code, 503)

    def test_manifest_initialization_failure_releases_admission_without_work(self):
        with patch.object(self.server._run_manifest.RunManifest, 'start', side_effect=OSError('synthetic')):
            denied = self.client.post('/engagement/captured.example/investigate',
                                     json={'base_url': 'https://captured.example/ordinary'})
        self.assertEqual(denied.status_code, 503)
        self.assertEqual(self.calls, 0)
        saved = self.server._job_store().list('captured.example')
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]['status'], 'error')
        self.assertIn('no work was scheduled', saved[0]['error'])
        self.poll(self.start(), 'done')
        self.assertEqual(self.calls, 1)

    def test_manifest_terminal_failure_is_visible_without_task_exception_detail(self):
        async def caller():
            started = await self.server.engagement_investigate('captured.example',
                self.server.InvestigateRequest(base_url='https://captured.example'),
                authorization=self.fixture.auth['Authorization'])
            job_id = started['job_id']
            task = self.server._INVESTIGATE_JOBS[job_id]['task']
            await task  # failures must become job status, not an unhandled task
            job = self.server._job_store().get(job_id)
            self.assertEqual(job['status'], 'done')
            self.assertIn('manifest persistence failed', job['delivery_error'])
            self.assertNotIn('ARBITRARY_MANIFEST_SECRET_SENTINEL', json.dumps(job))
        with patch.object(self.server._run_manifest.RunManifest, 'finish',
                          side_effect=OSError('ARBITRARY_MANIFEST_SECRET_SENTINEL')):
            asyncio.run(caller())
        self.assertEqual(self.calls, 1)

    def test_live_foreign_owner_is_not_interrupted_or_cancelled(self):
        journal = self.server._job_store()
        foreign = JobStatusStore(journal.path, 'foreign-live-owner')
        foreign.create(dict(job_id='foreign-live', host='captured.example',
                            base_url='https://captured.example', status='running', started_at=time.time()))
        listed = self.client.get('/engagement/captured.example/investigate').json()
        self.assertEqual(listed['jobs'][0]['status'], 'running')
        denied = self.client.post('/engagement/captured.example/investigate/foreign-live/cancel')
        self.assertEqual(denied.status_code, 409)
        self.assertEqual(journal.get('foreign-live')['status'], 'running')
        self.assertEqual(self.calls, 0)

    def test_atomic_shared_journal_capacity_has_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        from harness.job_status import JobCapacityError
        from threading import Barrier
        journal = self.server._job_store()
        JobStatusStore(journal.path, 'initialize').list('captured.example')
        barrier = Barrier(2)
        def admit(index):
            candidate = JobStatusStore(journal.path, f'contender-{index}', max_running=1)
            barrier.wait(timeout=5)
            try:
                candidate.create(dict(job_id=f'contender-{index}', host='captured.example',
                                      base_url='https://captured.example', status='running', started_at=time.time()))
                return 'admitted'
            except JobCapacityError:
                return 'denied'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(admit, (1, 2)))
        self.assertEqual(sorted(results), ['admitted', 'denied'])
        self.assertEqual(len(journal.list('captured.example')), 1)
        self.assertEqual(self.calls, 0)

    def test_dead_process_becomes_interrupted_and_artifact_is_preserved(self):
        folder = Path(self.fixture.tmp.name)
        artifact = folder/'ordinary-artifact.txt'
        artifact.write_text('ordinary captured metadata', encoding='utf-8')
        journal = self.server._job_store()
        # A real owned child writes only metadata then exits before completion.
        code = '''import sys,time
from harness.job_status import JobStatusStore
JobStatusStore(sys.argv[1], 'owned-child').create(dict(job_id='interrupted-fixture',
host='captured.example',base_url='https://captured.example',status='running',
started_at=time.time(),manifest_path=sys.argv[2],result=None))
'''
        subprocess.run([sys.executable,'-c',code,str(journal.path),str(artifact)],
                       check=True,capture_output=True,text=True,timeout=20)
        before = artifact.read_bytes()
        # Disabling process-loss recovery leaves the dead owner's durable row
        # falsely running. This control exercises the actual polling caller.
        with patch.object(JobStatusStore, 'recover_interrupted', return_value=None):
            unrecovered = self.poll('interrupted-fixture', 'running')
        self.assertFalse(unrecovered['recovered'])
        self.assertEqual(self.calls, 0)
        recovered = self.poll('interrupted-fixture','interrupted')
        self.assertTrue(recovered['recovered'])
        self.assertIn('no work was resumed', recovered['error'])
        self.assertEqual(self.calls, 0)
        self.assertEqual(artifact.read_bytes(), before)
        self.assertEqual(self.client.get('/engagement/other.example/investigate/interrupted-fixture').status_code,404)
        # An explicit subsequent synthetic request runs once; polling never resumes.
        self.poll(self.start(), 'done')
        self.assertEqual(self.calls, 1)

    def test_cancellation_is_durable_and_pruning_does_not_delete_artifacts(self):
        async def waiting(*args, **kwargs):
            self.calls += 1
            await asyncio.Event().wait()
        self.server.orchestrator.investigate_engagement = waiting
        job_id = self.start()
        cancel = self.client.post(f'/engagement/captured.example/investigate/{job_id}/cancel')
        self.assertEqual(cancel.status_code, 200)
        done = self.poll(job_id,'cancelled')
        artifact = Path(done['manifest_path'])
        self.server._INVESTIGATE_JOBS.clear()
        self.assertEqual(self.poll(job_id,'cancelled')['status'],'cancelled')
        with patch.object(self.server,'_JOB_RETENTION_SECONDS',-1):
            self.assertEqual(self.client.get(f'/engagement/captured.example/investigate/{job_id}').status_code,404)
        self.assertTrue(artifact.exists())

    def test_cancel_preserves_run_bound_partial_evidence_and_result_artifact(self):
        from harness.models import HttpExchange, Finding
        async def waiting(*args, **kwargs):
            self.calls += 1
            store.persist_findings(HttpExchange(url='https://captured.example/partial', method='GET'),
                'synthetic', [Finding(vulnerability_class='information_disclosure', severity='info',
                    confidence=0.7, summary='PARTIAL_CAPTURE', evidence='ordinary',
                    suggested_test='Review captured metadata', basis='derived')])
            await asyncio.Event().wait()
        self.server.orchestrator.investigate_engagement = waiting
        job_id = self.start()
        for _ in range(50):
            if store.all_host_findings('https://captured.example/'):
                break
            time.sleep(0.01)
        reply = self.client.post(f'/engagement/captured.example/investigate/{job_id}/cancel')
        self.assertEqual(reply.status_code, 200)
        cancelled = self.poll(job_id, 'cancelled')
        self.assertTrue(cancelled['result']['partial'])
        self.assertTrue(cancelled['result_available'])
        self.assertEqual([row['summary'] for row in cancelled['result']['findings']], ['PARTIAL_CAPTURE'])
        self.server._INVESTIGATE_JOBS.clear()
        durable = self.poll(job_id, 'cancelled')
        page = self.client.get(durable['result_ref']).json()
        artifact = json.loads(base64.b64decode(page['data']))
        self.assertEqual(artifact, cancelled['result'])
        self.assertEqual(self.calls, 1)

    def test_result_and_status_update_roll_back_together_on_failure(self):
        job_id = self.start()
        completed = self.poll(job_id, 'done')
        journal = self.server._job_store()
        before = journal.read_result(job_id)
        foreign = JobStatusStore(journal.path, 'not-the-owner')
        replacement = dict(self.server._INVESTIGATE_JOBS[job_id], result={'invalid': 'replacement'})
        with self.assertRaises(ValueError):
            foreign.update(replacement)
        self.assertEqual(journal.read_result(job_id), before)
        self.assertEqual(self.poll(job_id, 'done'), completed)

    def test_resume_uses_only_matching_authenticated_managed_checkpoint(self):
        checkpoint = {'context_key': 'fixture-source-config', 'signature': 'fixture-captures', 'rows': []}
        received = []
        async def with_checkpoint(*args, **kwargs):
            self.calls += 1
            received.append(kwargs.get('coverage_checkpoint'))
            return {'coverage': {'checkpoint': checkpoint}}
        self.server.orchestrator.investigate_engagement = with_checkpoint
        path = '/engagement/captured.example/investigate'
        from harness import coverage_tracker
        with patch.object(coverage_tracker, 'resume_context_key', return_value='fixture-source-config'):
            job_id = self.start()
            self.poll(job_id, 'done')
            self.server._INVESTIGATE_JOBS.clear()
            resumed = self.client.post(path, json={'base_url': 'https://captured.example/another',
                                                  'resume_job_id': job_id,
                                                  'coverage_checkpoint': {'tampered': True}})
            self.assertEqual(resumed.status_code, 200, resumed.text)
            self.poll(resumed.json()['job_id'], 'done')
            self.assertEqual(received, [None, checkpoint])
            for body, status in [
                ({'base_url': 'https://captured.example', 'resume_job_id': 'missing'}, 404),
                ({'base_url': 'http://captured.example', 'resume_job_id': job_id}, 409),
                ({'base_url': 'https://captured.example:8443', 'resume_job_id': job_id}, 409),
            ]:
                self.assertEqual(self.client.post(path, json=body).status_code, status)
            with patch.object(coverage_tracker, 'resume_context_key', return_value='changed-source-config'):
                denied = self.client.post(path, json={'base_url': 'https://captured.example', 'resume_job_id': job_id})
                self.assertEqual(denied.status_code, 409)
            denied = self.client.post(path, headers={'Authorization': 'Bearer wrong'},
                json={'base_url': 'https://captured.example', 'resume_job_id': job_id})
            self.assertEqual(denied.status_code, 401)
            journal = self.server._job_store()
            from contextlib import closing
            with closing(journal._connect()) as conn, conn:
                conn.execute('DELETE FROM job_results WHERE job_id=?', (job_id,))
            self.assertEqual(self.client.post(path, json={'base_url': 'https://captured.example',
                'resume_job_id': job_id}).status_code, 409)
            self.assertEqual(self.calls, 2)

    def test_failed_admission_never_schedules_work_and_failed_update_is_visible(self):
        with patch.object(JobStatusStore,'create',side_effect=OSError('synthetic')):
            denied = self.client.post('/engagement/captured.example/investigate',
                                     json={'base_url':'https://captured.example'})
        self.assertEqual(denied.status_code,503)
        self.assertEqual(self.calls,0)
        with patch.object(JobStatusStore,'update',side_effect=OSError('synthetic')):
            job_id = self.start()
            done = self.poll(job_id,'done')
        self.assertIn('durable job status unavailable',done['persistence_error'])

    def test_total_journal_outage_is_explicit_and_does_not_reexecute(self):
        job_id = self.start()
        self.poll(job_id, 'done')
        with patch.object(JobStatusStore, '_connect', side_effect=OSError('synthetic outage')):
            for method, path in (
                ('get', '/engagement/captured.example/investigate'),
                ('get', f'/engagement/captured.example/investigate/{job_id}'),
                ('post', f'/engagement/captured.example/investigate/{job_id}/cancel'),
            ):
                reply = getattr(self.client, method)(path)
                self.assertEqual(reply.status_code, 503, reply.text)
                self.assertIn('durable job status unavailable', reply.text)
            denied = self.client.post('/engagement/captured.example/investigate',
                                     json={'base_url': 'https://captured.example'})
            self.assertEqual(denied.status_code, 503)
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.poll(job_id, 'done')['status'], 'done')

    def test_durable_admission_cap_survives_memory_loss(self):
        import os
        journal = self.server._job_store()
        for index in range(self.server._MAX_RUNNING_JOBS):
            journal.create(dict(job_id=f'live-{index}',host='captured.example',
                                base_url='https://captured.example',status='running',started_at=time.time()))
        denied = self.client.post('/engagement/captured.example/investigate',
                                 json={'base_url':'https://captured.example'})
        self.assertEqual(denied.status_code,503)
        self.assertEqual(self.calls,0)

    def test_cancel_before_coroutine_first_step_is_terminal(self):
        async def caller():
            started = await self.server.engagement_investigate('captured.example',
                self.server.InvestigateRequest(base_url='https://captured.example'),
                authorization=self.fixture.auth['Authorization'])
            job_id = started['job_id']
            task = self.server._INVESTIGATE_JOBS[job_id]['task']
            await self.server.engagement_investigate_cancel('captured.example', job_id,
                authorization=self.fixture.auth['Authorization'])
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0)
            self.assertEqual(self.server._job_store().get(job_id)['status'],'cancelled')
            self.assertEqual(self.calls,0)
        asyncio.run(caller())
