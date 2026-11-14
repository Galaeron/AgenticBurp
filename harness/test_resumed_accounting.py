"""A resumed job's issue count covers every attempt it continues (r9 review).

r9 ran as three jobs: the first, two resumes from its run journal. Each job's
accounting read only the findings and proofs of its own run id, and the last one
was cancelled, a path with no accounting at all: it reported no vulnerability while
the three attempts held 196 confirmed proofs. A case's id hashes the run id, so the
same case confirmed again by a later attempt also has a second case id.

Callers: POST /engagement/{host}/investigate with resume_job_id over the durable-job
server fixture (the orchestrator stubbed, no target I/O), finished and cancelled;
and confirmed_issue_accounting directly for the grouping. Controls bring back the
r9 scope (own run only) and the run-bound case key.
"""
from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import patch

from harness import assessment_health, evidence, store, telemetry
from harness import test_job_status_passive as _durable
from harness import test_run_journal as _journal
from harness.assessment_health import confirmed_issue_accounting, confirmed_issue_inventory
from harness.evidence import ProofRecord, TestCaseRef
from harness.models import Finding, HttpExchange

ORIGIN = "https://captured.example"


def _confirm(run_id: str, path: str, param: str) -> dict:
    """Persist a confirmed sqli proof of GET <path>?<param>=1 under `run_id` and bind it
    to the stored finding, as the confirm path does. Returns the in-run finding dict."""
    url = f"{ORIGIN}{path}?{param}=1"
    case = TestCaseRef.make(run_id=run_id, request_template_id=evidence._short("GET", url, ""),
                            check_id="sqli", parameter_location="query", parameter_name=param)
    proof = ProofRecord.from_validation_result(case=case, validator="sqlmap", status="confirmed",
                                               confirmed=True)
    ok, why = store.persist_proof_record(proof)
    assert ok, why
    finding = Finding(vulnerability_class="sqli", confidence=0.95, summary=f"sqli {path}",
                      evidence="fixture", suggested_test="verify", basis="derived", confirmed=True,
                      proof_id=proof.proof_id, case_id=case.case_id,
                      parameter_location="query", parameter_name=param)
    before = telemetry.current_run_id()
    telemetry.bind_current_run(run_id)            # persist_findings stamps the bound run
    try:
        store.bind_confirmation_proof(HttpExchange(url=url, method="GET"), finding, "sqlmap")
    finally:
        telemetry.bind_current_run(before)
    return {"confirmed": True, "case_id": case.case_id, "proof_id": proof.proof_id, "url": url,
            "vulnerability_class": "sqli", "finding_id": f"{run_id}-{param}"}


class ResumedAccountingServerTests(_durable.DurableJobCallerTests, unittest.TestCase):
    """ROOT ran first, PRIOR resumed it and was interrupted; this job resumes PRIOR.
    ROOT confirmed /api/items, PRIOR /api/search. This job confirms /api/items again
    (a new case id under its own run) and /api/users."""

    ROOT, PRIOR = "r00t00000001", "deadbeef0001"
    _key = _journal.JournalResumeServerTests._key
    _units = _journal.JournalResumeServerTests._units
    _resume = _journal.JournalResumeServerTests._resume

    def _prior_job(self, **extra):
        job = {"job_id": self.PRIOR, "host": "captured.example", "base_url": ORIGIN,
               "status": "interrupted", "started_at": time.time() - 5, "finished_at": time.time(),
               "error": "previous job process ended; no work was resumed", "recovered": True,
               "manifest_path": "", "result": None, "journal_root": self.ROOT, **extra}
        self.server._job_store().create(job)

    def _earlier_attempts(self, **extra):
        self.server.config['runs']['journal'] = True
        self._prior_job(**extra)
        self._units(root=self.ROOT)
        _confirm(self.ROOT, "/api/items", "q")
        _confirm(self.PRIOR, "/api/search", "term")

    def _this_attempt(self, *, wait=False):
        async def stub(*args, **kwargs):
            self.calls += 1
            run_id = kwargs['run_context'].run_id
            found = [_confirm(run_id, "/api/items", "q"), _confirm(run_id, "/api/users", "id")]
            if wait:
                await asyncio.Event().wait()
            return {'summary': {}, 'findings': found}
        self.server.orchestrator.investigate_engagement = stub

    def _resumed(self, *, wait=False, **extra):
        self._earlier_attempts(**extra)
        self._this_attempt(wait=wait)
        reply = self._resume()
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply.json()['job_id']

    def test_a_resumed_job_counts_every_attempt_and_each_case_once(self):
        job_id = self._resumed()
        result = self.poll(job_id, 'done')['result']
        self.assertEqual(result['attempt_run_ids'], [self.ROOT, self.PRIOR, job_id])
        self.assertEqual(result['confirmed_issues'], 3)          # items, search, users
        self.assertEqual(sorted(r['url'].split('?')[0] for r in result['confirmed_issue_refs']),
                         [f"{ORIGIN}/api/{p}" for p in ("items", "search", "users")])
        counts = result['issue_accounting']['counts']
        self.assertEqual(counts['proof_bound_cases'], 3)
        self.assertEqual(counts['ledger_confirmed_proof_instances'], 4)   # items twice
        self.assertEqual(result['issue_accounting']['run_id'], job_id)
        self.assertEqual(result['issue_accounting']['attempt_run_ids'], [self.ROOT, self.PRIOR, job_id])
        self.assertEqual(self.server._job_store().get(job_id)['attempt_run_ids'],
                         [self.ROOT, self.PRIOR, job_id])

    def test_control_counting_its_own_run_only_loses_the_earlier_attempts(self):
        own_findings, own_accounting = self.server._attempt_findings, self.server._attempt_accounting
        with patch.object(self.server, '_attempt_findings', lambda url, a: own_findings(url, a[-1:])), \
                patch.object(self.server, '_attempt_accounting', lambda a, f: own_accounting(a[-1:], f)):
            job_id = self._resumed()
            result = self.poll(job_id, 'done')['result']
        self.assertEqual(result['confirmed_issues'], 2)          # the r9 scope: search is lost

    def test_control_the_run_bound_case_id_counts_a_reconfirmed_case_twice(self):
        with patch.object(assessment_health, 'attempt_case_key', lambda case: case['case_id']):
            job_id = self._resumed()
            result = self.poll(job_id, 'done')['result']
        self.assertEqual(result['confirmed_issues'], 4)
        self.assertEqual(result['issue_accounting']['counts']['proof_bound_cases'], 4)

    def _cancelled(self):
        job_id = self._resumed(wait=True)
        for _ in range(100):
            if len(store.all_host_findings(ORIGIN, run_id=job_id)) == 1:   # users; items was bound
                break
            time.sleep(0.01)
        reply = self.client.post(f'/engagement/captured.example/investigate/{job_id}/cancel')
        self.assertEqual(reply.status_code, 200)
        return job_id, self.poll(job_id, 'cancelled')['result']

    def test_a_cancelled_resumed_job_reports_every_attempt(self):
        job_id, result = self._cancelled()
        self.assertTrue(result['partial'])
        self.assertEqual(result['attempt_run_ids'], [self.ROOT, self.PRIOR, job_id])
        self.assertEqual(len(result['findings']), 3)
        self.assertEqual(result['confirmed_issues'], 3)
        self.assertEqual(result['issue_accounting']['counts']['proof_bound_cases'], 3)

    def test_control_a_failing_accounting_never_hides_the_cancel(self):
        with patch.object(self.server, '_attempt_accounting', side_effect=RuntimeError('boom')):
            _job_id, result = self._cancelled()
        self.assertEqual(result['accounting_error'], 'RuntimeError')
        self.assertNotIn('confirmed_issues', result)
        self.assertEqual(len(result['findings']), 3)

    def test_the_attempts_carry_through_a_chain_of_resumes(self):
        job_id = self._resumed(attempt_run_ids=["a0", self.ROOT, self.PRIOR])
        self.poll(job_id, 'done')
        self.assertEqual(self.server._job_store().get(job_id)['attempt_run_ids'],
                         ["a0", self.ROOT, self.PRIOR, job_id])

    def test_a_new_job_is_its_own_only_attempt(self):
        self._this_attempt()
        job_id = self.start()
        result = self.poll(job_id, 'done')['result']
        self.assertEqual(result['attempt_run_ids'], [job_id])
        self.assertEqual(result['issue_accounting']['run_id'], job_id)
        self.assertNotIn('attempt_run_ids', result['issue_accounting'])
        self.assertEqual(result['confirmed_issues'], 2)


# unittest runs every test of the base class too; the base tests are not this module's.
for _name in [n for n in dir(_durable.DurableJobCallerTests) if n.startswith("test_")]:
    if _name not in ResumedAccountingServerTests.__dict__:
        setattr(ResumedAccountingServerTests, _name, None)


def _structured(run_id, path, n, *, created):
    url = f"{ORIGIN}{path}"
    case = TestCaseRef.make(run_id=run_id, request_template_id=f"tpl{path}", check_id="idor",
                            principal_id="alice").to_dict()
    proof = {"proof_id": f"p-{run_id}-{n}", "case": case, "validator": "cross_identity_validator",
             "verdict": "confirmed", "executed": True, "legacy": False, "created_at": created,
             "baseline_artifact_id": f"b{run_id}{n}", "attack_artifact_id": f"a{run_id}{n}",
             "control_artifact_ids": [f"c{run_id}{n}"]}
    finding = {"confirmed": True, "case_id": case["case_id"], "proof_id": proof["proof_id"],
               "url": url, "vulnerability_class": "idor", "finding_id": f"f-{run_id}-{n}"}
    return proof, finding


class AttemptGroupingTests(unittest.TestCase):
    """Two attempts proving one case are one vulnerability; one run is unchanged."""

    def _inputs(self):
        pairs = [_structured("run1", "/api/orders/{id}", 1, created=1.0),
                 _structured("run2", "/api/orders/{id}", 1, created=2.0),
                 _structured("run2", "/api/invoices/{id}", 2, created=3.0)]
        proofs = [p for p, _ in pairs]
        by_case = {}
        for p in proofs:
            by_case.setdefault(p["case"]["case_id"], []).append(p)
        return [f for _, f in pairs], proofs, lambda case_id: by_case.get(case_id, [])

    def _accounting(self, runs):
        findings, proofs, lookup = self._inputs()
        return confirmed_issue_accounting(findings, runs, lookup, run_proofs=proofs,
                                          artifact_resolver=lambda proof: True)

    def test_a_case_two_attempts_proved_is_one_vulnerability(self):
        counts = self._accounting(["run1", "run2"])["counts"]
        self.assertEqual((counts["vulnerabilities"], counts["proof_bound_cases"]), (2, 2))
        self.assertEqual(counts["ledger_confirmed_proof_instances"], 3)
        findings, _proofs, lookup = self._inputs()
        self.assertEqual(len(confirmed_issue_inventory(findings, ["run1", "run2"], lookup)), 2)

    def test_control_the_run_bound_key_makes_it_two(self):
        with patch.object(assessment_health, "attempt_case_key", lambda case: case["case_id"]):
            counts = self._accounting(["run1", "run2"])["counts"]
        self.assertEqual((counts["vulnerabilities"], counts["proof_bound_cases"]), (3, 3))

    def test_one_run_given_alone_or_as_a_list_is_the_single_run_accounting(self):
        alone = self._accounting("run2")
        self.assertEqual(alone, self._accounting(["run2"]))
        self.assertEqual(alone["run_id"], "run2")
        self.assertNotIn("attempt_run_ids", alone)
        self.assertEqual(alone["counts"]["vulnerabilities"], 2)
        # run1's proof is another run's: excluded, as before
        self.assertEqual([e["reason"] for e in alone["excluded"]], ["proof belongs to another run"])


if __name__ == "__main__":
    unittest.main()
