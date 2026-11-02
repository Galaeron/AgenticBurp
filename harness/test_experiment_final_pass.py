"""AR-FP: the bounded final re-evaluation pass for experiment tasks.

Caller-level, through `investigate_engagement` with the loopback notes app of
test_experiment_cycle. The dependent Comment experiment needs `note_id` and a second
identity. At the experiments phase bob's session is expired, so nothing can run. In
the worklist phase the real iterative worker (a scripted model, the only fixture)
re-authenticates bob and hands off ONLY the Note hypothesis: that run observes
`note_id`, which makes the Comment task READY -- but the hand-off never selects it.
Only the final pass, after the coverage phase, runs it.

The controls: experiments disabled sends nothing; max_runs already spent leaves the
Comment deferred by that bound; an attempt that failed with nothing changed since is
not re-run; a task waiting on operator input is reported with the exact input and no
send; unplugging `_final_experiment_pass` fails the same acceptance check.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness import store, task_graph
from harness.application_semantic_model import BusinessObject, ChainingHypothesis
from harness.assessment_health import stored_proof_artifacts_resolve
from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.test_experiment_cycle import (_COMMENT_ID_BASE, _GATE, _NOTE_ID_BASE, _CycleCase,
                                           _asm, _comment_expectation, _note_expectation)
from harness.test_iterative_agent import _ScriptedOllama

_SELECT_NOTE = {"action": "experiment", "kind": "cross_account_private_object",
                "hypothesis": "bch:note-idor"}
_STOP = {"action": "stop", "verdict": "gave_up"}


def _with_profile(asm):
    """Adds an IDOR hypothesis on an object no access expectation is declared for."""
    asm.business_objects.append(BusinessObject(
        name="Profile", id_params=["id"], object_scoped=True,
        read_endpoints=["GET /api/profiles/{id}"], write_endpoints=["POST /api/profiles"]))
    asm.chaining_hypotheses.append(ChainingHypothesis(
        id="bch:profile-idor", source="IDOR/BOLA on Profile", target="account takeover",
        rationale="profiles are addressed by id", rank=0.4, classes=["idor"],
        endpoints=["GET /api/profiles/{id}", "POST /api/profiles"]))
    return asm


class FinalExperimentPassTests(_CycleCase):

    def _engage(self, *, enabled=True, max_runs=4, profile=False):
        from harness import business_context_agent, role_crawl, worklist_investigator
        from harness.role_crawl import RoleSession
        app = self._app()
        orch = self._orch(hosts=("127.0.0.1",))
        orch.iterative_agent_enabled, orch.iterative_agent_max_steps = True, 3
        orch.business_context_enabled = True
        engagement = orch.config.setdefault("engagement", {})
        engagement["experiments"] = {"enabled": enabled, "max_runs": max_runs}
        engagement["access_expectations"] = [_note_expectation(), _comment_expectation()]
        asm = _asm(comments=True)
        if profile:
            _with_profile(asm)

        class Model(_ScriptedOllama):
            async def chat_json_metered(script, **kwargs):
                from harness.ollama_client import OllamaResult
                return OllamaResult(data=await script.chat_json(**kwargs),
                                    prompt_tokens=1, completion_tokens=1)

        orch.ollama = Model([_SELECT_NOTE, _STOP])
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": "Bearer tok-alice"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer tok-bob"}, name="bob")]
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                config=orch.config, gate_config=_GATE)
        seen = {}

        def bob():
            return next(s for s in ctx.sessions.all() if s.name == "bob")

        def comment_task(state=None):
            state = state or ctx.experiment_context["state"]
            return next((t for t in state.graph.tasks.values()
                         if t.kind == "experiment" and t.meta.get("object") == "Comment"), None)

        def build_model(*args, **kwargs):
            # Bob's credentials were rejected during discovery: the experiments phase
            # that follows has no second identity.
            bob().health = "expired"
            return asm

        async def worker(probe_fn, *args, **kwargs):
            task = comment_task()
            seen["at_worklist"] = (task.status, task.needs) if task else None
            # The production refresh path installs re-authenticated credentials.
            ctx.sessions.replace_headers(bob().session_id, {"Authorization": "Bearer tok-bob"})
            seen["worker"] = await probe_fn(
                HttpExchange(url=app.base + "/api/notes", method="POST",
                             request_body='{"title":"initial"}'),
                "Select the declared experiment", "idor", 3)
            task = comment_task()
            seen["after_worker"] = task.status if task else None
            return []

        async def go():
            async with ctx:
                with patch.object(role_crawl, "crawl_roles",
                                  AsyncMock(return_value=role_crawl.RoleCrawlResult(base_url=app.base))), \
                     patch.object(business_context_agent.BusinessContextAgent, "build_model",
                                  side_effect=build_model), \
                     patch.object(worklist_investigator, "investigate_worklist", worker):
                    result = await orch.investigate_engagement(
                        app.base, roles, max_nodes=0, max_chain_rounds=0,
                        active_discovery=False, run_context=ctx)
                seen["state"] = ctx.experiment_context["state"]
                return result

        result = asyncio.run(go())
        state = seen["state"]
        return SimpleNamespace(result=result, app=app, seen=seen, run_id=ctx.run_id, state=state,
                               comment=comment_task(state))

    def _disposition(self, b, task_id):
        return next(t for t in b.result["experiment_preflight"]["tasks"] if t["task_id"] == task_id)

    def _assert_final_pass_completed(self, b):
        """The acceptance check, shared with the unplugged control: the Comment task,
        unrunnable at the experiments phase and left READY by the hand-off, is DONE
        with a stored, resolvable proof the final pass produced, bound to the note id
        the worker's run observed."""
        note = _NOTE_ID_BASE
        self.assertEqual(b.seen["at_worklist"][0], task_graph.BLOCKED)
        self.assertIn("value 'note_id' not yet observed", b.seen["at_worklist"][1])
        records = b.seen["worker"]["iterative_result"]["mechanism_results"]
        self.assertEqual([r["status"] for r in records], ["completed"], records)
        self.assertEqual(b.seen["after_worker"], task_graph.READY)
        final = b.result["experiment_final_pass"]
        self.assertIsNotNone(final, "the final experiment pass did not run")
        self.assertEqual([c["task_id"] for c in final["completed"]], [b.comment.id], final)
        self.assertEqual(b.comment.status, task_graph.DONE)
        proof = next(p for p in store.proofs_for_run(b.run_id)
                     if p["proof_id"] == b.comment.evidence_ref)
        self.assertEqual(proof["verdict"], "controlled_negative")
        self.assertTrue(stored_proof_artifacts_resolve(proof))
        self.assertIn(("POST", f"/api/notes/{note}/comments", "alice"), b.app.requests)
        self.assertIn(("GET", f"/api/notes/{note}/comments/{_COMMENT_ID_BASE}", "bob"),
                      b.app.requests)
        disposition = self._disposition(b, b.comment.id)
        self.assertEqual((disposition["status"], disposition["blocked_on"]), ("completed", None))
        self.assertIn(proof["proof_id"],
                      [c.get("proof_id") for c in b.result["coverage"]["experiment_cases"]])

    def test_a_dependent_unblocked_by_a_later_phase_completes_in_the_final_pass(self):
        b = self._engage()
        self.assertEqual([e for e in b.result["errors"] if e["phase"].startswith("experiments")], [])
        self.assertEqual(b.result["experiments"]["runs"], 0, b.result["experiments"])
        self._assert_final_pass_completed(b)
        self.assertEqual(b.result["experiment_preflight"]["schema_version"], 2)

    def test_unplugging_the_final_pass_fails_the_acceptance_check(self):
        from harness.orchestrator_chain import ChainMixin
        with patch.object(ChainMixin, "_final_experiment_pass", AsyncMock(return_value=None)):
            b = self._engage()
        with self.assertRaises(AssertionError):
            self._assert_final_pass_completed(b)
        self.assertEqual(b.comment.status, task_graph.READY)
        self.assertEqual(self._disposition(b, b.comment.id)["status"], "advisory")
        self.assertFalse(any("/comments" in path for _, path, _ in b.app.requests))

    def test_experiments_disabled_sends_nothing_and_runs_no_pass(self):
        b = self._engage(enabled=False)
        self.assertIsNone(b.result["experiment_final_pass"])
        self.assertIsNone(b.result["experiments"])
        self.assertEqual(b.app.requests, [])
        self.assertEqual(store.proofs_for_run(b.run_id), [])

    def test_max_runs_already_spent_leaves_the_dependent_deferred_by_that_bound(self):
        b = self._engage(max_runs=1)          # the worker's Note run spends the only one
        self.assertEqual(b.seen["after_worker"], task_graph.READY)
        final = b.result["experiment_final_pass"]
        self.assertEqual((final["runs"], final["completed"]), (0, []))
        self.assertEqual(final["stopped_by"], "engagement experiment max_runs exhausted")
        self.assertFalse(any("/comments" in path for _, path, _ in b.app.requests))
        disposition = self._disposition(b, b.comment.id)
        self.assertEqual(disposition["status"], "deferred")
        self.assertEqual(disposition["blocked_on"], {
            "category": "budget", "inputs": ["engagement experiment max_runs exhausted"]})

    def test_an_unchanged_failed_attempt_is_not_re_run_by_the_final_pass(self):
        from harness.test_experiment_cycle import InvestigateWiringTests
        app = self._app(allow_cross=True)
        with patch.object(store, "persist_proof_record", side_effect=RuntimeError("owned failure")):
            run_id, result = InvestigateWiringTests._investigate(self, app)
        sent = list(app.requests)
        self.assertEqual(sum(method == "POST" for method, _, _ in sent), 2)   # one attempt only
        final = result["experiment_final_pass"]
        self.assertEqual((final["runs"], final["ready"], final["requeued"]), (0, [], []))
        task = result["experiment_preflight"]["tasks"][0]
        self.assertEqual(final["failed_unchanged"], [task["task_id"]])
        self.assertEqual(task["status"], "inconclusive")
        self.assertEqual(task["blocked_on"], {
            "category": "failed_unchanged",
            "inputs": ["unchanged failed attempt requires new evidence"]})

    def test_an_operator_blocked_task_names_its_missing_input_and_sends_nothing(self):
        b = self._engage(profile=True)
        self._assert_final_pass_completed(b)
        profile = next(t for t in b.state.graph.tasks.values()
                       if t.kind == "experiment" and t.meta.get("object") == "Profile")
        self.assertEqual(profile.status, task_graph.BLOCKED)
        disposition = self._disposition(b, profile.id)
        self.assertEqual(disposition["status"], "missing_prerequisite")
        self.assertEqual(disposition["blocked_on"]["category"], "operator_input")
        self.assertIn("no declared access expectation for object 'Profile' "
                      "(engagement.access_expectations)", disposition["blocked_on"]["inputs"])
        self.assertFalse(any("/api/profiles" in path for _, path, _ in b.app.requests))
        self.assertNotIn(disposition["status"], ("completed", "negative", "controlled_negative"))


if __name__ == "__main__":
    import unittest
    unittest.main()
