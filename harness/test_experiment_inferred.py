"""r7: an unattended run infers an access expectation from self-observed ownership.

Caller-level. The loopback notes application of test_experiment_cycle (notes are
private to their creator; `allow_cross` breaks that) and a real RunContext with
two same-role bearer sessions and the run's SelfOwnership. Each principal first
creates a note through the run's real transport, which is how the ownership facts
arise in a run. No expectation is declared. The cycle runs through
ChainMixin._run_experiments, and the verdict is read back from the stored proof
and the experiment projection.

  inferred   ownership facts, nothing declared -> the experiment is ready, runs,
             cleans up; its expectation, proof and finding say "inferred"
  negative   the same with a correct app -> controlled negative
  control 1  no ownership facts -> still blocked on the missing expectation, no send
  control 2  a declared 'shared' expectation -> blocked on it, nothing inferred
  control 3  a declared private_to_creator expectation -> used, not inferred
  control 4  owner and other of different roles -> nothing inferred
"""
from __future__ import annotations

import asyncio
import json
import unittest
from types import SimpleNamespace

from harness import experiment, store
from harness.application_semantic_model import (ApplicationSemanticModel, BusinessObject,
                                                ChainingHypothesis)
from harness.engagement import EngagementState
from harness.run_context import RunContext
from harness.self_ownership import SelfOwnership
from harness.test_experiment_cycle import _GATE, _CycleCase, _note_expectation


def _asm() -> ApplicationSemanticModel:
    return ApplicationSemanticModel(host="127.0.0.1", business_objects=[
        BusinessObject(name="note", id_params=["id"], object_scoped=True,
                       read_endpoints=["GET /api/notes/{id}"],
                       write_endpoints=["POST /api/notes", "DELETE /api/notes/{id}"])],
        chaining_hypotheses=[ChainingHypothesis(
            id="bch:note-idor", source="IDOR/BOLA on note", target="data exposure",
            rationale="notes are addressed by id", rank=0.8, classes=["idor"],
            endpoints=["GET /api/notes/{id}", "POST /api/notes"])])


class InferredExpectationTests(_CycleCase):
    def _run(self, *, allow_cross=True, seed=True, expectations=(), bob_role="user"):
        app = self._app(allow_cross=allow_cross)
        orch = self._orch(hosts=("127.0.0.1",))
        engagement = orch.config.setdefault("engagement", {})
        engagement["experiments"] = {"enabled": True, "max_runs": 4, "planner": False}
        engagement["access_expectations"] = list(expectations)
        asm, state = _asm(), EngagementState(host="127.0.0.1")
        out = SimpleNamespace(app=app, state=state)

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                         gate_config=_GATE) as run:
                run.self_ownership = SelfOwnership(run_id=run.run_id, persist=False)
                run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[app.base])
                run.sessions.register("principal:1:alice", "alice",
                                      {"Authorization": "Bearer tok-alice"},
                                      allowed_origins=[app.base], role="user")
                run.sessions.register("principal:2:bob", "bob", {"Authorization": "Bearer tok-bob"},
                                      allowed_origins=[app.base], role=bob_role)
                if seed:
                    for ref in ("principal:1:alice", "principal:2:bob"):
                        sent = await run.target_transport().send(
                            "POST", app.base + "/api/notes", capability=experiment.VALIDATOR,
                            session_ref=ref, headers={"Content-Type": "application/json"},
                            body=json.dumps({"title": "my own note"}))
                        self.assertEqual(sent.status, 201)
                out.seeded = len(app.requests)
                state.apply_semantic_model(asm)
                out.result = await orch._run_experiments(state, asm, run, base_url=app.base)
                out.projection = experiment.project_proofs(state, run)
                out.run_id = run.run_id

        asyncio.run(go())
        out.task = next(t for t in experiment.experiment_tasks(out.state))
        return out

    def _assert_inferred_run(self, out, outcome):
        self.assertEqual(out.result["runs"], 1, out.result)
        done = out.result["completed"][0]
        self.assertEqual(done["outcome"], outcome, done)
        expectation = out.task.meta["experiment"]["access_expectation"]
        self.assertTrue(expectation["inferred"])
        self.assertEqual(expectation["expectation"], "owner_only")
        self.assertTrue(expectation["source"].startswith(experiment.INFERRED_SOURCE))
        self.assertIn("observed owned by 2 principal(s)", expectation["basis"])
        proof = store.proofs_for_run(out.run_id)[0]
        self.assertTrue(proof["expected_invariant"].startswith("inferred owner_only"))
        self.assertIn(experiment.INFERRED_LIMITATION, proof["limitation"])
        # Created with what a principal of the run actually sent, then removed again.
        creates = [b for b in out.app.bodies[out.seeded:] if b[0] == "POST"]
        self.assertEqual([json.loads(b[3]) for b in creates], [{"title": "my own note"}] * 2)
        self.assertEqual(len(out.app.notes), 2, "the experiment's own notes were not cleaned up")
        return proof

    def test_inferred_expectation_runs_and_confirms_with_a_stated_assumption(self):
        out = self._run(allow_cross=True)
        proof = self._assert_inferred_run(out, "confirmed")
        self.assertEqual(proof["verdict"], "confirmed")
        finding = out.projection["findings"][0]
        self.assertEqual(finding["basis"], "assumed")
        self.assertLess(finding["confidence"], 1.0)
        self.assertIn("assumption", finding["summary"])
        self.assertIn("inferred, not declared", finding["confirmation_assumption"])

    def test_inferred_expectation_correct_app_is_a_controlled_negative(self):
        out = self._run(allow_cross=False)
        proof = self._assert_inferred_run(out, "negative")
        self.assertEqual(proof["verdict"], "controlled_negative")
        self.assertEqual(out.projection["findings"], [])

    def test_control_no_ownership_facts_stays_blocked(self):
        out = self._run(seed=False)
        self.assertEqual(out.result["runs"], 0)
        self.assertEqual(list(out.result["blocked"].values()),
                         [[experiment.missing_expectation("note")]])
        self.assertEqual(out.app.requests, [])

    def test_control_declared_shared_is_not_overridden_by_inference(self):
        out = self._run(expectations=[_note_expectation(object="note", expectation="shared")])
        self.assertEqual(out.result["runs"], 0)
        (missing,) = out.result["blocked"].values()
        self.assertIn("unsupported access expectation 'shared'", missing[0])
        self.assertEqual(len(out.app.requests), out.seeded, "nothing beyond the seed was sent")
        self.assertNotIn("experiment", out.task.meta)

    def test_control_declared_expectation_wins_over_inference(self):
        declared = _note_expectation(object="note")
        declared["delete"] = {"method": "DELETE", "path": "/api/notes/{id}"}
        out = self._run(expectations=[declared])
        self.assertEqual(out.result["runs"], 1, out.result)
        expectation = out.task.meta["experiment"]["access_expectation"]
        self.assertNotIn("inferred", expectation)
        self.assertEqual(expectation["source"], experiment.EXPECTATION_SOURCE)
        self.assertEqual(out.projection["findings"][0]["basis"], "derived")

    def test_control_different_roles_infer_nothing(self):
        out = self._run(bob_role="admin")
        self.assertEqual(out.result["runs"], 0)
        self.assertEqual(list(out.result["blocked"].values()),
                         [[experiment.missing_expectation("note")]])


class InferenceUnitControls(unittest.TestCase):
    def test_ambiguous_object_blocks_inference(self):
        owned = SelfOwnership(persist=False)
        for pid in ("alice", "bob"):    # one object served to two principals: maybe shared
            owned.observe(source="transport", principal_id=pid, method="GET",
                          url="http://app.test/whoami", status=200,
                          response_body=json.dumps({"id": 1 if pid == "alice" else 2}))
        owned._own("http://app.test", "notes", "7", owned._objects[("user", "1")][0], "x")
        owned._own("http://app.test", "notes", "7", owned._objects[("user", "2")][0], "y")
        self.assertIsNone(owned.owned_type("note"))
        self.assertIsNotNone(owned.owned_type("user"))


if __name__ == "__main__":
    unittest.main()
