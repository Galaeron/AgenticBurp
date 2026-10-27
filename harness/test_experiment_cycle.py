"""Ticket G: one graph -> experiment -> workflow -> proof -> graph cycle.

Caller-level. A real ThreadingHTTPServer on 127.0.0.1 plays an application whose
notes are private to their creator; a real RunContext holds two bearer-token
sessions registered the way engagement_builder registers them; an
EngagementState holds an ASM with one object-scoped BusinessObject and an IDOR
hypothesis. The cycle is driven through ChainMixin._run_experiments (and, in the
wiring test, investigate_engagement itself), and every verdict is read back from
the stored proof and the run's own ledger events.

The negative control (scenario 5) disables the graph -> workflow connection and
proves the shared acceptance check (`_assert_cycle`) then raises AssertionError,
so the scenario-1 test is shown to exercise that connection.
"""
from __future__ import annotations

import asyncio
import copy
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

from harness import experiment, experiment_planner, store, task_graph
from harness.application_semantic_model import (ApplicationSemanticModel, BusinessObject,
                                                ChainingHypothesis)
from harness.assessment_health import stored_proof_artifacts_resolve
from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.principals import (AuthzDecision, OwnershipLedger, Principal, declared_reference,
                                object_reference)
from harness.run_context import RunContext
from harness.test_confirmation_soundness_rve import _CallerBase
from harness.test_workflow_engine import _Context, _out
from harness.workflow_engine import (StepResult, StepStatus, Workflow, WorkflowResult,
                                     WorkflowStep, execute_workflow)

_CONFIG = Path(__file__).resolve().parent / "config.yaml"
_GATE = {"active_enabled": True, "allow_mutating_replay": True}
_TOKENS = {"tok-alice": "alice", "tok-bob": "bob"}
_NOTE_ID_BASE, _COMMENT_ID_BASE = 41, 900


class _NotesApp:
    """Owned loopback application. Notes (and comments on a note) belong to their
    creator: the owner reads them, anyone else gets 403 -- unless `allow_cross`,
    the broken-authorization variant. Every request is logged server-side as
    (method, path, user), which is what the zero-send assertions count."""

    def __init__(self, allow_cross: bool = False, soft_deny: bool = False, shape: str = "owner"):
        self.allow_cross = allow_cross
        self.soft_deny = soft_deny      # non-owners get 200 with an error object echoing the id
        # What GET /api/notes/{id} returns: "owner" {id, owner} (the default), "title"
        # {id, title} (no owner field), "typed" {id, type} (nothing per-identity at
        # all), "viewer" {id, title, isOwner, views} (fields that depend on the reader).
        self.shape = shape
        self.requests: list = []
        self.bodies: list = []          # (method, path, user, request body)
        self.titles: dict = {}
        self.views: dict = {}
        self.notes: dict = {}
        self.comments: dict = {}
        self._notes_next, self._comments_next = _NOTE_ID_BASE, _COMMENT_ID_BASE
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _user(self):
                return _TOKENS.get(self.headers.get("Authorization", "").replace("Bearer ", "", 1))

            def _send(self, status, payload=None):
                body = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _begin(self):
                user = self._user()
                length = int(self.headers.get("Content-Length") or 0)
                text = self.rfile.read(length).decode() if length else ""
                app.requests.append((self.command, self.path, user))
                app.bodies.append((self.command, self.path, user, text))
                return user

            def do_POST(self):
                user = self._begin()
                if user is None:
                    return self._send(401, {"error": "login required"})
                if self.path == "/api/notes":
                    nid, app._notes_next = app._notes_next, app._notes_next + 1
                    app.notes[nid] = user
                    try:
                        app.titles[nid] = json.loads(app.bodies[-1][3] or "{}").get("title", "")
                    except ValueError:
                        app.titles[nid] = ""
                    return self._send(201, {"data": {"id": nid, "owner": user}})
                match = re.fullmatch(r"/api/notes/(\d+)/comments", self.path)
                if match and int(match.group(1)) in app.notes:
                    cid, app._comments_next = app._comments_next, app._comments_next + 1
                    app.comments[(int(match.group(1)), cid)] = user
                    return self._send(201, {"data": {"id": cid, "owner": user,
                                                     "note": int(match.group(1))}})
                self._send(404, {"error": "not found"})

            def do_GET(self):
                user = self._begin()
                if user is None:
                    return self._send(401, {"error": "login required"})
                note = re.fullmatch(r"/api/notes/(\d+)", self.path)
                comment = re.fullmatch(r"/api/notes/(\d+)/comments/(\d+)", self.path)
                is_note = bool(note and int(note.group(1)) in app.notes)
                if is_note:
                    owner, ident = app.notes[int(note.group(1))], int(note.group(1))
                elif comment and (int(comment.group(1)), int(comment.group(2))) in app.comments:
                    owner = app.comments[(int(comment.group(1)), int(comment.group(2)))]
                    ident = int(comment.group(2))
                else:
                    return self._send(404, {"error": "not found"})
                if owner != user and not app.allow_cross:
                    if app.soft_deny:
                        echo = {"type": "note"} if is_note and app.shape == "typed" else {}
                        return self._send(200, {"data": {"id": ident, "error": "forbidden", **echo}})
                    return self._send(403, {"error": "forbidden"})
                data = {"id": ident, "owner": owner}
                if is_note and app.shape == "title":
                    data = {"id": ident, "title": app.titles.get(ident, "")}
                elif is_note and app.shape == "typed":
                    data = {"id": ident, "type": "note"}
                elif is_note and app.shape == "viewer":
                    app.views[ident] = app.views.get(ident, 0) + 1
                    data = {"id": ident, "title": app.titles.get(ident, ""),
                            "isOwner": owner == user, "views": app.views[ident]}
                self._send(200, {"data": data})

            def do_DELETE(self):
                user = self._begin()
                note = re.fullmatch(r"/api/notes/(\d+)", self.path)
                if note and app.notes.get(int(note.group(1))) == user:
                    del app.notes[int(note.group(1))]
                    return self._send(204)
                self._send(403, {"error": "forbidden"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


def _note_expectation(**overrides) -> dict:
    declared = {"object": "Note", "expectation": "private_to_creator",
                "create": {"method": "POST", "path": "/api/notes", "body": {"title": "probe"},
                           "id_pointer": "/data/id"},
                "read": {"method": "GET", "path": "/api/notes/{id}"}}
    declared.update(overrides)
    return declared


def _tagged_expectation(**overrides) -> dict:
    """A note whose title carries a per-identity token: `{tag}` is filled with random
    hex unique to the identity and the run, so each identity's note holds content only
    its own create sent."""
    declared = _note_expectation(**overrides)
    declared["create"] = dict(declared["create"], body={"title": "note {tag}"})
    return declared


def _comment_expectation() -> dict:
    """A dependent expectation: a comment lives under a note, so its create and
    read paths need the note id an earlier experiment has to have observed."""
    return {"object": "Comment", "expectation": "private_to_creator",
            "create": {"method": "POST", "path": "/api/notes/{note_id}/comments",
                       "body": {"text": "hello"}, "id_pointer": "/data/id"},
            "read": {"method": "GET", "path": "/api/notes/{note_id}/comments/{id}"}}


def _asm(*, comments: bool = False, other_class: bool = False) -> ApplicationSemanticModel:
    objects = [BusinessObject(name="Note", id_params=["id"], object_scoped=True,
                              read_endpoints=["GET /api/notes/{id}"],
                              write_endpoints=["POST /api/notes"])]
    hypotheses = [ChainingHypothesis(
        id="bch:note-idor", source="IDOR/BOLA on Note", target="payment sink",
        rationale="notes are addressed by id; pivot to the payment sink", rank=0.8,
        classes=["idor", "payment"], endpoints=["GET /api/notes/{id}", "POST /api/notes"])]
    if comments:
        objects.append(BusinessObject(
            name="Comment", id_params=["id"], object_scoped=True,
            read_endpoints=["GET /api/notes/{id}/comments/{id}"],
            write_endpoints=["POST /api/notes/{id}/comments"]))
        hypotheses.append(ChainingHypothesis(
            id="bch:comment-idor", source="IDOR/BOLA on Comment", target="payment sink",
            rationale="comments are addressed by id", rank=0.6, classes=["idor", "payment"],
            endpoints=["GET /api/notes/{id}/comments/{id}", "POST /api/notes/{id}/comments"]))
    if other_class:
        hypotheses.append(ChainingHypothesis(
            id="bch:price", source="client-trusted 'price' in a workflow",
            target="price/quantity manipulation", rationale="price is client supplied",
            rank=0.5, classes=["business_logic", "mass_assignment"],
            endpoints=["POST /api/orders"]))
    return ApplicationSemanticModel(host="127.0.0.1", business_objects=objects,
                                    chaining_hypotheses=hypotheses)


def _register_sessions(run, base: str, *, second: bool = True, bob_permissions=(),
                       extra=()) -> list:
    """Sessions registered as engagement_builder does: roles in order, an
    anonymous one without headers, the rest `principal:{index}:{principal_id}`.
    `bob_permissions` are operator-declared permissions carried by bob's session
    Principal (RoleSession.expected_permissions); `extra` names more identities
    (registered, but the experiment uses the first two)."""
    run.sessions.register("anonymous", "anonymous", {}, allowed_origins=[base])
    run.sessions.register("principal:1:alice", "alice",
                          {"Authorization": "Bearer tok-alice"}, allowed_origins=[base])
    if second:
        run.sessions.register(
            "principal:2:bob", "bob", {"Authorization": "Bearer tok-bob"}, allowed_origins=[base],
            principal=(Principal(id="bob", expected_permissions=frozenset(bob_permissions))
                       if bob_permissions else None))
    for index, name in enumerate(extra, start=3):
        run.sessions.register(f"principal:{index}:{name}", name,
                              {"Authorization": f"Bearer tok-{name}"}, allowed_origins=[base])
    return experiment.run_sessions(run)


class _CycleCase(_CallerBase, unittest.TestCase):
    """Isolated store/cache plus an Orchestrator and the fixture app."""

    def _app(self, allow_cross: bool = False, soft_deny: bool = False,
             shape: str = "owner") -> _NotesApp:
        app = _NotesApp(allow_cross, soft_deny, shape)
        self.addCleanup(app.close)
        return app

    def _cycle(self, app, *, expectations, asm=None, enabled=True, max_runs=4, second=True,
               planner=False, captured=(), prepare=None, authz=None, max_requests=200,
               inject=None, tune=None, bob_permissions=(), extra=()):
        """One `_run_experiments` call inside an entered run. Returns a bundle with
        the job-result dict, the state, the run id and `ledger`: the ENGAGEMENT's
        ownership ledger, read back through `_configure_ownership` exactly as the
        validators read it. Nothing is injected into the validator registry unless
        `inject` (a ledger) is given -- production has none -- so the cycle has to
        find the engagement's ledger itself. `authz` is the operator's `authz`
        config (declared owners); `tune(orch)` adjusts the orchestrator."""
        orch = self._orch(hosts=("127.0.0.1",))
        engagement = orch.config.setdefault("engagement", {})
        engagement["experiments"] = {"enabled": enabled, "max_runs": max_runs, "planner": planner}
        engagement["access_expectations"] = expectations
        if authz is not None:
            orch.config["authz"] = authz
        if inject is not None:
            orch.validator_registry.set_ownership(inject)
        else:
            self.assertIsNone(orch.validator_registry.ownership)
        if tune:
            tune(orch)
        asm = asm if asm is not None else _asm()
        state = EngagementState(host="127.0.0.1")

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=max_requests,
                                         gate_config=_GATE) as run:
                _register_sessions(run, app.base, second=second,
                                   bob_permissions=bob_permissions, extra=extra)
                state.apply_semantic_model(asm)    # the production seam: operator-review tasks
                if prepare:
                    prepare(state, asm, run)
                result = await orch._run_experiments(state, asm, run, base_url=app.base,
                                                     captured=list(captured))
                ledger = orch._configure_ownership(app.base, run_context=run, install=False)
                return run.run_id, result, ledger

        run_id, result, ledger = asyncio.run(go())
        return SimpleNamespace(result=result, state=state, ledger=ledger, run_id=run_id,
                               app=app, orch=orch, asm=asm)

    def _assert_cycle(self, b, *, outcome="negative", verdict="controlled_negative"):
        """The scenario-1/2 acceptance check, shared with the negative control:
        the task is DONE with the proof as its evidence, the proof is persisted,
        its three artifacts are distinct, and each resolves to a successful
        execution event the run's ledger filed under the proof's own case."""
        self.assertIsNotNone(b.result, "the experiment cycle did not run")
        self.assertEqual(b.result["runs"], 1, b.result)
        self.assertEqual(len(b.result["completed"]), 1, b.result)
        done = b.result["completed"][0]
        self.assertEqual(done["outcome"], outcome, done)
        task = b.state.graph.tasks[done["task_id"]]
        self.assertEqual(task.status, task_graph.DONE)
        self.assertEqual(task.meta["outcome"], outcome)
        self.assertEqual(task.evidence_ref, done["proof_id"])
        proofs = store.proofs_for_run(b.run_id)
        self.assertEqual([p["proof_id"] for p in proofs], [done["proof_id"]])
        proof = proofs[0]
        self.assertEqual(proof["verdict"], verdict)
        self.assertTrue(proof["executed"])
        self.assertEqual(proof["validator"], "cross_account_experiment")
        self.assertEqual(proof["validator_version"], "1")
        case = proof["case"]
        self.assertEqual((case["check_id"], case["principal_id"], case["request_template_id"]),
                         ("ATHZ-cross-account", "bob", "GET /api/notes/{id}"))
        self.assertEqual((case["workflow_state_id"], case["finding_ref"]),
                         (done["experiment_id"], "bch:note-idor"))
        refs = [proof["baseline_artifact_id"], proof["attack_artifact_id"],
                *proof["control_artifact_ids"]]
        self.assertEqual(len(refs), 3, proof)
        self.assertEqual(len(set(refs)), 3, "baseline, attack and control must be distinct")
        self.assertEqual(task.meta["artifacts"], {"baseline": refs[0], "attack": refs[1],
                                                  "control": refs[2]})
        self.assertTrue(stored_proof_artifacts_resolve(proof))
        events = store.ledger_events_for(case["case_id"])
        for ref in refs:
            filed = [e for e in events if e["event_type"] == "execution"
                     and e["case_ref"] == case["case_id"]
                     and e["data"].get("artifact_id") == ref and e["data"].get("outcome") == "ok"]
            self.assertEqual(len(filed), 1, f"artifact {ref} is not filed under the proof's case")
        first = _NOTE_ID_BASE
        self.assertEqual(b.app.requests, [
            ("POST", "/api/notes", "alice"), ("POST", "/api/notes", "bob"),
            ("GET", f"/api/notes/{first}", "alice"),      # baseline: owner reads own note
            ("GET", f"/api/notes/{first}", "bob"),        # attack: other reads the owner's note
            ("GET", f"/api/notes/{first + 1}", "bob")])   # control: other reads its own note
        return proof


class PrivateNoteCycleTests(_CycleCase):
    def test_scenario_1_declared_private_note_denied_is_a_controlled_negative(self):
        b = self._cycle(self._app(), expectations=[_note_expectation()])
        proof = self._assert_cycle(b)
        ref = object_reference(f"{b.app.base}/api/notes/{_NOTE_ID_BASE}", run_id=b.run_id)
        # The declared owner is recorded; the other principal stays a denied reader.
        self.assertEqual(b.ledger.lookup(ref).owner_principal_id, "alice")
        self.assertEqual(proof["limitation"], "cleanup: none declared")
        self.assertEqual(b.result["completed"][0]["cleanup"], "none declared")
        self.assertEqual(b.result["blocked"], {})
        chain = b.state.graph.tasks["chain-hypothesis:bch:note-idor"]
        self.assertEqual(chain.status, task_graph.BLOCKED)
        self.assertEqual(chain.meta["experiment_outcome"], "negative")
        self.assertTrue(chain.meta["proposed_only"])

    def test_scenario_2_allow_cross_is_a_confirmed_authorization_failure(self):
        b = self._cycle(self._app(allow_cross=True), expectations=[_note_expectation()])
        proof = self._assert_cycle(b, outcome="confirmed", verdict="confirmed")
        ref = object_reference(f"{b.app.base}/api/notes/{_NOTE_ID_BASE}", run_id=b.run_id)
        self.assertEqual(b.ledger.authorization(Principal(id="bob"), ref), AuthzDecision.UNAUTHORIZED)
        self.assertEqual(b.ledger.authorization(Principal(id="alice"), ref), AuthzDecision.AUTHORIZED)
        fact = b.ledger.lookup(ref)
        self.assertEqual(fact.provenance,
                         "declared private_to_creator; created-as:alice via POST /api/notes")
        self.assertEqual(proof["case"]["principal_id"], "bob")
        # The sink pivot is never auto-run and never confirmed by the experiment.
        chain = b.state.graph.tasks["chain-hypothesis:bch:note-idor"]
        self.assertEqual(chain.status, task_graph.BLOCKED)
        self.assertEqual(chain.meta["experiment_outcome"], "confirmed")
        self.assertTrue(chain.needs.startswith("validated by experiment:"))

    def test_scenario_3_no_declared_expectation_blocks_with_zero_sends(self):
        b = self._cycle(self._app(), expectations=[])
        reason = "no declared access expectation for object 'Note' (engagement.access_expectations)"
        self.assertEqual(b.result["runs"], 0)
        self.assertEqual(b.result["completed"], [])
        self.assertEqual(list(b.result["blocked"].values()), [[reason]])
        task = b.state.graph.tasks[next(iter(b.result["blocked"]))]
        self.assertEqual((task.status, task.needs), (task_graph.BLOCKED, reason))
        self.assertEqual(b.app.requests, [])
        self.assertEqual(b.ledger._by_ref, {})
        self.assertEqual(store.proofs_for_run(b.run_id), [])
        # A successful read is never turned into an expectation: nothing was read.
        chain = b.state.graph.tasks["chain-hypothesis:bch:note-idor"]
        self.assertEqual(chain.status, task_graph.BLOCKED)

    def test_scenario_3_variant_missing_id_pointer_blocks_with_the_extraction_reason(self):
        declared = _note_expectation()
        del declared["create"]["id_pointer"]
        b = self._cycle(self._app(), expectations=[declared])
        self.assertEqual(list(b.result["blocked"].values()),
                         [["no declared id extraction (JSON pointer) for POST /api/notes"]])
        self.assertEqual((b.result["runs"], b.app.requests, b.ledger._by_ref), (0, [], {}))

    def test_one_identity_blocks_with_the_exact_second_identity_reason(self):
        b = self._cycle(self._app(), expectations=[_note_expectation()], second=False)
        self.assertEqual(list(b.result["blocked"].values()),
                         [["no second identity distinct from the owner"]])
        self.assertEqual(b.app.requests, [])

    def test_declared_delete_cleans_up_both_created_notes(self):
        declared = _note_expectation(delete={"method": "DELETE", "path": "/api/notes/{id}"})
        app = self._app()
        b = self._cycle(app, expectations=[declared])
        done = b.result["completed"][0]
        self.assertEqual(done["outcome"], "negative")
        self.assertEqual(done["cleanup"], "completed 2/2 registered cleanup step(s)")
        self.assertEqual(app.notes, {})
        deletes = [r for r in app.requests if r[0] == "DELETE"]
        self.assertEqual(sorted(deletes), sorted([
            ("DELETE", f"/api/notes/{_NOTE_ID_BASE}", "alice"),
            ("DELETE", f"/api/notes/{_NOTE_ID_BASE + 1}", "bob")]))
        proof = store.proofs_for_run(b.run_id)[0]
        self.assertEqual(proof["limitation"], "cleanup: completed 2/2 registered cleanup step(s)")
        self.assertTrue(stored_proof_artifacts_resolve(proof))

    def test_extracted_values_are_observed_but_not_persisted_with_the_task(self):
        b = self._cycle(self._app(), expectations=[_note_expectation()])
        self.assertEqual(b.state.observed_values, {
            "note_id": str(_NOTE_ID_BASE), "note_other_id": str(_NOTE_ID_BASE + 1)})
        self.assertNotIn("observed_values", b.state.to_dict())
        task = next(t for t in b.state.graph.tasks.values() if t.kind == "experiment")
        dumped = json.dumps(task.to_dict())
        self.assertNotIn(f'"{_NOTE_ID_BASE}"', dumped)
        self.assertNotIn(f'"{_NOTE_ID_BASE + 1}"', dumped)
        self.assertEqual(task.meta["workflow"]["values"]["note_id"], "[observed]")


class EngagementLedgerTests(_CycleCase):
    """The cycle consults and feeds the ENGAGEMENT's ownership ledger -- the one
    `_configure_ownership` builds from the operator's `authz.owners` -- not a
    private one. None of these inject a ledger into the validator registry
    (except the one that proves an injected ledger is honoured)."""

    @staticmethod
    def _authz(app, entry):
        return {"owners": {app.base.split("//", 1)[1]: [entry]}}

    def _ref(self, b, note=_NOTE_ID_BASE):
        return object_reference(f"{b.app.base}/api/notes/{note}", run_id=b.run_id)

    def test_without_declarations_the_fact_lands_in_the_engagement_ledger(self):
        b = self._cycle(self._app(), expectations=[_note_expectation()])
        self._assert_cycle(b)
        fact = b.ledger.lookup(self._ref(b))
        self.assertEqual((fact.owner_principal_id, fact.provenance), (
            "alice", "declared private_to_creator; created-as:alice via POST /api/notes"))

    def test_a_ledger_injected_into_the_registry_is_the_one_used(self):
        injected = OwnershipLedger()
        b = self._cycle(self._app(), expectations=[_note_expectation()], inject=injected)
        self._assert_cycle(b)
        self.assertIs(b.ledger, injected)
        self.assertEqual(injected.lookup(self._ref(b)).owner_principal_id, "alice")

    def test_a_declared_entitlement_blocks_confirmation_and_records_no_fact(self):
        entries = {
            "any authenticated account": {"path": "/api/notes/{id}", "authenticated": True},
            "explicitly shared": {"path": "/api/notes/{id}", "owner": "alice",
                                  "shared_with": ["bob"]},
            "public": {"path": "/api/notes/{id}", "public": True},
        }
        for name, entry in entries.items():
            with self.subTest(name):
                app = self._app(allow_cross=True)     # the fixture lets bob read: a reachable read
                b = self._cycle(app, expectations=[_note_expectation()],
                                authz=self._authz(app, entry))
                self.assertEqual(b.result["completed"], [], b.result)
                failed = b.result["failed"][0]
                self.assertEqual(failed["outcome"], "inconclusive")
                self.assertEqual(failed["reason"], "the ownership ledger already holds a "
                                                   "conflicting declaration for this object")
                task = b.state.graph.tasks[failed["task_id"]]
                self.assertEqual(task.status, task_graph.FAILED)
                self.assertNotEqual(task.meta["outcome"], "confirmed")
                proof = store.proofs_for_run(b.run_id)[0]
                self.assertEqual(proof["verdict"], "inconclusive")
                # No new fact: the ledger holds the operator's declaration and nothing else.
                self.assertEqual(b.ledger._by_ref, {})
                self.assertTrue(b.ledger.lookup(self._ref(b)).provenance.startswith(
                    "config authz.owners"))
                self.assertEqual(b.ledger.authorization(Principal(id="bob"), self._ref(b)),
                                 AuthzDecision.AUTHORIZED)

    def test_contradictory_declarations_do_not_confirm_and_record_nothing(self):
        # Two equally specific entries for one path, one public and one owned: the
        # ledger's lookup() is None for that, which is NOT "nothing declared".
        app = self._app(allow_cross=True)
        authz = {"owners": {app.base.split("//", 1)[1]: [
            {"path": "/api/notes/{id}", "public": True},
            {"path": "/api/notes/{id}", "owner": "alice"}]}}
        b = self._cycle(app, expectations=[_note_expectation()], authz=authz)
        ref = self._ref(b)
        self.assertIsNone(b.ledger.lookup(ref))
        self.assertTrue(b.ledger.has_declaration(ref))
        self.assertEqual(b.result["completed"], [], b.result)
        failed = b.result["failed"][0]
        self.assertEqual((failed["outcome"], failed["reason"]),
                         ("inconclusive", "contradictory operator declarations"))
        self.assertEqual(b.state.graph.tasks[failed["task_id"]].status, task_graph.FAILED)
        self.assertEqual(store.proofs_for_run(b.run_id)[0]["verdict"], "inconclusive")
        self.assertEqual(b.ledger._by_ref, {})         # no fact over the contradiction
        self.assertIsNone(b.ledger.lookup(ref))

    def test_a_denial_under_contradictory_declarations_is_negative_and_records_no_fact(self):
        app = self._app()           # bob is denied
        authz = {"owners": {app.base.split("//", 1)[1]: [
            {"path": "/api/notes/{id}", "public": True},
            {"path": "/api/notes/{id}", "owner": "alice"}]}}
        b = self._cycle(app, expectations=[_note_expectation()], authz=authz)
        self.assertEqual(b.result["failed"], [])
        self.assertEqual(b.result["completed"][0]["outcome"], "negative")
        self.assertEqual(store.proofs_for_run(b.run_id)[0]["verdict"], "controlled_negative")
        ref = self._ref(b)
        self.assertEqual(b.ledger._by_ref, {})          # no fact recorded over the contradiction
        self.assertIsNone(b.ledger.lookup(ref))
        self.assertTrue(b.ledger.has_declaration(ref))

    def test_an_undeclared_object_has_no_declaration(self):
        ledger = OwnershipLedger()
        self.assertFalse(ledger.has_declaration(
            "run:r|app:http://127.0.0.1:1|tenant:?|resource:/api/notes/41"))

    def test_a_declared_owner_other_than_the_creator_is_a_conflict(self):
        app = self._app(allow_cross=True)
        b = self._cycle(app, expectations=[_note_expectation()], extra=("carol",),
                        authz=self._authz(app, {"path": "/api/notes/{id}", "owner": "carol"}))
        failed = b.result["failed"][0]
        self.assertEqual((failed["outcome"], failed["reason"]), (
            "inconclusive", "the ownership ledger already holds a conflicting declaration "
                            "for this object"))
        self.assertEqual(b.ledger.lookup(self._ref(b)).owner_principal_id, "carol")
        self.assertEqual(b.ledger._by_ref, {})

    def test_a_permission_declared_for_the_sessions_principal_blocks_confirmation(self):
        # alice is the declared owner; bob's SESSION principal carries an operator-
        # declared permission for this object's declared reference.
        app = self._app(allow_cross=True)
        grant = declared_reference(f"{app.base}/api/notes/{_NOTE_ID_BASE}")
        b = self._cycle(app, expectations=[_note_expectation()], bob_permissions=[grant],
                        authz=self._authz(app, {"path": "/api/notes/{id}", "owner": "alice"}))
        failed = b.result["failed"][0]
        self.assertEqual((failed["outcome"], failed["reason"]), (
            "inconclusive", "the ownership ledger already holds a conflicting declaration "
                            "for this object"))
        self.assertEqual(store.proofs_for_run(b.run_id)[0]["verdict"], "inconclusive")
        self.assertEqual(b.ledger._by_ref, {})

    def test_the_final_ledger_check_catches_a_permission_unseen_before_recording(self):
        # Nothing is declared, so before the experiment records its fact the ledger
        # says UNKNOWN about bob. Once the owner is recorded, bob's declared
        # permission (on the run-agnostic reference) makes him AUTHORIZED: the read is
        # not a demonstrated crossing, and the proof must not say it is.
        app = self._app(allow_cross=True)
        grant = declared_reference(f"{app.base}/api/notes/{_NOTE_ID_BASE}")
        b = self._cycle(app, expectations=[_note_expectation()], bob_permissions=[grant])
        failed = b.result["failed"][0]
        self.assertEqual((failed["outcome"], failed["reason"]), (
            "inconclusive", "the ownership ledger does not establish the read as an "
                            "unauthorized crossing"))
        self.assertEqual(b.state.graph.tasks[failed["task_id"]].status, task_graph.FAILED)
        self.assertEqual(store.proofs_for_run(b.run_id)[0]["verdict"], "inconclusive")
        self.assertEqual(b.ledger.authorization(
            Principal(id="bob", expected_permissions=frozenset([grant])), self._ref(b)),
            AuthzDecision.AUTHORIZED)

    def test_the_cached_ledger_is_reused_when_the_engagement_has_no_owners(self):
        # `state.owners` is [] until something declares owners. A holder of the
        # engagement's ledger (the cross-identity validator) must keep seeing what
        # the cycle records: the cycle may not rebuild and replace it.
        app = self._app()
        held, orchs = {}, []

        def prepare(state, asm, run):
            held["ledger"] = orchs[0]._configure_ownership(app.base, run_context=run, install=False)
        b = self._cycle(app, expectations=[_note_expectation()], prepare=prepare,
                        tune=orchs.append,
                        authz=self._authz(app, {"path": "/api/other/{id}", "owner": "alice"}))
        self.assertIsNotNone(held["ledger"])
        self.assertEqual(len(held["ledger"]._patterns), 1)
        self.assertIs(b.ledger, held["ledger"])
        self.assertEqual(held["ledger"].lookup(self._ref(b)).owner_principal_id, "alice")
        self._assert_cycle(b)

    def test_a_declaration_that_agrees_with_the_expectation_still_confirms(self):
        app = self._app(allow_cross=True)
        b = self._cycle(app, expectations=[_note_expectation()],
                        authz=self._authz(app, {"path": "/api/notes/{id}", "owner": "alice"}))
        self._assert_cycle(b, outcome="confirmed", verdict="confirmed")
        self.assertEqual(b.ledger._by_ref, {})      # the operator's declaration was enough
        self.assertEqual(b.ledger.authorization(Principal(id="bob"), self._ref(b)),
                         AuthzDecision.UNAUTHORIZED)

    def test_a_denial_under_a_declared_entitlement_adds_no_fact_over_the_declaration(self):
        app = self._app()
        b = self._cycle(app, expectations=[_note_expectation()],
                        authz=self._authz(app, {"path": "/api/notes/{id}", "authenticated": True}))
        self.assertEqual(b.result["completed"][0]["outcome"], "negative")
        self.assertEqual(b.ledger._by_ref, {})


class UnsentWorkTests(_CycleCase):
    """A proof is `executed`, and cites an exchange, only for a step that was sent."""

    def test_budget_exhausted_at_the_baseline_is_not_an_executed_proof(self):
        app = self._app()
        b = self._cycle(app, expectations=[_note_expectation()], max_requests=2)
        failed = b.result["failed"][0]
        self.assertEqual(b.result["completed"], [])
        self.assertEqual(failed["outcome"], "inconclusive")
        self.assertIn("baseline did not complete", failed["reason"])
        self.assertIn("budget_exhausted", failed["reason"])
        proof = store.proofs_for_run(b.run_id)[0]
        self.assertEqual(proof["verdict"], "inconclusive")
        self.assertIs(proof["executed"], False)
        self.assertEqual((proof["baseline_artifact_id"], proof["attack_artifact_id"],
                          proof["control_artifact_ids"]), ("", "", []))
        self.assertEqual(failed["artifacts"], {"baseline": "", "attack": "", "control": ""})
        self.assertEqual([r[0] for r in app.requests], ["POST", "POST"])    # setup only
        # The transport did record exchange artifacts for the refused sends; the
        # proof must not cite them.
        steps = {st["step_id"]: st for st in
                 b.state.graph.tasks[failed["task_id"]].meta["workflow"]["steps"]}
        self.assertEqual(steps["baseline"]["status"], "blocked")
        self.assertTrue(steps["baseline"]["artifact_id"])
        self.assertTrue(steps["control"]["artifact_id"])

    def _plan(self):
        asm = _asm()
        return experiment.translate_cross_account(
            asm.chaining_hypotheses[0], asm, [_note_expectation()], TranslateTests.SESSIONS, {},
            base_url="http://127.0.0.1:9")

    def test_a_gate_blocked_baseline_and_control_are_not_an_executed_proof(self):
        ctx = _Context([_out(201, '{"data": {"id": 41}}'), _out(201, '{"data": {"id": 42}}'),
                        _out(None, outcome="blocked"),       # baseline refused by the gate
                        _out(None, outcome="blocked")])      # control refused by the gate
        ctx.run_id = "scripted-gate-run"
        done = asyncio.run(experiment.run_experiment(
            self._plan().experiment, ctx, ledger=OwnershipLedger()))
        steps = {s.step_id: s for s in done.workflow.steps}
        self.assertEqual(steps["baseline"].status.value, "blocked")
        self.assertEqual(steps["baseline"].artifact_id, "a-None")     # the engine saw an artifact...
        self.assertEqual(done.outcome, "inconclusive")
        self.assertIs(done.proof.executed, False)                       # ...the proof cites none
        self.assertEqual((done.proof.baseline_artifact_id, done.proof.attack_artifact_id,
                          done.proof.control_artifact_ids), ("", "", ()))
        stored = store.proofs_for_run("scripted-gate-run")[0]
        self.assertIs(stored["executed"], False)
        self.assertEqual(stored["verdict"], "inconclusive")

    def test_a_partly_sent_run_cites_only_what_was_sent(self):
        ctx = _Context([_out(201, '{"data": {"id": 41}}'), _out(201, '{"data": {"id": 42}}'),
                        _out(200, '{"data": {"id": 41}}'),        # baseline sent
                        _out(None, outcome="budget_exhausted"),   # attack refused
                        _out(None, outcome="budget_exhausted")])  # control refused
        ctx.run_id = "scripted-partial-run"
        done = asyncio.run(experiment.run_experiment(
            self._plan().experiment, ctx, ledger=OwnershipLedger()))
        self.assertEqual(done.outcome, "inconclusive")
        self.assertIs(done.proof.executed, True)
        self.assertEqual(done.proof.baseline_artifact_id, "a-200")
        self.assertEqual((done.proof.attack_artifact_id, done.proof.control_artifact_ids), ("", ()))


class SoftDenyTests(_CycleCase):
    def test_a_200_error_object_that_echoes_the_id_is_not_a_confirmation(self):
        app = self._app(soft_deny=True)
        b = self._cycle(app, expectations=[_note_expectation()])
        self.assertEqual(b.result["completed"], [], b.result)
        failed = b.result["failed"][0]
        self.assertEqual(failed["outcome"], "inconclusive")
        self.assertEqual(failed["reason"],
                         "the attack response carries the id but not the owner's object")
        self.assertEqual(app.requests[3], ("GET", f"/api/notes/{_NOTE_ID_BASE}", "bob"))
        task = b.state.graph.tasks[failed["task_id"]]
        self.assertEqual(task.status, task_graph.FAILED)
        self.assertEqual(store.proofs_for_run(b.run_id)[0]["verdict"], "inconclusive")
        self.assertEqual(b.ledger._by_ref, {})
        # No observed value (id, marker or object) in the persisted task.
        dumped = json.dumps(task.to_dict())
        for leaked in (f'"{_NOTE_ID_BASE}"', f'"{_NOTE_ID_BASE + 1}"', "forbidden"):
            self.assertNotIn(leaked, dumped)

    def test_the_deliberate_cross_access_fixture_is_still_confirmed(self):
        b = self._cycle(self._app(allow_cross=True), expectations=[_note_expectation()])
        self._assert_cycle(b, outcome="confirmed", verdict="confirmed")


class JudgeObjectMatchTests(unittest.TestCase):
    @staticmethod
    def _result(owner_object, attack_object, control_object="", attack=200):
        return WorkflowResult("w", 1, steps=[
            StepResult("baseline", StepStatus.PASSED, "", 200, "a",
                       {"owner_marker": "41", "owner_object": owner_object}),
            StepResult("attack", StepStatus.PASSED, "", attack, "b",
                       {"attack_marker": "41", "attack_object": attack_object}),
            StepResult("control", StepStatus.PASSED, "", 200, "c",
                       {"control_marker": "42", "control_object": control_object})])

    def _judge(self, owner_object, attack_object, control_object="", **kw):
        return experiment.judge(self._result(owner_object, attack_object, control_object),
                                "41", **kw)

    NOTHING_TO_COMPARE = "no distinctive content to compare"
    NOT_THE_OBJECT = "the attack response carries the id but not the owner's object"

    def test_an_object_of_only_its_id_and_volatile_keys_proves_nothing(self):
        j = self._judge('{"id":41,"createdAt":"t1","updatedAt":"t1"}',
                        '{"id":41,"error":"forbidden"}', match_object=True)
        self.assertEqual(j.outcome, "inconclusive")
        self.assertIn(self.NOTHING_TO_COMPARE, j.reason)

    def test_a_missing_key_is_not_a_null(self):
        # (b) null is trivial, so `{"id":41,"title":null}` has nothing to compare ...
        j = self._judge('{"id":41,"title":null}', '{"id":41}', match_object=True)
        self.assertEqual(j.outcome, "inconclusive")
        self.assertIn(self.NOTHING_TO_COMPARE, j.reason)
        # ... and with content to compare, an absent key still does not match a null.
        owner = '{"id":41,"owner":"alice","title":null}'
        j = self._judge(owner, '{"id":41,"owner":"alice"}', match_object=True)
        self.assertEqual((j.outcome, j.reason), ("inconclusive", self.NOT_THE_OBJECT))
        self.assertEqual(self._judge(owner, '{"id":41,"owner":"alice","title":null}',
                                     match_object=True).outcome, "confirmed")

    def test_trivial_values_cannot_be_matched_by_echoing_them(self):
        for owner in ('{"id":41,"shared":false}', '{"id":41,"note":""}',
                      '{"id":41,"note":null,"shared":false,"label":""}'):
            with self.subTest(owner=owner):
                j = self._judge(owner, owner, match_object=True)    # the attack echoes it all
                self.assertEqual(j.outcome, "inconclusive")
                self.assertIn(self.NOTHING_TO_COMPARE, j.reason)

    def test_a_zero_or_a_string_is_content_but_the_marker_itself_is_not(self):
        self.assertEqual(self._judge('{"id":41,"count":0}', '{"id":41,"count":0}',
                                     match_object=True).outcome, "confirmed")
        # marker_key: a body whose only non-trivial leaf IS the marker has nothing else.
        self.assertIn(self.NOTHING_TO_COMPARE, self._judge(
            '{"uid":41,"shared":false}', '{"uid":41,"shared":false}', match_object=True,
            marker_key="uid").reason)

    def test_only_content_that_differs_from_the_others_own_object_counts(self):
        owner, control = '{"id":41,"type":"note","owner":"alice"}', '{"id":42,"type":"note","owner":"bob"}'
        self.assertEqual(self._judge(owner, owner, control, match_object=True).outcome, "confirmed")
        # Everything but the id is shared with the other principal's own object: an echo
        # of it cannot show the owner's object was returned.
        shared = '{"id":41,"type":"note"}'
        j = self._judge(shared, shared, '{"id":42,"type":"note"}', match_object=True)
        self.assertEqual(j.outcome, "inconclusive")
        self.assertIn(self.NOTHING_TO_COMPARE, j.reason)
        # With no control object to contrast with, the non-trivial leaf is accepted.
        self.assertEqual(self._judge(shared, shared, match_object=True).outcome, "confirmed")

    def test_the_owners_object_with_volatile_keys_and_extras_is_confirmed(self):
        owner = '{"id":41,"owner":"alice","updatedAt":"t1","modified_at":"t1","timestamp":1}'
        attack = '{"id":41,"owner":"alice","updatedAt":"t2","modified_at":"t2","timestamp":2,"extra":1}'
        self.assertEqual(self._judge(owner, attack, match_object=True).outcome, "confirmed")

    def test_a_whole_body_object_is_read_back(self):
        # json_pointer("") renders a dict with str(); the judge reads that form too.
        self.assertEqual(self._judge("{'id': 41, 'owner': 'alice'}", '{"id":41,"owner":"alice"}',
                                     match_object=True).outcome, "confirmed")

    def test_an_error_object_echoing_the_id_is_inconclusive(self):
        for attack in ('{"id":41,"error":"forbidden"}', '{"id":41}', "",
                       '{"id":41,"owner":"mallory"}', '["id", 41]'):
            with self.subTest(attack=attack):
                j = self._judge('{"id":41,"owner":"alice"}', attack, match_object=True)
                self.assertEqual(j.outcome, "inconclusive")
                self.assertEqual(j.reason,
                                 "the attack response carries the id but not the owner's object")

    def test_nested_leaves_and_lists_are_compared_in_place(self):
        owner = '{"id":41,"meta":{"tags":["a","b"],"owner":"alice"}}'
        self.assertEqual(self._judge(owner, '{"id":41,"meta":{"tags":["a","b","c"],"owner":"alice"}}',
                                     match_object=True).outcome, "confirmed")
        self.assertEqual(self._judge(owner, '{"id":41,"meta":{"tags":["a","x"],"owner":"alice"}}',
                                     match_object=True).outcome, "inconclusive")

    def test_a_baseline_without_an_object_is_inconclusive(self):
        j = self._judge("", '{"id":41}', match_object=True)
        self.assertEqual((j.outcome, j.reason), (
            "inconclusive", "baseline response carries no object at the marker's parent"))

    def test_viewer_relative_fields_do_not_turn_a_real_leak_into_inconclusive(self):
        owner = '{"id":41,"title":"note TAGA","isOwner":true,"views":3}'
        control = '{"id":42,"title":"note TAGB","isOwner":true,"views":0}'
        leaked = '{"id":41,"title":"note TAGA","isOwner":false,"views":4}'
        j = self._judge(owner, leaked, control, match_object=True, owner_tag="TAGA")
        self.assertEqual((j.outcome, j.needs_tag), ("confirmed", False), j.reason)
        # Without a tag the counter differs from the control's, so it is "content"
        # and a reader-dependent value cannot match: the conservative answer.
        self.assertEqual(self._judge(owner, leaked, control, match_object=True).outcome,
                         "inconclusive")
        # The distinctive leaf is still required, and every key must still be present.
        for attack in ('{"id":41,"title":"note OTHER","isOwner":false,"views":4}',
                       '{"id":41,"title":"note TAGA","views":4}'):
            with self.subTest(attack=attack):
                self.assertEqual(self._judge(owner, attack, control, match_object=True,
                                             owner_tag="TAGA").outcome, "inconclusive")

    def test_masked_content_under_the_owners_metadata_is_not_a_leak(self):
        # Both creates sent the same body, so only the server's ownerId differs from
        # the other's own object. A response that keeps it while nulling or masking
        # the content shows metadata, not the owner's object.
        owner = '{"id":41,"title":"note","body":"text","ownerId":"alice"}'
        control = '{"id":42,"title":"note","body":"text","ownerId":"bob"}'
        for masked in ('{"id":41,"title":null,"body":null,"ownerId":"alice"}',
                       '{"id":41,"title":"***","body":"***","ownerId":"alice"}'):
            with self.subTest(masked=masked):
                j = self._judge(owner, masked, control, match_object=True)
                self.assertEqual((j.outcome, j.reason), ("inconclusive", self.NOT_THE_OBJECT))
        self.assertEqual(self._judge(owner, owner, control, match_object=True).outcome,
                         "confirmed")
        tagged_owner = '{"id":41,"title":"note TAGA","body":"secret","ownerId":"alice"}'
        tagged_control = '{"id":42,"title":"note TAGB","body":"other","ownerId":"bob"}'
        for masked in ('{"id":41,"title":null,"body":null,"ownerId":"alice"}',
                       '{"id":41,"title":"***","body":"***","ownerId":"alice"}'):
            with self.subTest(tagged=masked):
                self.assertEqual(self._judge(tagged_owner, masked, tagged_control,
                                             match_object=True, owner_tag="TAGA").outcome,
                                 "inconclusive")

    def test_a_tag_the_attack_lacks_is_a_soft_denial(self):
        owner, control = '{"id":41,"title":"note TAGA"}', '{"id":42,"title":"note TAGB"}'
        j = self._judge(owner, '{"id":41,"error":"forbidden"}', control, match_object=True,
                        owner_tag="TAGA")
        self.assertEqual((j.outcome, j.reason), ("inconclusive", self.NOT_THE_OBJECT))
        # Another principal's token in the response is not the owner's object either.
        j = self._judge(owner, '{"id":41,"title":"note TAGB"}', control, match_object=True,
                        owner_tag="TAGA")
        self.assertEqual((j.outcome, j.reason), ("inconclusive", self.NOT_THE_OBJECT))

    def test_nothing_to_compare_is_reported_as_needing_a_tag(self):
        shared = '{"id":41,"type":"note"}'
        j = self._judge(shared, shared, '{"id":42,"type":"note"}', match_object=True)
        self.assertEqual((j.outcome, j.needs_tag), ("inconclusive", True))
        # A denial needs no content to compare.
        denied = experiment.judge(self._result(shared, "", '{"id":42,"type":"note"}', attack=403),
                                  "41", match_object=True)
        self.assertEqual(denied.outcome, "negative")

    def test_an_explicit_marker_pointer_does_not_need_the_object_check(self):
        self.assertEqual(self._judge("", "", match_object=False).outcome, "confirmed")


class TagTests(_CycleCase):
    """Objects with no owner field: the two creates are made distinguishable by a
    per-identity `{tag}` in the declared create body."""

    TAG_REASON = ("the create body needs a per-identity {tag} field to distinguish the two "
                  "objects")

    def _titles(self, app):
        posts = [t for m, path, user, t in app.bodies if m == "POST"]
        return [json.loads(t)["title"] for t in posts]

    def test_allow_cross_with_a_tag_confirms_on_an_object_that_has_only_id_and_title(self):
        app = self._app(allow_cross=True, shape="title")
        b = self._cycle(app, expectations=[_tagged_expectation()])
        self._assert_cycle(b, outcome="confirmed", verdict="confirmed")
        owner_title, other_title = self._titles(app)
        tokens = [re.fullmatch(r"note ([0-9a-f]{12,})", t) for t in (owner_title, other_title)]
        self.assertTrue(all(tokens), (owner_title, other_title))
        self.assertNotEqual(tokens[0].group(1), tokens[1].group(1))   # unique per identity
        self.assertGreaterEqual(len(tokens[0].group(1)), 12)
        ref = object_reference(f"{app.base}/api/notes/{_NOTE_ID_BASE}", run_id=b.run_id)
        self.assertEqual(b.ledger.authorization(Principal(id="bob"), ref),
                         AuthzDecision.UNAUTHORIZED)

    def test_the_tokens_are_fresh_for_every_run(self):
        first = self._app(allow_cross=True, shape="title")
        self._cycle(first, expectations=[_tagged_expectation()])
        second = self._app(allow_cross=True, shape="title")
        self._cycle(second, expectations=[_tagged_expectation()])
        self.assertFalse(set(self._titles(first)) & set(self._titles(second)))

    def test_a_soft_deny_echoing_id_and_error_stays_inconclusive_with_a_tag(self):
        app = self._app(soft_deny=True, shape="title")
        b = self._cycle(app, expectations=[_tagged_expectation()])
        self.assertEqual(b.result["completed"], [])
        failed = b.result["failed"][0]
        self.assertEqual((failed["outcome"], failed["reason"]), (
            "inconclusive", "the attack response carries the id but not the owner's object"))
        self.assertEqual(b.result["blocked"], {})
        self.assertEqual(b.ledger._by_ref, {})

    def test_without_the_tag_the_experiment_is_blocked_on_that_exact_input(self):
        app = self._app(allow_cross=True, shape="title")
        b = self._cycle(app, expectations=[_note_expectation()])      # both creates send "probe"
        self.assertEqual(b.result["runs"], 1)
        self.assertEqual((b.result["completed"], b.result["failed"]), ([], []))
        (task_id, missing), = b.result["blocked"].items()
        self.assertEqual(missing, [self.TAG_REASON])
        task = b.state.graph.tasks[task_id]
        self.assertEqual((task.status, task.needs), (task_graph.BLOCKED, self.TAG_REASON))
        self.assertEqual(task.meta["outcome"], "inconclusive")
        proof = store.proofs_for_run(b.run_id)[0]
        self.assertEqual(proof["verdict"], "inconclusive")
        self.assertEqual(b.ledger._by_ref, {})
        # The loop does not run it again: the re-evaluation keeps it blocked.
        self.assertEqual(len([r for r in app.requests if r[0] == "POST"]), 2)
        chain = b.state.graph.tasks["chain-hypothesis:bch:note-idor"]
        self.assertEqual(chain.status, task_graph.BLOCKED)

    def test_a_denial_needs_no_tag(self):
        # The attack is denied, so there is no content to compare: still a negative.
        b = self._cycle(self._app(shape="title"), expectations=[_note_expectation()])
        self.assertEqual(b.result["blocked"], {})
        self.assertEqual(b.result["completed"][0]["outcome"], "negative")

    def test_a_declared_marker_pointer_works_with_the_tag(self):
        # marker_pointer already names the field that holds the per-identity marker;
        # the tag is what makes that field differ between the two identities.
        app = self._app(allow_cross=True, shape="title")
        tagged = _tagged_expectation(marker_pointer="/data/title")
        b = self._cycle(app, expectations=[tagged])
        self._assert_cycle(b, outcome="confirmed", verdict="confirmed")
        # Without the tag the marker is the same for both identities: blocked on it.
        app = self._app(allow_cross=True, shape="title")
        b = self._cycle(app, expectations=[_note_expectation(marker_pointer="/data/title")])
        self.assertEqual(list(b.result["blocked"].values()), [[self.TAG_REASON]])

    def test_viewer_relative_fields_do_not_block_a_real_leak(self):
        app = self._app(allow_cross=True, shape="viewer")
        b = self._cycle(app, expectations=[_tagged_expectation()])
        self._assert_cycle(b, outcome="confirmed", verdict="confirmed")

    def test_a_field_equal_for_both_identities_is_not_content(self):
        # {id, type:"note"}: nothing per-identity; the tag is declared but the server
        # never returns it. A soft-deny echoing `type` must not confirm.
        app = self._app(soft_deny=True, shape="typed")
        b = self._cycle(app, expectations=[_tagged_expectation()])
        self.assertEqual(b.result["completed"], [])
        failed = b.result["failed"][0]
        self.assertEqual(failed["outcome"], "inconclusive")
        self.assertIn("no distinctive content to compare", failed["reason"])
        self.assertEqual(b.ledger._by_ref, {})


class DependentExperimentTests(_CycleCase):
    EXPECTATIONS = [_note_expectation(), _comment_expectation()]

    def test_scenario_4_dependent_experiment_unblocks_on_an_observed_value_in_the_same_loop(self):
        seen = {}

        def before(state, asm, run):
            # Before anything runs the dependent task waits on exactly one value.
            experiment.evaluate_experiments(
                state, asm, self.EXPECTATIONS, experiment.run_sessions(run), {},
                base_url=run_base[0])
            dependent = [t for t in state.graph.tasks.values()
                         if t.kind == "experiment" and t.meta["object"] == "Comment"][0]
            seen["status"], seen["needs"] = dependent.status, dependent.needs
            seen["id"] = dependent.id
            seen["meta_keys"] = set(dependent.meta)

        app = self._app()
        run_base = [app.base]
        b = self._cycle(app, expectations=self.EXPECTATIONS, asm=_asm(comments=True),
                        prepare=before)
        self.assertEqual(seen["status"], task_graph.BLOCKED)
        self.assertEqual(seen["needs"], "value 'note_id' not yet observed")
        self.assertEqual(b.result["runs"], 2, b.result)
        self.assertEqual([c["outcome"] for c in b.result["completed"]], ["negative", "negative"])
        dependent = b.state.graph.tasks[seen["id"]]
        self.assertEqual((dependent.status, dependent.needs), (task_graph.DONE, ""))
        self.assertEqual(b.result["blocked"], {})
        # While blocked it carried the missing list; once released that is gone and
        # the task carries the experiment it ran.
        self.assertTrue({"missing", "unblock"} <= seen["meta_keys"])
        self.assertNotIn("experiment", seen["meta_keys"])
        self.assertNotIn("missing", dependent.meta)
        self.assertNotIn("unblock", dependent.meta)
        self.assertEqual(dependent.meta["experiment"]["id"], dependent.target)
        note = _NOTE_ID_BASE
        # The comment experiment ran after the note one, bound to the OBSERVED note id.
        self.assertEqual(b.app.requests[5:], [
            ("POST", f"/api/notes/{note}/comments", "alice"),
            ("POST", f"/api/notes/{note}/comments", "bob"),
            ("GET", f"/api/notes/{note}/comments/{_COMMENT_ID_BASE}", "alice"),
            ("GET", f"/api/notes/{note}/comments/{_COMMENT_ID_BASE}", "bob"),
            ("GET", f"/api/notes/{note}/comments/{_COMMENT_ID_BASE + 1}", "bob")])
        for proof in store.proofs_for_run(b.run_id):
            self.assertEqual(proof["verdict"], "controlled_negative")
            self.assertTrue(stored_proof_artifacts_resolve(proof))

    def test_a_dependency_on_two_values_is_released_by_the_re_evaluation(self):
        # needs = two values, so no single-value release applies: only the
        # re-evaluation after the run can make the dependent experiment READY.
        dependent = _comment_expectation()
        dependent["create"]["body"] = {"text": "hello", "about": "{note_other_id}"}
        app = self._app()
        seen = {}

        def before(state, asm, run):
            experiment.evaluate_experiments(state, asm, [_note_expectation(), dependent],
                                            experiment.run_sessions(run), {}, base_url=app.base)
            task = [t for t in state.graph.tasks.values()
                    if t.kind == "experiment" and t.meta["object"] == "Comment"][0]
            seen["needs"] = task.needs
        b = self._cycle(app, expectations=[_note_expectation(), dependent],
                        asm=_asm(comments=True), prepare=before)
        self.assertEqual(seen["needs"], "value 'note_id' not yet observed; "
                                        "value 'note_other_id' not yet observed")
        self.assertEqual(b.result["runs"], 2, b.result)
        self.assertEqual(b.result["blocked"], {})

    def test_dependent_experiment_stays_blocked_when_nothing_provides_its_value(self):
        # Only the dependent expectation is declared: nothing ever observes note_id.
        b = self._cycle(self._app(), expectations=[_comment_expectation()],
                        asm=_asm(comments=True))
        blocked = b.result["blocked"]
        self.assertIn(["value 'note_id' not yet observed"], blocked.values())
        self.assertEqual(b.result["runs"], 0)
        self.assertEqual(b.app.requests, [])

    def test_max_runs_bounds_the_loop_and_reports_the_deferred_experiment(self):
        b = self._cycle(self._app(), expectations=self.EXPECTATIONS, asm=_asm(comments=True),
                        max_runs=1)
        self.assertEqual(b.result["runs"], 1)
        self.assertEqual(len(b.result["deferred"]), 1)
        self.assertTrue(all("/comments" not in r[1] for r in b.app.requests))


class NegativeControlTests(_CycleCase):
    """Scenario 5. Break the graph -> workflow connection two different ways; the
    SAME acceptance check the scenario-1 test calls must then raise."""

    def test_scenario_5_control_a_no_op_compiler_fails_the_acceptance_check(self):
        with patch.object(experiment.Experiment, "to_workflow",
                          lambda self, case_ref="": Workflow("noop", ())):
            b = self._cycle(self._app(), expectations=[_note_expectation()])
        self.assertEqual(b.app.requests, [])
        with self.assertRaises(AssertionError):
            self._assert_cycle(b)

    def test_scenario_5_control_b_a_no_op_dispatch_fails_the_acceptance_check(self):
        from harness.orchestrator_chain import ChainMixin
        with patch.object(ChainMixin, "_run_experiments", AsyncMock(return_value=None)):
            b = self._cycle(self._app(), expectations=[_note_expectation()])
        self.assertIsNone(b.result)
        self.assertEqual(b.app.requests, [])
        with self.assertRaises(AssertionError):
            self._assert_cycle(b)

    def test_disabled_flag_sends_nothing_even_with_a_declared_expectation(self):
        b = self._cycle(self._app(), expectations=[_note_expectation()], enabled=False)
        self.assertIsNone(b.result)
        self.assertEqual(b.app.requests, [])
        self.assertEqual(store.proofs_for_run(b.run_id), [])

    def test_no_owning_run_means_no_experiments(self):
        orch = self._orch(hosts=("127.0.0.1",))
        orch.config.setdefault("engagement", {})["experiments"] = {"enabled": True}
        self.assertIsNone(asyncio.run(orch._run_experiments(
            EngagementState(host="x"), _asm(), None, base_url="http://127.0.0.1:1")))

    def test_committed_config_has_the_cycle_off_and_no_expectations(self):
        cfg = yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))
        self.assertIs(cfg["engagement"]["experiments"]["enabled"], False)
        self.assertIs(cfg["engagement"]["experiments"]["planner"], False)
        self.assertEqual(cfg["engagement"]["experiments"]["max_runs"], 4)
        self.assertEqual(cfg["engagement"]["access_expectations"], [])


class InconclusiveCycleTests(_CycleCase):
    def test_a_denied_baseline_is_inconclusive_and_never_upgrades_the_proof(self):
        # The fixture app 404s the owner's own note when the create body is wrong:
        # make the declared read path point at a route the app does not have.
        declared = _note_expectation(read={"method": "GET", "path": "/api/missing/{id}"})
        b = self._cycle(self._app(), expectations=[declared])
        self.assertEqual(b.result["completed"], [])
        failed = b.result["failed"][0]
        self.assertEqual(failed["outcome"], "inconclusive")
        self.assertIn("baseline read as the owner returned HTTP 404", failed["reason"])
        task = b.state.graph.tasks[failed["task_id"]]
        self.assertEqual(task.status, task_graph.FAILED)
        proof = store.proofs_for_run(b.run_id)[0]
        self.assertEqual(proof["verdict"], "inconclusive")
        self.assertEqual(b.ledger._by_ref, {})

    def test_a_gate_that_forbids_mutation_blocks_the_setup_and_is_inconclusive(self):
        app = self._app()
        orch = self._orch(hosts=("127.0.0.1",))
        orch.config.setdefault("engagement", {})["experiments"] = {"enabled": True}
        orch.config["engagement"]["access_expectations"] = [_note_expectation()]
        state = EngagementState(host="127.0.0.1")

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                         gate_config={"active_enabled": False}) as run:
                _register_sessions(run, app.base)
                state.apply_semantic_model(_asm())
                return await orch._run_experiments(state, _asm(), run, base_url=app.base)

        result = asyncio.run(go())
        self.assertEqual(result["completed"], [])
        self.assertEqual(result["failed"][0]["outcome"], "inconclusive")
        self.assertEqual(app.requests, [])


class TranslateTests(unittest.TestCase):
    SESSIONS = [("principal:1:alice", "alice"), ("principal:2:bob", "bob")]

    def _plan(self, expectations=None, sessions=None, values=None, asm=None, **kw):
        asm = asm or _asm()
        return experiment.translate_cross_account(
            asm.chaining_hypotheses[0], asm,
            [_note_expectation()] if expectations is None else expectations,
            self.SESSIONS if sessions is None else sessions, values or {},
            base_url=kw.pop("base_url", "http://127.0.0.1:9"), **kw)

    def test_every_read_step_extracts_the_object_it_will_be_compared_on(self):
        steps = self._plan().experiment
        names = lambda group: [e.name for step in group for e in step.extractors]   # noqa: E731
        self.assertEqual(names(steps.baseline_steps), ["owner_marker", "owner_object"])
        self.assertEqual(names(steps.attack_steps), ["attack_marker", "attack_object"])
        self.assertEqual(names(steps.control_steps), ["control_marker", "control_object"])
        # A declared marker_pointer is its own proof: no object comparison, no objects.
        declared = self._plan([_note_expectation(marker_pointer="/data/owner")]).experiment
        self.assertEqual(names(declared.control_steps), ["control_marker"])

    def test_a_tag_is_bound_per_identity_and_is_not_a_parent_value(self):
        exp = self._plan([_tagged_expectation()]).experiment
        owner, other = exp.setup_steps
        self.assertEqual(owner.body_template, '{"title":"note {{owner_tag}}"}')
        self.assertEqual(other.body_template, '{"title":"note {{other_tag}}"}')
        self.assertTrue(exp.tagged)
        self.assertEqual(exp.consumed_values, ())
        untagged = self._plan().experiment
        self.assertFalse(untagged.tagged)
        self.assertEqual(untagged.setup_steps[0].body_template, untagged.setup_steps[1].body_template)

    def test_ready_plan_compiles_to_one_ordered_workflow(self):
        plan = self._plan()
        self.assertTrue(plan.ready, plan.missing)
        exp = plan.experiment
        self.assertTrue(exp.id.startswith("exp:"))
        self.assertEqual(exp.id, experiment.experiment_id(
            "cross_account_private_object", "bch:note-idor", "Note"))
        self.assertEqual(exp.required_identities, {"owner": "principal:1:alice",
                                                   "other": "principal:2:bob"})
        self.assertEqual(exp.access_expectation["source"],
                         "config engagement.access_expectations")
        wf = exp.to_workflow("case-1")
        self.assertEqual([s.id for s in wf.steps],
                         ["setup_owner", "setup_other", "baseline", "attack", "control"])
        by_id = {s.id: s for s in wf.steps}
        # case_ref lands on baseline/attack/control only; setup keeps its per-step ref.
        self.assertEqual({k: v.case_ref for k, v in by_id.items()},
                         {"setup_owner": "", "setup_other": "", "baseline": "case-1",
                          "attack": "case-1", "control": "case-1"})
        self.assertTrue(all(by_id[k].observe for k in ("baseline", "attack", "control")))
        self.assertEqual((by_id["baseline"].session_ref, by_id["attack"].session_ref,
                          by_id["control"].session_ref),
                         ("principal:1:alice", "principal:2:bob", "principal:2:bob"))
        self.assertEqual(by_id["attack"].url_template, "http://127.0.0.1:9/api/notes/{{note_id}}")
        self.assertEqual(by_id["control"].url_template,
                         "http://127.0.0.1:9/api/notes/{{note_other_id}}")
        self.assertEqual(by_id["setup_owner"].content_type, "application/json")
        self.assertEqual(exp.extracted_values, ("note_id", "note_other_id"))

    def test_cleanup_steps_exist_only_when_a_delete_is_declared(self):
        self.assertEqual(self._plan().experiment.cleanup_steps, ())
        plan = self._plan([_note_expectation(delete={"method": "DELETE",
                                                     "path": "/api/notes/{id}"})])
        wf = plan.experiment.to_workflow()
        self.assertEqual([(s.id, s.cleanup) for s in wf.steps[-2:]],
                         [("cleanup_owner", True), ("cleanup_other", True)])
        self.assertTrue(all(not s.cleanup for s in wf.steps[:-2]))

    def test_every_blocked_reason_is_the_exact_missing_input(self):
        declared = _note_expectation()
        no_pointer = copy.deepcopy(declared)
        del no_pointer["create"]["id_pointer"]
        cases = [
            (dict(expectations=[]), "no declared access expectation for object 'Note' "
                                    "(engagement.access_expectations)"),
            (dict(expectations=[_note_expectation(expectation="shared_with_all")]),
             "unsupported access expectation 'shared_with_all' for object 'Note' "
             "(engagement.access_expectations supports only 'private_to_creator')"),
            (dict(expectations=[no_pointer]),
             "no declared id extraction (JSON pointer) for POST /api/notes"),
            (dict(expectations=[_note_expectation(read={"method": "GET", "path": "/api/notes"})]),
             "no supported read endpoint with an {id} placeholder for 'Note'"),
            (dict(sessions=self.SESSIONS[:1]), "no second identity distinct from the owner"),
            (dict(sessions=[("principal:1:alice", "alice"), ("principal:9:alice", "alice")]),
             "no second identity distinct from the owner"),
            (dict(sessions=[("anonymous", "anonymous"), ("principal:1:alice", "alice")]),
             "no second identity distinct from the owner"),
            (dict(expectations=[_comment_expectation()], asm=_asm(comments=True)),
             "value 'note_id' not yet observed"),
            (dict(base_url=""), "no target base URL to resolve '/api/notes'"),
        ]
        for kwargs, reason in cases:
            with self.subTest(reason=reason):
                asm = kwargs.get("asm")
                hyp_index = 1 if asm is not None else 0
                plan = experiment.translate_cross_account(
                    (asm or _asm()).chaining_hypotheses[hyp_index], asm or _asm(),
                    kwargs.get("expectations", [declared]),
                    kwargs.get("sessions", self.SESSIONS), {},
                    base_url=kwargs.get("base_url", "http://127.0.0.1:9"))
                self.assertFalse(plan.ready)
                self.assertIn(reason, plan.missing)

    def test_an_expectation_matches_by_endpoint_key_when_the_name_differs(self):
        declared = _note_expectation(object="Memo")
        plan = self._plan([declared])
        self.assertTrue(plan.ready, plan.missing)   # matched via GET /api/notes/{id}

    def test_a_planner_pointer_completes_an_extraction_but_never_an_expectation(self):
        declared = _note_expectation()
        del declared["create"]["id_pointer"]
        plan = self._plan([declared], id_pointers={"POST /api/notes": "/data/id"})
        self.assertTrue(plan.ready, plan.missing)
        absent = self._plan([], id_pointers={"POST /api/notes": "/data/id"})
        self.assertFalse(absent.ready)

    def test_ownership_is_never_inferred(self):
        # There is no code path from a read to an expectation: with none declared the
        # plan is blocked regardless of identities, values or planner pointers.
        plan = self._plan([], values={"note_id": "1"}, id_pointers={"POST /api/notes": "/data/id"})
        self.assertEqual(plan.status, "blocked")
        self.assertTrue(plan.unblock["hard"])


class JudgeTests(unittest.TestCase):
    @staticmethod
    def _result(baseline=200, attack=403, control=200, *, owner="41", attack_marker="",
                control_marker="42", artifacts=("a", "b", "c"), attack_status=StepStatus.PASSED):
        def step(name, status, art, **extracted):
            return StepResult(name, StepStatus.PASSED, "", status, art, dict(extracted))
        return WorkflowResult("w", 1, steps=[
            step("baseline", baseline, artifacts[0], owner_marker=owner),
            StepResult("attack", attack_status, "", attack, artifacts[1],
                       {"attack_marker": attack_marker} if attack_marker else {}),
            step("control", control, artifacts[2], control_marker=control_marker)])

    def test_denials_with_a_valid_baseline_and_control_are_negative(self):
        for status in (401, 403, 404):
            with self.subTest(status=status):
                j = experiment.judge(self._result(attack=status), "41")
                self.assertEqual(j.outcome, "negative", j.reason)
                self.assertEqual(j.artifacts, {"baseline": "a", "attack": "b", "control": "c"})

    def test_a_2xx_carrying_the_owner_marker_is_confirmed(self):
        j = experiment.judge(self._result(attack=200, attack_marker="41"), "41")
        self.assertEqual(j.outcome, "confirmed", j.reason)

    def test_every_other_shape_is_inconclusive(self):
        cases = {
            "baseline not 2xx": self._result(baseline=404),
            "baseline lacks marker": self._result(owner=""),
            "control not 2xx": self._result(control=403),
            "attack 2xx without the marker": self._result(attack=200, attack_marker=""),
            "attack 2xx with another object's marker": self._result(attack=200, attack_marker="42"),
            "attack 500": self._result(attack=500),
            "attack 302": self._result(attack=302),
            "marker does not tell the objects apart": self._result(control_marker="41"),
            "duplicate artifacts": self._result(artifacts=("a", "a", "c")),
            "attack never ran": self._result(attack=None, attack_status=StepStatus.BLOCKED),
        }
        for name, result in cases.items():
            with self.subTest(name):
                self.assertEqual(experiment.judge(result, "41").outcome, "inconclusive", name)

    def test_an_unknown_owner_marker_is_never_a_basis_for_a_verdict(self):
        self.assertEqual(experiment.judge(self._result(attack=200, attack_marker="41"), "").outcome,
                         "inconclusive")
        # None = derive it from the baseline (an explicitly declared marker pointer).
        derived = experiment.judge(self._result(attack=200, attack_marker="41"), None)
        self.assertEqual(derived.outcome, "confirmed")

    def test_an_empty_workflow_is_inconclusive(self):
        self.assertEqual(experiment.judge(WorkflowResult("w", 1), "41").outcome, "inconclusive")


class WorkflowOptionTests(unittest.TestCase):
    """observe/case_ref are opt-in; the defaults must keep the engine unchanged."""

    def test_default_step_still_fails_on_403_and_uses_the_per_step_case_ref(self):
        wf = Workflow("w", (WorkflowStep("read", "GET", "http://t.test/x", "alice"),))
        ctx = _Context([_out(403)])
        result = asyncio.run(execute_workflow(wf, ctx))
        self.assertEqual(result.steps[0].status, StepStatus.FAILED)
        self.assertEqual(ctx._executor.calls[0][1]["case_ref"], "w:1:read")

    def test_observe_records_any_status_as_passed_without_refreshing(self):
        refreshed = []

        async def refresh(session, context):
            refreshed.append(session)
            return True
        wf = Workflow("w", (WorkflowStep("read", "GET", "http://t.test/x", "alice", observe=True),))
        for status in (401, 403, 404, 500):
            with self.subTest(status=status):
                ctx = _Context([_out(status, '{"a":1}')])
                result = asyncio.run(execute_workflow(wf, ctx, refresh_fn=refresh))
                step = result.steps[0]
                self.assertEqual((step.status, step.status_code, step.artifact_id),
                                 (StepStatus.PASSED, status, f"a-{status}"))
                self.assertEqual(len(ctx._executor.calls), 1)
        self.assertEqual(refreshed, [])

    def test_observe_does_not_turn_a_send_that_never_happened_into_a_pass(self):
        wf = Workflow("w", (WorkflowStep("read", "GET", "http://t.test/x", "alice", observe=True),))
        result = asyncio.run(execute_workflow(wf, _Context([_out(None, outcome="blocked")])))
        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)

    def test_case_ref_precedence_step_then_call_then_per_step_string(self):
        wf = Workflow("w", (
            WorkflowStep("own", "GET", "http://t.test/a", "alice", case_ref="proof-case"),
            WorkflowStep("plain", "GET", "http://t.test/b", "alice")))
        ctx = _Context([_out(200), _out(200)])
        asyncio.run(execute_workflow(wf, ctx, case_ref="call-case"))
        self.assertEqual([c[1]["case_ref"] for c in ctx._executor.calls],
                         ["proof-case", "call-case"])
        ctx = _Context([_out(200), _out(200)])
        asyncio.run(execute_workflow(wf, ctx))
        self.assertEqual([c[1]["case_ref"] for c in ctx._executor.calls], ["proof-case", "w:1:plain"])

    def test_content_type_is_sent_only_when_declared(self):
        wf = Workflow("w", (WorkflowStep("a", "POST", "http://t.test/a", "alice", body_template="{}",
                                         content_type="application/json"),
                            WorkflowStep("b", "POST", "http://t.test/b", "alice", body_template="{}")))
        ctx = _Context([_out(200), _out(200)])
        asyncio.run(execute_workflow(wf, ctx))
        self.assertEqual(ctx._executor.calls[0][0].headers, {"Content-Type": "application/json"})
        self.assertEqual(ctx._executor.calls[1][0].headers, {})


class ApplySemanticModelTests(unittest.TestCase):
    SESSIONS = [("principal:1:alice", "alice"), ("principal:2:bob", "bob")]

    def test_default_call_keeps_the_blanket_operator_review_disposition(self):
        state = EngagementState(host="h")
        state.apply_semantic_model(_asm(other_class=True))
        needs = {t.id: t.needs for t in state.graph.tasks.values()}
        self.assertEqual(set(needs), {"chain-hypothesis:bch:note-idor", "chain-hypothesis:bch:price"})
        self.assertTrue(all(n == "operator review (proposed chain -- not confirmed)"
                            for n in needs.values()))

    def test_experiments_replace_the_blanket_disposition_for_idor_only(self):
        state = EngagementState(host="h")
        state.apply_semantic_model(_asm(other_class=True), experiments={
            "expectations": [_note_expectation()], "sessions": self.SESSIONS,
            "base_url": "http://127.0.0.1:9"})
        graph = state.graph
        exp_tasks = [t for t in graph.tasks.values() if t.kind == "experiment"]
        self.assertEqual(len(exp_tasks), 1)
        self.assertEqual((exp_tasks[0].status, exp_tasks[0].depends_on, exp_tasks[0].needs),
                         (task_graph.READY, [], ""))
        self.assertEqual(exp_tasks[0].meta["hypothesis_id"], "bch:note-idor")
        self.assertEqual(exp_tasks[0].meta["kind"], "cross_account_private_object")
        self.assertEqual(exp_tasks[0].meta["experiment"]["id"], exp_tasks[0].target)
        chain = graph.tasks["chain-hypothesis:bch:note-idor"]
        self.assertEqual(chain.needs, f"validated by {exp_tasks[0].id}")
        self.assertEqual(chain.depends_on, [exp_tasks[0].id])
        self.assertEqual(chain.status, task_graph.BLOCKED)
        self.assertTrue(chain.meta["proposed_only"] and not chain.meta["auto_runnable"])
        other = graph.tasks["chain-hypothesis:bch:price"]
        self.assertEqual(other.needs, "operator review (proposed chain -- not confirmed)")
        self.assertEqual(other.depends_on, [])

    def test_blocked_experiment_task_carries_the_missing_list_as_needs(self):
        state = EngagementState(host="h")
        state.apply_semantic_model(_asm(), experiments={"expectations": [], "sessions": self.SESSIONS})
        task = next(t for t in state.graph.tasks.values() if t.kind == "experiment")
        self.assertEqual(task.status, task_graph.BLOCKED)
        self.assertEqual(task.meta["missing"], [
            "no declared access expectation for object 'Note' (engagement.access_expectations)"])
        self.assertEqual(task.needs, "; ".join(task.meta["missing"]))

    def test_two_hypotheses_on_one_object_share_a_single_experiment(self):
        asm = _asm()
        asm.chaining_hypotheses.append(ChainingHypothesis(
            id="bch:note-idor-2", source="IDOR/BOLA on Note", target="admin sink",
            rationale="x", rank=0.7, classes=["idor", "admin_config"],
            endpoints=["GET /api/notes/{id}"]))
        state = EngagementState(host="h")
        state.apply_semantic_model(asm, experiments={
            "expectations": [_note_expectation()], "sessions": self.SESSIONS,
            "base_url": "http://127.0.0.1:9"})
        self.assertEqual(len([t for t in state.graph.tasks.values() if t.kind == "experiment"]), 1)
        gates = {t.depends_on[0] for t in state.graph.tasks.values() if t.kind == "chain-hypothesis"}
        self.assertEqual(len(gates), 1)


class PlannerTests(_CycleCase):
    CAPTURE = HttpExchange(url="http://127.0.0.1:1/api/notes", method="POST",
                           response_status=201, response_headers={"Content-Type": "application/json"},
                           response_body='{"data": {"id": 5, "owner": "alice"}, "token": "s3cr3t-value"}')

    def _blocked_task(self, expectations=None, values=None):
        state = EngagementState(host="h")
        declared = _note_expectation() if expectations is None else expectations
        if isinstance(declared, dict):
            declared = [declared]
        experiment.evaluate_experiments(state, _asm(), declared, TranslateTests.SESSIONS,
                                        values or {}, base_url="http://127.0.0.1:1")
        return next(t for t in state.graph.tasks.values() if t.kind == "experiment"), state

    def _no_pointer(self):
        declared = _note_expectation()
        del declared["create"]["id_pointer"]
        return declared

    def _plan(self, proposals, task, **kw):
        planner = experiment_planner.ExperimentPlanner(
            lambda subgraph: proposals, captures=[self.CAPTURE], **kw)
        return asyncio.run(planner.plan(task, hypotheses=_asm().chaining_hypotheses))

    def test_invalid_pointer_is_rejected_and_only_the_valid_proposal_resolves_the_need(self):
        task, _ = self._blocked_task(self._no_pointer())
        self.assertEqual(task.meta["unblock"]["extractions"][0]["endpoint"], "POST /api/notes")
        outcome = self._plan([
            {"action": "identify_field", "capture": 0, "pointer": "/data/nope", "as": "note_id"},
            {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id"}], task)
        self.assertEqual((len(outcome.accepted), len(outcome.rejected)), (1, 1))
        self.assertIn("does not resolve to a scalar", outcome.rejected[0]["reason"])
        self.assertEqual(outcome.pointers, {"POST /api/notes": "/data/id"})

    def test_planner_resolves_the_extraction_end_to_end_and_the_experiment_runs(self):
        app = self._app()
        capture = HttpExchange(url=f"{app.base}/api/notes", method="POST", response_status=201,
                               response_body='{"data": {"id": 5, "owner": "alice"}}')
        fake = lambda subgraph: [   # noqa: E731
            {"action": "identify_field", "capture": 0, "pointer": "/data/nope", "as": "note_id"},
            {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id"}]
        with patch.object(experiment_planner, "ollama_propose_fn", return_value=fake):
            b = self._cycle(app, expectations=[self._no_pointer()], planner=True, captured=[capture])
        self.assertEqual(b.result["planner"], {"accepted": 1, "rejected": 1, "calls": 1, "errors": 0})
        self._assert_cycle(b)

    def test_without_a_valid_proposal_the_task_stays_blocked_with_zero_sends(self):
        app = self._app()
        capture = HttpExchange(url=f"{app.base}/api/notes", method="POST", response_status=201,
                               response_body='{"data": {"id": 5}}')
        fake = lambda subgraph: [{"action": "identify_field", "capture": 0,   # noqa: E731
                                  "pointer": "/data/missing", "as": "note_id"}]
        with patch.object(experiment_planner, "ollama_propose_fn", return_value=fake):
            b = self._cycle(app, expectations=[self._no_pointer()], planner=True, captured=[capture])
        self.assertEqual(b.result["planner"]["rejected"], 1)
        self.assertEqual(b.result["runs"], 0)
        self.assertEqual(list(b.result["blocked"].values()),
                         [["no declared id extraction (JSON pointer) for POST /api/notes"]])
        self.assertEqual(app.requests, [])

    def test_a_proposal_that_sets_ownership_or_an_expectation_is_rejected(self):
        task, _ = self._blocked_task(self._no_pointer())
        outcome = self._plan([
            {"action": "set_ownership", "object": "Note", "owner": "alice"},
            {"action": "declare_expectation", "object": "Note", "expectation": "private_to_creator"},
            {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id",
             "owner": "alice"},
            {"action": "instantiate_workflow", "kind": "cross_account_private_object",
             "hypothesis": "bch:note-idor", "access_expectation": "private_to_creator"}], task)
        self.assertEqual((len(outcome.accepted), len(outcome.rejected)), (0, 4))
        self.assertTrue(all("access or ownership expectation" in r["reason"] for r in outcome.rejected))
        self.assertEqual((outcome.pointers, outcome.values, outcome.instantiate), ({}, {}, []))

    def test_the_planner_is_never_consulted_for_a_missing_expectation(self):
        app = self._app()
        called = []
        fake = lambda subgraph: called.append(subgraph) or [   # noqa: E731
            {"action": "set_ownership", "object": "Note", "owner": "alice"}]
        with patch.object(experiment_planner, "ollama_propose_fn", return_value=fake):
            b = self._cycle(app, expectations=[], planner=True,
                            captured=[HttpExchange(url=f"{app.base}/api/notes", method="POST",
                                                   response_status=201, response_body='{"id": 1}')])
        self.assertEqual(called, [])
        self.assertEqual(b.result["planner"]["calls"], 0)
        self.assertEqual(list(b.result["blocked"].values()), [[
            "no declared access expectation for object 'Note' (engagement.access_expectations)"]])
        self.assertEqual((app.requests, b.ledger._by_ref), ([], {}))

    def test_each_validation_rule_rejects_with_a_reason(self):
        task, _ = self._blocked_task(self._no_pointer())
        base = {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id"}
        cases = {
            "capture index does not exist": dict(base, capture=3),
            "bool is not a capture index": dict(base, capture=True),
            "pointer resolves to an object": dict(base, pointer="/data"),
            "pointer is not a JSON pointer": dict(base, pointer="data.id"),
            "as is not a name": dict(base, **{"as": "not a name"}),
            "as is not a missing input": dict(base, **{"as": "unrelated"}),
            "unsupported kind": {"action": "instantiate_workflow", "kind": "mass_assignment",
                                 "hypothesis": "bch:note-idor"},
            "hypothesis does not exist": {"action": "instantiate_workflow",
                                          "kind": "cross_account_private_object", "hypothesis": "bch:nope"},
            "unknown action": {"action": "send_request", "url": "http://x"},
            "not an object": "inspect_capture",
        }
        for name, proposal in cases.items():
            with self.subTest(name):
                outcome = self._plan([proposal], task)
                self.assertEqual((len(outcome.accepted), len(outcome.rejected)), (0, 1), outcome)

    def test_valid_inspect_instantiate_and_stop_proposals_are_accepted(self):
        task, _ = self._blocked_task(self._no_pointer())
        outcome = self._plan([
            {"action": "inspect_capture", "capture": 0},
            {"action": "instantiate_workflow", "kind": "cross_account_private_object",
             "hypothesis": "bch:note-idor"},
            {"action": "stop"},
            {"action": "inspect_capture", "capture": 0}], task)
        self.assertEqual((len(outcome.accepted), len(outcome.rejected)), (3, 0))
        self.assertTrue(outcome.stopped)
        self.assertEqual(outcome.instantiate, ["bch:note-idor"])

    def test_a_value_is_resolved_only_from_a_real_capture_scalar(self):
        # The dependent experiment needs note_id; the capture carries it at /data/id.
        state = EngagementState(host="h")
        experiment.evaluate_experiments(state, _asm(comments=True), [_comment_expectation()],
                                        TranslateTests.SESSIONS, {}, base_url="http://127.0.0.1:1")
        task = next(t for t in state.graph.tasks.values()
                    if t.kind == "experiment" and t.meta["object"] == "Comment")
        self.assertEqual(task.meta["unblock"]["values"], ["note_id"])
        outcome = self._plan([
            {"action": "identify_field", "capture": 0, "pointer": "/data", "as": "note_id"},
            {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id"}], task)
        self.assertEqual(outcome.values, {"note_id": "5"})
        self.assertEqual((len(outcome.accepted), len(outcome.rejected)), (1, 1))

    def test_proposals_are_bounded_and_invalid_ones_count(self):
        task, _ = self._blocked_task(self._no_pointer())
        junk = [{"action": "inspect_capture", "capture": 99} for _ in range(10)]
        good = {"action": "identify_field", "capture": 0, "pointer": "/data/id", "as": "note_id"}
        outcome = self._plan(junk + [good], task)
        self.assertEqual((len(outcome.accepted), len(outcome.rejected), outcome.dropped), (0, 6, 5))
        self.assertEqual(outcome.pointers, {})
        outcome = self._plan(junk + [good], task, max_proposals=11)
        self.assertEqual((len(outcome.accepted), len(outcome.rejected), outcome.dropped), (1, 10, 0))

    def test_capture_summaries_truncate_values_and_withhold_secrets(self):
        long = HttpExchange(url="http://127.0.0.1:1/api/notes?x=1", method="POST", response_status=201,
                            response_body=json.dumps({"title": "x" * 100, "access_token": "abc",
                                                      "data": {"id": 1}, "n": 7}))
        summary = experiment_planner.summarize_capture(long, 3)
        self.assertEqual((summary["capture"], summary["method"], summary["path"], summary["status"]),
                         (3, "POST", "/api/notes", 201))
        self.assertEqual(summary["keys"]["title"], "x" * 40)
        self.assertEqual(summary["keys"]["access_token"], "[withheld]")
        self.assertEqual(summary["keys"]["data"], "{...}")
        task, _ = self._blocked_task(self._no_pointer())
        planner = experiment_planner.ExperimentPlanner(lambda s: [], captures=[self.CAPTURE])
        sub = planner.subgraph_for(task)
        self.assertEqual(sub["captures"][0]["keys"]["token"], "[withheld]")
        self.assertEqual(sub["needs_extraction"], [{"endpoint": "POST /api/notes", "as": "note_id"}])
        self.assertNotIn("s3cr3t-value", json.dumps(sub))

    def test_the_planner_uses_the_local_agent_model_never_a_cloud_coordinator_model(self):
        app = self._app()
        seen = {}

        def factory(ollama, model, **kwargs):
            seen.update(ollama=ollama, model=model)
            return lambda subgraph: []

        def cloud_coordinator(orch):
            orch.coordinator_model = "claude-cloud-opus"
            orch.config["coordinator"].update(model="claude-cloud-opus",
                                              cloud_model="claude-cloud-opus", cloud_primary=True)
        capture = HttpExchange(url=f"{app.base}/api/notes", method="POST", response_status=201,
                               response_body='{"data": {"id": 5}}')
        with patch.object(experiment_planner, "ollama_propose_fn", side_effect=factory):
            b = self._cycle(app, expectations=[self._no_pointer()], planner=True,
                            captured=[capture], tune=cloud_coordinator)
        self.assertEqual(b.result["planner"]["calls"], 1)
        self.assertEqual(seen["model"], b.orch.config["agent_defaults"]["model"])
        self.assertNotIn("cloud", seen["model"])
        self.assertIs(seen["ollama"], b.orch.ollama)

    def test_no_local_model_configured_means_no_planner(self):
        app = self._app()
        capture = HttpExchange(url=f"{app.base}/api/notes", method="POST", response_status=201,
                               response_body='{"data": {"id": 5}}')
        with patch.object(experiment_planner, "ollama_propose_fn") as factory:
            b = self._cycle(app, expectations=[self._no_pointer()], planner=True, captured=[capture],
                            tune=lambda orch: orch.config.__setitem__("agent_defaults", {}))
        factory.assert_not_called()
        self.assertEqual(b.result["planner"]["calls"], 0)

    def test_the_model_never_sees_long_values_or_secret_named_keys(self):
        app = self._app()
        seen = []
        capture = HttpExchange(url=f"{app.base}/api/notes", method="POST", response_status=201,
                               response_body=json.dumps({"title": "x" * 100, "api_key": "AKIA-SECRET-1",
                                                         "password": "hunter2", "data": {"id": 5}}))
        fake = lambda subgraph: seen.append(json.dumps(subgraph)) or []   # noqa: E731
        with patch.object(experiment_planner, "ollama_propose_fn", return_value=fake):
            self._cycle(app, expectations=[self._no_pointer()], planner=True, captured=[capture])
        self.assertEqual(len(seen), 1)
        self.assertIn("x" * 40, seen[0])
        self.assertNotIn("x" * 41, seen[0])
        for secret in ("AKIA-SECRET-1", "hunter2"):
            self.assertNotIn(secret, seen[0])
        self.assertIn("[withheld]", seen[0])

    def test_a_failing_model_is_counted_and_never_sinks_the_loop(self):
        app = self._app()

        def boom(subgraph):
            raise RuntimeError("model unavailable")
        with patch.object(experiment_planner, "ollama_propose_fn", return_value=boom):
            b = self._cycle(app, expectations=[self._no_pointer()], planner=True,
                            captured=[HttpExchange(url=f"{app.base}/api/notes", method="POST",
                                                   response_status=201, response_body='{"id": 1}')])
        self.assertEqual((b.result["planner"]["errors"], b.result["runs"]), (1, 0))
        self.assertEqual(app.requests, [])


class InvestigateWiringTests(_CycleCase):
    """investigate_engagement reaches the cycle through _run_experiments, puts its
    return in the job result and records a failure as an "experiments" error."""

    def _investigate(self, app, *, enabled=True, authz=None):
        from harness import business_context_agent, role_crawl
        from harness.role_crawl import RoleSession
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        orch = self._orch(hosts=("127.0.0.1",))
        if authz is not None:
            orch.config["authz"] = authz
        orch.config.setdefault("engagement", {})["experiments"] = {"enabled": enabled}
        orch.config["engagement"]["access_expectations"] = [_note_expectation()]
        orch.business_context_enabled = True
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": "Bearer tok-alice"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer tok-bob"}, name="bob")]
        crawl = AsyncMock(return_value=role_crawl.RoleCrawlResult(base_url=app.base))

        real_init, spied = CrossIdentityValidator.__init__, {}

        def spy(validator, *args, **kwargs):
            spied["ownership"] = kwargs.get("ownership")
            return real_init(validator, *args, **kwargs)

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=300,
                                         gate_config=_GATE, config=orch.config) as run:
                with patch.object(role_crawl, "crawl_roles", crawl), \
                     patch.object(CrossIdentityValidator, "__init__", spy), \
                     patch.object(business_context_agent.BusinessContextAgent, "build_model",
                                  return_value=_asm()):
                    return run.run_id, await orch.investigate_engagement(
                        app.base, roles, max_nodes=0, max_chain_rounds=0,
                        active_discovery=False, run_context=run)

        run_id, result = asyncio.run(go())
        self.validator_ownership = spied.get("ownership")
        return run_id, result

    def test_job_result_carries_the_experiment_cycle(self):
        app = self._app()
        run_id, result = self._investigate(app)
        self.assertEqual([e for e in result["errors"] if e["phase"] == "experiments"], [])
        self.assertEqual(result["experiments"]["runs"], 1, result["experiments"])
        self.assertEqual(result["experiments"]["completed"][0]["outcome"], "negative")
        proof = store.proofs_for_run(run_id)[0]
        self.assertEqual(proof["verdict"], "controlled_negative")
        self.assertTrue(stored_proof_artifacts_resolve(proof))
        graph = result["task_graph"]["tasks"]
        self.assertEqual(graph[result["experiments"]["completed"][0]["task_id"]]["status"], "done")
        self.assertEqual(graph["chain-hypothesis:bch:note-idor"]["status"], "blocked")

    def test_the_cross_identity_validator_reads_the_ledger_the_experiment_feeds(self):
        app = self._app()
        run_id, result = self._investigate(app)
        self.assertEqual(result["experiments"]["completed"][0]["outcome"], "negative")
        ledger = self.validator_ownership
        self.assertIsNotNone(ledger, "nothing declared, yet the validator got no shared ledger")
        fact = ledger.lookup(object_reference(f"{app.base}/api/notes/{_NOTE_ID_BASE}", run_id=run_id))
        self.assertEqual(fact.owner_principal_id, "alice")

    def test_unrelated_declarations_still_share_the_ledger_with_the_validator(self):
        # authz.owners exists (so the ledger is the loaded one, with patterns) but
        # declares an unrelated path: the note's fact must still reach the ledger the
        # cross-identity validator reads.
        app = self._app()
        authz = {"owners": {app.base.split("//", 1)[1]: [
            {"path": "/api/unrelated/{id}", "owner": "alice"}]}}
        run_id, result = self._investigate(app, authz=authz)
        self.assertEqual(result["experiments"]["completed"][0]["outcome"], "negative")
        ledger = self.validator_ownership
        self.assertEqual(len(ledger._patterns), 1)          # the declared ledger, not a fresh one
        fact = ledger.lookup(object_reference(f"{app.base}/api/notes/{_NOTE_ID_BASE}", run_id=run_id))
        self.assertEqual((fact.owner_principal_id, fact.provenance), (
            "alice", "declared private_to_creator; created-as:alice via POST /api/notes"))

    def test_declared_sharing_governs_the_cycle_through_investigate(self):
        app = self._app(allow_cross=True)
        authz = {"owners": {app.base.split("//", 1)[1]: [
            {"path": "/api/notes/{id}", "owner": "alice", "shared_with": ["bob"]}]}}
        run_id, result = self._investigate(app, authz=authz)
        self.assertEqual(result["experiments"]["completed"], [])
        self.assertEqual(result["experiments"]["failed"][0]["outcome"], "inconclusive")
        ledger = self.validator_ownership
        self.assertTrue(ledger.lookup(object_reference(
            f"{app.base}/api/notes/{_NOTE_ID_BASE}", run_id=run_id)).provenance.startswith(
                "config authz.owners"))

    def test_flag_off_leaves_the_job_result_without_a_cycle(self):
        app = self._app()
        run_id, result = self._investigate(app, enabled=False)
        self.assertIsNone(result["experiments"])
        self.assertEqual(app.requests, [])
        self.assertEqual(store.proofs_for_run(run_id), [])

    def test_a_failing_cycle_is_an_experiments_phase_error_not_a_crash(self):
        from harness.orchestrator_chain import ChainMixin
        app = self._app()
        with patch.object(ChainMixin, "_run_experiments",
                          AsyncMock(side_effect=RuntimeError("boom"))):
            run_id, result = self._investigate(app)
        self.assertIsNone(result["experiments"])
        self.assertIn({"phase": "experiments", "error": "RuntimeError: boom"}, result["errors"])
        self.assertTrue(result["degraded"])


if __name__ == "__main__":
    unittest.main()
