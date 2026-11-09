"""HU-1: the operator access matrix, caller level.

A real ThreadingHTTPServer on 127.0.0.1 plays a generic two-role application:
notes are private to their creator (an owner-only object) and items are a shared
catalogue only the admin may change (an admin-only catalogue). `allow_cross`
breaks the note boundary. The draft is built from what the store holds (the
persisted engagement snapshot -- per-principal cells the test observed against
the app -- and an ownership fact); answers go through the real server routes;
the cross-owner read runs through ChainMixin._run_experiments, the seam
investigate_engagement uses, with the verdict read back from the stored proof.

  draft     lists both objects with their observed outcomes and proposals
  negative  no answers -> nothing confirms; the owner_only proposal is not truth
  owner     answered owner_only -> the cross-owner read confirms
  allowed   the same traffic answered allowed -> controlled negative (not_confirmed)
  routes    GET/PUT round trip with provenance; invalid entries save nothing
"""
from __future__ import annotations

import json
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harness import access_matrix, experiment, store
from harness.application_semantic_model import (ApplicationSemanticModel, BusinessObject,
                                                ChainingHypothesis)
from harness.engagement import EngagementState, persist_surface
from harness.principals import OwnershipFact, object_reference
from harness.test_experiment_cycle import _CycleCase

_TOKENS = {"tok-alice": "alice", "tok-bob": "bob", "tok-admin": "root"}
_ROLES = {"alice": "user", "bob": "user", "root": "admin"}
_NOTE_BASE = 41


class _App:
    """Notes: owner-only (403 to anyone else unless `allow_cross`). Items: every
    signed-in user reads them; only the admin updates one."""

    def __init__(self, allow_cross: bool = False):
        self.allow_cross = allow_cross
        self.requests: list = []
        self.notes: dict = {}
        self.items = {1: {"id": 1, "name": "widget", "price": 5}}
        self._next = _NOTE_BASE
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
                return user, text

            def do_POST(self):
                user, text = self._begin()
                if user is None:
                    return self._send(401, {"error": "login required"})
                if self.path != "/api/notes":
                    return self._send(404, {"error": "not found"})
                nid, app._next = app._next, app._next + 1
                title = (json.loads(text or "{}") or {}).get("title", "")
                app.notes[nid] = (user, title)
                return self._send(201, {"data": {"id": nid, "owner": user, "title": title}})

            def do_GET(self):
                user, _ = self._begin()
                if user is None:
                    return self._send(401, {"error": "login required"})
                if self.path == "/api/items":
                    return self._send(200, {"data": list(app.items.values())})
                item = re.fullmatch(r"/api/items/(\d+)", self.path)
                if item and int(item.group(1)) in app.items:
                    return self._send(200, {"data": app.items[int(item.group(1))]})
                note = re.fullmatch(r"/api/notes/(\d+)", self.path)
                if not note or int(note.group(1)) not in app.notes:
                    return self._send(404, {"error": "not found"})
                owner, title = app.notes[int(note.group(1))]
                if owner != user and not app.allow_cross:
                    return self._send(403, {"error": "forbidden"})
                return self._send(200, {"data": {"id": int(note.group(1)), "owner": owner,
                                                 "title": title, "email": f"{owner}@x.test"}})

            def do_PUT(self):
                user, _ = self._begin()
                item = re.fullmatch(r"/api/items/(\d+)", self.path)
                if user is None:
                    return self._send(401, {"error": "login required"})
                if not item or int(item.group(1)) not in app.items:
                    return self._send(404, {"error": "not found"})
                if _ROLES[user] != "admin":
                    return self._send(403, {"error": "admins only"})
                return self._send(200, {"data": app.items[int(item.group(1))]})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.host = self.base.split("://", 1)[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def send(self, method, path, user, body=None):
        token = next(t for t, u in _TOKENS.items() if u == user)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


def _observe(app: _App) -> None:
    """Record what each principal observed against the app into the store, the
    shape the role crawl and supplied captures leave behind: per-principal access
    cells, a create template with its response, and the creator's ownership fact."""
    from harness.models import HttpExchange
    state = EngagementState(host=app.host)
    for name, role in _ROLES.items():
        state.ingest_identity(f"rolecrawl:{name}", role)
    status, body = app.send("POST", "/api/notes", "alice", {"title": "groceries"})
    note = json.loads(body)["data"]["id"]
    state.record_template(app.base + "/api/notes", "POST", HttpExchange(
        method="POST", url=app.base + "/api/notes",
        request_headers={"Content-Type": "application/json"},
        request_body=json.dumps({"title": "groceries"}), response_status=status,
        response_headers={"Content-Type": "application/json"}, response_body=body))
    store.save_ownership_fact(OwnershipFact(
        object_ref=object_reference(f"{app.base}/api/notes/{note}", run_id="crawl"),
        owner_principal_id="alice", provenance="created-as:alice"))
    probes = [("POST", "/api/notes", "/api/notes"), ("GET", f"/api/notes/{note}", "/api/notes/{id}"),
              ("GET", "/api/items", "/api/items"), ("GET", "/api/items/1", "/api/items/{id}"),
              ("PUT", "/api/items/1", "/api/items/{id}")]
    for method, concrete, template in probes:
        ep = state._ep(method, template)
        for name, role in _ROLES.items():
            if method == "POST" and name != "alice":
                continue
            status, body = (201, "") if method == "POST" else app.send(method, concrete, name)
            ep.record_principal_observation(name, role=role, status=status,
                                            reachable=200 <= status < 300, source="role_crawl")
            if method == "GET" and status == 200:
                ep.capture_variants.append({"response_status": status, "response_body": body,
                                            "identity_key": name})
    persist_surface(state)


def _asm() -> ApplicationSemanticModel:
    return ApplicationSemanticModel(
        host="127.0.0.1",
        business_objects=[BusinessObject(name="Note", id_params=["id"], object_scoped=True,
                                         read_endpoints=["GET /api/notes/{id}"],
                                         write_endpoints=["POST /api/notes"])],
        chaining_hypotheses=[ChainingHypothesis(
            id="bch:note-idor", source="IDOR/BOLA on Note", target="data exposure",
            rationale="notes are addressed by id", rank=0.8, classes=["idor"],
            endpoints=["GET /api/notes/{id}", "POST /api/notes"])])


class AccessMatrixCycleTests(_CycleCase):
    def _app(self, allow_cross: bool = False) -> _App:
        app = _App(allow_cross)
        self.addCleanup(app.close)
        _observe(app)
        app.requests.clear()
        return app

    def _answer(self, app, answer, mechanics=True):
        draft = access_matrix.build_draft(app.host)
        note = next(o for o in draft["objects"] if o["object_type"] == "Note")
        entry = {"role": "user", "object_type": "Note", "action": "read", "answer": answer}
        if mechanics:
            entry["mechanics"] = note["proposed_mechanics"]
        access_matrix.save_answers(app.host, [entry], operator="tester")

    def _run(self, app):
        return self._cycle(app, expectations=[], asm=_asm())

    def test_the_draft_lists_both_objects_with_observed_outcomes(self):
        app = self._app()
        draft = access_matrix.build_draft(app.host)
        self.assertEqual({o["object_type"] for o in draft["objects"]}, {"Note", "Item"})
        rows = {r["cell_id"]: r for r in draft["rows"]}
        self.assertEqual(rows["user|note|read"]["observed"], "allowed")       # alice, her own
        self.assertEqual(rows["user|note|read"]["observed_statuses"], [200, 403])
        self.assertEqual(rows["admin|note|read"]["observed"], "denied")
        self.assertEqual(rows["user|note|read"]["proposed"], "owner_only")
        self.assertEqual(rows["user|note|read"]["sensitive_fields"], ["email"])
        self.assertEqual(rows["user|item|update"]["observed"], "denied")
        self.assertEqual(rows["user|item|update"]["proposed"], "admin_only")
        self.assertEqual(rows["admin|item|update"]["observed"], "allowed")
        self.assertEqual(rows["user|item|list"]["observed"], "allowed")
        self.assertTrue(all(r["answer"] is None and not r["proposal_is_truth"] for r in rows.values()))
        note = next(o for o in draft["objects"] if o["object_type"] == "Note")
        self.assertEqual(note["proposed_mechanics"]["create"]["id_pointer"], "/data/id")
        self.assertEqual(note["proposed_mechanics"]["read"], {"method": "GET",
                                                             "path": "/api/notes/{id}"})
        questions = draft["questions"]
        self.assertLessEqual(len(questions), 20)
        self.assertIn("Can a user read a Note?", [q["question"] for q in questions])
        self.assertIn("Can a user update an Item?", [q["question"] for q in questions])
        self.assertEqual(len(access_matrix.build_draft(app.host, max_questions=3)["questions"]), 3)
        self.assertEqual(draft, access_matrix.build_draft(app.host))   # deterministic

    def test_negative_control_no_answer_confirms_nothing(self):
        app = self._app(allow_cross=True)
        b = self._run(app)
        self.assertEqual(b.result["runs"], 0, b.result)
        self.assertEqual(b.result["completed"], [])
        self.assertIn(experiment.missing_expectation("Note"), sum(b.result["blocked"].values(), []))
        self.assertEqual(app.requests, [])
        self.assertEqual(store.proofs_for_run(b.run_id), [])
        # The draft proposes owner_only for this very cell; a proposal is never read.
        self.assertIsNone(access_matrix.expectation_for(None, app.host, "user", "Note", "read"))

    def test_an_unknown_answer_is_still_a_lead(self):
        app = self._app(allow_cross=True)
        self._answer(app, "unknown")
        b = self._run(app)
        self.assertEqual(b.result["runs"], 0, b.result)
        self.assertEqual(app.requests, [])

    def test_an_answer_without_mechanics_names_the_missing_endpoint(self):
        app = self._app(allow_cross=True)
        self._answer(app, "owner_only", mechanics=False)
        b = self._run(app)
        self.assertEqual(b.result["runs"], 0)
        self.assertIn("no declared create endpoint (method, path) for object 'Note'",
                      sum(b.result["blocked"].values(), []))

    def _assert_run(self, app, outcome, verdict):
        b = self._run(app)
        self.assertEqual(b.result["runs"], 1, b.result)
        done = b.result["completed"][0]
        self.assertEqual((done["outcome"], done["verdict"]), (outcome, verdict), done)
        proof = store.proofs_for_run(b.run_id)[0]
        self.assertEqual(proof["verdict"], verdict)
        self.assertTrue(proof["executed"])
        first = _NOTE_BASE + 1          # _observe created note 41
        self.assertEqual(app.requests, [
            ("POST", "/api/notes", "alice"), ("POST", "/api/notes", "bob"),
            ("GET", f"/api/notes/{first}", "alice"), ("GET", f"/api/notes/{first}", "bob"),
            ("GET", f"/api/notes/{first + 1}", "bob")])
        task = b.state.graph.tasks[done["task_id"]]
        self.assertIn("operator access matrix", task.meta["experiment"]["access_expectation"]["source"])
        return b, proof

    def test_answered_owner_only_confirms_a_cross_owner_read(self):
        app = self._app(allow_cross=True)
        self._answer(app, "owner_only")
        _, proof = self._assert_run(app, "confirmed", "confirmed")
        self.assertIn("private_to_creator", proof["expected_invariant"])

    def test_answered_owner_only_on_the_correct_app_is_a_controlled_negative(self):
        app = self._app(allow_cross=False)
        self._answer(app, "owner_only")
        self._assert_run(app, "negative", "controlled_negative")

    def test_the_same_traffic_answered_allowed_does_not_confirm(self):
        app = self._app(allow_cross=True)
        self._answer(app, "allowed")
        b, proof = self._assert_run(app, "negative", "controlled_negative")
        self.assertIn("declared allowed", proof["observed_result"])
        self.assertIsNone(b.ledger.lookup(object_reference(
            f"{app.base}/api/notes/{_NOTE_BASE + 1}", run_id=b.run_id)))   # no ownership fact

    def test_a_config_kind_that_contradicts_the_answer_blocks(self):
        app = self._app(allow_cross=True)
        self._answer(app, "allowed")
        mech = access_matrix.build_draft(app.host)["objects"]
        note = next(o for o in mech if o["object_type"] == "Note")["proposed_mechanics"]
        b = self._cycle(app, expectations=[dict(note, object="Note",
                                                expectation="private_to_creator")], asm=_asm())
        self.assertEqual(b.result["runs"], 0)
        self.assertTrue(any("conflicting access expectations" in m
                            for m in sum(b.result["blocked"].values(), [])))
        self.assertEqual(app.requests, [])


class LookupTests(_CycleCase):
    def test_lookup_matches_role_then_principal_then_wildcard_and_never_proposals(self):
        host = "app.test:8080"
        self.assertIsNone(access_matrix.expectation_for(None, host, "user", "Note", "read"))
        access_matrix.save_answers(host, [
            {"role": "*", "object_type": "Notes", "action": "read", "answer": "denied"},
            {"role": "bob", "object_type": "note", "action": "read", "answer": "allowed"},
            {"role": "user", "object_type": "Item", "action": "update", "answer": "admin_only"}],
            operator="tester", now=1000.0)
        found = access_matrix.expectation_for(None, host, "user", "Item", "update")
        self.assertEqual((found["answer"], found["expectation"], found["operator"],
                          found["answered_at"], found["source"]),
                         ("admin_only", "admin_only", "tester", 1000.0, "operator"))
        self.assertEqual(access_matrix.expectation_for(
            None, host, "user", "Note", "read", principal_id="bob")["answer"], "allowed")
        self.assertEqual(access_matrix.expectation_for(
            None, host, "user", "Note", "read", principal_id="carol")["answer"], "denied")
        self.assertIsNone(access_matrix.expectation_for(None, "other.test", "user", "Note", "read"))
        access_matrix.save_answers(host, [{"role": "*", "object_type": "Note", "action": "read",
                                           "answer": None}], operator="tester")
        self.assertIsNone(access_matrix.expectation_for(None, host, "user", "Note", "read"))

    def test_report_section_ships_off_and_lists_open_questions_when_on(self):
        app = _App()
        self.addCleanup(app.close)
        _observe(app)
        self.assertEqual(access_matrix.report_section(app.host, config={}), "")
        text = access_matrix.report_section(app.host, config={"access_matrix": {"report_section": True}})
        self.assertIn("## Access Matrix (operator intent)", text)
        self.assertIn("### Open questions (this round)", text)
        self.assertIn("Can a user read a Note?", text)


class AccessMatrixRouteTests(unittest.TestCase):
    def setUp(self):
        from harness.test_job_status_passive import DurableJobCallerTests
        self.fx = DurableJobCallerTests("test_export_retains_child_execution_without_parent_completion")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.client = self.fx.client

    def test_put_then_get_round_trips_answers_with_provenance(self):
        host = "app.test:8080"
        reply = self.client.put(f"/engagement/{host}/access-matrix", json={
            "operator": "tester", "answers": [
                {"role": "user", "object_type": "Note", "action": "read", "answer": "owner_only",
                 "note": "notes are private"}]})
        self.assertEqual(reply.status_code, 200, reply.text)
        saved = reply.json()["answers"]
        self.assertEqual(len(saved), 1)
        self.assertEqual((saved[0]["answer"], saved[0]["operator"], saved[0]["source"]),
                         ("owner_only", "tester", "operator"))
        self.assertIsInstance(saved[0]["answered_at"], float)
        view = self.client.get(f"/engagement/{host}/access-matrix")
        self.assertEqual(view.status_code, 200, view.text)
        row = next(r for r in view.json()["rows"] if r["cell_id"] == "user|note|read")
        self.assertEqual(row["answer"], "owner_only")
        self.assertEqual((row["provenance"]["operator"], row["provenance"]["source"],
                          row["provenance"]["note"]), ("tester", "operator", "notes are private"))
        self.assertEqual(view.json()["answered"], 1)

    def test_an_invalid_entry_is_422_and_saves_nothing(self):
        host = "app.test:8080"
        reply = self.client.put(f"/engagement/{host}/access-matrix", json={
            "operator": "tester", "answers": [
                {"role": "user", "object_type": "Note", "action": "read", "answer": "allowed"},
                {"role": "user", "object_type": "Note", "action": "read", "answer": "maybe"},
                {"role": "user", "object_type": "Note", "action": "read", "answer": "allowed",
                 "mechanics": {"read": {"method": "GET", "path": "http://evil.test/x"}}}]})
        self.assertEqual(reply.status_code, 422, reply.text)
        self.assertEqual(len(reply.json()["detail"]), 2)
        self.assertEqual(access_matrix.load_answers(host), [])
        missing = self.client.put(f"/engagement/{host}/access-matrix", json={"answers": []})
        self.assertEqual(missing.status_code, 422)


if __name__ == "__main__":
    unittest.main()
