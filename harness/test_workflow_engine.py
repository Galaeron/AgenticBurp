import unittest
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from workflow_engine import (
    Assertion, Extractor, ExtractorKind, StepStatus, Workflow, WorkflowResult,
    WorkflowStep, bind_template, execute_workflow, extract_all, json_pointer,
    misuse_variants,
)


class _Executor:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
    async def execute(self, request, **kwargs):
        self.calls.append((request, kwargs))
        return self.outcomes.pop(0)


class _Context:
    def __init__(self, outcomes, cancelled=False):
        self._executor = _Executor(outcomes)
        self.cancel = SimpleNamespace(cancelled=cancelled)
    def executor(self):
        return self._executor


def _out(status=200, body="", headers=None, outcome="ok"):
    return SimpleNamespace(ok=outcome == "ok", outcome=outcome, status=status,
                           body=body, headers=headers or {}, final_url="http://t.test/x",
                           error="", artifact=SimpleNamespace(artifact_id=f"a-{status}"))


class ContractTests(unittest.TestCase):
    def test_versioned_workflow_requires_ordered_unique_dependencies(self):
        create = WorkflowStep("create", "POST", "/items", "alice")
        approve = WorkflowStep("approve", "POST", "/items/{{id}}/approve", "manager",
                               prerequisites=("create",))
        wf = Workflow("approval", (create, approve), version=2)
        self.assertEqual(wf.version, 2)
        with self.assertRaises(ValueError):
            Workflow("bad", (approve, create))
        with self.assertRaises(ValueError):
            Workflow("bad", (create, create))

    def test_cleanup_and_assertions_are_explicit_records(self):
        step = WorkflowStep("delete", "DELETE", "/items/{{id}}", "alice",
                            prerequisites=("create",), cleanup=True,
                            assertions=(Assertion("status", expected=204),))
        self.assertTrue(step.cleanup)
        self.assertEqual(step.assertions[0].expected, 204)

    def test_incomplete_result_is_never_complete(self):
        result = WorkflowResult("w", 1, steps=[
            type("S", (), {"status": StepStatus.BLOCKED})()
        ])
        self.assertFalse(result.complete)


class BindingTests(unittest.TestCase):
    def test_missing_value_blocks_instead_of_guessing(self):
        rendered, missing = bind_template("/items/{{item_id}}", {})
        self.assertEqual(rendered, "/items/{{item_id}}")
        self.assertEqual(missing, ("item_id",))

    def test_all_present_values_bind(self):
        rendered, missing = bind_template("/{{id}}?token={{token}}", {"id": "7", "token": "abc"})
        self.assertEqual(rendered, "/7?token=abc")
        self.assertEqual(missing, ())


class ExtractorTests(unittest.TestCase):
    def test_json_pointer_nested_and_escaped(self):
        self.assertEqual(json_pointer('{"a/b":{"~x":[3]}}', "/a~1b/~0x/0"), "3")

    def test_location_is_resolved(self):
        values, missing = extract_all((Extractor("item_url", ExtractorKind.LOCATION),),
                                      body="", headers={"Location": "/items/7"},
                                      response_url="http://t.test/items")
        self.assertEqual(values["item_url"], "http://t.test/items/7")
        self.assertEqual(missing, ())

    def test_hidden_field_extraction(self):
        ex = Extractor("csrf", ExtractorKind.HTML_HIDDEN, "csrf_token")
        values, missing = extract_all((ex,), body='<input type="hidden" name="csrf_token" value="T7">',
                                      headers={}, response_url="http://t.test/form")
        self.assertEqual(values, {"csrf": "T7"})
        self.assertEqual(missing, ())

    def test_required_missing_blocks_optional_missing_does_not(self):
        exs = (Extractor("id", ExtractorKind.JSON_POINTER, "/id"),
               Extractor("note", ExtractorKind.JSON_POINTER, "/note", required=False))
        values, missing = extract_all(exs, body="{}", headers={}, response_url="http://t.test")
        self.assertEqual(values, {})
        self.assertEqual(missing, ("id",))


class ExecutionTests(unittest.TestCase):
    def _workflow(self):
        return Workflow("approval", (
            WorkflowStep("create", "POST", "http://t.test/items", "alice",
                         extractors=(Extractor("item_id", ExtractorKind.JSON_POINTER, "/id"),)),
            WorkflowStep("approve", "POST", "http://t.test/items/{{item_id}}/approve", "manager",
                         prerequisites=("create",), assertions=(Assertion("status", expected=200),)),
            WorkflowStep("cleanup", "DELETE", "http://t.test/items/{{item_id}}", "alice",
                         prerequisites=("create",), cleanup=True),
        ), invariant="only an authorized manager may approve")

    def test_values_bind_and_cleanup_runs(self):
        ctx = _Context([_out(201, '{"id":7}'), _out(200), _out(204)])
        result = asyncio.run(execute_workflow(self._workflow(), ctx))
        self.assertEqual(result.values["item_id"], "7")
        self.assertEqual(result.cleanup_registered, ["cleanup"])
        self.assertEqual(result.cleanup_completed, ["cleanup"])
        self.assertIn("/7/approve", ctx._executor.calls[1][0].url)

    def test_missing_required_extraction_blocks_dependent_step(self):
        ctx = _Context([_out(201, "{}")])
        result = asyncio.run(execute_workflow(self._workflow(), ctx))
        by_id = {s.step_id: s for s in result.steps}
        self.assertEqual(by_id["create"].status, StepStatus.BLOCKED)
        self.assertEqual(by_id["approve"].status, StepStatus.BLOCKED)
        self.assertEqual(len(ctx._executor.calls), 1)

    def test_cancelled_run_still_attempts_registered_cleanup(self):
        ctx = _Context([_out(201, '{"id":7}'), _out(outcome="cancelled"), _out(204)])
        result = asyncio.run(execute_workflow(self._workflow(), ctx))
        self.assertEqual(result.cleanup_completed, ["cleanup"])
        self.assertTrue(ctx._executor.calls[-1][1]["allow_cancelled_cleanup"])

    def test_401_refresh_is_bounded_and_403_is_not_refreshed(self):
        calls = []
        async def refresh(session, context):
            calls.append(session)
            return True
        one = Workflow("w", (WorkflowStep("read", "GET", "http://t.test/x", "alice"),))
        ctx = _Context([_out(401), _out(200)])
        result = asyncio.run(execute_workflow(one, ctx, refresh_fn=refresh, max_refresh_attempts=1))
        self.assertEqual(result.steps[0].status, StepStatus.PASSED)
        self.assertEqual(calls, ["alice"])
        calls.clear()
        ctx = _Context([_out(403)])
        result = asyncio.run(execute_workflow(one, ctx, refresh_fn=refresh))
        self.assertEqual(result.steps[0].reason, "access denied")
        self.assertEqual(calls, [])

    def test_misuse_variants_are_plans_not_verdicts(self):
        variants = misuse_variants(self._workflow(), alternate_session_ref="bob")
        kinds = {(v.kind, v.step_id) for v in variants}
        self.assertIn(("skip_prerequisite", "approve"), kinds)
        self.assertIn(("repeat", "create"), kinds)
        self.assertIn(("switch_principal", "approve"), kinds)


class RealTransportWorkflowTests(unittest.TestCase):
    """Readable create->approve->verify fixture; transport and executor are real."""

    def _run(self, vulnerable):
        state = {"items": {}, "next": 1, "calls": [], "vulnerable": vulnerable}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def _principal(self):
                return "alice" if "alice" in self.headers.get("Cookie", "") else "bob"
            def _send(self, status, payload=""):
                body = payload.encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                state["calls"].append(("POST", self.path, self._principal()))
                if self.path == "/items":
                    item = str(state["next"]); state["next"] += 1
                    state["items"][item] = {"owner": self._principal(), "approved": False}
                    self._send(201, json.dumps({"id": item})); return
                if self.path.endswith("/approve"):
                    item = self.path.split("/")[2]
                    if not state["vulnerable"] and self._principal() != "alice":
                        self._send(403, '{"error":"forbidden"}'); return
                    state["items"][item]["approved"] = True
                    self._send(200, '{"approved":true}'); return
                self._send(404)
            def do_GET(self):
                state["calls"].append(("GET", self.path, self._principal()))
                item = self.path.split("/")[-1]
                self._send(200, json.dumps(state["items"].get(item, {})))
            def do_DELETE(self):
                state["calls"].append(("DELETE", self.path, self._principal()))
                state["items"].pop(self.path.split("/")[-1], None); self._send(204)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        from run_context import RunContext
        import engagement_builder
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"],
                                gate_config={"active_enabled": True, "allow_mutating_replay": True})
        ctx.sessions.register("alice", "alice", {"Cookie": "session=alice"}, allowed_origins=[base])
        ctx.sessions.register("bob", "bob", {"Cookie": "session=bob"}, allowed_origins=[base])
        declaration = {"id": "approve", "version": 1,
          "invariant": "only the owner may approve",
          "steps": [
            {"id":"create","method":"POST","url_template":base+"/items","session_ref":"alice",
             "extractors":[{"name":"id","kind":"json_pointer","expression":"/id"}]},
            {"id":"approve","method":"POST","url_template":base+"/items/{{id}}/approve",
             "session_ref":"bob","prerequisites":["create"],"assertions":[{"kind":"status","expected":200}]},
            {"id":"verify","method":"GET","url_template":base+"/items/{{id}}","session_ref":"alice",
             "prerequisites":["approve"],"assertions":[{"kind":"json_pointer","expression":"/approved","expected":"True"}]},
            {"id":"cleanup","method":"DELETE","url_template":base+"/items/{{id}}","session_ref":"alice",
             "prerequisites":["create"],"cleanup":True}
          ]}
        try:
            result = asyncio.run(engagement_builder.execute_declared_workflows([declaration], ctx))[0]
            asyncio.run(ctx.aclose())
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        return result, state

    def test_vulnerable_cross_principal_transition_needs_independent_state_read(self):
        result, state = self._run(True)
        self.assertTrue(any(s.step_id == "verify" and s.status == StepStatus.PASSED for s in result.steps))
        self.assertIn(("GET", "/items/1", "alice"), state["calls"])
        self.assertEqual(result.cleanup_completed, ["cleanup"])

    def test_patched_control_does_not_pass_or_verify(self):
        result, state = self._run(False)
        by_id = {s.step_id: s for s in result.steps}
        self.assertEqual(by_id["approve"].reason, "access denied")
        self.assertEqual(by_id["verify"].status, StepStatus.BLOCKED)
        self.assertNotIn(("GET", "/items/1", "alice"), state["calls"])
        self.assertEqual(result.cleanup_completed, ["cleanup"])


if __name__ == "__main__":
    unittest.main()
