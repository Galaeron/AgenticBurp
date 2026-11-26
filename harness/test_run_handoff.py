"""HU-5: the end-of-run handoff and the target change log, at the caller level.

* Through the real engagement entry (Orchestrator.investigate_engagement, with a
  RunContext built and given a handoff the way server.engagement_investigate does)
  against the generic loopback discovery fixture: a cancel injected while a
  confirmation leg runs still leaves a handoff ON DISK that names the phases not
  run; a completed run lists none (negative control).
* Through the real TargetTransport + workflow engine against a generic loopback
  item store, with the safety gate armed for writes: a mutating leg writes change
  log entries and restores what it created; a GET-only run writes none (negative
  control); a cleanup that fails is an error entry, shown first in the report
  section, which itself stays off by default.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from harness import run_handoff
from harness.run_context import RunContext

_HARNESS = Path(__file__).resolve().parent


class PhaseListTest(unittest.TestCase):
    def test_run_phases_match_the_phases_investigate_engagement_opens(self):
        # ARC-9: the stages run in this order; each module holds its stages in source order.
        src = "\n".join((_HARNESS / f"{stage}.py").read_text(encoding="utf-8") for stage in (
            "orchestrator_chain_discovery", "orchestrator_chain_legs", "orchestrator_chain_worklist",
            "orchestrator_chain_coverage", "orchestrator_chain_finish"))
        opened = list(dict.fromkeys(re.findall(r'_instr\.phases\.begin\(\s*"([a-z_]+)"', src)))
        self.assertEqual(opened, list(run_handoff.RUN_PHASES))


# ---------------------------------------------------------------------------
# Engagement runs (cancelled vs completed)
# ---------------------------------------------------------------------------

def _engagement_run(out_dir: Path, *, cancel_in_confirmation: bool):
    """One investigate_engagement run against the discovery fixture. Returns
    (handoff file contents before any finish(), handoff object, cancelled?)."""
    from harness import test_pipeline_gate as gate
    from harness import store, cache, global_throttle
    from harness.orchestrator import Orchestrator
    from harness.testing_fixtures.discovery_pipeline import DiscoveryPipelineFixture
    from harness.validators import cross_identity_validator as civ
    from unittest.mock import AsyncMock
    import os

    tmp = tempfile.mkdtemp(prefix="hu5_engagement_")
    orig_db, orig_cache = store._DB_PATH, cache._cache
    store._DB_PATH = Path(tmp) / "state.db"
    cache.init_cache(db_path=os.path.join(tmp, "cache.db"))
    tstats = global_throttle.throttle.stats()
    prev_rate = tstats["rate_per_second"] if tstats["enabled"] else 0.0
    prev_burst = tstats["burst"] if tstats["enabled"] else None
    global_throttle.configure(0)
    fx = DiscoveryPipelineFixture("vulnerable")
    try:
        cfg = gate._gate_config()
        cfg["server"]["allowed_hosts"] = list(gate.ALLOWED)
        orch = Orchestrator(cfg)
        orch.allowed_hosts = list(gate.ALLOWED)
        gate._install_silent_model(orch)
        orch.validator_registry.set_ownership(gate._declared_ownership(fx))
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        original = civ.CrossIdentityValidator.validate
        legs = []

        async def _validate(self, finding, exchange, **kw):
            legs.append(exchange.url)
            if cancel_in_confirmation:
                asyncio.current_task().cancel()   # the injected cancel
            return await original(self, finding, exchange, **kw)

        async def _main():
            rc = RunContext.create(run_id="hu5" + ("cancel" if cancel_in_confirmation else "done"),
                                   allowed_hosts=list(gate.ALLOWED),
                                   gate_config=dict(cfg["validators"]), config=cfg)
            handoff = run_handoff.attach(rc, host="127.0.0.1", base_url=fx.base, output_dir=out_dir)
            cancelled = False
            async with rc:
                task = asyncio.ensure_future(orch.investigate_engagement(
                    fx.base, gate.ROLES, max_nodes=8, step_budget=4, max_chain_rounds=0,
                    discovery_max_probes=gate.DISCOVERY_PROBES, run_context=rc))
                try:
                    await task
                except asyncio.CancelledError:
                    cancelled = True
            on_disk = json.loads(handoff.path.read_text(encoding="utf-8"))
            return on_disk, handoff, cancelled, list(legs)

        with patch("harness.ffuf_runner.ffuf_available", return_value=(False, "off")), \
             patch.object(civ.CrossIdentityValidator, "validate", new=_validate):
            return asyncio.run(_main())
    finally:
        fx.close()
        global_throttle.configure(prev_rate, prev_burst)
        store._DB_PATH, cache._cache = orig_db, orig_cache
        shutil.rmtree(tmp, ignore_errors=True)


class EngagementHandoffTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="hu5_out_"))

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def test_cancel_mid_confirmation_still_leaves_a_handoff_naming_the_phases_not_run(self):
        on_disk, handoff, cancelled, legs = _engagement_run(self.out, cancel_in_confirmation=True)
        self.assertTrue(legs, "the injected cancel fired inside a confirmation leg")
        self.assertTrue(cancelled)
        phases = on_disk["phases"]
        self.assertFalse(phases["run_completed"])
        self.assertIn("worklist", phases["interrupted"])
        not_run = [p["phase"] for p in phases["not_run"]]
        for phase in ("capture_review", "chain_rounds", "coverage_drive", "finalise"):
            self.assertIn(phase, not_run)
        self.assertNotIn("discovery", not_run)
        # Captures were enumerated at the header audit and none were reviewed.
        caps = on_disk["untested"]["unreviewed_captures"]
        self.assertTrue(caps["enumerated"])
        self.assertGreater(caps["count"], 0)
        # The server's terminal hook then stamps the status; phases stay listed.
        run_handoff.finish(SimpleRun(handoff), "cancelled")
        final = json.loads(handoff.path.read_text(encoding="utf-8"))
        self.assertEqual(final["status"], "cancelled")
        self.assertEqual(final["untested"]["phases_not_run"], phases["not_run"])

    def test_negative_control_completed_run_lists_no_phase_as_missing(self):
        on_disk, handoff, cancelled, legs = _engagement_run(self.out, cancel_in_confirmation=False)
        self.assertFalse(cancelled)
        self.assertTrue(legs, "the confirmation leg ran")
        phases = on_disk["phases"]
        self.assertTrue(phases["run_completed"])
        self.assertEqual(phases["not_run"], [])
        self.assertEqual(on_disk["untested"]["phases_not_run"], [])
        self.assertEqual(phases["interrupted"], [])


class SimpleRun:
    def __init__(self, handoff):
        self.handoff = handoff


# ---------------------------------------------------------------------------
# Change log (loopback item store)
# ---------------------------------------------------------------------------

class _Items(BaseHTTPRequestHandler):
    store: dict = {}
    fail_delete = False
    next_id = [100]

    def log_message(self, *a):
        pass

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        item = self.path.rstrip("/").rsplit("/", 1)[-1]
        if self.path.startswith("/items/") and item in self.store:
            return self._send(200, json.dumps(self.store[item]).encode())
        return self._send(200 if self.path == "/items" else 404,
                          json.dumps(list(self.store)).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        self.next_id[0] += 1
        item = str(self.next_id[0])
        self.store[item] = {"id": item, "body": body}
        return self._send(201, json.dumps({"id": item}).encode())

    def do_DELETE(self):
        item = self.path.rstrip("/").rsplit("/", 1)[-1]
        if self.fail_delete:
            return self._send(500, b'{"error":"cannot delete"}')
        self.store.pop(item, None)
        return self._send(204)


@contextlib.contextmanager
def _item_app(fail_delete=False):
    handler = type("Items", (_Items,), {"store": {}, "fail_delete": fail_delete, "next_id": [100]})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", handler
    finally:
        srv.shutdown()
        srv.server_close()


def _workflow(base, *, write=True):
    from harness.workflow_engine import (Assertion, Extractor, ExtractorKind, Workflow,
                                         WorkflowStep)
    if not write:
        return Workflow("read-only", (WorkflowStep("list", "GET", f"{base}/items", "alice"),
                                      WorkflowStep("one", "GET", f"{base}/items/1", "alice",
                                                   prerequisites=("list",))))
    create = WorkflowStep("create", "POST", f"{base}/items", "alice", body_template='{"n":1}',
                          content_type="application/json",
                          extractors=(Extractor("id", ExtractorKind.JSON_POINTER, "/id"),))
    delete = WorkflowStep("delete", "DELETE", f"{base}/items/{{{{id}}}}", "alice",
                          prerequisites=("create",), cleanup=True)
    return Workflow("create-then-clean", (create, delete))


def _run_workflow(base, out_dir, workflow, *, armed=True):
    from harness.workflow_engine import execute_workflow

    async def _main():
        gate_cfg = {"active_enabled": armed, "allow_mutating_replay": armed,
                    "max_mutating_requests_per_finding": 5}
        rc = RunContext.create(run_id="hu5wf", allowed_hosts=["127.0.0.1"],
                               gate_config=gate_cfg, config={})
        rc.sessions.register("alice", "alice", headers={}, allowed_origins=[base])
        handoff = run_handoff.attach(rc, host="127.0.0.1", base_url=base, output_dir=out_dir)
        async with rc:
            result = await execute_workflow(workflow, rc, capability="workflow_leg")
        return rc, handoff, result
    return asyncio.run(_main())


class ChangeLogTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="hu5_changes_"))

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def _persisted(self, rc):
        return json.loads((self.out / f"{rc.run_id}.changes.json").read_text(encoding="utf-8"))["entries"]

    def test_mutating_leg_records_its_writes_and_restores_them(self):
        with _item_app() as (base, app):
            rc, handoff, result = _run_workflow(base, self.out, _workflow(base))
            self.assertEqual(app.store, {}, "the leg restored what it created")
        self.assertEqual(result.cleanup_completed, ["delete"])
        entries = self._persisted(rc)
        self.assertEqual([(e["method"], e["path"], e["status"]) for e in entries],
                         [("POST", "/items", 201), ("DELETE", "/items/101", 204)])
        post, delete = entries
        self.assertEqual(post["object_ref"], "created:101")
        self.assertEqual(post["capability"], "workflow_leg")
        self.assertEqual(post["restore_status"], run_handoff.RESTORED)
        self.assertEqual(delete["object_ref"], "101")
        self.assertEqual(delete["restore_status"], run_handoff.RESTORE_SEND)
        self.assertEqual(handoff.snapshot()["changes"]["restore_failed"], 0)

    def test_negative_control_get_only_run_records_no_change(self):
        with _item_app() as (base, _app):
            rc, handoff, _ = _run_workflow(base, self.out, _workflow(base, write=False))
        self.assertEqual(rc.change_log.entries(), [])
        self.assertEqual(self._persisted(rc), [])
        self.assertEqual(handoff.snapshot()["changes"]["writes"], 0)

    def test_negative_control_gate_refused_write_is_a_skipped_leg_not_a_change(self):
        with _item_app() as (base, app):
            rc, handoff, _ = _run_workflow(base, self.out, _workflow(base), armed=False)
            self.assertEqual(app.store, {})
        self.assertEqual(rc.change_log.entries(), [])
        legs = handoff.snapshot()["untested"]["skipped_legs"]
        self.assertTrue(any(r["capability"] == "workflow_leg" and "POST /items" in r["examples"]
                            for r in legs), legs)

    def test_failed_restore_is_an_error_entry_shown_loudly(self):
        with _item_app(fail_delete=True) as (base, app):
            with self.assertLogs("harness.run_handoff", level="ERROR") as logs:
                rc, handoff, _ = _run_workflow(base, self.out, _workflow(base))
            self.assertEqual(len(app.store), 1, "the fixture really kept the write")
        self.assertTrue(any("RESTORE FAILED" in line for line in logs.output))
        post = self._persisted(rc)[0]
        self.assertEqual((post["method"], post["restore_status"], post["level"]),
                         ("POST", run_handoff.RESTORE_FAILED, "error"))
        self.assertIn("HTTP 500", post["restore_detail"])
        snap = json.loads(handoff.path.read_text(encoding="utf-8"))
        self.assertEqual(snap["changes"]["restore_failed"], 1)
        self.assertEqual(snap["changes"]["failed_restores"][0]["path"], "/items")
        # Report section: off by default (default report unchanged), loud when on.
        cfg = {"runs": {"output_dir": str(self.out)}}
        self.assertEqual(run_handoff.report_section("127.0.0.1", cfg), "")
        cfg["reporting"] = {"handoff_section": True}
        section = run_handoff.report_section("127.0.0.1", cfg)
        self.assertIn("ERROR: 1 write(s) on the target were NOT restored", section)
        self.assertIn("RESTORE_FAILED", section)
        self.assertLess(section.index("NOT restored"), section.index("Target change log"))


class ToolProxyChangeLogTest(unittest.TestCase):
    """A tool's writes reach the change log: the ToolProxy replays each request
    through the run's transport, whose execute() hook records every 2xx non-read
    send (r7's change log holds sqlmap_tool writes this way)."""

    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="hu5_tool_changes_"))
        self.addCleanup(shutil.rmtree, self.out, True)

    def _through_proxy(self, requests):
        import urllib.error
        import urllib.request
        from harness.tool_proxy import ToolProxy

        def client(proxy_url, method, body):
            req = urllib.request.Request(proxy_url, method=method,
                                         data=body.encode() if body else None,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        with _item_app() as (base, app):
            async def go():
                rc = RunContext.create(run_id="hu5tool", allowed_hosts=["127.0.0.1"], config={},
                                       gate_config={"active_enabled": True,
                                                    "allow_mutating_replay": True})
                run_handoff.attach(rc, host="127.0.0.1", base_url=base, output_dir=self.out)
                async with rc:
                    proxy = await ToolProxy(rc, base, capability="tool_x",
                                            case_ref="case-7").start()
                    try:
                        for method, path, body in requests:
                            await asyncio.to_thread(client, proxy.url_for(base + path),
                                                    method, body)
                    finally:
                        await proxy.close()
                return rc
            rc = asyncio.run(go())
            return rc, app

    def test_a_tool_write_through_the_proxy_is_in_the_change_log(self):
        rc, app = self._through_proxy([("GET", "/items", ""), ("POST", "/items", '{"n":1}')])
        self.assertEqual(len(app.store), 1)
        entries = json.loads((self.out / "hu5tool.changes.json").read_text(encoding="utf-8"))["entries"]
        self.assertEqual([(e["method"], e["path"], e["status"], e["capability"], e["case_ref"])
                          for e in entries], [("POST", "/items", 201, "tool_x", "case-7")])
        self.assertEqual(entries[0]["object_ref"], "created:101")

    def test_negative_control_tool_reads_are_not_changes(self):
        rc, _ = self._through_proxy([("GET", "/items", ""), ("GET", "/items/1", "")])
        self.assertEqual(rc.change_log.entries(), [])


class ReportExportTest(unittest.TestCase):
    def test_report_for_host_appends_section_only_when_enabled(self):
        from harness import report_generator, store
        out = Path(tempfile.mkdtemp(prefix="hu5_report_"))
        tmp_db = Path(tempfile.mkdtemp(prefix="hu5_db_"))
        orig_db = store._DB_PATH
        store._DB_PATH = tmp_db / "state.db"
        try:
            rc = RunContext.create(run_id="hu5rep", allowed_hosts=["127.0.0.1"], config={})
            run_handoff.attach(rc, host="127.0.0.1", base_url="http://127.0.0.1:9", output_dir=out)
            rc.change_log.record_send(method="PUT", url="http://127.0.0.1:9/things/7", status=200,
                                      capability="leg")
            cfg = {"runs": {"output_dir": str(out)}}
            plain = report_generator.generate_report_for_host("http://127.0.0.1:9/", config=cfg)
            self.assertNotIn("Run handoff", plain)
            cfg["reporting"] = {"handoff_section": True}
            with_section = report_generator.generate_report_for_host("http://127.0.0.1:9/", config=cfg)
            self.assertIn("Target change log (1 write(s))", with_section)
            self.assertIn("/things/7", with_section)
        finally:
            store._DB_PATH = orig_db
            shutil.rmtree(out, ignore_errors=True)
            shutil.rmtree(tmp_db, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
