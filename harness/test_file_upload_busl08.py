"""WG-2 open item (1): the file_upload leg gets its WSTG-BUSL-08 row, and the reused
legacy id "WSTG-BUSL-08" (pre-WG-1 TOCTOU, now ATHZ-03) reads by id scheme.

Caller level: each leg test drives ``Orchestrator._validate_findings`` against an
owned loopback upload app that records every request it receives.

  (a) the app stores and serves a disallowed .html upload -> confirmed (BUSL-08
      confirm evidence);
  (b) negative control: the app rejects the disallowed type -> not confirmed
      (BUSL-08 control evidence);
  (c) validators.allow_mutating_replay off -> nothing is sent.

Scheme reads: an unmarked (scheme-1) matrix, evidence record or event naming
BUSL-08 lands on ATHZ-03; scheme-2 data keeps BUSL-08. Attribution negative
controls: toctou never fills BUSL-08, file_upload never fills ATHZ-03 or confirms
BUSL-09. The import guard still rejects an undeclared alias that shadows a row.
"""
import email
import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import harness.coverage_manifest as cm
import harness.coverage_model as model
from harness import engagement, global_throttle
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.coverage_model import (
    CHECK_ID_SCHEME, CHECKS_BY_ID, REUSED_LEGACY_IDS, CellStatus, CoverageMatrix,
    UnknownCheckIdError, is_legacy_check_id, resolve_check_id,
)
from harness.coverage_tracker import CoverageTracker, endpoint_view
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _RecordingModel
from harness.test_confirmation_soundness_rve import (_CallerBase, _finding, _json_exchange,
                                                     _verdicts)
from harness.validators.file_upload_validator import FileUploadValidator

BUSL08, BUSL09, ATHZ03 = "WSTG-BUSL-08", "WSTG-BUSL-09", "WSTG-ATHZ-03"


class _UploadApp:
    """POST /upload takes a multipart `file`; when `accepts_html`, it stores the file
    and serves it at /uploads/<name> as text/html, otherwise it rejects .html (400)."""

    def __init__(self, accepts_html: bool):
        app = self
        self.received: list[dict] = []
        self.stored: dict[str, bytes] = {}
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, body=b"", ctype="text/plain"):
                data = body if isinstance(body, bytes) else body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self, body=b""):
                with lock:
                    app.received.append({"method": self.command,
                                         "path": urlsplit(self.path).path, "body": body})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self._record(body)
                if urlsplit(self.path).path != "/upload":
                    return self._send(404, "not found")
                msg = email.message_from_bytes(
                    b"Content-Type: " + (self.headers.get("Content-Type") or "").encode()
                    + b"\r\n\r\n" + body)
                part = next((p for p in (msg.get_payload() if msg.is_multipart() else [])
                             if p.get_filename()), None)
                if part is None:
                    return self._send(400, "no file")
                name = part.get_filename()
                if name.lower().endswith((".html", ".htm")) and not accepts_html:
                    return self._send(400, "file type not allowed")
                with lock:
                    app.stored[name] = part.get_payload(decode=True) or b""
                self._send(200, json.dumps({"url": f"/uploads/{name}"}), "application/json")

            def do_GET(self):
                self._record()
                path = urlsplit(self.path).path
                if path.startswith("/uploads/") and path[len("/uploads/"):] in app.stored:
                    return self._send(200, app.stored[path[len("/uploads/"):]], "text/html")
                return self._send(404, "not found")

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def uploads(self):
        return [r for r in self.received if r["method"] == "POST" and r["path"] == "/upload"]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


# unittest.TestCase is listed explicitly so the static no-orphan check
# (test_no_orphan_test_files) sees these classes as test cases.
class _Base(_CallerBase, unittest.TestCase):
    mutating = True

    def _orch(self, hosts=("shop.invalid",)):
        """_CallerBase._orch with allow_mutating_replay set per class."""
        cfg = _config()
        cfg["server"]["allowed_hosts"] = list(hosts)
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=self.mutating)
        orch = Orchestrator(cfg)
        model_ = _RecordingModel()
        orch.ollama = model_
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model_
        global_throttle.configure(0)
        return orch

    def _app(self, accepts_html):
        app = _UploadApp(accepts_html)
        self.addCleanup(app.close)
        return app

    def _run(self, app):
        exchange = _json_exchange(app.base + "/upload", "POST", '{"note": "avatar"}')
        return self._validate("file_upload", FileUploadValidator(allowed_hosts=["127.0.0.1"]),
                              _finding("file_upload"), exchange, hosts=("127.0.0.1",))


class FileUploadCallerTests(EvidenceCase, _Base):
    # EvidenceCase writes the WSTG-BUSL-08 manifest evidence for the two bound tests.
    @evidence_for(**cm.caller_evidence("upload_confirm"))
    def test_disallowed_html_upload_served_confirms(self):
        app = self._app(accepts_html=True)
        reports = self._run(app)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].confirmed)
        self.assertEqual("file_upload", reports[0].finding_class)
        self.assertEqual(1, len(app.uploads()), app.received)
        name = next(iter(app.stored))
        self.assertTrue(name.endswith(".html"), name)
        # The marker is benign: an HTML comment, no script.
        self.assertNotIn(b"<script", app.stored[name].lower())
        self.assertTrue(any(r["method"] == "GET" and r["path"] == f"/uploads/{name}"
                            for r in app.received), app.received)

    @evidence_for(**cm.caller_evidence("upload_control"))
    def test_rejected_disallowed_type_is_not_confirmed(self):
        app = self._app(accepts_html=False)
        reports = self._run(app)
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        self.assertIn("rejected with status 400", reports[0].summary)
        self.assertEqual(1, len(app.uploads()), app.received)
        self.assertEqual({}, app.stored)


class FileUploadGateTests(_Base):
    mutating = False

    def test_gate_off_sends_nothing(self):
        app = self._app(accepts_html=True)
        reports = self._run(app)
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))
        self.assertEqual([], app.received)


class SchemeResolutionTests(unittest.TestCase):
    def test_scheme_rules(self):
        self.assertEqual(CHECK_ID_SCHEME, 2)
        self.assertEqual(resolve_check_id(BUSL08), BUSL08)
        self.assertEqual(resolve_check_id(BUSL08, scheme=1), ATHZ03)
        self.assertEqual(resolve_check_id("WSTG-INPV-05"), "WSTG-INJT-05")
        self.assertEqual(resolve_check_id("WSTG-INPV-05", scheme=1), "WSTG-INJT-05")
        self.assertEqual(resolve_check_id(ATHZ03, scheme=1), ATHZ03)
        self.assertTrue(is_legacy_check_id(BUSL08, 1))
        self.assertFalse(is_legacy_check_id(BUSL08, 2))
        for scheme in (1, 2):
            with self.subTest(scheme=scheme):
                with self.assertRaises(UnknownCheckIdError):
                    resolve_check_id("WSTG-INFO-01", scheme=scheme)
        with self.assertRaises(ValueError):
            resolve_check_id("WSTG-INPV-05", scheme=3)


class SchemeMatrixTests(unittest.TestCase):
    def test_unmarked_busl08_cell_and_case_load_as_athz03(self):
        stored = {
            "cells": {f"user|POST /upload|{BUSL08}": {"status": "confirmed", "reason": "r9"}},
            "cases": {f"user|POST /upload|{BUSL08}": [
                {"key": {"parameter_location": "body", "parameter_name": "role"},
                 "result": {"status": "confirmed", "reason": "r9"}}]},
        }
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(m.get("user", "POST /upload", ATHZ03).status, CellStatus.CONFIRMED)
        self.assertIsNone(m.get("user", "POST /upload", BUSL08))
        self.assertEqual(len(m.cases_for_cell("user", "POST /upload", ATHZ03)), 1)
        self.assertEqual(m.cases_for_cell("user", "POST /upload", BUSL08), [])

    def test_scheme2_busl08_cell_and_case_stay_busl08(self):
        stored = {
            "check_id_scheme": 2,
            "cells": {f"user|POST /upload|{BUSL08}": {"status": "confirmed", "reason": "now"}},
            "cases": {f"user|POST /upload|{BUSL08}": [
                {"key": {"parameter_location": "body", "parameter_name": "file"},
                 "result": {"status": "confirmed", "reason": "now"}}]},
        }
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(m.get("user", "POST /upload", BUSL08).status, CellStatus.CONFIRMED)
        self.assertIsNone(m.get("user", "POST /upload", ATHZ03))
        self.assertEqual(len(m.cases_for_cell("user", "POST /upload", BUSL08)), 1)
        self.assertEqual(m.cases_for_cell("user", "POST /upload", ATHZ03), [])

    def test_round_trip_keeps_both_rows_apart(self):
        stored = {
            "check_id_scheme": 2,
            "cells": {
                f"user|POST /upload|{BUSL08}": {"status": "confirmed", "reason": "upload"},
                f"user|POST /upload|{ATHZ03}": {"status": "not_detected", "reason": "race"},
            },
            "cases": {
                f"user|POST /upload|{BUSL08}": [
                    {"key": {"parameter_location": "body", "parameter_name": "file"},
                     "result": {"status": "confirmed", "reason": "upload"}}],
                f"user|POST /upload|{ATHZ03}": [
                    {"key": {"parameter_location": "body", "parameter_name": "role"},
                     "result": {"status": "not_detected", "reason": "race"}}],
            },
        }
        d = CoverageMatrix.from_dict(stored).to_dict()
        self.assertEqual(d["check_id_scheme"], CHECK_ID_SCHEME)
        m = CoverageMatrix.from_dict(json.loads(json.dumps(d)))
        self.assertEqual(m.get("user", "POST /upload", BUSL08).reason, "upload")
        self.assertEqual(m.get("user", "POST /upload", ATHZ03).reason, "race")
        self.assertEqual([ck.parameter_name for ck, _ in
                          m.cases_for_cell("user", "POST /upload", BUSL08)], ["file"])
        self.assertEqual([ck.parameter_name for ck, _ in
                          m.cases_for_cell("user", "POST /upload", ATHZ03)], ["role"])

    def test_current_id_still_wins_over_a_scheme1_duplicate(self):
        stored = {"cells": {
            f"user|POST /upload|{BUSL08}": {"status": "not_detected", "reason": "old"},
            f"user|POST /upload|{ATHZ03}": {"status": "confirmed", "reason": "new"},
        }}
        m = CoverageMatrix.from_dict(stored)
        self.assertEqual(m.get("user", "POST /upload", ATHZ03).reason, "new")
        self.assertEqual(len(m.to_dict()["cells"]), 1)


class SchemeEvidenceTests(unittest.TestCase):
    RUN = "RUN_WG2_BUSL08"

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="cov_busl08_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _raw(self, check_id, aspect, **extra):
        (self._tmp / f"{check_id}__{aspect}.json").write_text(json.dumps({
            "schema_version": cm.SCHEMA_VERSION, "check_id": check_id, "aspect": aspect,
            "execution": {"status": "pass", "run_id": self.RUN, "test_id": "m.T.test_x"},
            **extra}), encoding="utf-8")

    def test_unmarked_busl08_record_counts_for_athz03(self):
        self._raw(BUSL08, "race")
        loaded = cm.load_evidence(self._tmp, run_id=self.RUN)
        self.assertEqual(set(loaded), {(ATHZ03, "race")})
        self.assertEqual(loaded[(ATHZ03, "race")].status, cm.TestStatus.PASS)

    def test_written_busl08_record_is_stamped_and_loads_as_busl08(self):
        path = cm.write_evidence(check_id=BUSL08, aspect="upload", status="pass",
                                 test_id="m.T.test_x", run_id=self.RUN, evidence_dir=self._tmp)
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["check_id_scheme"], CHECK_ID_SCHEME)
        self.assertEqual(body["check_id"], BUSL08)
        self.assertEqual(body["schema_version"], cm.SCHEMA_VERSION)
        loaded = cm.load_evidence(self._tmp, run_id=self.RUN)
        self.assertEqual(set(loaded), {(BUSL08, "upload")})
        self.assertEqual(loaded[(BUSL08, "upload")].status, cm.TestStatus.PASS)

    def test_unmarked_non_reused_alias_still_resolves(self):
        self._raw("WSTG-INPV-05", "sqli")
        loaded = cm.load_evidence(self._tmp, run_id=self.RUN)
        self.assertEqual(set(loaded), {("WSTG-INJT-05", "sqli")})

    def test_unknown_scheme_is_an_invalid_record(self):
        self._raw(BUSL08, "odd", check_id_scheme=7)
        rec = cm.load_evidence(self._tmp, run_id=self.RUN)[(BUSL08, "odd")]
        self.assertEqual(rec.status, cm.TestStatus.FAIL)
        self.assertIn("check_id_scheme", rec.invalid_reason)


class SchemeEventTests(unittest.TestCase):
    def _tracker(self):
        st = engagement.EngagementState(host="t.test")
        ep = st._ep("POST", "/upload")
        ep.reachable_roles = ["user"]
        t = CoverageTracker()
        t.build(endpoint_view(st), ["user"])
        for cid in (BUSL08, ATHZ03):
            self.assertEqual(t.matrix.get("user", "POST /upload", cid).status,
                             CellStatus.PENDING, cid)
        return t

    def test_in_process_event_lands_on_busl08(self):
        t = self._tracker()
        n = t.record_execution_events([{"identity": "user", "endpoint_key": "POST /upload",
                                        "check_id": BUSL08, "status": "confirmed"}])
        self.assertEqual(n, 1)
        self.assertEqual(t.matrix.get("user", "POST /upload", BUSL08).status, CellStatus.CONFIRMED)
        self.assertEqual(t.matrix.get("user", "POST /upload", ATHZ03).status, CellStatus.PENDING)

    def test_scheme1_event_lands_on_athz03(self):
        t = self._tracker()
        n = t.record_execution_events([{"identity": "user", "endpoint_key": "POST /upload",
                                        "check_id": BUSL08, "check_id_scheme": 1,
                                        "status": "not_detected"}])
        self.assertEqual(n, 1)
        self.assertEqual(t.matrix.get("user", "POST /upload", ATHZ03).status,
                         CellStatus.NOT_DETECTED)
        self.assertEqual(t.matrix.get("user", "POST /upload", BUSL08).status, CellStatus.PENDING)


def _attributed(findings):
    st = engagement.EngagementState(host="t.test")
    ep = st._ep("POST", "/upload")
    ep.reachable_roles = ["user"]
    for f in findings:
        ep.add_finding(f)
    t = CoverageTracker()
    eps = endpoint_view(st)
    t.build(eps, ["user"])
    t.record_findings_from_state(eps, ["user"])
    return {cid: t.matrix.get("user", "POST /upload", cid) for cid in CHECKS_BY_ID}


class AttributionTests(unittest.TestCase):
    def test_row_shape(self):
        row = CHECKS_BY_ID[BUSL08]
        self.assertEqual((row.vulnerability_class, row.confirmation), ("file_upload", "file_upload"))
        self.assertNotIn("file_upload", model.VALIDATOR_ROW_EXCLUSIONS)
        self.assertTrue(row.applies({"path": "/upload", "methods": ["POST"]})[0])
        # The leg declines a non-write, so a GET download path is not applicable.
        self.assertFalse(row.applies({"path": "/download/1", "methods": ["GET"]})[0])
        self.assertFalse(row.applies({"path": "/api/search", "methods": ["POST"]})[0])

    def test_file_upload_validator_picks_busl08(self):
        t = CoverageTracker()
        self.assertEqual(t.resolve_class("file_upload", "file_upload"), ([BUSL08], False))
        self.assertEqual(t.resolve_class("file_upload", "file_upload_validator"), ([BUSL08], False))
        self.assertEqual(t.resolve_class("file_upload"), ([BUSL08, BUSL09], True))

    def test_file_upload_confirmation_fills_busl08_only(self):
        cells = _attributed([{"vulnerability_class": "file_upload", "confirmed": True,
                              "confirmed_by_leg": "file_upload", "severity": "high",
                              "confidence": 0.9}])
        self.assertEqual(cells[BUSL08].status, CellStatus.CONFIRMED)
        self.assertNotEqual(cells[BUSL09].status, CellStatus.CONFIRMED)
        self.assertEqual(cells[ATHZ03].status, CellStatus.PENDING)

    def test_toctou_confirmation_never_fills_busl08(self):
        cells = _attributed([{"vulnerability_class": "toctou", "confirmed": True,
                              "confirmed_by_leg": "toctou", "severity": "high",
                              "confidence": 0.9}])
        self.assertEqual(cells[ATHZ03].status, CellStatus.CONFIRMED)
        self.assertEqual(cells[BUSL08].status, CellStatus.PENDING)
        self.assertEqual(cells[BUSL09].status, CellStatus.PENDING)

    def test_bare_file_upload_is_detected_on_both_and_confirms_neither(self):
        cells = _attributed([{"vulnerability_class": "file_upload", "confirmed": True,
                              "severity": "high", "confidence": 0.9}])
        for cid in (BUSL08, BUSL09):
            self.assertEqual(cells[cid].status, CellStatus.DETECTED, cid)
        self.assertEqual(cells[ATHZ03].status, CellStatus.PENDING)

    def test_bare_confirmed_file_upload_with_unrelated_leg_confirms_neither(self):
        # A leg that confirms neither row cannot narrow the shared class.
        cells = _attributed([{"vulnerability_class": "file_upload", "confirmed": True,
                              "confirmed_by_leg": "path_traversal", "severity": "high",
                              "confidence": 0.9}])
        for cid in (BUSL08, BUSL09):
            self.assertNotEqual(cells[cid].status, CellStatus.CONFIRMED, cid)


class ImportGuardTests(unittest.TestCase):
    def test_undeclared_shadowing_alias_raises(self):
        with mock.patch.dict(model.LEGACY_CHECK_ID_ALIASES, {"WSTG-BUSL-09": ATHZ03}):
            with self.assertRaisesRegex(ValueError, "shadows"):
                model._check_catalog_ids()

    def test_declared_reused_id_must_be_alias_and_row(self):
        for bogus in ("WSTG-BUSL-09", "WSTG-INPV-05", "WSTG-INFO-01"):
            with self.subTest(bogus=bogus):
                with mock.patch.object(model, "REUSED_LEGACY_IDS",
                                       REUSED_LEGACY_IDS | {bogus}):
                    with self.assertRaisesRegex(ValueError, "reused legacy id"):
                        model._check_catalog_ids()
        model._check_catalog_ids()  # the shipped catalog passes


if __name__ == "__main__":
    unittest.main()
