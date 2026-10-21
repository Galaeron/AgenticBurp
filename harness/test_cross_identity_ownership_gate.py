"""WL-04: a cross-identity (BOLA/BFLA) confirmation requires declared ownership
evidence; a resource legitimately shared with every authenticated user is never
confirmed.

Drives the production confirmation caller -- Orchestrator.analyze in active mode
against an owned loopback fixture, with the registry's auto-armed real
CrossIdentityValidator sending real HTTP through the run's executor -- and reads
the outcome back through the API response, the store, the issue export, the
Markdown report and SARIF. Only the model is canned: one access-control finding
for the analysed URL.

The fixture is the acceptance spec's X2 family (reviews/2026-10-21-dual-mode-
cross-request-audit/CROSS_REQUEST_ACCEPTANCE_SPEC.md section 3): alice and bob,
both role `user`, plus anonymous; an owner-scoped object (bob denied), a
vulnerable object (bob receives alice's object) and a resource shared with every
authenticated user. X3's admin-namespaced function is the function-level twin.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

from harness import (cache, confirmation_gate, evidence_ledger, global_throttle,
                     identity_headers, principals, report_generator, safety_gate,
                     sarif_adapter, store)
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.validators import cross_identity_validator as civ

_HARNESS = Path(__file__).resolve().parent
HOST = "127.0.0.1"
# Bearer token -> (principal, role). Pre-shared for the fixture.
TOKENS = {"alice-token": ("alice", "user"), "bob-token": ("bob", "user"),
          "root-token": ("root", "admin")}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _caller(self):
        auth = self.headers.get("Authorization", "") or ""
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        return TOKENS.get(token)

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        fx = self.server.fixture
        path = self.path.split("?", 1)[0]
        fx.received.append({"path": path, "authorization": self.headers.get("Authorization")})
        caller = self._caller()
        if caller is None:
            # The anonymous control is denied the same way a non-owner is, so a held
            # control is comparable (identity_compare matches a denial to the baseline).
            return self._reply(403, {"error": "forbidden"})
        who, role = caller
        if path == "/objects/7":          # alice's private object: the vulnerable twin
            if fx.mode == "vulnerable" or who == "alice":
                return self._reply(200, {"id": 7, "owner": "alice", "secret": fx.marker("7")})
            return self._reply(403, {"error": "forbidden"})
        if path == "/objects/5":          # alice's private object: always owner-scoped
            if who == "alice":
                return self._reply(200, {"id": 5, "owner": "alice", "secret": fx.marker("5")})
            return self._reply(403, {"error": "forbidden"})
        if path == "/announcements/42":   # shared with every authenticated user
            return self._reply(200, {"id": 42, "audience": "all-staff", "body": fx.marker("42")})
        if path == "/admin/users":        # admin function: the function-level twin
            if fx.mode == "vulnerable" or role == "admin":
                return self._reply(200, {"users": ["alice", "bob", "carol", "dave"],
                                         "export": fx.marker("admin")})
            return self._reply(403, {"error": "forbidden"})
        return self._reply(404, {"error": "not found"})


class _X2Fixture:
    def __init__(self, mode: str = "vulnerable"):
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        nonce = uuid.uuid4().hex[:8]
        self._markers = {k: f"{k.upper()}_MARKER_{nonce}" for k in ("7", "5", "42", "admin")}
        self.received: list[dict] = []
        self.httpd = ThreadingHTTPServer((HOST, 0), _Handler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://{HOST}:{self.port}"

    def url(self, path: str) -> str:
        return self.base + path

    def marker(self, key: str) -> str:
        return self._markers[key]

    def requests_for(self, path: str) -> list[dict]:
        return [r for r in self.received if r["path"] == path]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class _CannedModel:
    """One access-control finding for the analysed URL; nothing else."""

    def __init__(self, url: str, cls: str):
        self.url, self.cls = url, cls

    def _reply(self, user_prompt: str) -> dict:
        if f"\nURL: {self.url}\n" not in user_prompt:
            return {"findings": [], "components": []}
        return {"findings": [{
            "vulnerability_class": self.cls, "severity": "high", "confidence": 0.6,
            "summary": f"{self.cls} candidate: object reachable by reference",
            "evidence": "benign fixture", "suggested_test": "replay as another identity",
            "basis": "derived"}], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._reply(user_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._reply(user_prompt), prompt_tokens=1, completion_tokens=1)


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = True   # the leg sends (loopback only)
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = [HOST]
    return cfg


class OwnershipGateCallerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="wl04_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()
        identity_headers.clear(HOST)
        stats = global_throttle.throttle.stats()
        self._throttle = ((stats["rate_per_second"] if stats["enabled"] else 0.0),
                          (stats["burst"] if stats["enabled"] else None))
        global_throttle.configure(0)   # a loopback run is not paced to a live-target rate
        self.fx = _X2Fixture("vulnerable")
        self.addCleanup(self.fx.close)

    def tearDown(self):
        global_throttle.configure(*self._throttle)
        identity_headers.clear(HOST)
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    # --- the production caller -------------------------------------------------
    def _analyze(self, path: str, *, source: str = "alice-token",
                 identities=(("bob", "bob-token", "user"),), ledger=None, cls: str = "idor"):
        """Capture `path` as `source` over real HTTP, register the other identities
        the way the operator does (identity_headers), and run Orchestrator.analyze
        with only the auto-armed cross-identity leg registered."""
        url = self.fx.url(path)
        for name, token, role in identities:
            identity_headers.set_identity(HOST, name, {"Authorization": f"Bearer {token}"}, role)
        orch = Orchestrator(_config())
        model = _CannedModel(url, cls)
        orch.ollama = model
        for agent in getattr(orch.agent_manager, "agents", {}).values():
            agent.ollama = model
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = model
        if getattr(orch, "coordinator", None) is not None and hasattr(orch.coordinator, "ollama"):
            orch.coordinator.ollama = model
        orch.validator_registry.validators = {}   # keep the real auto-arm path, nothing else
        if ledger is not None:
            orch.validator_registry.set_ownership(ledger)
        r = httpx.get(url, headers={"Authorization": f"Bearer {source}"})
        exchange = HttpExchange(url=url, method="GET",
                                request_headers={"Authorization": f"Bearer {source}"},
                                response_status=r.status_code,
                                response_headers={"Content-Type": "application/json"},
                                response_body=r.text)
        return asyncio.run(orch.analyze(exchange, force_agents=["idor"], bypass_cache=True))

    @staticmethod
    def _xid(resp):
        return [v for v in resp.validation_reports if v.validator == "cross_identity"]

    @staticmethod
    def _finding(resp, cls="idor"):
        """The canned finding. A leg-confirmed finding's class may have been
        relabelled from the leg's own class, so fall back to the one finding."""
        findings = [f for r in resp.agent_reports for f in r.findings]
        by_class = [f for f in findings if f.vulnerability_class == cls]
        if by_class:
            return by_class[0]
        assert len(findings) == 1, [(f.vulnerability_class, f.summary) for f in findings]
        return findings[0]

    def _proof_verdicts(self):
        conn = sqlite3.connect(str(store._DB_PATH))
        try:
            return conn.execute("SELECT validator, verdict FROM proof_records").fetchall()
        finally:
            conn.close()

    def _declared(self, path, **fact):
        led = principals.OwnershipLedger()
        led.declare(self.fx.url(path), **fact)
        return led

    def _assert_lead(self, reports):
        self.assertTrue(reports)
        self.assertEqual({v.status for v in reports}, {"supported"}, [(v.status, v.summary) for v in reports])
        self.assertFalse(any(v.confirmed for v in reports))
        self.assertFalse(any(v.control_outcome == "control_held" for v in reports))
        for v in reports:
            self.assertIn("not declared", v.evidence.lower())
            self.assertIn("ownership", v.manual_verification.lower())

    # --- (a) vulnerable object, nothing declared --------------------------------
    def test_vulnerable_object_without_declaration_is_a_lead_not_a_confirmation(self):
        resp = self._analyze("/objects/7")
        reports = self._xid(resp)
        self._assert_lead(reports)
        # the leg really ran: bob's replay and the anonymous control reached the target
        auths = [r["authorization"] for r in self.fx.requests_for("/objects/7")]
        self.assertIn("Bearer bob-token", auths)
        self.assertIn(None, auths)
        f = self._finding(resp)
        self.assertFalse(f.confirmed)
        self.assertEqual(f.manual_verification, reports[0].manual_verification)
        self.assertTrue(f.suggested_test.startswith(reports[0].manual_verification))
        # not a negative: no controlled negative for the gate, and the finding is
        # UNVERIFIED (neither confirmed nor refuted), not a likely false positive
        self.assertNotIn("idor", confirmation_gate._controlled_negatives(resp.validation_reports))
        self.assertEqual(f.review_verdict, "inconclusive_unverified")
        verdicts = {v for _, v in self._proof_verdicts()}
        self.assertNotIn("confirmed", verdicts)
        self.assertNotIn("controlled_negative", verdicts)

    # --- (b) declared ownership confirms ----------------------------------------
    def test_declared_ownership_confirms_the_vulnerable_object(self):
        resp = self._analyze("/objects/7", ledger=self._declared("/objects/7", owner="alice"))
        reports = self._xid(resp)
        self.assertTrue(any(v.confirmed and v.status == "confirmed" for v in reports),
                        [(v.status, v.summary) for v in reports])
        f = self._finding(resp)
        self.assertTrue(f.confirmed)
        self.assertEqual(f.confirmed_by_leg, "cross_identity")
        self.assertTrue(f.proof_id and f.case_id)
        self.assertTrue(any(p["proof_id"] == f.proof_id and p["verdict"] == "confirmed"
                            for p in store.proofs_for_case(f.case_id)))
        stored = next(s for s in store.all_host_findings(self.fx.url("/objects/7"))
                      if s["vulnerability_class"] == "idor")
        self.assertTrue(stored["confirmed"])

    def test_declared_ownership_confirms_when_the_capture_itself_is_the_crossing(self):
        # bob's own capture of alice's object; the entitled owner's replay matches it.
        resp = self._analyze("/objects/7", source="bob-token",
                             identities=(("alice", "alice-token", "user"), ("bob", "bob-token", "user")),
                             ledger=self._declared("/objects/7", owner="alice"))
        reports = self._xid(resp)
        self.assertTrue(any(v.confirmed for v in reports), [(v.status, v.summary) for v in reports])
        self.assertIn("bob", next(v for v in reports if v.confirmed).summary)
        self.assertTrue(self._finding(resp).confirmed)

    # --- (c) shared with every authenticated user -------------------------------
    def test_shared_resource_is_never_confirmed(self):
        cases = {"undeclared": None,
                 "declared shared": self._declared("/announcements/42", owner="alice",
                                                   shared_with={"alice", "bob"})}
        for label, ledger in cases.items():
            with self.subTest(label):
                resp = self._analyze("/announcements/42", ledger=ledger)
                reports = self._xid(resp)
                self.assertTrue(reports)
                self.assertFalse(any(v.confirmed for v in reports), [(v.status, v.summary) for v in reports])
                self.assertFalse(any(v.control_outcome == "control_held" for v in reports))
                self.assertFalse(self._finding(resp).confirmed)
                if ledger is None:
                    self._assert_lead(reports)
                else:
                    self.assertEqual([v.status for v in reports], ["not_confirmed"])
                    self.assertIn("authorized", reports[0].summary.lower())

    # --- (d) owner-scoped twin: the held control is unchanged -------------------
    def test_owner_scoped_object_keeps_the_held_control(self):
        for label, ledger in {"undeclared": None,
                              "declared": self._declared("/objects/5", owner="alice")}.items():
            with self.subTest(label):
                resp = self._analyze("/objects/5", ledger=ledger)
                reports = self._xid(resp)
                self.assertEqual([(v.status, v.control_outcome) for v in reports],
                                 [("not_confirmed", "control_held")], [(v.status, v.summary) for v in reports])
                f = self._finding(resp)
                self.assertFalse(f.confirmed)
                self.assertLessEqual(f.confidence, 0.35)   # RA-7 downgrade, then the gate's refutation
                self.assertIn("idor", confirmation_gate._controlled_negatives(resp.validation_reports))

    # --- (e) fault injection: bypass the ownership gate -------------------------
    def test_bypassing_the_ownership_gate_is_detected(self):
        """If missing ownership were read as 'not entitled', the shared resource
        would confirm -- so the shared-resource control above depends on the gate."""
        with patch.object(civ.CrossIdentityValidator, "_ownership_decision",
                          lambda self, principal, url: principals.AuthzDecision.UNAUTHORIZED):
            resp = self._analyze("/announcements/42")
        self.assertTrue(any(v.confirmed for v in self._xid(resp)),
                        "the gate bypass no longer confirms the shared resource; the "
                        "shared-resource control would be vacuous")

    # --- (f) the lead stays unconfirmed through storage and export --------------
    def test_undeclared_lead_stays_unconfirmed_through_storage_and_export(self):
        url = self.fx.url("/objects/7")
        resp = self._analyze("/objects/7")
        self._assert_lead(self._xid(resp))
        evidence_ledger.reset_default_ledger()   # every read below comes from SQLite
        stored = [s for s in store.all_host_findings(url) if s["vulnerability_class"] == "idor"]
        self.assertTrue(stored)
        for s in stored:
            self.assertFalse(s["confirmed"])
            self.assertNotEqual(s["lifecycle_state"], confirmation_gate.STATE_CONFIRMED)
            self.assertNotEqual(s["review_verdict"], "unconfirmed_hypothesis")   # not refuted
        issues = report_generator.export_issues_for_host(url)
        idor_issues = [i for i in issues if i["vulnerability_class"] == "idor"]
        self.assertTrue(idor_issues)
        self.assertFalse(any(i["confirmed"] for i in idor_issues))
        md = report_generator.generate_report_for_host(url)
        line = next(l for l in md.splitlines() if "confirmed finding(s)" in l)
        self.assertEqual(int(line.split("**")[1].split()[0]), 0)
        sarif = sarif_adapter.export_issues_to_sarif(issues)
        self.assertNotIn("confirmed_exploit", json.dumps(sarif))
        self.assertNotIn("confirmed_observation", json.dumps(sarif))
        verdicts = {v for _, v in self._proof_verdicts()}
        self.assertNotIn("confirmed", verdicts)

    # --- (g) the function-level twin: same gate ---------------------------------
    def test_function_level_match_requires_declared_entitlement(self):
        idents = (("bob", "bob-token", "user"), ("root", "root-token", "admin"))
        cases = {"undeclared": (None, "supported"),
                 "declared admin-only": (self._declared("/admin/users", shared_with={"root"}), "confirmed"),
                 "declared shared with staff": (
                     self._declared("/admin/users", shared_with={"root", "bob"}), "not_confirmed")}
        for label, (ledger, expected) in cases.items():
            with self.subTest(label):
                resp = self._analyze("/admin/users", identities=idents, ledger=ledger,
                                     cls="broken_access_control")
                reports = self._xid(resp)
                self.assertEqual([v.status for v in reports], [expected], [(v.status, v.summary) for v in reports])
                self.assertEqual(any(v.confirmed for v in reports), expected == "confirmed")
                self.assertFalse(any(v.control_outcome == "control_held" for v in reports))
                f = self._finding(resp, "broken_access_control")
                self.assertEqual(f.confirmed, expected == "confirmed")
                if expected == "supported":
                    self.assertIn("function", reports[0].evidence.lower())
                    self.assertTrue(f.manual_verification)


if __name__ == "__main__":
    unittest.main()
