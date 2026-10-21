"""WL-02: the role/access matrix is keyed by principal, and object ids share one rule.

X2 of the 2026-10-21 cross-request acceptance spec: two accounts with the SAME role
(alice and bob, both `user`) plus anonymous, against an owned loopback app with

  - an owner-scoped object      GET /api/orders/{id}        bob is denied alice's order;
  - a vulnerable object          GET /api/invoices/{id}      bob receives alice's invoice;
  - a declared-shared resource   GET /api/announcements/{id} every authenticated user may read it;
  - a UUID-addressed object      GET /api/vehicles/<uuid>/location (owner-scoped);
  - an ObjectId-addressed object GET /api/files/<24 hex>     (owner-scoped).

Before WL-02 the matrix was keyed by role label, so alice and bob collapsed into
one `user` column: the vulnerable route produced no lead, and the owner-scoped
cell read `{'user': 403}` while `reachable_roles == ['user']`. A UUID path was not
object-scoped. These tests drive the production callers
(`engagement_builder.build_engagement` -> `role_crawl.crawl_roles` -> the run's
transport -> this loopback app, and `Orchestrator.investigate_engagement`) and
include a fault injection that collapses principals back to role labels.

Nothing here confirms anything: a same-object lead is an unconfirmed hypothesis
("if it is a shared/public object it is benign -- confirm ownership"). No live
target and no model accuracy are measured.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import cache, engagement, engagement_builder, evidence_ledger, global_throttle
from harness import role_crawl, safety_gate, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.role_crawl import RoleSession
from harness.run_context import RunContext

_HARNESS = Path(__file__).resolve().parent

VEHICLE_ID = "0f6c1a52-1111-4a1a-9a1a-aaaaaaaaaaaa"   # alice's vehicle, UUID-addressed
FILE_ID = "507f1f77bcf86cd799439011"                   # alice's file, 24-hex ObjectId

ALICE = RoleSession("user", {"Authorization": "Bearer alice-token"}, name="alice")
BOB = RoleSession("user", {"Authorization": "Bearer bob-token"}, name="bob")
ANON = RoleSession("anonymous", {})
ROLES = [ANON, ALICE, BOB]

ORDERS = "/api/orders/{id}"
INVOICES = "/api/invoices/{id}"
SHARED = "/api/announcements/{id}"
VEHICLES = "/api/vehicles/{id}/location"
FILES = "/api/files/{id}"


class X2Fixture:
    """Owned loopback app for X2. Bearer tokens are pre-shared; every object carries
    a per-instance marker, so a generic 200 can never pass for an object."""

    TOKENS = {"alice-token": "alice", "bob-token": "bob"}

    def __init__(self):
        self.nonce = uuid.uuid4().hex[:8]
        self.received: list[dict] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _reply(self, status, payload, ctype="application/json"):
                data = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                auth = self.headers.get("Authorization", "") or ""
                caller = outer.TOKENS.get(auth[7:] if auth.lower().startswith("bearer ") else "")
                with outer._lock:
                    outer.received.append({"path": path, "caller": caller})
                status, payload = outer.respond(path, caller)
                if isinstance(payload, str) and payload.startswith("<"):
                    return self._reply(status, payload, "text/html")
                return self._reply(status, payload)

            def _other(self):
                self._reply(405, {"error": "method not allowed"})

            do_POST = do_PUT = do_PATCH = do_DELETE = _other

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def marker(self, kind: str) -> str:
        return f"{kind.upper()}_{self.nonce}"

    def respond(self, path: str, caller: str | None):
        if path in ("/", "/index.html"):
            links = ["/api/orders/1", "/api/invoices/1", "/api/announcements/1",
                     f"/api/vehicles/{VEHICLE_ID}/location", f"/api/files/{FILE_ID}"]
            return 200, "<html><body>" + "".join(
                f'<a href="{href}">{href}</a>' for href in links) + "</body></html>"
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "api":
            return 404, {"error": "not found"}
        kind, object_id = parts[1], parts[2]
        if caller is None:
            return 401, {"error": "authentication required"}
        if kind == "orders" and object_id == "1" and len(parts) == 3:
            # owner-scoped: only alice may read her order
            if caller != "alice":
                return 403, {"error": "forbidden"}
            return 200, {"order": 1, "owner": "alice", "marker": self.marker("order")}
        if kind == "invoices" and object_id == "1" and len(parts) == 3:
            # VULNERABLE: no ownership check, bob receives alice's invoice
            return 200, {"invoice": 1, "owner": "alice", "marker": self.marker("invoice")}
        if kind == "announcements" and object_id == "1" and len(parts) == 3:
            # DECLARED shared with every authenticated user (authorized sharing)
            return 200, {"announcement": 1, "audience": "all-authenticated",
                         "marker": self.marker("announcement")}
        if kind == "vehicles" and object_id == VEHICLE_ID and parts[3:] == ["location"]:
            if caller != "alice":
                return 403, {"error": "forbidden"}
            return 200, {"vehicle": VEHICLE_ID, "owner": "alice", "lat": 1.0,
                         "marker": self.marker("vehicle")}
        if kind == "files" and object_id == FILE_ID and len(parts) == 3:
            if caller != "alice":
                return 403, {"error": "forbidden"}
            return 200, {"file": FILE_ID, "owner": "alice", "marker": self.marker("file")}
        return 404, {"error": "not found"}

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# --- readers --------------------------------------------------------------------

def _row(result, path: str, method: str = "GET"):
    return next((e for e in result.endpoints if e.path == path and e.method == method), None)


def _leads(findings, path: str) -> list[dict]:
    """Same-object cross-principal leads (role_crawl._compare_identities) for `path`."""
    return [f for f in findings or []
            if f"cross_identity_compare:{path}" in (f.get("validation_hints") or [])]


def _collapse_principals_to_role_labels():
    """FAULT: key the matrix by role label again (the pre-WL-02 behaviour)."""
    return patch.object(role_crawl, "_matrix_principal_id", lambda r: r.role)


class _MatrixAssertions(unittest.TestCase):
    def assert_role_view_consistent(self, by_role: dict, reachable_roles: list, cells: dict,
                                    where: str = "") -> None:
        """The role view never contradicts the principal cells it is derived from:
        a role is reachable iff one of its principals reached the operation; a
        single role status is claimed only when all its principals agree on it;
        a role listed reachable never reads as a single non-2xx status."""
        self.assertEqual(len(reachable_roles), len(set(reachable_roles)),
                         f"{where}: reachable_roles has duplicates: {reachable_roles}")
        roles = {}
        for cell in cells.values():
            roles.setdefault(cell["role"], []).append(cell)
        for role, role_cells in roles.items():
            self.assertEqual(role in reachable_roles, any(c["reachable"] for c in role_cells),
                             f"{where}: role {role!r} reachability contradicts its principals")
            view = by_role[role]
            statuses = {c["status"] for c in role_cells}
            if isinstance(view, list):
                self.assertGreater(len(statuses), 1, f"{where}: a list view for agreeing principals")
                self.assertEqual(set(view), statuses, f"{where}: {role!r} list view lost a status")
            else:
                self.assertEqual(statuses, {view},
                                 f"{where}: {role!r} claims {view} but its principals saw {statuses}")
        for role in reachable_roles:
            view = by_role.get(role)
            if isinstance(view, int):
                self.assertTrue(200 <= view < 300,
                                f"{where}: {role!r} is listed reachable but reads {view}")


class X2BuildEngagementTests(_MatrixAssertions):
    """`engagement_builder.build_engagement` -> `role_crawl.crawl_roles`, through an
    owning RunContext's transport, against the owned loopback X2 app."""

    def setUp(self):
        stats = global_throttle.throttle.stats()
        prior = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                 stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        self.addCleanup(global_throttle.configure, *prior)
        self.fx = X2Fixture()
        self.addCleanup(self.fx.close)

    def _build(self, *, seed_exchanges=None, faults=()):
        async def go():
            rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=400,
                                   gate_config={"active_enabled": True})
            try:
                async with rc:
                    return await engagement_builder.build_engagement(
                        self.fx.base, ROLES, allowed_hosts=["127.0.0.1"],
                        active_discovery=False, run_context=rc,
                        **({"seed_exchanges": seed_exchanges} if seed_exchanges else {}))
            finally:
                await rc.aclose()

        with contextlib.ExitStack() as stack:
            for fault in faults:
                stack.enter_context(fault())
            state, result = asyncio.run(go())
        for e in result.endpoints:
            self.assert_role_view_consistent(e.by_role, e.reachable_roles, e.by_principal,
                                             f"matrix {e.method} {e.path}")
        for key, ep in state.endpoints.items():
            if ep.access_by_principal:
                self.assert_role_view_consistent(ep.access, ep.reachable_roles,
                                                 ep.access_by_principal, f"state {key}")
        return state, result

    def test_same_role_gap_yields_an_unconfirmed_lead_naming_both_principals(self):
        """(a) bob (role user) receives alice's (role user) invoice."""
        state, result = self._build()
        row = _row(result, INVOICES)
        self.assertIsNotNone(row, [e.path for e in result.endpoints])
        self.assertEqual(sorted(row.reachable_principals), ["alice", "bob"])
        self.assertEqual(row.reachable_roles, ["user"])
        self.assertEqual(row.by_role["user"], 200)
        leads = _leads(result.idor_findings, INVOICES)
        self.assertEqual(len(leads), 1, result.idor_findings)
        lead = leads[0]
        self.assertEqual(lead["principals"], ["alice", "bob"])
        self.assertEqual(lead["principal_roles"], {"alice": "user", "bob": "user"})
        self.assertIn("alice", lead["summary"])
        self.assertIn("bob", lead["summary"])
        self.assertFalse(lead["confirmed"], "a same-object comparison is a lead, not a proof")
        self.assertIn("confirm ownership", lead["evidence"])
        candidate = next(c for c in result.idor_candidates if c["path"] == INVOICES)
        self.assertEqual(candidate["reached_by"], ["user"])
        self.assertEqual(candidate["reached_by_principals"], ["alice", "bob"])
        # The lead reaches the fused engagement endpoint, still unconfirmed.
        ep = state.endpoints[f"GET {INVOICES}"]
        idor = [f for f in ep.findings if f["vulnerability_class"] == "idor"]
        self.assertTrue(idor, ep.findings)
        self.assertFalse(any(f["confirmed"] for f in idor))

    def test_owner_scoped_twin_records_alice_reached_and_bob_denied_without_contradiction(self):
        """(b) bob is denied alice's order: no lead, and the cell is not self-contradictory."""
        state, result = self._build()
        self.assertEqual(_leads(result.idor_findings, ORDERS), [])
        row = _row(result, ORDERS)
        alice, bob = row.by_principal["alice"], row.by_principal["bob"]
        self.assertEqual((alice["status"], alice["reachable"], alice["role"]), (200, True, "user"))
        self.assertEqual((bob["status"], bob["reachable"], bob["role"]), (403, False, "user"))
        self.assertNotEqual(alice["session_ref"], bob["session_ref"])
        self.assertTrue(alice["session_ref"] and bob["session_ref"])
        self.assertIsNotNone(alice["observed_at"])
        self.assertEqual(row.reachable_principals, ["alice"])
        # The documented role view for a disagreeing role: the sorted distinct statuses.
        self.assertEqual(row.by_role["user"], [200, 403])
        self.assertEqual(row.reachable_roles, ["user"])
        candidate = next(c for c in result.idor_candidates if c["path"] == ORDERS)
        self.assertEqual(candidate["reached_by_principals"], ["alice"])
        self.assertEqual(candidate["by_principal"]["bob"], {"role": "user", "status": 403})
        ep = state.endpoints[f"GET {ORDERS}"]
        self.assertEqual(ep.access_by_principal["bob"]["status"], 403)
        self.assertEqual(ep.reachable_principals, ["alice"])
        self.assertFalse([f for f in ep.findings if f["vulnerability_class"] == "idor"])
        # The engagement JSON carries the principal record through a snapshot round trip.
        reloaded = engagement.EngagementState.from_dict(json.loads(json.dumps(state.to_dict())))
        self.assertEqual(reloaded.endpoints[f"GET {ORDERS}"].access_by_principal,
                         ep.access_by_principal)

    def test_declared_shared_resource_is_never_confirmed(self):
        """(c) the announcement is shared with every authenticated user by design.
        The matrix may flag it as a lead; nothing here may confirm it."""
        state, result = self._build()
        for lead in _leads(result.idor_findings, SHARED):
            self.assertFalse(lead["confirmed"])
            self.assertIn("if it is a shared/public object it is benign -- confirm ownership",
                          lead["evidence"])
        self.assertFalse([f for f in result.idor_findings if f.get("confirmed")])
        ep = state.endpoints[f"GET {SHARED}"]
        self.assertFalse([f for f in ep.findings if f.get("confirmed")], ep.findings)
        self.assertNotEqual(ep.status, "validated")

    def test_uuid_and_objectid_addressed_routes_are_object_scoped(self):
        """(d) a UUID (and a 24-hex ObjectId) segment is an object id in the matrix
        and in the engagement keys, and the matrix still probes the real object."""
        state, result = self._build()
        for template, concrete in ((VEHICLES, f"/api/vehicles/{VEHICLE_ID}/location"),
                                   (FILES, f"/api/files/{FILE_ID}")):
            row = _row(result, template)
            self.assertIsNotNone(row, [e.path for e in result.endpoints])
            self.assertTrue(row.object_scoped)
            self.assertIsNone(_row(result, concrete), "the concrete id was left untemplated")
            self.assertEqual(engagement.normalize_path(self.fx.base + concrete), template)
            self.assertEqual(row.probed_path, concrete, "the matrix must probe the observed object")
            self.assertEqual(row.by_principal["alice"]["status"], 200)
            self.assertEqual(row.by_principal["bob"]["status"], 403)
            self.assertIn({"path": concrete, "caller": "bob"}, self.fx.received)
            ep = state.endpoints[f"GET {template}"]
            self.assertTrue(ep.object_scoped)
            self.assertEqual(_leads(result.idor_findings, template), [])
            self.assertTrue(any(c["path"] == template for c in result.idor_candidates))

    def test_supplied_capture_merges_per_principal_with_the_crawl(self):
        """Seed import records the capture under its principal and merges it: the
        crawl's other cells survive, and an older capture does not overwrite a
        newer observation of the same principal/operation."""
        fresh = HttpExchange(  # unknown capture time -> ordered by arrival
            url=f"{self.fx.base}/api/vehicles/{VEHICLE_ID}/location", method="GET",
            request_headers=dict(ALICE.headers), response_status=200,
            response_body='{"vehicle": "seen in Burp"}')
        stale = HttpExchange(
            url=f"{self.fx.base}/api/orders/1", method="GET",
            request_headers=dict(ALICE.headers), response_status=404,
            response_body="", captured_at=1.0)
        state, result = self._build(seed_exchanges=[fresh, stale])
        vehicles = [e for e in result.endpoints if "/api/vehicles/" in e.path]
        self.assertEqual([e.path for e in vehicles], [VEHICLES], "the seed opened a second row")
        row = vehicles[0]
        self.assertEqual(row.by_principal["alice"]["source"], "seed_capture")
        self.assertEqual(row.by_principal["bob"]["status"], 403, "the crawl's bob cell was erased")
        ep = state.endpoints[f"GET {VEHICLES}"]
        self.assertEqual(ep.access_by_principal["alice"]["source"], "seed_capture")
        self.assertEqual(ep.access_by_principal["bob"]["status"], 403)
        self.assertTrue(ep.object_scoped)
        orders = state.endpoints[f"GET {ORDERS}"]
        self.assertEqual(orders.access_by_principal["alice"]["status"], 200,
                         "a capture older than the crawl's observation overwrote it")
        self.assertEqual(orders.access_by_principal["alice"]["source"], "role_crawl")

    def test_fault_collapsing_principals_to_role_labels_loses_the_same_role_lead(self):
        """(e) Defect injection: key the matrix by role label again. alice and bob
        collapse into one `user` column and test (a)'s lead disappears."""
        _, result = self._build(faults=(_collapse_principals_to_role_labels,))
        row = _row(result, INVOICES)
        self.assertEqual(sorted(row.by_principal), ["anonymous", "user"], "fault not applied")
        self.assertEqual(_leads(result.idor_findings, INVOICES), [],
                         "defect injection is inert: the same-role lead survived role keying")


class X2EngagementIngestTests(_MatrixAssertions):
    """`EngagementState.ingest_role_crawl` merges a real crawl record per principal."""

    def setUp(self):
        stats = global_throttle.throttle.stats()
        prior = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                 stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        self.addCleanup(global_throttle.configure, *prior)
        fx = X2Fixture()
        self.addCleanup(fx.close)
        session_refs = ["anonymous", "alice", "bob"]

        async def crawl():
            from harness.run_context import ScopePolicy
            rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200,
                                   gate_config={"active_enabled": True})
            for ref, r in zip(session_refs, ROLES):
                rc.sessions.register(ref, r.principal_id(), dict(r.headers),
                                     allowed_origins=[ScopePolicy.origin_of(fx.base)], role=r.role)
            try:
                async with rc:
                    return await role_crawl.crawl_roles(
                        fx.base, ROLES, allowed_hosts=["127.0.0.1"], run_context=rc,
                        session_refs=session_refs)
            finally:
                await rc.aclose()

        # A REAL crawl record of the owner-scoped route (alice 200, bob 403).
        self.record = next(e for e in asyncio.run(crawl()).to_dict()["endpoints"]
                           if e["path"] == ORDERS)
        self.assertEqual(self.record["by_principal"]["bob"]["status"], 403)

    def test_a_later_partial_record_merges_instead_of_replacing(self):
        st = engagement.EngagementState(host="127.0.0.1")
        st.ingest_role_crawl({"endpoints": [self.record]})
        ep = st.endpoints[f"GET {ORDERS}"]
        alice_before = dict(ep.access_by_principal["alice"])
        # A later crawl that only saw bob, now allowed: alice's cell is untouched.
        later = dict(self.record, by_principal={"bob": dict(
            self.record["by_principal"]["bob"], status=200, reachable=True,
            observed_at=self.record["by_principal"]["bob"]["observed_at"] + 60)})
        st.ingest_role_crawl({"endpoints": [later]})
        self.assertEqual(ep.access_by_principal["alice"], alice_before)
        self.assertEqual(ep.access_by_principal["bob"]["status"], 200)
        self.assertEqual(sorted(ep.reachable_principals), ["alice", "bob"])
        self.assertEqual(ep.access["user"], 200)
        # An OLDER observation of alice does not overwrite the newer one.
        stale = dict(self.record, by_principal={"alice": dict(
            alice_before, status=500, reachable=False, observed_at=alice_before["observed_at"] - 60)})
        st.ingest_role_crawl({"endpoints": [stale]})
        self.assertEqual(ep.access_by_principal["alice"]["status"], 200)
        # A legacy role-only record is kept as its own cell, not merged over alice/bob.
        st.ingest_role_crawl({"endpoints": [{"method": "GET", "path": ORDERS,
                                             "by_role": {"user": 404}, "reachable_roles": [],
                                             "object_scoped": True}]})
        self.assertEqual(ep.access_by_principal["user"]["status"], 404)
        self.assertEqual(ep.access_by_principal["user"]["source"], "role_view")
        self.assertEqual(ep.access_by_principal["alice"]["status"], 200)
        self.assertEqual(ep.access["user"], [200, 404])
        self.assertEqual(ep.reachable_roles, ["user"])
        self.assert_role_view_consistent(ep.access, ep.reachable_roles, ep.access_by_principal)
        self.assertEqual(ep.access_by_principal["anonymous"]["status"], 401)
        self.assertEqual(ep.access_by_principal["bob"]["session_ref"], "bob")

    def test_merge_from_another_state_keeps_both_principals(self):
        primary = engagement.EngagementState(host="127.0.0.1")
        primary.ingest_role_crawl({"endpoints": [dict(
            self.record, by_principal={"alice": self.record["by_principal"]["alice"]})]})
        derived = engagement.EngagementState(host="127.0.0.1")
        derived.ingest_role_crawl({"endpoints": [dict(
            self.record, by_principal={"bob": self.record["by_principal"]["bob"]})]})
        primary.merge_from(derived)
        ep = primary.endpoints[f"GET {ORDERS}"]
        # anonymous is the records' role-only entry (no cell was kept for it).
        self.assertEqual(sorted(ep.access_by_principal), ["alice", "anonymous", "bob"])
        self.assertEqual(ep.access_by_principal["anonymous"]["source"], "role_view")
        self.assertEqual(ep.access["user"], [200, 403])
        self.assert_role_view_consistent(ep.access, ep.reachable_roles, ep.access_by_principal)


class SharedObjectIdRuleTests(unittest.TestCase):
    """One object-id rule for matrix rows and engagement keys (WL-02 item 5)."""

    def test_matrix_rows_and_engagement_keys_template_the_same_segments(self):
        cases = {
            "/api/orders/42": "/api/orders/{id}",
            "/api/accounts/17/orders/42": "/api/accounts/{id}/orders/{id}",
            f"/api/vehicles/{VEHICLE_ID}/location": "/api/vehicles/{id}/location",
            f"/api/vehicles/{VEHICLE_ID.upper()}": "/api/vehicles/{id}",
            f"/api/files/{FILE_ID}": "/api/files/{id}",
            "/api/blobs/deadbeefcafe": "/api/blobs/{id}",          # 12 hex
            "/api/blobs/deadbeef": "/api/blobs/deadbeef",          # 8 hex is a word, as before
            "/api/v1/users/me": "/api/v1/users/me",
            "/api/tickets/{id}/comments": "/api/tickets/{id}/comments",
            "/api/x/0f6c1a52-1111-4a1a-9a1a": "/api/x/0f6c1a52-1111-4a1a-9a1a",  # not a full UUID
        }
        for raw, expected in cases.items():
            self.assertEqual(role_crawl._template_ids(raw), expected, raw)
            self.assertEqual(engagement.normalize_path("http://h.test" + raw), expected, raw)
        self.assertEqual(engagement.path_id_values(f"http://h.test/a/17/v/{VEHICLE_ID}/x"),
                         ["17", VEHICLE_ID])
        self.assertEqual(
            engagement.template_from_exchange({"url": f"http://h.test/v/{VEHICLE_ID}/location"})
            ["path_ids"], [VEHICLE_ID])

    def test_numeric_slots_keep_id_fill_and_opaque_slots_keep_the_observed_id(self):
        raw = f"/api/accounts/17/vehicles/{VEHICLE_ID}"
        templated = role_crawl._template_ids(raw)
        values = role_crawl._observed_slot_values(raw)
        self.assertEqual(values, [None, VEHICLE_ID])
        self.assertEqual(role_crawl._fill_observed_ids(templated, values),
                         f"/api/accounts/{{id}}/vehicles/{VEHICLE_ID}")


# --- the full production caller --------------------------------------------------

class _SilentModel:
    """The only stubbed boundary: no model output (as in test_pipeline_gate)."""

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=1, completion_tokens=1)


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    v = cfg.setdefault("validators", {})
    v["active_enabled"] = True
    v["allow_mutating_replay"] = False
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg["engagement"]["feature_crawl"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


class X2InvestigateEngagementTests(_MatrixAssertions):
    """`Orchestrator.investigate_engagement`, entered inside its owning RunContext
    as the server does, against the X2 app. Only the model is stubbed (silent),
    the iterative probe is a no-op and ffuf/Chromium are off."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="wl02_x2_")
        self.addCleanup(shutil.rmtree, self._tmp, True)
        orig = (store._DB_PATH, cache._cache)
        self.addCleanup(lambda: (setattr(store, "_DB_PATH", orig[0]), setattr(cache, "_cache", orig[1])))
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        stats = global_throttle.throttle.stats()
        prior = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                 stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        self.addCleanup(global_throttle.configure, *prior)
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        evidence_ledger.reset_default_ledger()
        self.fx = X2Fixture()
        self.addCleanup(self.fx.close)

    def _investigate(self, faults=()) -> dict:
        from harness.orchestrator import Orchestrator
        cfg = _config()
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        model = _SilentModel()
        orch.ollama = model
        for agent in getattr(orch.agent_manager, "agents", {}).values():
            agent.ollama = model
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = model
        if hasattr(getattr(orch, "coordinator", None), "ollama"):
            orch.coordinator.ollama = model
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=2000, config=cfg,
                               gate_config={"active_enabled": True, "allow_mutating_replay": False})

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        self.fx.base, ROLES, max_nodes=8, step_budget=2, max_chain_rounds=0,
                        active_discovery=False, run_context=rc)
            finally:
                await rc.aclose()

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("harness.ffuf_runner.ffuf_available",
                                      return_value=(False, "ffuf disabled for this test")))
            stack.enter_context(patch("harness.browser_driver.default_driver", return_value=None))
            for fault in faults:
                stack.enter_context(fault())
            return asyncio.run(go())

    def _node(self, result: dict, path: str) -> dict:
        node = next((n for n in result["worklist"] if n["path"] == path and n["method"] == "GET"),
                    None)
        if node is None:
            self.fail(f"GET {path} missing from the worklist: "
                      f"{[(n['method'], n['path']) for n in result['worklist']]}")
        return node

    def test_investigation_reports_the_same_role_lead_and_a_principal_matrix(self):
        result = self._investigate()
        leads = _leads(result["idor_findings"], INVOICES)
        self.assertEqual([lead["principals"] for lead in leads], [["alice", "bob"]])
        self.assertFalse(any(f.get("confirmed") for f in result["idor_findings"]),
                         "a role_crawl comparison never confirms")
        self.assertEqual(_leads(result["idor_findings"], ORDERS), [])
        for path in (ORDERS, INVOICES, SHARED, VEHICLES, FILES):
            node = self._node(result, path)
            self.assertTrue(node["object_scoped"], path)
            self.assert_role_view_consistent(node["access"], node["reachable_roles"],
                                             node["access_by_principal"], f"worklist {path}")
        orders = self._node(result, ORDERS)
        self.assertEqual(orders["reachable_principals"], ["alice"])
        self.assertEqual(orders["access_by_principal"]["bob"]["status"], 403)
        # Negative control on confirmation: the owner-scoped twins stay unconfirmed
        # (the shared announcement's handling by the confirmation legs is WL-04's
        # scope and is not asserted here).
        for path in (ORDERS, VEHICLES, FILES):
            confirmed = [f for f in self._node(result, path)["findings"]
                         if f.get("confirmed") and "idor" in (f.get("vulnerability_class") or "")]
            self.assertEqual(confirmed, [], path)

    def test_investigation_fault_collapsing_principals_loses_the_lead(self):
        result = self._investigate(faults=(_collapse_principals_to_role_labels,))
        self.assertEqual(_leads(result["idor_findings"], INVOICES), [],
                         "defect injection is inert at the production caller")


if __name__ == "__main__":
    unittest.main()
