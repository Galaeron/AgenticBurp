"""Principal-keyed access matrix: the parity, negative controls, active probe,
readers and API inputs that the WL-02 matrix tests do not cover (X03).

Ported from the 2026-10-17 dual-mode audit probe
(reviews/2026-10-17-dual-mode-audit-opus55/evidence/role_matrix_probe.py) and
the F2 fixture in that audit's CROSS_REQUEST_ACCEPTANCE_SPEC.md, then adapted to
the WL-02 representation (harness.test_principal_access_matrix): principal
cells (`by_principal`, `access_by_principal`) are authoritative and `by_role` /
`reachable_roles` is the role view derived from them.

Covered here: identity in the role label and named principals agree; unnamed
same-role sessions with distinct credentials stay distinct; one principal under
renewed credentials is one cell and never compared with itself; role still
drives function-level trust; the active cross-role probe pairs principals; the
worklist, coverage and JWT-leg readers pick or skip an identity by its OWN cell
(a same-role principal that was denied is never used); /crawl-roles and
/engagement/{host}/advance keep the supplied principal name.

The crawler and the per-request probe are replaced by in-memory fakes, so no
request leaves the process. Fault injection: reading reachability from the role
view alone (engagement.principal_reached) makes the reader tests fail.
"""
import asyncio
import json
import unittest
from unittest.mock import patch

from harness import engagement_builder, global_throttle, role_crawl
from harness.role_crawl import RoleSession

_BASE = "http://shop.test/"
_HOSTS = ["shop.test"]
_ORDERS = "/api/orders/{id}"
_ALICE_OBJ = json.dumps({"order_id": 1, "owner": "alice@fixture.test", "total": 12})


def _fake_crawl(endpoints=("/api/orders/{id}",)):
    async def crawl(base_url, headers=None, allowed_hosts=None, **kwargs):
        from harness.crawler import CrawlResult
        result = CrawlResult(base_url=base_url)
        result.endpoints = set(endpoints)
        return result
    return crawl


def _fake_probe(sent, *, denied=(), privileged=()):
    """Any authenticated caller gets alice's object (a same-role BOLA) unless its
    token is in `denied`; anonymous gets 401. Paths in `privileged` answer 200
    only to the tokens listed there."""
    async def probe(method, url, headers, timeout, **kwargs):
        auth = (headers or {}).get("Authorization", "")
        sent.append((method, url, auth))
        token = auth.rsplit(" ", 1)[-1] if auth else ""
        for path, allowed in privileged:
            if path in url:
                if token in allowed:
                    return 200, '{"stats":[1,2,3]}', {"content-type": "application/json"}
                return 403, '{"error":"forbidden"}', {"content-type": "application/json"}
        if not auth:
            return 401, '{"error":"unauthorized"}', {"content-type": "application/json"}
        if token in denied:
            return 403, '{"error":"forbidden"}', {"content-type": "application/json"}
        return 200, _ALICE_OBJ, {"content-type": "application/json"}
    return probe


def _crawl(roles, *, denied=(), endpoints=("/api/orders/{id}",), privileged=(), **kw):
    sent: list = []
    with patch("harness.crawler.crawl", _fake_crawl(endpoints)), \
         patch("harness.role_crawl._probe", _fake_probe(sent, denied=denied, privileged=privileged)):
        return asyncio.run(role_crawl.crawl_roles(_BASE, roles, allowed_hosts=_HOSTS, **kw))


def _anon():
    return RoleSession("anonymous", {})


def _named_same_role():
    return [_anon(),
            RoleSession("user", {"Authorization": "Bearer alice"}, name="alice"),
            RoleSession("user", {"Authorization": "Bearer bob"}, name="bob")]


def _label_encoded():
    return [_anon(),
            RoleSession("alice-user", {"Authorization": "Bearer alice"}),
            RoleSession("bob-user", {"Authorization": "Bearer bob"})]


def _orders(result):
    rows = [e for e in result.endpoints if e.path == _ORDERS]
    assert rows, "precondition: the object-scoped endpoint was not probed"
    return rows[0]


def _compare_findings(result):
    return [f for f in result.idor_findings
            if f"cross_identity_compare:{_ORDERS}" in (f.get("validation_hints") or [])]


def _authed_cells(row):
    return sorted(pid for pid, cell in row.by_principal.items() if cell["role"] != "anonymous")


class PrincipalMatrixParityTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def test_identity_in_role_label_and_named_principals_agree(self):
        # F2 parity: encoding identity in the role label must not change the outcome.
        named, labelled = _crawl(_named_same_role()), _crawl(_label_encoded())
        self.assertEqual(len(_compare_findings(named)), 1)
        self.assertEqual(len(_compare_findings(labelled)), 1)
        self.assertEqual(len(_orders(named).reachable_principals),
                         len(_orders(labelled).reachable_principals))

    def test_unnamed_same_role_sessions_with_distinct_credentials_stay_distinct(self):
        roles = [_anon(),
                 RoleSession("user", {"Authorization": "Bearer alice"}),
                 RoleSession("user", {"Authorization": "Bearer bob"})]
        result = _crawl(roles)
        row = _orders(result)
        self.assertEqual(_authed_cells(row), sorted(r.principal_id() for r in roles[1:]),
                         f"distinct credentials collapsed: {sorted(row.by_principal)}")
        self.assertEqual(row.reachable_roles, ["user"])
        self.assertEqual(len(_compare_findings(result)), 1)

    def test_negative_control_bob_denied_yields_no_finding(self):
        for roles in (_named_same_role(), _label_encoded()):
            with self.subTest(roles=[r.principal_id() for r in roles]):
                self.assertEqual(_compare_findings(_crawl(roles, denied=("bob",))), [])

    def test_negative_control_renewed_credential_is_one_principal(self):
        # The same principal under two credentials (renewal) is one cell; it
        # must never be compared against itself.
        roles = [_anon(),
                 RoleSession("user", {"Authorization": "Bearer alice-old"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer alice-new"}, name="alice")]
        result = _crawl(roles)
        row = _orders(result)
        self.assertEqual(_authed_cells(row), ["alice"])
        self.assertEqual(row.reachable_principals, ["alice"])
        self.assertEqual(_compare_findings(result), [])

    def test_role_attribute_still_drives_function_level_trust(self):
        # alice (role user) reaches an admin-looking path that root (role admin)
        # cannot: the inverted-privilege candidate must still fire on role trust.
        roles = [RoleSession("user", {"Authorization": "Bearer alice"}, name="alice"),
                 RoleSession("admin", {"Authorization": "Bearer root"}, name="root")]
        result = _crawl(roles, endpoints=("/api/admin/stats",),
                        privileged=(("/api/admin/stats", ("alice",)),))
        authz = [c for c in result.auth_bypass_candidates if c["class"] == "authz"]
        self.assertEqual(len(authz), 1, result.auth_bypass_candidates)
        self.assertEqual(authz[0]["reached_by"], ["user"])
        self.assertEqual(authz[0]["reached_by_principals"], ["alice"])

    def test_cross_role_probe_pairs_same_role_principals(self):
        owned = {"alice": {_ORDERS: "101"}, "bob": {_ORDERS: "202"}}
        result = _crawl(_named_same_role(), owned_object_ids=owned)
        pairs = {(o["owner_role"], o["requester_role"], o["classification"])
                 for o in result.cross_role_outcomes}
        self.assertIn(("alice", "bob", "leaked"), pairs)
        self.assertIn(("bob", "alice", "leaked"), pairs)
        self.assertFalse([p for p in pairs if p[0] == p[1]], f"a principal probed itself: {pairs}")

    def test_cross_role_probe_accepts_a_principal_id_as_owner(self):
        roles = [RoleSession("user", {"Authorization": "Bearer alice"}),
                 RoleSession("user", {"Authorization": "Bearer bob"})]
        alice_id, bob_id = (r.principal_id() for r in roles)
        result = _crawl(roles, owned_object_ids={alice_id: {_ORDERS: "101"}, bob_id: {_ORDERS: "202"}})
        pairs = {(o["owner_role"], o["requester_role"]) for o in result.cross_role_outcomes}
        self.assertEqual(pairs, {(alice_id, bob_id), (bob_id, alice_id)})


def _fake_discovery_none():
    class _NoDiscovery:
        def __init__(self, base_url, **kwargs):
            self.base_url = base_url

        async def discover(self):
            from harness.api_surface_discovery import SurfaceResult
            return SurfaceResult(base_url=self.base_url, routes=[], probes_sent=0)
    return _NoDiscovery


def _build(roles, *, seeds=None, endpoints=("/api/orders/{id}",), denied=()):
    sent: list = []
    with patch("harness.crawler.crawl", _fake_crawl(endpoints)), \
         patch("harness.api_surface_discovery.SurfaceDiscovery", _fake_discovery_none()), \
         patch("harness.role_crawl._probe", _fake_probe(sent, denied=denied)):
        return asyncio.run(engagement_builder.build_engagement(
            _BASE, roles, allowed_hosts=_HOSTS, seed_exchanges=seeds))


def _role_view_only(cells, reachable_roles, principal_id, role):
    """Fault injection: reachability read from the role view alone."""
    return (role or principal_id) in (reachable_roles or [])


class _RecordedLeg:
    status = "not_confirmed"
    summary = ""
    confidence = None
    evidence = ""
    validator = "stub"


class WorklistProbePrincipalTests(unittest.TestCase):
    """The worklist probes as a principal whose own cell reached the node."""

    def setUp(self):
        global_throttle.configure(0)

    def _order_probes(self, roles, *, denied):
        from harness import worklist_investigator
        state, _ = _build(roles, denied=denied)
        probed = []

        async def probe_fn(exchange, hypothesis, specialty, step_budget):
            probed.append((exchange.url, dict(exchange.request_headers or {})))
            return {"findings": []}

        outcomes = asyncio.run(worklist_investigator.investigate_worklist(
            probe_fn, state, _BASE.rstrip("/"), roles, max_nodes=4))
        order_outcomes = [o for o in outcomes if o.get("path") == _ORDERS]
        self.assertTrue(order_outcomes, "the object-scoped node was not investigated")
        order_probes = [h for url, h in probed if "/api/orders/" in url]
        self.assertTrue(order_probes, "the object-scoped node was never probed")
        return order_outcomes[0], order_probes

    def test_worklist_skips_the_denied_same_role_principal(self):
        # bob is listed last: a role-keyed credential lookup keeps his headers.
        outcome, probes = self._order_probes(_named_same_role(), denied=("bob",))
        self.assertEqual(outcome["probe_role"], "user")
        self.assertEqual(outcome["probe_principal"], "alice")
        self.assertEqual(probes[0].get("Authorization"), "Bearer alice",
                         "worklist probed the object as the principal that was denied")

    def test_fault_role_view_only_probes_as_the_denied_principal(self):
        anon, alice, bob = _named_same_role()
        roles = [anon, bob, alice]   # bob first: the role view alone takes the first of role user
        outcome, probes = self._order_probes(roles, denied=("bob",))
        self.assertEqual(probes[0].get("Authorization"), "Bearer alice", "precondition")
        with patch("harness.engagement.principal_reached", _role_view_only):
            _, probes = self._order_probes(roles, denied=("bob",))
        self.assertEqual(probes[0].get("Authorization"), "Bearer bob",
                         "fault injection is inert: the role view alone no longer picks bob")


class CoverageIdentityByPrincipalTests(unittest.TestCase):
    """Coverage reachability follows each principal's own cell (X03 review): a
    principal that reached an endpoint -- including one NAMED like a role --
    says nothing about another principal of that role."""

    def setUp(self):
        global_throttle.configure(0)

    def _drive(self, roles, *, denied):
        from harness import coverage_tracker
        state, _ = _build(roles, denied=denied)
        driven = []

        async def run_leg(identity, method, path, check):
            driven.append((identity, method, path))
            return _RecordedLeg()

        asyncio.run(coverage_tracker.build_coverage_driven(state, roles, run_leg, budget=500))
        return state, driven

    @staticmethod
    def _same_role_cases():
        return {
            "alice and bob": [_anon(),
                              RoleSession("user", {"Authorization": "Bearer alice"}, name="alice"),
                              RoleSession("user", {"Authorization": "Bearer bob"}, name="bob")],
            "a principal named like the role": [
                _anon(),
                RoleSession("user", {"Authorization": "Bearer usr"}, name="user"),
                RoleSession("user", {"Authorization": "Bearer bob"}, name="bob")],
        }

    def test_denied_same_role_principal_gets_no_legs(self):
        for case, roles in self._same_role_cases().items():
            with self.subTest(case=case):
                state, driven = self._drive(roles, denied=("bob",))
                ep = state.endpoints[f"GET {_ORDERS}"]
                self.assertEqual(ep.reachable_roles, ["user"], "precondition: role user reached")
                self.assertEqual(ep.access_by_principal["bob"]["status"], 403)
                reacher = roles[1].name
                bob_legs = [d for d in driven if d[0] == "bob" and d[2] == _ORDERS]
                self.assertEqual(bob_legs, [], f"{len(bob_legs)} leg(s) scheduled as the denied bob")
                self.assertTrue([d for d in driven if d[0] == reacher and d[2] == _ORDERS],
                                f"the reaching principal {reacher!r} got no legs (control)")

    def test_fault_role_view_only_schedules_legs_as_the_denied_principal(self):
        roles = self._same_role_cases()["alice and bob"]
        with patch("harness.engagement.principal_reached", _role_view_only):
            _, driven = self._drive(roles, denied=("bob",))
        self.assertTrue([d for d in driven if d[0] == "bob" and d[2] == _ORDERS],
                        "fault injection is inert: the role view alone gives bob no legs")

    def test_jwt_leg_identity_follows_the_principal_cell(self):
        from harness.engagement import principal_cell
        from harness.orchestrator_helpers import _jwt_identity
        jwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
        # bob first: a role-label match would pick bob whenever role user reached.
        roles = [RoleSession("user", {"Authorization": jwt + "b"}, name="bob"),
                 RoleSession("user", {"Authorization": jwt + "u"}, name="user")]

        def node(reached_by):
            return {"reachable_roles": ["user"],
                    "access_by_principal": {
                        pid: principal_cell(role="user", status=200 if pid == reached_by else 403,
                                            reachable=pid == reached_by)
                        for pid in ("bob", "user")}}

        self.assertEqual(_jwt_identity(node("bob"), roles).name, "bob")
        self.assertEqual(_jwt_identity(node("user"), roles).name, "user")

    def test_legacy_role_keyed_matrix_still_matches_by_role(self):
        # A role-only record (a snapshot from before principal cells, or a stub)
        # has no cell for these principals: fall back to the role view.
        from harness import coverage_tracker
        from harness.engagement import EngagementState
        st = EngagementState(host="shop.test")
        ep = st._ep("GET", _ORDERS)
        ep.reachable_roles = ["user"]
        ep.object_scoped = True
        roles = [RoleSession("user", {"Authorization": "Bearer A"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer B"}, name="bob")]
        driven = []

        async def run_leg(identity, method, path, check):
            driven.append(identity)
            return _RecordedLeg()

        asyncio.run(coverage_tracker.build_coverage_driven(st, roles, run_leg, budget=500))
        self.assertIn("alice", driven)
        self.assertIn("bob", driven)


class RoleCrawlApiKeepsPrincipalNamesTests(unittest.TestCase):
    """The API role inputs carry the principal name through to the matrix (X03
    review): renewed credentials of one named principal stay one cell."""

    _RENEWED = [{"role": "anonymous", "headers": {}},
                {"role": "user", "name": "alice", "headers": {"Authorization": "Bearer alice-old"}},
                {"role": "user", "name": "alice", "headers": {"Authorization": "Bearer alice-new"}}]

    def setUp(self):
        global_throttle.configure(0)
        import harness.server as server_module
        from fastapi.testclient import TestClient
        self.server_module = server_module
        self._prev_hosts = server_module.orchestrator.allowed_hosts
        server_module.orchestrator.allowed_hosts = _HOSTS
        self._prev_active = server_module.orchestrator.validator_registry.active_enabled
        server_module.orchestrator.validator_registry.set_active_enabled(True)
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})

    def tearDown(self):
        self.server_module.orchestrator.validator_registry.set_active_enabled(self._prev_active)
        self.server_module.orchestrator.allowed_hosts = self._prev_hosts

    def _post(self, path, roles, **extra):
        sent: list = []
        with patch("harness.crawler.crawl", _fake_crawl()), \
             patch("harness.role_crawl._probe", _fake_probe(sent)), \
             patch("harness.server._update_engagement", lambda host, fn: None), \
             patch("harness.store.load_engagement", lambda host: None):
            resp = self.client.post(path, json={"base_url": _BASE, "roles": roles, **extra})
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    @staticmethod
    def _orders_row(crawl):
        return next(e for e in crawl["endpoints"] if e["path"] == _ORDERS)

    def test_crawl_roles_keeps_a_renewed_principal_as_one_cell(self):
        body = self._post("/crawl-roles", self._RENEWED, register_identities=False)
        row = self._orders_row(body)
        self.assertEqual(sorted(row["by_principal"]), ["alice", "anonymous"])
        self.assertEqual(row["by_principal"]["alice"]["role"], "user")
        self.assertEqual(body["idor_findings"], [],
                         "one principal's two credentials were compared as two identities")

    def test_crawl_roles_keeps_named_same_role_principals_distinct(self):
        roles = [{"role": "anonymous", "headers": {}},
                 {"role": "user", "name": "alice", "headers": {"Authorization": "Bearer alice"}},
                 {"role": "user", "name": "bob", "headers": {"Authorization": "Bearer bob"}}]
        body = self._post("/crawl-roles", roles, register_identities=False)
        self.assertEqual(sorted(self._orders_row(body)["by_principal"]), ["alice", "anonymous", "bob"])
        self.assertEqual(len(body["idor_findings"]), 1)

    def test_engagement_advance_keeps_a_renewed_principal_as_one_cell(self):
        body = self._post("/engagement/shop.test/advance", self._RENEWED)
        self.assertEqual(sorted(self._orders_row(body["crawl"])["by_principal"]), ["alice", "anonymous"])


if __name__ == "__main__":
    unittest.main()
