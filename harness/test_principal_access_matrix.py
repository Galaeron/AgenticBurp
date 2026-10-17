"""The access matrix is keyed by principal, not by role label (X03).

Ported from the 2026-10-17 dual-mode audit probe
(reviews/2026-10-17-dual-mode-audit-opus55/evidence/role_matrix_probe.py) and
the F2 fixture in that audit's CROSS_REQUEST_ACCEPTANCE_SPEC.md.

Two named principals sharing the role label "user" (alice, bob) must stay two
matrix columns, so the same-object comparison can fire for the canonical
user-to-user BOLA. The same data with identity encoded in the role label must
give the same outcome. Role stays an attribute for trust decisions.

Callers: role_crawl.crawl_roles (the producer behind POST /crawl-roles and
engagement_builder.build_engagement), build_engagement itself (including its
seed-capture ingest) and worklist_investigator.investigate_worklist. The crawler
and the per-request probe are replaced by in-memory fakes, so no request leaves
the process. Negative controls: bob denied -> no finding; one principal under two
renewed credentials -> one column, no self-comparison. Fault injection: re-keying
the matrix by role must make the distinctness assertions fail.
"""
import asyncio
import json
import unittest
from unittest.mock import patch

from harness import engagement_builder, global_throttle, role_crawl
from harness.models import HttpExchange
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


class PrincipalKeyedMatrixTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def assert_distinct_principals(self, result):
        """F2: alice and bob stay two columns and produce the comparison."""
        row = _orders(result)
        self.assertEqual(sorted(row.by_role), ["alice", "anonymous", "bob"],
                         "two named principals sharing role 'user' collapsed into one column")
        self.assertEqual(sorted(row.reachable_roles), ["alice", "bob"])
        self.assertEqual(set(row.fingerprints), {"alice", "anonymous", "bob"})
        found = _compare_findings(result)
        self.assertEqual(len(found), 1, "same-object comparison did not fire for user-to-user BOLA")
        self.assertIn("alice", found[0]["summary"])
        self.assertIn("bob", found[0]["summary"])

    def test_same_role_named_principals_stay_distinct_columns(self):
        self.assert_distinct_principals(_crawl(_named_same_role()))

    def test_role_stays_an_attribute_of_each_column(self):
        row = _orders(_crawl(_named_same_role()))
        self.assertEqual(row.principal_roles,
                         {"anonymous": "anonymous", "alice": "user", "bob": "user"})
        self.assertEqual(row.to_dict()["principal_roles"], row.principal_roles)

    def test_identity_in_role_label_and_named_principals_agree(self):
        # F2 parity: encoding identity in the role label must not change the outcome.
        named, labelled = _crawl(_named_same_role()), _crawl(_label_encoded())
        self.assertEqual(len(_compare_findings(labelled)), 1)
        self.assertEqual(len(_compare_findings(named)), len(_compare_findings(labelled)))
        self.assertEqual(len(_orders(named).reachable_roles), len(_orders(labelled).reachable_roles))

    def test_unnamed_same_role_sessions_with_distinct_credentials_stay_distinct(self):
        roles = [_anon(),
                 RoleSession("user", {"Authorization": "Bearer alice"}),
                 RoleSession("user", {"Authorization": "Bearer bob"})]
        result = _crawl(roles)
        row = _orders(result)
        authed = [k for k in row.by_role if k != "anonymous"]
        self.assertEqual(len(authed), 2, f"distinct credentials collapsed: {sorted(row.by_role)}")
        self.assertEqual(sorted(authed), sorted(r.principal_id() for r in roles[1:]))
        self.assertEqual(len(_compare_findings(result)), 1)

    def test_negative_control_bob_denied_yields_no_finding(self):
        for roles in (_named_same_role(), _label_encoded()):
            with self.subTest(roles=[r.principal_id() for r in roles]):
                self.assertEqual(_compare_findings(_crawl(roles, denied=("bob",))), [])

    def test_negative_control_renewed_credential_is_one_principal(self):
        # The same principal under two credentials (renewal) is one column; it
        # must never be compared against itself.
        roles = [_anon(),
                 RoleSession("user", {"Authorization": "Bearer alice-old"}, name="alice"),
                 RoleSession("user", {"Authorization": "Bearer alice-new"}, name="alice")]
        result = _crawl(roles)
        row = _orders(result)
        self.assertEqual(len([k for k in row.by_role if k != "anonymous"]), 1)
        self.assertEqual(len(set(row.reachable_roles)), len(row.reachable_roles),
                         "one principal listed twice as reachable")
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
        self.assertEqual(len(authz[0]["reached_by"]), 1)

    def test_cross_role_probe_keys_owned_objects_by_principal(self):
        owned = {"alice": {_ORDERS: "101"}, "bob": {_ORDERS: "202"}}
        result = _crawl(_named_same_role(), owned_object_ids=owned)
        pairs = {(o["owner_role"], o["requester_role"], o["classification"])
                 for o in result.cross_role_outcomes}
        self.assertIn(("alice", "bob", "leaked"), pairs)
        self.assertIn(("bob", "alice", "leaked"), pairs)
        self.assertNotIn(("alice", "alice", "leaked"), pairs)


class PrincipalKeyedMatrixFaultInjectionTests(unittest.TestCase):
    """CROSS_REQUEST_ACCEPTANCE_SPEC.md section 5: re-keying the matrix by role
    must make the F2 assertions fail (the audit's probe case A)."""

    def setUp(self):
        global_throttle.configure(0)

    def test_rekeying_by_role_collapses_principals_and_fails_f2(self):
        checker = PrincipalKeyedMatrixTests("test_same_role_named_principals_stay_distinct_columns")
        with patch("harness.role_crawl.principal_keys",
                   lambda roles: [r.role for r in roles]):
            result = _crawl(_named_same_role())
        self.assertEqual(sorted(_orders(result).by_role), ["anonymous", "user"],
                         "fault injection is inert: role keying no longer collapses principals")
        with self.assertRaises(AssertionError):
            checker.assert_distinct_principals(result)


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


def _seed(token, status, body):
    return HttpExchange(url="http://shop.test/api/orders/7", method="GET",
                        request_headers={"Authorization": f"Bearer {token}"},
                        response_status=status, response_headers={"Content-Type": "application/json"},
                        response_body=body)


class EngagementBuilderPrincipalTests(unittest.TestCase):
    """F2 through the engagement builder and its worklist consumer."""

    def setUp(self):
        global_throttle.configure(0)

    def test_build_engagement_keeps_same_role_principals_distinct(self):
        state, result = _build(_named_same_role())
        ep = state.endpoints[f"GET {_ORDERS}"]
        self.assertEqual(sorted(ep.access), ["alice", "anonymous", "bob"])
        self.assertEqual(sorted(ep.reachable_roles), ["alice", "bob"])
        self.assertEqual(ep.access_roles.get("alice"), "user")
        self.assertEqual(len(_compare_findings(result)), 1)
        self.assertTrue(ep.findings, "the comparison finding did not reach the engagement state")
        _, reasons = ep.fused_score()
        self.assertTrue(any("IDOR candidate" in r for r in reasons), reasons)

    def test_seed_captures_attribute_to_principal_not_role(self):
        seeds = [_seed("alice", 200, _ALICE_OBJ), _seed("bob", 403, '{"error":"forbidden"}')]
        state, result = _build(_named_same_role(), seeds=seeds, endpoints=())
        ep = state.endpoints[f"GET {_ORDERS}"]
        self.assertEqual(ep.access.get("alice"), 200)
        self.assertEqual(ep.access.get("bob"), 403, f"bob's denial was lost: {ep.access}")
        self.assertEqual(ep.reachable_roles, ["alice"])
        row = _orders(result)
        self.assertEqual(row.by_role.get("alice"), 200)
        self.assertEqual(row.by_role.get("bob"), 403)

    def test_worklist_probes_as_a_reaching_principal_with_its_credentials(self):
        from harness import worklist_investigator
        roles = _named_same_role()
        state, _ = _build(roles)
        probed = []

        async def probe_fn(exchange, hypothesis, specialty, step_budget):
            probed.append((exchange.url, dict(exchange.request_headers or {})))
            return {"findings": []}

        outcomes = asyncio.run(worklist_investigator.investigate_worklist(
            probe_fn, state, _BASE.rstrip("/"), roles, max_nodes=4))
        order_outcomes = [o for o in outcomes if o.get("path") == _ORDERS]
        self.assertTrue(order_outcomes, "the object-scoped node was not investigated")
        self.assertIn(order_outcomes[0]["probe_role"], {"alice", "bob"})
        order_probes = [h for url, h in probed if "/api/orders/" in url]
        self.assertTrue(order_probes)
        self.assertIn(order_probes[0].get("Authorization"), {"Bearer alice", "Bearer bob"},
                      "worklist probed the object as no authenticated principal")


if __name__ == "__main__":
    unittest.main()
