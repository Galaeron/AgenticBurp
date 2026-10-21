"""Batch RV-S (I10): the operator declares which routes are protected.

RV-M stopped the engagement chain from treating a model label or a privileged-looking
path as a protection declaration, so the chain could no longer confirm missing
authentication at all. The owner decided (2026-10-21) that protected routes come from
an operator list of path patterns per target: ``authz.protected_paths`` in
config.local.yaml, keyed by host (or host:port), plus an optional list on the
engagement. A listed route goes to the missing-auth probe as declared protected with
an authenticated baseline; an unlisted route stays the unconfirmed candidate it was.

Every chain case drives ``Orchestrator.investigate_engagement`` with the real
``_confirm`` dispatcher and the real ``missing_auth_probe`` against an owned loopback
server. Only the engagement builder and the worklist investigator are doubled, as in
RV-M's ``ChainMissingAuthDeclarationTests``, to hand a node to the real callbacks. The
probe identity is anonymous, as ``investigate_worklist`` picks the lowest-trust role
that reached the node.

S1  a listed route that serves the authenticated data anonymously is confirmed, and the
    evidence names the pattern and its source.
S2  an unlisted route stays a candidate.
S3  a listed route that denies anonymous access gives no finding.
S4  a listed route whose anonymous answer differs from the baseline is not confirmed.
S5  malformed entries are ignored, warned about, and never confirm.
S6  engagement and config lists combine; a pattern for another host never matches.
"""
from __future__ import annotations

import asyncio
import socketserver
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import (config_schema, engagement_builder, protected_routes, role_crawl,
                     worklist_investigator)
from harness.engagement import EngagementState
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RunContext

_HARNESS = Path(__file__).resolve().parent
_REPORT = '{"report": "q3 payroll", "rows": 41}'
_PUBLIC_DOCS = ("<h1>Administrator help</h1><p>Public documentation: how to request an "
                "administrator account and where to find the release notes.</p>")
_ADMIN_CONSOLE = '{"admins": ["root", "ops"], "pending_invites": 3}'
_TOKEN = "Bearer user-token"


class _Loopback:
    """Owned loopback server. `route(path, headers) -> (status, body)` answers every
    GET; each request is recorded as (path, lower-cased headers)."""

    def __init__(self, route):
        self.requests: list[tuple[str, dict]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                headers = {k.lower(): v for k, v in self.headers.items()}
                outer.requests.append((self.path, headers))
                status, body = route(self.path, headers)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.key = f"127.0.0.1:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def sent_to(self, path: str) -> list[dict]:
        return [h for p, h in self.requests if p == path]


def _chain_config() -> dict:
    cfg = yaml.safe_load((_HARNESS / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = True
    cfg["validators"]["allow_mutating_replay"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    eng["coverage_drive_legs"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


def _node(path: str) -> dict:
    return {"method": "GET", "path": path, "reachable_roles": ["anonymous"],
            "template": {"method": "GET", "query": "", "body": "", "content_type": "",
                         "object_id": None}}


def _roles(user_headers: dict | None = None) -> list[RoleSession]:
    return [RoleSession("anonymous", {}),
            RoleSession("user", dict(user_headers or {"Authorization": _TOKEN}), name="alice")]


def _leak(path, headers):
    """The bug: the report is served whether or not credentials are attached."""
    return 200, _REPORT


def _authz(paths) -> dict:
    return {"protected_paths": paths}


class _ChainCase(unittest.TestCase):
    """Drives the production chain with the doubled builder and worklist."""

    def _run_chain(self, route, paths, *, authz=None, engagement_paths=None,
                   roles=None, via: str = "shape", use_run_context: bool = False):
        """`authz(server) -> dict | None` builds the config's `authz` section once the
        server's port is known. Returns ({path: findings}, server)."""
        server = _Loopback(route)
        self.addCleanup(server.close)
        base = server.origin + "/"
        nodes = [_node(p) for p in paths]
        roles = roles if roles is not None else _roles()

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": n["path"], "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False,
                "template": n["template"]} for n in nodes]})
            if engagement_paths is not None:
                state.protected_paths = engagement_paths
            return state, role_crawl.RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            outcomes = []
            for node in nodes:
                ex = worklist_investigator._seed_exchange(base, node, {}, "1")
                if via == "shape":
                    findings = await kwargs["precondition_fn"](node, ex)
                else:
                    label = {"vulnerability_class": "missing_authentication",
                             "confidence": 0.6, "severity": "high",
                             "summary": "model: served without auth", "evidence": "",
                             "suggested_test": "", "basis": "agent"}
                    await kwargs["confirm_fn"](label, ex)
                    findings = [label]
                outcomes.append({"path": node["path"], "method": "GET",
                                 "findings_detail": findings,
                                 "confirmed": any(f.get("confirmed") for f in findings)})
            return outcomes

        cfg = _chain_config()
        section = authz(server) if authz is not None else None
        if section is not None:
            cfg["authz"] = section
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]

        async def drive():
            kwargs = dict(max_nodes=len(nodes), max_chain_rounds=0, discovery_max_probes=1)
            if not use_run_context:
                return await orch.investigate_engagement(base, roles, **kwargs)
            rc = RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg)
            async with rc:
                return await orch.investigate_engagement(base, roles, run_context=rc, **kwargs)

        with patch.object(engagement_builder, "build_engagement", new=build), \
                patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
                patch("harness.orchestrator_chain.review_captured_exchanges",
                      new=AsyncMock(return_value=0)), \
                patch("harness.orchestrator_chain.universal_header_audit",
                      new=AsyncMock(return_value=0)), \
                patch.object(orch, "_persist_confirmation_proof",
                             new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(drive())
        by_path = {o["path"]: o["findings_detail"] for o in result["outcomes"]}
        return by_path, server

    def _assert_confirmed(self, findings, pattern: str, source: str):
        self.assertEqual(len(findings), 1, findings)
        f = findings[0]
        self.assertTrue(f.get("confirmed"), f.get("evidence"))
        self.assertEqual(f.get("confirmed_by_leg"), "missing_auth")
        self.assertIn("missing-auth CONFIRMED", f.get("evidence", ""))
        self.assertIn(repr(pattern), f["evidence"], "the evidence must name the pattern")
        self.assertIn(source, f["evidence"], "the evidence must name the pattern's source")
        self.assertEqual(f.get("protected_route", {}).get("pattern"), pattern)
        self.assertEqual(f.get("protected_route", {}).get("source"), source)

    def _assert_anonymous_then_baseline(self, sent):
        self.assertEqual([h.get("authorization") for h in sent], [None, _TOKEN],
                         "an anonymous replay, then one authenticated baseline")
        self.assertNotIn("cookie", sent[0])

    def _assert_not_confirmed(self, findings, via):
        if via == "shape":
            self.assertEqual(findings, [], "the precondition leg keeps only confirmations")
        else:
            self.assertFalse(findings[0].get("confirmed"), findings[0].get("evidence"))
            self.assertNotIn("confirmed_by_leg", findings[0])
            self.assertNotIn("missing-auth CONFIRMED", findings[0].get("evidence", ""))


# ------------------------------------------------------------------ S1
class ListedRouteConfirmsTests(_ChainCase):
    """S1: an operator-listed route that serves the authenticated payload to an
    anonymous caller is confirmed, through either chain entry."""

    def _listed(self, server):
        return _authz({server.key: ["/admin/**"]})

    def test_shape_leg_confirms_a_listed_route(self):
        found, server = self._run_chain(_leak, ["/admin/report"], authz=self._listed)
        self._assert_confirmed(found["/admin/report"], "/admin/**", "config")
        self._assert_anonymous_then_baseline(server.sent_to("/admin/report"))

    def test_model_label_on_a_listed_route_is_confirmed(self):
        found, server = self._run_chain(_leak, ["/admin/report"], authz=self._listed,
                                        via="label")
        self._assert_confirmed(found["/admin/report"], "/admin/**", "config")
        self._assert_anonymous_then_baseline(server.sent_to("/admin/report"))

    def test_listed_route_confirms_inside_a_run(self):
        """The server's /engagement/investigate path owns a RunContext."""
        found, server = self._run_chain(_leak, ["/admin/report"], authz=self._listed,
                                        use_run_context=True)
        self._assert_confirmed(found["/admin/report"], "/admin/**", "config")
        self._assert_anonymous_then_baseline(server.sent_to("/admin/report"))


# ------------------------------------------------------------------ S2
class UnlistedRouteStaysCandidateTests(_ChainCase):
    """S2: with credentials available and the payload leaking, an unlisted route is
    still not confirmed and no baseline is spent on it. RV-M's
    ChainMissingAuthDeclarationTests keep covering the anonymous-only case."""

    def test_route_outside_the_list_stays_a_candidate(self):
        for via in ("shape", "label"):
            with self.subTest(via=via):
                found, server = self._run_chain(
                    _leak, ["/reports/q3"], via=via,
                    authz=lambda s: _authz({s.key: ["/admin/**"]}))
                self._assert_not_confirmed(found["/reports/q3"], via)
                sent = server.sent_to("/reports/q3")
                self.assertEqual(len(sent), 1, "no baseline for an unlisted route")
                self.assertNotIn("authorization", sent[0])

    def test_no_list_at_all_stays_a_candidate(self):
        found, server = self._run_chain(_leak, ["/admin/report"])
        self.assertEqual(found["/admin/report"], [])
        self.assertEqual(len(server.sent_to("/admin/report")), 1)


# ------------------------------------------------------------------ S3
class ListedRouteDeniedTests(_ChainCase):
    """S3: a listed route that refuses the anonymous caller gives no finding, and the
    anonymous replay carries none of the identity's credentials, including a
    credential header the probe does not know by name."""

    @staticmethod
    def _guarded(path, headers):
        if headers.get("authorization") or headers.get("x-tenant-session"):
            return 200, _REPORT
        return 401, '{"error": "login required"}'

    def test_denied_listed_route_has_no_finding(self):
        roles = _roles({"Authorization": _TOKEN, "X-Tenant-Session": "t-1"})
        for via in ("shape", "label"):
            with self.subTest(via=via):
                found, server = self._run_chain(
                    self._guarded, ["/admin/report"], roles=roles, via=via,
                    authz=lambda s: _authz({s.key: ["/admin/**"]}))
                self._assert_not_confirmed(found["/admin/report"], via)
                sent = server.sent_to("/admin/report")
                self.assertEqual(len(sent), 1, "no baseline after an anonymous denial")
                self.assertFalse({"authorization", "x-tenant-session", "cookie"} & set(sent[0]))


# ------------------------------------------------------------------ S4
class ListedRouteDiffersFromBaselineTests(_ChainCase):
    """S4: a listed route whose anonymous answer is a public page while the
    authenticated baseline is the protected payload is not confirmed."""

    @staticmethod
    def _public_help(path, headers):
        return (200, _ADMIN_CONSOLE) if headers.get("authorization") else (200, _PUBLIC_DOCS)

    def test_public_page_differing_from_the_baseline_is_not_confirmed(self):
        for via in ("shape", "label"):
            with self.subTest(via=via):
                found, server = self._run_chain(
                    self._public_help, ["/admin/help"], via=via,
                    authz=lambda s: _authz({s.key: ["/admin/**"]}))
                self._assert_not_confirmed(found["/admin/help"], via)
                self._assert_anonymous_then_baseline(server.sent_to("/admin/help"))


# ------------------------------------------------------------------ S5
class MalformedEntriesTests(_ChainCase):
    """S5: a malformed entry is ignored with a warning and never makes a route
    protected. Each config would list /admin/report if it were read leniently."""

    _CASES = {
        "malformed patterns": lambda s: _authz({s.key: [
            "", "   ", 42, None, ["/admin/report"], {"path": "/admin/report"},
            "admin/report", "/admin/***", "/admin/rep**", "/admin/report?tab=1",
            "/admin/report#top", "GET", "GET POST /admin/report", "G3T /admin/report",
            "https://127.0.0.1/admin/report"]}),
        "host value not a list": lambda s: _authz({s.key: "/admin/report"}),
        "protected_paths not a mapping": lambda s: _authz(["/admin/report"]),
        "authz not a mapping": lambda s: "/admin/report",
        "malformed host key": lambda s: _authz({
            f"http://{s.key}": ["/admin/report"], f"{s.key}/": ["/admin/report"],
            "127.0.0.1:0x50": ["/admin/report"], "": ["/admin/report"],
            7: ["/admin/report"]}),
    }

    def test_malformed_entries_never_confirm_and_are_warned_about(self):
        for name, authz in self._CASES.items():
            with self.subTest(name):
                with self.assertLogs("harness.protected_routes", "WARNING") as logs:
                    found, server = self._run_chain(_leak, ["/admin/report"], authz=authz)
                self.assertEqual(found["/admin/report"], [])
                self.assertEqual(len(server.sent_to("/admin/report")), 1)
                self.assertTrue(any("ignored" in line for line in logs.output), logs.output)

    def test_malformed_engagement_list_never_confirms(self):
        for value in ("/admin/report", {"/admin/report": True}, ["admin/report", 3, ""]):
            with self.subTest(value=value):
                with self.assertLogs("harness.protected_routes", "WARNING"):
                    found, _ = self._run_chain(_leak, ["/admin/report"],
                                               engagement_paths=value)
                self.assertEqual(found["/admin/report"], [])


# ------------------------------------------------------------------ S6
class CombinedSourcesTests(_ChainCase):
    """S6: the engagement's list and the config's list both declare routes; an entry
    keyed to another host, or to this host's default port, never matches."""

    @staticmethod
    def _config(server):
        return _authz({"other.example.test": ["/admin/**"],
                       "127.0.0.1": ["/admin/**"],
                       "127.0.0.2:" + str(server.port): ["/admin/**"],
                       server.key: ["GET /invoices/*"]})

    def test_both_sources_declare_and_other_hosts_do_not(self):
        found, server = self._run_chain(
            _leak, ["/admin/console", "/reports/q3", "/invoices/{id}"],
            authz=self._config, engagement_paths=["/reports/*"])
        self.assertEqual(found["/admin/console"], [],
                         "a pattern keyed to another host or port must not match")
        self.assertEqual(len(server.sent_to("/admin/console")), 1)
        self._assert_confirmed(found["/reports/q3"], "/reports/*", "engagement")
        self._assert_confirmed(found["/invoices/{id}"], "GET /invoices/*", "config")
        self._assert_anonymous_then_baseline(server.sent_to("/invoices/1"))

    def test_engagement_list_alone_declares(self):
        found, _ = self._run_chain(_leak, ["/reports/q3"], engagement_paths=["/reports/**"])
        self._assert_confirmed(found["/reports/q3"], "/reports/**", "engagement")


# ------------------------------------------------------------------ syntax
def _routes(patterns, target="https://app.example.test/", key="app.example.test"):
    return protected_routes.ProtectedRoutes.for_target(
        {"authz": {"protected_paths": {key: patterns}}}, target)


class PatternSyntaxTests(unittest.TestCase):
    """Glob semantics: anchored to the whole normalized path, `*` within a segment,
    `**` across segments, case-sensitive path, optional method."""

    URL = "https://app.example.test"

    def _hits(self, pattern, method, path):
        return _routes([pattern]).match(method, self.URL + path) is not None

    def test_single_star_stays_within_one_segment(self):
        self.assertTrue(self._hits("/api/*/profile", "GET", "/api/alice/profile"))
        self.assertFalse(self._hits("/api/*/profile", "GET", "/api/a/b/profile"))
        self.assertTrue(self._hits("/files/*.pdf", "GET", "/files/q3.pdf"))
        self.assertFalse(self._hits("/files/*.pdf", "GET", "/files/sub/q3.pdf"))

    def test_double_star_spans_zero_or_more_segments(self):
        for path in ("/admin", "/admin/", "/admin/users", "/admin/a/b/c"):
            self.assertTrue(self._hits("/admin/**", "GET", path), path)
        for path in ("/administrator", "/x/admin", "/"):
            self.assertFalse(self._hits("/admin/**", "GET", path), path)
        self.assertTrue(self._hits("/api/**/export", "GET", "/api/export"))
        self.assertTrue(self._hits("/api/**/export", "GET", "/api/v1/q/export"))
        self.assertFalse(self._hits("/api/**/export", "GET", "/api/v1/export/x"))
        self.assertTrue(self._hits("/**", "GET", "/"))

    def test_pattern_is_anchored_to_the_whole_path(self):
        self.assertFalse(self._hits("/admin", "GET", "/admin/users"))
        self.assertFalse(self._hits("/admin", "GET", "/v2/admin"))
        self.assertTrue(self._hits("/admin", "GET", "/admin"))

    def test_path_is_case_sensitive(self):
        self.assertFalse(self._hits("/Admin/**", "GET", "/admin/users"))
        self.assertFalse(self._hits("/admin/**", "GET", "/ADMIN/users"))

    def test_optional_method_restricts_the_match(self):
        self.assertFalse(self._hits("POST /admin/**", "GET", "/admin/users"))
        self.assertTrue(self._hits("POST /admin/**", "post", "/admin/users"))
        self.assertTrue(self._hits("get /admin/**", "GET", "/admin/users"))

    def test_query_is_dropped_and_ids_are_normalized(self):
        for pattern in ("/orders/42", "/orders/{id}", "/orders/*"):
            self.assertTrue(self._hits(pattern, "GET", "/orders/7?expand=items"), pattern)
        self.assertTrue(self._hits("/blobs/*", "GET", "/blobs/0123456789abcdef"))

    def test_the_match_names_pattern_and_source(self):
        m = _routes(["GET /admin/**"]).match("GET", self.URL + "/admin/x")
        self.assertEqual((m.pattern, m.source), ("GET /admin/**", "config"))
        self.assertIn("'GET /admin/**'", m.describe())
        e = protected_routes.ProtectedRoutes.for_target(
            {}, self.URL, engagement_paths=["/r/*"]).match("GET", self.URL + "/r/1")
        self.assertEqual(e.source, "engagement")

    def test_matching_cannot_blow_up(self):
        start = time.perf_counter()
        segment = "*a" * 30 + "*b"
        path = "/" + "/".join(["a" * 2000] * 50)
        self.assertFalse(self._hits("/" + "/".join(["**"] * 40) + "/" + segment, "GET", path))
        self.assertLess(time.perf_counter() - start, 5.0)


class TargetKeyTests(unittest.TestCase):
    """The key is the host, or host:port when the port is not the scheme's default;
    a pattern keyed to any other target never matches."""

    def _hits(self, key, url):
        routes = protected_routes.ProtectedRoutes.for_target(
            {"authz": {"protected_paths": {key: ["/admin/**"]}}}, url)
        return routes.match("GET", url.rstrip("/") + "/admin/x") is not None

    def test_bare_host_means_the_default_port_only(self):
        self.assertTrue(self._hits("app.example.test", "https://app.example.test/"))
        self.assertTrue(self._hits("app.example.test", "https://app.example.test:443/"))
        self.assertTrue(self._hits("app.example.test", "http://app.example.test/"))
        self.assertFalse(self._hits("app.example.test", "https://app.example.test:8443/"))

    def test_host_port_key(self):
        self.assertTrue(self._hits("app.example.test:8443", "https://app.example.test:8443/"))
        self.assertTrue(self._hits("app.example.test:443", "https://app.example.test/"))
        self.assertFalse(self._hits("app.example.test:8443", "https://app.example.test/"))
        self.assertTrue(self._hits("[::1]:8080", "http://[::1]:8080/"))

    def test_host_compares_case_insensitively_and_exactly(self):
        self.assertTrue(self._hits("App.Example.TEST", "https://app.example.test/"))
        self.assertFalse(self._hits("example.test", "https://app.example.test/"))
        self.assertFalse(self._hits("other.example.test", "https://app.example.test/"))

    def test_url_on_another_target_never_matches(self):
        routes = _routes(["/admin/**"])
        self.assertIsNone(routes.match("GET", "https://evil.example.test/admin/x"))
        self.assertIsNone(routes.match("GET", "https://app.example.test:8443/admin/x"))
        self.assertIsNone(routes.match("GET", "/admin/x"))

    def test_absent_section_declares_nothing(self):
        for cfg in ({}, {"authz": {}}, {"authz": {"protected_paths": {}}}, None):
            with self.subTest(cfg=cfg):
                routes = protected_routes.ProtectedRoutes.for_target(cfg, "https://a.test/")
                self.assertEqual((routes.patterns, routes.problems), ([], []))


class ConfigSchemaWarningTests(unittest.TestCase):
    """S5 at load time: config_schema reports malformed entries as warnings."""

    def test_malformed_entries_are_warnings_not_errors(self):
        cfg = {"authz": {"protected_paths": {
            "app.example.test": ["/admin/**", "", 7, "admin", "/a/**b", "/x?y=1"],
            "other.test": "/admin/**", "http://bad.test": ["/x"]}}}
        result = config_schema.validate_config(cfg)
        self.assertTrue(result.ok, result.errors)
        text = "\n".join(result.warnings)
        for bad in ("''", "7", "'admin'", "'/a/**b'", "'/x?y=1'", "'other.test'",
                    "'http://bad.test'"):
            self.assertIn(bad, text)
        self.assertNotIn("'/admin/**' ignored", text)
        self.assertEqual(len(result.warnings), 7, result.warnings)

    def test_wrong_section_types_are_warnings(self):
        for cfg in ({"authz": "x"}, {"authz": {"protected_paths": ["/admin/**"]}}):
            with self.subTest(cfg=cfg):
                result = config_schema.validate_config(cfg)
                self.assertTrue(result.ok)
                self.assertTrue(any("ignored" in w for w in result.warnings), result.warnings)

    def test_valid_and_absent_lists_have_no_warning(self):
        for cfg in ({}, {"authz": {"protected_paths": {"a.test:8080": ["GET /x/*"]}}}):
            self.assertEqual(config_schema.validate_config(cfg).warnings, [])


class EngagementListTests(unittest.TestCase):
    """The engagement's list survives a snapshot round trip and a merge; a snapshot
    without one is unchanged."""

    def test_round_trip_and_merge(self):
        st = EngagementState(host="app.example.test")
        self.assertNotIn("protected_paths", st.to_dict())
        st.protected_paths = ["/admin/**"]
        again = EngagementState.from_dict(st.to_dict())
        self.assertEqual(again.protected_paths, ["/admin/**"])
        other = EngagementState(host="app.example.test", protected_paths=["/admin/**", "/r/*"])
        again.merge_from(other)
        self.assertEqual(again.protected_paths, ["/admin/**", "/r/*"])

    def test_malformed_stored_value_is_kept_for_the_warning(self):
        st = EngagementState.from_dict({"host": "a.test", "protected_paths": "/admin/**"})
        self.assertEqual(st.protected_paths, "/admin/**")
        with self.assertLogs("harness.protected_routes", "WARNING"):
            routes = protected_routes.ProtectedRoutes.for_target(
                {}, "https://a.test/", engagement_paths=st.protected_paths)
        self.assertIsNone(routes.match("GET", "https://a.test/admin/x"))


if __name__ == "__main__":
    unittest.main()
