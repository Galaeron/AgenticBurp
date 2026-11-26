"""
r5 (job ec2d4f39326d) leg-routing regressions: a confident finding must reach a
leg that can test its class AND request shape, and a finding no leg can test must
record `no_applicable_leg` -- never a tested negative.

  * POST /rest/user/login "Broken Authentication" went to the GET-only
    cross-identity replay (access_control_gate lists the phrase).
  * GET /rest/admin/application-configuration "Exposed Administrative
    Configuration Data" went to verb_tamper on a 2xx response.
  * GET /api/SecurityQuestions/ "Information Disclosure" was REFUTED by the
    stack-trace detector.
  * GET /rest/memories/ "BOLA" went to cross-identity with no object id.
"""
from __future__ import annotations

import asyncio
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

from harness import (engagement_builder, missing_auth_probe, orchestrator_chain as oc,
                     plan_dispatch, role_crawl, worklist_investigator)
from harness.engagement import EngagementState
from harness.models import Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.test_chain_coverage_rvm import _chain_config
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.base import ValidationResult
from harness.validators.cross_identity_validator import CrossIdentityValidator
from harness.validators.idor_read_validator import IdorReadValidator
from harness.validators.verb_tamper_validator import VerbTamperValidator
from harness.validators.verbose_error_validator import VerboseErrorValidator
from harness.chain_stage_patch import chain_patch
from harness import orchestrator_chain_support as ocs

_O = "http://127.0.0.1:3000"


def _f(vc: str, agent: str = "", summary: str = "") -> Finding:
    return Finding(vulnerability_class=vc, severity="high", confidence=0.8, summary=summary,
                   evidence="", suggested_test="", basis="agent", agent=agent)


def _ex(path: str, method: str = "GET", status=200, body: str = "", req_body: str = "",
        ctype: str = "") -> HttpExchange:
    headers = {"Content-Type": ctype} if ctype else {}
    return HttpExchange(url=_O + path, method=method, request_headers=headers,
                        request_body=req_body, response_status=status,
                        response_headers={}, response_body=body)


def _skip(name: str) -> ValidationResult:
    return ValidationResult(validator=name, status="skipped", finding_class="x",
                            confidence=0.0, confirmed=False, summary="test stub",
                            evidence="", raw_output="")


# ------------------------------------------------------------------ applies()
class ValidatorAppliesShapeTests(unittest.TestCase):
    def test_cross_identity_rejects_login_post_and_collection_read(self):
        v = CrossIdentityValidator.__new__(CrossIdentityValidator)
        self.assertFalse(v.applies(_f("Broken Authentication"),
                                   _ex("/rest/user/login", "POST")))
        self.assertFalse(v.applies(_f("Insecure Data Exposure / BOLA"), _ex("/rest/memories/")))

    def test_cross_identity_still_applies_to_object_and_admin_reads(self):
        v = CrossIdentityValidator.__new__(CrossIdentityValidator)
        self.assertTrue(v.applies(_f("idor"), _ex("/rest/basket/1")))
        self.assertTrue(v.applies(_f("broken_access_control"), _ex("/rest/admin/users")))

    def test_cross_identity_rejects_non_access_control_class(self):
        v = CrossIdentityValidator.__new__(CrossIdentityValidator)
        self.assertFalse(v.applies(_f("xss"), _ex("/rest/basket/1")))

    def test_idor_read_requires_access_control_class(self):
        v = IdorReadValidator.__new__(IdorReadValidator)
        self.assertFalse(v.applies(_f("xss"), _ex("/rest/basket/1")))
        self.assertFalse(v.applies(_f("sqli"), _ex("/rest/basket/1")))
        self.assertTrue(v.applies(_f("idor"), _ex("/rest/basket/1")))

    def test_verb_tamper_needs_a_denied_original(self):
        v = VerbTamperValidator.__new__(VerbTamperValidator)
        admin = "/rest/admin/application-configuration"
        self.assertFalse(v.applies(_f("misconfig", "misconfig"),
                                   _ex(admin, status=200)))
        self.assertTrue(v.applies(_f("misconfig", "misconfig"), _ex(admin, status=403)))


# ------------------------------------------------------------------ verbose_error
class VerboseErrorNoLegTests(unittest.TestCase):
    def _run(self, finding, exchange):
        return asyncio.run(VerboseErrorValidator().validate(finding, exchange))

    def test_generic_disclosure_without_trace_is_no_applicable_leg(self):
        r = self._run(_f("Information Disclosure"), _ex("/api/SecurityQuestions/",
                                                         body='{"data":[{"id":1}]}'))
        self.assertEqual(r.status, "skipped")
        self.assertTrue(r.summary.startswith("no_applicable_leg"))
        self.assertFalse(r.confirmed)

    def test_verbose_error_claim_without_trace_is_still_refuted(self):
        r = self._run(_f("verbose_error"), _ex("/api/x", body="ok"))
        self.assertEqual(r.status, "not_confirmed")

    def test_trace_still_confirms(self):
        r = self._run(_f("Information Disclosure"), _ex(
            "/api/x", status=500, body="Traceback (most recent call last):\n  boom"))
        self.assertTrue(r.confirmed)


# ------------------------------------------------------------------ helpers / plan
class RoutingHelperTests(unittest.TestCase):
    def test_user_enumeration_vs_object_enumeration(self):
        self.assertTrue(ocs._USER_ENUMERATION.search("user enumeration via login"))
        self.assertTrue(ocs._USER_ENUMERATION.search("enumeration of accounts"))
        self.assertIsNone(ocs._USER_ENUMERATION.search("broken object/resource enumeration"))

    def test_authentication_only_class(self):
        self.assertTrue(ocs._authentication_only_class("Broken Authentication"))
        self.assertFalse(ocs._authentication_only_class("Broken Authentication / IDOR"))
        self.assertFalse(ocs._authentication_only_class("idor"))

    def test_missing_auth_class(self):
        self.assertTrue(ocs._missing_auth_class("Exposed Administrative Configuration Data", "GET"))
        self.assertTrue(ocs._missing_auth_class("missing_authentication", "POST"))
        self.assertFalse(ocs._missing_auth_class("Exposed Administrative Configuration Data", "POST"))
        self.assertFalse(ocs._missing_auth_class("Information Disclosure", "GET"))
        self.assertFalse(ocs._missing_auth_class("idor", "GET"))

    def test_auth_plan_binds_auth_sequence(self):
        self.assertIn("auth_sequence",
                      plan_dispatch.CAPABILITY_VALIDATORS["authorization_boundary_compare"])


# ------------------------------------------------------------------ chain callers
class _AnyVerbLoopback:
    def __init__(self):
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                outer.requests.append((self.command, self.path))
                data = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_OPTIONS = do_HEAD = _any

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class ChainLegRoutingTests(unittest.TestCase):
    def _run(self, vc: str, method: str, path: str, *, body: str = "", ctype: str = ""):
        server = _AnyVerbLoopback()
        self.addCleanup(server.close)
        base = server.origin + "/"
        node = {"method": method, "path": path, "reachable_roles": ["anonymous"],
                "template": {"method": method, "query": "", "body": body,
                             "content_type": ctype, "object_id": None}}
        label = {"vulnerability_class": vc, "confidence": 0.8, "severity": "high",
                 "summary": "model claim", "evidence": "", "suggested_test": "",
                 "basis": "agent"}

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": method, "path": path, "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False,
                "template": node["template"]}]})
            return state, role_crawl.RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            ex = worklist_investigator._seed_exchange(base, node, {}, "1")
            await kwargs["confirm_fn"](label, ex)
            return [{"path": path, "method": method, "findings_detail": [label],
                     "confirmed": bool(label.get("confirmed"))}]

        xval = AsyncMock(return_value=_skip("cross_identity"))
        idor = AsyncMock(return_value=_skip("idor_read"))
        auth = AsyncMock(return_value=_skip("auth_sequence"))
        probe = AsyncMock(side_effect=RuntimeError("stub: probe reached"))
        orch = Orchestrator(_chain_config())
        orch.allowed_hosts = ["127.0.0.1"]
        with patch.object(engagement_builder, "build_engagement", new=build), \
                patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
                chain_patch("review_captured_exchanges",
                      new=AsyncMock(return_value=0)), \
                chain_patch("universal_header_audit",
                      new=AsyncMock(return_value=0)), \
                patch.object(CrossIdentityValidator, "validate", new=xval), \
                patch.object(IdorReadValidator, "validate", new=idor), \
                patch.object(AuthSequenceValidator, "validate", new=auth), \
                patch.object(missing_auth_probe, "probe", new=probe), \
                patch.object(orch, "_persist_confirmation_proof",
                             new=AsyncMock(return_value=(False, None, "test"))):
            asyncio.run(orch.investigate_engagement(
                base, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=0,
                discovery_max_probes=1))
        return label, {"xval": xval, "idor": idor, "auth": auth, "probe": probe}, server.requests

    def test_login_post_broken_auth_reaches_auth_sequence(self):
        label, legs, reqs = self._run("Broken Authentication", "POST", "/rest/user/login",
                                      body='{"email":"a@b.c","password":"x"}',
                                      ctype="application/json")
        self.assertTrue(legs["auth"].await_count >= 1)
        self.assertEqual(legs["xval"].await_count, 0)
        self.assertNotIn(("GET", "/rest/user/login"), reqs, "no GET baseline to a POST route")

    def test_login_get_without_credentials_is_no_applicable_leg(self):
        """Negative control: auth-sequence needs a credential write."""
        label, legs, _ = self._run("Broken Authentication", "GET", "/rest/user/whoami")
        self.assertEqual(legs["auth"].await_count, 0)
        self.assertEqual(label.get("leg_disposition"), ocs.NO_APPLICABLE_LEG)

    def test_collection_bola_is_no_applicable_leg_and_sends_nothing(self):
        label, legs, reqs = self._run("Insecure Data Exposure / BOLA", "GET", "/rest/memories/")
        self.assertEqual(label.get("leg_disposition"), ocs.NO_APPLICABLE_LEG)
        self.assertEqual(legs["xval"].await_count, 0)
        self.assertNotIn(("GET", "/rest/memories/"), reqs)
        self.assertFalse(label.get("confirmed"))

    def test_object_idor_still_reaches_cross_identity(self):
        """Positive control: an object-id read keeps its cross-identity leg."""
        label, legs, _ = self._run("idor", "GET", "/rest/basket/7")
        self.assertTrue(legs["xval"].await_count >= 1)
        self.assertNotIn("leg_disposition", label)

    def test_exposed_admin_config_reaches_missing_auth_probe(self):
        label, legs, _ = self._run("Exposed Administrative Configuration Data", "GET",
                                   "/rest/admin/application-configuration")
        self.assertTrue(legs["probe"].await_count >= 1)
        self.assertEqual(legs["xval"].await_count, 0)

    def test_information_disclosure_is_no_applicable_leg(self):
        label, legs, _ = self._run("Information Disclosure", "GET", "/api/SecurityQuestions/")
        self.assertEqual(label.get("leg_disposition"), ocs.NO_APPLICABLE_LEG)
        self.assertFalse(label.get("confirmed"))
        for leg in legs.values():
            self.assertEqual(leg.await_count, 0)


if __name__ == "__main__":
    unittest.main()
