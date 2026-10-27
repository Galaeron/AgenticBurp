"""H1 -- one credential-header classification for session binding and identity.

`security.is_credential_header` decides which request headers are credentials. The
run Executor, SessionManager.bind_headers, send_creds, the invalid-token control
and the captured-session binder all use it, so a target that authenticates with
X-API-Key (or X-Auth-Token, a CSRF/session header ...) gets the same session
scoping as one that uses Authorization. These tests drive the real Executor
against 127.0.0.1 fixtures and count, server-side, what each request carried.
The negative control swaps the old three-name rule back in and shows the same
scenarios then misbehave.
"""
from __future__ import annotations

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from harness import engagement, engagement_builder, feature_workflow, global_throttle
from harness import run_context, security
from harness.models import HttpExchange
from harness.orchestrator_chain import _invalidated_headers
from harness.orchestrator_detect import DetectMixin
from harness.role_crawl import RoleSession
from harness.run_context import RunContext, ScopePolicy, TypedRequest

KEY = "key-alice-1"

POSITIVES = ["X-API-Key", "x-api-key", "X-Api-Key", "Api-Key", "Apikey", "Ocp-Apim-Subscription-Key",
             "X-Auth-Token", "X-Access-Token", "X-CSRF-Token", "X-XSRF-TOKEN", "X-JWT-Assertion",
             "X-Password", "X-Passphrase", "X-Secret", "X-Session-Id", "X-Sid", "X-Bearer",
             "X-Credentials", "Proxy-Authorization", "Authorization", "Cookie",
             "Set-Cookie", "Idempotency-Key"]
NEGATIVES = ["Accept", "Accept-Encoding", "Accept-Language", "Content-Type", "Content-Length",
             "User-Agent", "X-Requested-With", "X-Forwarded-For", "If-None-Match", "Host",
             "Origin", "Referer", "Cache-Control", "Pragma", "Connection", "X-Bypass-Cache",
             "Sec-WebSocket-Key", "Sec-Fetch-Site", "X-Request-Id", "Upgrade-Insecure-Requests"]


def _old_rule(name) -> bool:
    """The rule before H1: exactly three names."""
    return isinstance(name, str) and name.lower() in run_context._CREDENTIAL_HEADERS


class ClassifierTableTests(unittest.TestCase):
    def test_positives(self):
        for name in POSITIVES:
            self.assertTrue(security.is_credential_header(name), name)

    def test_negatives(self):
        for name in NEGATIVES:
            self.assertFalse(security.is_credential_header(name), name)

    def test_every_secret_header_and_secret_field_name_is_a_credential(self):
        for name in security.SECRET_HEADER_NAMES:
            self.assertTrue(security.is_credential_header(name), name)
        for name in security.SECRET_FIELD_NAMES:
            self.assertTrue(security.is_credential_header(name), name)
            self.assertTrue(security.is_credential_header(name.replace("_", "-")), name)

    def test_any_proxy_header_is_a_credential(self):
        for name in ("Proxy-Foo", "proxy-authenticate", "PROXY-X"):
            self.assertTrue(security.is_credential_header(name), name)

    def test_case_whitespace_and_non_strings(self):
        self.assertTrue(security.is_credential_header("  X-API-KEY "))
        for bad in (None, 5, b"x-api-key", "", "   "):
            self.assertFalse(security.is_credential_header(bad), repr(bad))

    def test_old_rule_missed_the_custom_schemes(self):
        # Documents what H1 changes: the three-name rule did not see these.
        missed = [n for n in POSITIVES if security.is_credential_header(n) and not _old_rule(n)]
        self.assertIn("X-API-Key", missed)
        self.assertIn("X-Auth-Token", missed)
        self.assertIn("X-CSRF-Token", missed)


class IdentityKeyAgreementTests(unittest.TestCase):
    def test_every_header_the_classifier_flags_changes_the_identity_key(self):
        # An allowlist is the safer side for identity: it may call MORE headers part of
        # an identity than the classifier calls credentials, never fewer.
        candidates = set(POSITIVES) | set(security.SECRET_HEADER_NAMES)
        candidates |= {n.replace("_", "-") for n in security.SECRET_FIELD_NAMES}
        candidates |= {"X-" + frag for frag in ("Auth", "Token", "ApiKey", "Secret", "Session",
                                                "Csrf", "Xsrf", "Jwt", "Bearer", "Password",
                                                "Credential", "Foo-Key", "Foo-Sid")}
        flagged = sorted(n for n in candidates if security.is_credential_header(n))
        self.assertGreater(len(flagged), 40)
        base = engagement.capture_identity_key({"Accept": "*/*"})
        for name in flagged:
            self.assertNotEqual(
                engagement.capture_identity_key({"Accept": "*/*", name: "v1"}), base, name)
            self.assertNotEqual(
                engagement.capture_identity_key({name: "v1"}), engagement.capture_identity_key({name: "v2"}), name)

    def test_no_public_header_is_a_credential(self):
        # The identity key's own public allowlist must stay clear of the classifier.
        for name in ("host", "content-type", "content-length", "accept", "accept-encoding",
                     "accept-language", "user-agent", "connection", "referer", "origin",
                     "cache-control", "pragma", "upgrade-insecure-requests"):
            self.assertFalse(security.is_credential_header(name), name)
            self.assertEqual(engagement.capture_identity_key({name: "v"}),
                             engagement.capture_identity_key({}), name)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _serve(self):
        srv = self.server
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        path = self.path.split("?", 1)[0]
        with srv.lock:
            srv.received.append({"path": path, "method": self.command,
                                 "headers": {k.lower(): v for k, v in self.headers.items()}})
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", srv.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _serve


class _Fixture:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.received = []
        self.httpd.lock = threading.Lock()
        self.httpd.redirect_to = ""
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def received(self, path=None):
        with self.httpd.lock:
            return [r for r in self.httpd.received if path is None or r["path"] == path]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(5)


def _ctx():
    return RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=400,
                             gate_config={"active_enabled": True, "allow_mutating_replay": True})


class _ExecutorCase(unittest.TestCase):
    def setUp(self):
        stats = global_throttle.throttle.stats()
        prior = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                 stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        self.addCleanup(global_throttle.configure, *prior)
        self.srv = _Fixture()
        self.addCleanup(self.srv.close)


class CredentialNeedsSessionTests(_ExecutorCase):
    def _send(self, headers):
        ctx = _ctx()

        async def go():
            out = await ctx.executor().execute(
                TypedRequest("GET", self.srv.base + "/api/me", headers=headers), capability="probe")
            await ctx.aclose()
            return out
        return asyncio.run(go())

    def test_an_api_key_request_without_a_session_is_blocked_unsent(self):
        out = self._send({"X-API-Key": KEY})
        self.assertEqual(out.outcome, "blocked")
        self.assertIn("credential-bearing request requires an explicit session reference", out.error)
        self.assertEqual(self.srv.received(), [])

    def test_a_public_header_request_without_a_session_still_goes_out(self):
        out = self._send({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
        self.assertTrue(out.ok)
        self.assertEqual(len(self.srv.received("/api/me")), 1)

    def test_control_with_the_old_three_name_rule_the_unsessioned_key_is_sent(self):
        with patch.object(run_context, "is_identity_credential_header", _old_rule),                 patch.object(run_context, "is_credential_header", _old_rule):
            out = self._send({"X-API-Key": KEY})
        self.assertTrue(out.ok)                                            # the old rule let it out
        self.assertEqual(self.srv.received("/api/me")[0]["headers"].get("x-api-key"), KEY)


class RoleBindingTests(_ExecutorCase):
    ALICE = RoleSession(role="user", headers={"X-API-Key": KEY}, name="alice")
    ANON = RoleSession(role="anonymous", headers={})

    def _registered_run(self):
        """A run whose sessions came from the production role -> session path."""
        ctx = _ctx()

        async def go():
            async with ctx:
                await engagement_builder.build_engagement(
                    self.srv.base, [self.ANON, self.ALICE], allowed_hosts=["127.0.0.1"],
                    active_discovery=False, crawl_max_pages=1, max_endpoints=3, run_context=ctx)
        asyncio.run(go())
        return ctx

    def test_a_role_whose_credential_is_a_custom_header_binds_to_its_session(self):
        ctx = self._registered_run()
        session_id, rest = ctx.sessions.bind_headers({"X-API-Key": KEY, "Accept": "*/*"})
        self.assertEqual(session_id, "principal:1:alice")
        self.assertEqual(rest, {"Accept": "*/*"})                          # the key left the inline headers
        self.assertEqual(ctx.sessions.bind_headers({"X-API-Key": "someone-else"})[0], None)

    def test_send_creds_uses_the_roles_session_and_sends_the_key(self):
        ctx = self._registered_run()
        before = len(ctx.sessions.all())
        mark = len(self.srv.received())

        async def go():
            out = await ctx.executor().send_creds(
                "GET", self.srv.base + "/api/me", capability="probe",
                headers={"X-API-Key": KEY, "Accept": "*/*"})
            await ctx.aclose()
            return out

        out = asyncio.run(go())
        self.assertTrue(out.ok)
        self.assertEqual(out.artifact.session_ref, "principal:1:alice")
        self.assertEqual(len(ctx.sessions.all()), before)                  # no ephemeral duplicate
        sent = self.srv.received("/api/me")[-1]
        self.assertEqual(sent["headers"].get("x-api-key"), KEY)
        self.assertGreater(len(self.srv.received()), mark)

    def test_the_feature_crawl_fetches_as_the_roles_session(self):
        ctx = self._registered_run()
        refs = []
        real = feature_workflow.run_context_fetch_fn

        def spy(run, session_ref, **kw):
            refs.append(session_ref)
            return real(run, session_ref, **kw)

        async def go():
            with patch.object(feature_workflow, "run_context_fetch_fn", spy):
                await engagement_builder.feature_crawl_captures(
                    self.srv.base, [self.ALICE], run_context=ctx, allowed_hosts=["127.0.0.1"],
                    max_steps=2, max_depth=1)
            await ctx.aclose()
        asyncio.run(go())
        self.assertEqual(refs, ["principal:1:alice"])

    def test_control_with_the_old_rule_the_role_never_binds(self):
        ctx = self._registered_run()
        with patch.object(run_context, "is_identity_credential_header", _old_rule):
            self.assertIsNone(ctx.sessions.bind_headers({"X-API-Key": KEY})[0])
            refs = []
            real = feature_workflow.run_context_fetch_fn

            def spy(run, session_ref, **kw):
                refs.append(session_ref)
                return real(run, session_ref, **kw)

            async def go():
                with patch.object(feature_workflow, "run_context_fetch_fn", spy):
                    await engagement_builder.feature_crawl_captures(
                        self.srv.base, [self.ALICE], run_context=ctx, allowed_hosts=["127.0.0.1"],
                        max_steps=2, max_depth=1)
                await ctx.aclose()
            asyncio.run(go())
        self.assertEqual(refs, [None])                                     # sent with no session reference


class RequestBindingHeaderTests(_ExecutorCase):
    """A CSRF/XSRF token or Idempotency-Key next to the identity credential must
    not stop a capture binding to its role's session (review of H1)."""

    CASES = [
        ({"Cookie": "c"}, {"Cookie": "c", "X-XSRF-TOKEN": "t"}),
        ({"Cookie": "c", "X-CSRF-Token": "t0"}, {"Cookie": "c"}),
        ({"Authorization": "Bearer a"}, {"Authorization": "Bearer a", "Idempotency-Key": "k1"}),
    ]

    def _check_binds_and_sends(self):
        for role_headers, replay in self.CASES:
            ctx = _ctx()

            async def go():
                ctx.sessions.register("s-alice", "alice", headers=role_headers,
                                      allowed_origins=[self.srv.base])
                before = len(ctx.sessions.all())
                bound, _rest = ctx.sessions.bind_headers(replay)
                out = await ctx.executor().send_creds("GET", self.srv.base + "/api/basket",
                                                      capability="probe", headers=replay)
                after = len(ctx.sessions.all())
                await ctx.aclose()
                return bound, out, before, after
            mark = len(self.srv.received())
            bound, out, before, after = asyncio.run(go())
            self.assertEqual(bound, "s-alice", replay)
            self.assertTrue(out.ok, replay)
            self.assertEqual(before, after, "bound to the role, no ephemeral session")
            sent = self.srv.received()[mark:]
            self.assertEqual(len(sent), 1, replay)
            for k, v in replay.items():
                self.assertEqual(sent[0]["headers"].get(k.lower()), v, (replay, k))

    def test_a_capture_with_a_csrf_or_idempotency_header_binds_to_its_role(self):
        self._check_binds_and_sends()

    def test_control_comparing_every_credential_header_breaks_the_binding(self):
        with patch.object(run_context, "is_identity_credential_header", security.is_credential_header):
            with self.assertRaises(AssertionError):
                self._check_binds_and_sends()

    def test_a_different_identity_key_still_does_not_bind(self):
        ctx = _ctx()
        ctx.sessions.register("s-alice", "alice", headers={"Cookie": "c"},
                              allowed_origins=[self.srv.base])
        self.assertIsNone(ctx.sessions.bind_headers({"Cookie": "c", "X-API-Key": "other"})[0])
        asyncio.run(ctx.aclose())

    def test_an_anonymous_csrf_token_alone_needs_no_session(self):
        out = CredentialNeedsSessionTests._send(self, {"X-CSRF-Token": "t"})
        self.assertTrue(out.ok)
        self.assertEqual(self.srv.received("/api/me")[0]["headers"].get("x-csrf-token"), "t")

    def test_identity_split_and_proxy_connection(self):
        self.assertTrue(security.is_identity_credential_header("X-API-Key"))
        self.assertTrue(security.is_credential_header("X-CSRF-Token"))
        self.assertFalse(security.is_identity_credential_header("X-CSRF-Token"))
        self.assertFalse(security.is_identity_credential_header("Idempotency-Key"))
        self.assertFalse(security.is_credential_header("Proxy-Connection"))
        self.assertTrue(security.is_credential_header("Proxy-Authorization"))


class RedirectTests(_ExecutorCase):
    def test_a_cross_origin_redirect_hop_does_not_carry_the_api_key(self):
        other = _Fixture()
        self.addCleanup(other.close)
        self.srv.httpd.redirect_to = other.base + "/collect"
        ctx = _ctx()
        ctx.sessions.register("s1", "alice", {"X-API-Key": KEY, "X-CSRF-Token": "csrf-1"},
                              allowed_origins=[self.srv.base])

        async def go():
            out = await ctx.executor().execute(
                TypedRequest("GET", self.srv.base + "/redirect"), capability="probe",
                session_ref="s1")
            await ctx.aclose()
            return out

        out = asyncio.run(go())
        self.assertTrue(out.ok)
        first = self.srv.received("/redirect")[0]["headers"]
        self.assertEqual((first.get("x-api-key"), first.get("x-csrf-token")), (KEY, "csrf-1"))
        landed = other.received("/collect")
        self.assertEqual(len(landed), 1)                                   # the hop did happen
        self.assertNotIn("x-api-key", landed[0]["headers"])
        self.assertNotIn("x-csrf-token", landed[0]["headers"])


class CaptureAndControlTests(_ExecutorCase):
    def test_a_captured_exchange_registers_its_api_key_with_its_session(self):
        ctx = _ctx()
        exchange = HttpExchange(
            url=self.srv.base + "/api/me", method="GET", response_status=200,
            request_headers={"Authorization": "Bearer t0", "X-API-Key": KEY, "Accept": "*/*"})
        stub = SimpleNamespace(validator_registry=SimpleNamespace(active_enabled=True))

        async def go():
            with patch("harness.store.captured_principal_id", return_value="captured:test"):
                await DetectMixin._bind_captured_session(stub, ctx, exchange)
            owner, rest = ctx.sessions.bind_headers(
                {"Authorization": "Bearer t0", "X-API-Key": KEY, "Accept": "*/*"})
            out = await ctx.executor().send_creds(
                "GET", self.srv.base + "/api/me", capability="replay",
                headers={"Authorization": "Bearer t0", "X-API-Key": KEY})
            await ctx.aclose()
            return owner, rest, out

        owner, rest, out = asyncio.run(go())
        self.assertEqual(owner, "captured")
        self.assertEqual(rest, {"Accept": "*/*"})
        self.assertEqual(ctx.sessions.get("captured").headers.get("X-API-Key"), KEY)
        self.assertEqual(out.artifact.session_ref, "captured")

    def test_the_invalid_token_control_corrupts_only_credential_headers(self):
        out = _invalidated_headers({"X-API-Key": "k", "X-Trace": "t", "Accept": "*/*"})
        self.assertEqual(out["X-API-Key"], "k_fr6_invalid")
        self.assertEqual((out["X-Trace"], out["Accept"]), ("t", "*/*"))
        # With no recognised credential it still corrupts everything it was given.
        self.assertEqual(_invalidated_headers({"X-Trace": "t"}), {"X-Trace": "t_fr6_invalid"})


if __name__ == "__main__":
    unittest.main()
