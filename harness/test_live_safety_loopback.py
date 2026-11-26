"""GAP-4: the live safety properties, each exercised over real loopback sockets.

Every server here is an owned HTTP/1.0 recorder on 127.0.0.1 or 127.0.0.2 (one
connection per request, so each send makes a fresh connect), and every name ends
in `.test` and is answered by a controlled resolver (socket.getaddrinfo is patched
for those names only). Nothing leaves the machine.

The properties, and the control each negative-control test removes:

1. DNS rebinding (HS-PIN-01): a name answers 127.0.0.1 when it is checked and
   127.0.0.2 afterwards. Every send, redirect hops included, connects to the
   address pinned at check time; a special-purpose first answer is refused before
   any connect. Control: the connect-time pin (`run_context._pinned_backend`).
2. Caller-set Host (HS-HOST-01): `Host: other-vhost` from a caller or from the
   iterative agent's `set_header` never reaches the server; the URL's authority
   does. Controls: the transport's strip (`run_context._drop_transport_controlled`)
   and the "host" entry of `run_context.TRANSPORT_CONTROLLED_HEADERS`.
3. Environment proxies (HS-PROXY-01): with HTTP(S)_PROXY / ALL_PROXY aimed at a
   loopback recorder, no target send reaches it (default, session and
   GatedAsyncClient paths), and the pin still holds. Control: `trust_env=False`
   with the pinned transport (`run_context._target_client`).
4. Redirect re-check (HS-REDIR-01): a 302 to an out-of-scope host is not followed
   and that host receives nothing; a same-origin 302 still is. Control: the
   per-hop scope and gate re-check in `TargetTransport._execute`.
5. Cleanup after a mutating leg (HS-CLEAN-01): when the leg raises part-way, is
   cancelled, or its undo fails, the cleanup is sent and the write is marked
   `restored`, or it is marked `restore_failed` (owed). Controls: cleanup
   registration and the `finally` in `workflow_engine.execute_workflow`, the
   restore record (`run_handoff.mark_restore`), the cancelled-cleanup allowance
   (`allow_cancelled_cleanup`), and `WriteIntegrityValidator._run_creates`'s
   `finally` cleanup.

The bound (evidence) tests are also re-run with every async send severed
(testing_fixtures.leg_fault): none of them may pass without the loopback traffic.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import httpx

import harness.coverage_manifest as cm
from harness import run_context as rc
from harness import run_handoff, safety_gate, workflow_engine
from harness import test_write_integrity as _wi
from harness.coverage_evidence_case import EvidenceCase, evidence_for
from harness.iterative_agent import IterativeAgent
from harness.models import HttpExchange
from harness.run_context import RunContext
from harness.safety_gate import ActionRiskTier, AuthorizationDecision, GatedAsyncClient
from harness.test_destination_policy_callers import _Resolver
from harness.test_iterative_header_policy import _STOP, _Model, _hdr
from harness.testing_fixtures.leg_fault import bound_test_names, outcomes_with_leg_severed
from harness.validators.write_integrity_validator import WriteIntegrityValidator
from harness.workflow_engine import (
    Extractor, ExtractorKind, Workflow, WorkflowStep, execute_workflow,
)

_CAP = "gap4_live_safety"


class _Recorder:
    """Owned loopback HTTP/1.0 server bound to one address; records each request.

    Routes: /redir -> 302 to `redirect_to`; /explode -> 401; POST /items creates
    an item, DELETE /items/<id> removes it (500 when `fail_delete`); anything
    else -> 200 naming the server. A proxy recorder sees absolute-form targets."""

    def __init__(self, ip: str = "127.0.0.1", port: int = 0, *, label: str = "target"):
        self.ip, self.label = ip, label
        self.seen: list[dict] = []
        self.items: dict[int, dict] = {}
        self.redirect_to = ""
        self.fail_delete = False
        self._next = 1
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _record(self) -> str:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                with outer._lock:
                    outer.seen.append({"method": self.command, "path": self.path,
                                       "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "body": body})
                return body

            def _reply(self, status, obj=None, extra=()):
                data = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(status)
                for k, v in extra:
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._record()
                if self.path.startswith("/redir") and outer.redirect_to:
                    return self._reply(302, extra=[("Location", outer.redirect_to)])
                if self.path.startswith("/explode"):
                    return self._reply(401, {"error": "session expired"})
                self._reply(200, {"served_by": outer.label, "ip": outer.ip})

            def do_POST(self):
                body = self._record()
                if self.path.rstrip("/") != "/items":
                    return self._reply(404, {})
                with outer._lock:
                    nid, outer._next = outer._next, outer._next + 1
                    outer.items[nid] = json.loads(body or "{}")
                self._reply(201, {"id": nid})

            def do_DELETE(self):
                self._record()
                if outer.fail_delete:
                    return self._reply(500, {"error": "delete failed"})
                m = re.fullmatch(r"/items/(\d+)", self.path)
                with outer._lock:
                    found = bool(m) and outer.items.pop(int(m.group(1)), None) is not None
                self._reply(204 if found else 404)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                # Skip HTTPServer's reverse lookup of the bind address (slow for 127.0.0.2).
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server((ip, port), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

    def hosts(self) -> list[str]:
        return [r["headers"].get("host", "") for r in self.seen]

    def methods(self) -> list[str]:
        return [r["method"] for r in self.seen]

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _Loopback(EvidenceCase, unittest.IsolatedAsyncioTestCase):
    """Servers, resolver and run factory shared by the property tests."""

    def setUp(self):
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)

    def server(self, ip: str = "127.0.0.1", port: int = 0, **kw) -> _Recorder:
        s = _Recorder(ip, port, **kw)
        self.addCleanup(s.close)
        return s

    def pair(self) -> tuple[_Recorder, _Recorder]:
        """The in-scope server and the 'internal' one, same port on 127.0.0.1/2."""
        first = self.server("127.0.0.1")
        return first, self.server("127.0.0.2", first.port, label="internal")

    def resolver(self, answers: dict[str, list[str]]) -> _Resolver:
        r = _Resolver(answers)
        p = patch("socket.getaddrinfo", side_effect=r)
        p.start()
        self.addCleanup(p.stop)
        return r

    @staticmethod
    def run_for(hosts, *, writes: bool = False) -> RunContext:
        gate = {"active_enabled": True, **({"allow_mutating_replay": True} if writes else {})}
        return RunContext.create(allowed_hosts=list(hosts), max_requests=50, config={},
                                 timeout=5.0, gate_config=gate)


# -- 1. DNS rebinding ------------------------------------------------------------------

class DnsRebindingPinTests(_Loopback):
    async def _rebound_sends(self):
        good, internal = self.pair()
        good.redirect_to = f"http://rebind.test:{good.port}/final"
        resolver = self.resolver({"rebind.test": ["127.0.0.1", "127.0.0.2"]})
        run = self.run_for(["rebind.test"])
        base = f"http://rebind.test:{good.port}"
        async with run:
            # Check time: the name is resolved (and pinned) before anything is sent;
            # every later lookup of it answers the internal address.
            checked = await run.address_pins.address_for("rebind.test")
            transport = run.target_transport()
            outs = [await transport.send("GET", base + "/a", capability=_CAP),
                    await transport.send("GET", base + "/b", capability=_CAP),
                    await transport.send("GET", base + "/redir", capability=_CAP)]
            pinned = run.address_pins.pinned()
        return good, internal, resolver, checked, outs, pinned

    @evidence_for(**cm.caller_evidence("safety_pin_rebinding"))
    async def test_rebound_name_is_sent_to_its_pinned_address(self):
        good, internal, resolver, checked, outs, pinned = await self._rebound_sends()
        self.assertEqual(checked, "127.0.0.1")
        self.assertEqual([o.outcome for o in outs], ["ok", "ok", "ok"])
        self.assertEqual(outs[2].final_url, f"http://rebind.test:{good.port}/final")
        self.assertEqual([r["path"] for r in good.seen], ["/a", "/b", "/redir", "/final"])
        self.assertEqual(internal.seen, [], "a send reached the rebound address")
        self.assertEqual(pinned, {"rebind.test": "127.0.0.1"})
        self.assertEqual(resolver.calls, ["rebind.test"], "the name was resolved again")
        self.record_observation({"pinned": pinned, "internal_requests": 0,
                                 "served_paths": [r["path"] for r in good.seen]})

    @evidence_for(**cm.caller_evidence("safety_pin_special_purpose"))
    async def test_special_purpose_first_answer_is_refused_before_connect(self):
        good, internal = self.pair()
        self.resolver({"meta.test": ["169.254.169.254"]})
        run = self.run_for(["meta.test"])
        async with run:
            out = await run.target_transport().send(
                "GET", f"http://meta.test:{good.port}/latest/meta-data", capability=_CAP)
        self.assertEqual(out.outcome, "blocked")
        self.assertIn("special-purpose", out.error)
        self.assertEqual(out.artifact.transport_outcome, "destination_blocked")
        self.assertEqual((good.seen, internal.seen), ([], []))
        self.record_observation({"outcome": out.outcome,
                                 "transport_outcome": out.artifact.transport_outcome,
                                 "requests_seen": 0})

    async def test_negative_control_without_the_connect_pin_the_rebound_address_is_reached(self):
        with patch.object(rc, "_pinned_backend", lambda pins: None):
            good, internal, _resolver, checked, outs, _pinned = await self._rebound_sends()
        self.assertEqual(checked, "127.0.0.1")
        self.assertEqual([o.outcome for o in outs], ["ok", "ok", "ok"])
        self.assertTrue(internal.seen, "with the pin removed the rebound address must be reached")
        self.assertEqual(good.seen, [])


# -- 2. Caller-set Host -------------------------------------------------------------------

_HOSTS = ("Host", " host ", "HOST")


class CallerHostHeaderTests(_Loopback):
    async def _caller_sends(self):
        target = self.server()
        self.resolver({"vhost.test": ["127.0.0.1"]})
        run = self.run_for(["vhost.test"])
        url = f"http://vhost.test:{target.port}/page"
        async with run:
            transport = run.target_transport()
            outs = []
            for name in _HOSTS:
                headers = {name: "other-vhost", "X-Probe": "1"}
                outs.append(await transport.send("GET", url, capability=_CAP, headers=headers))
                outs.append(await transport.send_creds("GET", url, capability=_CAP,
                                                       headers=headers))
        return target, outs

    async def _agent(self, actions):
        target = self.server()
        self.resolver({"vhost.test": ["127.0.0.1"]})
        run = self.run_for(["vhost.test"])
        exchange = HttpExchange(url=f"http://vhost.test:{target.port}/api/search?q=widget",
                                method="GET", request_headers={"User-Agent": "x"},
                                request_body="", response_status=200, response_body="results")
        async with run:
            agent = IterativeAgent(_Model(actions), "m", ["vhost.test"], run_context=run)
            result = await agent.run(exchange, "header probe", "sqli",
                                     step_budget=len(actions) + 1)
        return target, result

    @evidence_for(**cm.caller_evidence("safety_host_header"))
    async def test_caller_set_host_is_stripped_before_the_send(self):
        target, outs = await self._caller_sends()
        authority = f"vhost.test:{target.port}"
        self.assertEqual([o.outcome for o in outs], ["ok"] * len(outs))
        self.assertEqual(len(target.seen), 2 * len(_HOSTS))
        self.assertEqual(target.hosts(), [authority] * len(target.seen))
        self.assertTrue(all(r["headers"].get("x-probe") == "1" for r in target.seen))
        self.record_observation({"arrived_host": authority, "sends": len(target.seen)})

    @evidence_for(**cm.caller_evidence("safety_host_agent"))
    async def test_agent_set_header_host_is_refused_with_zero_sends(self):
        target, result = await self._agent([_hdr("Host", "other-vhost"), _STOP])
        self.assertEqual(target.seen, [])
        self.assertEqual(result.diagnostics["rejected_proposals"], 1)
        # Non-vacuous: an allowed header from the same agent does reach the server.
        target, result = await self._agent([_hdr("X-Probe", "1"), _STOP])
        self.assertEqual(target.hosts(), [f"vhost.test:{target.port}"])
        self.assertEqual(target.seen[0]["headers"].get("x-probe"), "1")

    async def test_negative_control_without_the_strip_the_caller_host_arrives(self):
        with patch.object(rc, "_drop_transport_controlled",
                          lambda headers, allow_framing: dict(headers)):
            target, _outs = await self._caller_sends()
        self.assertIn("other-vhost", target.hosts())

    async def test_negative_control_without_the_deny_entry_the_agent_host_arrives(self):
        with patch.object(rc, "TRANSPORT_CONTROLLED_HEADERS",
                          rc.TRANSPORT_CONTROLLED_HEADERS - {"host"}):
            target, result = await self._agent([_hdr("Host", "other-vhost"), _STOP])
        self.assertEqual(result.diagnostics["rejected_proposals"], 0)
        self.assertEqual(target.hosts(), ["other-vhost"])


# -- 3. Environment proxies ----------------------------------------------------------------

class EnvironmentProxyTests(_Loopback):
    def setUp(self):
        super().setUp()
        self.proxy = self.server(label="proxy")
        url = f"http://127.0.0.1:{self.proxy.port}"
        env = patch.dict(os.environ, {"HTTP_PROXY": url, "HTTPS_PROXY": url, "ALL_PROXY": url,
                                      "http_proxy": url, "https_proxy": url, "all_proxy": url,
                                      "NO_PROXY": "", "no_proxy": ""})
        env.start()
        self.addCleanup(env.stop)

    async def _proxied_env_sends(self):
        good, internal = self.pair()
        self.resolver({"tgt.test": ["127.0.0.1", "127.0.0.2"]})
        run = self.run_for(["tgt.test"])
        base = f"http://tgt.test:{good.port}"
        run.sessions.register("alice", "alice", {"Authorization": "Bearer alice"},
                              allowed_origins=[base])
        async with run:
            transport = run.target_transport()
            outs = [await transport.send("GET", base + "/default", capability=_CAP),
                    await transport.send("GET", base + "/session", capability=_CAP,
                                         session_ref="alice")]
            async with GatedAsyncClient(run.gate, _CAP, run_context=run, timeout=5.0) as client:
                resp = await client.get(base + "/gated")
            outs.append(resp)
            outs.append(await transport.send("GET", base + "/again", capability=_CAP))
            pinned = run.address_pins.pinned()
        return good, internal, outs, pinned

    @evidence_for(**cm.caller_evidence("safety_env_proxy"))
    async def test_target_sends_bypass_environment_proxies_and_keep_pins(self):
        self.assertEqual(httpx_env_proxy(), f"http://127.0.0.1:{self.proxy.port}")  # env is live
        good, internal, outs, pinned = await self._proxied_env_sends()
        self.assertEqual([outs[0].outcome, outs[1].outcome, outs[3].outcome], ["ok"] * 3)
        self.assertEqual(outs[2].status_code, 200)
        self.assertEqual(self.proxy.seen, [], "a target send was carried by the env proxy")
        self.assertEqual([r["path"] for r in good.seen], ["/default", "/session", "/gated", "/again"])
        self.assertEqual(good.seen[1]["headers"].get("authorization"), "Bearer alice")
        self.assertEqual(internal.seen, [], "the pin did not hold under env proxies")
        self.assertEqual(pinned, {"tgt.test": "127.0.0.1"})
        self.record_observation({"proxy_requests": 0, "target_requests": len(good.seen),
                                 "pinned": pinned})

    async def test_negative_control_an_env_trusting_client_is_carried_by_the_proxy(self):
        def env_trusting_client(*, verify, timeout, http2, pins):
            return httpx.AsyncClient(follow_redirects=False, verify=verify, timeout=timeout,
                                     cookies=httpx.Cookies(), http2=http2)

        with patch.object(rc, "_target_client", env_trusting_client):
            good, _internal, _outs, _pinned = await self._proxied_env_sends()
        self.assertGreaterEqual(len(self.proxy.seen), 3, self.proxy.seen)
        self.assertEqual(good.seen, [])


def httpx_env_proxy() -> str:
    """What an environment-trusting client reads for http:// (sanity: env is live)."""
    import urllib.request
    return urllib.request.getproxies_environment().get("http", "")


# -- 4. Redirect re-check ------------------------------------------------------------------

class RedirectRecheckTests(_Loopback):
    async def _redirected(self):
        inside = self.server()
        outside = self.server(label="outside")
        self.resolver({"inside.test": ["127.0.0.1"], "outside.test": ["127.0.0.1"]})
        run = self.run_for(["inside.test"])
        url = f"http://inside.test:{inside.port}/redir"
        async with run:
            transport = run.target_transport()
            inside.redirect_to = f"http://outside.test:{outside.port}/landing"
            off = await transport.send("GET", url, capability=_CAP)
            inside.redirect_to = "http://169.254.169.254/latest/meta-data"
            metadata = await transport.send("GET", url, capability=_CAP)
            inside.redirect_to = f"http://inside.test:{inside.port}/final"
            same = await transport.send("GET", url, capability=_CAP)
        return inside, outside, off, metadata, same

    @evidence_for(**cm.caller_evidence("safety_redirect_recheck"))
    async def test_redirect_to_out_of_scope_host_is_not_followed(self):
        inside, outside, off, metadata, same = await self._redirected()
        self.assertEqual(off.outcome, "out_of_scope")
        self.assertTrue(off.final_url.startswith("http://outside.test:"), off.final_url)
        self.assertEqual(metadata.outcome, "out_of_scope")
        self.assertEqual(outside.seen, [], "the out-of-scope redirect target was contacted")
        # Non-vacuous: the same transport does follow a same-origin redirect.
        self.assertEqual((same.outcome, same.status), ("ok", 200))
        self.assertEqual([r["path"] for r in inside.seen], ["/redir", "/redir", "/redir", "/final"])
        self.record_observation({"off_scope_outcome": off.outcome, "outside_requests": 0})

    async def test_negative_control_without_the_per_hop_recheck_the_redirect_is_followed(self):
        """Admit every hop after the first, as a transport that checked only the
        initial URL would: the out-of-scope host is then contacted."""
        scope_cls = type(self.run_for(["inside.test"]).scope)
        real_in_scope, real_authorize = scope_cls.in_scope, safety_gate.SafetyGate.authorize
        calls = {"scope": 0, "gate": 0}

        def first_hop_scope(self_, url):
            calls["scope"] += 1
            return real_in_scope(self_, url) if calls["scope"] == 1 else True

        def first_hop_gate(self_, **kw):
            calls["gate"] += 1
            if calls["gate"] == 1:
                return real_authorize(self_, **kw)
            return AuthorizationDecision(allowed=True, tier=ActionRiskTier.SAFE,
                                         reason="negative control")

        inside, outside = self.server(), self.server(label="outside")
        self.resolver({"inside.test": ["127.0.0.1"], "outside.test": ["127.0.0.1"]})
        inside.redirect_to = f"http://outside.test:{outside.port}/landing"
        run = self.run_for(["inside.test"])
        with patch.object(scope_cls, "in_scope", first_hop_scope), \
                patch.object(safety_gate.SafetyGate, "authorize", first_hop_gate):
            async with run:
                out = await run.target_transport().send(
                    "GET", f"http://inside.test:{inside.port}/redir", capability=_CAP)
        self.assertEqual(out.outcome, "ok")
        self.assertEqual([r["path"] for r in outside.seen], ["/landing"])


# -- 5. Cleanup after a mutating leg -------------------------------------------------------

def _workflow(base: str) -> Workflow:
    return Workflow("gap4_mutating_leg", (
        WorkflowStep("create", "POST", base + "/items", session_ref="alice",
                     body_template='{"name": "gap4"}', content_type="application/json",
                     extractors=(Extractor("item_id", ExtractorKind.JSON_POINTER, "/id"),)),
        WorkflowStep("judge", "GET", base + "/explode", session_ref="alice",
                     prerequisites=("create",)),
        WorkflowStep("undo", "DELETE", base + "/items/{{item_id}}", session_ref="alice",
                     prerequisites=("create",), cleanup=True),
    ))


class _NoAppend(list):
    def append(self, item):   # cleanup registration removed
        pass


@dataclasses.dataclass
class _UnregisteredResult(workflow_engine.WorkflowResult):
    def __post_init__(self):
        self.cleanup_registered = _NoAppend()


class MutatingCleanupTests(_Loopback):
    async def _leg(self, refresh_fn, *, fail_delete=False):
        store = self.server(label="store")
        store.fail_delete = fail_delete
        run = self.run_for(["127.0.0.1"], writes=True)
        base = f"http://127.0.0.1:{store.port}"
        run.sessions.register("alice", "alice", {"Authorization": "Bearer alice"},
                              allowed_origins=[base])
        raised = None
        async with run:
            try:
                result = await execute_workflow(_workflow(base), run,
                                                capability=_CAP, refresh_fn=refresh_fn)
            except BaseException as exc:   # the leg's own failure, re-raised after cleanup
                raised, result = exc, None
        posts = [e for e in run.change_log.entries() if e["method"] == "POST"]
        return store, run, posts, raised, result

    @staticmethod
    async def _crash(session_ref, run_context):
        raise RuntimeError("leg crashed part-way")

    @evidence_for(**cm.caller_evidence("safety_cleanup_on_error"))
    async def test_cleanup_runs_when_the_leg_raises_part_way(self):
        store, run, posts, raised, _ = await self._leg(self._crash)
        self.assertIsInstance(raised, RuntimeError)
        self.assertEqual(store.methods(), ["POST", "GET", "DELETE"])
        self.assertEqual(store.items, {}, "the created item was left on the target")
        self.assertEqual([e["restore_status"] for e in posts], ["restored"])
        self.assertEqual(run.change_log.failed_restores(), [])
        self.record_observation({"sent": store.methods(), "restore_status": "restored"})

    @evidence_for(**cm.caller_evidence("safety_cleanup_on_cancel"))
    async def test_cleanup_runs_after_cancellation(self):
        async def cancel(session_ref, run_context):
            run_context.cancel.cancel()
            return False

        store, _run, posts, raised, result = await self._leg(cancel)
        self.assertIsNone(raised)
        self.assertEqual(store.methods(), ["POST", "GET", "DELETE"])
        self.assertEqual(store.items, {})
        self.assertEqual(result.cleanup_completed, ["undo"])
        self.assertEqual([e["restore_status"] for e in posts], ["restored"])

    @evidence_for(**cm.caller_evidence("safety_cleanup_owed"))
    async def test_failed_cleanup_is_recorded_as_owed(self):
        store, run, posts, raised, _ = await self._leg(self._crash, fail_delete=True)
        self.assertIsInstance(raised, RuntimeError)
        self.assertEqual(store.methods(), ["POST", "GET", "DELETE"])
        self.assertEqual(len(store.items), 1)
        self.assertEqual([(e["restore_status"], e["level"]) for e in posts],
                         [("restore_failed", "error")])
        self.assertEqual(len(run.change_log.failed_restores()), 1)

    async def test_negative_control_without_cleanup_registration_the_write_is_left(self):
        with patch.object(workflow_engine, "WorkflowResult", _UnregisteredResult):
            store, _run, posts, raised, _ = await self._leg(self._crash)
        self.assertIsInstance(raised, RuntimeError)
        self.assertEqual(store.methods(), ["POST", "GET"])
        self.assertEqual(len(store.items), 1)
        self.assertEqual([e["restore_status"] for e in posts], ["none_declared"])

    async def test_negative_control_without_the_restore_record_the_write_is_unmarked(self):
        with patch.object(run_handoff, "mark_restore", lambda *a, **k: 0):
            store, _run, posts, _raised, _ = await self._leg(self._crash)
        self.assertEqual(store.methods(), ["POST", "GET", "DELETE"])
        self.assertEqual([e["restore_status"] for e in posts], ["none_declared"])

    async def test_negative_control_without_the_cancelled_cleanup_allowance_the_undo_is_dropped(self):
        real_execute = rc.TargetTransport.execute

        async def no_allowance(self_, request, **kw):
            kw["allow_cancelled_cleanup"] = False
            return await real_execute(self_, request, **kw)

        async def cancel(session_ref, run_context):
            run_context.cancel.cancel()
            return False

        with patch.object(rc.TargetTransport, "execute", no_allowance):
            store, _run, posts, _raised, _ = await self._leg(cancel)
        self.assertEqual(store.methods(), ["POST", "GET"])
        self.assertEqual(len(store.items), 1)
        self.assertEqual([e["restore_status"] for e in posts], ["restore_failed"])


async def _raise_after_the_create(self, case, plan, m):
    raise RuntimeError("leg crashed after its create")


class WriteIntegrityCleanupTests(EvidenceCase, _wi._Fixture, unittest.IsolatedAsyncioTestCase):
    """The write-integrity leg raising between an attack create and its read-back."""

    async def _crashed_leg(self):
        with patch.object(WriteIntegrityValidator, "_login_after", _raise_after_the_create):
            return await self.dispatch("cross_identity_write", "/api/items", _wi._ITEM)

    @evidence_for(**cm.caller_evidence("safety_cleanup_write_integrity"))
    async def test_write_integrity_leg_raising_part_way_deletes_its_creates(self):
        result, run = await self._crashed_leg()
        self.assertEqual(result.status, "error", result.summary)
        self.assertIn("probe raised RuntimeError", result.summary)
        self.assertEqual([m for m, _ in self.writes()], ["POST", "DELETE", "POST", "DELETE"])
        self.assert_store_restored()
        self.assert_creates_restored(run)
        self.record_observation({"writes": [m for m, _ in self.writes()], "restored": True})

    async def test_negative_control_without_the_finally_cleanup_the_attack_create_is_left(self):
        real_undo, calls = WriteIntegrityValidator._undo, []

        async def preflight_only(self_, case, made, first=None):
            calls.append(made)
            if len(calls) == 1:   # the control's restore preflight, before any attack
                return await real_undo(self_, case, made, first)

        with patch.object(WriteIntegrityValidator, "_undo", preflight_only):
            result, run = await self._crashed_leg()
        self.assertIn("probe raised RuntimeError", result.summary)
        self.assertEqual([m for m, _ in self.writes()], ["POST", "DELETE", "POST"])
        self.assertNotEqual(self.server.data, _wi._seed(), "the attack create should be left")
        posts = [e for e in run.change_log.entries() if e["method"] == "POST"]
        self.assertNotEqual({e["restore_status"] for e in posts}, {"restored"})


# -- the bound tests need the loopback traffic -----------------------------------------------

class SeveredEgressTests(unittest.TestCase):
    _BOUND = (DnsRebindingPinTests, CallerHostHeaderTests, EnvironmentProxyTests,
              RedirectRecheckTests, MutatingCleanupTests, WriteIntegrityCleanupTests)

    def test_bound_safety_tests_fail_with_egress_severed(self):
        names = {cls: bound_test_names(cls) for cls in self._BOUND}
        self.assertEqual(sum(len(n) for n in names.values()), len(cm.SAFETY_TESTS), names)
        for cls, bound in names.items():
            for name, outcome in outcomes_with_leg_severed(cls, bound).items():
                with self.subTest(test=f"{cls.__name__}.{name}"):
                    self.assertNotEqual(outcome, "passed",
                                        f"{name} passes without any loopback traffic")


if __name__ == "__main__":
    unittest.main()
