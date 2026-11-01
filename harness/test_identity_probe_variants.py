"""E5b: per-identity replay variants and a prerequisite inventory before dispatch.

The role crawl probes every endpoint as every principal but keeps one exchange per
distinct response body and never a 401/403, so an identity whose body matched an
earlier one's (or that was refused) had no replayable request and every check on it
came back "missing_principal". These tests cover the crawl's identity probes, the
variants the engagement builds from them, and the coverage drive: an identity that
WAS probed is dispatched, an identity that was never probed is still
"missing_principal" and reported once per (endpoint, identity), however many checks
it blocks. Each positive has a control that removes the new logic. Everything runs
against a loopback fixture.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import urlsplit

from harness import engagement, engagement_builder, global_throttle, role_crawl, worklist_investigator
from harness.crawler import CrawlResult
from harness.engagement import capture_identity_key, capture_variant, replayable_variants
from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.test_engagement_transport_callers import _EngagementCallerBase, _config
from harness.validators.base import ValidationResult

_PRODUCT = '{"id": 1, "name": "Apple Juice"}'
_USERS = '{"users": ["user1"]}'
ANON = RoleSession("anonymous", {})
USER1 = RoleSession("user", {"Authorization": "Bearer user1-token"}, name="user1")
GHOST = RoleSession("user", {"Authorization": "Bearer ghost-token"}, name="ghost")
_REAL_BUILD = engagement_builder.build_engagement


class _Api:
    """Loopback fixture. /api/Products/1 returns the same JSON to everyone (so the
    crawl keeps one capture for it); /api/Users is refused (401) without a
    credential and answered for user1."""

    def __init__(self):
        self.requests: list[tuple[str, str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                outer.requests.append((self.command, self.path, auth))
                path = urlsplit(self.path).path
                if path.startswith("/api/Products/"):
                    status, body = 200, _PRODUCT
                elif path == "/api/Users":
                    status, body = (200, _USERS) if auth else (401, '{"error": "login required"}')
                else:
                    status, body = 404, "{}"
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _fake_crawl(base_url, headers=None, allowed_hosts=None, max_pages=40, max_depth=2,
                timeout=15.0, **kwargs):
    async def crawl():
        result = CrawlResult(base_url=base_url)
        result.endpoints = {"/api/Products/1", "/api/Users"}
        return result
    return crawl()


class _CrawlBase(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)
        self.api = _Api()
        self.addCleanup(self.api.close)

    def crawl(self, roles, **kw):
        kw.setdefault("allowed_hosts", ["127.0.0.1"])
        with patch("harness.crawler.crawl", _fake_crawl):
            return asyncio.run(role_crawl.crawl_roles(self.api.base, roles, **kw))

    def build(self, roles, **kw):
        kw.setdefault("allowed_hosts", ["127.0.0.1"])
        kw.setdefault("active_discovery", False)
        with patch("harness.crawler.crawl", _fake_crawl):
            return asyncio.run(_REAL_BUILD(self.api.base, roles, **kw))


class RoleCrawlIdentityProbeTests(_CrawlBase):
    def test_the_content_dedup_stays_and_every_identity_gets_a_probe_record(self):
        result = self.crawl([ANON, USER1])
        products = [c for c in result.captured if urlsplit(c["url"]).path == "/api/Products/1"]
        self.assertEqual(len(products), 1, "the same body for two identities is still one capture")
        probes = [p for p in result.identity_probes if urlsplit(p["url"]).path == "/api/Products/1"]
        self.assertEqual(len(probes), 2, result.identity_probes)
        self.assertEqual({p["principal_id"] for p in probes}, {"anonymous", "user1"})
        self.assertEqual(len({p["identity_key"] for p in probes}), 2)
        self.assertEqual({p["identity_key"] for p in probes},
                         {capture_identity_key(ANON.headers), capture_identity_key(USER1.headers)})
        for probe in probes:
            self.assertEqual((probe["method"], probe["response_status"]), ("GET", 200))
            self.assertEqual(probe["response_body_sha256"], hashlib.sha256(_PRODUCT.encode()).hexdigest())
            self.assertEqual(probe["response_body_len"], len(_PRODUCT))
            self.assertFalse([k for k in probe if "body" in k and k not in
                              ("request_body", "response_body_sha256", "response_body_len")],
                             "a probe record carries no response body")
        self.assertEqual({p["role"] for p in probes}, {"anonymous", "user"})

    def test_a_refused_response_is_recorded_too(self):
        result = self.crawl([ANON, USER1])
        users = {p["principal_id"]: p for p in result.identity_probes
                 if urlsplit(p["url"]).path == "/api/Users"}
        self.assertEqual({k: v["response_status"] for k, v in users.items()},
                         {"anonymous": 401, "user1": 200})
        # ... although the refusal was not kept as a capture.
        self.assertFalse([c for c in result.captured
                          if urlsplit(c["url"]).path == "/api/Users" and c["response_status"] == 401])

    def test_probes_are_bounded_by_the_probed_operations_and_roles(self):
        result = self.crawl([ANON, USER1], max_endpoints=1)
        self.assertEqual(len(result.identity_probes), 2)
        self.assertEqual(len({urlsplit(p["url"]).path for p in result.identity_probes}), 1)

    def test_the_serialised_result_does_not_carry_the_probes_credentials(self):
        result = self.crawl([ANON, USER1])
        self.assertNotIn("identity_probes", result.to_dict())

    def test_nothing_is_recorded_for_a_probe_that_was_never_sent(self):
        result = self.crawl([ANON, USER1], allowed_hosts=["elsewhere.invalid"])
        self.assertEqual(result.identity_probes, [])
        self.assertEqual(self.api.requests, [])


class BuilderVariantTests(_CrawlBase):
    def state(self, roles=(ANON, USER1)):
        state, _ = self.build(list(roles))
        return state

    def test_each_probed_identity_has_a_variant_on_the_endpoint(self):
        state = self.state()
        products = state.endpoints["GET /api/Products/{id}"]
        keys = {v["identity_key"] for v in products.capture_variants}
        self.assertEqual(keys, {capture_identity_key(ANON.headers), capture_identity_key(USER1.headers)})
        for variant in products.capture_variants:
            self.assertEqual(variant["source"], "access_matrix")
            self.assertEqual(variant["template"]["method"], "GET")
            self.assertEqual(variant["template"]["object_id"], "1")

    def test_a_refused_identity_still_has_a_variant(self):
        state = self.state()
        users = state.endpoints["GET /api/Users"]
        anonymous = [v for v in users.capture_variants
                     if v["identity_key"] == capture_identity_key(ANON.headers)]
        self.assertEqual([v["response_status"] for v in anonymous], [401])
        # An auth-bypass style leg can replay it: the drive's node for the anonymous
        # identity carries the request with no credentials.
        nodes = list(worklist_investigator.captured_nodes(
            users.to_dict(), self.api.base, [ANON, USER1], include_probes=True))
        node = next(n for n in nodes if n.get("probe_session") is ANON)
        exchange = worklist_investigator._seed_exchange(self.api.base, node, {}, "1")
        self.assertEqual((exchange.method, urlsplit(exchange.url).path, exchange.request_headers),
                         ("GET", "/api/Users", {}))
        self.assertEqual(exchange.response_status, 401)

    def test_a_probe_variant_keeps_no_response_body(self):
        state = self.state()
        self.assertEqual(sum(len(ep.capture_variants) for ep in state.endpoints.values()), 4)
        for ep in state.endpoints.values():
            for variant in ep.capture_variants:
                self.assertEqual(variant["response_body"], "")
                self.assertGreater(variant["response_body_len"], 0)
                self.assertEqual(len(variant["response_body_sha256"]), 64)
        snapshot = json.dumps(state.to_dict())
        self.assertNotIn("Apple Juice", snapshot)
        self.assertNotIn("user1-token", snapshot)

    def test_a_probe_variant_is_not_a_full_captures_variant(self):
        state = self.state()
        probe = state.endpoints["GET /api/Products/{id}"].capture_variants[0]
        exchange = HttpExchange(url=f"{self.api.base}/api/Products/1", method="GET",
                                request_headers=dict(ANON.headers), response_status=200,
                                response_headers={"Content-Type": "application/json"},
                                response_body=_PRODUCT)
        full = capture_variant(exchange)
        self.assertNotEqual(full["capture_id"], probe["capture_id"])
        self.assertEqual(full["template"], probe["template"])
        # Recording the full capture next to the probes keeps both, deduped by id.
        state.record_template(exchange.url, "GET", exchange)
        state.record_template(exchange.url, "GET", exchange)
        ids = [v["capture_id"] for v in state.endpoints["GET /api/Products/{id}"].capture_variants]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn(full["capture_id"], ids)
        self.assertEqual(len(ids), 3)

    def test_replay_prefers_a_full_capture_of_the_same_request(self):
        state = self.state()
        ep = state.endpoints["GET /api/Products/{id}"]
        key = capture_identity_key(ANON.headers)
        self.assertEqual([v["source"] for v in replayable_variants(ep, key)], ["access_matrix"])
        exchange = HttpExchange(url=f"{self.api.base}/api/Products/1", method="GET",
                                request_headers=dict(ANON.headers), response_status=200,
                                response_body=_PRODUCT)
        state.record_template(exchange.url, "GET", exchange)
        replay = replayable_variants(ep, key)
        self.assertEqual(len(replay), 1)
        self.assertNotEqual(replay[0].get("source"), "access_matrix")
        # An identity with no variant yields nothing: nothing is built for it.
        self.assertEqual(replayable_variants(ep, capture_identity_key(GHOST.headers)), [])

    def test_the_new_keys_survive_serialisation_and_merging(self):
        state = self.state()
        again = engagement.EngagementState.from_dict(json.loads(json.dumps(state.to_dict())))
        self.assertTrue(all(ep.capture_variants for ep in state.endpoints.values()))
        for key, ep in state.endpoints.items():
            self.assertEqual(again.endpoints[key].capture_variants, ep.capture_variants)
        merged = engagement.EngagementState(host=state.host)
        merged.merge_from(again)
        added = merged.merge_from(state)
        self.assertEqual(added, 0)
        for key, ep in state.endpoints.items():
            self.assertEqual(len(merged.endpoints[key].capture_variants), len(ep.capture_variants), key)

    def test_the_job_result_keeps_the_probes_real_digest(self):
        state = self.state()
        entry = state.result_worklist(10)
        products = next(e for e in entry if e["path"] == "/api/Products/{id}")
        for variant in products["capture_variants"]:
            self.assertEqual(variant["response_body_sha256"], hashlib.sha256(_PRODUCT.encode()).hexdigest())
            self.assertEqual(variant["response_body_len"], len(_PRODUCT))
            self.assertEqual(variant["response_body_head"], "")
            self.assertNotIn("response_body", variant)

    def test_recording_a_probe_twice_adds_one_variant(self):
        state = self.state()
        ep = state.endpoints["GET /api/Products/{id}"]
        before = len(ep.capture_variants)
        probe = ep.capture_variants[0]
        raw = {"request_headers": dict(ANON.headers), "request_body": "", "response_status": 200,
               "response_headers": {}, "response_body_sha256": probe["response_body_sha256"],
               "response_body_len": probe["response_body_len"]}
        state.record_identity_probe(f"{self.api.base}/api/Products/1", "GET", raw)
        state.record_identity_probe(f"{self.api.base}/api/Products/1", "GET", raw)
        self.assertLessEqual(len(ep.capture_variants), before + 1)

    def test_the_worklist_investigates_full_captures_not_probe_variants(self):
        state = self.state()
        nodes = list(worklist_investigator.captured_nodes(
            state.endpoints["GET /api/Products/{id}"].to_dict(), self.api.base, [ANON, USER1]))
        self.assertEqual(len(nodes), 1)
        self.assertIsNone(nodes[0].get("capture"), "the unchanged fabricated node, as before probes")
        with_probes = list(worklist_investigator.captured_nodes(
            state.endpoints["GET /api/Products/{id}"].to_dict(), self.api.base, [ANON, USER1],
            include_probes=True))
        self.assertEqual(len(with_probes), 2)


def _record_cross_identity(calls):
    async def validate(self, finding, exchange, *args, **kwargs):
        calls.append((urlsplit(exchange.url).path, exchange.request_headers.get("Authorization", ""),
                      exchange.response_body, exchange.response_status))
        return ValidationResult("cross_identity", "not_confirmed", "idor", summary="recorded")
    return validate


class DriveCallerTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement with the real builder and crawl against the fixture,
    the coverage drive on, and the cross-identity leg recorded."""

    def _investigate(self, roles, *, crawled=None, extra=()):
        api = _Api()
        self.addCleanup(api.close)
        calls = []

        async def build(base_url, roles_arg, **kw):
            kw["active_discovery"] = False
            with patch("harness.crawler.crawl", _fake_crawl):
                return await _REAL_BUILD(base_url, list(crawled) if crawled else roles_arg, **kw)

        def drive_config(*, mutating):
            cfg = _config(mutating=mutating)
            cfg["engagement"]["coverage_drive_legs"] = True
            return cfg
        patches = [patch("harness.engagement_builder.build_engagement", side_effect=build),
                   patch("harness.validators.cross_identity_validator.CrossIdentityValidator.validate",
                         new=_record_cross_identity(calls)), *extra]
        with patch("harness.test_engagement_transport_callers._config", drive_config):
            result, rc, model = self._run(api, max_requests=500, roles=list(roles),
                                          extra_patches=patches)
        return result, calls

    @staticmethod
    def cells(result, identity):
        return [c for c in result["coverage"]["phase_ledger"]["cells"] if c["identity"] == identity]

    def test_a_probed_identity_is_dispatched_instead_of_missing_principal(self):
        result, calls = self._investigate([ANON, USER1])
        user1_legs = [c for c in calls if c[1] == "Bearer user1-token"
                      and c[0] == "/api/Products/1"]
        self.assertTrue(user1_legs, f"no leg ran as user1: {calls}")
        # It replayed the request the crawl sent as user1 (its probe carries the
        # status it drew), not a shape made up for the identity.
        self.assertEqual({status for _, _, _, status in user1_legs}, {200})
        self.assertEqual(result["prerequisite_blocks"], [])
        blocked = [c for c in self.cells(result, "user1") if c["terminal_reason"] == "missing_principal"]
        self.assertEqual(blocked, [])
        # The leg replayed the probe's request; no response body travelled with it.
        self.assertTrue(all(body == "" for path, auth, body, _ in calls
                            if auth == "Bearer user1-token" and path == "/api/Products/1"))

    def test_without_the_identity_probes_the_same_identity_is_missing_principal(self):
        """The control for the test above: with the new variants patched out, user1
        has no request on the endpoint and its checks cannot run."""
        result, calls = self._investigate(
            [ANON, USER1],
            extra=[patch.object(engagement.EngagementState, "record_identity_probe",
                                lambda self, url, method, probe: None)])
        self.assertFalse([c for c in calls if c[1] == "Bearer user1-token"
                          and c[0] == "/api/Products/1"], calls)
        blocks = {(b["endpoint"], b["identity"]): b for b in result["prerequisite_blocks"]}
        self.assertIn(("GET /api/Products/{id}", "user1"), blocks)
        self.assertGreater(blocks[("GET /api/Products/{id}", "user1")]["checks_affected"], 1)

    def test_an_identity_the_crawl_never_probed_stays_missing_principal_once_per_pair(self):
        lookups = []
        real = engagement.replayable_variants

        def counting(ep, key):
            lookups.append((ep.key, key))
            return real(ep, key)
        result, calls = self._investigate([ANON, USER1, GHOST], crawled=[ANON, USER1],
                                          extra=[patch("harness.engagement.replayable_variants", counting)])
        blocks = result["prerequisite_blocks"]
        ghost = [b for b in blocks if b["identity"] == "ghost"]
        self.assertEqual(sorted(b["endpoint"] for b in ghost),
                         ["GET /api/Products/{id}", "GET /api/Users"])
        for block in ghost:
            self.assertGreater(block["checks_affected"], 1, block)
            self.assertEqual(block["missing"], "no request captured as this identity")
            self.assertIn("signed in as user", block["action"])
            self.assertIn("role crawl seed", block["action"])
        self.assertFalse([c for c in calls if c[1] == "Bearer ghost-token"], calls)
        # The coverage accounting keeps the per-cell reason.
        ghost_cells = [c for c in self.cells(result, "ghost") if c["terminal_reason"] == "missing_principal"]
        self.assertTrue(ghost_cells)
        self.assertTrue(all(not c["attempted"] and not c["sent"] for c in ghost_cells), ghost_cells)
        self.assertTrue(all(c["terminal_reason"] == "missing_principal" for c in ghost_cells), ghost_cells)
        self.assertEqual(sum(b["checks_affected"] for b in ghost), len(ghost_cells))
        # The inventory is worked out once per (endpoint, identity), not per check.
        self.assertEqual(len(lookups), len(set(lookups)), "a pair was looked up more than once")
        self.assertEqual(len(lookups), 2 * 3)
        # The probed identities have no block.
        self.assertEqual({b["identity"] for b in blocks}, {"ghost"})

    def test_probing_that_identity_removes_the_block(self):
        result, calls = self._investigate([ANON, USER1, GHOST])
        self.assertEqual(result["prerequisite_blocks"], [])
        self.assertTrue([c for c in calls if c[1] == "Bearer ghost-token"], calls)


if __name__ == "__main__":
    unittest.main()
