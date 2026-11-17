"""verb_tamper: an override POST the server executed as a POST is a create.

A POST carrying X-HTTP-Method-Override (or a sibling header) that the server
ignores runs as a plain POST; on a collection it creates an object. That answer
(201, a Location header, or a body naming an id the URL does not carry) used to
be reported as an OBSERVATION of a bypass. It is a negative for the bypass, the
object is named in the result and in the run's change log, and it is deleted
and verified gone when a DELETE route is known -- otherwise named as left in
place, with the remaining override POSTs withheld. A path where the run already
saw a POST create, with no restore route known, gets no override POST at all.

The transport is faked below httpx (the run executor and the default-gate client
both end in httpx.AsyncClient.request), so the run's gate, budget and change log
decide.
"""
import asyncio
import json
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx

from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate, SafetyGateConfig, gate_scope
from harness.validators.verb_tamper_validator import VerbTamperValidator, _created

_HOST = "shop.invalid"
_COLLECTION = f"http://{_HOST}/api/admin/things"
_ROUTE = "DELETE /api/admin/things/{id}"
_OVERRIDES = ("x-http-method-override", "x-method-override", "x-http-method")


def _finding() -> Finding:
    return Finding(vulnerability_class="misconfig", confidence=0.5, summary="denied admin listing",
                   evidence="fixture", suggested_test="verb tamper", basis="derived",
                   finding_id="vt-create-1")


def _exchange(url=_COLLECTION) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers={}, response_status=403,
                        response_headers={"Content-Type": "application/json"},
                        response_body='{"error": "forbidden"}')


def _response(method, url, status, body="", headers=None):
    return httpx.Response(status, text=body, headers=headers or {}, request=httpx.Request(method, url))


class _Api:
    """A collection whose reads are denied and whose POST creates, whatever
    override header it carries (honour=False) -- or a server that honours the
    override and serves the denied read (honour=True)."""

    def __init__(self, *, honour=False, location=True, status=201, deletes=True, honour_body=None):
        self.honour, self.location, self.status, self.deletes = honour, location, status, deletes
        self.honour_body = honour_body
        self.things: dict[int, dict] = {}
        self.next_id = 41
        self.sent: list[tuple[str, str, dict]] = []

    async def request(self, client, method, url, **kwargs):
        u = str(url)
        headers = {str(k).lower(): v for k, v in (kwargs.get("headers") or {}).items()}
        self.sent.append((method, u, headers))
        path = urlsplit(u).path
        override = next((headers[h] for h in _OVERRIDES if h in headers), None)
        if path == "/api/admin/things":
            if method == "POST" and override and self.honour:
                body = self.honour_body or json.dumps([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}])
                return _response(method, u, 200, body, {"content-type": "application/json"})
            if method == "POST":
                oid, self.next_id = self.next_id, self.next_id + 1
                self.things[oid] = {"id": oid, "name": ""}
                headers_out = {"content-type": "application/json"}
                if self.location:
                    headers_out["location"] = f"/api/admin/things/{oid}"
                return _response(method, u, self.status,
                                 json.dumps({"status": "success", "data": self.things[oid]}), headers_out)
            return _response(method, u, 403, '{"error": "forbidden"}')
        if path.startswith("/api/admin/things/"):
            oid = int(path.rsplit("/", 1)[1])
            if method == "DELETE":
                if self.deletes:
                    self.things.pop(oid, None)
                return _response(method, u, 200, '{"status": "success"}')
            if method == "GET":
                if oid in self.things:
                    return _response(method, u, 200, json.dumps(self.things[oid]),
                                     {"content-type": "application/json"})
                return _response(method, u, 404, "not found")
        return _response(method, u, 404, "not found")

    def methods(self, path=None):
        return [m for m, u, _ in self.sent if path is None or urlsplit(u).path == path]


def _run(*, mutating=True, max_requests=60) -> RunContext:
    return RunContext.create(allowed_hosts=[_HOST], max_requests=max_requests,
                             gate_config={"active_enabled": True, "allow_mutating_replay": mutating})


def _validate(api, *, run=None, exchange=None, before=None, **kwargs):
    """Validate inside the (entered) run, or unbound under an allowing default gate."""
    validator = VerbTamperValidator(allowed_hosts=[_HOST], timeout=1.0, run_context=run, **kwargs)

    async def go():
        if run is not None:
            async with run:
                if before is not None:
                    before(run)
                return await validator.validate(_finding(), exchange or _exchange())
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                           allowed_hosts=frozenset({_HOST})))
        with gate_scope(gate):
            return await validator.validate(_finding(), exchange or _exchange())

    async def transport(client, method, url, **kw):
        return await api.request(client, method, url, **kw)

    with patch.object(httpx.AsyncClient, "request", transport):
        return asyncio.run(go())


def _posts(run):
    return [e for e in run.change_log.entries()
            if e["method"] == "POST" and e["path"] == "/api/admin/things"]


# unittest.TestCase is named explicitly so the static orphan-test guard collects these.
class OverrideCreateTests(unittest.TestCase):

    def test_ignored_override_that_creates_is_a_negative_and_is_deleted(self):
        api, run = _Api(), _run()
        result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.confidence, 0.0)
        self.assertNotIn("OBSERVATION", result.summary)
        self.assertIn("override was ignored", result.summary)
        self.assertIn("3 deleted and verified gone", result.summary)
        # Each override POST created one object; each was deleted and read back gone.
        self.assertEqual(api.methods("/api/admin/things").count("POST"), 3)
        self.assertEqual(api.things, {})
        for oid in (41, 42, 43):
            self.assertIn(f"http://{_HOST}/api/admin/things/{oid}", result.evidence)
            self.assertEqual(api.methods(f"/api/admin/things/{oid}"), ["DELETE", "GET"])
        # The change log names each create and its verified restore; the cleanup
        # sends are recorded as cleanup.
        posts = _posts(run)
        self.assertEqual([e["object_ref"] for e in posts], ["created:41", "created:42", "created:43"])
        self.assertEqual({e["restore_status"] for e in posts}, {"restored"})
        self.assertEqual({e["capability"] for e in posts}, {"verb_tamper"})
        deletes = [e for e in run.change_log.entries() if e["method"] == "DELETE"]
        self.assertEqual({e["restore_status"] for e in deletes}, {"restore_send"})
        self.assertTrue(all(e["artifact_id"] in result.evidence for e in posts), result.evidence)

    def test_route_inventory_supplies_the_delete_route(self):
        api, run = _Api(), _run()
        result = _validate(api, run=run, route_inventory=lambda: ["GET /api/admin/things", _ROUTE])
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(api.things, {})

    def test_create_with_no_restore_route_is_left_in_place_and_named(self):
        api, run = _Api(), _run()
        with self.assertLogs("harness.validators.verb_tamper_validator", "WARNING") as logs:
            result = _validate(api, run=run)
        self.assertNotIn("OBSERVATION", result.summary)
        self.assertFalse(result.confirmed)
        self.assertIn(f"LEFT IN PLACE: http://{_HOST}/api/admin/things/41", result.summary)
        self.assertIn("left in place", "\n".join(logs.output))
        # One create only: the other override POSTs would each create another.
        self.assertEqual(api.methods("/api/admin/things").count("POST"), 1)
        self.assertNotIn("DELETE", api.methods())
        self.assertEqual(list(api.things), [41])
        self.assertIn("another would create another", result.summary)
        # Not a negative: two override headers were never sent.
        self.assertEqual(result.status, "inconclusive", result.summary)
        [entry] = _posts(run)
        self.assertEqual(entry["object_ref"], "created:41")
        self.assertEqual(entry["restore_status"], "none_declared")
        self.assertIn("LEFT IN PLACE", entry["restore_detail"])

    def test_delete_that_does_not_verify_is_a_loud_restore_failure(self):
        api, run = _Api(deletes=False), _run()
        with self.assertLogs("harness", "ERROR"):
            result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertEqual(result.status, "error", result.summary)
        self.assertTrue(result.summary.startswith("RESTORE FAILED"), result.summary)
        self.assertIn("remove it manually", result.summary)
        self.assertEqual(api.methods("/api/admin/things").count("POST"), 1)
        [entry] = _posts(run)
        self.assertEqual(entry["restore_status"], "restore_failed")

    def test_body_id_alone_is_read_as_a_create_but_never_deleted(self):
        # 200, no Location, a body naming a new id: could be an existing object an
        # honoured override returned, so nothing is deleted on that alone.
        api, run = _Api(status=200, location=False), _run()
        result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertNotIn("DELETE", api.methods())
        self.assertNotIn("OBSERVATION", result.summary)
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertIn("could be the override honoured", result.summary)
        self.assertIn("LEFT IN PLACE", result.summary)

    def test_honoured_override_keeps_the_observation(self):
        api, run = _Api(honour=True), _run()
        result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertEqual(result.status, "not_confirmed")
        self.assertEqual(result.confidence, 0.4)
        self.assertTrue(result.summary.startswith("OBSERVATION (not confirmed): POST with "
                                                  "X-HTTP-Method-Override: GET"), result.summary)
        self.assertNotIn("DELETE", api.methods())
        self.assertEqual(_posts(run)[0]["object_ref"], "")

    def test_honoured_override_returning_the_object_in_the_url_is_not_a_create(self):
        url = f"{_COLLECTION}/7"
        api, run = _Api(honour=True), _run()

        async def item(client, method, u, **kwargs):
            headers = {str(k).lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            api.sent.append((method, str(u), headers))
            if method == "POST" and any(h in headers for h in _OVERRIDES):
                return _response(method, str(u), 200, json.dumps({"id": 7, "secret": "s3cr3t-value"}),
                                 {"content-type": "application/json"})
            return _response(method, str(u), 403, '{"error": "forbidden"}')

        api.request = item
        result = _validate(api, run=run, exchange=_exchange(url), restore_routes=(_ROUTE,))
        self.assertTrue(result.summary.startswith("OBSERVATION"), result.summary)
        self.assertNotIn("DELETE", api.methods())

    def test_no_override_post_whose_cleanup_the_budget_cannot_pay_for(self):
        # HEAD and OPTIONS spend 2 of 4; a create's POST, DELETE and read-back need 3.
        api, run = _Api(), _run(max_requests=4)
        result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertNotIn("POST", api.methods())
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertIn("cannot pay for the POST plus the delete", result.summary)

    def test_mutating_permission_still_gates_the_override_post(self):
        api, run = _Api(), _run(mutating=False)
        result = _validate(api, run=run, restore_routes=(_ROUTE,))
        self.assertNotIn("POST", api.methods())
        self.assertEqual(api.things, {})
        self.assertIn(result.status, ("blocked", "inconclusive"), result.summary)
        self.assertIn("not a negative", result.summary)


class ObservedCreateSkipTests(unittest.TestCase):
    """The run already saw a POST to this path create: no override POST without a restore route."""

    @staticmethod
    def _seen_create(run):
        run.change_log.record_send(method="POST", url=_COLLECTION, status=201, capability="sequence",
                                   artifact_id="earlier-create",
                                   response_body=json.dumps({"id": 9, "name": "seen"}))

    def test_override_post_is_skipped_with_its_reason(self):
        api, run = _Api(), _run()
        result = _validate(api, run=run, before=self._seen_create)
        self.assertNotIn("POST", api.methods())
        self.assertEqual(api.things, {})
        self.assertFalse(result.confirmed)
        self.assertNotEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("created an object earlier in this run", result.summary)
        self.assertIn("created:9", result.summary)
        self.assertIn("not a negative", result.summary)
        # The safe alternates still ran.
        self.assertIn("HEAD", api.methods())

    def test_override_post_is_sent_when_a_restore_route_is_known(self):
        api, run = _Api(), _run()
        result = _validate(api, run=run, before=self._seen_create, restore_routes=(_ROUTE,))
        self.assertEqual(api.methods("/api/admin/things").count("POST"), 3)
        self.assertEqual(api.things, {})
        self.assertEqual(result.status, "not_confirmed", result.summary)

    def test_a_read_only_observed_post_does_not_skip(self):
        # A 200 POST with no created id is not evidence that POST creates here.
        def seen(run):
            run.change_log.record_send(method="POST", url=_COLLECTION, status=200,
                                       capability="sequence", artifact_id="search",
                                       response_body=json.dumps([{"id": 1}]))
        api, run = _Api(honour=True), _run()
        result = _validate(api, run=run, before=seen)
        self.assertIn("POST", api.methods())
        self.assertTrue(result.summary.startswith("OBSERVATION"), result.summary)


class NoContextCreateTests(unittest.TestCase):
    """Unbound, the same reading and restore go through the default gate."""

    def test_unbound_create_is_deleted_through_the_default_gate(self):
        api = _Api()
        result = _validate(api, restore_routes=(_ROUTE,))
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertNotIn("OBSERVATION", result.summary)
        self.assertEqual(api.things, {})
        self.assertEqual(api.methods().count("DELETE"), 3)

    def test_unbound_honoured_override_keeps_the_observation(self):
        result = _validate(_Api(honour=True))
        self.assertTrue(result.summary.startswith("OBSERVATION"), result.summary)


class CreatedReadingTests(unittest.TestCase):
    def test_signals(self):
        url = _COLLECTION
        strong = _created(url, 201, {}, json.dumps({"data": {"id": 5}}))
        self.assertEqual((strong["strong"], strong["item"], strong["id"]), (True, f"{url}/5", "5"))
        loc = _created(url, 200, {"Location": "/api/admin/things/6"}, "")
        self.assertEqual((loc["strong"], loc["item"]), (True, f"{url}/6"))
        off_origin = _created(url, 201, {"Location": "http://elsewhere.invalid/x/6"}, "")
        self.assertEqual(off_origin["item"], "")
        weak = _created(url, 200, {}, json.dumps({"id": 8}))
        self.assertFalse(weak["strong"])
        self.assertIsNone(_created(f"{url}/8", 200, {}, json.dumps({"id": 8})))
        self.assertIsNone(_created(url, 200, {}, json.dumps([{"id": 1}])))
        self.assertIsNone(_created(url, 302, {"Location": "/login"}, ""))
        self.assertIsNone(_created(url, None, {}, ""))


class WiringTests(unittest.TestCase):
    def test_registry_passes_the_declared_restore_routes(self):
        from harness import test_smoke_investigate as smoke
        from harness.validators.registry import ValidatorRegistry
        cfg = smoke._test_config()
        cfg["validators"].setdefault("write_integrity", {})["restore_routes"] = [_ROUTE]
        registry = ValidatorRegistry(cfg)
        self.assertEqual(registry.validators["verb_tamper"].restore_routes, (_ROUTE,))
        run = _run()
        [bound] = registry.bind_run_context([registry.validators["verb_tamper"]], run)
        self.assertIs(bound.run_context, run)
        self.assertEqual(bound.restore_routes, (_ROUTE,))


if __name__ == "__main__":
    unittest.main()
