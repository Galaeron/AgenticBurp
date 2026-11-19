"""R11-9: the crawler's guessed body no longer serves as the endpoint template.

- A PUT/PATCH of one object sent only with the crawler's guess, whose GET was
  observed, gets a template body built from that read (settable fields only),
  marked read-built; the injection legs then mutate the read's fields.
- Negative control: a real captured body is never replaced, and a captured body
  arriving after the read-built one takes over.
- Negative control: a guessed body is never offered to an injection leg as known
  parameters (param_targets, the shape routing, sqlmap, stored_xss, nosql and the
  coverage parameter cases).

Offline: nothing is sent anywhere.
"""
import asyncio
import json
import unittest

from harness.coverage_model import derive_input_cases_from_template
from harness.engagement import EngagementState, READ_BUILT_BODY, template_body_is_read_built
from harness.models import Finding, HttpExchange
from harness.orchestrator_helpers import shape_precondition_legs
from harness.role_crawl import _GENERIC_JSON_BODY
from harness.validators.injection_targets import guessed_body, param_targets
from harness.validators.nosql_validator import operator_targets
from harness.validators.sqlmap import SqlmapValidator
from harness.validators.stored_xss_validator import StoredXssValidator
from harness import worklist_investigator

_BASE = "http://127.0.0.1:9"
_ITEM = "/api/Products/7"
_READ = {"status": "success",
         "data": {"id": 7, "name": "Apple Juice", "description": "fresh", "price": 1.99,
                  "createdAt": "2026-11-01T10:00:00Z", "image": "apple.jpg",
                  "deluxePrice": 0.99, "passwordHash": "x" * 32, "tags": ["a"]}}
_SETTABLE = {"name", "description", "price", "image", "deluxePrice"}
_AUTH = {"Authorization": "Bearer t"}


def _get(path=_ITEM, doc=_READ, status=200):
    return HttpExchange(url=_BASE + path, method="GET", request_headers=dict(_AUTH),
                        response_status=status, response_body=json.dumps(doc),
                        response_headers={"Content-Type": "application/json"})


def _write(body=_GENERIC_JSON_BODY, method="PUT", path=_ITEM):
    return HttpExchange(url=_BASE + path, method=method, request_body=body,
                        request_headers=dict(_AUTH, **{"Content-Type": "application/json"}),
                        response_status=400, response_body="{}")


def _state(*exchanges):
    state = EngagementState(host="127.0.0.1")
    for ex in exchanges:
        state.record_template(ex.url, ex.method, ex)
    return state


def _seed(state, method="PUT", path="/api/Products/{id}"):
    node = state.endpoints[f"{method} {path}"].to_dict()
    return node, worklist_investigator._seed_exchange(_BASE, node, dict(_AUTH), "1")


class ReadBuiltTemplateTest(unittest.TestCase):
    def test_guessed_write_with_observed_read_gets_a_read_built_template(self):
        for order in ((_get(), _write()), (_write(), _get())):
            state = _state(*order)
            tmpl = state.endpoints["PUT /api/Products/{id}"].template
            self.assertTrue(template_body_is_read_built(tmpl), order)
            self.assertEqual(tmpl["body_source"], READ_BUILT_BODY)
            self.assertEqual(set(json.loads(tmpl["body"])), _SETTABLE)
            self.assertEqual(tmpl["content_type"], "application/json")
            self.assertEqual(tmpl["object_id"], "7")
            self.assertEqual(tmpl["read_from"], "GET /api/Products/{id}")

    def test_injection_legs_mutate_the_reads_settable_fields(self):
        node, ex = _seed(_state(_get(), _write()))
        self.assertFalse(guessed_body(ex))
        self.assertEqual({p for _, p in param_targets(ex)}, _SETTABLE)
        legs = {name for name, _ in shape_precondition_legs(node, ex, [], _BASE)}
        self.assertTrue({"sqli", "command_injection", "ssti", "xss"} <= legs, legs)
        self.assertTrue(StoredXssValidator().applies(
            Finding(vulnerability_class="stored_xss", confidence=0.5, summary="s", evidence="", suggested_test="", basis="derived"), ex))
        cases = {c.parameter_name for c in derive_input_cases_from_template(node["template"])}
        self.assertTrue({"/name", "/description"} <= cases, cases)

    def test_a_guessed_capture_variant_replays_the_read_built_body(self):
        state = _state(_get(), _write())
        ep = state.endpoints["PUT /api/Products/{id}"]
        role = type("R", (), {"headers": dict(_AUTH), "role": "user"})()
        nodes = list(worklist_investigator.captured_nodes(ep.to_dict(), _BASE, [role]))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(set(json.loads(nodes[0]["template"]["body"])), _SETTABLE)
        # another object's guessed capture keeps its own (guessed) body
        other = worklist_investigator._read_built_over_guess(
            dict(nodes[0]["capture"]["template"], path_ids=["8"]), ep.template)
        self.assertEqual(other["body"], _GENERIC_JSON_BODY)

    def test_control_a_captured_body_is_never_replaced(self):
        real = '{"name": "Banana", "price": 2}'
        for order in ((_get(), _write(real)), (_write(real), _get())):
            tmpl = _state(*order).endpoints["PUT /api/Products/{id}"].template
            self.assertEqual(tmpl["body"], real)
            self.assertFalse(template_body_is_read_built(tmpl))

    def test_control_a_captured_body_arriving_later_takes_over(self):
        real = '{"name": "Banana", "price": 2}'
        state = _state(_get(), _write())
        self.assertTrue(template_body_is_read_built(state.endpoints["PUT /api/Products/{id}"].template))
        state.record_template(_BASE + _ITEM, "PUT", _write(real))
        tmpl = state.endpoints["PUT /api/Products/{id}"].template
        self.assertEqual(tmpl["body"], real)
        self.assertFalse(template_body_is_read_built(tmpl))
        # a later guessed capture does not displace the read-built body either
        state = _state(_get(), _write())
        state.record_template(_BASE + _ITEM, "PUT", _write())
        self.assertTrue(template_body_is_read_built(state.endpoints["PUT /api/Products/{id}"].template))

    def test_no_read_built_body_without_a_usable_read(self):
        cases = [
            ("no GET observed", [_write()]),
            ("GET failed", [_get(status=403), _write()]),
            ("GET is a listing", [_get(doc={"data": [{"id": 1}, {"id": 2}]}), _write()]),
            ("POST create", [_get(path="/api/Products/7"), _write(method="POST")]),
        ]
        for label, exchanges in cases:
            state = _state(*exchanges)
            for key, ep in state.endpoints.items():
                if not key.startswith("GET"):
                    self.assertFalse(template_body_is_read_built(ep.template), label)


class GuessedBodyIsNotParametersTest(unittest.TestCase):
    def test_guessed_body_offers_no_body_target(self):
        ex = _write()
        self.assertTrue(guessed_body(ex))
        self.assertEqual(param_targets(ex), [])
        self.assertEqual(operator_targets(ex), [])
        with_query = _write().model_copy(update={"url": _BASE + _ITEM + "?q=1"})
        self.assertEqual(param_targets(with_query), [("query", "q")])

    def test_shape_routing_opens_no_injection_leg_on_a_guess(self):
        state = _state(_write())
        node, ex = _seed(state)
        legs = {name for name, _ in shape_precondition_legs(node, ex, [], _BASE)}
        self.assertFalse({"sqli", "command_injection", "ssti", "xss", "nosql"} & legs, legs)
        self.assertEqual([c for c in derive_input_cases_from_template(node["template"])
                          if c.parameter_location.startswith("body")], [])

    def test_stored_xss_does_not_plant_into_a_guess(self):
        f = Finding(vulnerability_class="stored_xss", confidence=0.5, summary="s", evidence="", suggested_test="", basis="derived")
        self.assertFalse(StoredXssValidator().applies(f, _write()))

    def test_sqlmap_is_not_launched_on_a_guess_without_query(self):
        v = SqlmapValidator(allowed_hosts=["127.0.0.1"])
        f = Finding(vulnerability_class="sqli", confidence=0.5, summary="s", evidence="", suggested_test="", basis="derived")
        res = asyncio.run(v.validate(f, _write()))
        self.assertEqual(res.status, "skipped", res.summary)
        self.assertIn("harness-guessed placeholder", res.summary)
        self.assertIn("not a negative", res.limitation or "")


if __name__ == "__main__":
    unittest.main()
