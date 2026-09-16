"""W-21: OpenAPI / Swagger ingestion extracts the full operation surface
(path x method x parameters), not just path strings."""
import json
import unittest

import harness.openapi_ingest as oi


_OPENAPI3 = {
    "openapi": "3.0.0",
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path"}],  # path-level, shared
            "get": {"parameters": [{"name": "fields", "in": "query"}]},
            "delete": {},
        },
        "/orders": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"item": {"type": "string"}, "qty": {"type": "integer"}},
                            }
                        }
                    }
                }
            }
        },
        "/search": {
            "get": {"parameters": [{"$ref": "#/components/parameters/Q"}]},
        },
    },
    "components": {"parameters": {"Q": {"name": "q", "in": "query"}}},
}

_SWAGGER2 = {
    "swagger": "2.0",
    "paths": {
        "/login": {
            "post": {
                "parameters": [
                    {"name": "next", "in": "query"},
                    {"in": "body", "name": "body",
                     "schema": {"type": "object", "properties": {"user": {}, "pass": {}}}},
                ]
            }
        }
    },
}


class OpenApi3Tests(unittest.TestCase):
    def setUp(self):
        self.ops = oi.operations_from_spec(_OPENAPI3)

    def _op(self, path, method):
        return next(o for o in self.ops if o.path == path and o.method == method)

    def test_methods_extracted_per_path(self):
        got = {(o.path, o.method) for o in self.ops}
        self.assertIn(("/users/{id}", "GET"), got)
        self.assertIn(("/users/{id}", "DELETE"), got)
        self.assertIn(("/orders", "POST"), got)

    def test_path_level_parameters_apply_to_all_operations(self):
        # the shared {id} path param appears on both GET and DELETE
        self.assertIn("id", self._op("/users/{id}", "GET").param_names)
        self.assertIn("id", self._op("/users/{id}", "DELETE").param_names)

    def test_operation_parameters_extracted_with_location(self):
        get = self._op("/users/{id}", "GET")
        by_name = {p.name: p.location for p in get.parameters}
        self.assertEqual(by_name.get("fields"), "query")
        self.assertEqual(by_name.get("id"), "path")

    def test_request_body_fields_become_body_params(self):
        post = self._op("/orders", "POST")
        by_name = {p.name: p.location for p in post.parameters}
        self.assertEqual(by_name.get("item"), "body")
        self.assertEqual(by_name.get("qty"), "body")

    def test_parameter_ref_is_resolved(self):
        self.assertIn("q", self._op("/search", "GET").param_names)


class Swagger2Tests(unittest.TestCase):
    def test_swagger2_body_and_query_params(self):
        ops = oi.operations_from_spec(_SWAGGER2)
        post = next(o for o in ops if o.path == "/login" and o.method == "POST")
        by_name = {p.name: p.location for p in post.parameters}
        self.assertEqual(by_name.get("next"), "query")
        self.assertEqual(by_name.get("user"), "body")
        self.assertEqual(by_name.get("pass"), "body")


class HelpersAndRobustnessTests(unittest.TestCase):
    def test_methods_by_path(self):
        m = oi.methods_by_path(_OPENAPI3)
        self.assertEqual(m["/users/{id}"], ("DELETE", "GET"))
        self.assertEqual(m["/orders"], ("POST",))

    def test_accepts_json_string(self):
        ops = oi.operations_from_spec(json.dumps(_OPENAPI3))
        self.assertTrue(ops)

    def test_garbage_returns_empty(self):
        self.assertEqual(oi.operations_from_spec("not json"), [])
        self.assertEqual(oi.operations_from_spec({}), [])
        self.assertEqual(oi.operations_from_spec({"paths": "nope"}), [])

    def test_non_http_keys_ignored(self):
        spec = {"paths": {"/x": {"x-vendor": {}, "get": {}}}}
        ops = oi.operations_from_spec(spec)
        self.assertEqual([(o.path, o.method) for o in ops], [("/x", "GET")])


if __name__ == "__main__":
    unittest.main()
