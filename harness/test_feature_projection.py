"""Tests for the anonymized cloud-coordinator feature projection.

The central invariant these tests defend is the anonymization contract: the
projection is transmitted OFF-PREM, so it must carry routing signal (names,
shapes, status, presence booleans) while NEVER carrying a body value, a
header value, a query value, or a resource id.
"""
import json
import unittest

from harness.models import HttpExchange
from harness.feature_projection import project_exchange


class ProjectionSignalTests(unittest.TestCase):
    def test_method_path_status_preserved(self):
        ex = HttpExchange(
            url="https://shop.test/rest/products",
            method="get",
            response_status=200,
        )
        p = project_exchange(ex)
        self.assertEqual(p.method, "GET")
        self.assertEqual(p.path, "/rest/products")
        self.assertEqual(p.response_status, 200)

    def test_numeric_id_segment_flagged_and_redacted(self):
        ex = HttpExchange(url="https://shop.test/api/Users/35", method="GET")
        p = project_exchange(ex)
        self.assertTrue(p.has_resource_id)
        self.assertEqual(p.path, "/api/Users/{id}")
        self.assertNotIn("35", p.path)

    def test_uuid_segment_flagged_and_redacted(self):
        uid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        ex = HttpExchange(url=f"https://shop.test/orders/{uid}", method="GET")
        p = project_exchange(ex)
        self.assertTrue(p.has_resource_id)
        self.assertNotIn(uid, p.path)

    def test_query_param_names_only_no_values(self):
        ex = HttpExchange(
            url="https://shop.test/search?q=secretterm&category=42",
            method="GET",
        )
        p = project_exchange(ex)
        self.assertEqual(set(p.query_param_names), {"q", "category"})
        # Values must never appear anywhere in the projection.
        blob = json.dumps(p.to_dict())
        self.assertNotIn("secretterm", blob)
        self.assertNotIn("42", blob)

    def test_json_body_key_names_only_no_values(self):
        ex = HttpExchange(
            url="https://shop.test/rest/user/login",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"email": "admin@juice-sh.op' -- ", "password": "hunter2"}),
        )
        p = project_exchange(ex)
        self.assertEqual(set(p.body_param_names), {"email", "password"})
        self.assertEqual(p.request_json_shape, "json_object")
        blob = json.dumps(p.to_dict())
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("juice-sh.op", blob)

    def test_header_values_never_leak_only_presence(self):
        ex = HttpExchange(
            url="https://shop.test/api/me",
            method="GET",
            request_headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.secretpayload.sig",
                "Cookie": "session=topsecretvalue",
                "Origin": "https://evil.test",
            },
            response_headers={"Access-Control-Allow-Origin": "*"},
        )
        p = project_exchange(ex)
        self.assertTrue(p.has_authorization)
        self.assertTrue(p.has_cookie)
        self.assertTrue(p.request_has_cors_origin)
        self.assertTrue(p.response_has_cors_headers)
        blob = json.dumps(p.to_dict()) + json.dumps(p.to_prompt_dict())
        self.assertNotIn("secretpayload", blob)
        self.assertNotIn("topsecretvalue", blob)
        self.assertNotIn("evil.test", blob)

    def test_no_body_content_leaks(self):
        ex = HttpExchange(
            url="https://shop.test/rest/products/reviews",
            method="GET",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body=json.dumps({"data": [{"message": "PROPRIETARY-SECRET-REVIEW"}]}),
        )
        p = project_exchange(ex)
        blob = json.dumps(p.to_dict())
        self.assertNotIn("PROPRIETARY-SECRET-REVIEW", blob)

    def test_response_shape_stack_trace(self):
        ex = HttpExchange(
            url="https://shop.test/api/Feedbacks",
            method="POST",
            response_status=500,
            response_body='SequelizeDatabaseError\n    at com.foo.Bar(Bar.java:42)\n    at org.baz',
        )
        p = project_exchange(ex)
        self.assertIn("stack_trace", p.response_shape)

    def test_response_shape_directory_listing(self):
        ex = HttpExchange(
            url="https://shop.test/ftp",
            method="GET",
            response_status=200,
            response_body='<title>Index of /ftp</title><pre><a href="coupons.txt">coupons.txt</a></pre>',
        )
        p = project_exchange(ex)
        self.assertIn("directory_listing", p.response_shape)

    def test_size_bucketing_is_coarse(self):
        small = HttpExchange(url="https://shop.test/a", method="GET", response_body="x" * 10)
        large = HttpExchange(url="https://shop.test/b", method="GET", response_body="x" * 50000)
        self.assertEqual(project_exchange(small).response_size_bucket, "small")
        self.assertEqual(project_exchange(large).response_size_bucket, "large")

    def test_prompt_dict_omits_empty_and_false_fields(self):
        ex = HttpExchange(url="https://shop.test/health", method="GET", response_status=200)
        d = project_exchange(ex).to_prompt_dict()
        # No id, no params, no auth -> those keys absent, keeping the prompt tight.
        self.assertNotIn("has_resource_id", d)
        self.assertNotIn("query_param_names", d)
        self.assertNotIn("has_authorization", d)
        self.assertEqual(d["path"], "/health")

    def test_malformed_json_body_fails_closed(self):
        ex = HttpExchange(
            url="https://shop.test/x",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body="{not valid json",
        )
        p = project_exchange(ex)
        self.assertEqual(p.body_param_names, [])
        self.assertIsNone(p.request_json_shape)

    def test_deterministic(self):
        ex = HttpExchange(
            url="https://shop.test/api/orders/9?sort=date",
            method="POST",
            request_headers={"Content-Type": "application/json", "Authorization": "Bearer z"},
            request_body=json.dumps({"a": 1, "b": 2}),
            response_status=201,
        )
        self.assertEqual(project_exchange(ex).to_dict(), project_exchange(ex).to_dict())


if __name__ == "__main__":
    unittest.main()
