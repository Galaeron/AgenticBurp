"""Client-side routes that answer one HTML document are checked once (r9 review, F4).

r9: a single-page app answered every client-side route (/, /about, /accounting,
/2fa/enter, /address/saved, /address/create, ...) with the same 9,984-byte
document, and each route was a new request shape, so ssti sent 238 payloads to
each of them. A shape-keyed leg's clean result on a route whose capture is a full
HTML document now also covers another route whose capture is that same document.

Caller: _ConfirmationCache, the coverage drive's and the worklist's entry into the
run's ExecutionRegistry. Controls: the grouping removed (the r9 behaviour), two
different documents, identical JSON at two routes, a result that detected something,
and a leg that is not shape-keyed.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from harness import execution_registry
from harness.execution_registry import ExecutionRegistry
from harness.models import HttpExchange
from harness.orchestrator_chain_support import _ConfirmationCache
from harness.test_execution_registry import _Counting, _finding_of

ORIGIN = "http://127.0.0.1:3000"
SHELL = ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>App</title>"
         "<base href=\"/\"><link rel=\"stylesheet\" href=\"styles.css\"></head><body>"
         "<app-root></app-root>" + "<script src=\"main.js\" type=\"module\"></script>" * 6
         + "</body></html>")


def _get(path, body=SHELL, ctype="text/html; charset=UTF-8"):
    return HttpExchange(url=ORIGIN + path, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={"Content-Type": ctype},
                        response_body=body)


def _validate_each(exchanges, *, name="ssti", status="not_confirmed", confirmed=False):
    registry = ExecutionRegistry()
    validator = _Counting(name=name, status=status, confirmed=confirmed)
    cache = _ConfirmationCache(None, lambda *a: "unused", registry=registry)

    async def go():
        return [await cache.validate(validator, _finding_of(name), exchange, case_ref=f"case-{n}")
                for n, exchange in enumerate(exchanges)]
    return asyncio.run(go()), validator, registry


class ShellDocumentCoverTests(unittest.TestCase):

    ROUTES = ("/about", "/accounting", "/address/create")

    def test_routes_serving_one_document_are_checked_once(self):
        results, validator, registry = _validate_each([_get(p) for p in self.ROUTES])
        self.assertEqual(len(validator.calls), 1)
        self.assertEqual([r.covered_by for r in results[1:]], ["case-0", "case-0"])
        self.assertTrue(all("same HTML document /about returned" in r.summary
                            for r in results[1:]), [r.summary for r in results])
        self.assertTrue(all(not r.confirmed and r.sent_count == 0 for r in results[1:]))
        self.assertEqual(registry.stats()["by_validator"]["ssti"]["shell_covers"], 2)

    def test_control_without_the_grouping_every_route_is_checked(self):
        with patch.object(execution_registry, "_shell_key", lambda *a: None):
            _results, validator, _ = _validate_each([_get(p) for p in self.ROUTES])
        self.assertEqual(len(validator.calls), len(self.ROUTES))     # the r9 behaviour

    def test_control_different_documents_are_checked_apart(self):
        other = SHELL.replace("<app-root></app-root>", "<main>Order history</main>")
        _results, validator, _ = _validate_each([_get("/about"), _get("/orders", other)])
        self.assertEqual(len(validator.calls), 2)

    def test_control_identical_json_at_two_routes_is_not_a_shell(self):
        body = "[" + ",".join('{"id": %d}' % i for i in range(40)) + "]"
        _results, validator, _ = _validate_each(
            [_get("/api/a", body, "application/json"), _get("/api/b", body, "application/json")])
        self.assertEqual(len(validator.calls), 2)

    def test_control_a_detection_covers_no_other_route(self):
        _results, validator, _ = _validate_each([_get("/about"), _get("/accounting")],
                                                status="confirmed", confirmed=True)
        self.assertEqual(len(validator.calls), 2)

    def test_control_a_leg_that_is_not_shape_keyed_runs_per_route(self):
        _results, validator, _ = _validate_each([_get("/about"), _get("/accounting")],
                                                name="cross_identity")
        self.assertEqual(len(validator.calls), 2)

    def test_the_same_route_again_uses_its_own_key(self):
        results, validator, _ = _validate_each([_get("/about"), _get("/about")])
        self.assertEqual(len(validator.calls), 1)
        self.assertIn("same check, route template", results[1].summary)


if __name__ == "__main__":
    unittest.main()
