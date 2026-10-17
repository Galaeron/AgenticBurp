"""LB-NOTE-A negative control.

`_ssti_readback_urls` (harness/orchestrator_chain.py) builds the SSTI readback
candidate list from `_all_captured`, which is a UNION of two shapes by design:
`HttpExchange` objects (feature_workflow's captures) and the dict form
role_crawl's discovery captures use (`HttpExchange(...).model_dump()`, required
by test_role_crawl.py's dict-indexed assertions on RoleCrawlResult.captured).
Before this fix, a dict element crashed the loop with
`AttributeError: 'dict' object has no attribute 'method'` (harness/
orchestrator_chain.py:663, as hit by harness/test_pipeline_gate.py's real
pipeline runs, which exercise role_crawl's dict-shaped captures).

This proves the consumer-side guard (a) no longer crashes on a dict-shaped
capture, (b) still returns the right answer for both shapes, and critically
(c) still EXCLUDES a legitimate non-GET captured exchange from readbacks --
the guard must not swallow or alter real non-GET handling, only stop the
crash.
"""
from __future__ import annotations

import unittest

from harness.models import HttpExchange
from harness.orchestrator_chain import _ssti_readback_urls


def _dict_capture(**overrides) -> dict:
    base = dict(
        url="http://127.0.0.1:8000/api/notes",
        method="GET",
        request_headers={}, request_body="",
        response_status=200, response_headers={},
        response_body="{}", analyst_note="", capture_id="",
    )
    base.update(overrides)
    return base


def _exchange_capture(**overrides) -> HttpExchange:
    return HttpExchange(**_dict_capture(**overrides))


class SstiReadbackUrlsTest(unittest.TestCase):
    def test_dict_shaped_get_capture_no_longer_crashes_and_is_included(self):
        """The exact crash reproduction: role_crawl's dict-shaped capture
        (HttpExchange(...).model_dump()) used to raise AttributeError here."""
        captured = [_dict_capture(url="http://127.0.0.1:8000/api/notes")]
        self.assertEqual(
            _ssti_readback_urls(captured), ["http://127.0.0.1:8000/api/notes"])

    def test_object_shaped_get_capture_is_included(self):
        captured = [_exchange_capture(url="http://127.0.0.1:8000/api/notes")]
        self.assertEqual(
            _ssti_readback_urls(captured), ["http://127.0.0.1:8000/api/notes"])

    def test_negative_control_dict_shaped_non_get_is_excluded(self):
        """A legitimate NON-GET captured exchange, in the dict shape, must STILL
        be excluded -- the guard must not swallow/alter real non-GET handling."""
        captured = [_dict_capture(url="http://127.0.0.1:8000/api/notes", method="POST")]
        self.assertEqual(_ssti_readback_urls(captured), [])

    def test_negative_control_object_shaped_non_get_is_excluded(self):
        """Same negative control, object shape -- prior readback semantics for
        real exchanges are unchanged by the dict-tolerant guard."""
        captured = [_exchange_capture(url="http://127.0.0.1:8000/api/notes", method="POST")]
        self.assertEqual(_ssti_readback_urls(captured), [])

    def test_mixed_shapes_preserve_per_item_get_post_filtering(self):
        """A realistic _all_captured union: dict (role_crawl) + object
        (feature_workflow) items, GET and POST interleaved. Only the GET urls
        survive, regardless of which shape carried them."""
        captured = [
            _dict_capture(url="http://127.0.0.1:8000/api/profile", method="GET"),
            _exchange_capture(url="http://127.0.0.1:8000/api/notes", method="POST"),
            _dict_capture(url="http://127.0.0.1:8000/api/orders", method="DELETE"),
            _exchange_capture(url="http://127.0.0.1:8000/api/search", method="GET"),
        ]
        self.assertEqual(
            sorted(_ssti_readback_urls(captured)),
            sorted(["http://127.0.0.1:8000/api/profile",
                    "http://127.0.0.1:8000/api/search"]))

    def test_destructive_path_excluded_for_both_shapes(self):
        captured = [
            _dict_capture(url="http://127.0.0.1:8000/account/logout", method="GET"),
            _exchange_capture(url="http://127.0.0.1:8000/account/delete", method="GET"),
        ]
        self.assertEqual(_ssti_readback_urls(captured), [])

    def test_non_2xx_status_excluded_for_both_shapes(self):
        captured = [
            _dict_capture(url="http://127.0.0.1:8000/api/notes", response_status=403),
            _exchange_capture(url="http://127.0.0.1:8000/api/other", response_status=500),
        ]
        self.assertEqual(_ssti_readback_urls(captured), [])

    def test_malformed_dict_item_is_skipped_not_fatal(self):
        """A dict missing required HttpExchange fields must not crash the whole
        readback build -- it is just not a candidate."""
        captured = [
            {"not_an_exchange_field": True},
            _dict_capture(url="http://127.0.0.1:8000/api/notes"),
        ]
        self.assertEqual(
            _ssti_readback_urls(captured), ["http://127.0.0.1:8000/api/notes"])


if __name__ == "__main__":
    unittest.main()
