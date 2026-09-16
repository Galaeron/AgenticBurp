"""Tests for the LLM priority feed to the F5 allocator (mocked model)."""
import asyncio
import unittest
from unittest.mock import AsyncMock

import harness.allocation_prioritizer as ap
from harness.ollama_client import OllamaError
from harness.resource_governor import AllocationCandidate


def _c(id, vc="idor", sev="high", conf=0.5, url="https://t.test/api/users/42"):
    return AllocationCandidate(id=id, vulnerability_class=vc, url=url, severity=sev, confidence=conf)


class RedactTests(unittest.TestCase):
    def test_strips_host_and_numeric_ids(self):
        self.assertEqual(ap._redact_path("https://t.test/api/users/42/orders/7"),
                         "/api/users/{id}/orders/{id}")

    def test_strips_query_and_hex(self):
        p = ap._redact_path("https://t.test/reset/a1b2c3d4e5f6a7b8?token=secret")
        self.assertEqual(p, "/reset/{id}")
        self.assertNotIn("secret", p)

    def test_root_path(self):
        self.assertEqual(ap._redact_path("https://t.test"), "/")


class RankTests(unittest.TestCase):
    def _rank(self, cands, parsed=None, raise_exc=None):
        ollama = AsyncMock()
        if raise_exc is not None:
            ollama.chat_json.side_effect = raise_exc
        else:
            ollama.chat_json.return_value = parsed
        return asyncio.run(ap.rank(cands, ollama, "gemma4:31b-cloud"))

    def test_scores_mapped_by_index(self):
        cands = [_c("a"), _c("b")]
        parsed = {"results": [{"index": 0, "priority": 0.9}, {"index": 1, "priority": 0.2}]}
        out = self._rank(cands, parsed)
        self.assertEqual(out, {"a": 0.9, "b": 0.2})

    def test_omitted_candidate_absent(self):
        cands = [_c("a"), _c("b")]
        parsed = {"results": [{"index": 0, "priority": 0.8}]}
        out = self._rank(cands, parsed)
        self.assertEqual(out, {"a": 0.8})  # b keeps static priority (absent here)

    def test_out_of_range_index_ignored(self):
        cands = [_c("a")]
        parsed = {"results": [{"index": 5, "priority": 0.8}, {"index": 0, "priority": 0.3}]}
        self.assertEqual(self._rank(cands, parsed), {"a": 0.3})

    def test_scores_clamped(self):
        cands = [_c("a"), _c("b")]
        parsed = {"results": [{"index": 0, "priority": 5.0}, {"index": 1, "priority": -2.0}]}
        self.assertEqual(self._rank(cands, parsed), {"a": 1.0, "b": 0.0})

    def test_call_failure_returns_empty_map(self):
        cands = [_c("a")]
        self.assertEqual(self._rank(cands, raise_exc=OllamaError("down")), {})

    def test_garbage_output_returns_empty_map(self):
        cands = [_c("a")]
        self.assertEqual(self._rank(cands, parsed=["not", "a", "dict"]), {})

    def test_empty_candidates_no_call(self):
        ollama = AsyncMock()
        out = asyncio.run(ap.rank([], ollama, "m"))
        self.assertEqual(out, {})
        ollama.chat_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
