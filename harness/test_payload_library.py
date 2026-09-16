import unittest
from harness.payload_library import next_candidate, library_exhausted, llm_fallback_prompt, _LIBRARY


class NextCandidateTests(unittest.TestCase):
    def test_prefers_matching_context_over_agnostic(self):
        p = next_candidate("xss", tried=[], context_tags=("js_string",))
        self.assertIn("js_string", p.context_tags)

    def test_skips_already_tried(self):
        first = next_candidate("xss", tried=[])
        second = next_candidate("xss", tried=[first.value])
        self.assertNotEqual(first.value, second.value)

    def test_exhaustion_returns_none(self):
        all_values = [p.value for p in _LIBRARY["business_logic"]]
        self.assertIsNone(next_candidate("business_logic", tried=all_values))
        self.assertTrue(library_exhausted("business_logic", all_values))

    def test_unknown_category_returns_none_not_error(self):
        self.assertIsNone(next_candidate("nonexistent_category", tried=[]))

    def test_mismatched_context_still_reachable_as_last_resort(self):
        # every ssrf payload tried except a mismatched-context one --
        # should still be returned rather than None, since context
        # detection can be wrong and a last-resort option beats nothing.
        mismatched = [p for p in _LIBRARY["ssrf"] if "localhost_blocklist_suspected" in p.context_tags][0]
        tried = [p.value for p in _LIBRARY["ssrf"] if p.value != mismatched.value]
        result = next_candidate("ssrf", tried=tried, context_tags=("url_param",))
        self.assertEqual(result.value, mismatched.value)

    def test_no_duplicate_payload_values_within_a_category(self):
        for category, payloads in _LIBRARY.items():
            values = [p.value for p in payloads]
            self.assertEqual(len(values), len(set(values)), f"duplicate payload value in {category}")


class LlmFallbackPromptTests(unittest.TestCase):
    def test_includes_tried_and_failure_notes(self):
        prompt = llm_fallback_prompt(
            "xss", tried=["<script>x</script>"], exchange_summary="GET /search?q=x",
            failure_notes=["canary was HTML-entity-encoded in the response"],
        )
        self.assertIn("<script>x</script>", prompt)
        self.assertIn("HTML-entity-encoded", prompt)
        self.assertIn("untrusted data", prompt)  # prompt-injection guard, matching project convention

    def test_handles_empty_history_without_error(self):
        prompt = llm_fallback_prompt("xss", tried=[], exchange_summary="", failure_notes=[])
        self.assertIn("(none)", prompt)


if __name__ == "__main__":
    unittest.main()
