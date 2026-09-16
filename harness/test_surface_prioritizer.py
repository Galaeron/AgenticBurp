import unittest

from harness import surface_prioritizer
from harness.models import PrioritizeRequestItem
from harness.ollama_client import OllamaError


class FakeOllama:
    """Minimal stand-in for OllamaClient.chat_json -- returns a canned
    parsed dict (or raises OllamaError), no real network call."""
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls: list[tuple[str, str, str, float]] = []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls.append((model, system_prompt, user_prompt, temperature))
        if self.error is not None:
            raise self.error
        return self.response


def _item(method="GET", url="https://x.test/a", params=None):
    return PrioritizeRequestItem(method=method, url=url, param_names=params or [])


class PrioritizeTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_input_returns_empty_without_calling_ollama(self):
        ollama = FakeOllama()
        result = await surface_prioritizer.prioritize([], ollama, "m")
        self.assertEqual(result, [])
        self.assertEqual(ollama.calls, [])

    async def test_well_formed_response_maps_results_by_index_in_input_order(self):
        items = [_item(url="https://x.test/a"), _item(url="https://x.test/b")]
        ollama = FakeOllama(response={"results": [
            {"index": 1, "ai_priority": "high", "ai_score": 0.9, "reasoning": "mutating"},
            {"index": 0, "ai_priority": "low", "ai_score": 0.1, "reasoning": "static"},
        ]})
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].url, "https://x.test/a")
        self.assertEqual(results[0].ai_priority, "low")
        self.assertEqual(results[1].url, "https://x.test/b")
        self.assertEqual(results[1].ai_priority, "high")

    async def test_missing_index_leaves_that_row_unscored_not_crashed(self):
        items = [_item(url="https://x.test/a"), _item(url="https://x.test/b")]
        ollama = FakeOllama(response={"results": [
            {"index": 0, "ai_priority": "critical", "ai_score": 1.0, "reasoning": "id param"},
        ]})
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(results[0].ai_priority, "critical")
        self.assertEqual(results[1].ai_priority, "unscored")

    async def test_out_of_range_index_is_ignored(self):
        items = [_item()]
        ollama = FakeOllama(response={"results": [
            {"index": 5, "ai_priority": "critical", "ai_score": 1.0, "reasoning": "x"},
        ]})
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(results[0].ai_priority, "unscored")

    async def test_out_of_bounds_score_is_clamped_not_a_validation_crash(self):
        items = [_item()]
        ollama = FakeOllama(response={"results": [
            {"index": 0, "ai_priority": "high", "ai_score": 5.0, "reasoning": "x"},
        ]})
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(results[0].ai_score, 1.0)

    async def test_ollama_error_degrades_every_row_to_unscored(self):
        items = [_item(url="https://x.test/a"), _item(url="https://x.test/b")]
        ollama = FakeOllama(error=OllamaError("connection refused"))
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.ai_priority == "unscored" for r in results))

    async def test_malformed_results_field_does_not_crash(self):
        items = [_item()]
        ollama = FakeOllama(response={"results": "not a list"})
        results = await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(results[0].ai_priority, "unscored")

    async def test_single_call_for_whole_batch(self):
        """The whole point of this module: one LLM call per batch, not
        one per endpoint."""
        items = [_item(url=f"https://x.test/{i}") for i in range(10)]
        ollama = FakeOllama(response={"results": []})
        await surface_prioritizer.prioritize(items, ollama, "m")
        self.assertEqual(len(ollama.calls), 1)


if __name__ == "__main__":
    unittest.main()
