import json
import unittest
import httpx

from harness.ollama_client import (
    OllamaClient,
    OllamaError,
    OllamaModelNotFoundError,
    OllamaInvalidJSONError,
    _repair_json_escapes,
    _loads_lenient,
)


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _make_client(testcase: unittest.TestCase, handler) -> OllamaClient:
    client = OllamaClient(base_url="http://fake-ollama:11434")

    class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    import harness.ollama_client as mod
    mod.httpx.AsyncClient = PatchedAsyncClient
    # httpx is a shared module object, so this assignment affects every transport
    # user in the process.  Restore it after EACH test; module cleanup registered
    # during discovery can run under the wrong module boundary.
    testcase.addCleanup(setattr, mod.httpx, "AsyncClient", _REAL_ASYNC_CLIENT)
    return client


class ChatJsonMeteredTests(unittest.IsolatedAsyncioTestCase):
    async def test_extracts_real_prompt_eval_count_and_eval_count(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"findings": []})},
                "done": True,
                "prompt_eval_count": 742,
                "eval_count": 88,
            })
        client = _make_client(self, handler)
        result = await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result.data, {"findings": []})
        self.assertEqual(result.prompt_tokens, 742)
        self.assertEqual(result.completion_tokens, 88)

    async def test_missing_usage_fields_falls_back_to_zero_not_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"ok": True})},
                "done": True,
                # no prompt_eval_count / eval_count -- older server or stripping proxy
            })
        client = _make_client(self, handler)
        result = await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result.prompt_tokens, 0)
        self.assertEqual(result.completion_tokens, 0)
        self.assertEqual(result.data, {"ok": True})

    async def test_chat_json_unmetered_still_returns_plain_dict(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"dispatch": ["sqli"]})},
                "done": True,
                "prompt_eval_count": 500,
                "eval_count": 40,
            })
        client = _make_client(self, handler)
        result = await client.chat_json(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result, {"dispatch": ["sqli"]})
        self.assertNotIsInstance(result, tuple)

    async def test_invalid_json_content_raises_ollama_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": "not json"}, "done": True})
        client = _make_client(self, handler)
        with self.assertRaises(OllamaError):
            await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")

    async def test_non_200_status_raises_ollama_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")
        client = _make_client(self, handler)
        with self.assertRaises(OllamaError):
            await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")


class ThinkingModeDisabledTests(unittest.IsolatedAsyncioTestCase):
    """
    Live bug found this session: a "thinking"-capable model (Qwen3, Gemma 4)
    defaults to thinking ON when the request never sets a `think` option,
    generating a full hidden chain-of-thought before any content -- confirmed
    directly against a real Ollama instance: the identical trivial prompt
    against qwen3:8b went from >130s (timed out) to 6s the moment `think:
    false` was added. This had been misdiagnosed as a circuit-breaker/model-
    config problem before the real cause was found. Every call site in this
    harness wants fast, structured JSON classification output, never a
    reasoning trace, so this must always be sent, not made conditional on
    which model is configured.
    """

    async def test_think_false_is_always_sent(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"ok": True})},
                "done": True,
            })
        client = _make_client(self, handler)
        await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertIn("think", captured["body"])
        self.assertFalse(captured["body"]["think"])


class NumCtxOptInTests(unittest.IsolatedAsyncioTestCase):
    """options.num_ctx is opt-in: sent ONLY when the client was built with a
    num_ctx, omitted (byte-for-byte the prior payload) otherwise. Motivated by
    a VRAM finding on this hardware -- qwen3:8b at its 32768 default context
    loads at 10GB and spills 41% onto CPU (~19s/call), while the same model
    pinned to a context that still covers the harness's <4k-token prompts stays
    fully GPU-resident (6.2GB, 100% GPU, ~3s/call). The pin must never change
    behavior for a caller that leaves it unset."""

    def _capture_client(self, num_ctx):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"ok": True})},
                "done": True,
            })
        client = OllamaClient(base_url="http://fake-ollama:11434", num_ctx=num_ctx)

        class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        import harness.ollama_client as mod
        mod.httpx.AsyncClient = PatchedAsyncClient
        self.addCleanup(setattr, mod.httpx, "AsyncClient", _REAL_ASYNC_CLIENT)
        return client, captured

    async def test_num_ctx_sent_when_set(self):
        client, captured = self._capture_client(8192)
        await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(captured["body"]["options"].get("num_ctx"), 8192)
        # temperature still present alongside it
        self.assertIn("temperature", captured["body"]["options"])

    async def test_num_ctx_absent_when_unset(self):
        # NEGATIVE CONTROL: default client (no num_ctx) must not emit the key at
        # all -- the options block is exactly {temperature: ...} as before.
        client, captured = self._capture_client(None)
        await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertNotIn("num_ctx", captured["body"]["options"])
        self.assertEqual(list(captured["body"]["options"].keys()), ["temperature"])

    async def test_zero_or_falsy_num_ctx_is_treated_as_unset(self):
        # 0 is not a meaningful context window; guard against it silently
        # being sent (Ollama would reject/ignore it) -- falsy => omitted.
        client, captured = self._capture_client(0)
        await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertNotIn("num_ctx", captured["body"]["options"])


class ModelNotFoundDoesNotTripSharedBreakerTests(unittest.IsolatedAsyncioTestCase):
    """
    Regression test for a live bug found this session: a nonexistent model
    tag (verified directly against a real Ollama instance: HTTP 404,
    {"error": "model '<name>' not found"}) was raising the same plain
    OllamaError as a genuine outage/timeout -- both counted toward the same
    process-wide, shared "ollama" circuit breaker's failure threshold (3).
    Three calls to one misconfigured agent's/coordinator's bad model tag
    therefore tripped the SAME breaker every other agent's OllamaClient
    uses, rejecting every subsequent call for 60s regardless of model --
    reproduced live: `auth`/`business_logic` (a correctly-configured
    llama3.1:8b) failed with "Circuit breaker 'ollama' is OPEN" during a
    real session. A permanent, config-level "this tag doesn't exist" error
    must never be treated as evidence the whole service is unhealthy.
    """

    def setUp(self):
        import harness.circuit_breaker as cb_module
        self._original_registry = cb_module._registry
        cb_module._registry = None

    def tearDown(self):
        import harness.circuit_breaker as cb_module
        cb_module._registry = self._original_registry

    async def test_404_raises_model_not_found_subclass(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "model 'bad-tag:latest' not found"})
        client = _make_client(self, handler)
        with self.assertRaises(OllamaModelNotFoundError):
            await client.chat_json_metered(model="bad-tag:latest", system_prompt="s", user_prompt="u")

    async def test_three_consecutive_404s_do_not_open_the_breaker(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "model 'bad-tag:latest' not found"})
        client = _make_client(self, handler)
        for _ in range(3):
            with self.assertRaises(OllamaModelNotFoundError):
                await client.chat_json_metered(model="bad-tag:latest", system_prompt="s", user_prompt="u")
        self.assertTrue(client.circuit_breaker.is_closed,
                         "3 model-not-found errors must not trip the breaker")

    async def test_bad_model_404s_do_not_block_a_different_working_model(self):
        """The actual regression: a broken coordinator/agent model must not
        collaterally block an unrelated, correctly-configured agent that
        shares the same breaker."""
        def not_found_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "model 'bad-tag:latest' not found"})
        bad_client = _make_client(self, not_found_handler)
        for _ in range(5):  # well past the failure_threshold of 3
            with self.assertRaises(OllamaModelNotFoundError):
                await bad_client.chat_json_metered(model="bad-tag:latest", system_prompt="s", user_prompt="u")

        def working_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"ok": True})},
                "done": True, "prompt_eval_count": 10, "eval_count": 5,
            })
        good_client = _make_client(self, working_handler)
        self.assertIs(good_client.circuit_breaker, bad_client.circuit_breaker,
                       "test assumption: both clients must share the same breaker")
        result = await good_client.chat_json_metered(model="working-model", system_prompt="s", user_prompt="u")
        self.assertEqual(result.data, {"ok": True})


class StrayBackslashJsonRepairTests(unittest.TestCase):
    r"""Root cause found live this session against gemma4:31b-cloud: a CLOUD
    model reached through Ollama ignores `format: json` (no output grammar for
    cloud-hosted models -- verified: every response markdown-fenced and
    free-generated) and intermittently emits a RAW single backslash inside a
    JSON string (a regex `\s`/`\(` it forgot to double). That is illegal JSON
    and was silently dropping ~15-20% of that model's agent findings, whole SQLi
    detections among them. The repair doubles only invalid-escape backslashes,
    leaving genuine escapes intact, and runs ONLY as a post-failure fallback."""

    def test_stray_backslash_is_doubled(self):
        bad = r'{"regex":"id=[^&]*\s*(AND|SLEEP\()"}'
        with self.assertRaises(json.JSONDecodeError):
            json.loads(bad)
        obj = _loads_lenient(bad)
        # The regex round-trips byte-for-byte -- \s and \( are preserved.
        self.assertEqual(obj["regex"], r"id=[^&]*\s*(AND|SLEEP\()")

    def test_valid_escapes_are_preserved(self):
        good = r'{"a":"line\nbreak","b":"quote\"q","c":"back\\slash","d":"uA"}'
        obj = _loads_lenient(good)
        self.assertEqual(obj["a"], "line\nbreak")
        self.assertEqual(obj["b"], 'quote"q')
        self.assertEqual(obj["c"], "back\\slash")
        self.assertEqual(obj["d"], "uA")

    def test_repair_is_idempotent_on_valid_json(self):
        good = r'{"c":"back\\slash","n":"x\ny"}'
        self.assertEqual(_repair_json_escapes(good), good)

    def test_repair_does_not_fabricate_on_structurally_broken_json(self):
        # Unbalanced braces are not an escaping problem; repair must not rescue it.
        broken = r'{"regex":"\s","missing":'
        with self.assertRaises(json.JSONDecodeError):
            _loads_lenient(broken)


class InvalidEscapeEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def test_fenced_content_with_stray_backslash_parses(self):
        # Exactly what gemma4:31b-cloud returned: markdown-fenced JSON whose
        # regex value carries an unescaped backslash. Must survive the pipeline.
        content = (
            "```json\n"
            r'{"findings":[{"vulnerability_class":"sql_injection","confidence":0.9,'
            r'"suggested_test":"detect with regex id=[^&]*\s*(UNION|SLEEP\()"}]}'
            "\n```"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": content},
                "done": True, "prompt_eval_count": 100, "eval_count": 20,
            })
        client = _make_client(self, handler)
        result = await client.chat_json(model="gemma4:31b-cloud", system_prompt="s", user_prompt="u")
        self.assertEqual(result["findings"][0]["vulnerability_class"], "sql_injection")
        self.assertIn(r"\s", result["findings"][0]["suggested_test"])

    async def test_truly_broken_json_still_raises_invalid_json(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": "this is not json at all"},
                "done": True,
            })
        client = _make_client(self, handler)
        with self.assertRaises(OllamaInvalidJSONError):
            await client.chat_json(model="m", system_prompt="s", user_prompt="u")


if __name__ == "__main__":
    unittest.main()
