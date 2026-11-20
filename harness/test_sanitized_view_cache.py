"""TOK-6: one sanitised view per exchange, shared by every agent routed it.

Caller-level: the agents' real prompt paths (`_user_prompt`, `fit_agent_prompts`) and the
coordinator's `choose_agents` run against one exchange while `security.sanitize_text` is
wrapped to count how often the exchange's own body is sanitised. The negative control is
the old path, reproduced by disabling the view cache (`cached_exchange_view` -> `build()`).
"""
import asyncio
import json
import re
import unittest
from unittest import mock

from harness import security
from harness.agents.base_agent import BaseAgent
from harness.coordinator import Coordinator
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.prompt_budget import PromptBudget, fit_agent_prompts

_BODY = json.dumps({"items": [{"id": i, "name": f"item-{i}"} for i in range(40)],
                    "password": "CANARY-PASSWORD-p9q8", "note": "plain text"})
_REQ_BODY = json.dumps({"username": "alice", "api_key": "CANARY-APIKEY-k1l2"})
_ROUTED = (1, 4, 8)


class _Agent(BaseAgent):
    name = "dummy"

    @property
    def specialty_prompt(self):
        return "dummy specialty"


def _exchange(body=_BODY, req_body=_REQ_BODY, note="note") -> HttpExchange:
    return HttpExchange(url="https://a.test/items?token=CANARY-URL-t5", method="POST",
                        request_headers={"Authorization": "Bearer CANARY-HEADER-h3"},
                        request_body=req_body, response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body=body, analyst_note=note)


class _CountSanitizer:
    """Wraps security.sanitize_text; records each call whose text is a given body."""

    def __init__(self, *bodies):
        self.bodies = set(bodies)
        self.hits = 0
        self._real = security.sanitize_text

    def __call__(self, text, **kwargs):
        if text in self.bodies:
            self.hits += 1
        return self._real(text, **kwargs)


def _cache_off(namespace, exchange, build):  # the old path: every caller sanitises afresh
    return build()


class SharedViewTest(unittest.TestCase):
    def setUp(self):
        security.clear_exchange_views()

    def _body_sanitisations(self, n_agents: int, *, cache: bool, via) -> int:
        security.clear_exchange_views()
        exchange = _exchange()
        counter = _CountSanitizer(exchange.response_body)
        agents = [_Agent(ollama=None, model="m") for _ in range(n_agents)]
        with mock.patch.object(security, "sanitize_text", counter):
            if not cache:
                with mock.patch.object(security, "cached_exchange_view", _cache_off):
                    via(agents, exchange)
            else:
                via(agents, exchange)
        return counter.hits

    @staticmethod
    def _user_prompts(agents, exchange):
        return [a._user_prompt(exchange, 6000) for a in agents]

    @staticmethod
    def _fitted_prompts(agents, exchange):
        budget = PromptBudget(context_tokens=2000, answer_tokens=200, source="test")
        return [fit_agent_prompts(a, exchange, 6000, "", budget) for a in agents]

    def test_response_body_is_sanitised_once_however_many_agents_are_routed(self):
        for path in (self._user_prompts, self._fitted_prompts):
            counts = {n: self._body_sanitisations(n, cache=True, via=path) for n in _ROUTED}
            self.assertEqual(set(counts.values()), {1}, f"{path.__name__}: {counts}")

    def test_old_path_sanitises_once_per_agent(self):
        """Negative control: with the cache forced off the count is N, so the
        constant-in-N assertion above is what the shared view buys."""
        for path in (self._user_prompts, self._fitted_prompts):
            counts = {n: self._body_sanitisations(n, cache=False, via=path) for n in _ROUTED}
            self.assertEqual(counts, {n: n for n in _ROUTED}, f"{path.__name__}: {counts}")

    def test_coordinator_and_agents_share_one_sanitisation(self):
        class _Stub:
            async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1,
                                        seed=None):
                return OllamaResult(data={"dispatch": ["sqli"], "reason": "r"}, prompt_tokens=1,
                                    completion_tokens=1)

        exchange = _exchange()
        counter = _CountSanitizer(exchange.response_body)
        with mock.patch.object(security, "sanitize_text", counter):
            asyncio.run(Coordinator(_Stub(), {"model": "m"}).choose_agents(exchange, ["sqli", "xss"]))
            for agent in [_Agent(ollama=None, model="m") for _ in range(5)]:
                agent._user_prompt(exchange, 6000)
        self.assertEqual(counter.hits, 1)

    def test_every_routed_agent_still_gets_a_fully_redacted_prompt(self):
        prompts = self._user_prompts([_Agent(ollama=None, model="m") for _ in range(4)], _exchange())
        for prompt in prompts:
            for canary in ("CANARY-PASSWORD", "CANARY-APIKEY", "CANARY-URL", "CANARY-HEADER"):
                self.assertNotIn(canary, prompt)
            self.assertIn("item-39", prompt)           # the non-secret content is untouched
        # the agents' prompts differ only by their fence nonce
        self.assertEqual(len({re.sub(r"UNTRUSTED-DATA-[0-9a-f]+", "N", p) for p in prompts}), 1)

    def test_cached_view_equals_a_fresh_one(self):
        exchange = _exchange()
        agent = _Agent(ollama=None, model="m")
        security.clear_exchange_views()
        cached = agent._prompt_view(exchange)
        again = agent._prompt_view(exchange)
        with mock.patch.object(security, "cached_exchange_view", _cache_off):
            fresh = agent._prompt_view(exchange)
        self.assertEqual(cached, again)
        self.assertEqual(cached, fresh)

    def test_view_is_keyed_by_content_not_identity(self):
        exchange = _exchange()
        agent = _Agent(ollama=None, model="m")
        counter = _CountSanitizer(exchange.response_body)
        with mock.patch.object(security, "sanitize_text", counter):
            agent._prompt_view(exchange)
            agent._prompt_view(exchange.model_copy())            # another object, same content
            agent._prompt_view(HttpExchange(**exchange.model_dump()))
        self.assertEqual(counter.hits, 1)

        # an exchange edited in place after its view was built gets a new view
        exchange.response_body = json.dumps({"changed": "yes", "password": "CANARY-NEW-x"})
        view = agent._prompt_view(exchange)
        self.assertIn("changed", view.response_body)
        self.assertNotIn("CANARY-NEW", view.response_body)

    def test_a_changed_redaction_policy_is_not_served_a_stale_view(self):
        exchange = _exchange(body=json.dumps({"widget": "W-VALUE-1"}))
        agent = _Agent(ollama=None, model="m")
        self.assertIn("W-VALUE-1", agent._prompt_view(exchange).response_body)
        with mock.patch.object(security, "SECRET_FIELD_NAMES", set(security.SECRET_FIELD_NAMES) | {"widget"}):
            self.assertNotIn("W-VALUE-1", agent._prompt_view(exchange).response_body)
        self.assertIn("W-VALUE-1", agent._prompt_view(exchange).response_body)

    def test_each_caller_gets_its_own_copy_of_the_exchange(self):
        exchange = _exchange()
        first = security.sanitized_exchange(exchange)
        first.request_headers["X-Mutated"] = "1"
        first.response_body = "mutated"
        second = security.sanitized_exchange(exchange)
        self.assertNotIn("X-Mutated", second.request_headers)
        self.assertNotEqual(second.response_body, "mutated")

    def test_cache_is_bounded(self):
        for i in range(security._VIEW_CACHE_SIZE + 10):
            security.sanitized_exchange(_exchange(body=f"body {i}"))
        self.assertLessEqual(len(security._view_cache), security._VIEW_CACHE_SIZE)


class CoordinatorSanitisesBeforeTruncatingTest(unittest.TestCase):
    """A secret-named JSON object cut at 1000 characters no longer parses as JSON, so
    the by-name redaction misses its tail; sanitising the whole body first does not."""

    BODY = '{"token": {"payload": "' + "LEAKTAIL" * 400 + '"}}'

    def _prompt(self) -> str:
        prompts = []

        class _Stub:
            async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1,
                                        seed=None):
                prompts.append(user_prompt)
                return OllamaResult(data={"dispatch": ["sqli"], "reason": "r"}, prompt_tokens=1,
                                    completion_tokens=1)

        exchange = HttpExchange(url="http://a.test/x", method="GET", response_status=200,
                                response_body=self.BODY)
        asyncio.run(Coordinator(_Stub(), {"model": "m"}).choose_agents(exchange, ["sqli"]))
        return prompts[0]

    def test_nested_secret_object_is_withheld_from_the_routing_prompt(self):
        prompt = self._prompt()
        self.assertNotIn("LEAKTAIL", prompt)
        self.assertIn("[REDACTED-SECRET]", prompt)

    def test_truncating_first_would_leak_it(self):
        """Negative control: with the sanitised view forced off (the raw exchange is
        cut to 1000 characters), the same body reaches the prompt."""
        with mock.patch.object(security, "sanitized_exchange", lambda exchange: exchange):
            self.assertIn("LEAKTAIL", self._prompt())


class SanitizerDecodesInPlaceTest(unittest.TestCase):
    def test_raw_decode_never_copies_the_remainder_of_the_text(self):
        """The old loop sliced result[brace:] for every `{` -- a copy of the rest of the
        body per brace. raw_decode must always be handed the whole text and an index."""
        body = "a{b}" * 300 + '{"password": "CANARY-P"}'
        seen = []
        real = json.JSONDecoder.raw_decode

        def spy(self, s, idx=0):
            seen.append((len(s), idx))
            return real(self, s, idx)

        with mock.patch.object(json.JSONDecoder, "raw_decode", spy):
            out = security.sanitize_text(body)
        self.assertEqual(len({length for length, _ in seen}), 1, "a slice was decoded")
        self.assertGreater(len(seen), 300)
        self.assertNotIn("CANARY-P", out)
        self.assertEqual(out.count("a{b}"), 300)


if __name__ == "__main__":
    unittest.main()
