"""W-14: the coordinator's fail-open blast radius.

Default ("all") keeps the recall-safe fire-everything fallback. Opt-in
("curated") fires a high-value, shape-keyed subset instead, so a routing failure
does not dispatch all ~36 agents. The curated set always covers the "easiest to
miss" core and never comes out empty.
"""
import asyncio
import unittest

from coordinator import Coordinator, _curated_fallback
from models import HttpExchange
from ollama_client import OllamaResult

_AGENTS = ["sqli", "xss", "idor", "misconfig", "info_disclosure", "business_logic",
           "auth", "recon", "supply_chain", "ssrf", "xxe", "jwt", "csrf", "crypto"]


class _StubOllama:
    def __init__(self, dispatch=None, raise_exc=False):
        self._dispatch = dispatch or []
        self._raise = raise_exc

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        if self._raise:
            raise RuntimeError("boom")
        return OllamaResult(data={"dispatch": self._dispatch, "reason": "r"},
                            prompt_tokens=1, completion_tokens=1)


def _ex():
    return HttpExchange(url="https://t.test/api/orders/1?id=1", method="GET", response_body="")


class FailOpenModeTests(unittest.TestCase):
    def test_default_mode_all_fires_everything(self):
        c = Coordinator(_StubOllama(dispatch=[]), {"model": "m"})
        agents, reason = asyncio.run(c.choose_agents(_ex(), list(_AGENTS)))
        self.assertEqual(set(agents), set(_AGENTS))
        self.assertIn("fallback", reason)

    def test_curated_mode_fires_a_subset(self):
        c = Coordinator(_StubOllama(dispatch=[]), {"model": "m", "fail_open_mode": "curated"})
        agents, reason = asyncio.run(c.choose_agents(_ex(), list(_AGENTS)))
        self.assertLess(len(agents), len(_AGENTS), "curated fallback must be smaller than all")
        self.assertTrue(set(agents).issubset(set(_AGENTS)))
        for core in ("idor", "misconfig", "business_logic"):
            self.assertIn(core, agents, f"curated fallback dropped high-value core {core!r}")

    def test_curated_mode_on_coordinator_error(self):
        c = Coordinator(_StubOllama(raise_exc=True), {"model": "m", "fail_open_mode": "curated"})
        agents, reason = asyncio.run(c.choose_agents(_ex(), list(_AGENTS)))
        self.assertLess(len(agents), len(_AGENTS))
        self.assertIn("fallback", reason)

    def test_curated_never_returns_empty(self):
        # No core class and no shape match available -> degrade to all-available,
        # never an empty dispatch (which would be worse than the old behavior).
        self.assertEqual(_curated_fallback(_ex(), ["some_unknown_agent"]),
                         ["some_unknown_agent"])


if __name__ == "__main__":
    unittest.main()
