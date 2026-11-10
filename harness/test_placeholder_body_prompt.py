"""r7: three SQLi/NoSQLi findings on JSON-body writes named 'name' and 'value' as
the vulnerable body parameters. Neither is a field of those endpoints: they are the
keys of the body role_crawl guesses when it has no schema and no form
({"name": "probe", "value": "probe"}). That capture reached the specialist agents
looking like the endpoint's real request, so the model read its keys as inputs.

The caller tests drive the real crawl_roles capture into a real specialist agent's
run() (only the model call is faked, and it records the prompt it was sent). The
controls are a capture whose body came from an observed form, which still shows
its body, and the parameter binding falling back to the real request parameters
when a finding names one the request lacks.
"""
import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from harness import global_throttle, role_crawl
from harness.agents.sqli_agent import SqliAgent
from harness.iterative_agent import IterativeAgent
from harness.models import Finding, HttpExchange, request_body_is_placeholder
from harness.role_crawl import RoleSession
from harness.validators.injection_targets import (
    NAMED_PARAMETER_UNTESTED, param_targets, select_targets)


def _crawl(cr):
    async def fake_crawl(base_url, **kwargs):
        return cr

    async def fake_probe(method, url, headers, timeout, **kwargs):
        return 201, '{"status": "success", "data": {"id": 7}}', {"content-type": "application/json"}

    async def scenario():
        with patch("harness.crawler.crawl", fake_crawl), \
             patch("harness.role_crawl._probe", fake_probe):
            return await role_crawl.crawl_roles(
                "http://shop.test/", [RoleSession("anonymous", {})], allowed_hosts=["shop.test"])
    return asyncio.run(scenario())


def _prompt_seen_by_agent(exchange: HttpExchange) -> str:
    agent = SqliAgent(ollama=None, model="m")
    agent.ollama = AsyncMock()
    agent.ollama.chat_json = AsyncMock(return_value={"findings": []})
    asyncio.run(agent.run(exchange, max_body_chars=4000))
    sent = agent.ollama.chat_json.await_args
    return json.dumps([sent.args, sent.kwargs], default=str)


class PlaceholderBodyPromptTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def test_guessed_body_is_withheld_from_the_agent_prompt(self):
        from harness.crawler import CrawlResult
        from harness.js_endpoint_extractor import CallShape
        cr = CrawlResult(base_url="http://shop.test/")
        cr.call_shapes.append(CallShape("POST", "/api/widgets"))
        result = _crawl(cr)
        self.assertEqual(len(result.captured), 1)
        exchange = HttpExchange(**result.captured[0])
        self.assertEqual(json.loads(exchange.request_body), {"name": "probe", "value": "probe"})
        self.assertTrue(request_body_is_placeholder(exchange))
        prompt = _prompt_seen_by_agent(exchange)
        self.assertNotIn('\\"value\\": \\"probe\\"', prompt)
        self.assertIn("guessed placeholder body", prompt)
        self.assertIn("NOT parameters of this endpoint", prompt)

    def test_control_observed_form_body_still_reaches_the_prompt(self):
        from harness.crawler import CrawlResult
        from harness.feature_workflow import FormAction, FormField
        cr = CrawlResult(base_url="http://shop.test/")
        cr.forms.append(FormAction(method="POST", action="http://shop.test/product/stock",
                                   fields=[FormField("productId", "hidden", "1"),
                                           FormField("storeId", "hidden", "1")]))
        result = _crawl(cr)
        exchange = HttpExchange(**result.captured[0])
        self.assertFalse(request_body_is_placeholder(exchange))
        prompt = _prompt_seen_by_agent(exchange)
        self.assertIn("productId=1&storeId=1", prompt)
        self.assertNotIn("guessed placeholder body", prompt)

    def test_iterative_agent_is_told_the_body_is_a_guess(self):
        from harness.models import PLACEHOLDER_BODY_NOTE
        seen = []

        async def next_action(system, user, effort_budget, diag):
            seen.append(user)
            return {"action": "stop", "verdict": "not_found", "thought": "t"}

        def run(note, body='{"name": "probe", "value": "probe"}'):
            agent = IterativeAgent(ollama=AsyncMock(), model="m", allowed_hosts=["shop.test"])
            agent._next_action = next_action
            ex = HttpExchange(url="http://shop.test/api/widgets", method="POST",
                              request_headers={"Content-Type": "application/json"},
                              request_body=body, response_status=201, analyst_note=note)
            seen.clear()
            asyncio.run(agent.run(ex, "sqli in body", "sqli", step_budget=1))
            self.assertTrue(seen)
            return " ".join(seen)
        self.assertIn("placeholder the harness guessed", run("capture; " + PLACEHOLDER_BODY_NOTE))
        # A worklist template carries no note: the guessed body itself is recognised.
        self.assertIn("placeholder the harness guessed", run(""))
        self.assertNotIn("placeholder the harness guessed",
                         run("capture", body='{"title": "a", "qty": 2}'))

    def test_worklist_write_node_on_a_guessed_body_is_not_told_its_keys_are_inputs(self):
        from harness import worklist_investigator as wi
        def node(body):
            return {"method": "POST", "path": "/api/widgets", "reachable_roles": ["user"],
                    "template": {"body": body, "content_type": "application/json"}}
        guessed = node('{"name": "probe", "value": "probe"}')
        (_, hypothesis), = wi._derive_probe(guessed)
        self.assertIn("fields are unknown", hypothesis)
        seeded = wi._seed_exchange("http://shop.test", guessed, {}, "1")
        self.assertTrue(request_body_is_placeholder(seeded))
        # Control: a captured body keeps the body-parameter injection probe.
        real = node('{"title": "a", "qty": 2}')
        (_, hypothesis), = wi._derive_probe(real)
        self.assertIn("Test its body parameters one at a time", hypothesis)
        self.assertFalse(request_body_is_placeholder(wi._seed_exchange("http://shop.test", real, {}, "1")))


class NamedParameterNotInRequestTests(unittest.TestCase):
    """26212cb8 binding: a named parameter the request lacks falls back to the
    request's real parameters and records that the named one was untested."""

    def _finding(self, name, only=False):
        return Finding(vulnerability_class="sqli", confidence=0.6, summary="s", evidence="e",
                       suggested_test="t", basis="derived", parameter_location="body",
                       parameter_name=name, parameter_only=only)

    EX = HttpExchange(url="http://shop.test/api/widgets?q=1", method="POST",
                      request_headers={"Content-Type": "application/json"},
                      request_body='{"title": "a", "qty": 2}')

    def test_absent_named_parameter_tests_the_real_ones_and_says_so(self):
        targets, coverage = select_targets(self._finding("value"), param_targets(self.EX), 6)
        self.assertEqual(targets, [("query", "q"), ("body", "title"), ("body", "qty")])
        self.assertEqual(coverage, NAMED_PARAMETER_UNTESTED)

    def test_control_present_named_parameter_is_tested_first_with_full_coverage(self):
        targets, coverage = select_targets(self._finding("qty"), param_targets(self.EX), 6)
        self.assertEqual(targets[0], ("body", "qty"))
        self.assertEqual(coverage, "")


if __name__ == "__main__":
    unittest.main()
