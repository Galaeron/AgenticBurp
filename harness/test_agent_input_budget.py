"""E8: per-agent input budget for header-only review agents.

The cors and csp agents judge response HEADERS, so the shared max_body_chars
(6000) of HTML/JSON body adds prompt tokens without adding evidence. They set
`input_body_chars` (1500 / 2500); BaseAgent._body_budget lowers the budget to
min(max_body_chars, input_body_chars) and BaseAgent.run / FamilyRunner.run
build the user prompt with it.

All tests are caller level: they drive `agent.run(...)` (or
`FamilyRunner.run(...)`) with a fake OllamaClient that records the user_prompt
it was sent and returns {"findings": []}, then assert on the region between
<response-body> and </response-body>. No model, no network.

The negative controls remove the fix IN-PROCESS (patching the attribute, the
budget helper, the family budget or the signal regex) and prove the same size
check then fails, so the positive assertions are known to be sensitive to the
behaviour they claim to cover.
"""
import asyncio
import re
import unittest
from unittest.mock import patch

from harness.agent_families import FamilyRunner
from harness.agents import base_agent
from harness.agents.auth_agent import AuthAgent
from harness.agents.base_agent import BaseAgent
from harness.agents.cors_agent import CorsAgent
from harness.agents.csp_agent import CspAgent
from harness.agents.misconfig_agent import MisconfigAgent
from harness.agents.web_cache_poisoning_agent import WebCachePoisoningAgent
from harness.agents.xss_agent import XssAgent
from harness.models import HttpExchange

MAX_BODY_CHARS = 6000
BODY_LEN = 9984                      # the 9,984-character capture from the E8 measurement
LINE_LEN = 128                       # 127 chars + "\n": 78 lines, well under the line cap
# Allowance for everything _user_prompt adds around the cut body: the
# "...[truncated by character limit]" note plus an optional <=400-char excerpt
# and its heading.
FRAMING_CHARS = 600
TRUNCATION_NOTE = "\n...["
EXCERPT_HEADING = "relevant excerpt from the truncated region"


class RecordingOllama:
    """Fake OllamaClient: records every user_prompt, returns no findings."""

    def __init__(self):
        self.user_prompts = []

    async def chat_json(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        return {"findings": []}


def make_body(*markers):
    """A BODY_LEN-character HTML body with no signal markers, with each
    (position, text) marker written over the filler at that character offset."""
    unit = '<p class="row">lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut</p>'
    line = (unit * 2)[:LINE_LEN - 1] + "\n"
    body = (line * (BODY_LEN // LINE_LEN + 1))[:BODY_LEN]
    for pos, text in markers:
        body = body[:pos] + text + body[pos + len(text):]
    assert len(body) == BODY_LEN
    return body


def make_exchange(body):
    return HttpExchange(
        url="https://app.test/page", method="GET",
        request_headers={"Host": "app.test"},
        response_headers={"Content-Type": "text/html", "Access-Control-Allow-Origin": "*"},
        response_status=200, response_body=body,
    )


def body_region(prompt):
    """Text between <response-body> and </response-body> (framing excluded)."""
    start = prompt.index("<response-body>") + len("<response-body>")
    end = prompt.index("</response-body>")
    return prompt[start:end].strip("\n")


def shown_body_chars(prompt):
    """Body characters actually shown: the region before any truncation note."""
    return len(body_region(prompt).split(TRUNCATION_NOTE)[0])


def assert_body_budget(test, prompt, budget):
    """Shared size check (positive tests and negative controls both use it):
    the prompt shows exactly `budget` body characters, plus at most
    FRAMING_CHARS of truncation note / excerpt."""
    region = body_region(prompt)
    test.assertEqual(shown_body_chars(prompt), budget)
    test.assertLessEqual(len(region), budget + FRAMING_CHARS)


def run_agent(agent_cls, body, max_body_chars=MAX_BODY_CHARS, configure=None):
    """Drive agent.run(...) with the fake client; return (user_prompt, report)."""
    ollama = RecordingOllama()
    agent = agent_cls(ollama, "fake-model")
    if configure:
        configure(agent)
    report = asyncio.run(agent.run(make_exchange(body), max_body_chars))
    assert len(ollama.user_prompts) == 1
    return ollama.user_prompts[0], report


class FixtureSanityTests(unittest.TestCase):
    def test_filler_body_has_no_signal_marker_and_is_9984_chars(self):
        body = make_body()
        self.assertEqual(len(body), 9984)
        self.assertIsNone(base_agent._SIGNAL_RE.search(body))
        # 6,000 chars of it stay under the per-field line cap, so a full-budget
        # prompt really carries 6,000 body characters.
        self.assertLessEqual(len(body[:MAX_BODY_CHARS].split("\n")), base_agent._MAX_BODY_LINES)


class HeaderOnlyAgentBudgetTests(unittest.TestCase):
    def test_cors_prompt_carries_at_most_1500_body_chars(self):
        prompt, report = run_agent(CorsAgent, make_body())
        assert_body_budget(self, prompt, 1500)
        self.assertEqual(report.input_body_chars, 1500)

    def test_csp_prompt_carries_at_most_2500_body_chars(self):
        prompt, report = run_agent(CspAgent, make_body())
        assert_body_budget(self, prompt, 2500)
        self.assertEqual(report.input_body_chars, 2500)

    def test_agents_that_read_the_body_still_get_all_6000_chars(self):
        # xss/misconfig/auth/web_cache_poisoning do not set the attribute: the
        # body is what their verdict depends on (reflections, debug pages,
        # listings), so they keep the full shared budget.
        for agent_cls in (XssAgent, MisconfigAgent, AuthAgent, WebCachePoisoningAgent):
            with self.subTest(agent=agent_cls.name):
                self.assertIsNone(agent_cls.input_body_chars)
                prompt, report = run_agent(agent_cls, make_body())
                assert_body_budget(self, prompt, MAX_BODY_CHARS)
                self.assertIsNone(report.input_body_chars)

    def test_only_cors_and_csp_set_the_attribute(self):
        from harness.agents.plugin import get_plugin_system
        plugins = get_plugin_system()
        budgeted = {}
        for name in plugins.list_agents():
            agent_cls = plugins.load_agent_class(name)
            if agent_cls is not None and agent_cls.input_body_chars is not None:
                budgeted[name] = agent_cls.input_body_chars
        self.assertEqual(budgeted, {"cors": 1500, "csp": 2500})

    def test_budget_never_raises_the_shared_max(self):
        # A max_body_chars already below the agent's cap is used as is, and the
        # report records nothing because the budget did not differ.
        prompt, report = run_agent(CorsAgent, make_body(), max_body_chars=1000)
        assert_body_budget(self, prompt, 1000)
        self.assertIsNone(report.input_body_chars)

    def test_body_budget_helper(self):
        cors = CorsAgent(None, "m")
        self.assertEqual(cors._body_budget(6000), 1500)
        self.assertEqual(cors._body_budget(900), 900)
        cors.input_body_chars = None
        self.assertEqual(cors._body_budget(6000), 6000)


class HighSignalKeptTests(unittest.TestCase):
    def test_traceback_beyond_cors_budget_is_still_excerpted(self):
        marker = "Traceback (most recent call last):"
        prompt, _ = run_agent(CorsAgent, make_body((4000, marker)))
        region = body_region(prompt)
        assert_body_budget(self, prompt, 1500)
        self.assertIn(EXCERPT_HEADING, region)
        # The marker is only in the excerpt (it sits past the 1,500-char cut).
        self.assertNotIn("Traceback", region.split(TRUNCATION_NOTE)[0])
        self.assertIn(marker, region.split(EXCERPT_HEADING)[1])

    def test_meta_csp_beyond_csp_budget_is_excerpted(self):
        tag = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        prompt, _ = run_agent(CspAgent, make_body((3000, tag)))
        region = body_region(prompt)
        assert_body_budget(self, prompt, 2500)
        self.assertIn(EXCERPT_HEADING, region)
        self.assertNotIn("http-equiv", region.split(TRUNCATION_NOTE)[0])
        self.assertIn(tag, region.split(EXCERPT_HEADING)[1])

    def test_meta_csp_inside_csp_budget_is_in_the_body_itself(self):
        tag = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        prompt, _ = run_agent(CspAgent, make_body((1200, tag)))
        self.assertIn(tag, body_region(prompt).split(TRUNCATION_NOTE)[0])


class FamilyRunnerBudgetTests(unittest.TestCase):
    """FamilyRunner builds ONE user prompt for every dispatched member."""

    @staticmethod
    def run_family(member_classes, body):
        ollama = RecordingOllama()
        members = [cls(ollama, "fake-model") for cls in member_classes]
        report = asyncio.run(FamilyRunner("config_headers", members).run(
            make_exchange(body), MAX_BODY_CHARS))
        assert len(ollama.user_prompts) == 1
        return ollama.user_prompts[0], report

    def test_family_of_header_only_agents_uses_the_largest_member_budget(self):
        prompt, report = self.run_family([CorsAgent, CspAgent], make_body())
        assert_body_budget(self, prompt, 2500)
        self.assertEqual(report.input_body_chars, 2500)

    def test_single_header_only_member_family_uses_its_budget(self):
        prompt, report = self.run_family([CorsAgent], make_body())
        assert_body_budget(self, prompt, 1500)
        self.assertEqual(report.input_body_chars, 1500)

    def test_family_with_a_body_reading_member_keeps_the_full_body(self):
        # cors is the primary (first member) but misconfig shares the prompt and
        # needs the body: the family must not be shortened to cors' budget.
        prompt, report = self.run_family([CorsAgent, MisconfigAgent], make_body())
        assert_body_budget(self, prompt, MAX_BODY_CHARS)
        self.assertIsNone(report.input_body_chars)


class NegativeControlTests(unittest.TestCase):
    """Each control removes the fix in-process; the shared size check must then
    FAIL for the budgeted agent, proving the positive tests above can fail."""

    def assert_check_fails(self, prompt, budget):
        with self.assertRaises(AssertionError):
            assert_body_budget(self, prompt, budget)

    def test_control_attribute_none_gives_cors_the_full_6000(self):
        prompt, report = run_agent(
            CorsAgent, make_body(), configure=lambda a: setattr(a, "input_body_chars", None))
        assert_body_budget(self, prompt, MAX_BODY_CHARS)
        self.assert_check_fails(prompt, 1500)
        self.assertIsNone(report.input_body_chars)

    def test_control_run_ignoring_the_budget_helper_gives_cors_the_full_6000(self):
        with patch.object(BaseAgent, "_body_budget", lambda self, max_body_chars: max_body_chars):
            prompt, report = run_agent(CorsAgent, make_body())
        self.assert_check_fails(prompt, 1500)
        assert_body_budget(self, prompt, MAX_BODY_CHARS)
        self.assertIsNone(report.input_body_chars)

    def test_control_csp_without_budget_gives_the_full_6000(self):
        with patch.object(CspAgent, "input_body_chars", None):
            prompt, _ = run_agent(CspAgent, make_body())
        self.assert_check_fails(prompt, 2500)
        assert_body_budget(self, prompt, MAX_BODY_CHARS)

    def test_control_budget_wrongly_set_on_a_body_reading_agent_is_caught(self):
        # If misconfig/xss/web_cache_poisoning were given a header-only budget
        # the "still get all 6,000 chars" check would fail for them.
        for agent_cls in (XssAgent, MisconfigAgent, WebCachePoisoningAgent):
            with self.subTest(agent=agent_cls.name):
                with patch.object(agent_cls, "input_body_chars", 1500):
                    prompt, _ = run_agent(agent_cls, make_body())
                self.assert_check_fails(prompt, MAX_BODY_CHARS)
                self.assertEqual(shown_body_chars(prompt), 1500)

    def test_control_traceback_is_not_an_excerpt_without_the_budget(self):
        # With the fix removed the 4,000-char Traceback is simply inside the
        # 6,000-char prefix: no excerpt, and the cors size check fails.
        marker = "Traceback (most recent call last):"
        with patch.object(BaseAgent, "_body_budget", lambda self, max_body_chars: max_body_chars):
            prompt, _ = run_agent(CorsAgent, make_body((4000, marker)))
        region = body_region(prompt)
        self.assert_check_fails(prompt, 1500)
        self.assertNotIn(EXCERPT_HEADING, region)
        self.assertIn(marker, region.split(TRUNCATION_NOTE)[0])

    def test_control_meta_csp_lost_without_the_http_equiv_signal(self):
        tag = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        old_pattern = base_agent._SIGNAL_RE.pattern.replace("|http-equiv)", ")")
        self.assertNotEqual(old_pattern, base_agent._SIGNAL_RE.pattern)
        old_re = re.compile(old_pattern, re.IGNORECASE)
        with patch.object(base_agent, "_SIGNAL_RE", old_re):
            prompt, _ = run_agent(CspAgent, make_body((3000, tag)))
        # Budget still applies, but the meta CSP is neither in the prefix nor
        # excerpted: exactly the evidence loss the http-equiv alternative fixes.
        assert_body_budget(self, prompt, 2500)
        self.assertNotIn("http-equiv", body_region(prompt))

    def test_control_family_sized_by_primary_member_alone_would_hide_the_body(self):
        primary_only = lambda self, max_body_chars: self._primary._body_budget(max_body_chars)
        with patch.object(FamilyRunner, "_body_budget", primary_only):
            prompt, report = FamilyRunnerBudgetTests.run_family(
                [CorsAgent, MisconfigAgent], make_body())
        self.assert_check_fails(prompt, MAX_BODY_CHARS)
        self.assertEqual(shown_body_chars(prompt), 1500)
        self.assertEqual(report.input_body_chars, 1500)


class MeasuredReductionTests(unittest.TestCase):
    AGENTS = (CorsAgent, CspAgent, XssAgent, MisconfigAgent, AuthAgent)

    def prompt_sizes(self, restricted):
        """agent name -> user-prompt characters for the same 9,984-char capture,
        with the input_body_chars attribute left as shipped (restricted=True)
        or forced to None (the pre-E8 behaviour)."""
        body = make_body()
        sizes = {}
        for agent_cls in self.AGENTS:
            configure = None if restricted else (lambda a: setattr(a, "input_body_chars", None))
            prompt, _ = run_agent(agent_cls, body, configure=configure)
            sizes[agent_cls.name] = len(prompt)
        return sizes

    def test_cors_and_csp_prompts_shrink_by_at_least_25_percent(self):
        before = self.prompt_sizes(restricted=False)
        after = self.prompt_sizes(restricted=True)

        print("\nE8 measured user-prompt characters, one 9,984-char capture, max_body_chars=6000")
        print(f"{'agent':<12}{'before':>8}{'after':>8}{'saved':>8}")
        for name in before:
            print(f"{name:<12}{before[name]:>8}{after[name]:>8}{before[name] - after[name]:>8}")
        total_before, total_after = sum(before.values()), sum(after.values())
        pair_before = before["cors"] + before["csp"]
        pair_after = after["cors"] + after["csp"]
        print(f"{'all five':<12}{total_before:>8}{total_after:>8}{total_before - total_after:>8}"
              f"  ({100 * (total_before - total_after) / total_before:.1f}% smaller)")
        print(f"{'cors+csp':<12}{pair_before:>8}{pair_after:>8}{pair_before - pair_after:>8}"
              f"  ({100 * (pair_before - pair_after) / pair_before:.1f}% smaller)")

        self.assertGreaterEqual((pair_before - pair_after) / pair_before, 0.25)
        # The body-reading agents are untouched.
        for name in ("xss", "misconfig", "auth"):
            self.assertEqual(before[name], after[name], name)

    def test_control_reduction_vanishes_without_the_budget(self):
        # With the helper removed, "after" equals "before" for cors/csp.
        with patch.object(BaseAgent, "_body_budget", lambda self, max_body_chars: max_body_chars):
            after = self.prompt_sizes(restricted=True)
        before = self.prompt_sizes(restricted=False)
        pair_before = before["cors"] + before["csp"]
        pair_after = after["cors"] + after["csp"]
        self.assertLess((pair_before - pair_after) / pair_before, 0.25)


if __name__ == "__main__":
    unittest.main()
