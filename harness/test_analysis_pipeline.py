"""
Tests for AnalysisPipeline, focused on the injected-ollama_client fix.

Before this fix, AnalysisPipeline._critique() constructed a brand-new
OllamaClient() inline on every call -- meaning its circuit breaker was
always freshly-CLOSED and could never accumulate failures the way the
main dispatch path's long-lived client's breaker does. This file exists
so that regression is caught by the test suite, not rediscovered by a
future audit.
"""
import unittest
from unittest.mock import AsyncMock, MagicMock

from harness.analysis_pipeline import AnalysisPipeline
from harness.models import AgentReport, ComponentCandidate, Finding, HttpExchange


def _make_pipeline(ollama_client=None) -> AnalysisPipeline:
    agent_manager = MagicMock()
    effort_budget = MagicMock()
    store = MagicMock()
    # Every _init_clients lookup other than the ollama fallback uses
    # .get() with a default; "ollama" is only required when no client is
    # injected (the fallback-construction path), so it's harmless to
    # always include it here.
    config: dict = {"ollama": {"base_url": "http://example.invalid"}}
    return AnalysisPipeline(agent_manager, effort_budget, store, config, ollama_client=ollama_client)


def _make_report(finding: Finding):
    from harness.models import AgentReport
    return AgentReport(agent="test_agent", model="m", findings=[finding])


def _make_finding(confidence: float = 0.9) -> Finding:
    return Finding(
        vulnerability_class="sqli",
        confidence=confidence,
        summary="s",
        evidence="e",
        suggested_test="t",
        basis="derived",
    )


class InjectedOllamaClientTests(unittest.TestCase):
    def test_pipeline_stores_the_injected_client_instead_of_building_one(self):
        fake_client = MagicMock()
        pipeline = _make_pipeline(ollama_client=fake_client)
        self.assertIs(pipeline.ollama_client, fake_client)

    def test_pipeline_without_an_injected_client_builds_a_standalone_one(self):
        # Documents the fallback path explicitly: still works, but the
        # docstring/log message says its breaker is not shared with
        # anything, which callers need to know if they rely on it.
        pipeline = _make_pipeline(ollama_client=None)
        self.assertIsNotNone(pipeline.ollama_client)


class CritiqueUsesInjectedClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_critique_calls_chat_json_metered_on_the_injected_client(self):
        """
        The actual regression test: _critique() must call
        chat_json_metered on the client that was injected at
        construction time, not build a new OllamaClient inline.
        """
        fake_client = MagicMock()
        fake_result = MagicMock()
        fake_result.data = {"reviews": []}
        fake_client.chat_json_metered = AsyncMock(return_value=fake_result)

        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {
            "critique": {"enabled": True, "confidence_threshold": 0.5, "max_findings": 12},
            "coordinator": {"model": "test-model"},
        }

        exchange = HttpExchange(url="https://example.com/x", method="GET")
        finding = _make_finding(confidence=0.9)
        reports = [_make_report(finding)]

        await pipeline._critique(exchange, reports)

        fake_client.chat_json_metered.assert_awaited_once()

    async def test_critique_does_not_construct_a_second_ollama_client(self):
        """
        Guards against a regression that keeps the injected client around
        but still builds a second, throwaway one somewhere in _critique
        (which would silently reintroduce the unshared-breaker bug even
        though the constructor-level fix looks complete).
        """
        import harness.analysis_pipeline as ap_module

        fake_client = MagicMock()
        fake_result = MagicMock()
        fake_result.data = {"reviews": []}
        fake_client.chat_json_metered = AsyncMock(return_value=fake_result)

        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {
            "critique": {"enabled": True, "confidence_threshold": 0.5, "max_findings": 12},
            "coordinator": {"model": "test-model"},
        }

        exchange = HttpExchange(url="https://example.com/x", method="GET")
        reports = [_make_report(_make_finding(confidence=0.9))]

        with unittest.mock.patch("harness.ollama_client.OllamaClient") as mock_cls:
            await pipeline._critique(exchange, reports)
            mock_cls.assert_not_called()


class CritiquePromptStripsBackticksTests(unittest.IsolatedAsyncioTestCase):
    """
    Regression test for a real bug found during this project's first
    real (non-substituted) Ollama run against Juice Shop:
    AnalysisPipeline._critique() -- the ONE that actually runs in the
    real analyze() flow (orchestrator.py used to have its own dead
    duplicate; removed, see its own note) -- embedded finding summary/
    evidence text VERBATIM into the critique prompt. A model wrote a
    completely ordinary finding summary using Markdown code-formatting
    ("the `/api/Users/1` endpoint...", "`Access-Control-Allow-Origin:
    *`"), which tripped prompt_validator.py's backtick-command-
    substitution pattern (deliberately broad by design), failing
    critique validation and shipping those findings unreviewed. Same
    fix and reasoning as store.prior_findings_summary(): this text is
    the harness's own model output, not raw exchange data.
    """

    async def test_backtick_in_finding_summary_does_not_reach_the_critique_prompt(self):
        fake_client = MagicMock()
        fake_result = MagicMock()
        fake_result.data = {"reviews": []}
        fake_client.chat_json_metered = AsyncMock(return_value=fake_result)

        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {
            "critique": {"enabled": True, "confidence_threshold": 0.5, "max_findings": 12},
            "coordinator": {"model": "test-model"},
        }

        exchange = HttpExchange(url="https://example.com/api/Users/1", method="GET")
        finding = Finding(
            vulnerability_class="cors", confidence=0.9,
            summary="The `/api/Users/1` endpoint reflects `Access-Control-Allow-Origin: *`.",
            evidence="e", suggested_test="t", basis="derived",
        )
        reports = [_make_report(finding)]

        await pipeline._critique(exchange, reports)

        sent_prompt = fake_client.chat_json_metered.call_args.kwargs["user_prompt"]
        self.assertNotIn("`", sent_prompt)
        self.assertIn("/api/Users/1", sent_prompt)


class NoDuplicateKnownVulnerabilityResolutionTests(unittest.IsolatedAsyncioTestCase):
    """
    Regression tests for a real, live-reproduced bug: AnalysisPipeline
    used to run its own GitHub Advisory + KEV resolution pass inside
    run_full_analysis, duplicating orchestrator.analyze()'s own
    equivalent pass over the same components -- confirmed live during
    this project's first real (non-substituted) Ollama run, where both
    independently called GitHub's Advisory API for the same components
    in the same request and each logged its own "Known vulnerability
    lookup errors" line. See HANDOVER.md and the comment in
    AnalysisPipeline._init_clients.
    """

    def test_pipeline_no_longer_constructs_advisory_or_kev_clients(self):
        """The whole point of the fix: this class shouldn't even own
        these clients any more, since it never calls them."""
        pipeline = _make_pipeline()
        self.assertFalse(hasattr(pipeline, "gha_client"))
        self.assertFalse(hasattr(pipeline, "kev_client"))
        self.assertFalse(hasattr(pipeline, "registry_client"))

    async def test_run_full_analysis_never_appends_a_known_vuln_report(self):
        """Even with a component candidate present in an agent's report
        (the exact input that used to trigger a real, redundant GitHub
        API call), run_full_analysis must not produce a
        known_vuln_lookup report -- that's orchestrator.analyze()'s job
        now, exactly once, over the complete final list."""
        fake_client = MagicMock()
        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {"critique": {"enabled": False}}

        component = ComponentCandidate(ecosystem="pypi", name="Werkzeug", version="3.1.7", source="Server header")
        report_with_component = AgentReport(agent="misconfig", model="m", components=[component])
        pipeline.agent_manager.run_multiple_agents = AsyncMock(return_value=[report_with_component])

        exchange = HttpExchange(
            url="https://example.com/x", method="GET",
            response_headers={"Server": "Werkzeug/3.1.7"},
        )
        reports, _, _, _ = await pipeline.run_full_analysis(exchange, ["misconfig"], "", 6000)

        self.assertEqual([r.agent for r in reports], ["misconfig"])
        self.assertNotIn("known_vuln_lookup", [r.agent for r in reports])


if __name__ == "__main__":
    unittest.main()
