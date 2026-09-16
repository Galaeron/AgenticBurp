"""
Tests for exchange_text.py -- the shared helper extracted to fix a real,
silently-diverged duplicate found during audit: orchestrator.py's
_exchange_text() included exchange.analyst_note; analysis_pipeline.py's
copy of the same logic did not. orchestrator.py delegates to this one
function; analysis_pipeline.py's own copy (and the known-vulnerability
resolution code that was its only caller) was removed entirely as a
separate, later fix -- see HANDOVER.md and the comment in
AnalysisPipeline._init_clients -- so there is no longer a second
implementation for this one to drift from.
"""
import unittest

from harness.exchange_text import exchange_text
from harness.models import HttpExchange


def _exchange_with_note(note: str) -> HttpExchange:
    return HttpExchange(
        url="https://example.com/x",
        method="GET",
        request_headers={"X-Req": "reqval"},
        response_headers={"X-Resp": "respval"},
        request_body="reqbody",
        response_body="respbody",
        analyst_note=note,
    )


class ExchangeTextIncludesEverythingTests(unittest.TestCase):
    def test_analyst_note_is_included(self):
        """
        The specific regression: analysis_pipeline.py's old duplicate
        omitted analyst_note entirely, meaning a note like "this looks
        like log4j 2.14" could count as component-observation evidence
        via orchestrator.py's path but not analysis_pipeline.py's.
        """
        ex = _exchange_with_note("looks like log4j 2.14 based on the stack trace")
        text = exchange_text(ex)
        self.assertIn("log4j 2.14", text)

    def test_headers_bodies_and_url_are_all_included(self):
        ex = _exchange_with_note("")
        text = exchange_text(ex)
        for expected in ("example.com/x", "reqbody", "respbody", "X-Req", "reqval", "X-Resp", "respval"):
            self.assertIn(expected, text)


class OrchestratorDelegatesToSharedFunctionTests(unittest.TestCase):
    """
    Confirms orchestrator.py's _exchange_text() genuinely delegates to
    the shared function rather than reintroducing its own copy -- a
    regression here would mean it started passing extra/fewer fields,
    silently reintroducing exactly the divergence this file exists to
    prevent. This used to compare against analysis_pipeline.py's own
    copy of the same method too, but that copy (and its only caller,
    the known-vulnerability resolution code) was removed entirely as a
    separate fix -- see HANDOVER.md -- so there is no second
    implementation left to compare against.
    """

    def test_orchestrator_matches_the_shared_function_directly(self):
        from harness import orchestrator

        ex = _exchange_with_note("some analyst note with a version string 4.17.21")

        self.assertEqual(orchestrator._exchange_text(ex), exchange_text(ex))


if __name__ == "__main__":
    unittest.main()
