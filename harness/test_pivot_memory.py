"""Tests for F2 pause->validate->remember (pivot/combine), against a temp DB."""
import asyncio
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from harness import store
from harness import pivot_memory
from harness.models import Finding, HttpExchange


@dataclass
class _FakeResult:
    """Duck-typed stand-in for iterative_agent.IterativeResult."""
    agent: str = "iterative:idor"
    findings: list = field(default_factory=list)
    handoff_note: str = ""
    stop_reason: str = "found"


def _exchange(url="https://shop.test/api/report", method="GET"):
    return HttpExchange(url=url, method=method, request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


def _finding(vc="idor", summary="s", conf=0.7, confirmed=True):
    return Finding(vulnerability_class=vc, confidence=conf, summary=summary, evidence="e",
                   suggested_test="t", basis="derived", severity="high", confirmed=confirmed)


class PivotMemoryTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmpdir.cleanup()

    def _integrate(self, result, exchange, **kw):
        return asyncio.run(pivot_memory.integrate(result, exchange, **kw))

    def test_findings_are_held_unconfirmed(self):
        # An active agent's confirmed=True is downgraded: LLM reasoning never
        # ships as confirmed, even after active probing.
        r = _FakeResult(findings=[_finding(confirmed=True)])
        out = self._integrate(r, _exchange())
        self.assertEqual(len(out.held_findings), 1)
        self.assertFalse(out.held_findings[0].confirmed)

    def test_validation_plans_built(self):
        r = _FakeResult(agent="iterative:sqli", findings=[_finding(vc="sqli", summary="sqli on id")])
        out = self._integrate(r, _exchange())
        self.assertTrue(out.validation_plans)
        self.assertTrue(any("sql" in p.capability for p in out.validation_plans))

    def test_remembered_into_host_history(self):
        r = _FakeResult(findings=[_finding(vc="idor")])
        ex = _exchange()
        out = self._integrate(r, ex)
        self.assertTrue(out.remembered)
        rows = store.all_host_findings(ex.url)
        self.assertTrue(any(row["vulnerability_class"] == "idor" for row in rows))

    def test_persist_false_writes_nothing(self):
        r = _FakeResult(findings=[_finding(vc="idor")])
        ex = _exchange()
        out = self._integrate(r, ex, persist=False)
        self.assertFalse(out.remembered)
        self.assertEqual(store.all_host_findings(ex.url), [])
        # plans are still computed for preview
        self.assertTrue(out.validation_plans)

    def test_combination_detected_with_prior_finding(self):
        # Prior host finding: SSRF. New active finding: open_redirect on same host.
        # chaining rule "open_redirect+ssrf" should fire as a combination.
        ex_prior = _exchange(url="https://shop.test/fetch")
        store.persist_findings(ex_prior, "ssrf_agent",
                               [_finding(vc="ssrf", summary="ssrf via url param", confirmed=False)])
        r = _FakeResult(agent="iterative:open_redirect",
                        findings=[_finding(vc="open_redirect", summary="open redirect on next=")])
        out = self._integrate(r, _exchange(url="https://shop.test/login"))
        self.assertTrue(any("open_redirect+ssrf" in c.vulnerability_class for c in out.chains))

    def test_pivot_hint_when_only_half_present(self):
        # Host has no ssrf. New finding is open_redirect -> pivot hint should say
        # "look for ssrf to complete open_redirect+ssrf".
        r = _FakeResult(agent="iterative:open_redirect",
                        findings=[_finding(vc="open_redirect", summary="open redirect")])
        out = self._integrate(r, _exchange(url="https://shop.test/login"))
        sigs = {(h["signature"], h["look_for"]) for h in out.pivot_hints}
        self.assertIn(("open_redirect+ssrf", "ssrf"), sigs)
        # and no completed chain, since ssrf isn't present
        self.assertFalse(any("open_redirect+ssrf" in c.vulnerability_class for c in out.chains))

    def test_grounding_includes_handoff_note(self):
        r = _FakeResult(handoff_note="tried id=2..5, id=3 leaked another user's ticket",
                        findings=[_finding(vc="idor")])
        out = self._integrate(r, _exchange())
        self.assertIn("id=3 leaked", out.grounding)

    def test_no_findings_still_returns_grounding(self):
        r = _FakeResult(findings=[], handoff_note="exhausted payloads, DB errors on quote suggest sqli",
                        stop_reason="exhausted_steps")
        out = self._integrate(r, _exchange())
        self.assertEqual(out.held_findings, [])
        self.assertFalse(out.remembered)
        self.assertIn("exhausted payloads", out.grounding)

    def test_chain_not_redetected_second_run(self):
        ex_prior = _exchange(url="https://shop.test/fetch")
        store.persist_findings(ex_prior, "ssrf_agent",
                               [_finding(vc="ssrf", summary="ssrf", confirmed=False)])
        r = _FakeResult(agent="iterative:open_redirect",
                        findings=[_finding(vc="open_redirect", summary="open redirect")])
        first = self._integrate(r, _exchange(url="https://shop.test/login"))
        self.assertTrue(first.chains)
        # second integration of another open_redirect finding: chain already marked
        r2 = _FakeResult(agent="iterative:open_redirect",
                         findings=[_finding(vc="open_redirect", summary="another open redirect")])
        second = self._integrate(r2, _exchange(url="https://shop.test/logout"))
        self.assertFalse(any("open_redirect+ssrf" in c.vulnerability_class for c in second.chains))


if __name__ == "__main__":
    unittest.main()
