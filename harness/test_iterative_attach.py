"""An iterative agent's finding on an issue the harness already proved joins it.

The proven issue comes from the production confirmation path (a reproduced sqlmap
detection through Orchestrator._validate_findings against an owned 127.0.0.1
fixture, persisted as analyze() does). The iterative result then goes through the
real consumer, pivot_memory.integrate(persist=True), and the stored rows through
the real issue grouping/export. Controls: a finding on a different route stays a
separate, unbound issue; with the attach step patched out the same-issue finding
is the old unbound duplicate.
"""
import asyncio
import unittest
from dataclasses import dataclass, field
from unittest.mock import patch

from harness import issues, pivot_memory, store
from harness.models import Finding, HttpExchange
from harness.report_generator import issue_exports
from harness.test_confirmation_soundness_rve import _finding
from harness.test_proof_artifacts import _ProofCallerBase, _Target
from harness.test_sqlmap_points import _JSON_Q_BOOLEAN, _search_app, _sqlmap_says
from harness.validators.sqlmap import SqlmapValidator


@dataclass
class _IterResult:
    """Duck-typed iterative_agent.IterativeResult."""
    agent: str = "iterative:sqli"
    findings: list = field(default_factory=list)
    handoff_note: str = ""
    stop_reason: str = "found"


def _iter_finding(**kw):
    return Finding(vulnerability_class="Authentication Bypass / SQL Injection", confidence=0.9,
                   summary="login bypass via SQL injection", evidence="model transcript",
                   suggested_test="t", basis="observed", severity="high", confirmed=True, **kw)


def _hdr():
    return Finding(vulnerability_class="missing_headers", confidence=0.6, summary="no HSTS",
                   evidence="e", suggested_test="t", basis="observed", severity="low")


class IterativeAttachTests(_ProofCallerBase, unittest.TestCase):

    def setUp(self):
        super().setUp()
        target = _Target(_search_app(blind={"q"}))
        self.addCleanup(target.close)
        self.exchange = HttpExchange(
            url=target.origin + "/search", method="POST",
            request_headers={"Content-Type": "application/json"}, request_body='{"q": "x"}',
            response_status=200, response_body='{"rows": []}')
        cm = _sqlmap_says(_JSON_Q_BOOLEAN)
        cm.start()
        self.addCleanup(cm.stop)
        finding = _finding("sqli").model_copy(update={"parameter_location": "body",
                                                      "parameter_name": "q"})
        _, reports, _ = self._confirm("sqlmap", SqlmapValidator(allowed_hosts=list(self.HOSTS)),
                                      finding, self.exchange)
        self.assertEqual([r.status for r in reports], ["confirmed"])
        store.persist_findings(self.exchange, "sqlmap", [finding])
        self.proven = finding

    def _issues(self):
        rows = store.all_host_findings(self.exchange.url)
        exports = issue_exports(rows, proofs_by_case={
            r["case_id"]: store.proofs_for_case(r["case_id"]) for r in rows if r.get("case_id")})
        return rows, exports

    def _split(self, exports):
        """(issues referencing the proven case, every other issue)."""
        refs = lambda e: {p.get("case_id") for p in e["proof_references"]}
        proven = [e for e in exports if self.proven.case_id in refs(e)]
        return proven, [e for e in exports if e not in proven]

    def _integrate(self, exchange, f):
        return asyncio.run(pivot_memory.integrate(_IterResult(findings=[f]), exchange, persist=True))

    def test_same_issue_attaches_to_the_proven_issue(self):
        _, before = self._issues()
        self.assertEqual(len(before), 1)
        for f in (_iter_finding(), _iter_finding(parameter_location="body", parameter_name="q")):
            out = self._integrate(self.exchange, f)
            self.assertTrue(out.attached)
            self.assertEqual({a["proof_id"] for a in out.attached}, {self.proven.proof_id})
            for held in out.held_findings:                         # incl. the per-input follow-up
                self.assertEqual((held.proof_id, held.case_id, held.parameter_name),
                                 (self.proven.proof_id, self.proven.case_id, "q"))
        rows, after = self._issues()
        self.assertEqual(len(after), 1, after)                     # issue count unchanged
        self.assertEqual(after[0]["issue_id"], before[0]["issue_id"])
        self.assertTrue(after[0]["confirmed"])
        self.assertIn(self.proven.case_id, [p.get("case_id") for p in after[0]["proof_references"]])
        self.assertTrue(all(r.get("proof_id") for r in rows), rows)  # no unbound duplicate row

    def test_different_route_stays_separate_and_unbound(self):
        other = self.exchange.model_copy(update={"url": self.exchange.url.replace("/search", "/login")})
        out = self._integrate(other, _iter_finding())
        self.assertEqual(out.attached, [])
        self.assertFalse(out.held_findings[0].confirmed or out.held_findings[0].proof_id)
        rows, exports = self._issues()
        proven, new = self._split(exports)
        self.assertEqual(len(proven), 1)
        self.assertTrue(new)
        self.assertTrue(all("/login" in e["title"] for e in new), new)
        for e in new:                                              # accurate binding state
            self.assertEqual((e["confirmed"], e["evidence_state"], e["proof_references"]),
                             (False, "candidate", []))

    def test_different_named_input_stays_separate(self):
        out = self._integrate(self.exchange, _iter_finding(parameter_location="query", parameter_name="id"))
        named = [h for h in out.held_findings if h.parameter_name == "id"]
        self.assertEqual(len(named), 1)
        self.assertFalse(named[0].confirmed or named[0].proof_id)   # a new issue: unbound
        # Only the harness's own body:q follow-up joins the proven q issue.
        self.assertTrue(all(h.parameter_name == "q" for h in out.held_findings if h.proof_id))
        proven, new = self._split(self._issues()[1])
        self.assertEqual(len(proven), 1)
        self.assertEqual([e["confirmed"] for e in new], [False])

    def test_host_wide_class_on_another_route_is_not_attached(self):
        """issue_key drops the route for a host-wide class (missing_headers): a
        proof of /search must not become a /login finding's proof. Same route:
        attached (control)."""
        proven_row = {"url": self.exchange.url, "method": "POST", "vulnerability_class": "missing_headers",
                      "confirmed": True, "proof_id": "p-hdr", "case_id": "c-hdr",
                      "proof_status": "resolved", "finding_id": "f-hdr",
                      "summary": "no HSTS", "evidence": "e", "severity": "low", "confidence": 0.9}
        other = self.exchange.model_copy(update={"url": self.exchange.url.replace("/search", "/login")})
        real = store.all_host_findings
        with patch.object(store, "all_host_findings",
                          side_effect=lambda *a, **k: real(*a, **k) + [proven_row]):
            off = asyncio.run(pivot_memory.integrate(
                _IterResult(findings=[_hdr()]), other, persist=True))
            on = asyncio.run(pivot_memory.integrate(
                _IterResult(findings=[_hdr()]), self.exchange, persist=True))
        self.assertEqual(issues.issue_key({**proven_row}),
                         issues.issue_key({**proven_row, "url": other.url}))  # same issue key
        self.assertEqual(off.attached, [])
        self.assertFalse(off.held_findings[0].proof_id)
        self.assertEqual([a["proof_id"] for a in on.attached], ["p-hdr"])

    def test_control_without_attach_it_is_an_unbound_duplicate(self):
        with patch.object(pivot_memory, "attach_to_proven_issues", return_value=[]):
            self._integrate(self.exchange, _iter_finding())
        rows, exports = self._issues()
        proven, new = self._split(exports)
        self.assertEqual(len(proven), 1)
        self.assertEqual([e["confirmed"] for e in new], [False])   # the pre-fix duplicate
        self.assertTrue(any(not r.get("proof_id") for r in rows))


if __name__ == "__main__":
    unittest.main()
