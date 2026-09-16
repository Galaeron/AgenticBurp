"""Tests for the Milestone-C chain linker: escalation edges + chain composition
written into the engagement graph. Deterministic, no network."""
import unittest

from harness import engagement
from harness import chain_linker


def _state():
    return engagement.EngagementState(host="t")


def _f(vc, url, conf=0.8, sev="high", summary="", confirmed=False):
    return {"vulnerability_class": vc, "url": url, "confidence": conf, "severity": sev,
            "summary": summary or vc, "confirmed": confirmed}


class ChainCompositionTests(unittest.TestCase):
    def test_sqli_plus_idor_composes_a_chain(self):
        st = _state()
        out = chain_linker.link_findings(st, [
            _f("sqli", "http://t/api/login"),
            _f("idor", "http://t/api/tickets/1"),
        ])
        sigs = [c["vulnerability_class"] for c in out["chain_findings"]]
        self.assertTrue(any("sqli+idor" in s for s in sigs))
        # the composed chain is recorded in the graph as a `chain` task (linked, inspectable)
        self.assertTrue(any(t.kind == "chain" for t in st.graph.tasks.values()))

    def test_no_chain_from_a_single_class(self):
        st = _state()
        out = chain_linker.link_findings(st, [_f("idor", "http://t/api/tickets/1")])
        self.assertEqual(out["chain_findings"], [])

    def test_findings_without_url_are_ignored(self):
        st = _state()
        out = chain_linker.link_findings(st, [{"vulnerability_class": "sqli", "summary": "x"}])
        self.assertEqual(out["chain_findings"], [])


class EscalationEdgeTests(unittest.TestCase):
    def test_access_control_finding_creates_reachable_area_task(self):
        st = _state()
        chain_linker.link_findings(st, [
            _f("broken_access_control", "http://t/api/admin/users", conf=0.9, confirmed=True)])
        kinds = {t.kind for t in st.graph.tasks.values()}
        self.assertTrue(kinds & {"recrawl_area", "recrawl_as_privileged", "obtain"})

    def test_llm_freetext_class_still_links(self):
        # The iterative agent emits free-text labels ('IDOR/BOLA', 'Broken
        # Function-Level Authorization') that engagement._canon returns None for.
        # The linker must canonicalise them or escalation edges silently vanish
        # (the capstone bug: 7 findings, 0 task-graph edges).
        st = _state()
        chain_linker.link_findings(st, [
            _f("IDOR/BOLA", "http://t/api/reports/1", conf=1.0),
            _f("Broken Function-Level Authorization", "http://t/api/admin/debug", conf=1.0),
        ])
        self.assertTrue(any(t.kind in ("recrawl_area", "recrawl_as_privileged", "obtain")
                            for t in st.graph.tasks.values()),
                        "access-control findings in LLM phrasing must still create escalation edges")

    def test_leaked_credential_becomes_derived_identity_and_closed_loop_edge(self):
        st = _state()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.aGVsbG8sIHRoaXMgaXMgYSB0b2tlbg"
        out = chain_linker.link_findings(
            st,
            [_f("auth", "http://t/api/login", conf=0.9, confirmed=True)],
            responses={"http://t/api/login": {"headers": {}, "body": f'{{"token":"{jwt}"}}'}},
        )
        # a replayable credential -> returned for the caller's re-test loop ...
        self.assertTrue(out["credential_caps"])
        self.assertEqual(out["credential_caps"][0]["type"], "credential")
        # ... and the graph gained the obtain -> recrawl_as_derived escalation edge
        kinds = {t.kind for t in st.graph.tasks.values()}
        self.assertIn("recrawl_as_derived", kinds)
        self.assertTrue(any(i["role"] == "derived" for i in st.identities))


class ChainInputProvenanceTests(unittest.TestCase):
    """R20: _chain_input must preserve confirmed/basis/evidence so chaining.detect
    can distinguish a verified input from a speculative one (previously dropped,
    which defeated the Phase-3.5 speculative-chain tagging)."""

    def test_provenance_survives_projection(self):
        from harness import attribution
        proj = chain_linker._chain_input([
            {"url": "http://t/a", "vulnerability_class": "idor", "confirmed": True,
             "basis": "derived", "evidence": "proof", "identity": "user"},
            {"url": "http://t/b", "vulnerability_class": "sqli", "confirmed": False,
             "basis": "assumed"},
        ])
        self.assertTrue(proj[0]["confirmed"])
        self.assertEqual(proj[0]["evidence"], "proof")
        self.assertEqual(proj[0]["identity"], "user")
        # a confirmed input is never speculative; an unconfirmed assumed one is
        self.assertFalse(attribution.chain_input_speculative(proj[0]))
        self.assertTrue(attribution.chain_input_speculative(proj[1]))


if __name__ == "__main__":
    unittest.main()
