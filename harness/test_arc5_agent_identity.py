"""ARC-5: an agent's JSON cannot choose a finding's identity.

The model's finding dict became a Finding with a denylist (R02) that stripped the
authority fields and kept everything else. So the model chose:
- finding_id, which _case_for honours as the case's finding_ref: two findings
  given the same id shared one case ref, and so one proof's exchanges;
- request_template_id and workflow_state_id, which key the case ref too;
- principal_id, which keys the stored fingerprint. A tester suppression matches
  that fingerprint, so a model naming any principal stepped around it.

Now models.sanitize_agent_finding keeps an allowlist (AGENT_SETTABLE_FIELDS), the
harness stamps finding_id, and a principal_id stands only when it names a session
principal of the run.

Caller-level: Orchestrator.analyze over a captured exchange, with only the model
boundary stubbed. State and cache DBs are temporary; active validators are off,
so nothing leaves the process. The negative control runs the same path with the
old denylist sanitizer; the collision and the bypass must then reappear.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from harness import evidence, store
from harness.models import AGENT_AUTHORITY_FIELDS
from harness.run_context import RunContext
from harness.test_cross_request_prior_context import _IsolatedStateCase, _build, _exchange
from harness.test_smoke_detection import _test_config

_URL_PATH = "/api/v1/orders/101"
_MODEL_ID = "model-chosen-id"
_MODEL_PRINCIPAL = "admin"


def _finding(**identity):
    return {"vulnerability_class": "idor", "confidence": 0.5, "severity": "medium",
            "summary": "order object returned with owner field",
            "evidence": "owner_email present in body",
            "suggested_test": "compare the same object as a second principal",
            "basis": "derived", "validation_hints": [], **identity}


class _Model:
    """Emits the configured findings for every agent prompt."""

    def __init__(self, findings):
        self.findings = findings

    def _answer(self):
        return {"findings": [dict(f) for f in self.findings], "components": []}

    async def chat_json(self, *a, **kw):
        return self._answer()

    async def chat_json_metered(self, *a, **kw):
        from harness.ollama_client import OllamaResult
        return OllamaResult(data=self._answer(), prompt_tokens=1, completion_tokens=1)


def _denylist_sanitizer(raw):
    """The pre-ARC-5 sanitizer: drop the R02 authority fields, keep the rest."""
    clean = {k: v for k, v in raw.items() if k not in AGENT_AUTHORITY_FIELDS}
    for key in ("parameter_location", "parameter_name"):
        if key in clean:
            value = clean[key]
            clean[key] = value.strip()[:200] if isinstance(value, str) else ""
    return clean


def _honouring_path():
    """The old honouring path: the denylist sanitizer at every agent-output seam."""
    return [patch("harness.agents.base_agent.sanitize_agent_finding", side_effect=_denylist_sanitizer),
            patch("harness.models.sanitize_agent_finding", side_effect=_denylist_sanitizer)]


class _Arc5Case(_IsolatedStateCase, unittest.TestCase):
    def _analyze(self, findings, *, sessions=(), defects=()):
        """One Orchestrator.analyze of the order read; the model emits `findings`.
        `sessions`: (session_id, principal) registered on a run the caller owns, as
        an engagement does. Returns (idor findings, case refs built for them)."""
        orch = _build(_Model(findings))
        ex = _exchange(_URL_PATH, "fixture-alice-token", "ARC5")
        cases = []
        real_make = evidence.TestCaseRef.make

        def spy(**kw):
            ref = real_make(**kw)
            if kw.get("check_id") == "idor":
                cases.append(ref)
            return ref

        async def go():
            if not sessions:
                return await orch.analyze(ex, force_agents=["idor"], bypass_cache=True)
            rc = RunContext.create(allowed_hosts=["localhost"], config=_test_config())
            async with rc:
                for session_id, principal in sessions:
                    rc.sessions.register(session_id, principal, {},
                                         allowed_origins=["http://localhost"])
                return await orch.analyze(ex, force_agents=["idor"], bypass_cache=True,
                                          run_context=rc)

        patches = [patch.object(evidence.TestCaseRef, "make", side_effect=spy), *defects]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        idor = [f for r in result.agent_reports if r.agent == "idor" for f in r.findings]
        self.assertEqual(len(idor), len(findings), "precondition: the stubbed findings were not parsed")
        return idor, cases

    def _rows(self, **kw):
        return store.all_host_findings("http://localhost" + _URL_PATH, **kw)

    def _fingerprint(self, principal):
        return store.finding_fingerprint("localhost", "GET", "http://localhost" + _URL_PATH, "idor",
                                         principal_id=principal)


class AllowlistTests(unittest.TestCase):
    def test_no_authority_field_is_agent_settable(self):
        # The models.py import-time assert is stripped under -O; this is not.
        from harness.models import AGENT_SETTABLE_FIELDS
        self.assertFalse(AGENT_SETTABLE_FIELDS & AGENT_AUTHORITY_FIELDS)
        self.assertFalse(AGENT_SETTABLE_FIELDS & {"finding_id", "request_template_id",
                                                  "workflow_state_id", "header_fingerprint"})


class CaseIdentityCallerTests(_Arc5Case):
    def test_a_duplicate_model_finding_id_yields_distinct_case_refs(self):
        twins = [_finding(finding_id=_MODEL_ID), _finding(finding_id=_MODEL_ID)]
        idor, cases = self._analyze(twins)
        ids = [f.finding_id for f in idor]
        self.assertNotIn(_MODEL_ID, ids, "the model's finding_id survived")
        self.assertEqual(len(set(ids)), 2, ids)
        self.assertEqual(len(cases), 2)
        self.assertEqual(len({c.case_id for c in cases}), 2, "two findings share one case ref")
        self.assertEqual({c.finding_ref for c in cases}, set(ids))

    def test_model_template_and_workflow_ids_do_not_key_the_case(self):
        idor, cases = self._analyze([_finding(request_template_id="tmpl-model",
                                              workflow_state_id="wf-model")])
        self.assertEqual((idor[0].request_template_id, idor[0].workflow_state_id), ("", ""))
        self.assertNotEqual(cases[0].request_template_id, "tmpl-model")
        self.assertEqual(cases[0].workflow_state_id, "")


class PrincipalBindingCallerTests(_Arc5Case):
    def test_an_unknown_principal_is_replaced_before_fingerprinting(self):
        idor, cases = self._analyze([_finding(principal_id=_MODEL_PRINCIPAL)])
        self.assertEqual(idor[0].principal_id, "")
        self.assertNotEqual(cases[0].principal_id, _MODEL_PRINCIPAL)
        self.assertEqual([r["fingerprint"] for r in self._rows()], [self._fingerprint("")])

    def test_a_session_principal_of_the_run_stands(self):
        # Positive control: the binding keeps what the run vouches for.
        idor, cases = self._analyze([_finding(principal_id="alice")],
                                    sessions=[("identity:alice", "alice")])
        self.assertEqual(idor[0].principal_id, "alice")
        self.assertEqual(cases[0].principal_id, "alice")
        self.assertEqual([r["fingerprint"] for r in self._rows()], [self._fingerprint("alice")])

    def test_a_principal_of_another_run_does_not_stand(self):
        idor, _ = self._analyze([_finding(principal_id=_MODEL_PRINCIPAL)],
                                sessions=[("identity:alice", "alice")])
        self.assertEqual(idor[0].principal_id, "")

    def test_a_tester_suppression_holds_against_a_model_chosen_identity(self):
        self._analyze([_finding()])
        (row,) = self._rows()
        store.suppress_finding(row["fingerprint"], "accepted risk")
        self.assertEqual(self._rows(), [])
        self._analyze([_finding(principal_id=_MODEL_PRINCIPAL, finding_id=_MODEL_ID)])
        self.assertEqual(self._rows(), [], "a model-chosen principal or id stepped around the suppression")


class HonouringPathNegativeControlTests(_Arc5Case):
    """The old honouring path, through the same agent-output parsing: the defects
    reappear, so the assertions above are not vacuous."""

    def test_the_old_path_collides_two_findings_on_one_case(self):
        twins = [_finding(finding_id=_MODEL_ID), _finding(finding_id=_MODEL_ID)]
        idor, cases = self._analyze(twins, defects=_honouring_path())
        self.assertEqual([f.finding_id for f in idor], [_MODEL_ID, _MODEL_ID])
        self.assertEqual(len({c.case_id for c in cases}), 1)

    def test_the_old_path_lets_a_model_principal_step_around_a_suppression(self):
        self._analyze([_finding()], defects=_honouring_path())
        (row,) = self._rows()
        store.suppress_finding(row["fingerprint"], "accepted risk")
        self._analyze([_finding(principal_id=_MODEL_PRINCIPAL)], defects=_honouring_path())
        self.assertEqual([r["fingerprint"] for r in self._rows()], [self._fingerprint(_MODEL_PRINCIPAL)])


if __name__ == "__main__":
    unittest.main()
