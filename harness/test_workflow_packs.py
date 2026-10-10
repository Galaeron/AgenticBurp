"""SC-11: versioned workflow/chain data packs -- strict schema + fixtures.

Covers the four acceptance criteria, each with a positive case AND a negative
control:

  1. deterministic compile/validate command
     (CompileValidateTests, ShippedPackTests, CommandTests)
  2. unknown fields/assertions rejected (SC-4)  (StrictSchemaTests)
  3. cyclic prerequisites rejected              (StrictSchemaTests)
  4. a vulnerable and a patched fixture reach OPPOSITE final evidence states
     through the real engagement caller execute_declared_workflows
     (OppositeFixtureTests, FingerprintGateTests)
"""
from __future__ import annotations

import asyncio
import copy
import json
import unittest
from types import SimpleNamespace

from harness import engagement_builder, workflow_engine, workflow_packs
from harness.workflow_packs import (
    PackEvidenceState, compile_pack, run_pack, validate_pack,
)


# --------------------------------------------------------------------------
# Fixture server doubles: a route-based executor so a vulnerable and a patched
# "server" differ only in the escalate response, and the fingerprint endpoint
# can be made to (mis)match. Same shape as test_workflow_engine._Executor.
# --------------------------------------------------------------------------
def _out(status=200, body="", headers=None, outcome="ok"):
    return SimpleNamespace(ok=outcome == "ok", outcome=outcome, status=status,
                           body=body, headers=headers or {},
                           final_url="http://shop.test/x", error="",
                           artifact=SimpleNamespace(artifact_id=f"a-{status}"))


class _RouteExecutor:
    """Return the first (method, url-substring) route that matches; records
    every dispatched (method, url) so a test can prove the fingerprint gate
    halted before the workflow ran."""

    def __init__(self, routes):
        self.routes = routes  # ordered list of ((method, substr), outcome)
        self.calls: list[tuple[str, str]] = []

    async def execute(self, request, **kwargs):
        self.calls.append((request.method, request.url))
        for (method, substr), outcome in self.routes:
            if request.method == method and substr in request.url:
                return outcome
        return _out(404)  # transport-ok 404 for an unrouted request


class _Ctx:
    def __init__(self, *, app="shop-api", approve_status=200):
        routes = [
            (("GET", "/health"), _out(200, json.dumps({"app": app}))),
            (("POST", "/approve"), _out(approve_status,
                                        json.dumps({"approved": approve_status == 200}))),
            (("POST", "/orders"), _out(201, json.dumps({"id": 7}))),
            (("DELETE", "/orders"), _out(204)),
        ]
        self._executor = _RouteExecutor(routes)
        self.cancel = SimpleNamespace(cancelled=False)

    def executor(self):
        return self._executor


# A self-contained, valid pack dict used as the base for schema tests (mirrors
# the shipped bola-order-approve pack, kept inline so tests stay independent).
_BASE_PACK = {
    "pack_id": "bola-order-approve",
    "schema_version": 1,
    "engine_min": 1,
    "engine_max": 1,
    "taxonomy": "A01:Broken-Access-Control",
    "required_capabilities": ["workflow"],
    "impact": {"severity": "high", "scope": "cross-principal", "cwe": "CWE-639"},
    "fingerprint": {
        "method": "GET", "url_template": "http://shop.test/health",
        "session_ref": "probe",
        "assertions": [{"kind": "body_contains", "expected": "shop-api"}],
    },
    "proof_contract": {
        "proof_step": "escalate", "proven_status": "passed",
        "refuted_statuses": ["failed", "blocked"],
    },
    "negative_fixture": {
        "description": "patched build denies non-manager approve with 403",
        "expected_state": "refuted",
    },
    "cleanup_contract": {"required_steps": ["cleanup"]},
    "workflow": {
        "id": "bola-order-approve", "version": 1,
        "invariant": "only a manager principal may approve an order",
        "steps": [
            {"id": "create", "method": "POST", "url_template": "http://shop.test/orders",
             "session_ref": "user", "body_template": "{\"item\": \"widget\"}",
             "extractors": [{"name": "id", "kind": "json_pointer", "expression": "/id"}]},
            {"id": "escalate", "method": "POST",
             "url_template": "http://shop.test/orders/{{id}}/approve",
             "session_ref": "user", "prerequisites": ["create"],
             "assertions": [{"kind": "status", "expected": 200}]},
            {"id": "cleanup", "method": "DELETE",
             "url_template": "http://shop.test/orders/{{id}}",
             "session_ref": "user", "prerequisites": ["create"], "cleanup": True},
        ],
    },
}


def _pack_dict():
    return copy.deepcopy(_BASE_PACK)


# --------------------------------------------------------------------------
# Criterion 1: deterministic compile/validate
# --------------------------------------------------------------------------
class CompileValidateTests(unittest.TestCase):
    def test_base_pack_compiles(self):
        pack = compile_pack(_pack_dict())
        self.assertEqual(pack.pack_id, "bola-order-approve")
        self.assertEqual(pack.taxonomy, "A01:Broken-Access-Control")
        self.assertEqual(pack.proof_contract.proof_step, "escalate")
        self.assertEqual({s.id for s in pack.workflow.steps}, {"create", "escalate", "cleanup"})

    def test_validate_is_deterministic(self):
        data = _pack_dict()
        r1 = validate_pack(data)
        r2 = validate_pack(copy.deepcopy(data))
        self.assertEqual(r1, (True, []))
        self.assertEqual(r1, r2)
        # A broken pack yields the SAME single error on repeat runs.
        broken = _pack_dict()
        broken["surprise"] = 1
        b1 = validate_pack(broken)
        b2 = validate_pack(copy.deepcopy(broken))
        self.assertFalse(b1[0])
        self.assertEqual(b1, b2)


# --------------------------------------------------------------------------
# Criteria 2 & 3: strict schema -- unknown fields/assertions + cycles rejected
# --------------------------------------------------------------------------
class StrictSchemaTests(unittest.TestCase):
    def _assert_rejected(self, data, needle):
        ok, errors = validate_pack(data)
        self.assertFalse(ok, f"expected rejection for {needle!r}")
        self.assertTrue(any(needle in e for e in errors),
                        f"error {errors} did not mention {needle!r}")

    def test_unknown_top_level_field_rejected(self):
        data = _pack_dict(); data["bogus"] = 1
        self._assert_rejected(data, "unknown field")

    def test_unknown_step_field_rejected(self):
        data = _pack_dict(); data["workflow"]["steps"][0]["bogus"] = 1
        self._assert_rejected(data, "unknown field")

    def test_unknown_extractor_field_rejected(self):
        data = _pack_dict()
        data["workflow"]["steps"][0]["extractors"][0]["bogus"] = 1
        self._assert_rejected(data, "unknown field")

    def test_unknown_assertion_field_rejected(self):
        data = _pack_dict()
        data["workflow"]["steps"][1]["assertions"][0]["bogus"] = 1
        self._assert_rejected(data, "unknown field")

    def test_unknown_fingerprint_field_rejected(self):
        data = _pack_dict(); data["fingerprint"]["bogus"] = 1
        self._assert_rejected(data, "unknown field")

    def test_unknown_assertion_kind_rejected_sc4(self):
        data = _pack_dict()
        data["workflow"]["steps"][1]["assertions"][0]["kind"] = "telepathy"
        self._assert_rejected(data, "unknown assertion kind")

    def test_unknown_fingerprint_assertion_kind_rejected_sc4(self):
        data = _pack_dict()
        data["fingerprint"]["assertions"][0]["kind"] = "telepathy"
        self._assert_rejected(data, "unknown assertion kind")

    def test_cyclic_prerequisites_rejected(self):
        data = _pack_dict()
        data["workflow"]["steps"] = [
            {"id": "a", "method": "GET", "url_template": "http://shop.test/a",
             "session_ref": "user", "prerequisites": ["b"]},
            {"id": "b", "method": "GET", "url_template": "http://shop.test/b",
             "session_ref": "user", "prerequisites": ["a"]},
        ]
        data["proof_contract"]["proof_step"] = "a"
        data["cleanup_contract"] = {}
        self._assert_rejected(data, "cyclic prerequisites")

    def test_unsupported_schema_version_rejected(self):
        data = _pack_dict(); data["schema_version"] = 999
        self._assert_rejected(data, "unsupported schema_version")

    def test_engine_out_of_range_rejected(self):
        data = _pack_dict(); data["engine_min"] = 2; data["engine_max"] = 3
        self._assert_rejected(data, "outside supported range")

    def test_proof_step_must_be_a_workflow_step(self):
        data = _pack_dict(); data["proof_contract"]["proof_step"] = "ghost"
        self._assert_rejected(data, "not a workflow step")

    def test_proof_step_may_not_be_cleanup(self):
        data = _pack_dict(); data["proof_contract"]["proof_step"] = "cleanup"
        self._assert_rejected(data, "cleanup step")

    def test_invalid_proof_status_rejected(self):
        data = _pack_dict(); data["proof_contract"]["proven_status"] = "vibes"
        self._assert_rejected(data, "valid step status")

    def test_negative_fixture_expected_state_validated(self):
        data = _pack_dict(); data["negative_fixture"]["expected_state"] = "maybe"
        self._assert_rejected(data, "expected_state")

    def test_cleanup_contract_requires_real_cleanup_step(self):
        data = _pack_dict(); data["cleanup_contract"]["required_steps"] = ["escalate"]
        self._assert_rejected(data, "not a cleanup step")

    def test_forward_prerequisite_still_rejected_by_engine(self):
        # Non-cyclic but out-of-order: engine's own contract rejects it (SC-4 era).
        data = _pack_dict()
        data["workflow"]["steps"] = [
            {"id": "second", "method": "GET", "url_template": "http://shop.test/2",
             "session_ref": "user", "prerequisites": ["first"]},
            {"id": "first", "method": "GET", "url_template": "http://shop.test/1",
             "session_ref": "user"},
        ]
        data["proof_contract"]["proof_step"] = "second"
        data["cleanup_contract"] = {}
        ok, _ = validate_pack(data)
        self.assertFalse(ok)


# --------------------------------------------------------------------------
# Criterion 4: opposite evidence states through the REAL engagement caller
# --------------------------------------------------------------------------
class OppositeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.pack = compile_pack(_pack_dict())

    def test_real_caller_yields_opposite_completion_for_vuln_vs_patched(self):
        vuln = _Ctx(approve_status=200)
        patched = _Ctx(approve_status=403)
        [r_vuln] = asyncio.run(
            engagement_builder.execute_declared_workflows([self.pack.workflow], vuln))
        [r_patched] = asyncio.run(
            engagement_builder.execute_declared_workflows([self.pack.workflow], patched))
        # Opposite final evidence states, produced by the real caller.
        self.assertTrue(r_vuln.complete)
        self.assertFalse(r_patched.complete)
        self.assertEqual(self.pack.classify(r_vuln), PackEvidenceState.PROVEN)
        self.assertEqual(self.pack.classify(r_patched), PackEvidenceState.REFUTED)

    def test_run_pack_end_to_end_vuln_proven_patched_refuted(self):
        proven = asyncio.run(run_pack(self.pack, _Ctx(approve_status=200)))
        refuted = asyncio.run(run_pack(self.pack, _Ctx(approve_status=403)))
        self.assertEqual(proven.state, PackEvidenceState.PROVEN)
        self.assertTrue(proven.fingerprint_matched)
        self.assertEqual(refuted.state, PackEvidenceState.REFUTED)
        # The patched outcome matches the pack's declared negative fixture.
        self.assertEqual(refuted.state.value, self.pack.negative_fixture["expected_state"])

    def test_classify_maps_proof_step_status(self):
        Result = workflow_engine.WorkflowResult
        SR = workflow_engine.StepResult
        SS = workflow_engine.StepStatus
        proven = Result("w", 1, steps=[SR("escalate", SS.PASSED)])
        refuted = Result("w", 1, steps=[SR("escalate", SS.FAILED)])
        missing = Result("w", 1, steps=[SR("create", SS.PASSED)])
        self.assertEqual(self.pack.classify(proven), PackEvidenceState.PROVEN)
        self.assertEqual(self.pack.classify(refuted), PackEvidenceState.REFUTED)
        self.assertEqual(self.pack.classify(missing), PackEvidenceState.INCONCLUSIVE)


class FingerprintGateTests(unittest.TestCase):
    def setUp(self):
        self.pack = compile_pack(_pack_dict())

    def test_fingerprint_mismatch_halts_before_workflow_dispatch(self):
        ctx = _Ctx(app="some-other-app", approve_status=200)  # would be PROVEN if it ran
        run = asyncio.run(run_pack(self.pack, ctx))
        self.assertEqual(run.state, PackEvidenceState.FINGERPRINT_MISMATCH)
        self.assertFalse(run.fingerprint_matched)
        self.assertIsNone(run.workflow_result)
        # Programmatic halt: only the fingerprint probe was ever dispatched.
        self.assertEqual(len(ctx.executor().calls), 1)
        method, url = ctx.executor().calls[0]
        self.assertEqual(method, "GET")
        self.assertIn("/health", url)

    def test_fingerprint_match_allows_workflow_dispatch(self):
        ctx = _Ctx(app="shop-api", approve_status=200)
        run = asyncio.run(run_pack(self.pack, ctx))
        self.assertTrue(run.fingerprint_matched)
        self.assertEqual(run.state, PackEvidenceState.PROVEN)
        # Fingerprint GET + the three workflow steps were dispatched.
        self.assertGreater(len(ctx.executor().calls), 1)


# --------------------------------------------------------------------------
# Criterion 1 (cont.): the shipped pack(s) + the command
# --------------------------------------------------------------------------
class ShippedPackTests(unittest.TestCase):
    def test_at_least_one_pack_ships_and_all_compile(self):
        paths = workflow_packs.shipped_pack_paths()
        self.assertTrue(paths, "expected at least one shipped *.pack.json")
        packs = workflow_packs.load_shipped_packs()
        self.assertEqual(len(packs), len(paths))
        for pack in packs:
            self.assertEqual(pack.schema_version, workflow_packs.PACK_SCHEMA_VERSION)

    def test_shipped_pack_file_matches_inline_base(self):
        # Guards the inline _BASE_PACK against STRUCTURAL drift from the shipped
        # data file (free-text negative_fixture.description is prose, not
        # structure, so it is normalised out before comparing).
        paths = workflow_packs.shipped_pack_paths()
        with open(paths[0], "r", encoding="utf-8") as f:
            shipped = json.load(f)

        def _structure(pack_dict):
            d = compile_pack(pack_dict).to_dict()
            d["negative_fixture"] = {k: v for k, v in d["negative_fixture"].items()
                                     if k != "description"}
            return d

        self.assertEqual(_structure(shipped), _structure(_pack_dict()))


class CommandTests(unittest.TestCase):
    def test_command_passes_for_shipped_packs(self):
        self.assertEqual(workflow_packs.main([]), 0)

    def test_command_fails_for_an_invalid_pack(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.pack.json"
            data = _pack_dict(); data["nope"] = True
            bad.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(workflow_packs.main([str(bad)]), 1)


if __name__ == "__main__":
    unittest.main()
