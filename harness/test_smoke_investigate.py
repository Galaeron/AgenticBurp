"""
End-to-end smoke test for the graph-driven investigation path and its PROACTIVE,
precondition-driven confirmation legs (HANDOVER_6 §4).

Companion to test_smoke_detection.py (which covers analyze()). That one never
exercised investigate_engagement, and NOTHING did -- the exact "green tests, dead
pipeline" shape this project has been bitten by three times. This runs the REAL
investigate_engagement pipeline (build_engagement -> worklist_investigator ->
_precondition -> shape_precondition_legs -> _confirm -> the real jwt-forge
validator) and asserts that a JWT-carrying endpoint an agent NEVER labelled "jwt"
still gets its alg:none forgery run and CONFIRMED -- the precise failure §3
documented (jwt_forge never fired where it could confirm).

Hermetic: no GPU, no model, no live target. Discovery is replaced with a canned
one-endpoint surface; the socket layer (httpx.AsyncClient.get, the only network
the jwt leg uses here) is stubbed with a vulnerable/secure responder. The
negative control (a server that actually verifies signatures) proves the test
guards CONFIRMATION, not merely that the leg ran.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import httpx
import yaml

_HARNESS = Path(__file__).resolve().parent

import store
import cache
import engagement
from orchestrator import Orchestrator
from role_crawl import RoleSession
from validators.jwt_forge_validator import _b64url_encode, _b64url_decode
import json


def _jwt(payload: dict) -> str:
    h = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.originalsig0123456789"


ORIGINAL_TOKEN = _jwt({"user_id": 4, "role": "user"})
GARBAGE_SIG = _b64url_encode(b"not-a-valid-signature-xxxx")
BASE_URL = "http://localhost"
JWT_PATH = "/api/tickets/mine"

# The single canned endpoint: JWT-carrying, NOT object-scoped, and NOT labelled
# with any finding -- so the agent probe derives nothing and only the shape-driven
# jwt leg can fire. This is the §3 case: the endpoint where alg:none is confirmable
# but no agent ever hypothesised "jwt".
_ENDPOINT = {"method": "GET", "path": JWT_PATH, "by_role": {"user": 200, "anonymous": 401},
             "reachable_roles": ["user"], "object_scoped": False}

ROLES = [RoleSession("anonymous", {}),
         RoleSession("user", {"Authorization": f"Bearer {ORIGINAL_TOKEN}"})]


def _auth_of(headers) -> str:
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie"):
            return v or ""
    return ""


def _responder(vulnerable: bool):
    """Stub for httpx.AsyncClient.get. A patched class method is called WITHOUT
    self, so the signature is (url, headers=..., **kw)."""
    async def _get(url, headers=None, **kw):
        req = httpx.Request("GET", str(url))
        if JWT_PATH not in str(url):
            return httpx.Response(404, content=b"", request=req)
        auth = _auth_of(headers)
        if GARBAGE_SIG in auth:
            return httpx.Response(401, content=b"forbidden", request=req)   # control: rejected
        if vulnerable:
            # Broken verifier: ANY JWT (forged alg:none included) is accepted.
            if "eyJ" in auth:
                return httpx.Response(200, content=b'{"tickets":["mine"]}', request=req)
            return httpx.Response(401, content=b"forbidden", request=req)
        # Secure verifier: only the exact, legitimately-signed token is accepted.
        if ORIGINAL_TOKEN in auth:
            return httpx.Response(200, content=b'{"tickets":["mine"]}', request=req)
        return httpx.Response(401, content=b"forbidden", request=req)
    return _get


def _test_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = True          # the legs send live (here: stubbed) requests
    validators["allow_mutating_replay"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["localhost", "127.0.0.1"]
    return cfg


def _canned_engagement(base_url, roles, **kw):
    """Stand-in for engagement_builder.build_engagement: a real EngagementState
    holding the one canned endpoint, plus a role-crawl result with no findings."""
    state = engagement.EngagementState(host="localhost")
    state.ingest_role_crawl({"endpoints": [dict(_ENDPOINT)], "idor_findings": []})
    for r in roles:
        state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
    rc = SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[])
    return state, rc


class InvestigateProactiveJwtSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="smoke_investigate_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, vulnerable: bool, drive: bool = False, max_nodes: int = 4,
             case_drive: bool = False):
        orch = Orchestrator(_test_config())
        if drive or case_drive:
            orch.engagement_coverage_drive = True  # I1 matrix-driver on
        if case_drive:
            orch.engagement_coverage_case_drive = True  # T05: per-input case driving
        # No agent probe should be needed (the node derives no specialty), but stub
        # it so a stray derivation can't reach for a real model.
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        with patch("engagement_builder.build_engagement", side_effect=_canned_engagement), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_responder(vulnerable)):
            return asyncio.run(orch.investigate_engagement(
                BASE_URL, ROLES, max_nodes=max_nodes, step_budget=4, max_chain_rounds=0))

    def _worklist_confirmed_jwt(self, result):
        """Confirmed jwt findings attached to endpoints in state (the finding
        pipeline), as opposed to the worklist-investigation outcomes."""
        out = []
        for ep in result.get("worklist", []):
            for f in ep.get("findings", []):
                if f.get("confirmed") and "jwt" in (f.get("vulnerability_class") or "").lower():
                    out.append(f)
        return out

    def _confirmed_jwt(self, result):
        return [f for o in result.get("outcomes", []) for f in o.get("findings_detail", [])
                if f.get("confirmed") and "jwt" in (f.get("vulnerability_class") or "").lower()]

    def test_proactive_jwt_forge_confirms_on_unlabelled_endpoint(self):
        result = self._run(vulnerable=True)
        confirmed = self._confirmed_jwt(result)
        self.assertTrue(
            confirmed,
            "PROACTIVE CONFIRMATION IS DEAD: a JWT-carrying endpoint with a broken "
            "alg:none verifier was investigated, but the shape-driven jwt-forge leg "
            "never produced a confirmed finding -- the §4 routing is not reaching the "
            "validator end-to-end through investigate_engagement.")
        # It was proven from the low-trust 'user' identity, and it's a real confirm.
        self.assertTrue(any(f.get("confidence", 0) >= 0.9 for f in confirmed))

    def test_coverage_matrix_is_filled_end_to_end(self):
        # The coverage cell-filler must actually run inside investigate_engagement
        # (I1/I2/I5): a real run produces a matrix with the JWT check confirmed and
        # an auditable "not tested + reason" list -- not an empty stub.
        result = self._run(vulnerable=True)
        cov = result.get("coverage") or {}
        self.assertTrue(cov, "coverage matrix was not built by investigate_engagement")
        self.assertGreater(cov.get("total_cells", 0), 0)
        self.assertGreaterEqual(cov.get("confirmed", 0), 1,
                                "the confirmed JWT forge did not fill a CONFIRMED coverage cell")
        # WSTG-CRYP-04 is the JWT check; it must show a confirmed cell.
        jwt_check = cov.get("by_check", {}).get("WSTG-CRYP-04", {})
        self.assertGreaterEqual(jwt_check.get("confirmed", 0), 1)
        # every not-tested cell carries a reason (the audit guarantee)
        self.assertTrue(all(nt.get("reason") for nt in cov.get("not_tested", [])))

    def test_coverage_driver_fires_legs_end_to_end(self):
        # I1: with the matrix-driver on, investigate_engagement actively fires the
        # applicable deterministic legs (regardless of any agent label) and records
        # them -- coverage.legs_driven proves the drive path ran end-to-end, and the
        # JWT check still lands CONFIRMED.
        result = self._run(vulnerable=True, drive=True)
        cov = result.get("coverage") or {}
        self.assertGreaterEqual(cov.get("legs_driven", 0), 1,
                                "coverage driver did not fire any legs end-to-end")
        self.assertGreaterEqual(cov.get("by_check", {}).get("WSTG-CRYP-04", {}).get("confirmed", 0), 1)

    def test_coverage_driver_confirmation_reaches_findings_not_just_matrix(self):
        """R06: a matrix-driven confirmation must enter the finding pipeline, not
        live only in the coverage matrix. With max_nodes=0 the worklist path never
        runs, so the ONLY way a confirmed JWT finding reaches state is the coverage
        driver ingesting it (the R06 fix). Prove it appears in BOTH the matrix and
        the state findings."""
        result = self._run(vulnerable=True, drive=True, max_nodes=0)
        cov = result.get("coverage") or {}
        self.assertGreaterEqual(cov.get("by_check", {}).get("WSTG-CRYP-04", {}).get("confirmed", 0), 1,
                                "coverage driver did not confirm the JWT check with the worklist off")
        # The same confirmation is now a real finding on the endpoint in state.
        self.assertTrue(
            self._worklist_confirmed_jwt(result),
            "R06 REGRESSION: a coverage-driven confirmation filled a matrix cell but "
            "never entered the finding pipeline -- the confirmed JWT forge is absent "
            "from state's endpoint findings.")

    def test_coverage_driver_negative_control_no_matrix_only_finding(self):
        """Negative control for R06: a secure server yields no coverage-driven
        confirmation, so nothing is injected into the findings either."""
        result = self._run(vulnerable=False, drive=True, max_nodes=0)
        self.assertEqual(self._worklist_confirmed_jwt(result), [])

    @staticmethod
    def _proof_rows():
        """All persisted proof rows (run_id, case_id, check_id, param loc/name,
        verdict) -- read straight from the store DB the test scoped to a temp file."""
        import store
        conn = store._connect()
        try:
            return conn.execute(
                "SELECT run_id, case_id, check_id, parameter_location, parameter_name, "
                "verdict FROM proof_records").fetchall()
        finally:
            conn.close()

    def test_coverage_case_driver_binds_case_proofs_end_to_end(self):
        """T05/R26 end-to-end: with case driving on, the coverage DRIVER runs its
        legs and each one persists a CASE-BOUND proof (stable run_id + case_id) to
        the T01 store -- proving a coverage-driven attempt flows a case id to the
        proof store, not merely a matrix cell. (The JWT here is confirmed by the
        separate PROACTIVE path, so the driver's own legs are the coverage
        cross_identity/auth_sequence attempts.)"""
        before = len(self._proof_rows())
        result = self._run(vulnerable=True, case_drive=True, max_nodes=0)
        cov = result.get("coverage") or {}
        self.assertIn("cases_driven", cov, "case-driven coverage path did not run")
        self.assertGreaterEqual(cov.get("cases_enumerated", 0), 1)
        self.assertGreaterEqual(cov.get("cases_driven", 0), 1)
        rows = self._proof_rows()[before:]
        self.assertTrue(rows, "the case-driven path persisted no proof records")
        # every coverage-driven proof carries a real run + case identity
        self.assertTrue(all(r[0] and r[1] and r[2] for r in rows),
                        "a coverage-driven proof has an empty run_id/case_id/check_id")

    def test_coverage_case_driver_reports_pending_cases_honestly(self):
        """T05: the case-granular report exposes an honest per-case not-tested list;
        every entry carries a reason (the I5 audit guarantee at case granularity)."""
        result = self._run(vulnerable=True, case_drive=True)
        cov = result.get("coverage") or {}
        self.assertIn("cases_not_tested", cov)
        self.assertTrue(all(c.get("reason") for c in cov.get("cases_not_tested", [])))

    def test_coverage_case_driver_never_fabricates_a_confirmed_proof(self):
        """Negative control: a secure server yields no coverage-driven confirmation,
        so the driven legs persist only non-confirmed (inconclusive) proofs -- the
        case path never fabricates a confirmed verdict."""
        before = {r[1] for r in self._proof_rows()}  # case_ids seen before
        self._run(vulnerable=False, case_drive=True, max_nodes=0)
        # No proof minted in THIS run (not seen before) may be 'confirmed'.
        for run_id, case_id, check_id, ploc, pname, verdict in self._proof_rows():
            if case_id not in before:
                self.assertNotEqual(verdict, "confirmed",
                                    f"case path fabricated a confirmed proof for {check_id}")

    def test_operational_failure_is_surfaced_as_degraded(self):
        # R30: a phase that blows up is caught (never sinks the run) but must be
        # SURFACED -- the result declares degraded + records the error, rather than
        # looking like a clean run that silently skipped coverage.
        import coverage_tracker
        with patch.object(coverage_tracker, "build_coverage", side_effect=RuntimeError("boom")):
            result = self._run(vulnerable=True)
        self.assertTrue(result.get("degraded"))
        self.assertTrue(any(e.get("phase") == "coverage_build" for e in result.get("errors", [])))

    def test_clean_run_is_not_degraded(self):
        result = self._run(vulnerable=True)
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result.get("errors"), [])

    def test_negative_control_secure_server_yields_no_confirmation(self):
        # A server that actually verifies signatures must NOT be confirmed -- proving
        # the test guards CONFIRMATION, not merely that the leg executed.
        result = self._run(vulnerable=False)
        self.assertEqual(
            self._confirmed_jwt(result), [],
            "Smoke test is not testing confirmation: a secure (signature-verifying) "
            "server was still reported as a confirmed JWT forgery.")


class CoverageProofCoordinatesTest(unittest.TestCase):
    """T05/R26: the coverage-driven proof carries the CONCRETE parameter case
    coordinates, so a per-parameter coverage confirmation is a per-parameter T01
    proof (not an endpoint-wide one). Focused unit test of Orchestrator._coverage_proof."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="cov_proof_")
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_parameter_case_coordinates_reach_the_proof(self):
        from coverage_model import CHECKS_BY_ID, CaseKey
        orch = Orchestrator(_test_config())
        check = CHECKS_BY_ID["WSTG-INPV-05"]  # SQLi, parameter phase
        ex = SimpleNamespace(method="POST", url="http://localhost/api/search",
                             request_body="search=x&sort=y")
        res = SimpleNamespace(validator="sqlmap", status="confirmed", confirmed=True,
                              summary="injection at search", evidence="' OR 1=1", confidence=0.99)
        ck = CaseKey("query", "search", 0, "", "search")
        proof_id, case_id = asyncio.run(orch._coverage_proof(
            identity="user", check=check, exchange=ex, result=res, case_key=ck))
        self.assertTrue(proof_id and case_id)
        rows = store.proofs_for_case(case_id)
        self.assertTrue(rows, "coverage proof was not persisted")
        case = rows[0]["case"]
        self.assertEqual(case["parameter_location"], "query")
        self.assertEqual(case["parameter_name"], "search")
        self.assertEqual(case["check_id"], "WSTG-INPV-05")
        self.assertEqual(case["principal_id"], "user")
        self.assertEqual(rows[0]["verdict"], "confirmed")

    def test_repeated_occurrence_folds_into_proof_name(self):
        from coverage_model import CHECKS_BY_ID, CaseKey
        orch = Orchestrator(_test_config())
        check = CHECKS_BY_ID["WSTG-INPV-05"]
        ex = SimpleNamespace(method="GET", url="http://localhost/x?id=1&id=2", request_body="")
        res = SimpleNamespace(validator="sqlmap", status="not_confirmed", confirmed=False,
                              summary="", evidence="", confidence=0.0)
        _, case0 = asyncio.run(orch._coverage_proof(
            identity="user", check=check, exchange=ex, result=res, case_key=CaseKey("query", "id", 0)))
        _, case1 = asyncio.run(orch._coverage_proof(
            identity="user", check=check, exchange=ex, result=res, case_key=CaseKey("query", "id", 1)))
        self.assertNotEqual(case0, case1)  # occurrence -> distinct proof cases
        self.assertEqual(store.proofs_for_case(case1)[0]["case"]["parameter_name"], "id[1]")


if __name__ == "__main__":
    unittest.main()
