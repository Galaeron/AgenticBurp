"""Discovery-to-confirmation integration against an advertised loopback fixture.

Runs real surface discovery, role crawl, worklist and cross-identity confirmation.
The model is silent and ffuf is disabled. Paired vulnerable/secure controls test
confirmation; defect injection must detect starved discovery, dropped methods and
suppressed confirmation. This proves these fixture paths, not live-target recall.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

_HARNESS = Path(__file__).resolve().parent

from harness import store
from harness import cache
from harness import evidence_ledger
from harness import global_throttle
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.ollama_client import OllamaResult
from harness.testing_fixtures.discovery_pipeline import DiscoveryPipelineFixture


class _SilentModel:
    """Stand-in for OllamaClient that returns nothing. This is the ONLY stubbed
    boundary: the gate keeps discovery, transport and confirmation real, and stubs
    just the model (the audit's "stub only the model boundary for determinism").

    A silent model is the honest choice here -- the IDOR the gate confirms comes
    from the deterministic shape-driven cross-identity leg, NOT from an LLM guess,
    so removing the model must not remove the confirmation. It also stops
    review_captured_exchanges from firing the real Ollama model at localhost:11434
    for every discovered 2xx, which is what made an un-stubbed run take minutes."""

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data={"findings": [], "components": []},
                            prompt_tokens=1, completion_tokens=1)


def _install_silent_model(orch: Orchestrator) -> None:
    stub = _SilentModel()
    orch.ollama = stub
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub

# A constrained discovery budget: big enough that the spec-probe phase (which runs
# first) finds /openapi.json and the object route, small enough that the wordlist
# sweep stays fast. The gate deliberately uses a *constrained* budget -- the audit's
# canonical scenario -- so "the route was found" means real discovery found it, not
# that an unbounded sweep eventually stumbled on it.
DISCOVERY_PROBES = 80
ALLOWED = ["127.0.0.1", "localhost"]

ROLES = [
    RoleSession("anonymous", {}),
    RoleSession("alice", {"Authorization": "Bearer alice-token"}),
    RoleSession("bob", {"Authorization": "Bearer bob-token"}),
]


def _gate_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    v = cfg.setdefault("validators", {})
    v["active_enabled"] = True            # the shape-driven legs send live (loopback) requests
    v["allow_mutating_replay"] = True     # allow the write-bearing legs through the gate
    for k in ("autonomous_discovery", "github_advisories", "kev_check",
              "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("engagement", {})["feature_crawl"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = list(ALLOWED)
    return cfg


class _PipelineRun:
    """One end-to-end investigate_engagement run against the fixture, with the model
    boundary stubbed and ffuf disabled. `defect` optionally patches a piece of the
    real pipeline to reintroduce a known regression."""

    def __init__(self, mode: str, *, probes: int = DISCOVERY_PROBES, defect=None):
        self.mode = mode
        self.probes = probes
        self.defect = defect

    def run(self) -> tuple[dict, DiscoveryPipelineFixture]:
        """Run and tear down before returning: store._DB_PATH/cache._cache are
        back on the shared dev DB, and the run's temp DB is deleted, by the
        time the caller gets the result. Fine for callers that only look at
        the in-memory result dict/fixture. A caller that also needs to read
        the run's OWN store/evidence_ledger state (proofs_for_case,
        reconstruct_persisted, a raw store._connect() query, ...) must use
        run_live() instead and do those reads inside the `with` block --
        after this method returns, that data lives in a deleted temp dir and
        store._DB_PATH points back at the polluted shared dev DB."""
        with self.run_live() as (result, fx):
            return result, fx

    @contextlib.contextmanager
    def run_live(self):
        """Same run as run(), but stays open as a context manager so the
        caller can inspect store/evidence_ledger state while this run's own
        temp DB is still live -- i.e. while store._DB_PATH/cache._cache still
        point at it, before teardown restores the shared dev DB and deletes
        the temp dir. Do any store/evidence_ledger persistence assertions
        inside the `with` block; outside it they would read the shared,
        already-polluted dev DB (harness/harness_state.db) instead of this
        run's own database."""
        tmp = tempfile.mkdtemp(prefix="pipeline_gate_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(tmp, "cache.db"))
        # Disable the global request throttle for the run so a real loopback sweep
        # is not paced to a live-target rate (the mass_assignment slice does the
        # same); restored in the finally. This is what keeps the gate to seconds.
        _tstats = global_throttle.throttle.stats()
        _prev_rate = _tstats["rate_per_second"] if _tstats["enabled"] else 0.0
        _prev_burst = _tstats["burst"] if _tstats["enabled"] else None
        global_throttle.configure(0)
        fx = DiscoveryPipelineFixture(self.mode)
        try:
            orch = Orchestrator(_gate_config())
            orch.allowed_hosts = list(ALLOWED)
            _install_silent_model(orch)   # the only stubbed boundary
            orch.run_active_probe = AsyncMock(return_value={
                "iterative_result": {"stop_reason": "gave_up", "findings": []},
                "integration": {}})
            stack = [
                patch("harness.ffuf_runner.ffuf_available",
                      return_value=(False, "ffuf disabled for the pipeline gate")),
            ]
            if self.defect is not None:
                stack.append(self.defect())
            with _nest(stack):
                result = asyncio.run(orch.investigate_engagement(
                    fx.base, ROLES, max_nodes=8, step_budget=4,
                    max_chain_rounds=0, discovery_max_probes=self.probes))
            yield result, fx
        finally:
            fx.close()
            global_throttle.configure(_prev_rate, _prev_burst)
            store._DB_PATH, cache._cache = orig_db, orig_cache
            shutil.rmtree(tmp, ignore_errors=True)


class _nest:
    """Enter a list of context managers together (py<3.10-friendly, explicit)."""
    def __init__(self, mgrs):
        self._mgrs = mgrs
        self._entered = []

    def __enter__(self):
        for m in self._mgrs:
            m.__enter__()
            self._entered.append(m)
        return self

    def __exit__(self, *exc):
        for m in reversed(self._entered):
            m.__exit__(*exc)
        return False


# --- readers over the investigation result -------------------------------------

def _nodes(result: dict) -> list[dict]:
    return result.get("worklist", []) or []


def _node(result: dict, method: str, path_contains: str) -> dict | None:
    for ep in _nodes(result):
        if (ep.get("method") or "").upper() == method and path_contains in (ep.get("path") or ""):
            return ep
    return None


def _surface(result: dict) -> set[tuple[str, str]]:
    """The (method, path) surface real discovery actually built into the worklist."""
    return {((ep.get("method") or "").upper(), ep.get("path") or "") for ep in _nodes(result)}


def _confirmed_idor(result: dict) -> list[dict]:
    out = []
    for ep in _nodes(result):
        if "/api/notes/{id}" not in (ep.get("path") or ""):
            continue
        for f in ep.get("findings", []) or []:
            vc = (f.get("vulnerability_class") or "").lower()
            if f.get("confirmed") and ("idor" in vc or "authorization" in vc or "bola" in vc):
                out.append(f)
    return out


class RealPipelineGateTest(unittest.TestCase):
    """The positive gate: real discovery -> real confirmation, against a fixture the
    harness has to DISCOVER on its own."""

    def test_real_discovery_builds_the_get_post_and_object_surface(self):
        """Discovery liveness: with only /openapi.json advertised, the REAL discovery
        sweep must recover the object-scoped GET, the collection GET, and the POST --
        method and all. This is the exact thing the mocked smoke tests cannot check,
        and the exact failure pattern (dropped route/method) that has bitten this
        project."""
        result, fx = _PipelineRun("vulnerable").run()
        try:
            self.assertFalse(result.get("degraded"), f"run degraded: {result.get('errors')}")
            surface = _surface(result)
            obj = _node(result, "GET", "/api/notes/{id}")
            self.assertIsNotNone(
                obj, f"REAL DISCOVERY DROPPED THE OBJECT ROUTE: GET /api/notes/{{id}} is "
                     f"absent from the discovered surface {sorted(surface)}")
            self.assertTrue(obj.get("object_scoped"),
                            "the object route was found but not marked object_scoped, so the "
                            "cross-identity leg will never fire on it")
            self.assertIsNotNone(
                _node(result, "GET", "/api/notes"),
                f"discovery dropped the collection GET /api/notes: {sorted(surface)}")
            self.assertIsNotNone(
                _node(result, "POST", "/api/notes"),
                f"DISCOVERY DROPPED THE POST METHOD: POST /api/notes is absent from "
                f"{sorted(surface)} -- the exact method-loss regression this gate guards")
            # The fixture actually served the spec + the object route to the harness.
            hit = set(fx.paths())
            self.assertIn("/openapi.json", hit, "the harness never fetched the advertised spec")
            self.assertIn("/api/notes/1", hit, "the harness never probed the object route it found")
        finally:
            pass

    def test_real_pipeline_confirms_idor_end_to_end(self):
        """The whole chain: real discovery of the object route -> the shape-driven
        cross-identity leg -> a CONFIRMED IDOR in the investigation result. No model,
        no seeded endpoint. If this is red, the pipeline no longer turns a discovered
        object route into a confirmed access-control break."""
        result, fx = _PipelineRun("vulnerable").run()
        confirmed = _confirmed_idor(result)
        self.assertTrue(
            confirmed,
            "END-TO-END PIPELINE IS DEAD: a discovered object-scoped route with a broken "
            "object-level authorization check produced NO confirmed IDOR. Something between "
            "real discovery and the cross-identity confirmation leg is dropping it.")
        self.assertTrue(any(f.get("confirmed") for f in confirmed))

    def test_negative_control_patched_fixture_is_not_confirmed(self):
        """Proves the gate tests CONFIRMATION, not merely that the leg ran: the patched
        fixture (which enforces ownership) must yield no confirmed IDOR, even though the
        same route is discovered and the same leg runs."""
        result, fx = _PipelineRun("patched").run()
        # The route is still discovered in patched mode ...
        self.assertIsNotNone(_node(result, "GET", "/api/notes/{id}"),
                             "precondition: the object route must still be discovered in patched mode")
        # ... but the crossing must NOT confirm.
        self.assertEqual(
            _confirmed_idor(result), [],
            "GATE IS NOT TESTING CONFIRMATION: the patched (ownership-enforcing) fixture "
            "was still reported as a confirmed IDOR.")

    def test_engagement_confirmed_idor_persists_proof_and_ledger(self):
        """RB-4/INV-2 acceptance test: a confirmed=True finding produced by the
        ENGAGEMENT path (orchestrator_chain._apply, the graph-loop/PASS2
        confirmation -- NOT orchestrator_confirm._validate_findings/PASS1) must
        resolve to a persisted ProofRecord AND a durable evidence_ledger
        VALIDATION_DECISION -- exactly like PASS1 -- not merely a free-text
        evidence stamp. Before RB-4 this is the documented INV-2 gap
        (docs/investigations/INV-2-proof-gap.md): GT04/05/06 dropped from the
        proof-linked audit because this exact path never persisted a proof."""
        # store/evidence_ledger reads below must happen while this run's own
        # temp DB is still live -- run_live() only restores store._DB_PATH to
        # the shared dev DB, and deletes the temp dir, on exit from this
        # `with` block. Reading after .run() would silently hit the shared,
        # already-populated dev DB (harness/harness_state.db) instead.
        with _PipelineRun("vulnerable").run_live() as (result, fx):
            confirmed = _confirmed_idor(result)
            self.assertTrue(confirmed, "precondition: no confirmed engagement-path IDOR to check proof for")
            f = confirmed[0]
            case_id = f.get("case_id")
            proof_id = f.get("proof_id")
            self.assertTrue(case_id, f"engagement-confirmed finding carries no case_id: {f}")
            self.assertTrue(proof_id, f"engagement-confirmed finding carries no proof_id: {f}")

            proofs = store.proofs_for_case(case_id)
            match = [p for p in proofs if p["proof_id"] == proof_id]
            self.assertTrue(
                match, f"no persisted ProofRecord found for case_id={case_id!r} proof_id={proof_id!r} "
                       f"(persist_proof_record was never called, or failed, on the engagement path)")
            self.assertEqual(match[0]["verdict"], "confirmed")
            self.assertEqual(match[0]["case"]["case_id"], case_id,
                             "proof must resolve under the SAME case_id the finding carries (no "
                             "cross-case identity mismatch)")

            # The evidence_ledger side: reconstruct_persisted() must be able to answer
            # the audit questions purely from the durable store, independent of the
            # in-memory ledger singleton -- the same read path server.py's
            # /findings/{ref}/evidence and report_generator.py use.
            recon = evidence_ledger.reconstruct_persisted(case_id)
            self.assertTrue(recon["complete"], f"reconstruct_persisted incomplete: {recon}")
            self.assertTrue(recon["what_sent"], f"what_sent must be non-empty: {recon}")
            self.assertTrue(recon["what_came_back"], f"what_came_back must be non-empty: {recon}")
            self.assertTrue(recon["why_concluded"], f"why_concluded (VALIDATION_DECISION) must be recorded: {recon}")


class RealPipelineGateDefectInjectionTest(unittest.TestCase):
    """The gate is only worth having if it FAILS when the pipeline breaks. Each test
    reintroduces a known defect and asserts the positive gate's checks now go red.
    (These are the audit's required proofs: drop POST, exhaust the discovery budget,
    suppress findings -- and require the pipeline gate to fail.)"""

    def test_budget_starvation_hides_the_route_and_kills_confirmation(self):
        """Exhaust the discovery budget (1 probe) so the object route is never found.
        The confirmation the positive gate asserts must vanish -- proving that gate
        actually depends on discovery reaching the route."""
        result, fx = _PipelineRun("vulnerable", probes=1).run()
        self.assertIsNone(
            _node(result, "GET", "/api/notes/{id}"),
            "defect-injection is inert: the object route was still discovered on a "
            "1-probe budget, so the positive gate does not actually depend on discovery")
        self.assertEqual(
            _confirmed_idor(result), [],
            "with the route undiscovered there is nothing to confirm -- if this is "
            "non-empty the confirmation is coming from somewhere other than real discovery")

    def test_dropping_post_removes_it_from_the_surface(self):
        """Reintroduce the method-loss regression: force role_crawl to record only GET.
        The POST-surface assertion in the positive gate must now fail (POST absent)."""
        def _defect():
            import harness.role_crawl as rc
            # Simulate the historical bug where discovered non-GET methods are
            # discarded: wrap crawl_roles so every returned endpoint is forced to GET.
            return patch.object(
                rc, "crawl_roles",
                new=_get_only_crawl(orig_crawl=rc.crawl_roles))
        result, fx = _PipelineRun("vulnerable", defect=_defect).run()
        self.assertIsNone(
            _node(result, "POST", "/api/notes"),
            "defect-injection is inert: POST survived even though the crawl was forced "
            "GET-only, so the positive gate's POST assertion would not catch method loss")

    def test_suppressing_the_confirmation_leg_kills_the_gate(self):
        """Suppress the cross-identity confirmation (the 'findings suppressed' defect):
        the real leg is patched to never confirm. The positive gate's confirmation
        assertion must go red."""
        def _defect():
            from harness.validators import cross_identity_validator as civ
            from harness.validators.base import ValidationResult

            async def _never_confirm(self, finding, exchange, **kw):
                return ValidationResult(
                    validator="cross_identity", status="not_confirmed", finding_class="idor",
                    confirmed=False, confidence=0.0,
                    summary="suppressed for defect injection", evidence="")
            return patch.object(civ.CrossIdentityValidator, "validate", new=_never_confirm)
        result, fx = _PipelineRun("vulnerable", defect=_defect).run()
        self.assertEqual(
            _confirmed_idor(result), [],
            "defect-injection is inert: an IDOR was still 'confirmed' even though the "
            "cross-identity leg was suppressed, so the gate's confirmation does not "
            "actually come from that leg")

    def test_suppressed_confirmation_leg_persists_no_orphan_proof(self):
        """RB-4/INV-2 negative control: persistence must be additive to a GENUINE
        confirmation only. When the cross-identity leg is suppressed (never
        confirms, same defect injection as
        test_suppressing_the_confirmation_leg_kills_the_gate above), the
        engagement path must not persist a CONFIRMED ProofRecord for this run at
        all -- no orphan proof left behind by a leg that never actually
        confirmed anything."""
        def _defect():
            from harness.validators import cross_identity_validator as civ
            from harness.validators.base import ValidationResult

            async def _never_confirm(self, finding, exchange, **kw):
                return ValidationResult(
                    validator="cross_identity", status="not_confirmed", finding_class="idor",
                    confirmed=False, confidence=0.0,
                    summary="suppressed for defect injection", evidence="")
            return patch.object(civ.CrossIdentityValidator, "validate", new=_never_confirm)
        # The store read below must happen while this run's own temp DB is
        # still live -- run_live() only restores store._DB_PATH to the shared
        # dev DB, and deletes the temp dir, on exit from this `with` block.
        # Reading after .run() would hit the shared dev DB
        # (harness/harness_state.db), which holds hundreds of pre-existing
        # unrelated verdict='confirmed' idor rows from other runs/tests --
        # making this assertion match pollution instead of this run's data.
        with _PipelineRun("vulnerable", defect=_defect).run_live() as (result, fx):
            self.assertEqual(
                _confirmed_idor(result), [],
                "precondition: the cross-identity leg must genuinely be suppressed")

            # The finding itself must carry no case_id/proof_id -- a suppressed leg
            # never even attempts persistence (that code path is unreachable when
            # res.confirmed is False).
            obj = _node(result, "GET", "/api/notes/{id}")
            self.assertIsNotNone(obj, "precondition: the object route must still be discovered")
            for f in obj.get("findings", []) or []:
                self.assertFalse(f.get("case_id"), f"a suppressed leg must not stamp a case_id: {f}")
                self.assertFalse(f.get("proof_id"), f"a suppressed leg must not stamp a proof_id: {f}")

            # And the store itself -- this run's own isolated DB, still live here
            # inside the `with` block -- must hold no CONFIRMED idor proof record
            # at all: the "no orphan proofs" guarantee, checked directly against
            # persistence rather than only against the in-memory finding.
            conn = store._connect()
            try:
                rows = conn.execute(
                    "SELECT proof_id, check_id, verdict FROM proof_records WHERE verdict = 'confirmed'"
                ).fetchall()
            finally:
                conn.close()
            orphaned = [r for r in rows if "idor" in (r[1] or "").lower()]
            self.assertEqual(
                orphaned, [],
                f"a suppressed cross-identity leg must never leave a CONFIRMED idor "
                f"ProofRecord behind (no orphan proofs): {orphaned}")


def _get_only_crawl(orig_crawl):
    """Wrap crawl_roles so the returned endpoints keep only GET -- simulating the
    method-dropping discovery regression."""
    async def _wrapped(*args, **kwargs):
        result = await orig_crawl(*args, **kwargs)
        for ep in getattr(result, "endpoints", []) or []:
            if (getattr(ep, "method", "GET") or "GET").upper() != "GET":
                # neuter non-GET endpoints the way a method-losing crawl would
                ep.method = "GET"
        return result
    return _wrapped


if __name__ == "__main__":
    unittest.main()
