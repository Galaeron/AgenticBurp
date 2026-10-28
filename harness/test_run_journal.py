"""Ticket E7: an interrupted run resumes without repeating completed model calls or probes.

Unit: the journal's rows (round trip, checksum, context key, credentials).
Caller: investigate_engagement over an owned 127.0.0.1 fixture, counting what it
sends and how often the (fake) model and probe are called. Run 1 is interrupted right
after the worklist phase; run 2 shares its journal. The negative controls run the same
two runs with no journal (the old behaviour: everything repeats, exact counts) or with
another context key. Server: resume_job_id for an interrupted job that has journal units.
"""
from __future__ import annotations

import asyncio
import http.server
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from collections import Counter
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import yaml

from harness import cache, engagement, run_journal, store
from harness.coverage_tracker import CHECKPOINT_EVERY_LEGS, build_coverage_driven, resume_context_key
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.run_journal import RunJournal
from harness.validators.base import ValidationResult

_HARNESS = Path(__file__).resolve().parent
_USER_TOKEN = "Bearer user-secret-token-0123456789"
ROLES = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": _USER_TOKEN})]
ROUTES = ["/api/orders/mine", "/api/profile/mine", "/api/cart/mine"]


class _Crash(RuntimeError):
    """The process dying mid-run, as far as investigate_engagement can tell."""


class _Died(BaseException):
    """A death inside a drive, which catches Exception: it must not be swallowed there."""


# --------------------------------------------------------------------------- #
# The journal itself
# --------------------------------------------------------------------------- #

class RunJournalUnitTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="journal_unit_")
        self.addCleanup(shutil.rmtree, self._tmp, True)
        self.path = Path(self._tmp) / "journal.db"

    def _journal(self, context_key="ctx", root="root-1", roles=()):
        return RunJournal(self.path, root, context_key, roles=roles)

    def _rows(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return conn.execute("SELECT unit, payload, sha256 FROM run_units").fetchall()

    def test_put_get_round_trip_and_stats(self):
        journal = self._journal()
        self.assertFalse(journal.has_any())
        journal.put("worklist:GET|/a", {"findings": [{"summary": "x"}], "n": 1})
        self.assertTrue(journal.has_any())
        self.assertEqual(journal.get("worklist:GET|/a"), {"findings": [{"summary": "x"}], "n": 1})
        self.assertIsNone(journal.get("worklist:missing"))
        self.assertEqual(journal.stats(), {"hits": 1, "misses": 1, "writes": 1, "corrupt": 0})

    def test_put_replaces_a_unit_and_units_lists_by_prefix(self):
        journal = self._journal()
        journal.put("worklist:a", {"v": 1})
        journal.put("worklist:a", {"v": 2})
        journal.put("worklist:b", {"v": 3})
        journal.put("review:k", {"v": 4})
        self.assertEqual(journal.units("worklist:"), {"worklist:a": {"v": 2}, "worklist:b": {"v": 3}})
        self.assertEqual(self._journal(root="other").units("worklist:"), {})

    def test_a_tampered_payload_is_a_miss_and_counted(self):
        journal = self._journal()
        journal.put("discovery", {"state": {"host": "shop.test"}})
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("UPDATE run_units SET payload = ? WHERE unit = 'discovery'",
                         (json.dumps({"state": {"host": "evil.test"}}),))
        self.assertIsNone(journal.get("discovery"))
        self.assertEqual(journal.stats()["corrupt"], 1)
        self.assertEqual(journal.units("disc"), {})
        self.assertEqual(journal.stats()["corrupt"], 2)

    def test_a_row_that_is_not_json_is_a_miss_not_an_error(self):
        journal = self._journal()
        journal.put("discovery", {"a": 1})
        with closing(sqlite3.connect(self.path)) as conn, conn:
            garbage = "not json"
            conn.execute("UPDATE run_units SET payload = ?, sha256 = ? WHERE unit = 'discovery'",
                         (garbage, run_journal._digest(garbage)))
        self.assertIsNone(journal.get("discovery"))
        self.assertEqual(journal.stats()["corrupt"], 1)

    def test_another_context_key_is_a_miss(self):
        self._journal("ctx-a").put("discovery", {"a": 1})
        other = self._journal("ctx-b")
        self.assertIsNone(other.get("discovery"))
        self.assertFalse(other.has_any())
        self.assertTrue(other.has_any(any_context=True))
        self.assertEqual(other.stats()["corrupt"], 0)

    def test_role_credentials_never_reach_the_stored_text(self):
        roles = [RoleSession("user", {"Authorization": _USER_TOKEN, "Cookie": 'sid="quoted\\value"; theme=dark',
                                      "X-Tenant": "acme-tenant"})]
        journal = self._journal(roles=roles)
        journal.put("worklist:x", {"evidence": f"sent {_USER_TOKEN}",
                                   "nested": {"echo": ['sid="quoted\\value"; theme=dark']},
                                   "tenant": "acme-tenant"})
        stored = " ".join(payload for _, payload, _ in self._rows())
        self.assertNotIn("user-secret-token", stored)
        self.assertNotIn("quoted", stored)
        self.assertIn("acme-tenant", stored)                 # not a credential header: kept
        self.assertIn("[REDACTED-SECRET]", stored)

    def test_control_without_roles_a_credential_in_a_payload_would_be_stored(self):
        self._journal(roles=()).put("worklist:x", {"evidence": _USER_TOKEN})
        self.assertIn("user-secret-token", " ".join(p for _, p, _ in self._rows()))

    def test_a_packed_exchange_carries_no_credential_and_unpacks_to_the_role_header(self):
        exchange = HttpExchange(url="http://shop.test/api/orders/1", method="GET",
                                request_headers={"Authorization": _USER_TOKEN, "Accept": "application/json",
                                                 "X-Api-Key": "foreign-key-123456"},
                                response_status=200, response_body='{"id": 1}')
        packed = run_journal.pack_exchange(exchange, ROLES)
        text = json.dumps(packed)
        self.assertNotIn("user-secret-token", text)
        self.assertNotIn("foreign-key-123456", text)          # not a role's: redacted
        self.assertEqual(packed["request_headers"]["Authorization"], f"$role:{ROLES[1].principal_id()}")
        restored = run_journal.unpack_exchange(packed, ROLES)
        self.assertEqual(restored["request_headers"]["Authorization"], _USER_TOKEN)
        self.assertEqual(restored["request_headers"]["Accept"], "application/json")
        # A resumed run without that role does not send its credential.
        self.assertNotIn("Authorization", run_journal.unpack_exchange(packed, [ROLES[0]])["request_headers"])

    def test_prune_drops_old_rows_only(self):
        journal = self._journal()
        journal.put("discovery", {"a": 1})
        self.assertEqual(journal.prune(now=time.time()), 0)
        self.assertEqual(journal.prune(now=time.time() + run_journal.RETENTION_SECONDS + 5), 1)
        self.assertFalse(journal.has_any())


class ResumeFindingTests(unittest.TestCase):
    def _proof(self, **kw):
        return dict({"proof_id": "p1", "case": {"case_id": "c1"}, "verdict": "confirmed",
                     "baseline_artifact_id": "", "attack_artifact_id": "", "control_artifact_ids": []}, **kw)

    def _finding(self, **kw):
        return dict({"vulnerability_class": "sqli", "confirmed": True, "case_id": "c1", "proof_id": "p1"}, **kw)

    def test_a_confirmation_whose_exchanges_resolve_keeps_its_status_and_ids(self):
        proof = self._proof(baseline_artifact_id="a", attack_artifact_id="b", control_artifact_ids=["c"])
        out = run_journal.resume_finding(self._finding(), "root-1", proofs_for_case=lambda c: [proof],
                                         resolves=lambda p: True)
        self.assertTrue(out["confirmed"])
        self.assertEqual((out["proof_id"], out["resumed_from"]), ("p1", "root-1"))

    def test_a_confirmation_whose_exchanges_do_not_resolve_is_downgraded_with_the_reason(self):
        proof = self._proof(baseline_artifact_id="a", attack_artifact_id="b", control_artifact_ids=["c"])
        out = run_journal.resume_finding(self._finding(), "root-1", proofs_for_case=lambda c: [proof],
                                         resolves=lambda p: False)
        self.assertFalse(out["confirmed"])
        self.assertEqual(out["resume_downgrade"],
                         "proof belongs to interrupted job root-1; re-run to re-establish")

    def test_a_missing_proof_is_downgraded_and_a_legacy_proof_keeps_its_status(self):
        gone = run_journal.resume_finding(self._finding(), "r", proofs_for_case=lambda c: [],
                                          resolves=lambda p: True)
        self.assertFalse(gone["confirmed"])
        legacy = run_journal.resume_finding(self._finding(), "r", proofs_for_case=lambda c: [self._proof()],
                                            resolves=lambda p: False)
        self.assertTrue(legacy["confirmed"])                 # it never named exchanges

    def test_unconfirmed_and_pointerless_findings_are_only_marked(self):
        for finding in ({"vulnerability_class": "x", "confirmed": False, "case_id": "c1", "proof_id": "p1"},
                        {"vulnerability_class": "x", "confirmed": True}):
            out = run_journal.resume_finding(finding, "r", proofs_for_case=lambda c: self.fail("no lookup"))
            self.assertEqual(out["confirmed"], finding["confirmed"])
            self.assertEqual(out["resumed_from"], "r")


# --------------------------------------------------------------------------- #
# investigate_engagement, interrupted and resumed
# --------------------------------------------------------------------------- #

class _Site:
    """Loopback target counting requests per path."""

    def __init__(self):
        counts = self.counts = Counter()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                counts[self.path.split("?", 1)[0]] += 1
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)

    def discovery_requests(self) -> int:
        return sum(n for path, n in self.counts.items() if path.startswith("/disco/"))


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {}).update(active_enabled=False, allow_mutating_replay=False)
    for key in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(key, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


class _EngagementBase(unittest.TestCase):
    PATHS = ROUTES

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="journal_caller_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        self.addCleanup(self._restore)
        self.site = _Site()
        self.addCleanup(self.site.close)
        self.journal_path = Path(self._tmp) / "journal.db"
        self.probes: list[str] = []
        self.analyzed: list[str] = []
        self.discoveries = 0

    def _restore(self):
        store._DB_PATH, cache._cache = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)

    # -- fakes ----------------------------------------------------------------

    async def _discover(self, base_url, roles, **kwargs):
        """build_engagement stand-in: two real requests to the fixture, a state with one
        object-scoped endpoint per PATHS entry, and one capture per path made as `user`."""
        self.discoveries += 1
        async with httpx.AsyncClient() as client:
            for n in (1, 2):
                await client.get(f"{self.site.origin}/disco/{n}")
        state = engagement.EngagementState(host="127.0.0.1")
        state.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": path, "by_role": {"user": 200, "anonymous": 401},
             "reachable_roles": ["user"], "object_scoped": True} for path in self.PATHS],
            "idor_findings": []})
        for role in roles:
            state.ingest_identity(f"rolecrawl:{role.role}", role.role, source="seed")
        captured = [HttpExchange(url=f"{self.site.origin}{path}", method="GET",
                                 request_headers={"Authorization": _USER_TOKEN},
                                 response_status=200, response_body=json.dumps({"id": 1, "email": "a@b.c", "route": path}),
                                 response_headers={"Content-Type": "application/json"}).model_dump()
                    for path in self.PATHS]
        rc = SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[],
                             captured=captured, errors=[], endpoints=[], identity_probes=[])
        return state, rc

    async def _probe(self, exchange, hypothesis, specialty, step_budget=None, run_context=None, **kw):
        self.probes.append(exchange.url)
        path = exchange.url.replace(self.site.origin, "")
        return {"iterative_result": {"stop_reason": "gave_up", "findings": [
            {"vulnerability_class": "information_disclosure", "confidence": 0.6, "severity": "low",
             "summary": f"probe finding for {path}", "evidence": "fixture", "confirmed": False}]},
                "integration": {}}

    async def _analyze(self, exchange, _from_discovery=False, run_context=None, **kw):
        self.analyzed.append(exchange.url)
        finding = Finding(vulnerability_class="debug_endpoint", confidence=0.5, severity="low",
                          summary=f"review finding for {exchange.url.replace(self.site.origin, '')}",
                          evidence="fixture", suggested_test="t", basis="derived")
        return SimpleNamespace(agent_reports=[AgentReport(agent="fake", model="fake", findings=[finding])])

    def _orchestrator(self):
        orch = Orchestrator(_config())
        orch.run_active_probe = self._probe
        orch.analyze = self._analyze
        return orch

    def _journal(self, context_key="ctx", root="root-1"):
        return RunJournal(self.journal_path, root, context_key, roles=ROLES)

    def _investigate(self, journal, *, orch=None, review=None, extra=None, **kwargs):
        orch = orch or self._orchestrator()

        async def go():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=5000) as run:
                run.run_journal = journal
                patches = [patch("harness.engagement_builder.build_engagement", new=self._discover)]
                if review is not None:
                    patches.append(patch("harness.orchestrator_chain.review_captured_exchanges", new=review))
                for item in extra or ():
                    patches.append(item)
                for p in patches:
                    p.start()
                try:
                    return await orch.investigate_engagement(
                        self.site.origin, ROLES, max_nodes=8, step_budget=2, max_chain_rounds=0,
                        run_context=run, **kwargs)
                finally:
                    for p in reversed(patches):
                        p.stop()
        return asyncio.run(go())

    @staticmethod
    async def _crash_in_review(*args, **kwargs):
        raise _Crash("process died after the worklist phase")

    def _interrupted_first_run(self, journal):
        with self.assertRaises(_Crash):
            self._investigate(journal, review=self._crash_in_review)


class ResumeCallerTests(_EngagementBase):
    def test_the_interrupted_run_has_journaled_its_finished_units(self):
        journal = self._journal()
        self._interrupted_first_run(journal)
        self.assertEqual(self.discoveries, 1)
        self.assertEqual(len(self.probes), 3)
        self.assertEqual(self.site.discovery_requests(), 2)
        units = sorted(unit.split(":")[0] if unit.startswith(("worklist", "review")) else unit
                       for unit in journal.units("").keys())
        self.assertEqual(units, ["discovery", "phase:discovery", "phase:worklist",
                                 "worklist", "worklist", "worklist"])

    def test_run_two_skips_discovery_and_the_completed_nodes_and_reviews_the_captures(self):
        self._interrupted_first_run(self._journal())
        probes_run_1, requests_run_1 = list(self.probes), self.site.discovery_requests()
        result = self._investigate(self._journal())
        # 0 discovery requests, 0 probe calls: both came from the journal.
        self.assertEqual(self.discoveries, 1)
        self.assertEqual(self.site.discovery_requests(), requests_run_1)
        self.assertEqual(self.probes, probes_run_1)
        # The review phase did run, over captures restored with their role credentials.
        self.assertEqual(sorted(self.analyzed), sorted(self.site.origin + p for p in ROUTES))
        resume = result["resume"]
        self.assertEqual(resume["root_job_id"], "root-1")
        self.assertEqual(resume["resumed_units"],
                         {"discovery": True, "worklist": 3, "review": 0, "coverage_checkpoint": False})
        # Run 1's worklist findings are in run 2's result, marked as resumed.
        summaries = [f["summary"] for o in result["outcomes"] for f in o["findings_detail"]]
        self.assertEqual(sorted(summaries), sorted(f"probe finding for {p}" for p in ROUTES))
        self.assertTrue(all(o["resumed"] for o in result["outcomes"]))
        self.assertTrue(all(f["resumed_from"] == "root-1"
                            for o in result["outcomes"] for f in o["findings_detail"]))

    def test_a_resumed_review_does_not_call_the_model_again(self):
        # Run 1 completes its reviews, then dies before the end; run 2 reviews nothing.
        journal = self._journal()
        orch = self._orchestrator()
        with patch("harness.chain_linker.link_findings", side_effect=_Crash("died")):
            with self.assertRaises(_Crash):
                self._investigate(journal, orch=orch)
        self.assertEqual(len(self.analyzed), 3)
        analyzed_run_1 = list(self.analyzed)
        result = self._investigate(self._journal())
        self.assertEqual(self.analyzed, analyzed_run_1)
        self.assertEqual(result["resume"]["resumed_units"]["review"], 3)
        review_findings = [f["summary"] for f in result["findings"] if f["summary"].startswith("review finding")]
        self.assertEqual(len(review_findings), 3)

    def test_credentials_are_not_in_the_journal_and_the_resumed_captures_have_them_back(self):
        self._interrupted_first_run(self._journal())
        with closing(sqlite3.connect(self.journal_path)) as conn:
            stored = " ".join(row[0] for row in conn.execute("SELECT payload FROM run_units"))
        self.assertNotIn("user-secret-token", stored)
        self.assertIn(f"$role:{ROLES[1].principal_id()}", stored)
        restored = []

        async def review(orch, state, captured, **kwargs):
            restored.extend(c["request_headers"] for c in captured)
            return 0
        self._investigate(self._journal(), review=review)
        self.assertEqual(restored, [{"Authorization": _USER_TOKEN}] * 3)

    def test_control_without_a_journal_run_two_repeats_discovery_and_every_probe(self):
        self._interrupted_first_run(None)
        self.assertEqual((self.discoveries, len(self.probes), self.site.discovery_requests()), (1, 3, 2))
        result = self._investigate(None)
        self.assertEqual((self.discoveries, len(self.probes), self.site.discovery_requests()), (2, 6, 4))
        self.assertNotIn("resume", result)
        self.assertFalse(any(o.get("resumed") for o in result["outcomes"]))

    def test_control_another_context_key_does_a_full_run(self):
        self._interrupted_first_run(self._journal("ctx-a"))
        result = self._investigate(self._journal("ctx-b"))
        self.assertEqual((self.discoveries, len(self.probes), self.site.discovery_requests()), (2, 6, 4))
        self.assertEqual(result["resume"]["resumed_units"],
                         {"discovery": False, "worklist": 0, "review": 0, "coverage_checkpoint": False})
        self.assertFalse(result["resume"]["resumed"])

    def test_control_patching_the_resume_out_repeats_everything_with_the_same_journal(self):
        self._interrupted_first_run(self._journal())
        with patch.object(RunJournal, "has_any", return_value=False):
            self._investigate(self._journal())
        self.assertEqual((self.discoveries, len(self.probes)), (2, 6))

    def test_a_corrupt_discovery_unit_falls_back_to_a_full_discovery(self):
        self._interrupted_first_run(self._journal())
        with closing(sqlite3.connect(self.journal_path)) as conn, conn:
            conn.execute("UPDATE run_units SET payload = '{}' WHERE unit = 'discovery'")
        journal = self._journal()
        result = self._investigate(journal)
        self.assertEqual(self.discoveries, 2)
        self.assertFalse(result["resume"]["resumed_units"]["discovery"])
        self.assertEqual(journal.stats()["corrupt"], 1)

    def test_an_unreadable_journal_never_sinks_the_run(self):
        self._interrupted_first_run(self._journal())
        with patch.object(RunJournal, "has_any", side_effect=sqlite3.OperationalError("locked")), \
                patch.object(RunJournal, "put", side_effect=sqlite3.OperationalError("locked")):
            result = self._investigate(self._journal())
        self.assertEqual((self.discoveries, len(self.probes)), (2, 6))
        self.assertFalse(result["resume"]["resumed"])

    def test_an_errored_probe_is_not_journaled_and_runs_again(self):
        calls = []

        async def flaky(exchange, hypothesis, specialty, step_budget=None, run_context=None, **kw):
            calls.append(exchange.url)
            if exchange.url.endswith("/profile/mine") and len(calls) < 4:
                raise RuntimeError("model unavailable")
            return await self._probe(exchange, hypothesis, specialty)
        orch = self._orchestrator()
        orch.run_active_probe = flaky
        with self.assertRaises(_Crash):
            self._investigate(self._journal(), orch=orch, review=self._crash_in_review)
        self.assertEqual(sum(1 for u in self._journal().units("worklist:")), 2)
        self._investigate(self._journal(), orch=orch)
        self.assertEqual(sum(1 for u in calls if u.endswith("/profile/mine")), 2)    # only the failed node again
        self.assertEqual(len(calls), 4)


class ResumedProofTests(_EngagementBase):
    """A resumed confirmation is shown only while its proof still resolves."""

    def _confirmed_probe(self, case_id="c-1", proof_id="p-1"):
        async def probe(exchange, hypothesis, specialty, step_budget=None, run_context=None, **kw):
            self.probes.append(exchange.url)
            return {"iterative_result": {"stop_reason": "gave_up", "findings": [
                {"vulnerability_class": "information_disclosure", "confidence": 0.9, "severity": "high",
                 "summary": "confirmed in run 1", "evidence": "fixture", "confirmed": True,
                 "case_id": case_id, "proof_id": proof_id, "confirmed_by_leg": "fixture"}]},
                    "integration": {}}
        return probe

    PATHS = ROUTES[:1]

    def _resume_with(self, proofs_for_case, resolves):
        orch = self._orchestrator()
        orch.run_active_probe = self._confirmed_probe()
        with self.assertRaises(_Crash):
            self._investigate(self._journal(), orch=orch, review=self._crash_in_review)
        with patch("harness.store.proofs_for_case", side_effect=proofs_for_case), \
                patch("harness.assessment_health.stored_proof_artifacts_resolve", side_effect=resolves):
            return self._investigate(self._journal(), orch=orch)

    def _confirmed(self, result):
        return [f["confirmed"] for o in result["outcomes"] for f in o["findings_detail"]]

    def test_a_proof_that_resolves_keeps_the_confirmation(self):
        proof = {"proof_id": "p-1", "case": {"case_id": "c-1"}, "baseline_artifact_id": "a",
                 "attack_artifact_id": "b", "control_artifact_ids": ["c"]}
        result = self._resume_with(lambda case_id: [proof], lambda p: True)
        self.assertEqual(self._confirmed(result), [True])
        self.assertEqual(len(self.probes), 1)                    # no probe in run 2

    def test_a_proof_that_does_not_resolve_is_downgraded_with_the_reason(self):
        proof = {"proof_id": "p-1", "case": {"case_id": "c-1"}, "baseline_artifact_id": "a",
                 "attack_artifact_id": "b", "control_artifact_ids": ["c"]}
        result = self._resume_with(lambda case_id: [proof], lambda p: False)
        finding = result["outcomes"][0]["findings_detail"][0]
        self.assertFalse(finding["confirmed"])
        self.assertEqual(finding["resume_downgrade"],
                         "proof belongs to interrupted job root-1; re-run to re-establish")
        self.assertFalse(result["outcomes"][0]["confirmed"])

    def test_control_without_the_check_the_unresolvable_confirmation_would_stand(self):
        proof = {"proof_id": "p-1", "case": {"case_id": "c-1"}, "baseline_artifact_id": "a",
                 "attack_artifact_id": "b", "control_artifact_ids": ["c"]}
        with patch.object(run_journal, "resume_finding", side_effect=lambda f, root, **kw: dict(f)):
            result = self._resume_with(lambda case_id: [proof], lambda p: False)
        self.assertEqual(self._confirmed(result), [True])


# --------------------------------------------------------------------------- #
# The coverage drive
# --------------------------------------------------------------------------- #

class CoverageDriveResumeTests(unittest.IsolatedAsyncioTestCase):
    """The drive hands its checkpoint to the journal every CHECKPOINT_EVERY_LEGS legs,
    and a run that dies inside it resumes from the last one."""

    def _state(self, count=30):
        state = engagement.EngagementState("shop.test")
        roles = [RoleSession("user", {}, name="alice"), RoleSession("user", {}, name="bob")]
        for n in range(count):
            url = f"http://shop.test/api/orders/{n}x"
            state.record_template(url, "GET", HttpExchange(url=url, method="GET", response_status=200))
        for ep in state.endpoints.values():
            ep.reachable_roles = ["user"]
            ep.object_scoped = True
        return state, roles

    async def _drive(self, state, roles, calls, *, crash_after=None, journal=None, checkpoint=None):
        async def run_leg(identity, method, path, check):
            if crash_after is not None and len(calls) >= crash_after:
                raise _Died("process died inside the drive")
            calls.append((identity, method, path, check.id))
            return SimpleNamespace(status="not_confirmed", sent_count=1, summary="controls held")
        return await build_coverage_driven(
            state, roles, run_leg, driveable={"cross_identity"}, budget=500, context_key="same-source",
            checkpoint=checkpoint,
            **({"on_checkpoint": lambda cp: journal.put("coverage:checkpoint", cp)} if journal else {}))

    async def test_a_run_that_dies_after_the_checkpoint_resumes_without_resending_completed_legs(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = RunJournal(Path(tmp) / "j.db", "root-1", "same-source")
            state, roles = self._state()
            first_calls: list = []
            with self.assertRaises(_Died):
                await self._drive(state, roles, first_calls, crash_after=CHECKPOINT_EVERY_LEGS + 2,
                                  journal=journal)
            self.assertEqual(len(first_calls), CHECKPOINT_EVERY_LEGS + 2)
            checkpoint = journal.get("coverage:checkpoint")
            self.assertIsNotNone(checkpoint)
            completed = {c for c in checkpoint["matrix"]["cells"] if c.get("executed")} \
                if isinstance(checkpoint["matrix"].get("cells"), list) else None
            state2, roles2 = self._state()
            second_calls: list = []
            report = await self._drive(state2, roles2, second_calls, checkpoint=checkpoint)
        # Exactly the legs the checkpoint covers are not sent again; the rest are.
        self.assertEqual(report["phase_ledger"]["counts"]["resumed"], CHECKPOINT_EVERY_LEGS)
        self.assertEqual(set(second_calls) & set(first_calls[:CHECKPOINT_EVERY_LEGS]), set())
        self.assertEqual(set(second_calls) | set(first_calls[:CHECKPOINT_EVERY_LEGS]),
                         set(first_calls[:CHECKPOINT_EVERY_LEGS]) | set(second_calls))
        full_calls: list = []
        full = await self._drive(*self._state(), full_calls)
        self.assertEqual(len(second_calls) + CHECKPOINT_EVERY_LEGS, len(full_calls))
        self.assertEqual(report["audited"]["applicable"], full["audited"]["applicable"])

    async def test_no_checkpoint_is_written_before_the_first_n_legs(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = RunJournal(Path(tmp) / "j.db", "root-1", "same-source")
            state, roles = self._state(count=4)
            await self._drive(state, roles, [], crash_after=None, journal=journal)
            self.assertIsNone(journal.get("coverage:checkpoint"))

    async def test_control_without_the_callback_a_crash_leaves_nothing_to_resume_from(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = RunJournal(Path(tmp) / "j.db", "root-1", "same-source")
            state, roles = self._state()
            with self.assertRaises(_Died):
                await self._drive(state, roles, [], crash_after=CHECKPOINT_EVERY_LEGS + 2, journal=None)
            self.assertIsNone(journal.get("coverage:checkpoint"))

    async def test_a_failing_callback_does_not_stop_the_drive(self):
        state, roles = self._state()

        def broken(cp):
            raise OSError("disk full")
        calls: list = []

        async def run_leg(identity, method, path, check):
            calls.append(1)
            return SimpleNamespace(status="not_confirmed", sent_count=1)
        await build_coverage_driven(state, roles, run_leg, driveable={"cross_identity"}, budget=500,
                                    on_checkpoint=broken)
        self.assertGreater(len(calls), CHECKPOINT_EVERY_LEGS)


class CoverageThroughEngagementTests(_EngagementBase):
    """The same, through investigate_engagement: the journal's checkpoint is used when the
    caller gave none, and the run reports it."""

    PATHS = ROUTES

    def test_the_journal_checkpoint_is_the_resume_checkpoint(self):
        journal = self._journal(context_key=resume_context_key(_config()))
        journal.put("discovery", run_journal.discovery_payload(*self._canned(), ROLES))
        journal.put("coverage:checkpoint", {"signature": "stale", "context_key": "x", "matrix": {}})
        seen = {}

        async def fake_drive(state, roles, run_leg, **kwargs):
            seen["checkpoint"] = kwargs.get("checkpoint")
            return {"checkpoint": {"signature": "s", "context_key": "c", "matrix": {}}, "legs_driven": 0}
        orch = self._orchestrator()
        orch.engagement_coverage_drive = True
        result = self._investigate(self._journal(context_key=resume_context_key(_config())), orch=orch,
                                   extra=[patch("harness.coverage_tracker.build_coverage_driven", new=fake_drive)])
        self.assertEqual(seen["checkpoint"]["signature"], "stale")
        self.assertTrue(result["resume"]["resumed_units"]["coverage_checkpoint"])
        self.assertEqual(self._journal(context_key=resume_context_key(_config())).get(
            "coverage:checkpoint")["signature"], "s")

    def test_a_checkpoint_the_caller_gave_wins(self):
        journal = self._journal(context_key=resume_context_key(_config()))
        journal.put("discovery", run_journal.discovery_payload(*self._canned(), ROLES))
        journal.put("coverage:checkpoint", {"signature": "stale", "context_key": "x", "matrix": {}})
        seen = {}

        async def fake_drive(state, roles, run_leg, **kwargs):
            seen["checkpoint"] = kwargs.get("checkpoint")
            return {"checkpoint": None}
        orch = self._orchestrator()
        orch.engagement_coverage_drive = True
        result = self._investigate(self._journal(context_key=resume_context_key(_config())), orch=orch,
                                   coverage_checkpoint={"signature": "caller"},
                                   extra=[patch("harness.coverage_tracker.build_coverage_driven", new=fake_drive)])
        self.assertEqual(seen["checkpoint"], {"signature": "caller"})
        self.assertFalse(result["resume"]["resumed_units"]["coverage_checkpoint"])

    def test_a_death_inside_the_drive_leaves_the_last_checkpoint_in_the_journal(self):
        async def dying_drive(state, roles, run_leg, **kwargs):
            kwargs["on_checkpoint"]({"signature": "after-25-legs", "context_key": "c", "matrix": {}})
            raise _Died("process died inside the drive")
        orch = self._orchestrator()
        orch.engagement_coverage_drive = True
        journal = self._journal()
        with self.assertRaises(_Died):
            self._investigate(journal, orch=orch,
                              extra=[patch("harness.coverage_tracker.build_coverage_driven", new=dying_drive)])
        self.assertEqual(journal.get("coverage:checkpoint")["signature"], "after-25-legs")
        seen = {}

        async def drive(state, roles, run_leg, **kwargs):
            seen["checkpoint"] = kwargs.get("checkpoint")
            return {"checkpoint": None}
        result = self._investigate(self._journal(), orch=orch,
                                   extra=[patch("harness.coverage_tracker.build_coverage_driven", new=drive)])
        self.assertEqual(seen["checkpoint"]["signature"], "after-25-legs")
        self.assertEqual(self.discoveries, 1)                    # run 2 resumed everything before the drive
        self.assertTrue(result["resume"]["resumed_units"]["coverage_checkpoint"])

    def test_control_without_a_journal_the_dying_drive_leaves_no_checkpoint(self):
        async def dying_drive(state, roles, run_leg, **kwargs):
            self.assertNotIn("on_checkpoint", kwargs)
            raise _Died("process died inside the drive")
        orch = self._orchestrator()
        orch.engagement_coverage_drive = True
        with self.assertRaises(_Died):
            self._investigate(None, orch=orch,
                              extra=[patch("harness.coverage_tracker.build_coverage_driven", new=dying_drive)])
        self.assertFalse(self.journal_path.exists())

    def _canned(self):
        return asyncio.run(self._discover(self.site.origin, ROLES))


# --------------------------------------------------------------------------- #
# server: resume_job_id for an interrupted job
# --------------------------------------------------------------------------- #

from harness import test_job_status_passive as _durable  # noqa: E402


class JournalResumeServerTests(_durable.DurableJobCallerTests, unittest.TestCase):
    """Reuses the durable-job server fixture; only the tests below are run."""

    PRIOR = "deadbeef0001"

    def _interrupted_job(self, *, journal_root=None, with_result=False, result=None):
        job = {"job_id": self.PRIOR, "host": "captured.example", "base_url": "https://captured.example",
               "status": "interrupted", "started_at": time.time() - 5, "finished_at": time.time(),
               "error": "previous job process ended; no work was resumed", "recovered": True,
               "manifest_path": "",
               "result": result if result is not None else ({"summary": {}} if with_result else None),
               "journal_root": journal_root}
        self.server._job_store().create(job)

    def _units(self, root=None, context_key=None):
        journal = RunJournal(self.server._run_journal_path(), root or self.PRIOR,
                             context_key or self._key())
        journal.put("discovery", {"state": {}, "rc": {}})
        return journal

    def _key(self, **request):
        req = self.server.InvestigateRequest(base_url='https://captured.example', **request)
        return self.server._journal_context_key(self.server.config, req)

    def _resume(self, **request):
        return self.client.post('/engagement/captured.example/investigate',
                                json={'base_url': 'https://captured.example', 'resume_job_id': self.PRIOR,
                                      **request})

    def _capture_journal(self):
        seen = []

        async def stub(*args, **kwargs):
            self.calls += 1
            journal = kwargs['run_context'].run_journal
            seen.append(None if journal is None else (journal.root_job_id, journal.has_any()))
            return {'summary': {}}
        self.server.orchestrator.investigate_engagement = stub
        return seen

    def test_an_interrupted_job_with_journal_units_resumes(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR)
        self._units()
        seen = self._capture_journal()
        reply = self._resume()
        self.assertEqual(reply.status_code, 200, reply.text)
        done = self.poll(reply.json()['job_id'], 'done')
        self.assertEqual(seen, [(self.PRIOR, True)])                 # the prior job's root, with its units
        self.assertEqual(self.server._job_store().get(reply.json()['job_id'])['journal_root'], self.PRIOR)

    def test_the_same_job_with_the_journal_disabled_is_a_409(self):
        self._interrupted_job(journal_root=self.PRIOR)
        self._units()
        seen = self._capture_journal()
        reply = self._resume()
        self.assertEqual((reply.status_code, reply.json()['detail']), (409, 'prior result is missing or corrupt'))
        self.assertEqual((seen, self.calls), ([], 0))

    def test_journal_on_but_no_units_is_the_old_409(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR)
        reply = self._resume()
        self.assertEqual((reply.status_code, reply.json()['detail']), (409, 'prior result is missing or corrupt'))

    def test_units_written_for_another_configuration_are_a_409_about_the_configuration(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR)
        self._units(context_key='some-other-source-or-config')
        reply = self._resume()
        self.assertEqual((reply.status_code, reply.json()['detail']),
                         (409, 'prior coverage is unavailable or source, configuration '
                               'or request inputs changed'))

    _ADMIN = {'role': 'admin', 'name': 'root', 'headers': {'Authorization': 'Bearer old-token'}}

    def test_an_added_role_is_a_409_and_never_reuses_the_old_discovery(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR)
        self._units()                                         # written by a run with no roles
        seen = self._capture_journal()
        reply = self._resume(roles=[self._ADMIN])
        self.assertEqual(reply.status_code, 409, reply.text)
        self.assertIn('request inputs changed', reply.json()['detail'])
        self.assertEqual((seen, self.calls), ([], 0))

    def test_control_the_same_roles_with_a_fresh_credential_resume(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR)
        self._units(context_key=self._key(roles=[self._ADMIN]))
        seen = self._capture_journal()
        fresh = dict(self._ADMIN, headers={'Authorization': 'Bearer new-token'})
        reply = self._resume(roles=[fresh])
        self.assertEqual(reply.status_code, 200, reply.text)
        self.poll(reply.json()['job_id'], 'done')
        self.assertEqual(seen, [(self.PRIOR, True)])

    def test_a_finished_job_with_a_result_does_not_resume_from_its_journal(self):
        from harness.coverage_tracker import resume_context_key
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=self.PRIOR, result={'coverage': {'checkpoint': {
            'context_key': resume_context_key(self.server.config)}}})
        self._units()
        seen = self._capture_journal()
        reply = self._resume()
        self.assertEqual(reply.status_code, 200, reply.text)
        job_id = reply.json()['job_id']
        self.poll(job_id, 'done')
        self.assertEqual(seen, [(job_id, False)])             # its own fresh root, not the prior one

    def test_a_job_started_without_a_journal_has_no_root_to_resume(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(journal_root=None)             # started with the journal off
        reply = self._resume()
        self.assertEqual(reply.status_code, 409)

    def test_a_resumed_job_with_a_result_keeps_the_existing_checkpoint_path(self):
        self.server.config['runs']['journal'] = True
        self._interrupted_job(with_result=True)
        reply = self._resume()
        self.assertEqual((reply.status_code, reply.json()['detail']),
                         (409, 'prior coverage is unavailable or source/configuration changed'))

    def test_a_new_job_is_journaled_under_its_own_id_only_when_enabled(self):
        seen = self._capture_journal()
        job_id = self.start()
        self.poll(job_id, 'done')
        self.assertEqual(seen, [None])                       # runs.journal is off by default
        self.server.config['runs']['journal'] = True
        job_id = self.start()
        self.poll(job_id, 'done')
        self.assertEqual(seen[1], (job_id, False))
        self.assertEqual(self.server._job_store().get(job_id)['journal_root'], job_id)


# unittest runs every test of the base class too; the base tests are not this module's.
for _name in [n for n in dir(_durable.DurableJobCallerTests) if n.startswith("test_")]:
    setattr(JournalResumeServerTests, _name,
            getattr(JournalResumeServerTests, _name) if _name in JournalResumeServerTests.__dict__ else None)
del _name


if __name__ == "__main__":
    unittest.main()
