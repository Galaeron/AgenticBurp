"""I16 persistence: saved per-target declarations, applied only on opt-in.

Owner decision (2026-11-02): an operator's `protected_paths` and `owners` may be
SAVED per target (PUT /engagement/{host}/declarations), but are NEVER loaded by
default. An investigate request either sends its own lists (as before) or opts in
with `use_saved_declarations`. Rule when both: per field, a non-empty request list
replaces the saved list (never merged); an empty request field takes the saved one.
Targets are keyed on (host, effective port).

P1  control: lists saved for the target do not reach a request that did not opt in.
P2  opt-in: the saved lists reach `investigate_engagement`, and the job says so.
P3  a request's own list replaces the saved list for that field only.
P4  host isolation: lists saved for one host (or port) never apply to another.
P5  save validates: malformed or non-declaration entries are 422 and nothing is
    stored; out-of-scope 403; route/base_url mismatch 400; empty lists clear.
P6  the journal key of an opt-in run equals that of a run sending the same lists.
P7  end to end: a saved list reaches the real `investigate_engagement` and the
    missing-auth confirmation (RV-S loopback) only when the request opts in.
P8  store: additive versioned side table, legacy DB unchanged, rollback, version
    mismatch reads as nothing saved, wipe_engagement removes a host's rows only.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import store
from harness import test_protected_routes_rvs as rvs
from harness.test_i16_wiring import _declaring
from harness.test_observation_migration import _LEGACY_SQL, _legacy_identity, _schema

_PATHS = ["/reports/*", "GET /api/account/*"]
_OWNERS = [{"path": "/api/invoices/*", "owner": "alice"},
           {"path": "/api/announcements/**", "authenticated": True}]
_BASE = "https://captured.example/app"


class _RouteCase(unittest.TestCase):
    """The real server app over a synthetic store; `investigate_engagement` is
    replaced by a recorder of the keyword arguments the route passes it."""

    def setUp(self):
        from harness.test_job_status_passive import DurableJobCallerTests
        self.fx = DurableJobCallerTests("test_export_retains_child_execution_without_parent_completion")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.server = self.fx.server
        self.server.orchestrator.allowed_hosts = ["captured.example", "other.example"]
        self.client = self.fx.client
        self.calls: list[dict] = []

        async def recorder(*args, **kwargs):
            self.calls.append(kwargs)
            return {"summary": {}}
        self.server.orchestrator.investigate_engagement = recorder

    def _save(self, host="captured.example", base_url=_BASE, **lists):
        return self.client.put(f"/engagement/{host}/declarations", json={"base_url": base_url, **lists})

    def _saved(self, host="captured.example", base_url=_BASE) -> dict:
        reply = self.client.get(f"/engagement/{host}/declarations", params={"base_url": base_url})
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply.json()

    def _poll(self, host, job_id) -> dict:
        for _ in range(200):
            reply = self.client.get(f"/engagement/{host}/investigate/{job_id}")
            self.assertEqual(reply.status_code, 200, reply.text)
            if reply.json()["status"] in ("done", "failed", "cancelled"):
                return reply.json()
            time.sleep(0.01)
        self.fail(f"job did not finish: {reply.text}")

    def _investigate(self, host="captured.example", base_url=_BASE, **extra) -> tuple[dict, dict]:
        before = len(self.calls)
        response = self.client.post(f"/engagement/{host}/investigate", json={"base_url": base_url, **extra})
        self.assertEqual(response.status_code, 200, response.text)
        job = self._poll(host, response.json()["job_id"])
        self.assertEqual(job["status"], "done", job)
        self.assertEqual(len(self.calls), before + 1)
        return self.calls[-1], job.get("result") or {}


class SavedDeclarationsRouteTests(_RouteCase):

    def test_saved_lists_do_not_apply_without_opt_in(self):  # P1
        self.assertEqual(self._save(protected_paths=_PATHS, owners=_OWNERS).status_code, 200)
        kwargs, result = self._investigate()
        self.assertNotIn("protected_paths", kwargs)
        self.assertNotIn("owners", kwargs)
        self.assertNotIn("declarations_source", result)
        kwargs, _ = self._investigate(use_saved_declarations=False)
        self.assertNotIn("protected_paths", kwargs)

    def test_opt_in_applies_the_saved_lists(self):  # P2
        self.assertEqual(self._save(protected_paths=_PATHS, owners=_OWNERS).status_code, 200)
        self.assertEqual(self._saved(), {"host": "captured.example", "port": 443, "saved": True,
                                         "protected_paths": _PATHS, "owners": _OWNERS})
        kwargs, result = self._investigate(use_saved_declarations=True)
        self.assertEqual(kwargs["protected_paths"], _PATHS)
        self.assertEqual(kwargs["owners"], _OWNERS)
        self.assertEqual(result["declarations_source"], {"protected_paths": "saved", "owners": "saved"})

    def test_opt_in_with_nothing_saved_applies_nothing(self):
        kwargs, result = self._investigate(use_saved_declarations=True)
        self.assertNotIn("protected_paths", kwargs)
        self.assertNotIn("owners", kwargs)
        self.assertEqual(result["declarations_source"], {"protected_paths": "none", "owners": "none"})

    def test_request_list_replaces_the_saved_list_per_field(self):  # P3
        self._save(protected_paths=_PATHS, owners=_OWNERS)
        kwargs, result = self._investigate(use_saved_declarations=True, protected_paths=["/admin/**"])
        self.assertEqual(kwargs["protected_paths"], ["/admin/**"], "replaced, never merged")
        self.assertEqual(kwargs["owners"], _OWNERS)
        self.assertEqual(result["declarations_source"], {"protected_paths": "request", "owners": "saved"})
        # Without the opt-in, the request's own list is all there is.
        kwargs, _ = self._investigate(protected_paths=["/admin/**"])
        self.assertEqual(kwargs["protected_paths"], ["/admin/**"])
        self.assertNotIn("owners", kwargs)

    def test_saved_lists_never_cross_hosts_or_ports(self):  # P4
        self._save(protected_paths=_PATHS, owners=_OWNERS)
        for host, base_url in (("other.example", "https://other.example/app"),
                               ("captured.example", "https://captured.example:8443/app"),
                               ("captured.example", "http://captured.example/app")):
            with self.subTest(base_url=base_url):
                kwargs, result = self._investigate(host=host, base_url=base_url, use_saved_declarations=True)
                self.assertNotIn("protected_paths", kwargs)
                self.assertNotIn("owners", kwargs)
                self.assertEqual(result["declarations_source"], {"protected_paths": "none", "owners": "none"})
                self.assertFalse(self._saved(host, base_url)["saved"])
        # Saving for B leaves A's lists as they were.
        self._save("other.example", "https://other.example/", protected_paths=["/b/**"])
        self.assertEqual(self._saved()["protected_paths"], _PATHS)
        kwargs, _ = self._investigate(host="other.example", base_url="https://other.example/x",
                                      use_saved_declarations=True)
        self.assertEqual(kwargs["protected_paths"], ["/b/**"])
        self.assertNotIn("owners", kwargs)

    def test_save_rejects_anything_but_declarations(self):  # P5
        rejected = (
            {"protected_paths": ["reports/*"]},                       # not a path
            {"protected_paths": ["/a?token=x"]},                      # query string
            {"protected_paths": [7]},
            {"owners": [{"path": "/api/x/*", "owner": "alice", "authorization": "Bearer x"}]},
            {"owners": [{"path": "/api/x/*"}]},                       # declares nothing
            {"owners": ["alice"]},
        )
        for lists in rejected:
            with self.subTest(lists=lists):
                self.assertEqual(self._save(**lists).status_code, 422)
        self.assertFalse(self._saved()["saved"])
        self.assertEqual(self._save(base_url="https://unlisted.example/", host="unlisted.example",
                                    protected_paths=_PATHS).status_code, 403)
        self.assertEqual(self._save(host="other.example", protected_paths=_PATHS).status_code, 400)
        self.assertEqual(self.client.put("/engagement/captured.example/declarations",
                                         json={"base_url": _BASE, "protected_paths": _PATHS},
                                         headers={"Authorization": "Bearer wrong"}).status_code, 401)
        self.assertFalse(self._saved()["saved"])
        self.assertEqual(self.calls, [], "saving never starts an investigation")

    def test_saving_empty_lists_clears(self):
        self._save(protected_paths=_PATHS)
        self.assertTrue(self._saved()["saved"])
        self.assertEqual(self._save().json()["saved"], False)
        self.assertFalse(self._saved()["saved"])

    def test_opt_in_journal_key_equals_sending_the_same_lists(self):  # P6
        server, config = self.server, self.server.config
        self._save(protected_paths=_PATHS)
        sent = server.InvestigateRequest(base_url=_BASE, protected_paths=_PATHS)
        opted = server.InvestigateRequest(base_url=_BASE, use_saved_declarations=True,
                                          protected_paths=_PATHS)
        bare = server.InvestigateRequest(base_url=_BASE)
        self.assertEqual(server._journal_context_key(config, opted), server._journal_context_key(config, sent))
        self.assertEqual(server._journal_context_key(config, server.InvestigateRequest(
            base_url=_BASE, use_saved_declarations=True)), server._journal_context_key(config, bare))


class SavedDeclarationsReachTheChainTests(rvs._ChainCase, unittest.TestCase):  # P7
    # unittest.TestCase is listed so test_no_orphan_test_files proves the ancestry statically.
    """The investigate route hands what it resolved to the real
    `investigate_engagement`, run (in a worker thread) on RV-S's loopback with the
    production `_confirm` dispatcher and missing-auth probe. The route's target is
    the synthetic captured.example; the bridge is the only double between them."""

    def setUp(self):
        from harness.test_pairing_contract import PairingCallerTests
        fx = PairingCallerTests("test_health_is_liveness_and_pairing_requires_credential")
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.server = fx.server
        self.server.orchestrator.allowed_hosts = ["captured.example"]
        self.server.orchestrator.config = self.server.config
        self.server.orchestrator.validator_registry = SimpleNamespace(active_enabled=False)
        self.server.orchestrator.agent_manager.agents = {}
        self.server.config["runs"] = {"output_dir": fx.tmp.name}
        self.client = fx.client
        self.client.headers.update(fx.auth)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        git = patch.object(self.server._run_manifest, "_git_state", return_value=(None, None))
        git.start()
        self.addCleanup(git.stop)

        def chain(declared):
            with _declaring(**declared):
                found, _ = self._run_chain(rvs._leak, ["/reports/q3"], via="label")
            return found["/reports/q3"]

        async def bridge(base_url, roles, **kwargs):
            declared = {k: kwargs[k] for k in ("protected_paths", "owners") if k in kwargs}
            return {"summary": {}, "findings_q3": await asyncio.to_thread(chain, declared)}
        self.server.orchestrator.investigate_engagement = bridge

    def _findings(self, **extra) -> list[dict]:
        response = self.client.post("/engagement/captured.example/investigate",
                                    json={"base_url": _BASE, **extra})
        self.assertEqual(response.status_code, 200, response.text)
        job_id = response.json()["job_id"]
        for _ in range(1000):
            job = self.client.get(f"/engagement/captured.example/investigate/{job_id}").json()
            if job["status"] in ("done", "failed", "cancelled"):
                break
            time.sleep(0.01)
        self.assertEqual(job["status"], "done", job)
        return job["result"]["findings_q3"]

    def test_saved_list_confirms_only_when_the_request_opts_in(self):
        reply = self.client.put("/engagement/captured.example/declarations",
                                json={"base_url": _BASE, "protected_paths": ["/reports/*"]})
        self.assertEqual(reply.status_code, 200, reply.text)
        self._assert_not_confirmed(self._findings(), "label")
        self._assert_confirmed(self._findings(use_saved_declarations=True), "/reports/*", "engagement")


class DeclarationsStoreMigrationTests(unittest.TestCase):  # P8
    """The frozen pre-I02-C schema opened by this build (AR-08a's pattern)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="i16_persist_")
        self._orig = store._DB_PATH
        self.db = Path(self._tmp) / "legacy.db"
        conn = sqlite3.connect(self.db)
        try:
            conn.executescript(_LEGACY_SQL.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO state_metadata VALUES ('principal-hmac-v1', ?)", ("11" * 32,))
            conn.commit()
            self.before = _legacy_identity(conn)
        finally:
            conn.close()
        store._DB_PATH = self.db

    def tearDown(self):
        store._DB_PATH = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _open(self) -> sqlite3.Connection:
        store._connect().close()
        return sqlite3.connect(self.db)

    def test_migration_is_additive_and_versioned(self):
        conn = self._open()
        try:
            self.assertIn("engagement_declarations", _schema(conn))
            self.assertEqual(conn.execute("SELECT value FROM state_metadata WHERE name = "
                                          "'engagement-declarations-schema'").fetchone(), ("1",))
            after = _legacy_identity(conn)
            self.assertEqual(after["schema"], self.before["schema"])
            self.assertEqual(after["user_version"], self.before["user_version"])
            self.assertEqual(conn.execute("SELECT count(*) FROM engagement_declarations").fetchone()[0], 0)
        finally:
            conn.close()
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 443))

    def test_round_trip_is_per_host_and_port(self):
        store.save_engagement_declarations("Legacy.Example", 443, protected_paths=_PATHS, owners=_OWNERS)
        saved = store.load_engagement_declarations("legacy.example", 443)
        self.assertEqual((saved["protected_paths"], saved["owners"]), (_PATHS, _OWNERS))
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 8443))
        self.assertIsNone(store.load_engagement_declarations("other.example", 443))
        store.save_engagement_declarations("legacy.example", 443, protected_paths=[], owners=[])
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 443))

    def test_stored_row_holds_only_the_declarations(self):
        store.save_engagement_declarations("legacy.example", 443, protected_paths=_PATHS, owners=_OWNERS)
        conn = sqlite3.connect(self.db)
        try:
            (row,) = conn.execute("SELECT * FROM engagement_declarations").fetchall()
        finally:
            conn.close()
        self.assertEqual(row[:4], ("legacy.example", 443, json.dumps(_PATHS), json.dumps(_OWNERS)))

    def test_other_version_reads_as_nothing_saved(self):
        store.save_engagement_declarations("legacy.example", 443, protected_paths=_PATHS, owners=[])
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("UPDATE engagement_declarations SET declarations_version = ?",
                         (store._DECLARATIONS_VERSION + 1,))
            conn.commit()
        finally:
            conn.close()
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 443))

    def test_rollback_restores_the_legacy_store(self):
        store.save_engagement_declarations("legacy.example", 443, protected_paths=_PATHS, owners=[])
        conn = sqlite3.connect(self.db)
        try:
            # Rollback SQL for this migration, plus the earlier side tables this
            # fixture predates (each has its own rollback test).
            conn.executescript("""
                DROP TABLE engagement_declarations;
                DELETE FROM state_metadata WHERE name = 'engagement-declarations-schema';
                DROP TABLE proof_identity;
                DELETE FROM state_metadata WHERE name = 'proof-identity-schema';
                DROP TABLE exchange_observations;
                DROP TABLE observation_attributions;
                DELETE FROM state_metadata WHERE name = 'observation-schema';
                DROP TABLE finding_inputs;
                DELETE FROM state_metadata WHERE name = 'finding-inputs-schema';
            """)
            after = _legacy_identity(conn)
        finally:
            conn.close()
        self.assertEqual(after, self.before)
        # Re-migrating recreates an empty table: nothing is applied from the rollback.
        store._INITIALISED.clear()
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 443))

    def test_wipe_engagement_removes_only_that_hosts_declarations(self):
        store.save_engagement_declarations("legacy.example", 443, protected_paths=_PATHS, owners=[])
        store.save_engagement_declarations("legacy.example", 8443, protected_paths=_PATHS, owners=[])
        store.save_engagement_declarations("other.example", 443, protected_paths=_PATHS, owners=[])
        self.assertEqual(store.wipe_engagement("legacy.example:8443")["engagement_declarations"], 1)
        self.assertIsNotNone(store.load_engagement_declarations("legacy.example", 443))
        self.assertEqual(store.wipe_engagement("legacy.example")["engagement_declarations"], 1)
        self.assertIsNone(store.load_engagement_declarations("legacy.example", 443))
        self.assertIsNotNone(store.load_engagement_declarations("other.example", 443))


if __name__ == "__main__":
    unittest.main()
