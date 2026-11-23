"""OPS-5: per-engagement stores, close-with-export, and the optional retention TTL.

Caller-level: the server's POST /engagements/close route, the
data_maintenance CLI, and the store's own select/close/retention entry
points, each against a temporary legacy store. Includes the negative
controls the brief asks for: with the per-engagement separation forced
off, closing one engagement also removes the other's data.
"""
import contextlib
import hashlib
import importlib
import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml

from harness import data_maintenance, store
from harness.models import Finding, HttpExchange

_A, _B = "acme-2026", "globex-2026"
_URL_A = "https://a.example/api/1"
_URL_B = "https://b.example/api/1"
_URL_L = "https://legacy.example/api/1"


def _exchange(url: str) -> HttpExchange:
    return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body='{"id": 1}')


def _seed(url: str, case_id: str, *, engagement_id: str = "") -> None:
    finding = Finding(vulnerability_class="sqli", confidence=0.9, summary=f"finding {case_id}",
                      evidence="e", suggested_test="t", basis="derived", case_id=case_id,
                      finding_id=f"{case_id}-finding", proof_id=f"{case_id}-proof")
    store.persist_findings(_exchange(url), "test_agent", [finding], engagement_id=engagement_id)


def _rows(path: Path, sql: str, params=()) -> list:
    conn = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class _StoreFixture(unittest.TestCase):
    """A temporary legacy store; restores every module-level store selection."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self._tmp.name)
        self._saved = (store._DB_PATH, store._ACTIVE_ENGAGEMENT, store._ACTIVE_STORE_PATH,
                       store._LEGACY_DB_PATH)
        store._DB_PATH = self.root / "harness_state.db"
        store._ACTIVE_ENGAGEMENT, store._ACTIVE_STORE_PATH = "", None
        self.legacy = store._DB_PATH

    def tearDown(self):
        store._release_store_lock()
        (store._DB_PATH, store._ACTIVE_ENGAGEMENT, store._ACTIVE_STORE_PATH,
         store._LEGACY_DB_PATH) = self._saved
        self._tmp.cleanup()

    def _seed_two_engagements(self) -> tuple[str, str]:
        store.select_engagement_store(_A)
        _seed(_URL_A, "A1")
        blob_a = store.put_evidence_blob(b"acme evidence bytes")
        store.select_engagement_store(_B)
        _seed(_URL_B, "B1")
        blob_b = store.put_evidence_blob(b"globex evidence bytes")
        store.select_engagement_store("")
        return blob_a, blob_b

    def _findings_in(self, engagement_id: str, url: str) -> int:
        previous = store.active_engagement()
        store.select_engagement_store(engagement_id)
        try:
            return len(store.all_host_findings(url))
        finally:
            store.select_engagement_store(previous)

    def _exports(self) -> list[Path]:
        root = self.root / "engagement_exports"
        return sorted(root.iterdir()) if root.is_dir() else []


class SeparateStoresTests(_StoreFixture):

    def test_two_engagements_write_separate_databases(self):
        store.select_engagement_store(_A)
        _seed(_URL_A, "A1")
        blob = store.put_evidence_blob(b"acme evidence bytes")
        store.record_observation(_exchange(_URL_A).model_copy(update={"capture_id": "cap-a"}))
        path_a = Path(store._DB_PATH)
        store.select_engagement_store(_B)
        _seed(_URL_B, "B1")
        path_b = Path(store._DB_PATH)

        self.assertNotEqual(path_a, path_b)
        self.assertNotEqual(path_a.parent, path_b.parent)
        self.assertEqual(path_a.parent.parent, self.root / "engagements")
        # Each store holds only its own engagement's rows and blobs.
        self.assertEqual(_rows(path_a, "SELECT count(*) FROM findings")[0][0], 1)
        self.assertEqual(_rows(path_b, "SELECT count(*) FROM findings")[0][0], 1)
        self.assertEqual(_rows(path_a, "SELECT count(*) FROM evidence_blobs WHERE sha256 = ?", (blob,))[0][0], 1)
        self.assertEqual(_rows(path_b, "SELECT count(*) FROM evidence_blobs WHERE sha256 = ?", (blob,))[0][0], 0)
        self.assertEqual(_rows(path_a, "SELECT count(*) FROM exchange_observations")[0][0], 1)
        self.assertEqual(_rows(path_b, "SELECT count(*) FROM exchange_observations")[0][0], 0)
        self.assertEqual(len(store.all_host_findings(_URL_A)), 0, "B's store must not see A's finding")
        # Neither engagement wrote into the legacy single store.
        self.assertFalse(self.legacy.exists())
        self.assertEqual(store.active_engagement(), _B)
        self.assertEqual({entry["engagement_id"] for entry in store.list_engagement_stores()}, {_A, _B})

    def test_legacy_single_store_still_loads_and_is_not_modified(self):
        _seed(_URL_L, "L1")
        before = _sha(self.legacy)
        store.select_engagement_store(_A)
        _seed(_URL_A, "A1")
        self.assertEqual(_sha(self.legacy), before, "selecting an engagement must not touch the legacy store")
        self.assertEqual(store.legacy_store_path(), self.legacy)
        store.select_engagement_store("")
        self.assertEqual(Path(store._DB_PATH), self.legacy)
        self.assertEqual(store.active_engagement(), "")
        self.assertEqual(len(store.all_host_findings(_URL_L)), 1)

    def test_a_directory_claimed_by_another_engagement_fails_closed(self):
        directory = store.engagement_store_dir(_A)
        directory.mkdir(parents=True)
        (directory / "engagement.json").write_text(json.dumps({"engagement_id": _B}), encoding="utf-8")
        with self.assertRaises(ValueError):
            store.select_engagement_store(_A)
        self.assertEqual(Path(store._DB_PATH), self.legacy)

    def test_ids_that_slug_alike_get_different_directories(self):
        self.assertNotEqual(store.engagement_store_key("acme/2026"), store.engagement_store_key("acme 2026"))
        for bad in ("", " acme", "acme\n", "x" * 129, None):
            with self.assertRaises(ValueError):
                store.engagement_store_key(bad)


class CloseRouteTests(_StoreFixture):
    """POST /engagements/close, through the real server app."""

    def setUp(self):
        super().setUp()
        import harness.server as server_module
        importlib.reload(server_module)
        self.server = server_module
        self.assertIsNone(self.server._BEARER_TOKEN,
                          "test env must have no operator auth_token/HARNESS_BEARER_TOKEN set")
        self.assertFalse(self.server._WIPE_ENDPOINT_ENABLED, "server.enable_wipe_endpoint must ship false")
        self.token = self.server._mutation_token()
        self.server._WIPE_ENDPOINT_ENABLED = True
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        self.server._WIPE_ENDPOINT_ENABLED = False
        super().tearDown()

    def _close(self, engagement_id: str, confirm: str | None = None, *, token: str | None = "",
               **extra):
        headers = {} if token is None else {"Authorization": f"Bearer {token or self.token}"}
        body = {"engagement_id": engagement_id, **extra}
        if confirm is not None:
            body["confirm"] = confirm
        return self.client.post("/engagements/close", json=body, headers=headers)

    def test_close_exports_then_removes_one_engagement_and_leaves_the_other(self):
        blob_a, blob_b = self._seed_two_engagements()
        _seed(_URL_L, "L-shared")                      # unattributed legacy row: stays
        _seed(_URL_L, "L-acme", engagement_id=_A)      # legacy row attributed to A: closed with A
        _seed(_URL_L, "L-globex", engagement_id=_B)    # legacy row attributed to B: stays
        dir_a, dir_b = store.engagement_store_dir(_A), store.engagement_store_dir(_B)

        resp = self._close(_A, _A)
        self.assertEqual(resp.status_code, 200, resp.text)
        receipt = resp.json()
        self.assertEqual(receipt["status"], "closed")
        self.assertFalse(receipt["secure_erasure"])
        self.assertTrue(receipt["removed"]["engagement_store"])
        self.assertEqual(receipt["removed"]["legacy_rows"].get("findings"), 1)

        # Removed: A's own store directory and A's attributed legacy row.
        self.assertFalse(dir_a.exists())
        self.assertEqual(len(store.all_host_findings(_URL_L, engagement_id=_A)), 0)
        # Untouched: B's store, its blob, the unattributed and B-attributed legacy rows.
        self.assertTrue(dir_b.is_dir())
        self.assertEqual(self._findings_in(_B, _URL_B), 1)
        self.assertEqual(_rows(store.engagement_store_path(_B),
                               "SELECT count(*) FROM evidence_blobs WHERE sha256 = ?", (blob_b,))[0][0], 1)
        self.assertEqual(len(store.all_host_findings(_URL_L)), 1)
        self.assertEqual(len(store.all_host_findings(_URL_L, engagement_id=_B)), 1)

        # Exported first: A's rows and blob are in the export, with matching digests.
        export = Path(receipt["export_dir"])
        self.assertEqual(export.parent, self.root / "engagement_exports")
        snapshot = export / "engagement_store" / "harness_state.db"
        self.assertEqual(_rows(snapshot, "SELECT case_id FROM findings"), [("A1",)])
        self.assertEqual(_rows(snapshot, "SELECT count(*) FROM evidence_blobs WHERE sha256 = ?", (blob_a,))[0][0], 1)
        self.assertEqual(_sha(snapshot), receipt["exported"]["engagement_store/harness_state.db"]["sha256"])
        subset = export / "legacy_store_subset.db"
        self.assertEqual(_rows(subset, "SELECT case_id, engagement_id FROM findings"), [("L-acme", _A)])
        manifest = export / "export_manifest.json"
        self.assertEqual(_sha(manifest), receipt["export_manifest_sha256"])
        self.assertEqual(json.loads(manifest.read_text(encoding="utf-8"))["engagement_id"], _A)
        self.assertEqual({entry["engagement_id"] for entry in store.list_engagement_stores()}, {_B})

    def test_negative_control_without_separation_one_close_removes_both(self):
        # Force the separation off: every engagement maps to one directory and
        # the ownership manifest is not checked. The same close then removes
        # B's data too, which the test above would catch.
        with mock.patch.object(store, "engagement_store_key", lambda engagement_id: "shared-store"), \
                mock.patch.object(store, "_claim_engagement_dir",
                                  lambda directory, engagement_id: directory.mkdir(parents=True, exist_ok=True)), \
                mock.patch.object(store, "_manifest_engagement", lambda directory: _A):
            self._seed_two_engagements()
            self.assertEqual(self._findings_in(_B, _URL_B), 1)
            resp = self._close(_A, _A)
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(self._findings_in(_B, _URL_B), 0, "without separation B's finding goes too")

    def test_missing_or_wrong_confirmation_removes_nothing(self):
        self._seed_two_engagements()
        for confirm in (None, "", _B, _A.upper()):
            resp = self._close(_A, confirm)
            self.assertEqual(resp.status_code, 422, (confirm, resp.text))
        self.assertTrue(store.engagement_store_dir(_A).is_dir())
        self.assertEqual(self._findings_in(_A, _URL_A), 1)
        self.assertEqual(self._exports(), [])

    def test_auth_and_opt_in_gate_the_route(self):
        self._seed_two_engagements()
        self.assertEqual(self._close(_A, _A, token=None).status_code, 401)
        self.assertEqual(self._close(_A, _A, token="not-the-real-token").status_code, 401)
        self.server._WIPE_ENDPOINT_ENABLED = False
        self.assertEqual(self._close(_A, _A).status_code, 403)
        self.assertTrue(store.engagement_store_dir(_A).is_dir())
        self.assertEqual(self._exports(), [])

    def test_active_unknown_malformed_and_unexpected_entries_are_refused(self):
        self._seed_two_engagements()
        store.select_engagement_store(_A)
        self.assertEqual(self._close(_A, _A).status_code, 409)
        store.select_engagement_store("")
        self.assertEqual(self._close("never-stored", "never-stored").status_code, 404)
        self.assertEqual(self._close(" acme", " acme").status_code, 422)
        self.assertEqual(self._close(_A, _A, export_dir=str(self.root)).status_code, 422)
        # A file close does not recognise fails closed: nothing exported or removed.
        stray = store.engagement_store_dir(_A) / "notes.txt"
        stray.write_text("operator notes", encoding="utf-8")
        self.assertEqual(self._close(_A, _A).status_code, 422)
        self.assertTrue(stray.is_file())
        self.assertEqual(self._findings_in(_A, _URL_A), 1)
        self.assertEqual(self._exports(), [])

    def test_wipe_route_reports_which_store_it_acted_on(self):
        store.select_engagement_store(_B)
        _seed(_URL_B, "B1")
        resp = self.client.delete("/engagement/b.example/evidence",
                                  headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["engagement_store"], _B)
        self.assertEqual(len(store.all_host_findings(_URL_B)), 0)


_HOLDER = (
    "import sys\n"
    "from pathlib import Path\n"
    "from harness import store\n"
    "store._DB_PATH = Path(sys.argv[1])\n"
    "store.select_engagement_store(sys.argv[2])\n"
    "print('ready', flush=True)\n"
    "sys.stdin.read()\n")


def _child_env(**extra) -> dict:
    env = {key: value for key, value in os.environ.items() if key != store.ENGAGEMENT_ENV_VAR}
    env["PYTHONPATH"] = str(Path(store.__file__).resolve().parent.parent)
    env.update(extra)
    return env


class CrossProcessAndRecoveryTests(_StoreFixture):

    def test_a_store_another_process_has_selected_is_not_closed(self):
        import subprocess
        import sys
        self._seed_two_engagements()
        holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(self.legacy), _A],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=_child_env(), text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "ready")
            with self.assertRaises(store.EngagementStoreActive):
                store.close_engagement(_A)
            self.assertTrue(store.engagement_store_dir(_A).is_dir())
            self.assertEqual(self._findings_in(_A, _URL_A), 1)
            self.assertEqual(self._exports(), [])
            self.assertEqual(store.interrupted_closes(), [])
        finally:
            holder.communicate("", timeout=30)
        # Negative control: once the holder exits, the same close goes through.
        self.assertEqual(store.close_engagement(_A)["status"], "closed")

    def test_an_interrupted_close_is_recovered_not_hidden(self):
        self._seed_two_engagements()
        directory = store.engagement_store_dir(_A)
        aside = directory.with_name(f".closing-{directory.name}-deadbeef")
        os.rename(directory, aside)                       # as if the process died mid-export
        self.assertEqual(store.interrupted_closes(_A), [aside])
        self.assertNotIn(_A, [entry["engagement_id"] for entry in store.list_engagement_stores()])
        with self.assertRaises(ValueError):
            store.select_engagement_store(_A)            # no fresh store over the set-aside data
        receipt = store.close_engagement(_A)
        self.assertEqual(receipt["status"], "closed")
        self.assertEqual(_rows(Path(receipt["export_dir"]) / "engagement_store" / "harness_state.db",
                               "SELECT case_id FROM findings"), [("A1",)])
        self.assertFalse(aside.exists())
        self.assertEqual(store.interrupted_closes(), [])
        self.assertEqual(self._findings_in(_B, _URL_B), 1)

    def test_export_inside_the_engagement_stores_is_refused(self):
        self._seed_two_engagements()
        for root in (store.engagement_store_dir(_A) / "out", store.engagements_root()):
            with self.assertRaises(ValueError):
                store.close_engagement(_A, export_root=root)
        self.assertEqual(self._findings_in(_A, _URL_A), 1)
        self.assertEqual(sorted(path.name for path in store.engagement_store_dir(_A).iterdir()),
                         ["engagement.json", "engagement.lock", "harness_state.db"])

    def test_retention_apply_reports_a_failed_close_and_continues(self):
        self._seed_two_engagements()
        for engagement_id in (_A, _B):
            self._age(engagement_id, 40)
        real = store.close_engagement

        def flaky(engagement_id, **kwargs):
            if engagement_id == _A:
                raise PermissionError("locked")
            return real(engagement_id, **kwargs)

        with mock.patch.object(store, "close_engagement", flaky):
            result = store.apply_engagement_retention(30, apply=True)
        self.assertEqual(result["failed"], [{"engagement_id": _A, "error_type": "PermissionError"}])
        self.assertEqual([receipt["engagement_id"] for receipt in result["closed"]], [_B])
        self.assertTrue(store.engagement_store_dir(_A).is_dir())

    def test_a_malformed_environment_id_names_the_variable(self):
        import subprocess
        import sys
        done = subprocess.run([sys.executable, "-c", "import harness.store"], capture_output=True, text=True,
                              env=_child_env(**{store.ENGAGEMENT_ENV_VAR: "acme "}), timeout=60)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(store.ENGAGEMENT_ENV_VAR, done.stderr)

    def _age(self, engagement_id: str, days: float) -> None:
        RetentionTests._age(self, engagement_id, days)


class CloseCliTests(_StoreFixture):

    def _main(self, *argv) -> tuple[int, dict]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = data_maintenance.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_cli_close_requires_the_repeated_id(self):
        self._seed_two_engagements()
        code, result = self._main("close-engagement", "--engagement-id", _A, "--confirm", _B)
        self.assertEqual((code, result["status"]), (1, "failed"))
        self.assertTrue(store.engagement_store_dir(_A).is_dir())

        export_root = self.root / "operator_exports"
        code, result = self._main("close-engagement", "--engagement-id", _A, "--confirm", _A,
                                  "--export-dir", str(export_root))
        self.assertEqual((code, result["status"]), (0, "closed"))
        self.assertEqual(Path(result["export_dir"]).parent, export_root)
        self.assertFalse(store.engagement_store_dir(_A).exists())
        self.assertEqual(self._findings_in(_B, _URL_B), 1)

        code, result = self._main("engagements")
        self.assertEqual([entry["engagement_id"] for entry in result["stores"]], [_B])


class RetentionTests(_StoreFixture):

    def _age(self, engagement_id: str, days: float) -> None:
        stamp = time.time() - days * 86400
        for entry in store.engagement_store_dir(engagement_id).iterdir():
            os.utime(entry, (stamp, stamp))

    def test_ships_off(self):
        config = yaml.safe_load((Path(store.__file__).with_name("config.yaml")).read_text(encoding="utf-8"))
        self.assertEqual(store.engagement_retention_days(config), 0)
        self.assertEqual(store.engagement_retention_days({}), 0)
        for bad in (-1, True, "30", float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                store.engagement_retention_days({"store": {"engagement_retention_days": bad}})

    def test_off_never_expires_and_dry_run_removes_nothing(self):
        self._seed_two_engagements()
        self._age(_A, 400)
        self.assertEqual(store.apply_engagement_retention(0, apply=True)["expired"], [])
        result = store.apply_engagement_retention(30)
        self.assertEqual((result["expired"], result["closed"], result["applied"]), ([_A], [], False))
        self.assertTrue(store.engagement_store_dir(_A).is_dir())
        self.assertEqual(self._exports(), [])

    def test_apply_exports_and_closes_only_expired_inactive_stores(self):
        self._seed_two_engagements()
        store.select_engagement_store("active-2026")
        _seed(_URL_A, "X1")
        for engagement_id in (_A, "active-2026"):
            self._age(engagement_id, 40)
        result = store.apply_engagement_retention(30, apply=True)
        self.assertEqual(result["expired"], [_A], "the active store and the fresh store must not expire")
        self.assertEqual(result["closed"][0]["status"], "closed")
        self.assertTrue(Path(result["closed"][0]["export_dir"]).is_dir())
        self.assertFalse(store.engagement_store_dir(_A).exists())
        self.assertEqual(self._findings_in(_B, _URL_B), 1)
        self.assertTrue(store.engagement_store_dir("active-2026").is_dir())

    def test_negative_control_the_active_store_is_old_enough_to_expire(self):
        # On age alone the active store would expire; only the active guard keeps it.
        store.select_engagement_store(_A)
        _seed(_URL_A, "A1")
        self._age(_A, 40)
        cutoff = time.time() - 30 * 86400
        listed = store.list_engagement_stores()
        self.assertEqual([entry["engagement_id"] for entry in listed if entry["last_write"] < cutoff], [_A])
        self.assertTrue(listed[0]["active"])
        self.assertEqual(store.expired_engagement_stores(30), [])
        with self.assertRaises(store.EngagementStoreActive):
            store.close_engagement(_A)


if __name__ == "__main__":
    unittest.main()
