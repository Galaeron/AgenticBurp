"""Explicit SQLite snapshot maintenance. No implicit paths or destructive commands.

OPS-5: `close-engagement` exports, then removes, one engagement's store and its
attributed rows in the legacy store; `retention` lists (and with --apply closes)
engagement stores past store.engagement_retention_days. Both are explicit
commands; nothing here runs on its own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import time

from harness.security import _restrict_windows_file_acl


def maintenance_plan() -> dict:
    """No filesystem reads: scope inventory for an operator's maintenance plan."""
    return {"automatic_retention": False, "secure_erasure": False,
            "actions": [
                {"store": "main SQLite", "supported": "explicit verified backup/restore to new path",
                 "retention": "explicit global evidence-blob expiry only; default keep forever",
                 "deletion": "opt-in host subset; explicit engagement-attributed subset (wipe-context, "
                             "close-engagement exports it first)"},
                {"store": "engagement SQLite (engagements/<key>/)",
                 "supported": "one store per engagement, selected per process (HARNESS_ENGAGEMENT_ID)",
                 "retention": "optional store.engagement_retention_days; default 0 keeps forever; "
                              "applied only by the explicit retention --apply command",
                 "deletion": "close-engagement: verified export, then file removal (not secure erasure)"},
                {"store": "cache SQLite", "supported": "explicit SQLite backup/restore to new path",
                 "retention": "cache clear/expiry APIs; no age-based physical erasure guarantee"},
                {"store": "logs", "supported": "operator-owned sink rotation and closed-file handling",
                 "retention": "size/backups; no automatic age policy"},
                {"store": "exports/traces/external captures", "supported": "operator inventory and producer-specific removal",
                 "retention": "outside database maintenance"},
                {"store": "pairing/local config", "supported": "operator OS protection; re-pair after restore",
                 "retention": "excluded from SQLite snapshots"}],
            "requires": ["full-disk encryption of the state and export directories",
                         "operator-owned trusted directories", "separate encrypted backup policy",
                         "quiesced sealed backup for restore", "manual external-artifact inventory"]}


def _open_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)


def inspect_database(conn: sqlite3.Connection) -> dict:
    """Inventory a snapshot without emitting rows, credentials or raw evidence."""
    if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite integrity check failed")
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    counts = {name: conn.execute('SELECT count(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0]
              for name in tables}
    hashes = set()
    if "evidence_blobs" in tables:
        for digest, data in conn.execute("SELECT sha256, data FROM evidence_blobs"):
            if hashlib.sha256(bytes(data)).hexdigest() != digest:
                raise ValueError("Evidence blob integrity check failed")
            hashes.add(digest)
    references = set()
    if "ledger_events" in tables:
        for (raw,) in conn.execute("SELECT data_json FROM ledger_events"):
            try:
                event = json.loads(raw or "{}")
            except (ValueError, TypeError):
                raise ValueError("Malformed ledger data") from None
            if not isinstance(event, dict):
                raise ValueError("Malformed ledger data")
            for key in ("request_blob", "response_blob"):
                digest = event.get(key)
                if digest is not None:
                    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                        raise ValueError("Malformed evidence reference")
                    references.add(digest)
    if "exchange_observations" in tables:
        # I02-C: an observation's sanitized-capture blob is a registered reference too.
        for (digest,) in conn.execute(
                "SELECT evidence_sha256 FROM exchange_observations WHERE evidence_sha256 != ''"):
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Malformed evidence reference")
            references.add(digest)
    return {"tables": counts, "blob_count": len(hashes), "referenced_blob_count": len(references),
            "unavailable_reference_count": len(references - hashes),
            "scope": "one SQLite database; no caches/logs/exports/token files"}


def snapshot(source: Path, destination: Path, *, expected_sha256: str | None = None) -> dict:
    """Back up via SQLite or restore a verified sealed backup to a NEW path.

    Never replace an existing database. Destination parent must be operator owned.
    Restore requires the externally retained digest returned by backup. Missing
    historical evidence is counted honestly; corrupt present blobs fail closed.
    """
    source = Path(source).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Destination already exists")
    if not source.is_file():
        raise ValueError("Source must be a database file")
    if expected_sha256 is not None:
        if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError("Restore requires a sealed backup without SQLite sidecars")
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError("Backup digest mismatch")
    fd, name = tempfile.mkstemp(prefix=".sqlite-snapshot-", dir=destination.parent)
    temporary = Path(name)
    os.close(fd)
    try:
        if os.name == "nt":
            _restrict_windows_file_acl(temporary)
        else:
            temporary.chmod(0o600)
        with _open_readonly(source) as original, sqlite3.connect(temporary) as copied:
            original.backup(copied)
            # DELETE journal mode yields a portable sealed single-file snapshot.
            copied.execute("PRAGMA journal_mode=DELETE")
            report = inspect_database(copied)
        # sqlite context managers commit but do not close handles.
        original.close()
        copied.close()
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        report["sha256"] = hashlib.sha256(temporary.read_bytes()).hexdigest()
        # Atomic publication without overwrite, including a racing destination.
        if os.name == "nt":
            os.rename(temporary, destination)  # Windows fails if destination exists.
        else:
            os.link(temporary, destination)
        return report
    finally:
        # Explicit close also on failed verification (needed on Windows).
        if "original" in locals():
            original.close()
        if "copied" in locals():
            copied.close()
        temporary.unlink(missing_ok=True)


_CONTEXT_OWNED_TABLES = ("findings", "ledger_events", "scoped_engagement_state", "knowledge_notes",
                         "work_items", "exchange_observations", "observation_attributions")
# ARC-13: ledger_chain has no engagement_id; a context owns the chain rows of its events.
_LEDGER_CHAIN = "ledger_chain"
_CONTEXT_CHAIN_ROWS = "event_id IN (SELECT event_id FROM ledger_events WHERE engagement_id=?)"
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
_ENGAGEMENT_MANIFEST = "engagement.json"
_ENGAGEMENT_LOCK = "engagement.lock"
_LEGACY_SUBSET = "legacy_store_subset.db"
_EXPORT_MANIFEST = "export_manifest.json"
_EXPORT_FORMAT = "sqlite-snapshot-v1"


def _validated_context(engagement_id) -> str:
    if (not isinstance(engagement_id, str) or not engagement_id
            or engagement_id != engagement_id.strip() or len(engagement_id) > 128):
        raise ValueError("An explicit nonempty engagement ID is required")
    return engagement_id


def _context_columns(conn: sqlite3.Connection, inventory: dict) -> dict[str, set[str]]:
    columns = {name: {row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')}
               for name in _CONTEXT_OWNED_TABLES if name in inventory["tables"]}
    if "engagement_id" not in columns.get("findings", set()) or "engagement_id" not in columns.get("ledger_events", set()):
        raise ValueError("Database lacks explicit finding/ledger ownership")
    return columns


def _context_blobs(conn: sqlite3.Connection, engagement_id: str, columns: dict) -> tuple[set, set]:
    """(blobs the context references, blobs every other surviving row references)."""
    candidate, surviving = set(), set()
    for owner, raw in conn.execute("SELECT engagement_id, data_json FROM ledger_events"):
        event = json.loads(raw or "{}")  # inspect_database already validates shape.
        for key in ("request_blob", "response_blob"):
            digest = event.get(key)
            if digest:
                (candidate if owner == engagement_id else surviving).add(digest)
    if "engagement_id" in columns.get("exchange_observations", set()):
        for owner, digest in conn.execute(
                "SELECT engagement_id, evidence_sha256 FROM exchange_observations WHERE evidence_sha256 != ''"):
            (candidate if owner == engagement_id else surviving).add(digest)
    return candidate, surviving


def _delete_context(conn: sqlite3.Connection, engagement_id: str, inventory: dict, columns: dict,
                    candidate: set, surviving: set) -> dict:
    counts = {}
    if _LEDGER_CHAIN in inventory["tables"]:
        # ARC-13: an event's chain row goes with it (first: the subquery needs the events).
        counts[_LEDGER_CHAIN] = conn.execute(
            f"DELETE FROM {_LEDGER_CHAIN} WHERE {_CONTEXT_CHAIN_ROWS}", (engagement_id,)).rowcount
    for name in _CONTEXT_OWNED_TABLES:
        if "engagement_id" in columns.get(name, set()):
            counts[name] = conn.execute(f'DELETE FROM "{name}" WHERE engagement_id=?', (engagement_id,)).rowcount
    counts["evidence_blobs"] = 0
    if "evidence_blobs" in inventory["tables"]:
        for digest in candidate - surviving:
            counts["evidence_blobs"] += conn.execute("DELETE FROM evidence_blobs WHERE sha256=?", (digest,)).rowcount
    return {"deleted": counts, "scope": "explicit engagement-owned subset across hosts",
            "preserved_unowned_tables": [name for name in inventory["tables"]
                                         if name not in _CONTEXT_OWNED_TABLES
                                         and name not in ("evidence_blobs", _LEDGER_CHAIN)],
            "external_artifacts": "untouched; separate operator maintenance required"}


def _open_context(source: Path) -> sqlite3.Connection:
    # rw forbids silently creating a missing database.
    return sqlite3.connect(Path(source).resolve(strict=True).as_uri() + "?mode=rw", uri=True, timeout=10)


def wipe_context(source: Path, engagement_id: str) -> dict:
    """Delete explicitly attributed rows only, across hosts in one named context.

    Legacy/unowned rows and separate stores remain. All surviving ledger rows,
    including orphan rows, protect shared blobs. No reference-owner inference.
    """
    engagement_id = _validated_context(engagement_id)
    conn = _open_context(source)
    try:
        conn.execute("BEGIN IMMEDIATE")
        inventory = inspect_database(conn)
        columns = _context_columns(conn, inventory)
        candidate, surviving = _context_blobs(conn, engagement_id, columns)
        result = _delete_context(conn, engagement_id, inventory, columns, candidate, surviving)
        conn.commit()
        return result
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def context_row_count(source: Path, engagement_id: str) -> int:
    """OPS-5: rows one database explicitly attributes to `engagement_id` (0 when
    the file is missing or has no ownership columns). Read-only."""
    engagement_id = _validated_context(engagement_id)
    source = Path(source)
    if not source.is_file():
        return 0
    conn = _open_readonly(source.resolve())
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        total = 0
        for name in _CONTEXT_OWNED_TABLES:
            if name in tables and "engagement_id" in {row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')}:
                total += conn.execute(f'SELECT count(*) FROM "{name}" WHERE engagement_id=?',
                                      (engagement_id,)).fetchone()[0]
        return total
    finally:
        conn.close()


def _private_temporary(directory: Path, prefix: str) -> Path:
    fd, name = tempfile.mkstemp(prefix=prefix, dir=directory)
    os.close(fd)
    temporary = Path(name)
    try:
        if os.name == "nt":
            _restrict_windows_file_acl(temporary)
        else:
            temporary.chmod(0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _publish(temporary: Path, destination: Path) -> None:
    """fsync, then publish without overwriting an existing destination."""
    with temporary.open("r+b") as stream:
        os.fsync(stream.fileno())
    if os.name == "nt":
        os.rename(temporary, destination)  # Windows fails if destination exists.
    else:
        os.link(temporary, destination)
        temporary.unlink()


def _write_private(destination: Path, data: bytes) -> str:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Destination already exists")
    temporary = _private_temporary(destination.parent, ".export-")
    try:
        temporary.write_bytes(data)
        _publish(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def _extract_context(conn: sqlite3.Connection, engagement_id: str, inventory: dict, columns: dict,
                     blobs: set, destination: Path) -> dict:
    """Copy one context's rows, and every blob they reference, into a new sealed
    SQLite file with the source's table definitions. Runs inside the caller's
    transaction, so it copies exactly the rows the caller then deletes."""
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Destination already exists")
    temporary = _private_temporary(destination.parent, ".context-export-")
    try:
        copied = sqlite3.connect(temporary)
        try:
            tables = [name for name in _CONTEXT_OWNED_TABLES if "engagement_id" in columns.get(name, set())]
            if _LEDGER_CHAIN in inventory["tables"]:
                tables.append(_LEDGER_CHAIN)   # so the export's ledger still verifies (ARC-13)
            if "evidence_blobs" in inventory["tables"]:
                tables.append("evidence_blobs")
            for name in tables:
                copied.execute(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                                            (name,)).fetchone()[0])
                names = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
                quoted = ",".join('"' + column.replace('"', '""') + '"' for column in names)
                insert = f'INSERT INTO "{name}" ({quoted}) VALUES ({",".join("?" for _ in names)})'
                if name == "evidence_blobs":
                    rows = (row for digest in sorted(blobs)
                            for row in conn.execute(f"SELECT {quoted} FROM evidence_blobs WHERE sha256=?", (digest,)))
                elif name == _LEDGER_CHAIN:
                    rows = conn.execute(f"SELECT {quoted} FROM {_LEDGER_CHAIN} WHERE {_CONTEXT_CHAIN_ROWS}",
                                        (engagement_id,))
                else:
                    rows = conn.execute(f'SELECT {quoted} FROM "{name}" WHERE engagement_id=?', (engagement_id,))
                copied.executemany(insert, rows)
            copied.commit()
            copied.execute("PRAGMA journal_mode=DELETE")
            report = inspect_database(copied)
        finally:
            copied.close()
        report["sha256"] = hashlib.sha256(temporary.read_bytes()).hexdigest()
        _publish(temporary, destination)
        return report
    finally:
        temporary.unlink(missing_ok=True)


def close_context(source: Path, engagement_id: str, destination: Path) -> dict:
    """OPS-5: export, then delete, the rows one database explicitly attributes to
    `engagement_id` (the wipe_context subset). Both run under one write lock, so
    the export at `destination` (a new file) holds exactly what was deleted."""
    engagement_id = _validated_context(engagement_id)
    destination = Path(destination).absolute()
    conn = _open_context(source)
    try:
        conn.execute("BEGIN IMMEDIATE")
        inventory = inspect_database(conn)
        columns = _context_columns(conn, inventory)
        candidate, surviving = _context_blobs(conn, engagement_id, columns)
        exported = _extract_context(conn, engagement_id, inventory, columns, candidate, destination)
        result = _delete_context(conn, engagement_id, inventory, columns, candidate, surviving)
        conn.commit()
        return {"exported": exported, **result}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _store_entries(directory: Path) -> list[Path]:
    """The SQLite databases of one engagement store. Anything besides them, their
    sidecars and the manifest fails closed, before anything is exported or moved."""
    entries = sorted(directory.iterdir())
    names = {entry.name for entry in entries}
    databases = []
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise ValueError("Engagement store holds an unexpected entry")
        if entry.name.endswith(".db"):
            databases.append(entry)
        elif not (entry.name in (_ENGAGEMENT_MANIFEST, _ENGAGEMENT_LOCK) or any(
                entry.name.endswith(suffix) and entry.name[:-len(suffix)] in names for suffix in _SQLITE_SIDECARS)):
            raise ValueError("Engagement store holds an unexpected entry")
    return databases


class StoreInUse(RuntimeError):
    """Another process has the engagement store selected (holds its lock file)."""


def _set_store_aside(store_dir: Path, closing: Path):
    """Rename the store directory aside, refusing while another process has it
    selected. POSIX: an exclusive flock on the lock file the selecting process
    holds shared (kept until the caller closes the returned handle). Windows:
    that process's open handle makes the rename itself fail."""
    held = None
    if os.name != "nt" and (store_dir / _ENGAGEMENT_LOCK).is_file():
        import fcntl
        held = open(store_dir / _ENGAGEMENT_LOCK, "rb")
        try:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            held.close()
            raise StoreInUse() from None
    try:
        os.rename(store_dir, closing)
    except PermissionError:
        if held is not None:
            held.close()
        raise StoreInUse() from None
    except BaseException:
        if held is not None:
            held.close()
        raise
    return held


def close_engagement_store(engagement_id: str, *, store_dir: Path | None, legacy_db: Path | None,
                           export_dir: Path) -> dict:
    """OPS-5: export, then remove, one engagement's data.

    `store_dir` is the engagement's own store directory (or None); `legacy_db` a
    shared database whose rows attributed to the engagement are closed with
    close_context (or None). `export_dir` must not exist yet. The store
    directory is first renamed aside, so no writer can add rows the export would
    miss (on Windows the rename fails, and nothing changes, while a handle is
    open). Every database is exported before any file or row is removed; if an
    export fails the directory is renamed back. Removal is a file delete, not
    secure erasure."""
    engagement_id = _validated_context(engagement_id)
    export_dir = Path(export_dir).absolute()
    store_dir = Path(store_dir) if store_dir is not None else None
    databases = _store_entries(store_dir) if store_dir is not None else []
    export_dir.parent.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir()
    if os.name != "nt":
        export_dir.chmod(0o700)
    closing = None
    held = None
    exported: dict[str, dict] = {}
    legacy = None
    try:
        if store_dir is not None:
            aside = store_dir.with_name(f".closing-{store_dir.name}-{secrets.token_hex(4)}")
            held = _set_store_aside(store_dir, aside)
            closing = aside
            target = export_dir / "engagement_store"
            target.mkdir()
            for database in databases:
                exported["engagement_store/" + database.name] = snapshot(
                    closing / database.name, target / database.name)
            manifest = closing / _ENGAGEMENT_MANIFEST
            if manifest.is_file():
                exported["engagement_store/" + _ENGAGEMENT_MANIFEST] = {
                    "sha256": _write_private(target / _ENGAGEMENT_MANIFEST, manifest.read_bytes())}
        if legacy_db is not None:
            legacy = close_context(legacy_db, engagement_id, export_dir / _LEGACY_SUBSET)
            exported[_LEGACY_SUBSET] = legacy["exported"]
    except BaseException:
        # Nothing was removed: close_context rolled back; move the store back.
        # If that fails too (the directory was recreated meanwhile), the store
        # stays aside, where store.close_engagement recovers it; the original
        # error is the one raised.
        if held is not None:
            held.close()
        if closing is not None and closing.exists():
            try:
                os.rename(closing, store_dir)
            except OSError:
                pass
        shutil.rmtree(export_dir, ignore_errors=True)
        raise
    files = {name: {key: report[key] for key in ("sha256", "tables", "blob_count") if key in report}
             for name, report in exported.items()}
    # The legacy rows may already be gone (committed above), so a failed manifest
    # write is reported in the receipt, which carries the same digests.
    try:
        manifest_sha = _write_private(export_dir / _EXPORT_MANIFEST, json.dumps(
            {"engagement_id": engagement_id, "format": _EXPORT_FORMAT, "exported_at": time.time(),
             "files": files}, sort_keys=True, indent=1).encode("utf-8"))
    except OSError:
        manifest_sha = None
    if held is not None:
        held.close()
    remaining = []
    if closing is not None:
        for entry in sorted(closing.iterdir()):
            try:
                entry.unlink()
            except OSError:
                remaining.append(entry.name)
        if not remaining:
            try:
                closing.rmdir()
            except OSError:
                remaining.append(".")
    receipt = {"engagement_id": engagement_id, "export_dir": str(export_dir), "export_format": _EXPORT_FORMAT,
               "export_manifest_sha256": manifest_sha, "exported": files,
               "removed": {"engagement_store": closing is not None and not remaining,
                           "legacy_rows": legacy["deleted"] if legacy else {}},
               "status": "closed" if not remaining else "exported_removal_incomplete",
               "secure_erasure": False}
    if remaining:
        receipt["removal_incomplete"] = {"path": str(closing), "entries": remaining}
    return receipt


def configured_engagement_retention_days() -> float:
    """store.engagement_retention_days from config.yaml, overlaid by the
    git-ignored config.local.yaml (0 = off, the shipped default)."""
    import yaml
    from harness import store
    base = Path(__file__).with_name("config.yaml")
    section: dict = {}
    for path in (base, base.with_name("config.local.yaml")):
        if path.is_file():
            loaded = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("store") or {}
            if "engagement_retention_days" in loaded:
                section["engagement_retention_days"] = loaded["engagement_retention_days"]
    return store.engagement_retention_days({"store": section})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="Print supported scope and exclusions; reads no files")
    wipe = commands.add_parser("wipe-context", help="Explicit deletion of engagement-attributed SQLite rows only")
    wipe.add_argument("--source", type=Path, required=True)
    wipe.add_argument("--engagement-id", required=True)
    commands.add_parser("engagements", help="List engagement stores (metadata only)")
    close = commands.add_parser("close-engagement",
                                help="Export, then remove, one engagement's store and attributed rows")
    close.add_argument("--engagement-id", required=True)
    close.add_argument("--confirm", required=True, help="The same engagement ID again")
    close.add_argument("--export-dir", type=Path, default=None)
    retention = commands.add_parser("retention", help="List engagement stores past the retention TTL; "
                                                      "--apply closes them (export first)")
    retention.add_argument("--days", type=float, default=None,
                           help="Override store.engagement_retention_days (0 = off)")
    retention.add_argument("--export-dir", type=Path, default=None)
    retention.add_argument("--apply", action="store_true")
    for command in ("backup", "restore"):
        action = commands.add_parser(command)
        action.add_argument("--source", type=Path, required=True)
        action.add_argument("--destination", type=Path, required=True)
        if command == "restore":
            action.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(json.dumps(maintenance_plan(), sort_keys=True))
        return 0
    try:
        if args.command == "wipe-context":
            result = wipe_context(args.source, args.engagement_id)
        elif args.command in ("engagements", "close-engagement", "retention"):
            from harness import store
            if args.command == "engagements":
                result = {"active": store.active_engagement(), "stores": store.list_engagement_stores(),
                          "interrupted_closes": [str(path) for path in store.interrupted_closes()]}
            elif args.command == "close-engagement":
                if args.confirm != args.engagement_id:
                    raise ValueError("--confirm must repeat the engagement ID")
                result = store.close_engagement(args.engagement_id, export_root=args.export_dir)
            else:
                days = configured_engagement_retention_days() if args.days is None else \
                    store.engagement_retention_days({"store": {"engagement_retention_days": args.days}})
                result = store.apply_engagement_retention(days, apply=args.apply, export_root=args.export_dir)
        else:
            result = snapshot(args.source, args.destination,
                              expected_sha256=getattr(args, "expected_sha256", None))
    except (OSError, ValueError, LookupError, sqlite3.Error) as exc:
        # Exception strings may contain raw database values or operator paths.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps({"status": "ok", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
