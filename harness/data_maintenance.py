"""Explicit SQLite snapshot maintenance. No implicit paths or destructive commands."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from harness.security import _restrict_windows_file_acl


def maintenance_plan() -> dict:
    """No filesystem reads: scope inventory for an operator's maintenance plan."""
    return {"automatic_retention": False, "secure_erasure": False,
            "actions": [
                {"store": "main SQLite", "supported": "explicit verified backup/restore to new path",
                 "retention": "explicit global evidence-blob expiry only; default keep forever",
                 "deletion": "opt-in host subset only; no context-wide erasure"},
                {"store": "cache SQLite", "supported": "explicit SQLite backup/restore to new path",
                 "retention": "cache clear/expiry APIs; no age-based physical erasure guarantee"},
                {"store": "logs", "supported": "operator-owned sink rotation and closed-file handling",
                 "retention": "size/backups; no automatic age policy"},
                {"store": "exports/traces/external captures", "supported": "operator inventory and producer-specific removal",
                 "retention": "outside database maintenance"},
                {"store": "pairing/local config", "supported": "operator OS protection; re-pair after restore",
                 "retention": "excluded from SQLite snapshots"}],
            "requires": ["operator-owned trusted directories", "separate encrypted backup policy",
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


def wipe_context(source: Path, engagement_id: str) -> dict:
    """Delete explicitly attributed rows only, across hosts in one named context.

    Legacy/unowned rows and separate stores remain. All surviving ledger rows,
    including orphan rows, protect shared blobs. No reference-owner inference.
    """
    if not engagement_id or engagement_id != engagement_id.strip() or len(engagement_id) > 128:
        raise ValueError("An explicit nonempty engagement ID is required")
    source = Path(source).resolve(strict=True)
    # rw forbids silently creating a missing database.
    conn = sqlite3.connect(source.as_uri() + "?mode=rw", uri=True, timeout=10)
    try:
        conn.execute("BEGIN IMMEDIATE")
        inventory = inspect_database(conn)
        owned = ("findings", "ledger_events", "scoped_engagement_state", "knowledge_notes", "work_items")
        columns = {name: {row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')}
                   for name in owned if name in inventory["tables"]}
        if "engagement_id" not in columns.get("findings", set()) or "engagement_id" not in columns.get("ledger_events", set()):
            raise ValueError("Database lacks explicit finding/ledger ownership")
        candidate, surviving = set(), set()
        for owner, raw in conn.execute("SELECT engagement_id, data_json FROM ledger_events"):
            event = json.loads(raw or "{}")  # inspect_database already validates shape.
            for key in ("request_blob", "response_blob"):
                digest = event.get(key)
                if digest:
                    (candidate if owner == engagement_id else surviving).add(digest)
        counts = {}
        for name in owned:
            if "engagement_id" in columns.get(name, set()):
                counts[name] = conn.execute(f'DELETE FROM "{name}" WHERE engagement_id=?', (engagement_id,)).rowcount
        counts["evidence_blobs"] = 0
        if "evidence_blobs" in inventory["tables"]:
            for digest in candidate - surviving:
                counts["evidence_blobs"] += conn.execute("DELETE FROM evidence_blobs WHERE sha256=?", (digest,)).rowcount
        conn.commit()
        return {"deleted": counts, "scope": "explicit engagement-owned subset across hosts",
                "preserved_unowned_tables": [name for name in inventory["tables"] if name not in owned and name != "evidence_blobs"],
                "external_artifacts": "untouched; separate operator maintenance required"}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="Print supported scope and exclusions; reads no files")
    wipe = commands.add_parser("wipe-context", help="Explicit deletion of engagement-attributed SQLite rows only")
    wipe.add_argument("--source", type=Path, required=True)
    wipe.add_argument("--engagement-id", required=True)
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
        else:
            result = snapshot(args.source, args.destination,
                              expected_sha256=getattr(args, "expected_sha256", None))
    except (OSError, ValueError, sqlite3.Error) as exc:
        # Exception strings may contain raw database values or operator paths.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps({"status": "ok", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
