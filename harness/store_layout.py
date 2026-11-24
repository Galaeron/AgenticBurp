"""Engagement store layout and request context of the harness state store.

OPS-5 store selection (one engagement per process) and the engagement and
captured-principal context variables records are attributed to.

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import time
import hashlib
import json
import functools
import hmac
import os
import re
from pathlib import Path

from harness.models import HttpExchange


# ---------------------------------------------------------------------------
# OPS-5: per-engagement stores.
#
# Layout, all under the directory of the single legacy store (`_DB_PATH`):
#   harness_state.db                      the legacy single store. Used whenever
#                                         no engagement is selected (the default),
#                                         so existing data loads unchanged.
#   engagements/<key>/engagement.json     which engagement ID owns the directory
#   engagements/<key>/harness_state.db    that engagement's own store, same schema
#   engagements/<key>/harness_jobs.db ... sibling databases that callers derive
#                                         from `_DB_PATH` (job status, run journal)
#
# The engagement key is the `engagement_id` partition that findings, the ledger,
# observations, work items and engagement snapshots already carry (a named
# engagement can span several hosts; a host-keyed wipe cannot separate clients).
# A process stores into ONE engagement: `HARNESS_ENGAGEMENT_ID` at import, or
# select_engagement_store(). Per-process, not per-request, because plan, proof
# and job lookups by ID (validation results, the Burp plane) carry no engagement
# and must find the rows the run wrote. Inside an engagement store the
# `engagement_id` columns still partition, as they do in the legacy store.
# close_engagement() exports, then removes, one engagement's store and its
# attributed rows in the legacy store. Nothing here deletes anything implicitly.
# ---------------------------------------------------------------------------
ENGAGEMENT_ENV_VAR = "HARNESS_ENGAGEMENT_ID"
_ENGAGEMENTS_DIRNAME = "engagements"
_EXPORTS_DIRNAME = "engagement_exports"
_ENGAGEMENT_DB_NAME = "harness_state.db"
_ENGAGEMENT_MANIFEST = "engagement.json"
_ENGAGEMENT_LOCK = "engagement.lock"
_CLOSING_PREFIX = ".closing-"
_STORE_LAYOUT_VERSION = 1


class EngagementStoreActive(ValueError):
    """The engagement named is the one this process is storing into."""


def _named_engagement_id(engagement_id) -> str:
    if (not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 128
            or engagement_id != engagement_id.strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in engagement_id)):
        raise ValueError("an engagement store needs a nonempty engagement ID of at most 128 "
                         "printable characters, without surrounding whitespace")
    return engagement_id


def engagement_store_key(engagement_id: str) -> str:
    """Directory name for one engagement: a readable slug plus a digest of the
    exact ID, so two IDs that slug alike still get different directories."""
    engagement_id = _store._named_engagement_id(engagement_id)
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", engagement_id).strip("_")[:40] or "engagement"
    return f"{slug}-{hashlib.sha256(engagement_id.encode('utf-8')).hexdigest()[:16]}"


def active_engagement() -> str:
    """The engagement this process stores into; '' for the legacy single store.
    A `_DB_PATH` pointed elsewhere (a test fixture) counts as the legacy store."""
    if _store._ACTIVE_ENGAGEMENT and _store._ACTIVE_STORE_PATH is not None and Path(_store._DB_PATH) == _store._ACTIVE_STORE_PATH:
        return _store._ACTIVE_ENGAGEMENT
    return ""


def legacy_store_path() -> Path:
    """The single legacy store, whichever engagement is selected."""
    return _store._LEGACY_DB_PATH if _store.active_engagement() else Path(_store._DB_PATH)


def engagements_root() -> Path:
    return _store.legacy_store_path().parent / _store._ENGAGEMENTS_DIRNAME


def engagement_store_dir(engagement_id: str) -> Path:
    return _store.engagements_root() / _store.engagement_store_key(engagement_id)


def engagement_store_path(engagement_id: str) -> Path:
    """The database one engagement stores into: '' is the legacy single store."""
    if engagement_id == "":
        return _store.legacy_store_path()
    return _store.engagement_store_dir(engagement_id) / _store._ENGAGEMENT_DB_NAME


def _manifest_engagement(directory: Path) -> str | None:
    """The engagement ID a store directory's manifest names, or None."""
    try:
        data = json.loads((directory / _store._ENGAGEMENT_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = data.get("engagement_id") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def _claim_engagement_dir(directory: Path, engagement_id: str) -> None:
    """Create the directory and its manifest, or check an existing manifest names
    this engagement (a digest collision or a hand-copied directory fails closed)."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    manifest = directory / _store._ENGAGEMENT_MANIFEST
    try:
        with manifest.open("x", encoding="utf-8") as stream:
            json.dump({"engagement_id": engagement_id, "created_at": time.time(),
                       "store_layout": _store._STORE_LAYOUT_VERSION}, stream, sort_keys=True)
    except FileExistsError:
        if _store._manifest_engagement(directory) != engagement_id:
            raise ValueError("engagement store directory belongs to a different engagement") from None


def _hold_store_lock(directory: Path):
    """Open the store's lock file and keep it open while the store is selected,
    so a close from another process sees the store is in use: a shared flock on
    POSIX; on Windows the open handle alone makes the directory rename fail."""
    stream = open(directory / _store._ENGAGEMENT_LOCK, "a+b")
    if os.name != "nt":
        import fcntl
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            stream.close()
            raise _store.EngagementStoreActive("that engagement store is being closed") from None
    return stream


def _release_store_lock() -> None:
    if _store._HELD_STORE_LOCK is not None:
        try:
            _store._HELD_STORE_LOCK.close()
        except OSError:
            pass
        _store._HELD_STORE_LOCK = None


def interrupted_closes(engagement_id: str | None = None) -> list[Path]:
    """Store directories a close renamed aside and did not finish removing (a
    crash mid-export, or files it could not delete). close_engagement recovers
    them; selecting that engagement is refused until it does."""
    root = _store.engagements_root()
    if not root.is_dir():
        return []
    pattern = _store._CLOSING_PREFIX + (f"{_store.engagement_store_key(engagement_id)}-*" if engagement_id else "*")
    return sorted(path for path in root.glob(pattern) if path.is_dir() and not path.is_symlink())


def select_engagement_store(engagement_id: str) -> Path:
    """Point this process's store at one engagement's own database, creating it
    on first use; '' goes back to the legacy single store. Returns the path.
    Selecting never moves or deletes data: rows already in the legacy store stay
    there and load again once the legacy store is selected. The selected store's
    lock file stays open, so another process cannot close it meanwhile."""
    legacy = _store.legacy_store_path()
    if engagement_id == "":
        _store._release_store_lock()
        _store._DB_PATH, _store._ACTIVE_ENGAGEMENT, _store._ACTIVE_STORE_PATH = legacy, "", None
        return legacy
    directory = legacy.parent / _store._ENGAGEMENTS_DIRNAME / _store.engagement_store_key(engagement_id)
    if directory.parent.is_dir() and any(directory.parent.glob(f"{_store._CLOSING_PREFIX}{directory.name}-*")):
        raise ValueError("an interrupted close holds this engagement's data aside; run "
                         "close-engagement for it before storing into it again")
    _store._claim_engagement_dir(directory, engagement_id)
    lock = _store._hold_store_lock(directory)
    _store._release_store_lock()
    path = directory / _store._ENGAGEMENT_DB_NAME
    _store._LEGACY_DB_PATH, _store._DB_PATH, _store._ACTIVE_ENGAGEMENT, _store._ACTIVE_STORE_PATH = legacy, path, engagement_id, path
    _store._HELD_STORE_LOCK = lock
    return path


def isolate_engagement_context(fn):
    """Keep passive record attribution local to one async caller's lifetime."""
    @functools.wraps(fn)
    async def wrapped(*args, **kwargs):
        token = _store._CURRENT_ENGAGEMENT.set("")
        principal_token = _store._CURRENT_CAPTURED_PRINCIPAL.set("")
        try:
            return await fn(*args, **kwargs)
        finally:
            _store._CURRENT_ENGAGEMENT.reset(token)
            _store._CURRENT_CAPTURED_PRINCIPAL.reset(principal_token)
    return wrapped


def bind_engagement_context(engagement_id: str) -> None:
    _store._CURRENT_ENGAGEMENT.set(_store._engagement_partition(engagement_id))


def bind_captured_principal_context(principal: str) -> None:
    _store._CURRENT_CAPTURED_PRINCIPAL.set(principal)


def captured_principal_id(exchange: HttpExchange) -> str:
    """Opaque captured-auth context, never an authenticated identity/authority.

    Recognized credential headers distinguish contexts conservatively. Custom
    authentication schemes are unsupported. Anonymous means no recognized
    credential header, not proof that the application treats the user as anonymous.
    """
    from harness import security
    credentials = sorted((name.lower(), value) for name, value in exchange.request_headers.items()
                         if name.lower() in security.SECRET_HEADER_NAMES)
    if not credentials:
        return "anonymous"
    conn = _store._connect()
    try:
        key = bytes.fromhex(conn.execute("SELECT value FROM state_metadata WHERE name='principal-hmac-v1'").fetchone()[0])
    finally:
        conn.close()
    return "captured:" + hmac.new(key, json.dumps(credentials).encode(), hashlib.sha256).hexdigest()


def _engagement_partition(engagement_id: str) -> str:
    if not isinstance(engagement_id, str) or len(engagement_id) > 128:
        raise ValueError("engagement_id must be a string of at most 128 characters")
    return engagement_id


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
