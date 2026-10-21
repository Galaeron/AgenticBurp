"""Nonsecret source identity. Snapshots describe capture time, not live files.

The default snapshot lives for this Python process. Restart after source edits,
or explicitly capture and pass a fresh snapshot to Provenance.capture(). Only
allowlisted application source is read; local configuration, tests/targets,
runtime state, keys and symlinks are excluded before opening any file.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path


def _eligible(name: str) -> bool:
    parts = name.lower().split("/")
    if any("answer_key" in p or "secret" in p or "token" in p or "key" in p
           for p in parts):
        return False
    if any(p in {"testing", "tests", "test", "runtime", "archive", "reviews",
                 "__pycache__", "build", "dist", ".git"} for p in parts):
        return False
    if any(p.startswith("test_") for p in parts):
        return False
    return ((len(parts) == 1 and name.endswith(".py"))
            or (parts[0] == "harness" and name.endswith((".py", ".j2")))
            or (name.startswith("burp-extension/src/") and name.endswith(".java"))
            or name in {"pyproject.toml", "requirements.txt", "harness/config.yaml",
                        "burp-extension/build.gradle"})


@dataclass(frozen=True)
class SourceSnapshot:
    content_id: str = ""
    head: str = "unknown"
    dirty: bool | None = None
    file_count: int = 0
    captured_at: float = 0.0
    lifetime: str = "explicit snapshot; restart or recapture after source edits"
    scope: str = "allowlisted application source v1; excludes tests, targets and secrets"
    status: str = "unavailable"

    def to_dict(self) -> dict:
        return asdict(self)


def capture_source_snapshot(root: Path | None = None) -> SourceSnapshot:
    root = (root or Path(__file__).resolve().parent.parent).resolve()
    stamp = time.time()
    try:
        def git(*args):
            return subprocess.run(["git", *args], cwd=root, capture_output=True,
                                  check=True, timeout=10).stdout
        try:
            # An installed package inside an unrelated checkout must not inherit
            # that checkout's HEAD or claim its dirty state.
            top = Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve()
            if top != root:
                raise ValueError("different Git root")
            head = git("rev-parse", "HEAD").decode().strip()
            raw = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
            names = sorted({n.decode("utf-8") for n in raw.split(b"\0") if n
                            and _eligible(n.decode("utf-8"))})
            # Git itself must not inspect excluded tracked contents.
            changed = (git("diff", "--name-only", "-z", "HEAD", "--", *names).split(b"\0")
                       if names else [])
            untracked = git("ls-files", "-z", "--others", "--exclude-standard").split(b"\0")
            dirty = any(n and _eligible(n.decode("utf-8")) for n in changed + untracked)
            scope = SourceSnapshot().scope
        except (OSError, ValueError, subprocess.SubprocessError):
            # Wheels have no Git metadata. Hash only the installed harness
            # package, never sibling site-packages or the surrounding checkout.
            package = root / "harness"
            if not package.is_dir() or package.is_symlink():
                return SourceSnapshot(captured_at=stamp)
            names = []
            for directory, dirs, files in os.walk(package, followlinks=False):
                current = Path(directory)
                dirs[:] = [d for d in dirs if not (current/d).is_symlink()
                           and _eligible((current/d/'source.py').relative_to(root).as_posix())]
                names.extend((current/f).relative_to(root).as_posix() for f in files
                             if _eligible((current/f).relative_to(root).as_posix()))
            names.sort()
            head, dirty = "unknown", None
            scope = "installed harness package source v1; Git identity unavailable; excludes tests and secrets"
        manifest = []
        for name in names:
            path = root / name
            if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
                raise ValueError("source symlink excluded")
            if not path.exists():
                manifest.append((name, "missing"))
                continue
            manifest.append((name, hashlib.sha256(path.read_bytes()).hexdigest()))
        digest = hashlib.sha256(json.dumps(manifest, ensure_ascii=True,
                                           separators=(",", ":")).encode()).hexdigest()
        return SourceSnapshot("sha256:" + digest, head, dirty, len(manifest), stamp,
                              scope=scope, status="captured")
    except (OSError, ValueError, subprocess.SubprocessError):
        return SourceSnapshot(captured_at=stamp)


@functools.lru_cache(maxsize=1)
def process_source_snapshot() -> SourceSnapshot:
    """Capture once; immutable identity has an explicit process lifetime."""
    snap = capture_source_snapshot()
    return SourceSnapshot(**{**snap.to_dict(), "lifetime": "process snapshot; restart after source edits"})
