"""Versioned, append-only metadata for engagement investigation runs."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_SECRET_PARTS = ("authorization", "cookie", "password", "passwd", "secret", "token", "api_key", "apikey")


def _is_secret_key(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_")
    return any(part in normalized for part in _SECRET_PARTS)


def redact(value: Any) -> Any:
    """Return a JSON-safe copy with credential-bearing values removed."""
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if _is_secret_key(k) else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def config_fingerprint(config: dict) -> str:
    encoded = json.dumps(redact(config), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _git_state(repo_root: Path) -> tuple[str | None, bool | None]:
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root, check=True,
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=repo_root, check=True, capture_output=True,
                                    text=True, timeout=5).stdout.strip())
        return revision or None, dirty
    except (OSError, subprocess.SubprocessError):
        return None, None


class RunManifest:
    """Persist lifecycle snapshots for one run without storing live credentials."""

    def __init__(self, data: dict, output_dir: Path):
        self.data = data
        self.output_dir = output_dir
        self.path = output_dir / f"{data['run_id']}.json"
        self.ledger_path = output_dir / "ledger.jsonl"

    @classmethod
    def start(cls, *, run_id: str, target_identifier: str, config: dict,
              cache_namespace: str | None = None, output_dir: Path | str | None = None,
              repo_root: Path | str | None = None, model_versions: dict | None = None,
              tool_versions: dict | None = None) -> "RunManifest":
        out = Path(output_dir or Path(__file__).parent / "run-output")
        root = Path(repo_root or Path(__file__).parent.parent)
        revision, dirty = _git_state(root)
        data = {
            "schema_version": SCHEMA_VERSION, "run_id": run_id,
            "git": {"revision": revision, "dirty": dirty},
            "config": redact(deepcopy(config)), "config_fingerprint": config_fingerprint(config),
            "cache_namespace": cache_namespace, "target_identifier": target_identifier,
            "model_versions": redact(model_versions or {}),
            "tool_versions": redact(tool_versions or {"python": platform.python_version(),
                                                        "platform": platform.platform()}),
            "started_at": time.time(), "finished_at": None, "request_count": None,
            "confirmed_issues": None, "operational_errors": [],
            "completion_status": "running", "degraded": False, "model_metrics": None,
            "measurement": {"fixture_kind": "unscored", "precision": None, "recall": None,
                            "scoring_limitation": "No independent expected-case mapping supplied"},
        }
        manifest = cls(data, out)
        manifest._persist(append_ledger=True)
        return manifest

    def finish(self, status: str, *, result: dict | None = None, error: str | None = None) -> None:
        result = result or {}
        errors = list(result.get("errors") or [])
        if error:
            errors.append({"phase": "job", "error": error})
        self.data.update({"finished_at": time.time(), "completion_status": status,
                          "request_count": result.get("request_count"),
                          "confirmed_issues": result.get("confirmed_issues"),
                          "operational_errors": redact(errors),
                          "degraded": bool(result.get("degraded") or errors),
                          # R01/R07: the auditable executed-vs-inferred coverage
                          # breakdown (coverage_summary.summarize_coverage's
                          # output, already additive on CoverageTracker.report()),
                          # persisted here so a LATER reader (e.g. the MCP
                          # coverage resource) can see it without needing the
                          # live in-memory job result.
                          "coverage_audited": (result.get("coverage") or {}).get("audited")})
        self._persist(append_ledger=True)

    def _persist(self, *, append_ledger: bool) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        if append_ledger:
            with self.ledger_path.open("a", encoding="utf-8") as ledger:
                ledger.write(json.dumps(self.data, sort_keys=True) + "\n")

