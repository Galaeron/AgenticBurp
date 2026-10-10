"""Phase 1.3 -- the reproducibility-provenance stamp recorded with every result.

Every decisive-run result file must say exactly what produced it: the harness
commit, the config hash (from testing/decisive_config.py), the model name, and
the reproducibility controls that were in force -- the effective Ollama seed,
temperature, model digest and runtime version. These are CONTROLS, not a
guarantee of identical output across hardware or Ollama/model versions; the
stamp records them so a result can be reproduced and audited, not so anyone can
claim bit-identical reruns.

The external eval scripts call ``run_provenance(...)`` once the config is loaded
and the model known, and write the returned dict into each result file. The
git/Ollama lookups are split into small helpers (``current_harness_commit``,
``ollama_model_digest``, ``ollama_runtime_version``) that degrade to "unknown"
rather than crash the run, and are injectable so the assembler stays hermetic
and testable.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parent.parent

REPRODUCIBILITY_NOTE = (
    "Reproducibility controls (seed, temperature, model digest, runtime version), "
    "NOT a guarantee of identical output across hardware or Ollama/model versions."
)


def current_harness_commit(*, repo_root=_REPO_ROOT, run_fn=None) -> str:
    """`git rev-parse HEAD` for the harness checkout, or 'unknown' on any failure
    (a provenance stamp must never abort the run it is describing)."""
    runner = run_fn or (lambda args: subprocess.run(
        args, cwd=str(repo_root), capture_output=True, text=True, timeout=10))
    try:
        result = runner(["git", "rev-parse", "HEAD"])
        out = (getattr(result, "stdout", "") or "").strip()
        if getattr(result, "returncode", 1) == 0 and out:
            return out
    except Exception:
        pass
    return "unknown"


def ollama_model_digest(base_url, model, *, client=None, timeout=10.0) -> str | None:
    """The Ollama model's digest (from /api/tags), or None if unavailable.

    The digest pins the exact weights behind a tag like 'qwen3:8b', so a result
    can say which model build produced it even after the tag is re-pulled."""
    owns = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        resp = client.get(base_url.rstrip("/") + "/api/tags")
        if getattr(resp, "status_code", 0) // 100 != 2:
            return None
        data = resp.json()
    except Exception:
        return None
    finally:
        if owns:
            client.close()
    for entry in (data or {}).get("models", []) if isinstance(data, dict) else []:
        if isinstance(entry, dict) and entry.get("name") == model and entry.get("digest"):
            return entry["digest"]
    return None


def ollama_runtime_version(base_url, *, client=None, timeout=10.0) -> str | None:
    """The Ollama server version (from /api/version), or None if unavailable."""
    owns = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        resp = client.get(base_url.rstrip("/") + "/api/version")
        if getattr(resp, "status_code", 0) // 100 != 2:
            return None
        data = resp.json()
    except Exception:
        return None
    finally:
        if owns:
            client.close()
    return (data or {}).get("version") if isinstance(data, dict) else None


def run_provenance(*, model_name, config_hash, seed, temperature,
                   harness_commit=None, model_digest=None, runtime_version=None,
                   created_at=None) -> dict:
    """Assemble the provenance stamp written into each result file.

    Pure: every field is supplied by the caller (gathered via the helpers above),
    so this stays trivially testable and has no side effects. `seed` is recorded
    exactly as given -- including 0 -- and None is recorded as None ("no fixed
    seed"), never silently dropped.
    """
    return {
        "harness_commit": harness_commit if harness_commit is not None else current_harness_commit(),
        "config_hash": config_hash,
        "model_name": model_name,
        "effective_seed": seed,
        "temperature": temperature,
        "model_digest": model_digest,
        "runtime_version": runtime_version,
        "python_version": sys.version.split()[0],
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "reproducibility_note": REPRODUCIBILITY_NOTE,
    }
