"""Versioned evaluation-manifest creation and consistency checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "evaluation-integrity-manifest/v1"
MODES = {"fresh_end_to_end", "historical_rescore"}
_REQUIRED = {
    "schema_version", "experiment_id", "invocation_id", "revision", "dirty_tree",
    "config_fingerprint", "corpus", "artifacts", "scoring_policy_version",
    "model_prompt", "evaluation_mode", "created_at",
}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_manifest(manifest: dict[str, Any], bundle_root: str | Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = [
        "Artifact hashes establish bundle consistency, not independent authenticity."
    ]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"unsupported manifest schema: {manifest.get('schema_version')!r}")
    missing = sorted(key for key in _REQUIRED if key not in manifest)
    if missing:
        errors.append("missing required metadata: " + ", ".join(missing))
    mode = manifest.get("evaluation_mode")
    if mode not in MODES:
        errors.append(f"unsupported evaluation mode: {mode!r}")
    invocation = manifest.get("invocation_id")
    experiment = manifest.get("experiment_id")
    if not isinstance(invocation, str) or not invocation.strip():
        errors.append("invocation_id must be nonempty")
    if not isinstance(experiment, str) or not experiment.strip():
        errors.append("experiment_id must be nonempty and distinct from commit identity")
    if experiment and experiment == manifest.get("revision"):
        errors.append("experiment_id must be distinct from revision")
    corpus = manifest.get("corpus")
    if not isinstance(corpus, dict) or not corpus.get("identifier") or not corpus.get("version"):
        errors.append("corpus requires identifier and version")
    model_prompt = manifest.get("model_prompt")
    if not isinstance(model_prompt, dict) or "relevant" not in model_prompt:
        errors.append("model_prompt requires an explicit relevant flag")
    elif model_prompt.get("relevant") and (not model_prompt.get("model_id") or not model_prompt.get("prompt_id")):
        errors.append("relevant model/prompt identity requires model_id and prompt_id")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must be a nonempty list")
        artifacts = []
    root = Path(bundle_root).resolve()
    checked: list[dict[str, Any]] = []
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            errors.append(f"artifact[{index}] must be an object")
            continue
        rel = item.get("path")
        expected = item.get("sha256")
        item_invocation = item.get("invocation_id")
        if item_invocation != invocation:
            errors.append(f"artifact[{index}] invocation_id does not match manifest")
        if not isinstance(rel, str) or not rel:
            errors.append(f"artifact[{index}] has no path")
            continue
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"artifact[{index}] escapes the bundle root")
            continue
        if not candidate.is_file():
            errors.append(f"artifact[{index}] is missing: {rel}")
            continue
        actual = sha256_file(candidate)
        content_invocation = None
        if candidate.suffix.lower() == ".json":
            try:
                content = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(content, dict):
                    content_invocation = content.get("invocation_id")
            except (OSError, UnicodeError, json.JSONDecodeError):
                # Hash checking still applies to opaque JSON-shaped artifacts.
                pass
        checked.append({"path": rel, "sha256_matches": actual == expected,
                        "content_invocation_id_matches": (
                            None if content_invocation is None else content_invocation == invocation)})
        if actual != expected:
            errors.append(f"artifact[{index}] hash mismatch: {rel}")
        if content_invocation is not None and content_invocation != invocation:
            errors.append(f"artifact[{index}] content invocation_id does not match manifest")
    if errors:
        provenance = "unknown_or_mismatched"
    elif mode == "historical_rescore":
        provenance = "historical_rescore"
        warnings.append("Historical outputs were deliberately rescored; this is not fresh end-to-end validation.")
    elif manifest.get("dirty_tree") is False:
        provenance = "fresh_stated_build"
    else:
        provenance = "unknown_or_mismatched"
        warnings.append("A dirty tree cannot be identified by revision alone; fresh-build provenance is unknown.")
    return {"valid": not errors, "provenance": provenance, "errors": errors,
            "warnings": warnings, "checked_artifacts": checked}


def load_and_check_manifest(path: str | Path, bundle_root: str | Path | None = None) -> dict[str, Any]:
    source = Path(path)
    try:
        manifest = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"valid": False, "provenance": "unknown_or_mismatched",
                "errors": [f"cannot read manifest: {exc}"], "warnings": [],
                "checked_artifacts": []}
    if not isinstance(manifest, dict):
        return {"valid": False, "provenance": "unknown_or_mismatched",
                "errors": ["manifest root must be an object"], "warnings": [],
                "checked_artifacts": []}
    return check_manifest(manifest, bundle_root or source.parent)
