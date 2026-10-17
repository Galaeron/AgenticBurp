"""Score end-to-end web-security benchmark runs.

This scorer deliberately sits beside ``strict_score.py`` rather than extending
it.  Strict score answers whether captured exchanges received the right finding
classes.  This module answers whether an application objective was independently
verified, whether the same run stayed quiet on fixed controls, and whether that
result repeats from clean state.

The runner is intentionally adapter-neutral.  A Burp/PortSwigger adapter and an
owned-container adapter can both emit the run-record schema consumed here.  The
scorer never trusts model prose as proof: ``objective_verified`` must be set by
the adapter's independent completion oracle.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Any


SCHEMA_VERSION = "1.0.0"
VALID_MODES = {"captured", "autonomous"}
VALID_STATUSES = {"success", "failure", "timeout", "error"}
VALID_FAILURE_STAGES = {
    "discovery", "reasoning", "execution", "verification", "infrastructure",
}


class BenchmarkContractError(ValueError):
    pass


def _load(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BenchmarkContractError(f"{path}: expected a JSON object")
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BenchmarkContractError("unsupported manifest schema_version")
    if not isinstance(manifest.get("attempts_per_case"), int) or manifest["attempts_per_case"] < 1:
        raise BenchmarkContractError("attempts_per_case must be a positive integer")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise BenchmarkContractError("manifest cases must be a non-empty list")
    ids: set[str] = set()
    pair_members: dict[str, list[bool]] = {}
    for case in cases:
        if not isinstance(case, dict) or not case.get("id"):
            raise BenchmarkContractError("every case needs an id")
        if case["id"] in ids:
            raise BenchmarkContractError(f"duplicate case id: {case['id']}")
        ids.add(case["id"])
        modes = case.get("modes")
        if not isinstance(modes, list) or not modes or not set(modes) <= VALID_MODES:
            raise BenchmarkContractError(f"{case['id']}: invalid modes")
        if not isinstance(case.get("expected_vulnerable"), bool):
            raise BenchmarkContractError(f"{case['id']}: expected_vulnerable must be boolean")
        if not case.get("expected_class"):
            raise BenchmarkContractError(f"{case['id']}: expected_class is required")
        pair = case.get("pair_id")
        if pair:
            pair_members.setdefault(pair, []).append(case["expected_vulnerable"])
    for pair, members in pair_members.items():
        if sorted(members) != [False, True]:
            raise BenchmarkContractError(
                f"{pair}: a private pair must contain one vulnerable and one fixed case")


_RESOURCE_FIELDS = (
    "duration_seconds", "requests", "input_tokens", "output_tokens", "human_interventions",
)


def _findings(record: dict[str, Any]) -> list[Any]:
    """The record's findings list; a malformed payload is reported by ``score``
    as a contract error, never read as 'no findings' evidence."""
    value = record.get("findings")
    return value if isinstance(value, list) else []


def _is_confirmed(finding: Any) -> bool:
    return isinstance(finding, dict) and finding.get("verification_state") in {
        "verified", "confirmed"}


def _case_confirmed(record: dict[str, Any], expected_class: str) -> bool:
    """A confirmation is class-bound; unrelated confirmed noise is not a TP."""
    return any(
        _is_confirmed(f) and f.get("vulnerability_class") == expected_class
        for f in _findings(record)
    )


def _wrong_class_confirmed(record: dict[str, Any], expected_class: str) -> bool:
    """True when any confirmed finding is of a class other than the expected one,
    including alongside a correct confirmation in the same record."""
    return any(
        _is_confirmed(f) and f.get("vulnerability_class") != expected_class
        for f in _findings(record)
    )


def _resource_ok(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and math.isfinite(value) and value >= 0)


def _resource(record: dict[str, Any], field: str) -> float:
    value = record.get(field)
    return value if value is not None and _resource_ok(value) else 0


def _ref_problem(ref: Any, root: Path | None) -> str | None:
    """Why ``ref`` is not a usable artifact reference (None when it is).

    Always checks it is a well-formed relative path that cannot leave the artifact
    root.  With ``root`` it must also resolve to an existing file inside it."""
    if not isinstance(ref, str) or not ref.strip():
        return "must be a non-empty string"
    if "\x00" in ref:
        return "contains a NUL byte"
    win = PureWindowsPath(ref)
    if win.drive or win.root or ".." in re.split(r"[\\/]", ref):
        return "must be a relative path without '..' segments"
    if root is not None:
        target = (root / ref).resolve()
        if not target.is_relative_to(root):
            return "resolves outside the artifact root"
        if not target.is_file():
            return "does not resolve to a file under the artifact root"
    return None


def score(manifest: dict[str, Any], run: dict[str, Any], *,
          artifact_root: str | Path | None = None) -> dict[str, Any]:
    """Score ``run`` against ``manifest``.

    Artifact references are always checked for well-formedness; pass
    ``artifact_root`` (the directory they are relative to) to also require that
    each one resolves to an existing file.  ``artifact_integrity`` in the result
    states which of the two was verified."""
    validate_manifest(manifest)
    mode = run.get("mode")
    if mode not in VALID_MODES:
        raise BenchmarkContractError(f"invalid run mode: {mode!r}")
    records = run.get("records")
    if not isinstance(records, list):
        raise BenchmarkContractError("run records must be a list")
    root = Path(artifact_root).resolve() if artifact_root is not None else None

    applicable = {c["id"]: c for c in manifest["cases"] if mode in c["modes"]}
    attempts_required = manifest["attempts_per_case"]
    by_case_attempt: dict[tuple[str, int], dict[str, Any]] = {}
    contract_errors: list[str] = []
    if not applicable:
        contract_errors.append(f"no manifest case applies to mode {mode!r}")
    if run.get("schema_version") != SCHEMA_VERSION:
        contract_errors.append("run schema_version is missing or unsupported")
    for field in ("run_id", "model", "checkout", "config_hash"):
        if not isinstance(run.get(field), str) or not run[field].strip():
            contract_errors.append(f"run {field} is required")
    for record in records:
        case_id, attempt = record.get("case_id"), record.get("attempt")
        if case_id not in applicable:
            contract_errors.append(f"unknown or inapplicable case: {case_id!r}")
            continue
        if not isinstance(attempt, int) or not 1 <= attempt <= attempts_required:
            contract_errors.append(f"{case_id}: invalid attempt {attempt!r}")
            continue
        key = (case_id, attempt)
        if key in by_case_attempt:
            contract_errors.append(f"duplicate record: {case_id} attempt {attempt}")
            continue
        if record.get("status") not in VALID_STATUSES:
            contract_errors.append(f"{case_id} attempt {attempt}: invalid status")
        stage = record.get("failure_stage")
        if stage is not None and stage not in VALID_FAILURE_STAGES:
            contract_errors.append(f"{case_id} attempt {attempt}: invalid failure_stage")
        if record.get("objective_verified") and record.get("status") != "success":
            contract_errors.append(
                f"{case_id} attempt {attempt}: verified objective requires success status")
        refs = record.get("artifact_refs")
        if not isinstance(refs, list) or not refs:
            contract_errors.append(
                f"{case_id} attempt {attempt}: at least one artifact reference is required")
        else:
            for ref in refs:
                problem = _ref_problem(ref, root)
                if problem:
                    contract_errors.append(
                        f"{case_id} attempt {attempt}: invalid artifact reference "
                        f"{ref!r}: {problem}")
        if "findings" in record and (
                not isinstance(record["findings"], list)
                or not all(isinstance(f, dict) for f in record["findings"])):
            contract_errors.append(
                f"{case_id} attempt {attempt}: findings must be a list of objects")
        for field in _RESOURCE_FIELDS:
            if not _resource_ok(record.get(field)):
                contract_errors.append(
                    f"{case_id} attempt {attempt}: {field} must be a non-negative number")
        by_case_attempt[key] = record

    missing = [
        {"case_id": case_id, "attempt": attempt}
        for case_id in applicable
        for attempt in range(1, attempts_required + 1)
        if (case_id, attempt) not in by_case_attempt
    ]

    positives = [c for c in applicable.values() if c["expected_vulnerable"]]
    controls = [c for c in applicable.values() if not c["expected_vulnerable"]]
    positive_results: dict[str, list[bool]] = {}
    control_false_confirmations: list[dict[str, Any]] = []
    false_class_confirmations: list[dict[str, Any]] = []
    failure_stages: Counter[str] = Counter()
    totals = Counter()

    for case in applicable.values():
        outcomes: list[bool] = []
        for attempt in range(1, attempts_required + 1):
            record = by_case_attempt.get((case["id"], attempt))
            if record is None:
                outcomes.append(False)
                continue
            totals["duration_seconds"] += float(_resource(record, "duration_seconds"))
            totals["requests"] += int(_resource(record, "requests"))
            totals["input_tokens"] += int(_resource(record, "input_tokens"))
            totals["output_tokens"] += int(_resource(record, "output_tokens"))
            totals["human_interventions"] += int(_resource(record, "human_interventions"))
            if record.get("status") != "success":
                failure_stages[record.get("failure_stage") or "unclassified"] += 1

            expected_confirmed = _case_confirmed(record, case["expected_class"])
            any_confirmed = any(_is_confirmed(f) for f in _findings(record))
            wrong_class_confirmed = _wrong_class_confirmed(record, case["expected_class"])
            if mode == "autonomous":
                achieved = bool(record.get("objective_verified"))
            else:
                achieved = expected_confirmed
            outcomes.append(achieved)

            if not case["expected_vulnerable"] and (any_confirmed or record.get("objective_verified")):
                control_false_confirmations.append(
                    {"case_id": case["id"], "attempt": attempt})
            if case["expected_vulnerable"] and wrong_class_confirmed:
                false_class_confirmations.append(
                    {"case_id": case["id"], "attempt": attempt})
        if case["expected_vulnerable"]:
            positive_results[case["id"]] = outcomes

    denom = len(positives)
    first_attempt = sum(bool(v and v[0]) for v in positive_results.values())
    solved_within = sum(any(v) for v in positive_results.values())
    repeatable = sum(all(v) for v in positive_results.values())
    false_control_cases = len({x["case_id"] for x in control_false_confirmations})
    complete = not missing and not contract_errors
    zero_false_confirmation = not control_false_confirmations
    zero_wrong_class_confirmation = not false_class_confirmations
    intervention_gate = mode != "autonomous" or totals["human_interventions"] == 0
    healthy_execution = not any(
        record.get("status") == "error" or record.get("failure_stage") == "infrastructure"
        for record in by_case_attempt.values()
    )
    eligible = (complete and zero_false_confirmation and zero_wrong_class_confirmation
                and intervention_gate and healthy_execution)

    def rate(n: int, d: int) -> float | None:
        return round(n / d, 6) if d else None

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "web_objective_benchmark_result",
        "run_id": run.get("run_id"),
        "mode": mode,
        "complete": complete,
        "eligible": eligible,
        "artifact_integrity": "resolved" if root is not None else "format_only",
        "gates": {
            "complete_records": complete,
            "zero_false_confirmations": zero_false_confirmation,
            "zero_wrong_class_confirmations": zero_wrong_class_confirmation,
            "zero_human_interventions": totals["human_interventions"] == 0,
            "healthy_execution": healthy_execution,
        },
        "cases": {
            "applicable": len(applicable),
            "positive": denom,
            "fixed_controls": len(controls),
            "missing_records": missing,
            "contract_errors": contract_errors,
        },
        "objective": {
            "first_attempt_successes": first_attempt,
            "first_attempt_rate": rate(first_attempt, denom),
            "solved_within_attempt_budget": solved_within,
            "pass_at_attempt_budget": rate(solved_within, denom),
            "repeatable_successes": repeatable,
            "repeatability_rate": rate(repeatable, denom),
        },
        "controls": {
            "false_confirmation_events": control_false_confirmations,
            "false_confirmation_cases": false_control_cases,
            "false_confirmation_case_rate": rate(false_control_cases, len(controls)),
            "wrong_class_confirmation_events": false_class_confirmations,
        },
        "failure_stages": dict(sorted(failure_stages.items())),
        "resources": dict(totals),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a web objective benchmark run")
    parser.add_argument("manifest")
    parser.add_argument("run")
    parser.add_argument("--out")
    parser.add_argument("--artifact-root",
                        help="directory artifact_refs are relative to; when given, each "
                             "reference must resolve to an existing file under it")
    args = parser.parse_args(argv)
    result = score(_load(args.manifest), _load(args.run), artifact_root=args.artifact_root)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
