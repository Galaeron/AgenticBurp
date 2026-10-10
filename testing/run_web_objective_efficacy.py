"""Priority 1 (efficacy) — orchestrate N clean attempts + fixed controls and score them.

This is the missing turnkey layer between the single-run runner
(:mod:`testing.run_web_objective_smoke`, which drives ONE authorized attempt and
writes an ``attempt.json`` artifact) and the scorer
(:mod:`testing.web_objective_benchmark`, which aggregates attempts into
first-attempt / pass-at-budget / repeatability numbers with clean-vs-fixed
controls and eligibility gates). It automates every mechanical step CURRENT_STATE
asks for — "three clean autonomous attempts plus matching fixed controls from one
checkout/config" — WITHOUT weakening the trust discipline:

* The completion oracle stays out of band. The runner never treats model output
  as proof; likewise this orchestrator never derives ``objective_verified`` from
  findings. For autonomous cases the owner supplies an ``--oracle`` file recording
  the lab's own solved state per attempt; with no oracle, ``objective_verified``
  is False (unverified is not solved).
* A lab-solved-but-not-cleanly-completed attempt is NOT counted as a success
  (CURRENT_STATE's attempt-4 discipline): ``objective_verified`` is carried only
  when the attempt's own status is a clean completion.
* One checkout/one config is enforced, not assumed: assembling the run refuses if
  the per-attempt artifacts span more than one ``checkout`` or ``config_hash``.

Nothing here sends traffic; the live runs happen inside the subprocess runner the
owner authorizes. Offline, the pure record-mapping / assembly / scoring path is
exercised by ``test_run_web_objective_efficacy.py`` with an injected fake runner.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

_HERE = Path(__file__).resolve().parent
ROOT = _HERE.parent
try:  # keep one module identity with the tests/suite when the repo root imports
    from testing import web_objective_benchmark as wob
except ImportError:  # script mode: `python testing/run_web_objective_efficacy.py`
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    import web_objective_benchmark as wob  # noqa: E402

# Smoke-runner status -> (scorer status, failure_stage). "done" is a clean
# completion (execution healthy); a timeout is a non-achievement but not an
# infrastructure fault; an error/anything-else is an unhealthy run that must make
# the whole measurement ineligible rather than silently scoring around it.
_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "done": ("success", None),
    "timeout": ("timeout", None),
    "error": ("error", "infrastructure"),
}


def select_cases(manifest: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    """Manifest cases applicable to ``mode`` (validates the manifest first)."""
    wob.validate_manifest(manifest)
    if mode not in wob.VALID_MODES:
        raise wob.BenchmarkContractError(f"invalid mode: {mode!r}")
    return [c for c in manifest["cases"] if mode in c["modes"]]


def attempt_record(artifact: dict[str, Any], *, case_id: str, attempt: int,
                   artifact_ref: str, oracle_verified: bool = False) -> dict[str, Any]:
    """Map one ``attempt.json`` artifact into a scorer record.

    ``objective_verified`` is set ONLY when the owner's oracle says verified AND
    the attempt itself completed cleanly (status "success"); a solved lab behind a
    timed-out/errored attempt is excluded, matching CURRENT_STATE's discipline.
    """
    smoke_status = str(artifact.get("status") or "")
    status, failure_stage = _STATUS_MAP.get(smoke_status, ("error", "infrastructure"))
    verified = bool(oracle_verified) and status == "success"
    record = {
        "case_id": case_id,
        "attempt": attempt,
        "status": status,
        "failure_stage": failure_stage,
        "objective_verified": verified,
        "findings": list(artifact.get("findings", []) or []),
        "duration_seconds": float(artifact.get("duration_seconds") or 0),
        "requests": int(artifact.get("requests") or 0),
        "input_tokens": int(artifact.get("input_tokens") or 0),
        "output_tokens": int(artifact.get("output_tokens") or 0),
        "human_interventions": int(artifact.get("human_interventions") or 0),
        "artifact_refs": [artifact_ref],
    }
    # Surface an oracle/attempt conflict for the summary without lying in the
    # scored record (a solved lab that the run could not cleanly complete).
    if bool(oracle_verified) and not verified:
        record["_excluded_verified"] = True
    return record


def assemble_run(mode: str, attempts: list[dict[str, Any]], *,
                 run_id: str) -> dict[str, Any]:
    """Build the scorer ``run`` from mapped attempt entries.

    Each entry is ``{"case_id", "attempt", "artifact", "artifact_ref",
    "oracle_verified"}``. Enforces one-checkout/one-config: refuses if the
    artifacts disagree on ``checkout`` or ``config_hash``.
    """
    if not attempts:
        raise wob.BenchmarkContractError("no attempts to assemble")
    checkouts = {str(a["artifact"].get("checkout") or "") for a in attempts}
    config_hashes = {str(a["artifact"].get("config_hash") or "") for a in attempts}
    if len(checkouts) != 1:
        raise wob.BenchmarkContractError(
            f"attempts span multiple checkouts (need one): {sorted(checkouts)}")
    if len(config_hashes) != 1:
        raise wob.BenchmarkContractError(
            f"attempts span multiple config hashes (need one): {sorted(config_hashes)}")
    models = {str(a["artifact"].get("model") or "") for a in attempts}
    records = [
        attempt_record(a["artifact"], case_id=a["case_id"], attempt=a["attempt"],
                       artifact_ref=a["artifact_ref"],
                       oracle_verified=bool(a.get("oracle_verified")))
        for a in attempts
    ]
    return {
        "schema_version": wob.SCHEMA_VERSION,
        "run_id": run_id,
        "mode": mode,
        "model": next(iter(models)) or "unknown",
        "checkout": next(iter(checkouts)) or "unknown",
        "config_hash": next(iter(config_hashes)) or "unknown",
        "records": [{k: v for k, v in r.items() if not k.startswith("_")} for r in records],
        "_excluded_verified": [
            {"case_id": r["case_id"], "attempt": r["attempt"]}
            for r in records if r.get("_excluded_verified")
        ],
    }


def _default_runner(*, python: str, runner: Path, target: str, case_id: str,
                    objective_class: str, out_dir: Path, run_id: str,
                    budgets: dict[str, Any]) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [python, str(runner), target, "--case-id", case_id,
           "--objective-class", objective_class, "--output", str(out_dir),
           "--run-id", run_id]
    for flag, value in budgets.items():
        cmd += [f"--{flag.replace('_', '-')}", str(value)]
    subprocess.run(cmd, cwd=str(ROOT), check=False)
    artifact_path = out_dir / "attempt.json"
    if not artifact_path.exists():
        return {"status": "error", "error": "runner produced no attempt.json",
                "findings": [], "checkout": "unknown", "config_hash": "unknown"}
    return json.loads(artifact_path.read_text(encoding="utf-8"))


def orchestrate(manifest: dict[str, Any], targets: dict[str, str], *, mode: str,
                output_dir: Path, oracle: dict[str, list[bool]] | None = None,
                run_id: str | None = None, python: str | None = None,
                runner: Path | None = None, budgets: dict[str, Any] | None = None,
                runner_fn: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run every applicable case × attempt, assemble, and score.

    ``runner_fn`` is injectable (tests pass a fake that writes synthetic
    artifacts); by default each attempt shells out to ``run_web_objective_smoke``.
    Returns ``{"scorecard", "run", "attempts"}``. Writes ``scorecard.json`` and
    ``summary.md`` under ``output_dir``.
    """
    oracle = oracle or {}
    budgets = budgets or {}
    run_id = run_id or f"efficacy-{uuid.uuid4().hex[:12]}"
    python = python or sys.executable
    runner = runner or (_HERE / "run_web_objective_smoke.py")
    runner_fn = runner_fn or _default_runner
    output_dir = Path(output_dir)

    cases = select_cases(manifest, mode)
    missing_targets = sorted(c["id"] for c in cases if not targets.get(c["id"]))
    if missing_targets:
        raise wob.BenchmarkContractError(
            f"no target URL supplied for: {missing_targets}")
    attempts_required = manifest["attempts_per_case"]

    attempts: list[dict[str, Any]] = []
    for case in cases:
        for attempt in range(1, attempts_required + 1):
            out_dir = output_dir / case["id"] / f"attempt-{attempt}"
            attempt_run_id = f"{run_id}-{case['id']}-a{attempt}"
            artifact = runner_fn(
                python=python, runner=runner, target=targets[case["id"]],
                case_id=case["id"], objective_class=case["expected_class"],
                out_dir=out_dir, run_id=attempt_run_id, budgets=budgets)
            try:
                ref = str((out_dir / "attempt.json").relative_to(output_dir))
            except ValueError:
                ref = str(out_dir / "attempt.json")
            case_oracle = oracle.get(case["id"], [])
            oracle_verified = bool(attempt <= len(case_oracle) and case_oracle[attempt - 1])
            attempts.append({
                "case_id": case["id"], "attempt": attempt, "artifact": artifact,
                "artifact_ref": ref, "oracle_verified": oracle_verified,
            })

    run = assemble_run(mode, attempts, run_id=run_id)
    excluded = run.pop("_excluded_verified", [])
    scorecard = wob.score(manifest, run, artifact_root=output_dir)
    scorecard["excluded_verified_attempts"] = excluded

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "scorecard.json").write_text(
        json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "run.json").write_text(
        json.dumps(run, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "summary.md").write_text(render_summary(scorecard), encoding="utf-8")
    return {"scorecard": scorecard, "run": run, "attempts": attempts}


def render_summary(scorecard: dict[str, Any]) -> str:
    """A short shareable markdown digest of a scorecard."""
    obj = scorecard.get("objective", {})
    ctrl = scorecard.get("controls", {})
    gates = scorecard.get("gates", {})
    lines = [
        f"# Web-objective efficacy — {scorecard.get('run_id', '')}",
        "",
        f"- Mode: `{scorecard.get('mode', '')}`",
        f"- **Eligible: {scorecard.get('eligible')}** "
        f"(complete={gates.get('complete_records')}, "
        f"zero_false_confirmations={gates.get('zero_false_confirmations')}, "
        f"zero_wrong_class_confirmations={gates.get('zero_wrong_class_confirmations')}, "
        f"zero_human_interventions={gates.get('zero_human_interventions')}, "
        f"healthy_execution={gates.get('healthy_execution')})",
        "",
        "## Objective (positive cases)",
        f"- First-attempt: {obj.get('first_attempt_successes')} "
        f"(rate {obj.get('first_attempt_rate')})",
        f"- Pass @ attempt budget: {obj.get('solved_within_attempt_budget')} "
        f"(rate {obj.get('pass_at_attempt_budget')})",
        f"- Repeatable (all attempts): {obj.get('repeatable_successes')} "
        f"(rate {obj.get('repeatability_rate')})",
        "",
        "## Controls",
        f"- Fixed-control false-confirmation cases: {ctrl.get('false_confirmation_cases')}",
        f"- Wrong-class confirmations: {len(ctrl.get('wrong_class_confirmation_events', []))}",
    ]
    excluded = scorecard.get("excluded_verified_attempts", [])
    if excluded:
        lines += ["", "## Excluded (lab-solved but attempt did not complete cleanly)",
                  *[f"- {e['case_id']} attempt {e['attempt']}" for e in excluded]]
    return "\n".join(lines) + "\n"


def _load(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--targets", required=True,
                        help="JSON {case_id: target_url} of fresh authorized labs")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--mode", default="autonomous", choices=sorted(wob.VALID_MODES))
    parser.add_argument("--oracle", help="JSON {case_id: [bool per attempt]} owner "
                                         "lab-solved verdicts (out-of-band oracle)")
    parser.add_argument("--run-id")
    parser.add_argument("--max-requests", type=int)
    parser.add_argument("--wall-timeout", type=float)
    parser.add_argument("--step-budget", type=int)
    parser.add_argument("--max-nodes", type=int)
    args = parser.parse_args(argv)

    budgets = {k: v for k, v in {
        "max_requests": args.max_requests, "wall_timeout": args.wall_timeout,
        "step_budget": args.step_budget, "max_nodes": args.max_nodes,
    }.items() if v is not None}

    result = orchestrate(
        _load(args.manifest), _load(args.targets), mode=args.mode,
        output_dir=Path(args.output_dir),
        oracle=_load(args.oracle) if args.oracle else None,
        run_id=args.run_id, budgets=budgets)
    print(render_summary(result["scorecard"]))
    return 0 if result["scorecard"]["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
