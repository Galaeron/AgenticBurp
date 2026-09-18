"""Separate process / artifact / target-health / eval-validity signals (P0.7,
evaluation integrity).

A run's exit code alone conflates four independent questions a reviewer
actually cares about: did the harness PROCESS finish cleanly, did it write
every ARTIFACT it was supposed to, was the TARGET actually healthy the whole
time (not restarted, not returning a stateless-DB error), and did every
expected PHASE run at all. A clean exit code says nothing about whether the
target died at minute 40 or a phase was silently skipped -- exactly the
"green tests, dead pipeline" failure mode this project has hit three times.
`evaluate_health` keeps the four signals independent and explicit rather
than inferring target health (or anything else) from the exit code alone.

Pure and hermetic: reads a plain job-summary dict the caller assembles from
whatever it already tracked (process exit code, artifact manifest, target
health probe, phase ledger) -- no I/O, no live run.
"""
from __future__ import annotations


def evaluate_health(job: dict) -> dict:
    """Evaluate one run's health from a plain summary dict.

    Expected `job` keys (all optional; a missing key reads as the unhealthy
    default, never as "assumed fine"):
      - "exit_code": int | None -- the harness process's own exit code.
      - "expected_artifacts": list[str], "present_artifacts": list[str].
      - "target_healthy": bool, "target_health_reason": str.
      - "expected_phases": list[str], "completed_phases": list[str].

    Returns {"process_complete", "artifacts_complete", "target_healthy",
    "no_missing_phase", "eval_valid", "reasons"}. `eval_valid` is the AND of
    all four; each False flag appends a human-readable reason. This never
    infers target health (or artifact/phase completeness) from the exit
    code -- each signal reads only its own dedicated job field.
    """
    reasons: list[str] = []

    process_complete = job.get("exit_code") == 0
    if not process_complete:
        reasons.append(f"process did not complete cleanly (exit_code={job.get('exit_code')!r})")

    expected_artifacts = set(job.get("expected_artifacts", []) or [])
    present_artifacts = set(job.get("present_artifacts", []) or [])
    missing_artifacts = sorted(expected_artifacts - present_artifacts)
    artifacts_complete = not missing_artifacts
    if not artifacts_complete:
        reasons.append(f"missing artifact(s): {missing_artifacts}")

    target_healthy = bool(job.get("target_healthy", False))
    if not target_healthy:
        reasons.append(
            f"target not healthy: {job.get('target_health_reason', 'no health signal reported')}")

    expected_phases = list(job.get("expected_phases", []) or [])
    completed_phases = set(job.get("completed_phases", []) or [])
    missing_phases = [p for p in expected_phases if p not in completed_phases]
    no_missing_phase = not missing_phases
    if not no_missing_phase:
        reasons.append(f"missing phase(s): {missing_phases}")

    eval_valid = process_complete and artifacts_complete and target_healthy and no_missing_phase

    return {
        "process_complete": process_complete,
        "artifacts_complete": artifacts_complete,
        "target_healthy": target_healthy,
        "no_missing_phase": no_missing_phase,
        "eval_valid": eval_valid,
        "reasons": reasons,
    }
