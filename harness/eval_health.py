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

_UNSET = object()


def _completeness(job: dict, expected_key: str, present_key: str, label: str) -> tuple[bool, str | None]:
    """True (no reason) only when the caller EXPLICITLY declared its expected
    set -- even an explicit empty list counts as a real "nothing expected"
    declaration -- and every expected member is present. A MISSING
    expected_key reads as "unknown expectations", never "assumed fine": the
    absence of a declared expectation is not evidence the phase/artifact list
    was legitimately empty."""
    expected_raw = job.get(expected_key, _UNSET)
    if expected_raw is _UNSET:
        return False, f"no {label} expectations declared ({expected_key!r} key missing)"
    expected = set(expected_raw or [])
    present = set(job.get(present_key, []) or [])
    missing = sorted(expected - present)
    if missing:
        return False, f"missing {label}: {missing}"
    return True, None


def evaluate_health(job: dict) -> dict:
    """Evaluate one run's health from a plain summary dict.

    Expected `job` keys (all optional; a MISSING key reads as the unhealthy
    default, never as "assumed fine" -- an explicit empty list/False is a
    real declaration and is honoured):
      - "exit_code": int | None -- the harness process's own exit code.
      - "expected_artifacts": list[str], "present_artifacts": list[str].
      - "target_healthy": bool (must be an actual bool; a truthy non-bool
        value such as the string "false" is never read as healthy),
        "target_health_reason": str.
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

    artifacts_complete, artifact_reason = _completeness(
        job, "expected_artifacts", "present_artifacts", "artifact(s)")
    if artifact_reason:
        reasons.append(artifact_reason)

    target_healthy_raw = job.get("target_healthy", _UNSET)
    if target_healthy_raw is _UNSET:
        target_healthy = False
        reasons.append("target health not reported (target_healthy key missing)")
    elif not isinstance(target_healthy_raw, bool):
        target_healthy = False
        reasons.append(
            f"target_healthy must be a real bool, got {target_healthy_raw!r} -- a truthy "
            "non-bool value (e.g. the string 'false') is never read as healthy")
    else:
        target_healthy = target_healthy_raw
        if not target_healthy:
            reasons.append(
                f"target not healthy: {job.get('target_health_reason', 'no health signal reported')}")

    no_missing_phase, phase_reason = _completeness(
        job, "expected_phases", "completed_phases", "phase(s)")
    if phase_reason:
        reasons.append(phase_reason)

    eval_valid = process_complete and artifacts_complete and target_healthy and no_missing_phase

    return {
        "process_complete": process_complete,
        "artifacts_complete": artifacts_complete,
        "target_healthy": target_healthy,
        "no_missing_phase": no_missing_phase,
        "eval_valid": eval_valid,
        "reasons": reasons,
    }
