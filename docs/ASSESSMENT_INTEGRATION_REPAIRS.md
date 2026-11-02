# Active assessment integration

This branch combines the PR #1 base (9866784), the selected assessment repairs,
RV-T, RV-U and approved callback configuration. Older main-checkout UI, export,
health and triage WIP is excluded. The history/privacy dependencies in cache.py,
knowledge.py and agents/base_agent.py were selected separately for Ticket 1.

Captured request variants retain query/body/content type, concrete object IDs,
observed response and a credential fingerprint. Graph serialization and atomic
merge preserve distinct variants. Request credentials come from the matching
supplied identity, never another capture. Unknown custom headers conservatively
participate in identity matching. Missing bodies, unmatched identities, adjacent
origins and unsupported methods remain explicit unexecuted work. A shape with no
iterative hypothesis is reported separately from a missing capture; deterministic
coverage may still test it. These distinctions explain why the old worklist's
`missing_template` count was not a reliable count of lost captures: its final
fallback also covered a shape scan that produced no confirmation.

Coverage exposes a phase ledger with explicit units (identity/endpoint/check),
shape applicability, implementation, policy evidence, queue/attempt/send/conclusion
and one terminal reason. Routes and identities are interleaved; starting checks
rotate across groups. Parameter cases without separate proof remain untested.
Dispatch exceptions do not prove a send. Transport-observed replies are counted
per task, avoiding another concurrent caller's activity granting execution credit.
The ledger's `drive` block (and `audited.drive`, the run manifest's
`coverage_audited`, and `assessment.requests_driven`/`conclusive`) reports
requests driven next to conclusive cells: a leg that sent requests but ended
inconclusive is a fresh attempt with its send count, yet stays unexecuted. The
ledger key `sent` is kept for compatibility; it counts cells with a recorded
execution, not requests (`drive.labels` names each unit).

Completed coverage results include a checkpoint. `resume_job_id` accepts only a
managed, hash-verified result from the same origin and unchanged source/config.
The driver also matches exact captures and identities before restoring conclusive
executed cells. Changed inputs conservatively cause a fresh check. Discovery and
precondition stages can run again; resume only skips completed deterministic
coverage cells. A cancelled job retains partial findings, but does not claim an
in-flight coverage checkpoint before that phase completed.

See HISTORY_AND_JOB_RESULTS.md for authenticated bounded retrieval and retention,
VERIFICATION_SNAPSHOTS.md for reproducible source copies, and
CALLBACK_CONFIGURATION.md for explicit callback approval and network preflight.
Branch/unit checks are not evidence of live model accuracy or target recall.
