# Current state

AgenticVibe is a **working research prototype**: a Burp Suite copilot that uses
local LLMs to review captured HTTP traffic and deterministic validators to
confirm or refute the findings. See [README.md](README.md) for what it is and
[docs/USER_MANUAL.md](docs/USER_MANUAL.md) for how to run it safely.

## What is verified

- **It installs and runs.** `python -m harness.server` starts the FastAPI
  server on `127.0.0.1:8787`; the Burp extension (Java/Montoya) compiles and its
  Java unit tests pass.
- **The parts behave as designed.** ~2,400 Python tests and ~230 Java tests pass
  (`python -m harness.suite full`). These are component/behaviour tests —
  e.g. a validator flags a planted vuln in a fixture, a gate caps a finding.
- **Safe-by-default posture.** Out of the box the harness does passive review
  only: active validators, autonomous discovery, the oracle and the cloud seams
  are all OFF; `allowed_hosts` is unset. See the USER MANUAL to enable active
  testing on a scoped host.

## What is NOT verified (read before trusting results)

- **Real-model accuracy on unseen targets.** The component tests do not measure
  how often the LLM agents catch real bugs on an unfamiliar app, or the
  false-positive rate. The detection scorer (`testing/score.py`) is reproducible
  but needs a local model and a corpus you build yourself (see the USER MANUAL),
  and the corpora it was developed against are **tuning corpora, not blind** —
  their answer keys ship in the repo. Treat headline detection claims as
  unproven until you run it against a target it was never tuned on
  (WebGoat/DVWA/a PortSwigger lab — runbook in the USER MANUAL).
- **LLM-agent detection from traffic.** The confirmation/validator layer *is*
  live-verified against an owned loopback fixture with paired secure controls
  (`harness/test_leg_live_verification.py`, broad class coverage); what is not
  measured is whether the agents flag the issue from real traffic in the first
  place. (The `coverage_manifest.py` ledger reports most classes as
  `gap_unimplemented`, but that means "not registered in the ledger," not "no
  test" — see docs/LIMITATIONS.md.)

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full, honest list of
known issues, gaps and roadmap (Burp integration, an in-flight scope-handling
refactor, performance, data handling, architecture debt).

## In-flight / known rough edges

- **Scope handling is mid-refactor.** The main analysis path and the crawler now
  fail *closed* on an empty scope in active mode, but `scope_lock`/`safety_gate`
  and several validators' own inline checks are still being migrated to the same
  contract; some unit tests that construct an active gate without a scope are red
  in the working tree because of this migration. Do not rely on a single
  entry-point check — set `server.allowed_hosts` explicitly for any active run.
- Historical reviews and plans under `archive/` and `reviews/` describe the
  revisions they were written for, not current capability. Code is authoritative
  for behaviour; `docs/` is the current documentation.
