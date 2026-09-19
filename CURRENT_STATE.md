# Current state — 2026-09-19

## Checkout and scope

Branch `reconciliation-backlog`; base HEAD `8f63511` at this audit's start.
The checkout is dirty and has concurrent product work. Do not assume HEAD alone
identifies the tested tree, or stage unrelated edits. This session rationalizes
documentation, test selection and repeated transport tests; it does not certify
new exploit capability, current model accuracy or a Java build.

## Current orientation

- AGENTS.md is the shared onboarding source; CLAUDE.md redirects there.
- README.md covers setup; docs/ indexes architecture and test evidence boundaries.
- `python -m harness.suite full` runs harness unittest, pytest-native, score
  plumbing and standalone evaluation tests. Smoke is a smaller caller-level gate.
- Seven validator transport adapters share `test_validator_transport.py`:
  14 positive/denied scenarios remain; CORS-specific controls remain separately.
- Discovery guards now reject main-only modules, mixed uncollected tests and
  shadowed definitions, and verify actual CI selections. No bulk test deletion
  was justified by age or mocked boundaries.

## Verification in this session

An isolated `.venv-rationalisation` was created with the declared core/dev
dependencies, Flask and proxy dependencies to work around the bundled
runtime's incomplete old dependency directories; Python 3.12 requires an
explicit typing-extensions metadata workaround (see docs/TESTING.md).
Sandbox access to existing audit-log and pytest temp paths blocked that
environment's initial full run.

`python -m harness.suite full` was subsequently run to completion against
this exact working tree (this rationalization plus the concurrent
role-crawl/task-graph/agent/knowledge work below, both present) on the
ambient Python 3.14 interpreter: harness unittest discovery **2293 OK**
(386s), native pytest (`test_plugin_system`/`test_execution_protocol`/
`test_hardening`) **38 passed**, `testing/` **13 OK**, `evaluation_integrity/
tests` **42 OK** — combined exit 0. This is a fresh pass of the actual suite
selections, not a re-report of the blocked `.venv-rationalisation` attempt
above; it does not by itself certify model accuracy, live-target recall, or
the caller-level integration gaps the implementation review raised.

## Open work and inherited evidence

The [implementation review](reviews/2026-09-19/implementation-review/REVIEW.md)
reported evaluation integration, proof binding, provenance/health, shared-memory
privacy, export/UI, coverage attribution, comparison and SARIF gaps at the base
revision. Concurrent edits to these areas appeared during this audit; their
completion is not certified here. Helper tests alone cannot close caller-level
integration findings. Use the review as a task-specific checklist, not onboarding.

Other pre-existing work includes Ollama/agent, model, role-crawl and task-graph
changes plus new attack-tree/cross-role tests. Leave it with its owner.

**Update from that owner's session (same day, `reconciliation-backlog`):** the
role-crawl/task-graph/agent/knowledge work above is DONE, not WIP — it
implemented `reviews/2026-09-19/IMPLEMENTATION_PLAN.md` P1.2/P2.3 (RAG),
P1.3 (multi-role probe), P1.4 (attack tree), P1.14 (tactical guides), four
focused commits (`1b0b1d5`..`506e2e5`), each with its own hermetic tests
(9+21+16+13 new tests) and a negative control per the plan's #0 discipline.
Full suite green after the last commit: `python -m unittest discover -t .
-s harness -p "test_*.py"` → **2285 OK**, exit 0, ~388s (run concurrently
with this audit session's own edits to unrelated files). Not live-verified
against a target/model — hermetic only, same caveat as the rest of this
session's inherited work. See the commit messages for what each item does;
not re-narrated here to avoid duplicating/drifting from them.

Prior suite counts and live scores are historical/reported, not fresh evidence.
The earlier integrated live run used
`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`; its completion and
results were not checked here. Do not stop a process based on an old status note.
No model/target run, hosted CI or Java build was performed for this rationalization.

The complete pre-consolidation notes (including pre-existing uncommitted text)
are preserved in [the onboarding snapshot](archive/onboarding-2026-09-19/INDEX.md).
Read them only for a specific historical question; do not restore the session chain.
