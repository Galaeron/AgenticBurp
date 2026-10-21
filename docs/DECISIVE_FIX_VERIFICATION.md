# Decisive-run fixes: verification, 2026-10-14

Base: `474ad511`. Reviewed candidate: `5aedf787` on
`reconciliation-backlog`. Verification distinguishes this committed candidate
from the main checkout, which contains substantial earlier work in progress.

## Changes committed

- `ba7a649e`: forward explicit Ollama provider seeds, including zero; enforce
  zero temperature across coordinator, agents and critique; reject conflicting
  seeds and non-Ollama providers for this decisive-run contract.
- `4d713696`: authenticate server provenance, bind the actual captured-analysis
  driver to server controls and source identity, invalidate on drift, and exercise
  all 14 cross-user dispatch fixtures through the production confirmation caller.
  Missing identities, disabled active mode and denied scope are negative controls.
- `4374e060`: suppress traversal probes for distinct SQLi/IDOR/business-logic
  classifications; repair stored-finding fixtures, seed-aware provider doubles
  and the static test-discovery guard.
- `5aedf787`: make the report fixture's optional history mock compatible with
  the committed store API as well as the main checkout's additional WIP API.

The server commit contains only the two provenance hunks. Earlier health,
engagement, store, export, cache, UI and normalization work remains separate.
Two stale fixtures in pre-existing untracked tests were also repaired in place:
the engagement provider double accepts `seed`, and the IDOR fixture explicitly
scopes `t.test`. Those test modules are not bundled into these commits.

## Verification evidence

Logs are under `.test-work/consolidation-20261014/` in the primary checkout.
Python is `.venv-rationalisation/Scripts/python.exe` (3.12.14).
The managed worktree `verify-decisive-fixes/AgenticVibe` contains the committed
candidate without the main checkout's uncommitted files.

- Isolated focused caller/configuration/seed/dispatch controls: **136 pass**,
  including `harness.test_orchestrator_precondition` (`committed-focused.log`).
- Main checkout smoke: **93 pass** plus the coverage-manifest check (`smoke.log`).
- Final isolated smoke: **93 pass**, coverage-manifest check passed, exit 0
  (`committed-smoke.log`).
- Java: JDK 17 and Gradle 8.7, existing provisioned dependency cache;
  `--no-daemon --offline --rerun-tasks test shadowJar` actually executed.
  Isolated candidate: **229 pass**, no failures/errors/skips (`committed-java.log`).
  Main checkout: **252 pass**, no failures/errors/skips (`java-cached.log`).
  Initial attempt without that cache failed plugin resolution (`java.log`).
  Java was built at `4374e060`; `5aedf787` changes only one Python test mock,
  so the verified Java source and build inputs are unchanged.

- Main checkout `python -m harness.suite full`: **3,398 harness tests**, **38
  pytest tests**, **364 evaluation tests**, **42 integrity tests**, all pass;
  coverage-manifest check passed, process exit 0 (`full.log`). This run included
  pre-existing untracked tests and WIP. The endpoint fixture was made independent
  during that run and rechecked separately (86 controls in `final-callers.log`).

The first isolated full run (`committed-full.log`) caught one test-fixture error:
the report test mocked a history helper present only in the main checkout's WIP.
Commit `5aedf787` corrects that dependency. Its full-suite rerun passed with exit
0: **3,103 harness tests**, **38 pytest tests**, **284 evaluation tests passed
and 17 skipped** (301 collected), **42 integrity tests**; coverage-manifest check
passed (`committed-full-final.log`). The final fixture also passes all 12 report
tests in the main checkout (`working-final-report-fixture.log`).

The 17 isolated evaluation skips are optional local-artifact tests: two missing
DVWA/WebGoat captured corpora, one historical strict-run pooling smoke test, and
14 historical benchmark reconciliation/config-drift tests. Exact names/reasons
are in `committed-skip-reasons.log`. These artifacts are absent from Git; the
skips are not evidence of a passing live or historical benchmark.

## Remaining gates and limits

- Live crAPI confirmation has not run. Docker's Linux-engine pipe is unavailable;
  captured crAPI `localhost:8888` and harness `127.0.0.1:8787` failed TCP connection
  checks. Ollama `127.0.0.1:11434` accepts TCP; this alone does not establish model
  readiness. No unrelated service was stopped and safe defaults remain unchanged.
- The external `agenticburp-eval/eval-run/run_analysis.py` delegates to the
  versioned driver using `--harness-repo`. An owned server must be restarted from
  the intended source with a filled overlay and registered test identities;
  updating a client checkout does not update a running server.
- Phase 2.2 remains open. Recomputed class-vocabulary misses at the committed
  candidate are **63/122 labels (51.64%)**, **374/978 occurrences (38.24%)**.
  The main checkout's earlier normalization WIP yields **60/122 (49.18%)** and
  **272/978 (27.81%)**. Neither metric establishes production dispatch or recall.
- Model digest/runtime version remain explicitly unavailable in provenance;
  a fixed seed is a reproducibility control, not a bit-identical-output guarantee.
- Offline controls and Java compilation establish neither live Burp behavior
  nor current model accuracy, secure-control rejection or blind-target recall.
