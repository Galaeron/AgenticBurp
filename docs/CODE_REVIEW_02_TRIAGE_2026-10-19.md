# Code review 02 triage — 2026-10-19

Source: `reviews/2026-10-17-code-review-02/FINAL_REVIEW.md` (untracked), which reviewed
`a7d03b5` plus the main-checkout WIP. Its reproduction scripts (`*_checks.py`,
`boundary_checks.py`) and logs sit beside it. Nothing has landed since `a7d03b5`, so every
finding is open, except R04.

**R04 needs no work.** It is the rejected W2 `analyze:<uuid>` hunk (owner decision
2026-10-17), which exists only as WIP. It closes when I01 drops that hunk from the WIP.

## Rules for every batch

- Read only your findings' sections of FINAL_REVIEW.md: grep `### Rnn`, then read that range.
- Reproduce first with the reviewer's check: its assertion must fail before your fix.
- Then port the check into a harness test that drives the production caller. That test needs:
  - the reviewer's control as the negative control;
  - one fault injection.
- The reviewer's scripts import from the main checkout (`ROOT = parents[1]`). Copy what you need
  into your worktree; do not run them against a worktree unchanged.
- Work in your own in-repo worktree under `.test-work/`, using `sitecustomize.py` +
  `PYTHONPATH` (CURRENT_STATE "Verification").
- Commit on your own branch only. Never push.
- Four files carry main-checkout WIP: `harness/server.py`, `harness/store.py`,
  `harness/orchestrator_detect.py` and `HarnessPanel.java`. Batches touching them:
  - start only after I02-C lands;
  - land from the index, never with a path-limited commit, which would sweep in W1–W4 WIP.
- Verify precondition, smoke and full on Python 3.14 and the 3.12 venv.
- Write exit codes to a summary file and read only that summary.
- Finish with HANDOFF.md, using the guide's section 6 template, and record per finding:
  - the reproduction before the fix;
  - the fix;
  - the control;
  - the fault injection;
  - the status label.

## Batches

P1 findings are in bold. Batches have disjoint files.

| Batch | Findings | Files | Ticket | Start | Model |
|---|---|---|---|---|---|
| RV-A tool cleanup | **R35, R36**, R34, R37 | `tool_proxy.py`, `tool_runner.py`, `testing/egress_probe.py` | I05 | now | Opus |
| RV-B evaluation certification | **R38, R39, R46**, R40, R47, R48 | `evaluation_integrity/audit.py`, `testing/evidence_grade.py`, `testing/run_web_objective_efficacy.py` | I12 | now | Sonnet |
| RV-C evaluation provenance | R41–R45 | `testing/eval_adapter.py`, `rescore_run.py`, `run_captured_analysis.py`, `score.py` | I12 | when a slot frees | Sonnet |
| RV-D false confirmations I | **R09, R14, R16, R17**, R08 | validators: `cors`, `idor_read`, `open_redirect`, `ssrf` | I10 | when a slot frees | Opus |
| RV-E false confirmations II | **R18, R19, R20, R33** | validators: `api_security`, `stored_xss`, `auth_sequence`; `attribution.py` | I10 | when a slot frees | Opus |
| RV-F blocked is not negative | R10, R11, R12 | validators: `cross_identity`, `ssti`; `coverage_tracker.py` | I10 | when a slot frees | Sonnet |
| RV-G no-run routes and settings | **R01, R02, R03, R15**, R07 | `server.py` (`/settings`, `/crawl`, `/crawl-roles`, `/engagement/{host}/advance`, `/probe-missing-auth`) and crawl helpers | I05 (its planned no-run routes) | after I02-C lands | Opus |
| RV-H evidence states | **R49**, R05, R06 | `store.py`, `orchestrator_detect.py`, `orchestrator_confirm.py` | I02 | after I02-C lands | Opus |
| RV-I discovery and anomalies | R13, R21, R22, R23 | `api_surface_discovery.py`, `validators/recon_validator.py`, `worklist_investigator.py`, `agents/anomaly_agent.py` | I06/I07 | when a slot frees | Sonnet |
| RV-J Burp executors | **R25–R29, R31**, R24, R32 | `ValidationExecutor.java`, `logic/OAuthFlowLogic.java`, `logic/CspClickjackingLogic.java` | I16 | needs a JDK build | Opus |
| RV-K Burp UI | R30, R50–R53 | `ui/HarnessPanel.java` (WIP), `ui/AnalysisTracker.java`, `ui/HarnessToolsPanel.java` | I16 | after I01 W-split; needs a JDK | Sonnet |

## Order

1. **Now**, alongside the I05 session (B, then D): RV-A and RV-B. They hold the P1 cleanup
   and certification findings and touch no WIP file. Keep to at most 3 sessions in parallel.
2. **After I02-C lands:** RV-G and RV-H.
   - RV-G replaces I05's separate "no-run routes" item.
   - Run no live target until RV-A, RV-G and RV-H have landed (the review's step 1).
3. **Then** RV-D and RV-E (P1 confirmation soundness, under I10), followed by RV-F, RV-I
   and RV-C.
4. **RV-J and RV-K** need a real JDK/Gradle build (I15). A Java source change without one
   stays labelled unverified.

The review's own disposition of non-promoted hypotheses (its last two sections) stands. It
adds no findings beyond R01–R53.

## Status

Landed on PR #1 (2026-10-19): RV-A and RV-G, verified together at `9d76c5d`. Both are
caller-verified, not live-validated. Handoffs are in `.test-work/rv-a-toolcleanup-20261019/` and
`.test-work/rv-g-norunroutes-20261019/`.

- **RV-A** (`aa97fc2`, `8b5ed4e`, `cf4a264`):
  - R35: the tool proxy's close() is bounded, and a client that stalls for 30 s gets a 408.
  - R36: on Windows, when no Job Object can contain a tool, the harness refuses to start it
    (outcome `containment_unavailable`). The PID-only fallback is removed.
  - R34: a same-origin redirect is returned origin-relative, so a container client keeps its
    own proxy address. This is checked against an emulated container client only.
  - R37: the egress probe records a connection when it is accepted and drains handlers before
    the verdict.
  - Open: real Docker runs of R34 and of the R37 egress proof.
- **RV-G** (`9d76c5d`):
  - R01: `/settings` rejects non-boolean toggles with a 422 (also `coordinator.cloud_reasoning`).
  - R02: `/crawl`, `/crawl-roles` and `/engagement/{host}/advance` each own a run. Every hop,
    redirects included, passes scope, target policy, the safety gate and budget. Caller headers
    stay on the base origin. Their clients are now pinned, which closes I05 B's limit.
  - R03: `/advance` refuses with a 403 while active testing is off.
  - R07: robots.txt paths and query endpoints that look destructive (`/logout` and similar)
    are suppressed and never fetched.
  - R15: `/probe-missing-auth` confirms only when the endpoint is declared protected and a
    matching authenticated baseline exists. Otherwise the result is an unconfirmed
    `unauthenticated_access` candidate.
  - Interim choices, accepted by the owner for now (2026-10-19):
    - the routes have no request ceiling beyond `runs.max_requests` (unset) and their own
      page caps;
    - they never send mutating probes;
    - the Burp "Probe missing auth" panel sends no baseline, so its results stay
      unconfirmed until an I16 Java change adds one.
  - Follow-ups (not findings):
    - A: orchestrator_chain's missing-auth confirm still hardcodes `expected_protected=True`.
    - B: `_require_target_fetch(bulk=True)` could be relaxed for routes that own a run.
    - C: `/probe-missing-auth` creates its runs without `config=`, so config transport
      settings are not applied there.
    - D: `/probe-missing-auth` sends anonymous GETs while active testing is off.

Next: RV-H (it gates live targets), then RV-B, RV-D, RV-E and the rest in the order above.
