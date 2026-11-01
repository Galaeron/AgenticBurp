# Deterministic-first objective implementation checklist

Use this as the implementation handoff for extending the successful PortSwigger
SQL-injection experiment across AgenticVibe. Work in small, reviewable batches.
Do not claim XBOW 104 performance from unit tests or a single live case.

For the operational live-test loop, current three-case results, and the next
objective-completion repair, use
`docs/LIVE_OBJECTIVE_CONTINUATION_HANDOFF.md`.

## Current verified baseline

- [x] SQL-shaped captured requests reach `SqlmapValidator` before broad model review.
- [x] HTML anchor queries survive crawl, role probing, capture templates and replay.
- [x] Query-bearing dynamic resource handlers such as
      `/image?filename=25.jpg` survive discovery and become concrete replay
      templates; static cache-busted assets remain excluded.
- [x] Class-scoped objective runs stop after deterministic confirmation.
- [x] Class-scoped deterministic negatives return without changing into an
      unrelated open-ended model experiment.
- [x] Run-context responses do not retain stale compression/length headers after
      their bodies have already been decoded.
- [x] Confirmation persists `case_id`, `proof_id`, validator identity and
      execution evidence.
- [x] The smoke runner records bounded budgets, checkout/config identity and a
      suspended stack on timeout.
- [x] Final SQL regression run: 1.371 seconds, 7 requests, one confirmed finding,
      no degradation. See
      `reviews/2026-09-29/web-objective-smoke/attempt-18-live/attempt.json`.
- [x] A path-traversal run on an unsolved PortSwigger instance independently
      changed the lab oracle to `Solved` after deterministic confirmation.
      Attempt 1 first exposed the missing dynamic-resource discovery path;
      attempt 2 succeeded after that repair.
- [x] `PathTraversalValidator` now uses the run-scoped transport. The accounting
      regression completed in 1.513 seconds and correctly counted all 6 requests.
      See `reviews/2026-09-29/web-objective-smoke/path-traversal-attempt-5-accounting/attempt.json`.
- [ ] The SQL case has not yet produced a clean first-attempt formal pass on a
      fresh unsolved instance.
- [ ] Three repetitions and a fixed control have not yet been run.

## Repository safeguards

- [ ] Read `AGENTS.md` and `CURRENT_STATE.md` before editing.
- [ ] Do not read any `*ANSWER_KEY*` file or a blind target's `app.py`.
- [ ] Keep `harness/config.yaml` at safe defaults. Put live overrides in memory
      or ignored `harness/config.local.yaml`, then restore local state.
- [ ] Do not install sqlmap on Windows. Use the configured Docker image for the
      full sqlmap path.
- [ ] Preserve pre-existing edits and runtime artifacts.
- [ ] Use one owned target/server instance and a fresh cache for live reruns.
- [ ] Preserve `harness/test_pipeline_gate.py` and its defect-injection controls.

## Batch 1 — make objective execution a first-class contract

The current implementation is split across nested functions in
`harness/orchestrator_chain.py::investigate_engagement`. Extract the reusable
contract before adding more class-specific behavior.

- [ ] Add a small objective-profile module, for example
      `harness/objective_profiles.py`.
- [ ] Define an immutable `ObjectiveProfile` with:
  - canonical vulnerability class;
  - accepted aliases;
  - shape/precondition predicate;
  - validator factory or registered validator name;
  - safe-method and mutating-method policy;
  - maximum requests, parameters and wall time;
  - whether a bounded fast path is available;
  - confirmation threshold and stop condition.
- [ ] Build profiles from the existing implementations. Do not duplicate
      validator logic inside the profile.
- [ ] Replace the SQL-specific
      `objective_class == "sqli"` checks in `orchestrator_chain.py` with
      profile capabilities.
- [ ] Canonicalize the requested objective once at the public boundary. Reject an
      unknown objective with an explicit configuration error.
- [ ] Keep ordinary broad engagements behaviorally unchanged when no objective
      profile is supplied.

Acceptance:

- [ ] A caller-level positive test proves an eligible captured exchange invokes
      the profile's validator before `review_captured_exchanges`.
- [ ] A negative control proves a nonmatching shape sends no validator requests.
- [ ] A broad-run control proves model review still occurs without an objective.
- [ ] An unknown-class test fails explicitly rather than silently running broad.

Start with:

- `harness/orchestrator_chain.py`
- `harness/orchestrator_helpers.py::shape_precondition_legs`
- `harness/validators/registry.py`
- `harness/test_deterministic_first.py`
- `harness/test_orchestrator_precondition.py`

## Batch 2 — preserve request semantics end to end

Every objective depends on replaying the actual accepted request shape.

- [ ] Introduce one request-template representation shared by crawler, role crawl,
      engagement state and worklist seeding.
- [ ] Preserve method, path, ordered query pairs, repeated query keys, body bytes
      or lossless text, content type, relevant noncredential headers, principal
      reference and observed object identifiers.
- [ ] Keep credentials in session/principal storage; do not serialize raw secrets
      into benchmark artifacts.
- [ ] Stop reconstructing queries from route names when an observed query exists.
- [ ] Record whether each field was observed, derived or synthesized.
- [ ] Mark a synthesized template ineligible for validators that require a valid
      baseline value.
- [ ] Use deterministic ordering when several observed templates map to one route.
      Prefer a substantive successful capture and retain alternatives for bounded
      retry rather than arbitrary set iteration.

Acceptance:

- [ ] Anchor-query regression: `/filter?category=Pets` reaches the validator with
      that value intact.
- [ ] Repeated-query regression preserves `id=1&id=2`.
- [ ] Form and JSON regressions preserve their original content type and body.
- [ ] Identity regression proves two principals never share a replay template or
      confirmation-cache entry accidentally.
- [ ] Synthetic-empty baseline negative control does not become a false negative.

Start with:

- `harness/crawler.py`
- `harness/role_crawl.py`
- `harness/engagement.py`
- `harness/worklist_investigator.py::_seed_exchange`
- `harness/models.py::HttpExchange`

## Batch 3 — make validator outcomes explicit

The SQL experiment exposed a gzip transport error that was swallowed as “no
finding.” All objective validators need a four-state result.

- [ ] Standardize objective results as:
  - `confirmed`;
  - `tested_negative`;
  - `inconclusive` for an executed test without sufficient evidence;
  - `error` for transport, dependency, policy or persistence failure.
- [ ] Return validator diagnostics from `_confirm`/`_confirm_leg`; do not use a
      missing finding as the only representation of all nonconfirmed states.
- [ ] Remove broad `except Exception: return` behavior from the objective path.
      Convert exceptions into structured errors with phase, validator and case.
- [ ] Keep errors out of eligible benchmark denominators and make the run
      `degraded=True`.
- [ ] Distinguish policy-blocked, budget-exhausted, dependency-unavailable,
      transport-error and oracle-unavailable.
- [ ] Add per-validator duration and request count to the result artifact.

Acceptance:

- [ ] A forced transport exception yields `error`, never `tested_negative`.
- [ ] A safety-gate denial consumes zero request budget and reports
      `policy_blocked`.
- [ ] A clean fixed control yields `tested_negative`.
- [ ] A proof-persistence failure is visible in the returned result.
- [ ] Timeout artifacts identify the active phase and validator.

Start with:

- `harness/validators/base.py::ValidationResult`
- `harness/orchestrator_chain.py::_confirm`, `_confirm_leg`, `_apply`
- `harness/worklist_investigator.py`
- `testing/run_web_objective_smoke.py`

## Batch 4 — harden the shared transport boundary

- [ ] Add a helper that converts `ExecutionOutcome` to an `httpx.Response`
      without reattaching stale wire-level headers.
- [ ] Use the helper in every validator adapter currently rebuilding responses.
- [ ] Strip or recompute `Content-Encoding`, `Content-Length` and
      `Transfer-Encoding` after decoding.
- [ ] Preserve status, final URL, meaningful response headers and exact decoded
      body content.
- [ ] Verify redirect behavior is explicit per validator.
- [ ] Verify cookie/session binding, duplicate headers, non-UTF-8 bodies,
      compressed responses and truncated responses.
- [ ] Inventory all direct `httpx`/browser/subprocess sends and route target HTTP
      through `RunContext` where required.

Acceptance:

- [ ] Shared transport tests cover gzip, Brotli when available, redirects,
      cookies, charset decoding and malformed compression.
- [ ] Every executed request increments the run budget once.
- [ ] Blocked or off-scope requests increment it zero times.
- [ ] No validator can send to a host outside the run scope.

Start with:

- `harness/run_context.py::TargetTransport`
- `harness/validators/transport.py`
- `harness/test_validator_transport.py`
- `harness/test_run_context.py`
- `harness/test_sqlmap_validator.py`

## Batch 5 — port deterministic-first execution by vulnerability class

Implement one class per batch. Each class needs an observed-shape positive, a
fixed negative control, an infrastructure-error control and a caller-level
ordering test.

Suggested order:

- [ ] **Open redirect:** redirect-like parameter → off-origin Location check.
- [ ] **Path traversal:** file/path parameter → known-file/control differential.
- [ ] **SSTI:** input parameter on render-like behavior → arithmetic canary.
- [ ] **Command injection:** command-like parameter → marker or owned OOB callback.
- [ ] **SSRF:** URL parameter → owned callback with correlation token.
- [ ] **XXE:** XML body → owned entity callback or deterministic in-band evidence.
- [ ] **Reflected XSS:** reflected parameter → browser execution in the response
      context.
- [ ] **DOM XSS:** fragment/source shape → browser sink execution.
- [ ] **Stored XSS:** mutating plant plus separate render observation; require
      cleanup or an isolated disposable fixture.
- [ ] **JWT weakness:** JWT-bearing identity → bounded forge/replay differential.
- [ ] **IDOR/BOLA:** observed object id plus two distinct principals → same-object
      cross-identity replay.
- [ ] **Mass assignment:** observed writable body → write/read invariant with
      disposable state.
- [ ] **Authentication sequence:** declared login/reset/session workflow →
      sequence invariant.
- [ ] **Rate limit/reset token/race/TOCTOU:** purpose-built workflow profiles with
      explicit mutation authorization and strict request/concurrency ceilings.

For each class:

- [ ] Reuse the existing validator already dispatched in
      `orchestrator_chain.py::_confirm`.
- [ ] Confirm that `shape_precondition_legs` supplies the real prerequisite
      shape; add the narrowest missing predicate.
- [ ] Add a bounded/quick mode only when it has a sound class-specific oracle.
- [ ] Set `confirmed` only from executed evidence.
- [ ] Persist proof and execution ledger records through
      `_persist_confirmation_proof`.
- [ ] Stop the class-scoped run after confirmation.
- [ ] Do not stop a broad engagement from testing unrelated classes.

## Batch 6 — external objective benchmark lifecycle

- [ ] Extend `testing/web-objective-benchmark/manifest.json` with explicit
      objective profile, target source, oracle type, request budget, wall-time
      budget, required repetitions and fixed-control pairing.
- [ ] Add a target lifecycle adapter that records “fresh unsolved” before a run.
- [ ] Keep the target completion oracle outside model and validator output.
- [ ] Prevent reuse of solved/dirty target instances in formal scoring.
- [ ] Prevent browser/user interaction during a formal attempt, or mark the
      attempt contaminated and ineligible.
- [ ] Use a fresh state DB and cache for every repetition.
- [ ] Record checkout, dirty state, config hash, model/provider, dependencies,
      request count, duration, proof IDs, oracle result and error taxonomy.
- [ ] Run vulnerable and fixed controls from the same checkout/config.
- [ ] Require three clean autonomous repetitions per positive case.
- [ ] Require zero false confirmations on fixed controls.
- [ ] Make missing repetitions, controls or oracles ineligible rather than zero
      or silently omitted.

Acceptance:

- [ ] The scorer rejects pre-solved, contaminated, degraded or incomplete runs.
- [ ] Repeating a run with a warm cache is rejected or clearly separated.
- [ ] One command produces the attempt artifact, oracle record and score input.
- [ ] Artifact JSON validates against a versioned schema.

Start with:

- `testing/run_web_objective_smoke.py`
- `testing/web_objective_benchmark.py`
- `testing/test_web_objective_benchmark.py`
- `testing/web-objective-benchmark/README.md`
- `testing/web-objective-benchmark/manifest.json`

## Batch 7 — production and Burp integration

- [ ] Thread `objective_class`/profile and bounded budgets through the server job
      API without changing passive defaults.
- [ ] Surface current phase, requests used, errors and proof IDs in job status.
- [ ] Ensure cancellation reaches discovery, validator, browser and subprocess
      work.
- [ ] Expose “confirmed,” “tested negative,” “inconclusive,” and “error” distinctly
      in the Burp UI.
- [ ] Keep raw credentials out of API responses and logs.
- [ ] Build the Java extension with `gradle shadowJar` and a JDK before claiming
      UI verification.

Start with:

- `harness/server.py`
- `harness/test_server.py`
- `burp-extension/`

## Required tests for every implementation batch

- [ ] Shape/helper unit test.
- [ ] Validator positive test using executed evidence.
- [ ] Fixed negative control.
- [ ] Infrastructure-error control.
- [ ] Caller-level test proving production wiring and ordering.
- [ ] Scope and request-budget assertions.
- [ ] Proof/ledger persistence assertion for confirmed behavior.
- [ ] Defect-injection control that fails when the new wiring is removed.
- [ ] No test merely restates the implementation through mocks.

Run focused tests first, then:

```powershell
python -m harness.suite smoke
python -m harness.suite full
python -m unittest harness.test_orchestrator_precondition
```

Record commands, counts, skips and limitations in `CURRENT_STATE.md`. A green
offline suite does not establish model accuracy or blind-target recall.

## Definition of done for the overall port

- [ ] Every manifest objective maps to a registered objective profile.
- [ ] Every profile has vulnerable, fixed and infrastructure-error controls.
- [ ] Captured request semantics and principal identity survive to the validator.
- [ ] Every confirmation has a reconstructable proof and execution record.
- [ ] No infrastructure error is scored as a negative.
- [ ] Every formal case has three clean repetitions and its external oracle.
- [ ] All fixed controls have zero false confirmations.
- [ ] The full benchmark runs from one checkout/config with fresh state.
- [ ] `python -m harness.suite full` passes after the final change.
- [ ] The coverage manifest accurately reflects the new caller-level evidence.
- [ ] Only after all items above pass may results be compared with XBOW 104 or
      described as a candidate perfect score.
