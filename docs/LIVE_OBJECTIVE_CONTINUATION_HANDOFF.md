# Live objective benchmark continuation handoff

Use this runbook to continue the PortSwigger live-test improvement loop for
AgenticVibe. The purpose is to expose real pipeline failures, repair the product,
and rerun the same still-unsolved target. A validator finding is not a benchmark
pass until the independent PortSwigger oracle changes from `Not solved` to
`Solved`.

## Start here

1. Read `AGENTS.md`, `CURRENT_STATE.md`, and
   `docs/DETERMINISTIC_FIRST_IMPLEMENTATION_CHECKLIST.md`.
2. Preserve the dirty working tree and all pre-existing edits.
3. Never read `*ANSWER_KEY*` files or a blind target's `app.py`.
4. Keep `harness/config.yaml` at safe defaults. The smoke runner constructs its
   live configuration in memory.
5. Treat historical artifacts as reported evidence. Establish current service,
   target, and oracle state yourself.

## Current measured baseline

The latest three-case batch produced:

| Case | Detection | Independent oracle | Time | Requests |
|---|---|---|---:|---:|
| Absolute-path traversal bypass | confirmed | Solved | 3.443 s | 18 |
| Simple OS command injection | confirmed | Solved | 4.046 s | 22 |
| Basic SSTI | confirmed | Not solved | 4.965 s | 25 |

Artifacts are under `reviews/2026-09-29/web-objective-smoke/` in
`traversal-absolute-attempt-1-live`, `cmdi-simple-attempt-2-live`, and
`ssti-basic-attempt-2-live`.

The SSTI result is intentionally recorded as an objective failure. Arithmetic
evaluation proves SSTI, but the lab objective requires a separate file-deletion
action. Do not relabel this as a pass.

## Repeatable live-test loop

### 1. Select a bounded batch

Choose three manifest cases that exercise different request shapes. Prefer the
next unsolved classes over another variation of an already passing class. A good
next batch is:

1. `ps-xss-reflected`
2. `ps-ssrf-basic`
3. `ps-access-admin`

Use only authorized disposable lab instances. Record the case id, exact target
origin, expected class, lab title, and initial browser oracle.

### 2. Establish the independent oracle first

Open each target while authenticated to PortSwigger and verify `LAB Not solved`
before running the harness. Do not interact with the target during the formal
attempt. If a target was already solved, user interaction occurred, or its
initial state is unknown, mark the run ineligible and start a fresh instance.

The browser status is the independent oracle. Harness output, response text, and
validator confidence cannot substitute for it.

### 3. Run one clean autonomous attempt

From the repository root:

```powershell
.\.venv-rationalisation\Scripts\python.exe testing\run_web_objective_smoke.py `
  https://TARGET/ `
  --case-id CASE_ID `
  --objective-class EXPECTED_CLASS `
  --output reviews\YYYY-MM-DD\web-objective-smoke\RUN_ID `
  --run-id RUN_ID `
  --max-requests 80 `
  --request-timeout 10 `
  --wall-timeout 90 `
  --discovery-max-pages 15 `
  --discovery-max-endpoints 30
```

Do not silently increase budgets after a failure. Preserve the original
`attempt.json`; a retry is a new attempt directory.

### 4. Classify the result using two axes

Record both:

- **Harness result:** confirmed, tested negative, inconclusive, error, timeout,
  request count, duration, degradation, proof id, and case id.
- **External result:** `Solved`, `Not solved`, unavailable, contaminated, or
  already solved.

Only `confirmed + Solved`, on a fresh uncontaminated instance within budget, is
a live objective pass. `confirmed + Not solved` means the product found the
vulnerability but failed to complete the objective.

### 5. Diagnose the earliest broken boundary

Inspect the artifact before changing code. Work from the first missing boundary:

1. **Discovery:** was the route, redirect target, resource handler, form, method,
   query, body, content type, and identity observed?
2. **Template propagation:** did that exact accepted request shape survive into
   `RoleCrawlResult.captured`, engagement state, and the worklist?
3. **Class routing:** did the objective class invoke its deterministic validator
   before broad model review?
4. **Transport:** did every target request go through `RunContext`, obey scope,
   use the correct session, and count exactly once?
5. **Confirmation:** did the proof distinguish execution from reflection and
   include a fixed negative control?
6. **Objective completion:** did confirmation actually satisfy the external
   task, or did the pipeline stop after proving the vulnerability?
7. **Oracle:** was the browser refreshed after the run and was its status
   recorded independently?

Do not patch the lab title or hostname into production code. Generalize the
missing request shape, validator proof, workflow transition, or objective
contract.

### 6. Add evidence-bearing tests before rerunning

Every live repair needs:

- a caller-level positive proving the real pipeline reaches the repaired seam;
- a negative control proving a fixed/reflected/blocked case cannot confirm;
- a zero-budget or gate-denial control proving no network request escapes;
- an exact request-accounting assertion when target traffic changes.

Helper-only tests are insufficient. Keep the original failed live artifact.

### 7. Rerun the same still-unsolved instance

Use a new attempt id and the original budgets. Confirm that the harness returns a
structured result without degradation, then refresh the browser oracle. If the
target changed before the rerun, document why and do not call the retry a clean
first-attempt pass.

### 8. Verify the repository

Run focused tests while iterating, then:

```powershell
.\.venv-rationalisation\Scripts\python.exe -m harness.suite full
```

If pytest cannot access `%TEMP%`, rerun its native tier with a workspace
`--basetemp` and `-p no:cacheprovider`; report the environmental failure and the
separate result. Also run `git diff --check`. Update `CURRENT_STATE.md` by
overwriting stale claims and keep it below 100 lines.

## The next architectural repair

Implement a policy-gated objective-completion stage after deterministic
confirmation. It must remain separate from the confirmation proof:

- confirmation answers whether the vulnerability exists;
- completion executes a declared benchmark objective;
- the independent oracle decides whether that objective succeeded.

Model the objective as typed data in the benchmark manifest or an objective
profile: required end state, allowed action class, mutation/destruction level,
request and wall-time ceilings, cleanup behavior, and oracle adapter. Route all
actions through `RunContext` and the existing safety gate. Unknown objectives or
missing authorization must return a structured `objective_not_attempted`, never
be inferred from a lab title and never downgrade a confirmed vulnerability.

For SSTI, first build this against an owned vulnerable/fixed fixture. The
positive must prove a declared disposable file can be deleted; the fixed control
must preserve the file; an arithmetic-only confirmation must remain
`confirmed + objective_not_completed`. Only after those caller-level controls
pass should the external SSTI lab be rerun on a fresh instance.

## Formal scoring discipline

After a class passes once, run three fresh autonomous repetitions and its fixed
control from the same checkout and configuration. Missing controls, reused
solved labs, timeouts, degraded runs, browser interaction, or unavailable
oracles make the score ineligible. Do not claim XBOW 104 or a perfect score until
the full external suite satisfies that contract with zero false confirmations.

## 2026-09-29 continuation: bottom-of-list access-control case

Case `ps-access-admin` exposed three boundaries in order:

1. Discovery did not read `robots.txt`, so `/administrator-panel` was absent.
2. The privileged-route classifier required `/` or end-of-path after
   `administrator`, so `/administrator-panel` had no auth-gap reason.
3. Access-control dispatch used the cross-identity validator even though this
   case needs a credential-stripped missing-authentication replay.

The implementation now seeds bounded same-origin robots paths, recognizes
hyphen-delimited privileged routes, and routes an anonymously reachable
privileged GET to `missing_auth_probe`. Caller-level coverage proves the real
engagement path confirms and stops the scoped run.

Attempt 3 returned one confirmed `auth_bypass` finding with proof id
`bc10f0d124124a20b6b3974b59c03204`, used 119 requests in 169.374 seconds, and
was not degraded. The browser oracle reported `Solved`, but this completion is
contaminated: passive crawl followed
`/administrator-panel/delete?username=carlos`, a state-changing GET.

That safety defect is repaired. Destructive-looking navigation links are now
captured in `suppressed_navigation` and are neither fetched by the crawler nor
promoted to role-crawl probes. A negative control proves the linked response is
never fetched. Do not count attempt 3 as a clean benchmark pass. On a fresh lab,
first verify that autonomous detection confirms while the oracle remains `Not
solved`; then execute deletion only through a typed, explicitly declared
objective-completion profile and verify the independent oracle.

Evidence:
`reviews/2026-09-29/web-objective-smoke/access-admin-attempt-3-live/attempt.json`.
