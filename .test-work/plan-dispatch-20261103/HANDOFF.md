# Plan dispatch and coverage yield — handoff (2026-11-03)

Branch `claude/friendly-varahamihira-7c68f3`, base `bae5321`. Input: the 8h Juice
Shop run's `YIELD_ANALYSIS.md` (i16-persist worktree, `.test-work/juice-shop-8h-20261103/`).
That run had 2 confirmed findings from 47.7k requests. Run DB read only, through `q.py` (sqlite `mode=ro`).

## What was found

1. **Planner plans were never executed or reconciled.** `planner.plans_for_findings` makes
   plans named by capability. Most of them have `execution_plane="burp"`. Only the Burp
   extension reads them back. The harness validators run under their own plan ids, or with
   none (browser_xss has no plan). So all 62 `proposed` plans were planner plans, and they
   stayed proposed even where the matching validator had already run. The 7 planner sqlmap
   plans are an example: their id is `sql_injection_validation:…`, but sqlmap records under
   `sqlmap:{class}:{fp}`.
2. **Iterative-agent candidates were never reviewed.** `run_active_probe` → `pivot_memory.integrate`
   persisted the findings and plans with no validation and no confirmation gate. The
   `INSERT OR IGNORE` meant a later confirmation could never update those rows. Also,
   `"Authentication Bypass / SQL Injection"` does not canonicalize, so findings 8 and 9 got no plan at all.
3. **The worklist precondition budget was used up by nodes that warranted nothing.**
   `investigate_worklist` counted a leg for every node, whether or not its shape warranted a
   leg. The 24 legs were gone after the first 24 nodes, and later nodes were skipped under the
   misleading labels `no_applicable_hypothesis` / `missing_template`. This is the run's
   "172 skipped (of 40 eligible)". Also, `_derive_probe` only knew `idor` / `auth`.
   Write endpoints from the SPA's JS call shapes were probed by role_crawl with
   `_synthesize_body`. But only a substantive 2xx response became a capture. A write that
   answered 4xx to that probe therefore had no template, warranted no leg, and was never analysed.
4. **Reflected parameters never reached browser_xss.** Shape legs did add an `xss` hypothesis
   for every injectable parameter. But `analyze()` prunes shape-leg findings unless they are
   confirmed, so no xss plan or validator run came from a reflected `q`.

## What was fixed

- `harness/plan_dispatch.py` (new). It maps capabilities to validators. `dispatch_plans` works
  through an exchange's plans in priority order (severity, escalation, confidence,
  can-confirm). For each plan it does one of four things:
  - **binds** an existing validator result of the same class and validator;
  - **dispatches** the plan to its validator(s) through the normal `_validate_findings`
    (scope, safety gate, mutating ceilings and proofs all apply unchanged);
  - **defers** it once the cap (default 6, optional `validators.plan_dispatch_max`) is reached
    or the run budget is spent; the plan stays `proposed`;
  - marks it **`not_dispatchable`** with a reason (no local validator, active mode off, or the
    validator declined).

  `injection_followups` turns an injection class named only in the finding's free text into
  one derived finding per request parameter (capped at confidence 0.35).
- `store.py`: new `dispatch_note` column (migration), plus `record_plan_dispatch` (binds only a
  `proposed` plan and follows `capability_can_confirm`), `mark_plan_not_dispatchable` and
  `plan_dispatch_notes`.
- `orchestrator_confirm.py` / `orchestrator.py`: `_validate_findings(only_validators=…)`.
  `run_active_probe` now passes a review hook into `pivot_memory.integrate`.
  `_review_iterative_findings` dispatches the plans, validates the unplanned findings, stamps
  each finding's case, and runs `apply_confirmation_suppression` before the findings are persisted.
- `pivot_memory.integrate(review=…)` runs in this order: follow-ups → plans → persist the
  plans → review → persist the findings. A failing review never drops the findings.
- `orchestrator_detect.py`: after `persist_test_plans`, `dispatch_plans(validated=True)` binds
  or explains each plan, and never re-sends. `reflected_parameter_findings` (passive, in
  `orchestrator_helpers.py`) adds an xss hypothesis per query parameter whose value (3+
  characters) is echoed in the response. It goes in as a non-pruned `reflection_detector`
  report, and it replaces the shape xss legs when present.
- `worklist_investigator.py`:
  - only a node whose shape warrants a leg spends the precondition budget, via
    `precondition_fn.warranted`, set in `orchestrator_chain._precondition`;
  - a warranted node past the budget is reported as `budget_exhausted`;
  - a write node with no capture takes its own access-matrix probe body as its template
    (`template_source="access_matrix"`); nothing new is sent;
  - `_derive_probe` gives write nodes that have a body an `injection` specialty.

  The mutating sends are still gated by `allow_mutating_replay` and the safety gate.
- Config defaults are unchanged.

## Tests

`harness/test_plan_dispatch.py`, 25 tests, each with a negative control:
- store: bind and no-overwrite;
- bind, dispatch, explain, cap/defer, budget, priority;
- prose SQLi on the login body → sqli follow-ups for `email` and `password` → a `sql_injection_validation` plan;
- the review hook's ordering and the failure path;
- reflected `q` → a reflection plan;
- the worklist budget, with a negative control: the fix patched out makes the test fail;
- write-node templates.

Gates are listed in `py312.status` and `py314.status`.

## Not verified

- No live run. Effects on Juice Shop yield are expected, not measured.
- `_review_iterative_findings` and the `orchestrator_detect` dispatch call are covered only
  through their callees (`dispatch_plans` and `integrate`). There is no end-to-end
  orchestrator test.

## Owner questions

1. Is `plan_dispatch_max` = 6 per exchange the right default? It is code-only, and config.yaml is untouched.
2. Feature crawl's `submit_forms` follows `allow_mutating_replay`. "0 forms submitted" is
   probably because it was off in that run. Check the run's `effective-config.json`.
   Should a passive run submit safe forms at all?
3. `not_dispatchable` is a new plan status. Should the reports and coverage ledger treat it
   as "explained, not run", or keep showing such plans as outstanding for the Burp plane?
4. On worklist nodes, `confirm_fn` can validate an iterative finding again after the review
   hook has done so. It is idempotent, but it costs requests. Is that acceptable, or should
   the worklist skip findings that already carry a case?
5. The reflection detector echoes JSON-API values too. On a search API, the value matching
   product names is not real reflection. A browser check decides, and it costs at most
   `max_visits` (8). Should it be limited to HTML responses?
6. Write nodes now become eligible for the agent (`injection`), so they compete for `max_nodes`.
   Should they get their own budget instead?
