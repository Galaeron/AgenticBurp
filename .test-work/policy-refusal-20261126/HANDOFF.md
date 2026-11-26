# Policy-refusal framing — handoff (2026-11-26)

Brief: `.test-work/policy-refusal-20261126/BATCH.md` (on main; not copied into this branch).
Offline only: no Juice Shop, Ollama or Docker here. No live-run or model-behaviour claim is made.

## What changed

### 1. `harness/policy_refusal.py` (new)
- `MARKER = "HARNESS POLICY REFUSAL"`, categories `scope`, `safety_gate`, `budget`, `duplicate`,
  `rejected_proposal`, `session`, `route_paused`, `cancelled`, `mechanism`.
- `frame(category, reason)`: the model-facing line. It says the harness refused the action before
  anything was sent, that it is not a target response / error page / WAF block / rate limit, not to
  retry it or a re-encoded or varied form, what to do instead (per category), and ends with
  `Harness reason: <raw reason>`. Wording is this project's own; nothing was copied from ARTEX.
- `short(category, reason)`: the compact form for PRIOR ATTEMPTS lines.
- `category_for_outcome(outcome)`: maps the transport's unsent outcomes
  (`out_of_scope`, `blocked`, `budget_exhausted`, `session_expired`, `unknown_session`,
  `route_unavailable`, `cancelled`) to a category. `error` (a send that failed in transit) and
  `ok` (any HTTP status, 403/429/WAF included) map to nothing.

### 2. `harness/iterative_agent.py`
- `_execute` still returns the same raw `(None, reason)` texts; it now also sets
  `self._last_refusal` from the transport outcome (not by parsing text). `_run_loop` resets it before
  each call, so a test that replaces `_execute` frames nothing.
- Model-facing history lines framed: transport refusals (scope, gate, budget, session, route pause,
  cancel), the duplicate rejection, both `action rejected:` paths (build error, no-op reset), and the
  experiment handoff's own refusals (`rejected`, `needs_prerequisite` -> `mechanism`; `reused` ->
  `duplicate`). A completed/inconclusive mechanism result is not framed.
- PRIOR ATTEMPTS line: `AttemptRecord` gets `policy: str = ""`; only `line()` renders the marker,
  `outcome` stays raw (so a duplicate's citation of an earlier outcome is unchanged).
- System prompt: one new rule naming the marker and saying a target 403/429/WAF is shown as
  `HTTP <status>` and is evidence.
- Unchanged (raw): `IterativeStep.blocked` / `to_dict()["transcript"]`, `handoff_note`,
  `stop_reason`, all existing counters, log lines, distress accounting (still keys on the raw
  `request failed` prefix). The probe does not write the ledger itself.
- Requirement 5 (optional, done): `diagnostics["policy_refusal_repeats"]`, the number of harness
  refusals of a category this probe had already been refused for (counts only). It is not added to
  `worklist_investigator.DIAGNOSTIC_COUNTS`, so run-level totals do not sum it yet.
- Not framed: the parse-error line (`output was not a JSON action object; try again.`) — it is about
  the model's output format, not an action, and "do not retry" would be wrong for it.

### 3. Tests
- New `harness/test_policy_refusal_framing.py` (13 tests), caller-level through `IterativeAgent.run`
  with a recording fake model, the real TargetTransport, network patched at `httpx.AsyncClient.request`:
  scope, gate (default gate refuses POST), budget (`max_requests=0`), duplicate, rejected proposal,
  mechanism refusal (+ completed one as control), system prompt; negative controls: target 403, 429
  and a 406 WAF page are `HTTP <status>` with no marker anywhere, a transport `ConnectError` is not
  framed; raw-values tests run the same script with `frame`/`short` patched to identity and assert
  `to_dict()` (stop reason, counters, transcript) is identical, the prompts differ, and no log line
  carries the marker; repeat counter and its control.
- Updated assertions (old refusal text in the prompt, now framed; the raw reason is still asserted):
  `harness/test_iterative_agent.py` (3 duplicate tests), `harness/test_iterative_typed_actions.py`
  (2 rejected-action tests).

## Other LLM loops checked (requirement 4)
- `iterative_agent.py` — the only loop that feeds harness refusals back to a model. Changed.
  `worklist_investigator.py` and `orchestrator_confirm.run_active_probe` drive it, so they inherit it.
  The experiment handoff (`orchestrator_chain.py` ~:837-924) returns its refusals into this loop;
  framed at the loop, `orchestrator_chain.py` itself unchanged.
- `active_verification.py` escalation (`payload_library.llm_fallback_prompt`): failure notes are
  `"<status>: <mutation note>"` from Burp-plane submissions; status `blocked` there is reported by
  the Burp side and may be a target block or an operator/Burp decision, so it is NOT framed (framing a
  possibly real WAF block as policy would break requirement 3). Open question below.
- One-shot calls with no refusal feedback, not changed: `coordinator.py` (routing/re-spin),
  `experiment_planner.py`, `self_ownership.py`, `objective_completion.py`, `allocation_prioritizer.py`,
  `surface_prioritizer.py`, `agents/base_agent.py` / `agent_families.py` (passive), `writeups.py`,
  `orchestrator_detect.py`.

## Verification (this worktree, /home/user/.venv-agb Python 3.13, PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers)
- `python -m harness.suite smoke`: exit 0, 182 tests OK.
- `python -m unittest harness.test_orchestrator_precondition`: exit 0, 74 tests OK.
- `python -m unittest <the 67 harness/test_*.py modules that mention iterative_agent /
  IterativeAgent / run_active_probe> harness.test_policy_refusal_framing harness.test_pipeline_gate`
  (module list: `grep -rl "iterative_agent\|IterativeAgent\|run_active_probe" harness/test_*.py`;
  includes all `test_iterative_*`, `test_worklist_*`, `test_prompt_budget`): exit 0,
  1165 tests OK, no skips, 1341 s.
- `python -m unittest harness.test_policy_refusal_framing`: 13 OK (the gate test ran, not skipped).
- Before the assertion updates the iterative modules failed 5 tests (the 5 updated ones), as expected.
- Full suite not run (orchestrator runs it once after merging).

## Unverified / observations
- No model was run: whether a real model stops retrying variants after this framing is unmeasured.
- Pre-existing, not changed (stop reasons must stay): a `budget_exhausted`, `cancelled`,
  `route_unavailable` or `session_expired` refusal returns `request failed: ...`, which the loop
  counts toward `target_distress` like a real transport failure (`text.startswith("request failed")`).
  With `_MAX_CONSECUTIVE_TROUBLE = 3`, three such refusals in a row end a probe as `target_distress`
  (before the `no_progress` check) though the target was never contacted.
- The full suite was not run here (orchestrator runs it after merging).

## Next steps / open questions
- Owner: should Burp-plane `blocked` submissions (active_verification) be split into
  harness-blocked vs target-blocked so the escalation prompt can frame the former?
- Owner: should harness refusals stop counting as target distress (changes stop reasons)?
- Add `policy_refusal_repeats` to `worklist_investigator.DIAGNOSTIC_COUNTS` if run totals want it.
