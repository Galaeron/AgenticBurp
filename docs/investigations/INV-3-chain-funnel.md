# INV-3 — Chain candidate-to-report funnel

- **Item:** INV-3 (`docs/INVESTIGATION_DISPATCH_2026-09-20.md`)
- **Date:** 2026-09-21
- **HEAD at time of writing:** `9cbb70b6338b6851a8696732881cb5f860c92f7f`
- **Branch:** `reconciliation-backlog`
- **Tracked/untracked status at start:** `git status --short` showed no tracked
  modifications and only pre-existing untracked paths (`.agents/`, `.claude/`,
  `.test-deps/`, `.worktrees/`, several `reviews/2026-09-*` directories,
  `testing/blind-target-2/*`, `testing/blind-test-kit/target/invoices/`,
  `testing/juiceshop-full-run/`, `testing/test-target/*`,
  `testing/vulncorp-helpdesk/`, `harness/*.db.bak-pre-step5*`,
  `docs/EVALUATION_REASSESSMENT_2026-09-20.md`,
  `docs/INVESTIGATION_DISPATCH_2026-09-20.md`, `review_test_output.txt`) —
  nothing in that list was created or modified by this item except the new
  file this document names.
- **This is offline, read-only diagnosis.** No production code was changed, no
  scorer/driver was executed, no live model/Docker/blind run occurred. The
  only commands run were `git`, read-only Python `json.load()` reads of
  already-completed run artifacts, and read-only `sqlite3.connect(...,
  uri=True)` queries (`mode=ro`) against an already-completed run's own state
  database.
- Depends on INV-1 (`docs/investigations/INV-1-baseline.md`, closed at
  `c1133d5`) and INV-2 (`docs/investigations/INV-2-proof-gap.md`, closed at
  `40104a9`). This item reuses INV-1's revision table (the VulnCorp maxrun
  artifacts are from `.worktrees/integration-measure` @ `eb70210`, a different
  revision than current HEAD) and INV-2's finding that PASS2 graph findings
  are never persisted to `store.findings` — both are load-bearing for §3.

## Evidence-tag legend

- **VERIFIED-by-inspection** — read directly from source/config/artifact in
  this checkout at the stated revision; no code executed to obtain it.
- **VERIFIED-in-run** — read directly from an on-disk artifact produced by an
  actual completed run (not re-executed here), including ad hoc read-only
  Python/SQL queries against that run's own JSON/SQLite files.
- **SUPPORTED** — a reasonable inference from two or more inspected sources,
  not independently executed or artifact-confirmed.
- **INFERRED** — a plausible read with a named gap; flagged for the reviewer,
  not asserted as fact.
- **UNKNOWN** — not determinable from available, permitted material; stated as
  an explicit limitation, never guessed.

Safety note: this item never opened `vulncorp_ground_truth.py`, any
`*ANSWER_KEY*` file, or any blind target's `app.py`. All VulnCorp-side
evidence below is read from harness-generated run artifacts already treated
as inspectable by INV-1/INV-2 (`testing/vulncorp-helpdesk/maxrun/*.json`, the
run's own SQLite state DB opened `mode=ro`) and from
`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`, a driver script,
not a target implementation or an answer key.

---

## 1. Invocation and flag map: API/driver → final report

### 1.1 Two structurally distinct chain-detection code paths exist

The dispatch's own entry-point list (`orchestrator_chain.py`,
`engagement_builder.py`, `worklist_investigator.py`, `chain_linker.py`,
`chaining.py`) names the **graph-driven (PASS2) path**. There is a second,
**not named in the dispatch**, "similarly named but not the same pipeline"
path that also calls `chaining.detect()`:

| | PASS1 per-exchange chain path | PASS2 graph-driven chain path (dispatch's named target) |
|---|---|---|
| Symbol | `orchestrator_detect.py:736-772` (inline in the per-exchange `analyze()` flow, no separate function name) | `chain_linker.link_findings()` (`chain_linker.py:94-128`), called from `orchestrator_chain.py::investigate_engagement` |
| Trigger | Every `orchestrator.analyze(exchange)` call, after that exchange's own findings are persisted | `investigate_engagement()` calls it once after the initial worklist sweep, then again after each credential-derived re-crawl round (`orchestrator_chain.py:657-658`, `:687-688`) |
| Input set | `store.all_host_findings(exchange.url)` — the **persisted, cross-exchange, cross-call** finding history for the whole host, re-read fresh every call (`orchestrator_detect.py:739`) | `all_findings` — an **in-process Python list**, local to one `investigate_engagement()` call, seeded only by that call's own worklist/precondition/credential-round outputs (`orchestrator_chain.py:632`, `:680`) |
| Dedup | `store.is_chain_already_detected` / `store.mark_chain_detected` (`orchestrator_detect.py:748-760`) — persisted, so a chain is reported once per host ever | None — `chain_findings` is recomputed from scratch on every call within one `investigate_engagement()` invocation; no cross-invocation persistence |
| Persistence | `store.persist_findings(..., "chain_detector", chain_findings)` (`orchestrator_detect.py:767-772`) — becomes a normal row in `store.findings`, agent=`"chain_detector"` | **None.** `chain_linker.link_findings` only writes graph *tasks* (`state.graph.add("chain", ...)`, `chain_linker.py:121`) and returns `chain_findings` as plain dicts; nothing calls `store.persist_findings` or any other durable store for these | 
| Report surface | `report_generator`/`export_issues_for_host` reads `store.all_host_findings`, so a PASS1 chain finding is visible there like any other finding (VERIFIED-by-inspection of the same code path INV-2 §1.1 traced) | The `investigate_engagement()` return dict's `"chains"` key (`orchestrator_chain.py:940`) is the **only** place these are surfaced; a caller that discards the job result (or, per §3, computes it from a stale snapshot) loses them entirely |

**Which path did the reported VulnCorp maxrun actually invoke? Both, and they
disagree — VERIFIED-in-run.** `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`
calls PASS1 `analyze()` first (populating `store.findings` including any
`chain_detector` rows), then PASS2 `investigate_engagement()` (`run_maxcov_integrated.py`,
per INV-1 §1's revision table). Reading the run's own artifacts read-only:

```python
# investigate.chains from maxcov_results_integrated_full.json -- VERIFIED-in-run
investigate["chains"] == []
investigate["chain_rounds"] == 2

# store.findings rows with agent='chain_detector' -- VERIFIED-in-run, read-only
# sqlite3.connect("file:...maxcov_state_integrated_full.db?mode=ro", uri=True)
SELECT vulnerability_class, COUNT(*) FROM findings
  WHERE agent = 'chain_detector' GROUP BY vulnerability_class;
# -> potential-attack-chain:idor+rate_limit        1
#    potential-attack-chain:second_order_idor       1
#    potential-attack-chain:second_order_sqli       1
#    potential-attack-chain:session_fixation+xss    1
#    potential-attack-chain:sqli+idor                1
```

So **the PASS1 path produced 5 chain findings for this exact run, including
`sqli+idor`** (VERIFIED-in-run, both queries above run against the same
artifact pair `maxcov_results_integrated_full.json` /
`maxcov_state_integrated_full.db`), while **the PASS2 path — the one the
dispatch names and the one the SCORECARD's "0 chains" figure (INV-1's
baseline table) actually measures — produced zero for the same run.** The
"0 chains" headline is therefore not "chaining found nothing this run"; it is
specifically "the graph-driven `investigate.chains` field was empty", and the
review gate's warning ("zero chains alone is not a regression diagnosis")
applies exactly here: a reader who only sees `investigate.chains == 0` would
wrongly conclude chain composition never fired at all on this host, when a
structurally separate pipeline did fire, with the identical `sqli+idor`
signature this document traces the PASS2 loss of below. §3 explains why
PASS2 could not have found the same pair even in principle.

### 1.2 PASS2's invocation and required flags, entry point to return

The dispatch's named entry point, traced end to end:

1. **API entry**: `POST /engagement/{host}/investigate` (`server.py:958-1033`,
   `InvestigateRequest`) — the only production HTTP route to
   `investigate_engagement` (its own comment at `server.py:930-936` notes this
   route did not exist before R18: "server.py exposed run/advance/crawl but
   NEVER invoked investigate_engagement"). Runs as a background asyncio job;
   `max_chain_rounds` is caller-supplied, clamped to `[0, 10]`
   (`server.py:1012`).
2. **Driver entry** (what actually produced the historical numbers):
   `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py` calls
   `orchestrator.investigate_engagement(...)` directly (bypassing `server.py`
   entirely — it is a Python driver, not an HTTP client), with
   `max_chain_rounds=3` for its "full" mode (`run_maxcov_integrated.py:335`)
   and `engagement.coverage_drive_legs: True` explicitly set in its in-memory
   config override (`run_maxcov_integrated.py:90-91`, VERIFIED-by-inspection,
   already cited in INV-1 §1's revision table). **This flag is the one that
   matters most for §3**: the shipped `harness/config.yaml` default is
   `coverage_drive_legs` absent, and `orchestrator.py:278` defaults it to
   `False` (`self.engagement_coverage_drive = bool(_eng_cfg.get("coverage_drive_legs", False))`) —
   so on a default-config server-driven run, the coverage-driven confirmation
   phase (§3) does not run at all, and the specific SQLi-confirmation gap
   traced below is dormant. It was live on the one run this item has an
   artifact for.
3. **Evidence-trust / capability-extraction / linking, inside
   `investigate_engagement`** (`orchestrator_chain.py:256-954`), in call
   order:
   - `engagement_builder.build_engagement` (`:274-276`) — active discovery +
     per-role access matrix -> `EngagementState`. Pure app-model assembly, no
     findings yet.
   - Content review, sensitive-file findings, optional feature crawl, header
     audit (`:289-344`) — additive, none produce chain-eligible findings by
     themselves except via later validator dispatch.
   - `worklist_investigator.investigate_worklist(..., confirm_fn=_confirm,
     precondition_fn=_precondition, ...)` (`:626-632`) — the iterative agent
     probe (deterministic `confirm_fn`/`precondition_fn` legs on top). This is
     where `all_findings` is first populated.
   - `chain_linker.link_findings(state, all_findings, responses=_responses)`
     (`:657`) — **first candidate/proposed-chain computation**, assigns
     `chains = list(link["chain_findings"])` (`:658`).
   - Credential closed loop (`:659-689`, bounded by `max_chain_rounds`): for
     each round with newly-verified derived credentials, re-crawl + re-
     investigate + **recompute** `link`/`chains` (`:687-688`).
   - Second-order auto-confirmation (`:691-813`, gated on
     `allow_mutating_replay`) — plant/trigger differential SQLi+IDOR
     confirmation over `chaining.second_order_candidates(all_findings)`;
     appends newly-confirmed findings to `all_findings`
     (`:770`, `:809`) and to `state` (`state.ingest_findings`), but **does
     not call `chain_linker.link_findings` again.**
   - Coverage-driven leg confirmation (`:837-928`, gated on
     `self.engagement_coverage_drive` / `self.engagement_coverage_case_drive`)
     — actively fires every applicable deterministic validator (including
     `sqlmap`, `_val_by_conf["sqlmap"] = self.validator_registry.validators.get("sqlmap")`,
     `:863-865`) against every coverage cell up to `coverage_leg_budget`;
     confirmed cells append to `all_findings` (`:905`) and to `state`. **Also
     does not call `chain_linker.link_findings` again.**
   - Return (`:930-954`): `"chains": chains` — the value assigned at whichever
     of the two link/relink sites above ran **last**, which per the ordering
     above is always **before** second-order auto-confirmation and coverage-
     driven confirmation, never after.
4. **Report surface**: the caller (server job result, or the maxrun driver's
   `_all_findings()`/`score_and_report`) reads `investigate["chains"]`
   directly (`server.py:1008-1017`; `run_maxcov_integrated.py:144-145,340-342`).
   Neither caller re-derives chains from the final `state`/`all_findings`; both
   trust the returned field as-is.

---

## 2. Stage funnel table

Counts are filled only from the one available allowed artifact pair
(`testing/vulncorp-helpdesk/maxrun/maxcov_results_integrated_full.json` +
`maxcov_state_integrated_full.db`, VERIFIED-in-run, revision `eb70210` per
INV-1 — **not current HEAD**, so these are historical/reported numbers for
this specific run, not proof of current-HEAD behavior beyond what §3's source
inspection independently establishes). Where a stage has no counter recorded
anywhere in the pipeline, it is UNKNOWN, not estimated.

| Stage | PASS2 graph path (`chain_linker`) | PASS1 per-exchange path (`orchestrator_detect`) |
|---|---|---|
| Input findings (into `_chain_input`/`chaining.detect`) | UNKNOWN exact count per call (no counter is logged/returned — `chain_linker.py:123-124` logs only `len(credential_caps)`/`len(chain_findings)`, not input size); SUPPORTED lower bound from the artifact: at least 45 idor-shaped findings existed in `outcomes[].findings_detail` **before** the first `link_findings` call fired (VERIFIED-in-run, counted from `investigate.outcomes`), and 0 sqli-shaped findings existed at that point (same count, same artifact) | `store.all_host_findings(exchange.url)` at persist-time — UNKNOWN exact per-call size (not logged); by the end of the run it included the 5 PASS1-confirmed `chain_detector` inputs' source findings plus every PASS1-persisted class |
| Eligible capabilities (findings with a resolvable tag, `_tags_for`) | UNKNOWN precise count (not instrumented); SUPPORTED that `idor` was eligible pre-coverage (45 idor-shaped outcomes) and `sqli` was **not** eligible pre-coverage (0 sqli-shaped outcomes; sqlmap is dispatched only in the coverage phase, §3.1) | UNKNOWN (not instrumented) |
| Candidate edges / proposed chains (`chaining.detect()` rule matches, pre-dedup) | **0** for this run — VERIFIED-in-run (`investigate.chains == []`; `chaining.detect` returns exactly what `link_findings` returns as `chain_findings`, no separate filtering stage exists between detect() and the return, `chain_linker.py:118-126`) | **≥5** — VERIFIED-in-run (5 distinct `potential-attack-chain:*` rows in `store.findings`, `agent='chain_detector'`); could be undercount if any repeat detections were suppressed by `is_chain_already_detected` dedup before persistence — dedup count itself is UNKNOWN (not separately logged) |
| Authorized attempts (a chain hypothesis is never itself actively tested — `chaining.detect()` output is always `basis="derived"`, `confidence ∈ {0.35, 0.5}`, explicitly "not a confirmed exploit path", `chaining.py:494-506`) | N/A — chains are not an execution-gated stage; there is no confirmation leg for a *chain* itself, only for its two input findings (already confirmed independently before the pair is composed) | N/A, same reason |
| Confirmed chains | N/A (chains have no separate CONFIRMED state; see above) | N/A |
| Reported chains (what a caller reading `investigate["chains"]` / `store.findings` actually sees) | **0** — VERIFIED-in-run | **5**, but **only if the caller reads `store.findings`/`store.all_host_findings` directly**; `run_maxcov_integrated.py`'s own `_all_findings()` union (`:144-145`) reads `investigate.get("chains", [])` for its "chains" count specifically, so **its own logged/reported "N chains" number for this run is 0**, not 5, even though 5 exist in the store the same run wrote to |

**Budget/scope gates checked and found not to be the limiting factor for this
run:** `max_chain_rounds=3` was not exhausted (`chain_rounds` recorded as `2`
in the artifact, VERIFIED-in-run — the credential loop converged, it did not
hit the round cap); `coverage_drive_legs` was explicitly `True`
(VERIFIED-by-inspection, `run_maxcov_integrated.py:90-91`) so the
coverage-driven SQLi leg (`WSTG-INPV-05`) did run and did confirm 1 case
(VERIFIED-in-run, `coverage.by_check["WSTG-INPV-05"] == {"confirmed": 1, ...}`).
The loss is not "the SQLi leg never ran" or "the budget was exhausted" — both
of those preconditions were satisfied. The loss is specifically that the
chain-composition stage never got to see the SQLi confirmation once it
existed (§3).

---

## 3. First demonstrated loss

### 3.1 Classification: dropped reporting via a stale input snapshot (not disabled, not budget-exhausted, not a rejected proposal)

Using the dispatch's own taxonomy (disabled/not-invoked vs. no-compatible-
evidence vs. rejected-proposal vs. exhausted-budget vs. failed-confirmation
vs. dropped-reporting):

**This is dropped-reporting**, with the specific mechanism being that the
value ultimately reported (`chains`, `orchestrator_chain.py:940`) is fixed by
whichever `chain_linker.link_findings()` call ran **last before** two later,
independent phases (second-order auto-confirmation, coverage-driven leg
confirmation) append new confirmed findings to the same `all_findings`
list/`state` that chain composition already read from. Neither later phase
re-invokes chain composition, so any chain whose second half is confirmed
**only** by one of those two later phases is composed, in principle, over a
findings set that includes it — but the composition that actually ran, and
whose result is returned, never had it. This is a **timing/ordering gap
within one `investigate_engagement()` call**, not a config toggle, not a
budget ceiling, and not a rule-matching failure.

**Why `sqli+idor` specifically failed, traced to source (SOURCE-SUPPORTED,
not merely INFERRED):**

1. `idor`-tagged findings were already present when the first (and every
   subsequent) `link_findings()` call ran, because access-control/IDOR
   confirmation is wired into `_confirm`'s dispatch table (`_is_access_control_class`
   branch, `orchestrator_chain.py:469-493`) — reachable from **both**
   `worklist_investigator`'s `confirm_fn` (agent-labelled findings) **and**
   `precondition_fn` → `shape_precondition_legs` (`orchestrator_helpers.py:428-429`,
   object-scoped GET → `("idor", exchange)`) — i.e., IDOR confirmation fires
   during the **first** phase of `_investigate()`, well before any
   `link_findings()` call.
2. `sqli`-tagged findings were **structurally impossible** to have at that
   point, because **no code path reachable before the coverage phase ever
   dispatches to the `sqlmap` validator**:
   - `_confirm`'s dispatch table (`orchestrator_chain.py:463-594`) has a
     branch for every other major class (access-control, xss/dom-xss,
     jwt, ssrf, xxe, command-injection, ssti, path-traversal, open-redirect,
     toctou, mass-assignment, deserialization, auth-sequence, rate-limit,
     reset-token) — **there is no `"sql"`/`"sqli"` branch at all**, checked by
     reading the full `if/elif` chain (VERIFIED-by-inspection, no `sqlmap`
     identifier anywhere in `_confirm`).
   - `shape_precondition_legs` (`orchestrator_helpers.py:403-453`) likewise
     dispatches idor/jwt/xxe/ssrf/command-injection/ssti/path-traversal/
     open-redirect/deserialization/mass-assignment by shape — **no sqli/sqlmap
     leg exists in this function either** (VERIFIED-by-inspection, full
     function body read).
   - The **only** place `_val_by_conf["sqlmap"]` is constructed and dispatched
     is inside the coverage-driven phase
     (`orchestrator_chain.py:863-865`, `_run_leg_core`), which is gated by
     `self.engagement_coverage_drive` (default `False`,
     `orchestrator.py:278`) and runs **after** every
     `chain_linker.link_findings()` call in the function.
3. Empirically, on the one run with an artifact: 45 idor-shaped findings
   existed in `outcomes` (pre-`link_findings`) and 0 sqli-shaped findings
   existed there (VERIFIED-in-run, §2 table); the coverage phase later
   confirmed exactly 1 `WSTG-INPV-05` (SQLi) cell (VERIFIED-in-run); the
   returned `chains` was computed before that cell existed, so `sqli+idor`
   could not fire even though **both halves existed by the time the run
   actually finished** — and, independently, a completely different
   pipeline (PASS1, §1.1) *did* compose the identical `sqli+idor` signature
   for this same run, using its own persisted-findings view, which had no
   such timing gap (it re-reads `store.all_host_findings` fresh on every
   call, so it saw both PASS1's own SQLi and IDOR findings together once
   both existed).

**This is not the only rule affected in principle** — any chain rule whose
one side requires a class that (a) has a coverage-phase-only validator (per
the same audit: `sqlmap` is the only such case among `_val_by_conf`'s
entries — `verb_tamper`, `csrf`, `file_upload` are also coverage-phase-only
additions, `orchestrator_chain.py:857-862`, but no chain rule currently keys
on those tags) or (b) is produced only by the second-order auto-confirm phase
(`second_order_sqli`/`second_order_idor` composed findings, `:749-810`) is
subject to the identical loss. `command_injection+known_vuln` and
`deserialization+known_vuln` are UNKNOWN-affected rather than confirmed-
affected here: `known_vuln` is not produced anywhere in the traced PASS2
call graph at all (UNKNOWN whether it is produced elsewhere in the codebase;
out of this item's traced scope), so those two rules were not checked further.

### 3.2 What is NOT the cause (ruled out, not merely unconsidered)

- **Not disabled/not-invoked**: `chain_linker.link_findings` was called 3
  times in this run (initial + 2 credential rounds, `chain_rounds: 2`
  VERIFIED-in-run) — the path is live.
- **Not no-compatible-evidence**: both `idor` and `sqli` tags existed by the
  time `investigate_engagement` returned; the evidence existed, just not at
  the moment chain composition read the list.
- **Not exhausted budget**: `max_chain_rounds=3` was not hit (2 rounds ran);
  `coverage_leg_budget` was not reported as exhausted for `WSTG-INPV-05`
  specifically (it shows `confirmed: 1`, not `skipped`).
- **Not a rejected proposal**: `chaining.detect()` never had the chance to
  propose `sqli+idor` for this run — there is no rejection, because the
  candidate-generation stage itself never received both required tags
  simultaneously.
- **Not a failed confirmation**: both underlying findings (the SQLi
  `WSTG-INPV-05` coverage cell and the IDOR cross-identity confirmations)
  independently confirmed successfully; the loss is entirely downstream of
  confirmation, at the composition/reporting boundary.

---

## 4. Synthetic owned-fixture caller-level test — SPEC (not implemented as code)

Per the dispatch's step 4, a SPEC is chosen over an executable test file:
reproducing this exact ordering bug faithfully requires driving
`investigate_engagement`'s full internal sequence (worklist investigation →
first `link_findings` → credential loop → second-order auto-confirm →
coverage-driven phase → return), which is currently all inlined as nested
closures inside one large method (`_confirm`, `_apply`, `_investigate`,
`_run_leg_core` are all local functions of `investigate_engagement`, not
independently importable) — extracting a fixture-testable seam would itself
be a structural code change, which this item is not authorized to make. The
SPEC below is precise enough that Ticket 1 (§5) can be implemented against it
directly, and its acceptance test (already scoped in Ticket 1) supersedes it
once written.

**Setup (offline, no network, deterministic):**
- A fixture `EngagementState` (`harness.engagement.EngagementState`) for a
  single fake host, pre-seeded (via `state.ingest_findings`) with exactly two
  findings before `investigate_engagement`'s internal accounting begins:
  - Step A: a `confirmed=True` finding with `vulnerability_class="idor"`
    (canonicalizes to tag `idor`), url `http://fixture/a`, `basis="derived"`.
  - Step B: **not yet present** — added only by a stand-in for the
    coverage-driven phase (see below), so the test exercises the exact
    ordering this document traces, not a same-batch case already covered by
    `test_chain_linker.py`.
- Monkeypatch (or stub, matching `worklist_investigator`'s existing
  `probe_fn` injection seam) so:
  1. The initial worklist sweep returns Step A's finding as already
     described above (deterministic, no model call).
  2. A stand-in "coverage phase" step runs **after** the point in the call
     sequence where `chain_linker.link_findings` is first invoked, and adds
     a second, `confirmed=True` finding with `vulnerability_class="sqli"`
     (tag `sqli`), url `http://fixture/b`, distinct from Step A's url.

**Positive-control assertion (documents current behavior — should currently
FAIL, i.e. demonstrate the bug, matching the dispatch's "proposals must not
masquerade as confirmations" instruction by asserting the CURRENT empty
result, not a hoped-for one):**
- `result["chains"]` is empty (`[]`) even though, by the time
  `investigate_engagement` returns, both a `sqli`-tagged and an
  `idor`-tagged confirmed finding exist somewhere reachable from `state`/the
  function's own final `all_findings` — i.e., calling
  `chain_linker.link_findings(state, final_all_findings)` **directly, after**
  the function returns, using the test's own reference to `final_all_findings`
  it captured, **would** produce a `sqli+idor` chain (assert this succeeds),
  proving the loss is timing, not tag-matching capability.
- This is the exact shape of Ticket 1's acceptance test (§5); this SPEC
  should be inverted (assert `result["chains"]` is non-empty and contains the
  `sqli+idor` signature) once Ticket 1 lands.

**Negative control 1 (different principal/scope — no confirmed chain should
result):** repeat the setup with Step B's finding using a **different**,
scope-disallowed host (`http://not-in-scope/b`, not in `allowed_hosts`) —
assert no chain composes even after Ticket 1 lands, because
`_chain_input`/`chaining.detect` still operate over whatever `all_findings`
actually contains, and a link-linking fix must not bypass scope; a
scope-invalid finding should never have been added to `all_findings` in the
first place (this control belongs to the scope gate, not to chain
composition, and should already pass with today's code — it documents that
Ticket 1 must not accidentally widen scope, not that it fixes anything new).

**Negative control 2 (active-disabled control — must send zero requests):**
with `self.engagement_coverage_drive = False` (the shipped default) and no
mutating-replay-gated second-order phase enabled, assert that
`investigate_engagement`'s SQLi-producing stand-in step (the coverage-phase
stub above) is never invoked at all — i.e., with the shipped default config,
the ordering bug is provably dormant (no `sqli` tag is ever producible via
this path, matching §3.1 point 2's structural claim), and the test's stub for
"the coverage phase" must show zero calls, not merely an empty findings
result (a stub that runs but confirms nothing is not the same claim as a
stub that never runs — the SPEC requires asserting the latter via a call
counter on the stand-in, to keep this control honest per the dispatch's
"active-disabled control must send zero requests" instruction, generalized
here from network requests to leg-dispatch calls since this SPEC is entirely
offline).

**Why a SPEC and not code, explicitly:** driving the real
`investigate_engagement` requires either (a) refactoring its internal
closures into independently callable module-level functions (out of this
item's no-refactor constraint) or (b) monkeypatching deep internals of a
~700-line method in a way that would be brittle and arguably itself a
plausible-but-unverified test rather than a faithful reproduction. The SPEC
above is precise enough to implement directly as Ticket 1's acceptance test,
where the refactor it needs (extracting a final relink step, §5) is already
being made for production reasons, not merely to enable the test.

---

## 5. Proposed fix / instrumentation ticket

### Ticket — Recompute `chain_linker.link_findings` once, after all confirmation phases, before `investigate_engagement` returns

- **Symbol:** `harness/orchestrator_chain.py::investigate_engagement`, the
  region between the coverage-build `try/except` block ending at `:928` and
  the `return` statement at `:930`.
- **Change:** add exactly one more call,
  `link = chain_linker.link_findings(state, all_findings, responses=_responses)`
  followed by `chains = list(link["chain_findings"])`, positioned **after**
  the coverage-driven phase (`:837-928`) and **after** the second-order
  auto-confirmation phase (`:691-813`) — i.e., immediately before the
  `return {...}` block, using the final, fully-updated `all_findings` and
  `_responses`. This is additive (one more deterministic, network-free call
  to an already-used pure function) and does not change any existing call
  site, gate, or default. `state.graph.add("chain", ...)` calls from earlier
  rounds are idempotent-per-signature at the graph level only in the sense
  that `chain_linker.py` does not itself dedup across calls within one
  `investigate_engagement()` invocation (unlike PASS1's persisted
  `is_chain_already_detected`/`mark_chain_detected`) — this ticket should
  either (a) accept that a chain signature detected in an earlier round and
  again in the final relink appears as a duplicate graph task (cosmetic, not
  a scoring impact since `chains` in the return dict is a plain `list`, not
  deduplicated against earlier `chain_findings` unless the caller dedups),
  or (b) add an in-function `seen_signatures` set before writing graph tasks
  in `link_findings`'s caller — reviewer's choice; flagged as an open
  sub-decision, not resolved unilaterally here.
- **Acceptance test:** the positive-control assertion in §4, made executable
  once this ticket's refactor gives the test a legitimate seam to call
  through (either the production code path itself, end-to-end with stub
  `probe_fn`/validators per the existing `test_smoke_investigate.py` pattern
  INV-2 cited, or by extracting the final-relink call into a small named
  helper `orchestrator_chain._finalize_chains(state, all_findings,
  responses)` that both `investigate_engagement` and the test call directly —
  recommended, since it also makes the fix trivially unit-testable without
  driving the whole method). Paired negative control: §4's negative control 1
  (scope-disallowed finding never contributes to a chain) must continue to
  pass unchanged.
- **Does not require BusinessContextAgent, does not change any default,
  does not touch `engagement.coverage_drive_legs`'s shipped-off default.**
  It changes what is *reported* about findings the pipeline already
  confirms; it confirms nothing new and authorizes no new network traffic
  beyond what the existing coverage/second-order phases already send (this
  ticket adds zero HTTP requests — `chain_linker.link_findings` is pure/
  network-free, per its own module docstring, `chain_linker.py:23`).
- **Relationship to INV-2's tickets:** independent. INV-2 Ticket 2 (persist
  PASS2 graph findings to `store.findings`) would, if implemented, also let
  PASS1's per-exchange chain path (§1.1) see PASS2's confirmations on a
  *later* `analyze()` call for the same host — but PASS2's own in-process
  `chains` field (what `investigate_engagement`'s direct callers, including
  the server job and the maxrun driver, actually read) would remain stale
  without this ticket regardless. The two tickets address different callers
  of the same underlying "PASS2 findings are invisible to other chain
  computations" defect family; landing one does not substitute for the
  other.
- **Not filed as part of this ticket, flagged only:** whether
  `command_injection+known_vuln`/`deserialization+known_vuln` are similarly
  affected is UNKNOWN (§3.1) — a follow-up read of wherever `known_vuln` tags
  are actually produced (not traced in this item; not one of the dispatch's
  named INV-3 entry points) would need to happen before claiming those two
  rules are or are not affected by the same mechanism.

---

## Limitations

- **No live execution occurred in this item.** All PASS2 code-path claims are
  from reading source at current HEAD (`9cbb70b6`); all VulnCorp-side numbers
  are from reading an already-completed run's on-disk artifacts (JSON dump +
  read-only SQL queries against that run's own SQLite file, opened
  `mode=ro`) — nothing was re-run, re-scored, or modified.
- **The VulnCorp maxrun artifacts are from a different revision** (`eb70210`,
  `.worktrees/integration-measure`, per INV-1) than current HEAD (`9cbb70b6`).
  The code-path analysis in §1 and §3 (which functions exist, their call
  order, their dispatch tables) is VERIFIED against **current HEAD**, not
  against `eb70210`; this item did not diff `orchestrator_chain.py`/
  `chain_linker.py`/`orchestrator_helpers.py` between the two revisions. That
  the mechanism traced in §3 also explains the *historical* "0 chains" number
  is SUPPORTED by the artifact evidence (the exact absence of any sqli-tagged
  finding before coverage, the exact presence of a `WSTG-INPV-05 confirmed:1`
  cell, and the PASS1 path's independent `sqli+idor` composition on the same
  run) but not independently re-run against `eb70210`'s own code — the two
  revisions could in principle differ in ways not checked here; flagged, not
  assumed identical.
- **Exact per-call input-set sizes into `chain_linker.link_findings` and
  `chaining.detect` are UNKNOWN** — neither function logs or returns its
  input-list length, only `credential_caps`/`chain_findings` counts
  (`chain_linker.py:123-124`). The §2 table's "≥45 idor / 0 sqli pre-coverage"
  figures are derived indirectly, from `investigate.outcomes` (a different,
  independently-available field in the same artifact), not from an
  instrumented count at the actual call site. A precise fix to this gap would
  need one added log line at `chain_linker.py:117-118` (input list length,
  by tag) — not added here (documentation-only item; would be a production
  change).
- **Whether `command_injection+known_vuln` / `deserialization+known_vuln` are
  affected by the same ordering gap is UNKNOWN**, not traced (§3.1, §5) — the
  `known_vuln` tag's producer(s) were not one of the dispatch's named INV-3
  entry points and were not searched for in this item.
- **`_coverage_proof`'s callers and whether coverage-confirmed findings ever
  acquire a `case_id`/`proof_id` before entering `all_findings`** was traced
  by INV-2 as a partially-open question (`_coverage_proof`, path A′); this
  item did not re-open that trace. It is orthogonal to the chain-composition
  timing gap documented here — §3's finding holds regardless of whether the
  coverage-confirmed SQLi finding carries a proof link, since the loss is
  about which findings `chain_linker.link_findings` was ever shown, not about
  whether those findings are themselves durable/proof-linked.
- **This item did not open `vulncorp_ground_truth.py`** or any blind
  target's `app.py`. All artifact reads used the same harness-generated
  reports and read-only SQLite access pattern INV-2 established as safe.
- **No production code was changed and no database was written.** All
  SQLite access in this item used `mode=ro` URI connections; the working
  tree's untracked-file list is unchanged from the state recorded at the top
  of this document except for the new file this item was asked to produce.

---

## Validation

- No executable code was added by this item (documentation only, per the
  dispatch's rule: "If you add NO executable code, say so and skip the
  suite" — skipped; `harness.suite smoke`/`full` were not run).
- `git diff --check` — run against the working tree; the new file is
  untracked until staged; also checked by reading the file back for literal
  whitespace-conflict markers (none present).
- Every local path/symbol cited above was confirmed to exist in this
  checkout via direct `Read`/`Grep` at the stated line numbers (current HEAD
  `9cbb70b6`), not assumed from memory or from the dispatch's own
  entry-point list.
