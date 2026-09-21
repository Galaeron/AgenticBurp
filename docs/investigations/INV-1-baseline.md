# INV-1 — Baseline reconciliation and comparison preparation

- **Item:** INV-1 (`docs/INVESTIGATION_DISPATCH_2026-09-20.md`)
- **Date:** 2026-09-21
- **HEAD at time of writing:** `c1133d5738388fbee77eed889e5faa1ecd0f532a`
- **Branch:** `reconciliation-backlog`
- **Tracked/untracked status at start:** working tree has one tracked modification
  (`IMPROVEMENT_BACKLOG.md`, pre-existing, not touched by this item) and a long list
  of pre-existing untracked paths (`.agents/`, `.claude/`, `.test-deps/`, `.worktrees/`,
  several `reviews/2026-09-*` directories, `testing/blind-target-2/*`,
  `testing/vulncorp-helpdesk/`, `harness/*.db.bak-pre-step5*`, etc.) — recorded via
  `git status --short` at both the start and end of this item; nothing in that list
  was created or modified by this item except the new file this document names.
- **This is offline, read-only diagnosis.** No production code was changed, no
  scorer/driver was executed, no live model/Docker/blind run occurred.

## Evidence-tag legend

- **VERIFIED-by-inspection** — read directly from source/config/artifact in this
  checkout at the stated revision; no code executed to obtain it.
- **VERIFIED-in-run** — captured from an actual completed run (a committed or
  on-disk artifact with a timestamp/manifest), not re-executed here.
- **SUPPORTED** — a reasonable inference from two or more inspected sources, not
  independently executed or artifact-confirmed.
- **INFERRED** — a plausible read with a named gap; flagged for the reviewer, not
  asserted as fact.
- **UNKNOWN** — not determinable from available, permitted material; stated as an
  explicit limitation, never guessed.

Every numbered claim below carries one of these tags plus a source reference.

---

## 1. Revision table for the three historical runs

| Run | Tested commit / diff | Corpus | Model | Fresh-gen vs cache-scoring | Operating threshold | Pipeline scope exercised | Artifact location + availability |
|---|---|---|---|---|---|---|---|
| **PixelMart agents fixture + scorer** | Base `249b799` (2026-09-19 18:17:42) **plus** the pre-existing uncommitted 5-file working diff (`harness/agent_manager.py`, `harness/agents/__init__.py`, `harness/agents/plugin.py`, `harness/ollama_client.py`, `harness/test_ollama_client.py`), sha256 of that diff recorded in `testing/SCORECARD.md` line 183-186 as `72ff7a40b0…20592b0fa`. — VERIFIED-by-inspection (`testing/SCORECARD.md:178-199`) | `test-target` (PixelMart), 11 labeled TP + TN exchanges (`testing/test-target/detection_fixture.py:49,65-67` reads `C:\tmp\pixelmart_exchanges.json`) | `qwen3:8b` (local Ollama) — `testing/SCORECARD.md:12`; `score.py` derives the label from `harness/config.yaml`'s `agent_defaults.model` at scoring time (`testing/score.py:216-222`), which is currently `qwen3:8b` (`harness/config.yaml:232` per grep below) | **Agent generation is fresh**: `detection_fixture.py build` force-refreshes every dispatched agent (`refresh=True` in `build()`, `detection_fixture.py:131`) — this is a live model run, not a cache replay, per the SCORECARD's own note ("force-refreshes every dispatched agent — this is a live run, not a cache replay", `testing/SCORECARD.md:207-209`). **Scoring is then a separate, later, cache read**: `score.py --from-cache` reads the JSON cache `detection_fixture.py` just wrote (`testing/score.py:173-213`, `CACHE_PATH` at `detection_fixture.py:52`) — no second model call. So "fresh-generation followed by cached scoring" (dispatch's own phrasing) is accurate: two distinct process invocations, generation live, scoring cached. | `--min-severity medium` (SCORECARD repro command, `testing/SCORECARD.md:9`); `--conf` defaults to `0.0` (no confidence gate) unless passed (`testing/score.py:299-300`) | Agents only: `detection_fixture.py` calls `agent.run(...)` directly (`detection_fixture.py:104,111`), explicitly disabling active validators, mutating replay and autonomous discovery in its own config copy (`detection_fixture.py:58-61`) and stating in its module docstring "NO validators, NO mutating replay, NO autonomous discovery ever fire" (`detection_fixture.py:23-26`). `score.py`'s `_collect_from_fixture` additionally re-applies the deterministic `access_control_gate` response-status suppression outside the pipeline as a scorer-side correction (`testing/score.py:190,196-210`) — this is scorer logic, not evidence the real orchestrator ran that gate. | `testing/test-target/fixture/detection_fixture.json` — **present on disk**, 125,282 bytes, mtime 2026-09-19 20:12 (matches the SCORECARD's stated fixture-build-finish timestamp 20:12:17, `testing/SCORECARD.md:194`). VERIFIED-in-run (file listing). Numbers (precision 0.423, recall 1.000, tp=11 fp=15 fn=0) are as reported in `testing/SCORECARD.md:220`. |
| **blind-target-2 full pipeline** | Same base as above: `249b799` + the same 5-file diff (SCORECARD states both runs shared that window, `testing/SCORECARD.md:178-199`) | `blind-target-2` (helpdesk app), 10 curated exchanges from `testing/blind-target-2/blind_eval_exchanges.json` (2 `confirmed_vuln`, 6 `confirmed_secure`, 2 `inconclusive` per the driver's own docstring, `run_blind_eval.py:10-12`) | `qwen3:8b` local Ollama, live (`run_blind_eval.py` docstring line 3: "runs … through the REAL orchestrator with live Ollama") | **Fully fresh**: fresh state+cache DBs are created per run (`run_blind_eval.py:28-31`, "no warm-cache reuse" per its own docstring), and every exchange goes through `orch.analyze(ex)` (`run_blind_eval.py:72`) — real agent dispatch + validators, not a cache replay. | Not severity/confidence-gated by the driver itself; it dumps raw `agent_reports`/`validation_reports` (`run_blind_eval.py:74-75`). The SCORECARD's reported numbers (`positives 2/2`, `medium+ findings 39` then `51`) apply a `medium+` filter at analysis/reporting time external to this raw JSON dump — VERIFIED-by-inspection that the driver itself does not filter; the SCORECARD's own severity floor is not reproducible from this script alone (see §2 below on missing manifest fields). | Full: `orch.analyze()` invokes the real orchestrator, which (per code inspected in §2) includes coordinator routing, agent dispatch, `_validate_findings` (validators + `_oracle_gate`), i.e. the "agents + validators + live Ollama" scope the SCORECARD claims (`testing/SCORECARD.md:120-122`). | `C:\tmp\blind_eval_results.json` — **present on disk**, mtime 2026-09-19 20:18 (matches the SCORECARD's stated internal timestamp 20:18:37, `testing/SCORECARD.md:195`). Inspected the manifest header only (this is harness-generated aggregate output, not target/app source): `timestamp="2026-09-19 20:18:37"`, but `config_fingerprint`, `fail_open_mode`, `quarantine_leads`, `fail_open_stats_before/final` are all `None` and `results` has 10 entries. VERIFIED-in-run for existence/timestamp; **the manifest fields the CURRENT `run_blind_eval.py` writes (config fingerprint, fail_open_mode, quarantine_leads, fail_open stats) are absent from this file**, which means it was produced by an EARLIER revision of the driver that predates those fields — i.e. it predates curated routing and quarantine (both are 2026-09-20+ additions per CURRENT_STATE.md). This is consistent with, and further confirms, the dispatch's statement that curated routing/quarantine came after this run. |
| **VulnCorp maxrun** | `.worktrees/integration-measure` @ `eb70210` (independently verified: `git -C .worktrees/integration-measure rev-parse HEAD` → `eb702101fe02ce339515792d1d4cc9d2f3f57c5e`), "one day behind main's `249b799`" per SCORECARD (`testing/SCORECARD.md:234-236`) | VulnCorp-Helpdesk, captured exchanges (`captured_exchanges.json` in the maxrun dir) against 13 tracked planted bugs (`vulncorp_ground_truth.py`, not opened — ground-truth module, not an answer key/app.py, but out of scope for this item) | `qwen3:8b` — the worktree's `harness/config.yaml` sets `agent_defaults.model: "qwen3:8b"` at 3 places (`.worktrees/integration-measure/harness/config.yaml:65,232,242,246`); `run_maxcov_integrated.py`'s `build_config()` does not override the model (`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:72-99`), so it inherits the worktree default. | Fresh: state+cache DBs are deleted and rebuilt every run (`run_maxcov_integrated.py:44-51`, "hazard #4: never replay a warm cache") | No severity/confidence gate applied by this driver; PASS1 `analyze()` + PASS2 `investigate_engagement()` with explicit wide budgets (`max_nodes 60, step_budget 10, discovery_max_probes 12000, max_chain_rounds 3` — driver docstring, `run_maxcov_integrated.py:9-11`) | Widest of the three: `build_config()` merges in `validators.active_enabled=True`, `allow_mutating_replay=True`, `engagement.auto_escalate/driver_execute/feature_crawl/coverage_drive_legs=True`, `browser_xss.enabled=True`, `sqlmap`/`cross_identity` validators enabled (`run_maxcov_integrated.py:72-99`) — full pipeline including chaining/engagement, not just per-exchange analysis. `config.yaml` on disk is never touched; overrides are in-memory only (driver docstring line 15). | `testing/vulncorp-helpdesk/maxrun/recall_report_integrated_full.md` — **present on disk**, 4,770 bytes, mtime 2026-09-20 04:43. Untracked (not in git; confirmed by `git status --short` showing `testing/vulncorp-helpdesk/` as untracked). VERIFIED-in-run for existence. Numbers (9/13 confirmed, 6/13 proof-linked, 0 chains, 8.3h, 1,914 fused findings) are as reported in `testing/SCORECARD.md:234-248`; this item did not re-derive them from the raw JSON (out of INV-1 scope — see INV-4 for dedup/volume analysis). |

**Interpretation boundary (repeated from the dispatch, not re-derived here):** none of these three runs is proof of current-HEAD (`c1133d5`) behavior. PixelMart/blind-target-2 ran on `249b799` + a 5-file diff; VulnCorp ran on a different worktree at `eb70210`. Curated routing (`coordinator.fail_open_mode`), the passive oracle default (`oracle.safe_passive_default`), and lead quarantine (`reporting.quarantine_unverified_leads`) were all added later (P1-4 landed at `1e084e1`; the precision/blind-control sprint Items 1–3 landed in `a549d0b`/`ee54d02`/`bc5f599` per `CURRENT_STATE.md:41-58`) — **after** all three historical runs' code paths were captured. Fresh-run agent variance is already documented in-repo (`testing/SCORECARD.md:65-68`: a second fresh test-target run saw precision fall to 0.286 from 0.476 with recall held), so single historical numbers are not a stable baseline even before considering later code changes.

---

## 2. Mapping later changes to production consumers, and which config each driver loads

| Change | Config knob | Shipped default (`harness/config.yaml`) | Production consumer (VERIFIED-by-inspection) | Is it live on the historical drivers' code path? |
|---|---|---|---|---|
| **Curated routing** | `coordinator.fail_open_mode` (`"all"` / `"curated"`) | `"all"` (`harness/config.yaml:89`) | `harness/coordinator.py:214,221-223` — `Coordinator.__init__` reads `config.get("fail_open_mode", "all")`; `_curated_fallback` is only invoked when it equals `"curated"` (`coordinator.py:82` defines the fallback set; call site `coordinator.py:222-223`). Exercised on the fail-open path (coordinator returned no valid targets, coordinator error, or cloud-coordinator failure — `coordinator.py:281,288,343,350`), not on every dispatch. | **Yes, when set.** `run_blind_eval.py:47` sets `config["coordinator"]["fail_open_mode"]` from the `HARNESS_FAIL_OPEN_MODE` env var (default `"curated"` in that script — note this differs from the shipped `harness/config.yaml` default of `"all"`) before constructing the `Orchestrator`, so `Coordinator.__init__` sees it. The **historical** blind-target-2 run (artifact with `None` manifest fields, §1) predates this env-knob code existing in the driver at all — VERIFIED-by-inspection that the current driver reads this env var; INFERRED that the historical run used whatever `fail_open_mode` its (older) driver revision defaulted to, most plausibly `"all"` since curated routing did not exist yet (P1-4 test suite `harness/test_fail_open_curated.py` — see §1 — was added later). This is an UNKNOWN, not asserted as fact. |
| **Passive oracle default** | `oracle.enabled` (bool), `oracle.safe_passive_default` (bool) | `oracle.enabled: false` (`harness/config.yaml:548`); `oracle.safe_passive_default: true` (`harness/config.yaml:554`) | `harness/orchestrator_confirm.py:57-90`, `ConfirmMixin._oracle_gate`. With `enabled=false, safe_passive_default=true` (the shipped default), it runs `OracleRegistry.oracle_for(..., passive_only=True)` — restricted to validators with `active=False` (`harness/oracle_framework.py:280-296`) — zero live traffic, pure re-analysis of the already-captured exchange. `_oracle_gate` is called from inside `_validate_findings` at `orchestrator_confirm.py:471`, which is on the `orch.analyze()` path `run_blind_eval.py:72` invokes. | **Yes, structurally always active on `analyze()`** (the gate always runs; which of its 3 modes fires depends on the two booleans). `run_blind_eval.py` does not override either `oracle.*` key, so it inherits whatever `harness/config.yaml` has at run time — VERIFIED-by-inspection that `safe_passive_default` was **not present at all** in `harness/config.yaml` for the historical blind-target-2 run's revision window (it is listed in `CURRENT_STATE.md:43-48` as one of "the two new `harness/config.yaml` knobs" shipped in the precision/blind-control sprint, i.e. after the historical run). Before that knob existed, the code took the `cfg.get("safe_passive_default", True)` default inside `_oracle_gate` itself (`orchestrator_confirm.py:73`) — INFERRED that the *effective* behavior (passive-only oracle) was the same either way, because the function's own Python default matches the later-shipped config default; not independently verified against the exact revision `_oracle_gate` had at `249b799` (out of INV-1's read scope to diff historical revisions of this file). |
| **Lead quarantine** | `reporting.quarantine_unverified_leads` (bool) | `false` (`harness/config.yaml:565`) | `harness/confirmation_gate.py:381-413`, `should_quarantine_as_lead`, called from **`harness/report_generator.py:340,355-359`** inside `generate_markdown_report(..., quarantine_leads=...)`. **This is the only production call site of `should_quarantine_as_lead` outside tests** — confirmed by `grep -rn "should_quarantine_as_lead" harness/*.py` returning only `confirmation_gate.py` (definition) and `report_generator.py` (the one call). | **No — not exercised by `run_blind_eval.py` at all.** `run_blind_eval.py` sets `config["reporting"]["quarantine_unverified_leads"]` (`run_blind_eval.py:48`) and prints it in the console banner and manifest (`run_blind_eval.py:51,99`), but **the script never calls `report_generator.generate_markdown_report`** — it dumps `r.agent_reports`/`r.validation_reports` straight to JSON (`run_blind_eval.py:74-78`). `grep -rn "quarantine" harness/orchestrator.py harness/orchestrator_confirm.py harness/orchestrator_detect.py harness/orchestrator_chain.py` returns **no matches** — `orch.analyze()` itself never reads or applies this knob. **Consequence: for this driver, `HARNESS_QUARANTINE_LEADS` is a no-op on the actual output file; it only affects a would-be markdown report that this driver never generates.** VERIFIED-by-inspection (both the grep-empty result and the driver's own output code). The knob IS live in the `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`-style drivers, which do call `generate_markdown_report` (confirmed by grep: `report_generator.py`, `test_report_generator.py`, `test_quarantine_leads.py`, and three `testing/vulncorp-helpdesk/maxrun/*.py` files are the only repo-wide callers, outside `archive/` and `reviews/*/checks.py`). |

**Vendored-config hazard (relevant to "an overlay in the wrong config is not a valid comparison"):** `testing/blind-test-kit/harness/config.yaml` (a *separate*, vendored copy of the harness config used by `testing/blind-test-kit/harness_driver.py`, which loads it via bare `yaml.safe_load()` per `harness_driver.py:80-82` and `CURRENT_STATE.md:46-48`) currently ships `fail_open_mode: "curated"` (`testing/blind-test-kit/harness/config.yaml:21`) — **the opposite of the real `harness/config.yaml`'s `"all"` default.** This vendored kit is **not** the driver that produced the blind-target-2 SCORECARD number (that was `testing/blind-target-2/run_blind_eval.py`, which loads the real `harness/config.yaml` directly — `run_blind_eval.py:42-43`), so the two must not be conflated. VERIFIED-by-inspection. Flagging this because a future reviewer reproducing "the blind run" could easily point at the wrong kit and get a different `fail_open_mode` without noticing.

---

## 3. Same-revision 2×2 comparison plan (routing all/curated × quarantine off/on)

**Goal:** isolate the effect of (a) curated routing and (b) lead quarantine, holding
model/corpus/oracle-mode/scope/budgets fixed, on a single pinned revision — without
claiming precision/recall improved.

### 3.1 What must be held fixed

- **Revision:** current HEAD (or any single commit chosen for the run) — record via
  `git rev-parse HEAD` in the run manifest, not assumed.
- **Model:** `agent_defaults.model` and `coordinator.model` from `harness/config.yaml`
  (currently `qwen3:8b`, `harness/config.yaml:232`, cross-checked against
  `_PROFILE_KNOB_DEFAULTS["agent_defaults.model"]` in `harness/config_schema.py:252`)
  — do not let an operating-profile selection silently change this (see §3.4).
- **Corpus:** `testing/blind-target-2/blind_eval_exchanges.json` (10 curated
  exchanges) — same file, same order, for every cell.
- **Oracle mode:** `oracle.enabled` and `oracle.safe_passive_default` unchanged from
  whatever the run intends to hold fixed (recommend leaving at the shipped default,
  `enabled=false, safe_passive_default=true`, so the comparison isolates routing and
  quarantine, not the oracle).
- **Scope/budgets:** `server.allowed_hosts`, `concurrency.*`, `retry_budget`,
  `effort_budget` — unchanged from `harness/config.yaml` defaults across all 4 cells
  unless the comparison explicitly wants to vary one of them (it should not, per the
  dispatch).
- **Fresh state+cache DBs per cell** — `run_blind_eval.py` already does this
  (`store._DB_PATH`, `cache.init_cache(...)` at import time, `run_blind_eval.py:28-31`)
  but reuses the **same fixed path** across invocations (`C:\tmp\blind_eval_state.db`,
  `C:\tmp\blind_eval_cache.db`), which means **cell N+1 will silently reuse cell N's
  cache** unless the operator renames/deletes those files between cells (the driver
  does not do this itself — VERIFIED-by-inspection, no `unlink()` call in
  `run_blind_eval.py`, unlike `run_maxcov_integrated.py:44-51` which does delete its
  DBs). This is a **prerequisite check**, not an assumption — see §5.

### 3.2 The 2×2 cells and their config deltas from `harness/config.yaml`'s default

| Cell | `HARNESS_FAIL_OPEN_MODE` | `HARNESS_QUARANTINE_LEADS` | Effective `coordinator.fail_open_mode` | Effective `reporting.quarantine_unverified_leads` |
|---|---|---|---|---|
| A (all / off) | `all` | `0` | `"all"` | `False` |
| B (all / on) | `all` | `1` | `"all"` | `True` |
| C (curated / off) | `curated` | `0` | `"curated"` | `False` |
| D (curated / on) | `curated` | `1` | `"curated"` | `True` |

### 3.3 Config fingerprints and cache namespaces

- `run_blind_eval.py:50` already computes `config_fingerprint(config)` (from
  `harness/config_schema.py:179-184`, a sha256 over the redacted effective config) and
  prints/stores it (`run_blind_eval.py:51,97`). **Use this as the per-cell identity
  check**: cell A and cell B should differ only in the `reporting` section of the
  fingerprinted config; cell A and cell C should differ only in `coordinator`. If two
  cells' fingerprints are identical, the env vars did not take effect — treat that as
  a failed run, not a valid data point.
- **Cache namespace requirement (not currently satisfied by the driver as-is):**
  because `run_blind_eval.py` hardcodes `C:\tmp\blind_eval_state.db` /
  `C:\tmp\blind_eval_cache.db` regardless of cell, a reproducer MUST either (a) delete
  both files (plus their `-wal`/`-shm` siblings) before each cell, or (b) patch the
  driver to suffix the DB paths with the cell name (e.g. `blind_eval_state_A.db`)
  before running. Recommend (a) for a minimal, non-code-changing reproduction, and
  note this as a documentation-only recipe, not a code change made by this item.

### 3.4 Why quarantine can be isolated from stochastic generation, and why routing cannot

**Quarantine is strictly postprocessing** (§2: its only call site is
`report_generator.generate_markdown_report`, which runs over an already-produced
`findings` list and does not re-invoke any agent or validator — `report_generator.py`
lines around 318-359 take `findings` as a parameter, they do not call `orch.analyze`).
Consequently: **cells A and B (and separately, C and D) can share one set of raw
`orch.analyze()` results.** Run cell A once (routing=all, live model calls), capture
the raw `findings` list from `blind_eval_results.json`, then compute cell B's report
by calling `generate_markdown_report(..., quarantine_leads=True)` on that *same* raw
list, purely in Python, no new model calls. This holds stochastic model generation
literally constant between A and B (same list of findings), so any difference between
their reports is 100% attributable to the quarantine predicate — not sampling
variance. The same logic applies to C vs. D.

**Routing (all vs. curated) cannot be isolated this way**, because
`coordinator.fail_open_mode` changes which agents `Coordinator.choose_agents` /
`_curated_fallback` dispatch on the fail-open path (`coordinator.py:221-223`) —
different dispatched agents can mean different raw findings before any postprocessing
runs. **A and C must each be run live** (fresh model calls), and their comparison is
therefore subject to the fresh-run agent variance already documented in-repo
(`testing/SCORECARD.md:65-68`, `testing/DETECTION_BENCH_METHODOLOGY.md` referenced
there). This is why §5's repeat policy requires ≥3 independent live runs per
routing condition, not per quarantine condition.

**Caveat on scope:** `fail_open_mode` only matters on exchanges where the coordinator
actually fails open (a routing failure, timeout, or error) — on curated
`blind_eval_exchanges.json`, most exchanges may route normally and never reach
`_curated_fallback` at all, in which case cells A and C could show identical dispatch
for most/all of the 10 exchanges and the routing knob's effect would be
**UNKNOWN/near-zero on this specific corpus** rather than demonstrating a difference.
This must be checked from the `dispatched_agents` field each cell's `results[]` array
records (`run_blind_eval.py:76-77`) and from `fail_open_stats_before/final`
(`run_blind_eval.py:62,93`, backed by `harness/coordinator.py`'s `fail_open_stats()` —
not read in this item) — if `fail_open_stats_final['count']` is 0 in a cell, that
cell never exercised the fallback path, and A vs. C is not a real routing comparison
for this corpus; report that explicitly rather than asserting a routing effect that
didn't fire.

---

## 4. Metrics to report

For each of the 4 cells, report all of the following (never collapse to one number):

1. **Raw detection recall** — per the `testing/score.py` definition (`METRIC_SCOPE =
   "raw_detection"`, `score.py:100`): did a labeled exchange produce ≥1 finding of the
   correct OWASP class, regardless of `confirmed`/`oracle_verified`/quarantine status.
   `score.py` itself only reads `finding.vulnerability_class` strings
   (`score.py:114`), so it cannot distinguish a quarantined lead from a surfaced
   finding — do not use raw `score.py` output alone for the surfaced-finding number.
2. **Surfaced-finding recall** — same definition, but computed only over findings that
   survive `should_quarantine_as_lead` filtering when quarantine is on (cells B, D):
   a finding quarantined into "Test Suggestions" is not a surfaced finding for this
   purpose. This number requires reading `report_generator.py`'s split output
   (`## Confirmed Findings` / `## Unconfirmed Findings` vs. "Test Suggestions" —
   `harness/test_quarantine_leads.py:102-117` shows the exact section markers to
   grep for), not just the raw findings list.
3. **Raw FP count** and **surfaced FP count** — same raw-vs-surfaced split, applied to
   the `confirmed_secure` control exchanges (6 of the 10 in
   `blind_eval_exchanges.json`, per `run_blind_eval.py:11`).
4. **Clean controls** — count of the 6 `confirmed_secure` exchanges that produced
   *zero* surfaced findings (medium+ or whatever floor is chosen — state the floor
   explicitly per §5's exact commands).
5. **Leads** — count of findings routed to the quarantine/"Test Suggestions" bucket
   (cells B, D only; always 0 by construction in cells A, C since quarantine is off).
   **Do not report "leads" as if it were a reduction in true FPs** — a lead is a
   relabeled unconfirmed finding, not a suppressed one; the dispatch's explicit
   warning ("Hiding everything as leads is not a win") applies directly here.
6. **Proof-linked confirmation** — count of findings where `confirmed=True` AND the
   finding resolves to an actual persisted proof record for its own case/validator
   identity (this is INV-2's scope, not re-derived here; if INV-2's audit recipe is
   available by the time this comparison runs, apply it; otherwise report `confirmed`
   flag counts and explicitly label them "not proof-audited, see INV-2").
7. **Elapsed time** — `results[i]['elapsed_seconds']` per exchange
   (`run_blind_eval.py:78`, `:87`) and a run total; report both per-cell mean and
   the 3-run spread (§5).
8. **Model calls / tokens, when available** — `run_blind_eval.py` does not currently
   record token/call counts in its manifest (VERIFIED-by-inspection: the manifest
   dict at `run_blind_eval.py:95-103` has no token/call field). This is a **gap**:
   report it as UNKNOWN per-cell unless `harness/telemetry.py` (not read in this
   item — INV-4's entry point) is separately wired into the manifest before running.
   Do not fabricate a token estimate.

Use the corpus's existing ground-truth labels (`blind_eval_exchanges.json`'s
`ground_truth` field, read by the driver at `run_blind_eval.py:76`) unchanged; never
adjust ground truth to make a cell's numbers look better.

---

## 5. Exact reproduction commands (NOT executed in this item)

### 5.1 Prerequisite checks (run first, read-only)

```sh
# 1. Confirm the target revision and a clean-enough tree (no unrelated pending
#    changes to harness/coordinator.py, harness/confirmation_gate.py,
#    harness/report_generator.py, harness/orchestrator_confirm.py, or config.yaml
#    that would make the "same revision" claim false):
git rev-parse HEAD
git status --short -- harness/coordinator.py harness/confirmation_gate.py \
  harness/report_generator.py harness/orchestrator_confirm.py harness/config.yaml

# 2. Confirm Ollama is actually reachable with the configured model (do NOT assume
#    from old notes -- AGENTS.md hazard #6 applies equally to Ollama availability):
curl -s http://localhost:11434/api/tags | grep -o '"qwen3:8b"'

# 3. Confirm no stale cache/state DB will be silently reused for cell A:
ls -la C:/tmp/blind_eval_state.db C:/tmp/blind_eval_cache.db 2>NUL
# If present, delete before EVERY cell (fresh generation is required for
# routing comparisons -- see 3.4):
rm -f C:/tmp/blind_eval_state.db C:/tmp/blind_eval_state.db-wal \
      C:/tmp/blind_eval_state.db-shm C:/tmp/blind_eval_cache.db \
      C:/tmp/blind_eval_cache.db-wal C:/tmp/blind_eval_cache.db-shm

# 4. Confirm dependencies for the venv the project standardizes on:
.venv-rationalisation/Scripts/python.exe -c "import harness, yaml, httpx; print('ok')"
```

### 5.2 The four cells (owner-run; NOT executed by this item)

Per §3.4, cells A and C need fresh live runs; B and D can either be run live (for a
belt-and-suspenders check) or derived by rerunning `generate_markdown_report` over A's
/ C's already-captured raw findings. The commands below run all four live for
simplicity and to also validate the "identical raw findings" claim empirically
(A's raw findings should statistically resemble B's, modulo the run-to-run variance
in §3.4 — if there is drastic disagreement, that is itself a finding).

```sh
# Cell A: routing=all, quarantine=off
rm -f C:/tmp/blind_eval_state.db* C:/tmp/blind_eval_cache.db*
HARNESS_FAIL_OPEN_MODE=all HARNESS_QUARANTINE_LEADS=0 \
  .venv-rationalisation/Scripts/python.exe testing/blind-target-2/run_blind_eval.py
cp C:/tmp/blind_eval_results.json testing/blind-target-2/exports/cell_A_$(date +%Y%m%d_%H%M%S).json

# Cell B: routing=all, quarantine=on
rm -f C:/tmp/blind_eval_state.db* C:/tmp/blind_eval_cache.db*
HARNESS_FAIL_OPEN_MODE=all HARNESS_QUARANTINE_LEADS=1 \
  .venv-rationalisation/Scripts/python.exe testing/blind-target-2/run_blind_eval.py
cp C:/tmp/blind_eval_results.json testing/blind-target-2/exports/cell_B_$(date +%Y%m%d_%H%M%S).json

# Cell C: routing=curated, quarantine=off
rm -f C:/tmp/blind_eval_state.db* C:/tmp/blind_eval_cache.db*
HARNESS_FAIL_OPEN_MODE=curated HARNESS_QUARANTINE_LEADS=0 \
  .venv-rationalisation/Scripts/python.exe testing/blind-target-2/run_blind_eval.py
cp C:/tmp/blind_eval_results.json testing/blind-target-2/exports/cell_C_$(date +%Y%m%d_%H%M%S).json

# Cell D: routing=curated, quarantine=on
rm -f C:/tmp/blind_eval_state.db* C:/tmp/blind_eval_cache.db*
HARNESS_FAIL_OPEN_MODE=curated HARNESS_QUARANTINE_LEADS=1 \
  .venv-rationalisation/Scripts/python.exe testing/blind-target-2/run_blind_eval.py
cp C:/tmp/blind_eval_results.json testing/blind-target-2/exports/cell_D_$(date +%Y%m%d_%H%M%S).json
```

**Note on `quarantine_leads` and this specific script (repeated from §2):** because
`run_blind_eval.py` never calls `generate_markdown_report`, cells B and D's raw
`blind_eval_results.json` will be **byte-for-byte equivalent in shape** to A and C
except for the `quarantine_leads` manifest field and (if routing differs between the
pair) dispatch — the quarantine predicate itself will not visibly change anything in
this file. To actually measure quarantine's effect on *surfaced* findings (metric #2
in §4), the owner must additionally run each cell's raw findings through
`report_generator.generate_markdown_report(host, findings, quarantine_leads=<bool>)`
in a small script, or extend `run_blind_eval.py` to call it — **a code change**, out
of this item's scope, filed as its own ticket in §6.

### 5.3 Repeat policy

- **Cells A and C (model-generating, routing varies): ≥3 independent runs each**,
  per the dispatch's explicit floor. Each run must use a freshly-cleared cache (5.1
  step 3) — a second run against a warm cache is not an independent sample.
- **Cells B and D**, if derived from A's/C's raw findings per §3.4 (recommended):
  0 additional live runs needed — they are deterministic postprocessing of the
  already-captured ≥3 samples, so report the same ≥3-sample spread, split by
  quarantine on/off.
- If time/GPU budget only allows one pass per cell, **label it explicitly**
  "single-pass, variance unknown" in the results table — do not present a 1-run
  number with the same confidence as the SCORECARD's own headline numbers, which
  themselves are flagged as single-pass with documented run-to-run swings
  (`testing/SCORECARD.md:143-145`, `:65-68`).

### 5.4 Artifact outputs

- Raw per-cell JSON: `testing/blind-target-2/exports/cell_{A,B,C,D}_<timestamp>.json`
  (the `exports/` directory already exists — `testing/blind-target-2/exports` shown
  in the earlier `ls`).
- A summary table (metrics from §4, per cell, with the git revision and
  `config_fingerprint` for each) should be written to a new dated file under
  `reviews/<run-date>/`, per this repo's existing convention for owner-reported
  results (see `IMPROVEMENT_BACKLOG.md` P0-3 acceptance criteria: "Publish under
  `reviews/<date>/` as owner-reported with the exact command and model tag").

---

## 6. P0-3 remaining acceptance gaps

`IMPROVEMENT_BACKLOG.md:127-149` (P0-3) already has a 2026-09-20 status correction
noting real-model runs exist (`testing/SCORECARD.md`) and that "INV-1 inventories
remaining reproducibility/metric gaps and prepares measurement of subsequent
changes." Based on the inspection above, P0-3's **acceptance criteria**
("A re-runnable command + a results file with the metrics above and a config
fingerprint. Numbers labeled owner-reported/VERIFIED-in-run, never promoted from
stubbed results.") are **partially, not fully, met**:

- **Met:** a re-runnable command exists for all three historical drivers
  (`detection_fixture.py build` + `score.py`; `run_blind_eval.py`;
  `run_maxcov_integrated.py`) — VERIFIED-by-inspection, all three drivers' CLI/env
  surface was read in this item (§1).
- **Met:** `run_blind_eval.py` (current revision) does compute and print a
  `config_fingerprint` (`run_blind_eval.py:50-52`) — this exists for future runs.
  **Not met historically:** the actual on-disk artifact for the reported
  blind-target-2 run (`C:\tmp\blind_eval_results.json`, §1) predates that field
  (it is `None`), so the SCORECARD's reported blind-target-2 numbers have **no
  fingerprint binding them to a specific config** — an explicit limitation, not
  fixable by re-reading the same file.
- **Not met:** no single command or manifest ties **all three** historical runs'
  numbers together under one config fingerprint / revision — they are three
  separate ad-hoc drivers at two different revisions (§1), which is exactly what
  INV-1 was asked to reconcile, not resolve; resolving it (one unified
  measurement) is future work, not this item's product.
- **Not met:** the curated-routing / quarantine change has **zero** owner-run
  efficacy measurement yet (`CURRENT_STATE.md:61-64,78-81` explicitly says this is
  still open: "Owner: run both corpora under curated + quarantine; record
  precision/recall deltas … (sprint exit criterion)"). §3–§5 of this document are
  the prepared recipe for that measurement; they do not constitute the measurement.
- **Not met:** no token/model-call accounting is captured by any of the three
  historical drivers or by `run_blind_eval.py`'s current manifest (§4, metric 8) —
  P0-3's own recommendation text asks for "token cost" (`IMPROVEMENT_BACKLOG.md:143`)
  and this is not wired.
- **Newly identified gap (this item):** `reporting.quarantine_unverified_leads` is
  not consumed anywhere on `run_blind_eval.py`'s code path (§2) — so even after an
  owner runs the §5 commands, cells B/D will not show a quarantine effect on
  `blind_eval_results.json` without the follow-up change noted in §5.2. This must be
  fixed or worked around before the "record precision/recall deltas" exit criterion
  in `CURRENT_STATE.md:61-64` can be satisfied for the quarantine axis specifically
  (the routing axis is unaffected by this gap).

**Conclusion:** P0-3 remains correctly "open" per its current backlog status — it is
neither "wholly absent" (real historical numbers exist and are traceable) nor "done"
(no fingerprint-bound, config-varying, repeat-sampled measurement exists yet, and one
of the two changes it needs to measure — quarantine — has no effect on the
prescribed driver's output as currently wired).

### Separate owner-run measurement ticket (filed here, not implemented)

**Ticket: "P0-3 measurement pass — 2×2 curated-routing × quarantine on blind-target-2"**
- **Owner action, not a code change** (except the report_generator wiring noted
  below, which is a small, separately-scoped fix).
- **Steps:** run §5.1 prerequisite checks; run §5.2's four cells with ≥3 repeats each
  for A and C per §5.3; compute §4's metrics for each cell (deriving B/D's surfaced-
  finding numbers via `generate_markdown_report` over A's/C's raw findings, per §3.4,
  OR after the small fix below); write the summary to `reviews/<date>/P0-3_2x2_result.md`
  with each cell's config fingerprint, git revision, and raw artifact path.
- **Blocking sub-ticket (small, separate, code-touching):** wire
  `reporting.quarantine_unverified_leads` into `run_blind_eval.py` (or a thin wrapper)
  so the driver actually calls `report_generator.generate_markdown_report` on its
  captured findings and reports the confirmed/unconfirmed/leads split, instead of
  only printing raw `agent_reports`. Acceptance test: a caller-level test asserting
  that setting `HARNESS_QUARANTINE_LEADS=1` changes the *reported* (not just the
  manifest-echoed) output for a fixture finding that satisfies
  `should_quarantine_as_lead`, mirroring the existing negative control in
  `harness/test_quarantine_leads.py:119-126` (a confirmed+oracle-verified finding
  must NOT be quarantined) as the paired regression check. This is explicitly NOT
  implemented by this INV-1 item (no production code was changed here).

---

## Limitations

- **No live execution occurred in this item.** All "fresh vs. cached" and "which
  config a driver loads" claims are from reading driver source and, where available,
  on-disk artifact headers (timestamps, manifest field presence/absence) — not from
  re-running anything. Tagged VERIFIED-by-inspection / VERIFIED-in-run (artifact
  metadata only) throughout.
- **VulnCorp maxrun's detailed per-bug/per-validator numbers were not re-derived**
  from its raw JSON artifacts in this item (out of INV-1's stated scope; that
  belongs to INV-4's dedup/cost-attribution work). Only the report file's existence,
  timestamp, and the revision/model/config-merge facts from the driver source were
  verified here.
- **The exact `_oracle_gate`/`safe_passive_default` behavior at the historical
  blind-target-2 run's actual code revision was not diffed against current HEAD.**
  This item inspected the CURRENT `orchestrator_confirm.py` and inferred (not
  verified) that the effective default was equivalent before the config key
  formally existed, based on the function's Python-level default argument matching
  the later-shipped config default. A reviewer wanting certainty here should run
  `git log -p --follow -- harness/orchestrator_confirm.py` bounded to
  `249b799..<the commit right before the historical run>` — not done in this
  read-only item to stay within scope.
- **Token/model-call accounting is UNKNOWN for all three historical runs and for
  the current `run_blind_eval.py`.** No instrumentation currently writes this to
  any inspected manifest. `harness/telemetry.py` was named in the dispatch as an
  INV-4 entry point, not read here.
- **The quarantine axis of the prepared 2×2 comparison (§3, §5) cannot be measured
  from `run_blind_eval.py`'s existing output without the small follow-up fix filed
  in §6.** This is stated as an explicit limitation of the current driver, not
  worked around by inventing a substitute measurement path in this document.
- **`fail_open_stats` was not read in this item** (referenced in §3.4 as the
  correct field to check whether the fail-open path fired at all on this corpus) —
  its exact shape (`{"count": ..., "by_reason": ...}`) was only seen via the test
  file `harness/test_fail_open_curated.py:78-97`, not independently confirmed
  against `harness/coordinator.py`'s implementation in this item.
