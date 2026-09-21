# INV-4 — Duplicate noise and cost attribution

- **Item:** INV-4 (`docs/INVESTIGATION_DISPATCH_2026-09-20.md`)
- **Date:** 2026-09-21
- **HEAD at time of writing:** `21f9b37d13fdee72c72c28e15207923876259b79`
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
- **This is offline, read-only diagnosis.** No production code was changed.
  The only commands run were `git`, `Read`/`Grep` over source, and read-only
  `sqlite3.connect(..., uri=True)` queries (`mode=ro`) plus `json.load()`
  reads against an already-completed run's own artifacts. No scorer/driver
  was executed, no live model/Docker/blind run occurred.
- Depends on INV-1 (`docs/investigations/INV-1-baseline.md`, closed at
  `c1133d5`) and INV-3 (`docs/investigations/INV-3-chain-funnel.md`, closed at
  `cc8e817`). This item reuses INV-1's revision table (the VulnCorp maxrun
  artifacts are from `.worktrees/integration-measure` @ `eb70210`, a different
  revision than current HEAD) and INV-3's finding that the PASS2 graph path
  does not persist `chain_linker` output to `store.findings`.

## Evidence-tag legend

- **VERIFIED-by-inspection** — read directly from source/config in this
  checkout at the stated revision; no code executed to obtain it.
- **VERIFIED-in-run** — read directly from an on-disk artifact produced by an
  actual completed run (not re-executed here), including ad hoc read-only
  Python/SQL queries against that run's own JSON/SQLite files.
- **SUPPORTED** — a reasonable inference from two or more inspected sources,
  not independently executed or artifact-confirmed.
- **INFERRED** — a plausible read with a named gap; flagged for the reviewer,
  not asserted as fact.
- **UNKNOWN** — not determinable from available, permitted material; stated
  as an explicit limitation, never guessed.

Safety note: this item did not open `vulncorp_ground_truth.py`, any
`*ANSWER_KEY*` file, or any blind target's `app.py`. It did not execute or
import `recall_benchmark.py`/any scorer; it read `run_maxcov_integrated.py`
(a driver script, not a target implementation) as source text only, and read
already-completed run artifacts (`testing/vulncorp-helpdesk/maxrun/*.json`,
the run's own SQLite state DB opened `mode=ro`) — the same class of artifact
INV-1/INV-3 already treated as inspectable.

---

## 1. Dedup-key / layer map (built before proposing any new logic)

The dispatch's named entry point `harness/host_dep_dedup.py` (53 lines, read
in full) is **not a dedup module** — VERIFIED-by-inspection. It contains two
pure functions, `is_passive_banner` and `cap_passive_banner_severity`
(`harness/host_dep_dedup.py:37-53`), which cap the *severity* of a
dependency-advisory finding observed only via a passive response banner
(`Server`/`X-Powered-By`/`Via`). Neither function computes or checks a
dedup/identity key; there is no `_key`, `fingerprint`, or `dedupe` symbol
anywhere in this file. This is the module's true role, distinct from its
name's suggestion — flagged so the reviewer does not conflate it with the
actual dedup layers below.

The actual dedup/grouping keys live in five different places, one per
pipeline layer:

| Layer | Symbol | Key tuple (as implemented) | Where enforced |
|---|---|---|---|
| **Raw observation** (an agent/validator's in-memory `Finding`, pre-persistence) | none — no dedup at this layer | n/a | n/a; every dispatched agent's raw output is a candidate |
| **Fused/persisted finding** (`store.findings` row) | `store.finding_fingerprint()` (`harness/store.py:30-55`) | `sha256("\x1f".join([host, METHOD.upper(), normalized_endpoint, canonical_vulnerability_class, parameter_location.lower(), parameter_name (case-sensitive), principal_id]))`, where `normalized_endpoint` (`harness/store.py:19-27`) is `scheme://netloc/path` + the **sorted set of query PARAM NAMES** (values stripped, so `?id=1` and `?id=2` collapse but `?a=` and `?b=` stay distinct) | Enforced only jointly with `case_id`: `CREATE UNIQUE INDEX idx_findings_fingerprint_case ON findings(fingerprint, case_id)` (`harness/store.py:354-356`), written via `INSERT OR IGNORE` in `persist_findings` (`harness/store.py:448-478`). A finding with **no** `case_id` (empty string) dedups by `fingerprint` alone, because `("", "")` collides for every case-less repeat of the same fingerprint; a finding **with** a `case_id` dedups only if BOTH match — so two attempts with the same structural fingerprint but different `case_id` values are two separate rows by design (`harness/store.py:347-354` comment, T06/R08). |
| **Surfaced finding** (what a Markdown report / issue export presents) | `report_generator._dedup_key()` (`harness/report_generator.py:272-283`), which is explicitly `issues.issue_key()` (`harness/issues.py:219-235`) "by construction" so the two agree | `(host, endpoint_family, method, canonical_class, affected_input, authorization_boundary, disambiguator)` — `endpoint_family` collapses numeric-looking path segments to `{id}` (`normalize_path`, referenced at `issues.py:228`, not itself re-read in this item); `affected_input` is the parameter/object identity; `disambiguator` is `finding_id`/`fingerprint` **only when** `affected_input` is unknown, so two unattributed findings don't wrongly collapse (`issues.py:233-234`) | `report_generator._collapse_duplicates()` (`harness/report_generator.py:291-313`) — groups by this key, keeps the highest-ranked survivor (`confirmed` beats unconfirmed, then more-severe, then higher-confidence, `_rank_tuple` at `:286-288`), and records `duplicate_count` on the survivor. This runs only inside `generate_markdown_report`/issue export, i.e. it is a **reporting-time** collapse over whatever `store.all_host_findings()` already contains — it does not change what is in `store.findings`. |
| **Lead** (a quarantined, unconfirmed finding on a blind/no-oracle run) | `confirmation_gate.should_quarantine_as_lead()` (`harness/confirmation_gate.py:381-413`) | Not a grouping key at all — a per-finding **predicate**: `leg_tier(vulnerability_class) == "live"` AND `basis in ("assumed", "recalled")` AND `not confirmed` AND `not oracle_verified` (`confirmation_gate.py:409-413`). A finding either is or is not routed to the leads bucket; leads are never deduplicated against each other by this function — whatever collapse a lead undergoes happens earlier, at the surfaced-finding layer above, before the quarantine predicate is applied (`report_generator.py:340,355-359`, per INV-1 §2). |
| **Distinct case** | `case_id` (opaque string, generated upstream of `store.py` — not itself defined in any of this item's entry points) plus `proof_records` keyed on `proof_id` PRIMARY KEY, `idx_proof_case` on `case_id` (`harness/store.py:165-192`) | A "case" is the unit INV-2 already traced: one `case_id` can have multiple `proof_records` rows (one per attempt, `proof_id` unique per attempt), and `store.proofs_for_case`/`best_proof_for_case` (`harness/store.py:717-734`) select among them. A finding's `case_id` is what the fused-finding layer's unique index keys on jointly with `fingerprint` (row above) — so "distinct case" is the layer that determines whether a repeated structural fingerprint gets a new row at all. |

**Why this matters for step 5's noise/precision constraint:** the fused-finding
layer's `(fingerprint, case_id)` key is **coarser than fingerprint alone by
design** (to let independent confirmation attempts each keep their own proof
trail, per the `harness/store.py:347-354` comment) — so raw finding-volume
counts read from `store.findings` conflate two different things that a naive
"reduce noise" ticket could wrongly collapse: (a) genuinely repeated
observations of the identical structural finding across re-confirmation
attempts, and (b) genuinely distinct object/principal instances of the same
vulnerability class on the same endpoint family (e.g. IDOR proven on tickets
1..8), which the surfaced-finding layer already collapses correctly via
`endpoint_family` + `affected_input`, not via `fingerprint`. A dedup change
at the fused layer that keyed on `fingerprint` alone (ignoring `case_id`)
would violate the append-only, per-attempt proof trail this schema was built
for (§4 below returns to this).

**Missing fields, explicitly:** `store.finding_fingerprint()` takes
`principal_id` as a parameter, but `store.persist_findings` only supplies it
via `getattr(f, "principal_id", "") or ""` (`harness/store.py:462`) — for the
large majority of agent-produced findings this is an empty string (VERIFIED
in the artifact excerpt in §2 below: every sampled `analyze()`-returned
finding has `"principal_id": ""`), so the fingerprint's principal component
is present in the formula but frequently unpopulated in practice, meaning
fingerprint collisions across genuinely different principals are possible
wherever `principal_id` isn't threaded through by the producing agent. This
is a **missing-field gap in the raw observation layer**, not a bug in the
fingerprint formula itself.

---

## 2. Artifact grouping analysis (available allowed artifacts)

Source: `testing/vulncorp-helpdesk/maxrun/maxcov_state_integrated_full.db`
(opened `file:...?mode=ro`) and `maxcov_results_integrated_full.json` /
`recall_report_integrated_full.md` / `recall_report_integrated_full.json` —
the same artifact set INV-1/INV-3 already treated as an allowed harness-
generated report, revision `eb70210` per INV-1's revision table (**not**
current HEAD `21f9b37`). All counts below are VERIFIED-in-run against these
specific files; none were re-derived from a fresh run.

**By normalized endpoint (URL, uncanonicalized class), `information_disclosure`
family:**

```sql
SELECT url, COUNT(*) FROM findings
 WHERE vulnerability_class IN ('information_disclosure','info_disclosure','Information disclosure')
 GROUP BY url ORDER BY 2 DESC LIMIT 15;
```
Top hits: `/api/admin/debug` ×30, `/api/tickets/search?q=1` ×28,
`/api/kb/articles/{id}` ×27, `/api/tickets/search` ×26, `/api/register` ×24,
`/api/login` ×24, `/api/integrations/webhook-test` ×24, `/api/admin/users`
×24, … across **35 distinct URLs total** for 638 rows in this class family.

**By validator/proof identity, one heavy endpoint (`/api/admin/debug`):**

```sql
SELECT COUNT(*), COUNT(DISTINCT case_id), COUNT(DISTINCT fingerprint),
       COUNT(DISTINCT proof_id)
 FROM findings WHERE url='http://127.0.0.1:5002/api/admin/debug'
   AND vulnerability_class='information_disclosure';
-- -> (29, 29, 1, 29)
```
29 raw rows, **1 distinct fingerprint**, 29 distinct `case_id`/`proof_id`
values. Every sampled row's `proof_records.principal_id` for these
`case_id`s is the literal string `"captured"` (not a real distinct
principal) — VERIFIED-in-run:
`SELECT DISTINCT p.principal_id FROM findings f JOIN proof_records p ON
p.case_id=f.case_id WHERE f.url='...admin/debug' AND
f.vulnerability_class='information_disclosure' -> [('captured',)]`.

Family-wide: `SELECT COUNT(*), COUNT(DISTINCT fingerprint) FROM findings
WHERE vulnerability_class IN (...) -> (638, 58)`. **638 raw rows collapse to
58 distinct structural fingerprints** when grouped by the fused-finding
layer's own identity (§1). This is the mechanism, traced to source: the
`(fingerprint, case_id)` unique index (§1) does not collapse these, because
each of the 29 rows at `/api/admin/debug` carries a distinct `case_id` for
what is, by the fingerprint formula's own definition (host + method +
normalized endpoint + class + parameter + `principal_id`), the identical
structural finding — the `principal_id` component did not differentiate
them (all `"captured"`, not per-identity). **This is source-supported, not
merely a raw-volume observation**: the review gate's "a repeated class on
one endpoint is not automatically one duplicate" applies here in the
opposite direction too — this specific case genuinely is 29 repeats of one
structural finding under the schema's own key, not 29 distinct object/
principal instances, because the identity-bearing field (`principal_id`)
that would make them distinct was never populated with a real per-attempt
value.

**By agent (a stand-in for "validator" at the raw layer, since the schema's
`agent` column, not a separate `validator` column, records the producer):**

```sql
SELECT agent, vulnerability_class, COUNT(*) FROM findings
 WHERE vulnerability_class LIKE '%disclosure%'
 GROUP BY agent, vulnerability_class ORDER BY 3 DESC;
```
Top rows: `misconfig`→`information_disclosure` ×173, `auth`→
`information_disclosure` ×129, `supply_chain`→`information_disclosure` ×74,
`jwt`→`information_disclosure` ×68, `info_disclosure`→
`information_disclosure` ×66, `api_security`→`information_disclosure` ×43,
`verbose_error_detector`→`verbose_error_disclosure` ×40, `business_logic`→
`information_disclosure` ×27, … spread across 13 different agent names.
**This does not match the SCORECARD's "one validator" framing at the raw-
row level** — the raw rows are produced by many different agents, not one
validator — see §3 for where "one validator" actually comes from.

**Missing fields, explicitly:** `parameter_location`/`parameter_name` for
these rows are read from `proof_records` via a correlated subquery in
`all_host_findings` (`harness/store.py:810-812`), not stored directly on
`findings` — for rows with no matching `proof_records` case (581 of 691
class-family rows lack a `case_id`/`proof_id` per the count in §1's
"missing fields" note: 691 total rows in the two disclosure classes, 616
have non-empty `case_id`, 616 have non-empty `proof_id`, meaning 75 rows
have neither), these fields are UNKNOWN/empty for the purposes of a
principal/object grouping — VERIFIED-in-run via
`SELECT COUNT(*), SUM(case_id!=''), SUM(proof_id!='') FROM findings WHERE
vulnerability_class IN (...) -> (691, 616, 616)`.

---

## 3. Tracing the 641/107 disclosure counts to evidence

**Traced to source, not retained as an unexplained aggregate.** The exact
figures come from `testing/vulncorp-helpdesk/maxrun/recall_report_integrated_full.md:28-29`:

```
- **information_disclosure** x641  legs=['verbose_error_validator']
- **verbose_error_disclosure** x107  legs=['(none-stamped)']
```

These are **not** `store.findings` row counts (§2 showed the raw
`information_disclosure`-family total there is 638, across many agents, not
641 on "one validator"). They come from `run_maxcov_integrated.py`'s own
`_confirmed_classes()` (`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:185-193`),
which counts over `confirmed = [f for f in findings if f.get("confirmed")]`,
where `findings = _all_findings(analyze_findings, investigate)`
(`run_maxcov_integrated.py:149-154,161-162`):

```python
def _all_findings(analyze_findings, investigate):
    combined = list(analyze_findings)                       # (A) in-memory PASS1 returns
    combined += list(store.all_host_findings(BASE))          # (B) persisted store rows
    if isinstance(investigate, dict):
        combined += _graph_findings(investigate)             # (C) PASS2 graph outcomes/worklist/chains
    return combined
```

**This union has no dedup step between (A), (B), and (C).** `analyze_findings`
(A) is built by `analyze_findings.extend(rb.findings_from_analysis(ex, res))`
for every `res = await orch.analyze(ex)` call over all 37 captured exchanges
(`run_maxcov_integrated.py:306-316`) — i.e. it is the **in-memory return
value** of the same `orch.analyze()` calls that, per INV-2/INV-3's already-
established tracing of `orchestrator_detect.py`, **also persist their
findings to `store.findings` inside the same call**. `store.all_host_findings(BASE)`
(B) then re-reads those same persisted rows back from the database. Neither
list is filtered against the other before `_confirmed_classes()` counts them.
VERIFIED-in-run, from the same artifact pair: the top-level
`recall_report_integrated_full.json`'s `"totals": {"all_findings": 1914,
"confirmed": 987}` (`totals.all_findings`) is **exactly** `len(findings)`
from this same `_all_findings()` call (`run_maxcov_integrated.py:219`) — this
is the SCORECARD's own reported "1,914 fused findings" figure. Cross-checking
against the store directly: `SELECT COUNT(*) FROM findings` on the same
artifact's state DB returns **1,108** rows (VERIFIED-in-run) — i.e. list (B)
alone already accounts for the majority of the 1,914 total, and list (A) (the
in-memory PASS1 returns, 37 exchanges' worth, summing to **364** raw findings
across those exchanges per `sum(len(x['findings']) for x in
maxcov_results_integrated_full.json['analyze'])`, VERIFIED-in-run) is added
on top of it with no overlap check. Because PASS1's `analyze()` calls
persist their own returned findings into the same store the run reads back
from, (A) and (B) are **not** independent sets — every finding in (A) that
successfully persisted also appears in (B), so summing them double-counts
those findings before `_confirmed_classes()` groups by class.

**Conclusion on 641/107:** these two counts are **source-supported as a
driver-level counting artifact**, specifically `_all_findings()`'s
un-deduplicated three-way union in `run_maxcov_integrated.py`, compounded by
the fused-finding layer's own `(fingerprint, case_id)` multiplicity (§2:
29 rows / 1 fingerprint at one endpoint alone). This is traced to an actual
mechanism with cited line numbers and cross-checked artifact counts — **not**
retained as a bare unexplained aggregate — but it is **not** a verified
defect in `harness/store.py`'s dedup key itself (§1: that key's coarseness
relative to `fingerprint` alone is an intentional, documented design choice
for preserving per-attempt proof trails). The counting bug is in the
**testing driver** (`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`),
not in `harness/*.py` production code. Per the review gate ("no raw-volume
precision claims"), this trace explains **why** the raw number is inflated;
it does not and should not be read as "641 distinct verbose-error bugs exist"
nor as "0 real repeats exist" — §2 already showed at least one endpoint
(`/api/admin/debug`) where 29 raw rows genuinely do collapse to 1 structural
fingerprint by the schema's own identity, a separate, additional source of
inflation layered under the driver-level double-count.

**Not independently re-derivable to an exact 641/107 without re-running**:
this item did not attempt to reconstruct `analyze_findings`'s exact per-item
list (it is not persisted standalone in any artifact, only its aggregate
count and per-exchange `findings` sub-lists), so the *precise* split of
"driver double-count" vs "genuine (fingerprint,case_id) multiplicity" vs
"true distinct findings" within the 641/107 figures specifically is UNKNOWN
at exact-count precision — the mechanism is demonstrated with concrete,
cited numbers from the same artifact pair, but a byte-for-byte reconciliation
of 641 to N-driver-duplicated + M-store-duplicated + K-genuine would require
re-running with instrumentation this artifact does not have (§4/§5 return to
this as a ticket).

---

## 4. Runtime attribution from existing telemetry

**`harness/telemetry.py` (172 lines, read in full) contains zero timing
instrumentation.** VERIFIED-by-inspection: its only state is `_swallowed`
(a `dict[run_id, Counter]` of `"site:ExcType" -> count`,
`harness/telemetry.py:33,60-72`) and `_events` (a `dict[run_id, Counter]` of
`category -> count`, `:34,75-83`), plus a passthrough of
`coordinator.fail_open_stats()` into `snapshot()` (`:135-140`). There is no
`time.perf_counter`, no `duration`, no `elapsed` field anywhere in this
module — it answers "why did this run produce zero/few findings" (its own
docstring, `:1-25`), not "where did the wall-clock time go."

**`harness/ollama_client.py` records tokens, not time, per call.**
VERIFIED-by-inspection: `_chat()` (`:149-283`) logs `audit_logger.log_llm_prompt`
before the request (`:178-182`) and `audit_logger.log_llm_response` after a
successful parse (`:264-269`), passing `prompt_tokens`/`completion_tokens`
(from Ollama's own `prompt_eval_count`/`eval_count` response fields) — but
neither call passes a `request_id` that would let the two be correlated
per-call under concurrency, and `AuditLogger.log_llm_response`
(`harness/audit_logger.py:415-440`) does not compute or store an elapsed
duration between the matching prompt/response pair; each `AuditEvent` only
carries its own creation `timestamp` (`harness/audit_logger.py:122`), which
without a shared `request_id` cannot be reliably paired back into a
per-call latency under concurrent dispatch (multiple in-flight calls would
interleave their log lines). `self.timeout_seconds` (default 120.0s,
`:109-111`) is a **ceiling**, not a measurement.

**`harness/effort.py`'s `EffortLedger` measures tokens by call kind, not
time.** VERIFIED-by-inspection: `CallKind` (`harness/effort.py:19-27`) has
seven buckets — `ROUTING`, `AGENT_DISPATCH`, `CRITIQUE`, `VALIDATION_RETRY`,
`ESCALATION`, `PAYLOAD_LLM_FALLBACK`, `REDISCOVERY` — and `EffortLedger.record()`
(`:72-73`) stores only `(kind, model, prompt_tokens, completion_tokens)`, no
timestamp or duration field. `average_tokens()` (`:79-85`) and `breakdown()`
report token totals per kind (real, once at least one call of that kind has
happened, per the module's own docstring at `:60-68`), never wall-clock
time per kind. This is the closest existing structure to the dispatch's
requested "model calls, queue wait, validator work, retries, discovery"
breakdown — the **category axis already exists** (these seven `CallKind`
buckets map closely onto "model calls" [`AGENT_DISPATCH`/`ROUTING`/
`CRITIQUE`/`ESCALATION`], "retries" [`VALIDATION_RETRY`], and "discovery"
[`REDISCOVERY`]) — but the **time axis does not**.

**One measured time series does exist, at exchange granularity, in the
VulnCorp maxrun artifact itself** (not from `harness/telemetry.py` — this is
the driver script's own per-exchange bookkeeping): `analyze[i].elapsed_s` in
`maxcov_results_integrated_full.json`, one value per of the 37 PASS1
`orch.analyze(exchange)` calls. VERIFIED-in-run:

| Quantity | Value | Source |
|---|---|---|
| Total run wall time | 29,903.0 s (8.306 h) | `maxcov_results_integrated_full.json:"elapsed_s"` top-level field (also `recall_report_integrated_full.json:"elapsed_h"=8.306`) |
| PASS1 (`analyze()` over 37 exchanges) wall time | 6,443.4 s (1.79 h, ≈21.6% of total) | `sum(x["elapsed_s"] for x in maxcov_results_integrated_full.json["analyze"])`, 37 exchanges |
| PASS1 raw findings produced in that time | 364 | `sum(len(x["findings"]) for x in ... ["analyze"])` |
| PASS2 (`investigate_engagement`, single call) wall time | **UNKNOWN by direct measurement** — 23,459.6 s (≈6.52 h, ≈78.4% of total) only as the **residual** `total − PASS1`, not an independently measured PASS2 duration | `investigate["outcomes"][i]["elapsed_s"]` is present as a field but is **0 for every outcome** in this artifact (`sum(...) == 0`, VERIFIED-in-run) — the field exists in the schema but was never populated for the graph-driven path in this run |

**Do not assume all ~8.3h was model time** (per the dispatch's explicit
instruction): the 6,443.4s PASS1 figure itself is wall time for
`orch.analyze()`, which per `harness/orchestrator.py`'s dispatch (not
re-traced line-by-line in this item; established by prior INV items and
this module's own docstrings) includes coordinator routing, multiple agent
LLM calls, deterministic validator legs, and any confirmation-gate work for
that exchange — **not** isolated model latency. The PASS2 residual
(≈78% of total wall time) is even less attributable: per INV-3 §1.2/§2,
PASS2 includes active discovery (`engagement_builder.build_engagement`),
an iterative worklist probe, a credential-derived re-crawl loop (bounded by
`max_chain_rounds`), a second-order auto-confirmation phase (mutating
replay), and a coverage-driven leg-confirmation phase that explicitly
dispatches `sqlmap` (`validators.sqlmap.timeout_seconds: 300`,
`run_maxcov_integrated.py:104-105`) up to `coverage_leg_budget=150`
(`:91`) — a single `sqlmap` container invocation at `level=3, risk=2`
against a live target can itself run for minutes, entirely outside any LLM
call. **None of these phases' individual durations are recorded anywhere in
the inspected artifact or in `harness/telemetry.py`.**

**Missing instrumentation, named explicitly, before any concurrency change
is recommended:**

1. **Per-`CallKind` wall-clock duration** alongside the existing per-kind
   token counts in `harness/effort.py`'s `EffortLedger.record()` — the
   category axis already exists (§4 above); only the time axis is missing.
2. **A `request_id` passed through `audit_logger.log_llm_prompt`/
   `log_llm_response`** in `harness/ollama_client.py:178-182,264-269` so a
   prompt/response pair's latency is computable per-call under concurrent
   dispatch, not just per-process-in-order.
3. **Per-phase `elapsed_s` inside `investigate_engagement`** — worklist
   investigation, the credential re-crawl loop, second-order auto-
   confirmation, and the coverage-driven leg phase (the four phases
   INV-3 §1.2 already named and ordered) each need their own timer, the
   same way PASS1's per-exchange `elapsed_s` already exists in the driver
   (though even that is driver-level, not `harness/telemetry.py`-level —
   see point 5).
4. **A queue-wait / rate-limiter-wait counter** — `harness/ollama_client.py`
   constructs a `rate_limiter.get_token_limiter("ollama")` (`:141`) and
   awaits it (`async with self.rate_limiter:`, `:211`) before every call;
   whether time spent inside that `async with` block is ever queue-wait
   (rate-limited) vs. near-zero was not measured in this item — the
   rate limiter module itself was not opened (out of this item's traced
   entry points; flagged as a further read, not assumed empty).
5. **`harness/telemetry.py` itself has no run-scoped timing hook at all** —
   its `bind_current_run`/`record_event` machinery (§4 above) is
   structurally ready to carry a duration (events are already bucketed by
   `run_id`), but no call site anywhere in the traced entry points calls
   `record_event` with a timing payload; adding one is additive, not a
   concurrency change.

---

## 5. Tickets (at most three)

### Ticket 1 — Deduplicate `_all_findings()`'s three-way union in the VulnCorp maxrun driver

- **Bottleneck (source-supported, §3):** `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:149-154`,
  `_all_findings()`, concatenates `analyze_findings` (in-memory PASS1
  returns) with `store.all_host_findings(BASE)` (the same findings re-read
  from the database, since `orch.analyze()` persists what it returns) and
  `_graph_findings(investigate)`, with no dedup step. This directly inflates
  the reported "fused findings" count (1,914, matching `totals.all_findings`
  exactly, §3) and the `confirmed_by_class` breakdown (641/107, §3) used in
  `recall_report_integrated_full.md`.
- **Target metric:** `totals.all_findings` and each `confirmed_by_class[vc]`
  count should reflect **distinct** findings once, not once per source list
  they happen to appear in.
- **Smallest change:** dedupe the combined list in `_all_findings()` by
  `store.finding_fingerprint(...)`-equivalent identity (reuse
  `store.finding_fingerprint` directly, since both (A) and (B) items carry
  enough fields to recompute it, or — simpler and requiring no new import —
  dedupe by `(f.get("finding_id") or f.get("fingerprint"), f.get("case_id"))`
  before the three lists are concatenated, since `store.all_host_findings`
  already returns both fields per row (`harness/store.py:830-831`) and
  `analyze_findings` items carry `finding_id`/`case_id` too (per the sample
  finding dict read in §3). This is a driver-script change
  (`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`), **not** a
  `harness/*.py` production-code change — it is explicitly excluded from
  this item's "no production code changes" restriction because it is a
  test/measurement driver, not shipped harness behavior.
- **Positive control:** a fixture list with two dict findings sharing
  identical `(finding_id, case_id)` (simulating (A)/(B) overlap) and one
  with a different `case_id` (simulating a genuine second attempt) must
  collapse to 2, not 3, entries after the fix.
- **Negative control:** two findings with the same `vulnerability_class`
  and `url` but different `case_id` AND different `principal_id`-derived
  fingerprint (simulating genuinely distinct object/principal instances,
  per the dispatch's "a repeated class on one endpoint is not automatically
  one duplicate" instruction) must **not** collapse — both must survive.
  This mirrors §1's finding that `(fingerprint, case_id)` is the correct,
  already-existing identity to preserve, not something to loosen.

### Ticket 2 — Report both raw-row and distinct-fingerprint counts at the fused-finding layer

- **Bottleneck (source-supported, §2):** `store.finding_fingerprint`'s
  `(fingerprint, case_id)` unique index intentionally keeps one row per
  attempt (§1), but nothing downstream currently surfaces "N raw rows share
  M distinct structural fingerprints" as a countable fact — a reader of
  `recall_report_integrated_full.md`'s "x641/x107" lines, or of
  `store.all_host_findings()`'s raw length, has no way to see that (e.g.)
  29 of those rows are one structural finding under 29 different `case_id`s
  (§2, `/api/admin/debug`) without hand-running the SQL this item ran.
- **Target metric:** a new field, e.g. `distinct_fingerprint_count`,
  alongside any raw finding count a report already prints (both
  `report_generator.generate_markdown_report`'s summary line and
  `run_maxcov_integrated.py`'s `_confirmed_classes()` breakdown).
- **Smallest change:** add one function, e.g.
  `store.distinct_fingerprint_count(rows: list[dict]) -> int` (a one-line
  `len({r["fingerprint"] for r in rows})`, reusing the `fingerprint` field
  `all_host_findings` already returns per row, `harness/store.py:830-831`),
  and call it once where each existing raw count is already computed/printed
  — no change to `persist_findings`, the unique index, or any suppression/
  quarantine logic. This is additive instrumentation, not a dedup-policy
  change, so it cannot regress the append-only proof-trail property §1
  documented as intentional.
- **Positive control:** a fixture list of 5 dicts with `fingerprint` values
  `[A, A, A, B, B]` must report raw count 5, distinct-fingerprint count 2.
- **Negative control:** a fixture list of 5 dicts with 5 distinct
  `fingerprint` values (simulating 5 genuinely distinct findings, e.g. IDOR
  on 5 different `principal_id`s) must report raw count 5, distinct count
  5 — i.e. the new field must not shrink a set of genuinely distinct
  findings, only reveal repetition where it structurally exists.

### Ticket 3 — Add wall-clock duration to the existing `EffortLedger`/`CallKind` axis, and per-phase timers inside `investigate_engagement`

- **Bottleneck (source-supported, §4):** neither `harness/telemetry.py` nor
  `harness/effort.py` nor `harness/ollama_client.py` records elapsed time
  per call or per pipeline phase; the only measured time series in the
  inspected artifacts is PASS1's per-exchange `elapsed_s` (driver-level, not
  `harness/telemetry.py`), leaving PASS2's ≈78% of total run time (§4 table)
  as an unattributed residual with zero internal breakdown, and every
  `outcomes[i].elapsed_s` field in the one available PASS2 artifact reads 0
  despite the schema having a slot for it.
- **Target metric:** a `duration_seconds` (or `duration_ms`) field recorded
  alongside each existing `CallRecord` in `EffortLedger` (`harness/effort.py:46-56`),
  and one `elapsed_s` per named PASS2 phase (worklist investigation,
  credential re-crawl loop, second-order auto-confirmation, coverage-driven
  leg confirmation — the four phases INV-3 §1.2 already enumerated in call
  order) written into `investigate_engagement`'s own return dict, the same
  way each `outcomes[i]` entry already has an (unpopulated) `elapsed_s` slot.
- **Smallest change:** (a) add a `duration_ms: float = 0.0` field to
  `CallRecord` (`harness/effort.py:46-51`) and have `EffortLedger.record()`
  accept it optionally (default 0.0 preserves every existing caller); wrap
  each `OllamaClient._chat()` call site with a `time.perf_counter()` pair
  and pass the delta through to the ledger's `record()` call. (b) wrap each
  of the four named PASS2 phases in `orchestrator_chain.py::investigate_engagement`
  with `time.perf_counter()` and add the four deltas to the return dict as
  a new `"phase_seconds": {...}` key — additive, no existing key removed or
  renamed, no default/gate/threshold changed. **This does not require or
  imply any concurrency change** — it is pure instrumentation; per the
  dispatch's explicit constraint, no speedup is promised or implemented
  here, only the measurement needed before anyone could responsibly propose
  one.
- **Positive control:** a stub `OllamaClient._chat` that sleeps a known
  fixed duration (e.g. 50ms) must produce a ledger record whose
  `duration_ms` is within a generous tolerance (e.g. ±20ms) of that value,
  and a stub PASS2 phase function with a known sleep must produce a
  matching `phase_seconds` entry.
- **Negative control:** a call kind that never fires in a given run (e.g.
  `CallKind.ESCALATION` on a run with no escalations) must report
  `duration_ms` total 0 / no records, not a fabricated nonzero estimate —
  mirroring `EffortLedger.has_real_data_for()`'s existing real-vs-prior
  distinction (`harness/effort.py:87-88`), which this ticket must not
  weaken. Similarly, a PASS2 run with `engagement.coverage_drive_legs=False`
  (the shipped default) must show `phase_seconds["coverage_driven"] == 0`
  and the phase's own stand-in must show zero invocations, not merely zero
  time (mirroring INV-3 §4's negative control 2 pattern for the same gated
  phase).

**Ablation note (review gate compliance):** none of these three tickets
proposes removing an agent specialist, changing a default, or promising an
unmeasured speedup. Ticket 3 explicitly creates the measurement the dispatch
says must exist **before** any concurrency change is proposed; it does not
itself change scheduling, concurrency, or which agents run.

---

## Limitations

- **No live execution occurred in this item.** All dedup-key and telemetry
  claims are from reading source at current HEAD (`21f9b37`); all VulnCorp-
  side numbers are from reading an already-completed run's on-disk
  artifacts (JSON dump + read-only SQL queries against that run's own
  SQLite file, opened `mode=ro`) — nothing was re-run, re-scored, or
  modified.
- **The VulnCorp maxrun artifacts are from a different revision** (`eb70210`,
  `.worktrees/integration-measure`, per INV-1) than current HEAD (`21f9b37`).
  §1's dedup-key/layer map is VERIFIED against **current HEAD**; this item
  did not diff `store.py`/`report_generator.py`/`issues.py`/
  `confirmation_gate.py` between the two revisions, so whether the exact
  `(fingerprint, case_id)` schema was already in place at `eb70210` is
  SUPPORTED (the `store.py:14-16` `_FINGERPRINT_ALGO_VERSION` migration
  machinery implies this is a stable, versioned schema, not freshly added)
  but not independently re-run against that revision's own code.
- **The precise numeric split of the 641/107 figures into
  "driver-double-count" vs "store (fingerprint,case_id) multiplicity" vs
  "genuinely distinct findings" is UNKNOWN at exact-count precision** (§3) —
  the mechanism for each contributing factor is demonstrated with concrete,
  cited counts from the same artifact pair (1,914 total = `len(findings)`
  from the union; 1,108 store rows; 364 PASS1 in-memory findings; 638 raw
  rows / 58 distinct fingerprints for the disclosure family; 29 rows / 1
  fingerprint at one endpoint), but a full reconciliation to 641 and 107
  specifically would require artifacts this run did not produce (the raw
  `analyze_findings` list is not persisted standalone) or a fresh
  instrumented re-run (out of this item's offline, no-live-execution scope).
- **`harness/rate_limiter.py` (queue-wait candidate) was not opened in this
  item** — named as a further read in §4's missing-instrumentation list
  (point 4), not assumed to already measure or not measure queue wait.
- **`normalize_path` (used by `issues.issue_key`'s `endpoint_family`
  component, §1) was not independently re-read in this item** — its
  behavior is taken on the strength of `issues.py`'s own docstring comment
  at the `issue_key` call site (`issues.py:220-221`, "endpoint FAMILY,
  object ids collapsed") and `report_generator._dedup_key`'s matching
  docstring (`report_generator.py:273-279`), not a line-by-line reading of
  `normalize_path`'s implementation.
- **This item did not open `vulncorp_ground_truth.py`** or any blind
  target's `app.py`. All artifact reads used the same harness-generated
  reports and read-only SQLite access pattern INV-1/INV-3 established as
  safe; `run_maxcov_integrated.py` was read as driver source text only, and
  neither it nor `recall_benchmark.py` (imported by it, not itself opened
  in this item) was executed or imported here.
- **No production database was written.** All SQLite access in this item
  used `mode=ro` URI connections; the working tree's untracked-file list is
  unchanged from the state recorded at the top of this document except for
  the new file this item was asked to produce.

---

## Validation

- No executable code was added by this item (documentation only, per the
  dispatch's rule: "If you add NO executable code, say so and skip the
  suite" — skipped; `harness.suite smoke`/`full` were not run).
- `git diff --check` — run against the working tree; the new file is
  untracked until staged.
- Every local path/symbol cited above (`harness/host_dep_dedup.py`,
  `harness/store.py`, `harness/report_generator.py`, `harness/issues.py`,
  `harness/confirmation_gate.py`, `harness/telemetry.py`,
  `harness/ollama_client.py`, `harness/effort.py`, `harness/audit_logger.py`,
  `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`) was confirmed
  to exist in this checkout via direct `Read`/`Grep` at the stated line
  numbers (current HEAD `21f9b37`), not assumed from memory or from the
  dispatch's own entry-point list.
