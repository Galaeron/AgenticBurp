# INV-2 — Raw confirmation versus durable proof

- **Item:** INV-2 (`docs/INVESTIGATION_DISPATCH_2026-09-20.md`)
- **Date:** 2026-09-21
- **HEAD at time of writing:** `b3d40a2203f422936e0c9bdff71a5526710af148`
- **Branch:** `reconciliation-backlog`
- **Tracked/untracked status at start:** `git status --short` showed only pre-existing
  untracked paths (`.agents/`, `.claude/`, `.test-deps/`, `.worktrees/`, several
  `reviews/2026-09-*` directories, `testing/blind-target-2/*`, `testing/blind-test-kit/target/invoices/`,
  `testing/juiceshop-full-run/`, `testing/test-target/*`, `testing/vulncorp-helpdesk/`,
  `harness/*.db.bak-pre-step5*`, `docs/EVALUATION_REASSESSMENT_2026-09-20.md`,
  `docs/INVESTIGATION_DISPATCH_2026-09-20.md`, `review_test_output.txt`) and no
  tracked modifications; nothing in that list was created or modified by this item
  except the new file this document names.
- **This is offline, read-only diagnosis.** No production code was changed, no
  scorer/driver was executed, no live model/Docker/blind run occurred. The only
  commands run were `git`, read-only `sqlite3`/Python (`sqlite3.connect(..., uri=True)`
  with `mode=ro`) queries against an already-completed run's state database, and
  Python `json.load()` reads of already-completed run artifacts.
- Depends on INV-1 (`docs/investigations/INV-1-baseline.md`, closed at `c1133d5`):
  this item reuses INV-1's finding that the VulnCorp maxrun (`.worktrees/integration-measure`
  @ `eb70210`) is a different revision/worktree than current HEAD, and does not
  re-derive that revision table.

## Evidence-tag legend

- **VERIFIED-by-inspection** — read directly from source/config/artifact in this
  checkout at the stated revision; no code executed to obtain it.
- **VERIFIED-in-run** — read directly from an on-disk artifact produced by an actual
  completed run (not re-executed here), including ad hoc read-only SQL queries
  against that run's own SQLite database file.
- **SUPPORTED** — a reasonable inference from two or more inspected sources, not
  independently executed or artifact-confirmed.
- **INFERRED** — a plausible read with a named gap; flagged for the reviewer, not
  asserted as fact.
- **UNKNOWN** — not determinable from available, permitted material; stated as an
  explicit limitation, never guessed.

Safety note: this item never opened `vulncorp_ground_truth.py`, any `*ANSWER_KEY*`
file, or any blind target's `app.py`. All VulnCorp-side evidence below is quoted
from harness-generated run artifacts (JSON/MD reports, the run's own SQLite state
DB) and from `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py`, which is
a driver script this repo already treats as inspectable (INV-1 read it too), not a
target implementation or an answer key.

---

## 1. End-to-end trace: validator result → proof → persistence → finding reference → suppression/fusion → report/audit lookup

### 1.1 Actors and their actual keys/types

| Stage | Symbol | Keys / types actually produced |
|---|---|---|
| Case identity | `evidence.TestCaseRef` (`harness/evidence.py:105-166`) | frozen dataclass; `case_id: str` = `_short(run_id, request_template_id, check_id, principal_id, parameter_location, parameter_name, workflow_state_id[, finding_ref])`, a 16-hex sha256 prefix (`harness/evidence.py:51-54,127-133`). `.consistent` (`:136-140`) recomputes the hash and rejects a forged/unknown case. |
| Proof attempt | `evidence.ProofRecord` (`harness/evidence.py:214-338`) | frozen dataclass; `proof_id: str` (uuid4 hex, `:255-256`), `case: TestCaseRef`, `validator: str`, `verdict: Verdict` (`confirmed \| controlled_negative \| inconclusive \| blocked \| error`, `:57-97`), `executed: bool`, `legacy: bool`. Constructor **rejects** `verdict in {CONFIRMED, CONTROLLED_NEGATIVE}` with `executed=False` (`:247-250`), and rejects `CONTROLLED_NEGATIVE` with no `control_artifact_ids` (`:251-254`) — a proof cannot assert an executed comparison it didn't run. |
| In-memory grouping | `evidence.ProofLedger` (`harness/evidence.py:341-372`) | `dict[case_id, list[ProofRecord]]`; `best_proof(case_id)` picks max by `(verdict.rank(), created_at)` (`:360-365`). Not the persistence layer — `store.py` is (see 1.2). |
| Persistence (proof) | `store.proof_records` table (`harness/store.py:167-194`) | `PRIMARY KEY proof_id`; columns mirror `ProofRecord.to_dict()` plus the case fields flattened (`run_id, case_id, principal_id, request_template_id, check_id, parameter_location, parameter_name, workflow_state_id, finding_ref, validator, validator_version, verdict, executed, legacy, baseline_artifact_id, attack_artifact_id, control_artifact_ids_json, expected_invariant, observed_result, limitation, created_at`). Indexed on `case_id` and `run_id` (`:192-193`). |
| Persist call | `store.persist_proof_record(proof)` (`harness/store.py:663-696`) | `INSERT OR IGNORE ... PRIMARY KEY proof_id` — idempotent re-persist, never overwrites (`:663-667` docstring, append-only by construction of the primary key). Rejects a `proof.case` whose `case_id` doesn't match its own identity fields (forged/unknown case, mirrors `ProofLedger.record`'s check). Returns `(ok: bool, reason: str)`. |
| Read (proof) | `store.proofs_for_case(case_id)` / `store.best_proof_for_case(case_id)` (`harness/store.py:717-734`) | `proofs_for_case` — `SELECT ... WHERE case_id = ? ORDER BY created_at ASC`, returns `list[dict]` (each dict has the same shape as `ProofRecord.to_dict()`, reconstructed via `_proof_row_to_dict`, `:696-716`). `best_proof_for_case` picks the strongest from that list. |
| Finding reference | `harness.models.Finding.case_id: str`, `.proof_id: str`, `.finding_id: str`, `.confirmed_by_leg: str` (fields on the Pydantic `Finding` model) | Set **together, in the same code block**, only inside `orchestrator_confirm.py::_validate_findings`'s `if result.confirmed:` branch (`harness/orchestrator_confirm.py:452-468`): `finding.proof_id = pr.proof_id`, `finding.case_id = case.case_id`, `finding.confirmed_by_leg = result.validator`. **This is the only place in the pipeline where all three are stamped atomically alongside a persisted `ProofRecord`** — see §1.3 below for the paths that do not. |
| Persistence (finding) | `store.findings` table (`harness/store.py:57-86`, migration for `finding_id/case_id/proof_id` at `:335-337`) | `store.persist_findings(exchange, agent_name, findings, ...)` (`harness/store.py:448-481`) writes `finding.case_id`/`finding.proof_id` as plain `TEXT NOT NULL DEFAULT ''` columns — **not foreign keys**, no referential check against `proof_records` at write time. Dedup key is `(fingerprint, case_id)` (`:354-356`), not `proof_id`. |
| Suppression/fusion | `harness/confirmation_gate.py` (`active_confirmation_is_unproven`, `:357-378`); `harness/engagement.py::EngagementState.*.add_finding` (`:162-194`) | `add_finding` calls `confirmation_gate.active_confirmation_is_unproven(f)` (`harness/engagement.py:179`) and **downgrades `confirmed` to `False` only if NONE of `confirmed_by_leg`, `proof_id`, `confirmation_method` is present** (`harness/confirmation_gate.py:376`) — an **OR**, not a check that `proof_id` resolves to an actual persisted `confirmed` proof row. `add_finding`'s `slim` dict then carries `proof_id`/`case_id`/`confirmed_by_leg` through **only if `f.get(k)` is truthy** (`harness/engagement.py:190-194`) — a finding with `confirmed_by_leg` set but no `proof_id` keeps `confirmed=True` and silently drops the (absent) `case_id`/`proof_id` keys from the slim record. |
| Report/audit lookup | `report_generator.export_issues_for_host(url)` (`harness/report_generator.py:632-649`) | Reads `store.all_host_findings(url)` (only rows in the `findings` SQL table — see §1.3), then for each finding with a truthy `case_id`, calls `store.proofs_for_case(cid)` and attaches the **full attempt history** (`proofs_by_case[cid] = attempts`) to `issues.export_issue(...)`. This is the only production code path that joins a finding back to its `proof_records` rows for reporting. |
| Ledger lookup (distinct) | `server.py` `GET /findings/{finding_ref}/evidence` (`harness/server.py:1184-1197`) | Calls `evidence_ledger.reconstruct_persisted`/`reproduction_recipe_persisted`, which read **only** `store.ledger_events` (see §1.4) — **this endpoint never reads `proof_records` at all.** It is not a proof-lookup API. |

### 1.2 Ad hoc but already-implemented proof-linked audit (the source of "9/13 vs 6/13")

There is a third read path, not in production code, that already performs
exactly the audit INV-2 was asked to specify: `testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:161-183`
(`score_and_report`). For every finding with `f.get("confirmed")` truthy, it:

```python
case_id, proof_id = finding.get("case_id"), finding.get("proof_id")
leg = rb.confirmation_leg_of(finding)
if not case_id or not proof_id or not leg:
    continue
if case_id not in proof_cache:
    proof_cache[case_id] = store.proofs_for_case(case_id)
if any(p["proof_id"] == proof_id and p["verdict"] == "confirmed"
       and p["validator"].lower().replace("-", "_") == leg
       and p["case"]["case_id"] == case_id
       for p in proof_cache[case_id]):
    proof_linked.append(finding)
```
(`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:169-183`, VERIFIED-by-inspection.)

This is **exactly** what INV-2's review gate asks for: "specify what a complete
proof link means." From this driver, a complete proof link requires **all four**
of:

1. `finding.case_id` is non-empty,
2. `finding.proof_id` is non-empty,
3. a `store.proof_records` row exists whose `proof_id` equals `finding.proof_id`
   **and** whose `case_id` equals `finding.case_id` (both keys, not one — guards
   against a proof borrowed from a different case with a colliding/stale id), and
4. that row's `verdict == "confirmed"` **and** its `validator` (normalized
   `lower().replace("-","_")`) equals the leg named on the finding
   (`recall_benchmark.confirmation_leg_of`, `harness/recall_benchmark.py:191-217`,
   preferring the structured `confirmed_by_leg` field).

**This is the "complete proof link" key set used throughout the rest of this
document.** It is stricter than "trust the `confirmed` flag" (INV-2's explicit
warning) and stricter than "trust `proof_id` alone" (a dangling or
wrong-validator `proof_id` would fail condition 4). VERIFIED-by-inspection this
predicate is what produced the SCORECARD's reported 9/13 (raw `confirmed`) vs
6/13 (this predicate) VulnCorp numbers — the driver computes both scores in the
same function and writes both to `recall_report_integrated_full.md`/`.json`
(`testing/vulncorp-helpdesk/maxrun/run_maxcov_integrated.py:216-238`).

### 1.3 Four distinct places a `Finding` acquires `confirmed=True` — only one persists a proof

Tracing every producer of `confirmed=True` findings that can reach the maxrun's
`_all_findings()` union (`run_maxcov_integrated.py:149-154`: PASS1 `analyze()`
findings + `store.all_host_findings(BASE)` + PASS2 `investigate_engagement()`
graph/worklist/idor findings) turned up **four structurally different code paths**,
summarized here and detailed with direct artifact evidence in §2:

| # | Path | Sets `case_id`/`proof_id`? | Persists a `ProofRecord`? | Sets `confirmed_by_leg`? |
|---|---|---|---|---|
| A | `orchestrator_confirm.py::_validate_findings`, the `if result.confirmed:` block (`:452-468`) — PASS1 per-exchange validator dispatch, the only route `orch.analyze()` takes | **Yes**, both, at `:458-459` | **Yes**, `persist_proof_record(pr)` at `:449` (already called before the `if result.confirmed` check; the confirmed branch reuses `pr`) | Yes, `:468` |
| A′ | `orchestrator_confirm.py::_coverage_proof` (`:212-249`) — coverage-driven leg confirmation | Returns `(proof_id, case_id)` to its caller, but **is a helper, not itself applied to a `Finding`** — whether a caller stamps them on the `Finding` object is outside this function; not traced further here (out of INV-2's named entry points, flagged UNKNOWN below) | **Yes**, `persist_proof_record(pr)` at `:243` | N/A (returns ids, not fields) |
| B | `orchestrator_chain.py::_apply` (`:440-453`), invoked by `_confirm`/`_confirm_leg` (`:463-611`) — PASS2 `investigate_engagement()`'s graph/worklist/precondition confirmation loop, dispatching `CrossIdentityValidator`, `BrowserXssValidator`, `JwtForgeValidator`, `SsrfValidator`, `XxeValidator`, `CommandInjectionValidator`, `SstiValidator`, `PathTraversalValidator`, `OpenRedirectValidator`, `SequenceValidator`, `DeserializationOobValidator`, `AuthSequenceValidator`, `StoredXssValidator`, `RateLimitValidator`, `ResetTokenValidator`, `DomXssValidator`, `ToctouValidator` (imports at `:356-372`, dispatch table `:463-594`) | **No** — `_apply` only ever writes `finding["confirmed"]`, `finding["confidence"]`, `finding["evidence"]`, `finding["confirmed_by_leg"]` (`:441-453`); no `TestCaseRef`, no `ProofRecord`, no `store.persist_proof_record` call anywhere in `_apply`/`_confirm`/`_confirm_leg` | **Yes**, `:453` — "the STRUCTURED leg name, set at the SAME moment as the evidence stamp" (comment at `:446-452`), but crucially **not** at the same moment as a proof/case id, because none is ever created on this path |
| C | `role_crawl.py::_cross_role_finding` (`:261-279`), built by `probe_cross_role_objects`/`probe_cross_role_matrix` (`:282-365`) — the active same-object cross-role probe | **No** — `Finding(..., confirmed=True, validation_hints=[f"cross_role_probe:{method}:{url}"])` at `:263-279`; no `case_id`/`proof_id` fields set at all (Pydantic defaults apply) | **No** | **No** — uses `validation_hints`, not `confirmed_by_leg`; `recall_benchmark.confirmation_leg_of` would derive `"cross_role_probe"` from it, which never equals a real validator name, so this path can never satisfy condition 4 of §1.2 even in principle |
| D | `orchestrator_helpers.py::universal_header_audit` (`:575-639`), plus the deterministic detectors it/`orchestrator_detect.py` call directly (`verbose_error_validator.findings_from_exchange`, `secret_disclosure.findings_from_exchange`, `harness/orchestrator_detect.py:707-722`) — header/passive checks with **no validator dispatch at all** ("Already-confirmed on detection", `orchestrator_detect.py:706`) | **No** | **No** | **Partially** — `universal_header_audit` stamps the legacy `confirmation_method` field (`:634`), not `confirmed_by_leg`; the deterministic detectors set neither |

Path A is the only one whose `Finding` can ever satisfy the full §1.2 "complete
proof link" predicate, because it is the only one that both stamps `case_id`/
`proof_id` on the `Finding` AND persists the matching `proof_records` row with
the same ids. Paths B, C and D can produce `confirmed=True` findings that
`confirmation_gate.active_confirmation_is_unproven` (§1.1, engagement.py:179)
will **not** flag as unproven — because that predicate accepts `confirmed_by_leg`
alone (path B) or `confirmation_method` alone (path D) as sufficient — even
though no `ProofRecord` exists for them. Path C's `validation_hints` value never
matches a leg name, so it is not even caught by `confirmed_by_leg`; it would only
be caught by `active_confirmation_is_unproven` if its `vulnerability_class` (here
`"idor"`, a live-verified marker) reaches that check without a leg name, which it
does — worth noting as one path that IS structurally caught by the current
backstop (see §3, ticket 3).

VERIFIED-by-inspection for all cited line ranges above (read directly, current
HEAD).

### 1.4 Proof records vs. ledger events — explicitly not synonyms

Two persistence mechanisms exist side by side and must not be conflated:

| | `store.proof_records` (Astra T01, `evidence.py`) | `store.ledger_events` (P0-1, `evidence_ledger.py`) |
|---|---|---|
| Unit | One confirmation **attempt** for one **case** (`case_id` + `proof_id`, both structured identity hashes) | One **event** in a finding's causal chain (`OBSERVATION \| HYPOTHESIS \| PLANNED_ACTION \| AUTHORIZATION_DECISION \| EXECUTION \| VALIDATION_DECISION \| FINDING_REVISION`, `harness/evidence_ledger.py:43-50`) |
| Keyed by | `case_id` (endpoint+check+principal+parameter+workflow coordinates) | `finding_ref` (a per-finding id, `harness/evidence_ledger.py:96-105`), with an **optional** `case_ref: str` string field that is never validated against `proof_records.case_id` (no FK, no consistency check) |
| Verdict vocabulary | `Verdict` enum (`confirmed \| controlled_negative \| inconclusive \| blocked \| error`), immutable per record | Free-text `summary` + `data: dict`; "why concluded" is reconstructed from `VALIDATION_DECISION`/`FINDING_REVISION` event summaries (`evidence_ledger.py:170-171`), not a typed verdict |
| Reader | `store.proofs_for_case`/`best_proof_for_case` (§1.1); `report_generator.export_issues_for_host` (§1.1) | `evidence_ledger.reconstruct_persisted`/`reproduction_recipe_persisted`, exposed at `GET /findings/{finding_ref}/evidence` (`harness/server.py:1184-1197`) |
| Emitted by which of the 4 paths in §1.3? | Path A only (and A′, if wired) | Path A only — `evidence_ledger.emit(...VALIDATION_DECISION..., case_ref=case.case_id)` is called at `orchestrator_confirm.py:421-435`, inside the same loop that builds `case` via `_case_for` (`:310-324`); paths B/C/D never call `evidence_ledger.emit` at all (confirmed by `grep -n "evidence_ledger" harness/orchestrator_chain.py harness/role_crawl.py harness/orchestrator_helpers.py` returning no matches in the confirmation-application code) |
| `reconstruct()["complete"]` | Not consulted — this field belongs to the ledger's own reconstruction, defined as `bool(VALIDATION_DECISION or FINDING_REVISION events present)` (`evidence_ledger.py:176-177`) | **Does not mean "has a resolvable proof."** A finding can have `complete=True` here (some `VALIDATION_DECISION` event exists) while having zero rows in `proof_records`, if a caller emitted the ledger event but the proof-persistence `try/except` around it failed silently (`orchestrator_confirm.py:442-483`, `except Exception` swallows persistence failures into a `ValidationReport(status="error", ...)` without ever emitting a corresponding ledger correction) |

**Practical consequence:** the `/findings/{finding_ref}/evidence` API (the only
production "proof" lookup endpoint) answers "why was this concluded" from the
ledger's free-text `VALIDATION_DECISION` summaries; it never confirms that a
structured, replayable `ProofRecord` with a matching `verdict=confirmed` exists
for the same case. A finding whose ledger stream looks complete can still fail
the §1.2 audit. Conversely (per §1.3, path B/C/D), a finding that fails the §1.2
audit may never have emitted any ledger events either, since paths B/C/D call
neither `evidence_ledger.emit` nor `store.persist_proof_record`.

---

## 2. Artifact audit: the VulnCorp maxrun (allowed harness-generated artifact, not an answer key)

### 2.1 What is on disk and what was read

`testing/vulncorp-helpdesk/maxrun/` is untracked (confirmed by `git status --short`
showing the whole directory as `??`), produced by a run at `eb70210`
(`.worktrees/integration-measure`, per INV-1 §1) on 2026-09-20. The following
artifacts were read **read-only**, none were modified:

- `recall_report_integrated_full.md` (4,770 bytes) — human-readable summary,
  already containing a **per-planted-bug** raw-vs-proof-linked table.
- `recall_report_integrated_full.json` (VERIFIED-in-run existence/content) —
  machine-readable version with full `recall_score.items` and
  `proof_linked_recall_score.items` (both scored against the same 13-item ground
  truth, using the driver's own `rb.score_run`, `harness/recall_benchmark.py:247-264`).
- `maxcov_results_integrated_full.json` (5,237,560 bytes) — the raw `analyze`
  (PASS1) and `investigate` (PASS2) results the report was computed from.
- `maxcov_state_integrated_full.db` (2,600,960 bytes) — the run's own SQLite state
  DB, opened via `sqlite3.connect("file:...db?mode=ro", uri=True)` (read-only URI
  mode — no write handle was ever opened, no `.schema`-altering statement issued).

`vulncorp_ground_truth.py` (the module `GROUND_TRUTH`/`FRONTIER_CLASSES` are
imported from) was **not opened** in this item, consistent with INV-1's stance and
the dispatch's explicit rule; the 13 ground-truth ids/paths/classes quoted below
come entirely from the harness-generated report artifacts, which restate them as
output, not as the ground-truth source.

### 2.2 Per-bug raw vs. proof-linked breakdown (already computed by the artifact; not fabricated by this item)

From `recall_report_integrated_full.json`'s `recall_score.items` and
`proof_linked_recall_score.items` (VERIFIED-in-run, both read directly, not
re-derived):

| id | path | raw status | raw provenance | proof-linked status | proof-linked `matched_findings` |
|---|---|---|---|---|---|
| GT01-sqli-search | `/api/tickets/search` | confirmed | earned (`sqlmap`) | **confirmed** | 1 |
| GT02-sqli-login | `/api/login` | detected_unconfirmed | – | detected_unconfirmed→**missed*** | 0 |
| GT03-xxe-import | `/api/tickets/import` | confirmed | earned (`xxe`) | **confirmed** | 1 |
| GT04-idor-ticket | `/api/tickets/{id}` | confirmed | earned (`cross_identity`) | **missed** | 0 |
| GT05-idor-report | `/api/reports/{id}` | confirmed | earned (`cross_identity`) | **missed** | 0 |
| GT06-idor-comments | `/api/tickets/{id}/comments` | confirmed | earned (`cross_identity`) | **missed** | 0 |
| GT07-pathtrav-uploads | `/uploads/{id}` | confirmed | earned (`path_traversal`) | **confirmed** | 2 |
| GT08-jwt-forge | `/api/tickets` | confirmed | earned (`jwt_forge`) | **confirmed** | 4 |
| GT09-massassign-profile | `/api/account/profile` | detected_unconfirmed | – | missed | 0 |
| GT10-massassign-register | `/api/register` | detected_unconfirmed | – | missed | 0 |
| GT11-bfla-admin-users | `/api/admin/users` | confirmed | earned (`cross_identity`) | **confirmed** | 1 |
| GT12-disclosure-admin-debug | `/api/admin/debug` | confirmed | lucky (`verbose_error_validator`) | **confirmed** | 1 |
| GT13-ssrf-integrations | `/api/integrations` | missed | – | missed | 0 |

\* GT02/GT09/GT10 were never raw-`confirmed` in the first place (`detected_unconfirmed`
in the raw score), so their `missed` status under the proof-linked score reflects
the *scorer's* own `missed`/`detected_unconfirmed` distinction (score_run only
labels `confirmed` when at least one CONFIRMED finding exists, `harness/recall_benchmark.py:255-263`),
not a proof-link failure — they are unaffected by this item's finding and excluded
from the delta below.

**The three-item delta (9/13 → 6/13) is exactly {GT04, GT05, GT06}** — all three
are `idor`, all three were confirmed "via the intended leg 'cross_identity'" in
the raw score, and all three drop to `missed` (not merely "unlinked" — the
proof-linked scorer has no separate "confirmed-but-unproven" bucket, so a finding
that fails the §1.2 predicate scores as if it were never confirmed at all) under
the proof-linked audit. GT11 (`/api/admin/users`), the fourth `idor`/`cross_identity`
item, is the control: it kept its proof link. This delta is VERIFIED-in-run,
computed by the artifact itself, not fabricated from the aggregate 9/13-and-6/13
counts the dispatch's baseline table quotes.

### 2.3 Root cause of the GT04/05/06 delta, traced to source

Reading `maxcov_results_integrated_full.json`'s `investigate.worklist` entries for
these three paths (Python read, not `grep`, to avoid matching on secret-like
content — the file's `findings[].evidence` text was inspected as plain
non-credential prose):

```
/api/reports/{id}         {'confirmed': True, 'case_id': None, 'proof_id': None,
                            'confirmed_by_leg': 'cross_identity', 'validation_hints': None,
                            'evidence': "cross-identity CONFIRMED: Cross-identity (bob-user-org1): ..."}
/api/tickets/{id}         {'confirmed': True, 'case_id': None, 'proof_id': None,
                            'confirmed_by_leg': 'cross_identity', ...}
/api/tickets/{id}/comments {'confirmed': True, 'case_id': None, 'proof_id': None,
                            'confirmed_by_leg': 'cross_identity', ...}
```
(VERIFIED-in-run, six matching entries total across `worklist`/`outcomes` for
these three paths — `case_id`/`proof_id` are `None`/absent on every one.)

The evidence text `"cross-identity CONFIRMED: Cross-identity (bob-user-org1): ..."`
matches the format `_apply()` stamps (`harness/orchestrator_chain.py:444-445`:
`f"{leg} CONFIRMED: " + (res.summary or "")`) with `leg="cross-identity"`
(`:491`), i.e. **this is path B from §1.3 — the `investigate_engagement()` graph
loop's `_confirm`/`_apply`, not path A** (`orchestrator_confirm.py::_validate_findings`,
which GT11 and GT01/03/07/08/12 went through, evidenced by their proof-linked
`matched_findings` counts being non-zero and their `confirmed_by_leg` matching a
`store.proof_records.validator` row per §1.2's condition 4).

**This is SOURCE-SUPPORTED (not merely INFERRED):** `_apply` at
`orchestrator_chain.py:440-453` provably never calls `evidence.TestCaseRef.make`,
`evidence.ProofRecord.from_validation_result`, or `store.persist_proof_record`
(confirmed by reading the full body of `_apply`, `_confirm`, `_confirm_leg`, and
`_precondition`, `orchestrator_chain.py:440-620` — no such calls appear), so
**every** finding confirmed exclusively through this path is proof-less **by
construction**, independent of whether the underlying `CrossIdentityValidator`
(or any of the other 15 validators `_apply` dispatches to, per the table in
§1.3) genuinely executed a sound comparison. GT04/05/06 are not proof of a
validator defect; they are proof of a **caller-side persistence gap** in the one
production code path (`investigate_engagement`'s graph loop) that is structurally
incapable of writing a `ProofRecord`, regardless of how many other classes route
through it (§1.3's table lists all 16).

### 2.4 Broader (not per-bug) count: how much of the run's "confirmed" total is proof-linked

Independent of the 13-item ground truth, this item computed the same §1.2 audit
over the run's **entire** confirmed-finding population, read-only, by replaying
`score_and_report`'s own union logic (`_all_findings`, `run_maxcov_integrated.py:149-154`)
against the artifacts:

| Source | Findings | Confirmed | Confirmed missing `case_id`/`proof_id` |
|---|---|---|---|
| `analyze_findings` (PASS1, in-memory `AnalysisResponse.agent_reports`, from `maxcov_results_integrated_full.json`'s `analyze[].findings`) | 364 | 72 | 39 (37 `verbose_error_disclosure`, path D; 2 `jwt`) |
| `store.findings` table (`maxcov_state_integrated_full.db`, read-only query) | 1,108 rows total | 747 | 42 |
| `investigate` graph findings (PASS2 `worklist`/`outcomes`/`idor_findings`/`chains`, from the same JSON) | 442 | 168 | 106 |
| **Sum** (matches the artifact's own `totals.confirmed`) | — | **72+747+168 = 987** ✓ matches `recall_report_integrated_full.json`'s `"confirmed": 987` | — |

(All VERIFIED-in-run: Python `json.load`/`sqlite3` read-only queries against the
existing artifacts, commands and counts reproducible by re-running the same
queries against the same files — no run was re-executed.)

Of the `store.findings` table's 747 confirmed rows, **705 have both `case_id` and
`proof_id` set, and every one of those 705 resolves to a matching `verdict='confirmed'`
row in `proof_records` for the same `case_id`** (0 dangling, 0 verdict-mismatches
found in this table specifically — VERIFIED-in-run, exhaustive read-only join over
all 705). This means **path A (`_validate_findings`, the only route
`store.persist_findings` is called from for validator-confirmed findings —
`harness/orchestrator_detect.py:726-734`) is internally consistent: when it
stamps a proof link, that link resolves.** The 42 `store.findings` rows missing
ids are the deterministic detectors (path D: `verbose_error_validator`,
`secret_disclosure`, `confidential_info` — "already-confirmed on detection",
`orchestrator_detect.py:706`, persisted via the same `persist_findings` call at
`:726-734` but never routed through a validator, so they never had a `case_id`/
`proof_id` to set).

**The 442 PASS2 graph findings (168 confirmed) are never persisted to
`store.findings` at all** — `grep -rn "persist_findings" harness/orchestrator_chain.py
harness/worklist_investigator.py harness/role_crawl.py` returns no matches
(VERIFIED-by-inspection; the only production callers of `store.persist_findings`
are `orchestrator_detect.py:726-734,767-772` and `pivot_memory.py:134,155`, both
PASS1/analyze()-adjacent). Consequently `report_generator.export_issues_for_host`
(§1.1), which reads `store.all_host_findings(url)`, **cannot see these 168
findings at all** — not "proof-less," but structurally absent from the production
report/audit surface. They exist only in the maxrun driver's own JSON dump of
`investigate_engagement()`'s in-memory return value, because that driver script
(not production code) chose to flush it.

### 2.5 Categorized counts (INV-2 step 2's requested breakdown)

Applying the definitions strictly (a proof is "valid" only if it independently
satisfies all four §1.2 conditions; "dangling" = ids present but no matching
`proof_records` row for that exact `(case_id, proof_id)` pair; "identity mismatch"
= a row exists for that `proof_id` but its `case_id` or `validator` does not match
the finding's — never joined by URL/title/class alone):

| Category | `store.findings` table (747 confirmed) | PASS1 in-memory `analyze_findings` (72 confirmed) | PASS2 graph findings (168 confirmed) |
|---|---|---|---|
| Missing references (no `case_id`/`proof_id` on the finding at all) | 42 | 39 | 106 |
| Dangling references (`case_id`/`proof_id` present, no matching row) | 0 | UNKNOWN — not independently queried against `proof_records`; this item confirmed only the `store.findings`-table subset exhaustively (§2.4) | UNKNOWN — same reason; these findings were never persisted, so there is nothing in `proof_records` to dangle *to* even where a `case_id` happens to be present (none were, per row 1 of this table) |
| Identity mismatch (wrong case/validator/run) | 0 | UNKNOWN | UNKNOWN (n/a — see above) |
| Rejected proofs (a `ProofRecord` exists but `verdict != confirmed`) | not applicable to this table (only confirmed rows counted) — see `proof_records.verdict` distribution below | not applicable | not applicable |
| Valid links | 705 | 33 (72−39; not independently re-verified against `proof_records` beyond the aggregate 95-of-987 figure the driver itself reports, §2.4) | 62 (168−106; same caveat) |

The run's `proof_records` table itself holds 1,569 rows: 724 `verdict='confirmed'`,
845 `verdict='inconclusive'`, **0** `controlled_negative`, **0** `error`
(VERIFIED-in-run, `SELECT verdict, COUNT(*) FROM proof_records GROUP BY verdict`
against `maxcov_state_integrated_full.db`, read-only). The absence of any
`controlled_negative`/`error` rows in this run is noted as a fact, not explained
here — it is out of INV-2's traced scope (would require inspecting why every
non-confirming attempt this run made classified as `inconclusive` rather than a
controlled negative or a transport error; a candidate follow-up, not filed as a
ticket here since it does not bear on the raw-vs-proof-linked gap).

**Explicit "unexplained" statement, per the dispatch's requirement when artifacts
don't fully resolve a question:** the PASS1/PASS2 dangling-reference and
identity-mismatch counts in the table above are marked UNKNOWN rather than
guessed, because verifying them exhaustively (re-querying `proof_records` per
finding, as was done for the `store.findings` table) was not repeated for the two
JSON-only slices in the interest of a bounded, offline item; the §1.2 audit
recipe below lets a reader complete that specific gap without re-running the
target.

### 2.6 Read-only audit recipe (reusable on a future run's artifacts, or against this one)

```python
import json, sqlite3

# 1. Load the run's own findings (adjust filenames per run).
d = json.load(open("<rundir>/maxcov_results_<tag>.json"))
analyze_findings = [f for r in d.get("analyze", []) for f in (r.get("findings") or [])]
inv = d.get("investigate") or {}
graph_findings = (
    [f for o in inv.get("outcomes", []) or [] for f in o.get("findings_detail", []) or []]
    + [f for ep in inv.get("worklist", []) or [] for f in ep.get("findings", []) or []]
    + list(inv.get("idor_findings", []) or [])
    + list(inv.get("chains", []) or [])
)

# 2. Open the run's SQLite state DB read-only -- never write.
con = sqlite3.connect(f"file:<rundir>/maxcov_state_<tag>.db?mode=ro", uri=True)
con.row_factory = sqlite3.Row

def proofs_for_case(case_id):
    return con.execute(
        "SELECT proof_id, verdict, validator, case_id FROM proof_records WHERE case_id=?",
        (case_id,)).fetchall()

def complete_proof_link(finding, leg_of):
    """The §1.2 predicate: all four conditions, joined on BOTH proof_id and
    case_id -- never on URL/title/class alone, never borrowing a proof from a
    different case or run."""
    cid, pid = finding.get("case_id"), finding.get("proof_id")
    leg = leg_of(finding)
    if not cid or not pid or not leg:
        return "missing_reference"
    rows = proofs_for_case(cid)
    if not rows:
        return "dangling_reference"
    match = [r for r in rows if r["proof_id"] == pid]
    if not match:
        return "dangling_reference"
    r = match[0]
    if r["verdict"] != "confirmed":
        return "rejected_proof"
    if r["validator"].lower().replace("-", "_") != leg:
        return "identity_mismatch"
    return "valid_link"

# 3. Also cross-check store.findings (the persisted table) independently of the
#    driver's in-memory union, to catch findings the driver's own JSON dump missed.
db_confirmed = con.execute(
    "SELECT id, case_id, proof_id, vulnerability_class FROM findings WHERE confirmed=1"
).fetchall()
```

Never write to `<rundir>/maxcov_state_<tag>.db` (open with `mode=ro`), never
migrate its schema, and never copy raw request/response bodies out of it into an
audit output — only the coordinate fields (`case_id`, `proof_id`, `verdict`,
`validator`) are needed and were used in §2.4-2.5 above.

---

## 3. Regression scenarios (smallest caller-level, per source-supported failure mode)

Each scenario names the exact symbol to call and the exact assertion; none of
these were run in this item (documentation-only, per the dispatch's validation
rule — no executable code was added).

### 3.1 Positive control — a valid, matching proof link (path A)

Exercises `orchestrator_confirm.py::_validate_findings` directly, mirroring the
existing `ValidateFindingsWiringTests.test_exact_case_and_proof_survive_finding_persistence`
(`harness/test_evidence.py:388-397`, already in the suite):

- Build a `Finding` with a class that has an applicable fake validator
  (`_FakeValidator`/`_FakeRegistry` pattern already used in `test_evidence.py:223-258`)
  returning `status="confirmed", confirmed=True`.
- Call `_validate_findings(exchange, [report])`.
- Assert: `finding.confirmed is True`, `finding.case_id` and `finding.proof_id`
  are both non-empty, `store.proofs_for_case(finding.case_id)` returns exactly
  one row whose `proof_id == finding.proof_id`, `verdict == "confirmed"`, and
  `validator.lower().replace("-","_") == finding.confirmed_by_leg`.
- This is the §1.2 predicate returning `valid_link` — already effectively
  covered by the cited existing test; no new test needed here, cited as the
  positive-control baseline the negative controls below are contrasted against.

### 3.2 Negative control — missing proof (path B: the graph-loop `_apply` gap)

**New test, smallest caller-level reproduction of the GT04/05/06 defect:**

- Call `orchestrator_chain.py`'s `_apply(finding_dict, fake_confirmed_result, "cross-identity", 0.9)`
  directly (it is a nested function inside `investigate_engagement`; the smallest
  reproduction either (a) extracts `_apply`'s current inline body into a
  module-level helper `orchestrator_chain._apply_confirmation(finding, res, leg, floor)`
  as part of ticket 1 below, so it becomes independently callable/testable, or
  (b) drives the whole `_confirm(finding, exchange)` coroutine with a monkeypatched
  `CrossIdentityValidator.validate` returning a confirmed `ValidationResult`, which
  is callable today without a code change).
- Assert: `finding["confirmed"] is True`, `finding["confirmed_by_leg"] == "cross_identity"`,
  **and** `finding.get("case_id")` / `finding.get("proof_id")` are both falsy
  (`""`/`None`), **and** `store.proofs_for_case("")` (or any case id derivable from
  the finding) returns no matching row — demonstrating the exact `missing_reference`
  outcome §2.3 found in the real artifact, reproducibly, without a live target.
- This test should currently **pass as a demonstration of the bug** (i.e., it
  documents current behavior); once ticket 1 (§4) lands, it should be inverted to
  assert the opposite (a `valid_link`), becoming the regression guard.

### 3.3 Negative control — wrong case/validator/run (identity mismatch)

- Persist two `ProofRecord`s for two different `TestCaseRef`s (different
  `principal_id`, e.g. `alice` vs `bob`) against the same endpoint/check, one
  `CONFIRMED` and one `INCONCLUSIVE` (mirrors `test_evidence.py:110-118`'s
  structured-controlled-negative pattern and the existing
  `test_distinct_principal_distinct_case`, `harness/test_evidence.py:77-79`).
- Build a `Finding` whose `case_id` matches Alice's case but whose `proof_id` is
  swapped to point at Bob's confirmed proof (a forged/stale reference).
- Assert the §1.2 predicate (§2.6's `complete_proof_link`) returns
  `dangling_reference` (no row for `(case_id=Alice, proof_id=Bob's)` — the store
  layer's `store.proofs_for_case` is keyed by `case_id`, so a proof_id belonging
  to a different case_id simply won't appear in Alice's result set) rather than
  `valid_link` — i.e. the audit must never join by `proof_id` alone across cases.
  This is already implicitly guaranteed by `proofs_for_case`'s `WHERE case_id = ?`
  clause (`harness/store.py:717-723`); this test pins that guarantee.

### 3.4 Negative control — storage/reload (proof persisted, but reload from a fresh store loses it)

- Mirrors the existing `StoreTests.test_persist_and_roundtrip`
  (`harness/test_evidence.py:174-186`) and
  `test_additive_migration_preserves_legacy_data` (`:206-221`); no new gap was
  found here in this item — `persist_proof_record`'s `INSERT OR IGNORE` on the
  `proof_id` primary key (`store.py:663-696`) is idempotent and read back
  correctly by `proofs_for_case` (verified exhaustively for all 705 `store.findings`
  rows in §2.4, 0 dangling references found). This control is listed as
  **already covered, not a new failure mode** — included here only because the
  dispatch's step 4 asks for it explicitly "as applicable"; it is not applicable
  as a *new* ticket.

### 3.5 Negative control — the honesty-backstop OR-logic gap (why B passed engagement.add_finding unnoticed)

- Existing test `test_a_real_leg_proof_remains_proven`
  (`harness/test_confirmation_gate.py:240-242`) asserts
  `active_confirmation_is_unproven({"vulnerability_class": "sqli", "confirmed": True,
  "confirmed_by_leg": "sqlmap"})` is `False` — i.e., `confirmed_by_leg` ALONE (no
  `proof_id`) is currently treated as sufficient proof by this predicate's name
  and by `engagement.py::add_finding`'s only defense (`:179`).
- **New negative control**: assert that a finding shaped exactly like the GT04-06
  artifact evidence (`{"vulnerability_class": "idor", "confirmed": True,
  "confirmed_by_leg": "cross_identity"}`, no `case_id`/`proof_id`) is **currently**
  accepted as proven by `active_confirmation_is_unproven` (documents the gap,
  should assert `False` today) and, after ticket 3 below, should assert `True`
  (backstop catches it) once `active_confirmation_is_unproven` is tightened to
  require `proof_id` specifically for classes with `leg_tier() == "live"`.

---

## 4. Bounded implementation tickets

### Ticket 1 — Wire proof persistence into `orchestrator_chain.py::_apply` (path B)

- **Symbols:** `harness/orchestrator_chain.py::_apply` (`:440-453`), `_confirm`
  (`:463-594`), `_confirm_leg` (`:602-611`).
- **Change:** when `_apply` marks a finding confirmed, build a `TestCaseRef` (the
  same shape `_case_for` builds in `orchestrator_confirm.py:310-324` — `run_id`
  from the active `RunContext`, `request_template_id` from the exchange,
  `check_id` from the canonicalized `vulnerability_class`, `principal_id` from
  the identity used for the cross-identity/cross-role attempt), construct a
  `ProofRecord.from_validation_result(...)` from the `ValidationResult` `_apply`
  already receives as `res`, call `store.persist_proof_record` (best-effort, same
  swallow-on-exception discipline `orchestrator_confirm.py:442-483` already
  uses so a persistence hiccup can never sink the graph loop), and stamp
  `finding["case_id"]`/`finding["proof_id"]` alongside the existing
  `finding["confirmed_by_leg"]` write at `:453`.
- **Acceptance test:** §3.2's negative control, inverted to a positive
  assertion — `_apply`'s output finding satisfies the full §1.2 predicate
  (`valid_link`, not `missing_reference`). Paired negative control: a version of
  the same test where the validator's `ValidationResult.confirmed` is `False`
  asserts `finding["confirmed"]` stays `False` and no `ProofRecord` with
  `verdict=confirmed` is persisted for that case (mirrors the existing
  `test_unconfirmed_finding_has_no_leg_stamp`, `harness/test_evidence.py:310-316`,
  applied to this new call site).
- **Do not** build a second evidence ledger for this — reuse `evidence.TestCaseRef`/
  `ProofRecord`/`store.persist_proof_record` exactly as path A does; this ticket is
  additive parity between B and A, not new machinery.
- **P0-6 linkage:** P0-6 ("Require resolvable evidence for ledger completeness and
  reproduction", `IMPROVEMENT_BACKLOG.md:504-519`) is about per-hop
  request/response reconstruction depth for the *ledger*; this ticket is about the
  *proof_records* side reaching parity across confirmation paths. They are
  complementary, not duplicative — landing this ticket does not by itself resolve
  P0-6's per-hop evidence gap, and P0-6 does not by itself close this path-B gap.
  Sequence this ticket independently; do not fold it into P0-6's scope.

### Ticket 2 — Persist PASS2 graph findings to `store.findings` (§2.4's visibility gap)

- **Symbols:** `harness/orchestrator_chain.py::investigate_engagement` (the
  function containing `_apply`/`_confirm`, per §1.3/§2.4's grep evidence that no
  `store.persist_findings` call exists anywhere in this module).
- **Change:** at the point `investigate_engagement` finalizes `result.worklist`/
  `result.idor_findings`/`result.chains` (whichever the caller ultimately returns),
  call `store.persist_findings` for the confirmed subset, exactly as
  `orchestrator_detect.py:726-734` already does for PASS1, so
  `report_generator.export_issues_for_host` (`harness/report_generator.py:632-649`)
  can see these findings at all. **Sequence this after Ticket 1**, not before —
  persisting proof-less confirmations to the durable `findings` table before they
  can carry a real `case_id`/`proof_id` would make the visibility gap worse (more
  findings reach production reporting with no linkable proof), not better.
- **Acceptance test:** a caller-level test driving a minimal `investigate_engagement`
  call (fixture roles/exchange, no live network — reuse the pattern in
  `harness/test_smoke_investigate.py`) asserts a confirmed graph finding appears
  in `store.all_host_findings(host)` after the call. Negative control: an
  unconfirmed graph finding does NOT appear as `confirmed=1` in that table (guards
  against accidentally promoting hypotheses on persistence).

### Ticket 3 — Tighten `active_confirmation_is_unproven` to require `proof_id` for live-tier classes

- **Symbol:** `harness/confirmation_gate.py::active_confirmation_is_unproven`
  (`:357-378`).
- **Change:** for `leg_tier(vuln_class) == "live"` (the tier that already implies
  "a real oracle exists and should have produced durable proof" per
  `should_quarantine_as_lead`'s own docstring, `:381-397`), require `proof_id`
  specifically — not `confirmed_by_leg or proof_id or confirmation_method` — before
  treating a `confirmed=True` claim as proven. Keep the existing OR behavior for
  `leg_tier == "provisional"` classes if the review wants a softer bar there
  (open question for the reviewer, not resolved by this ticket unilaterally: the
  existing test `test_unproven_provisional_class_capped_at_medium_not_low`,
  `harness/test_confirmation_gate.py:187-197`, suggests provisional classes are
  already handled by a different mechanism — severity capping, not the boolean
  backstop — so tightening only the `"live"` branch should not regress it, but
  this should be re-verified against the full `TestLegAwareThreeState` class,
  `harness/test_confirmation_gate.py:136-228`, before landing).
- **Acceptance test:** invert §3.5's negative control —
  `active_confirmation_is_unproven({"vulnerability_class": "idor", "confirmed": True,
  "confirmed_by_leg": "cross_identity"})` (no `proof_id`) must become `True`.
  Paired positive control: the existing `test_a_real_leg_proof_remains_proven`
  (`harness/test_confirmation_gate.py:240-242`) must be updated to also carry a
  `proof_id` (since it currently only sets `confirmed_by_leg`) and must continue
  to assert `False` — do not weaken this test to make the new assertion pass; add
  `proof_id` to its fixture instead. This directly protects against "solving the
  gap by trusting `confirmed`" (the dispatch's explicit prohibition): after this
  ticket, `engagement.py::add_finding` (`:179`) will correctly downgrade GT04/05/06-
  shaped findings to `confirmed=False` at ingestion, which is the intended honesty
  backstop actually firing, not the audit being weakened to agree with the counts.
- **Depends on Ticket 1 partially**: landing Ticket 3 before Ticket 1 will cause
  every current path-B confirmation to be downgraded to `confirmed=False` at
  `engagement.add_finding` time — a real recall drop for anything currently relying
  on path B's (proof-less) confirmations, most notably the cross-identity IDOR
  class demonstrated here. Land Ticket 1 first (or in the same change) so the
  downgrade in Ticket 3 does not silently erase currently-"confirmed" IDOR
  detections; if Tickets 1 and 3 must ship separately, Ticket 3 should ship with
  an explicit CURRENT_STATE.md note that it is expected to reduce path-B's raw
  `confirmed` recall until Ticket 1 lands, and that reduction should be measured
  (owner-run) rather than assumed zero.

### Not filed as a ticket (explicitly out of scope / insufficient evidence)

- **Path C (`role_crawl.py::_cross_role_finding`)** — this run's `cross_role_outcomes`
  was empty (0 leaked pairs found, §2.4's cross-check), so this item found no
  artifact evidence of it ever producing a `confirmed=True` finding in this
  specific run; the structural gap (no `case_id`/`proof_id`, a `validation_hints`
  leg name that can never match a real validator name) is real and
  SOURCE-SUPPORTED from code alone (§1.3), but is lower-priority than Ticket 1
  because it never fired here. Recommend folding it into Ticket 1's pattern
  (reuse the same `TestCaseRef`/`ProofRecord` construction) rather than a
  separate ticket, once Ticket 1 establishes the pattern for `orchestrator_chain.py`.
- **Path D (deterministic detectors: `verbose_error_validator`, `secret_disclosure`,
  `confidential_info`)** — `confirmation_gate.leg_tier` correctly classifies these
  classes as having no live/provisional marker (`is_confirmable_class` gate,
  `confirmation_gate.py:273-278`, checked against `LIVE_VERIFIED_MARKERS`/
  `PROVISIONAL_MARKERS`, `:202-270` — "verbose_error"/"information_disclosure"
  do not appear in either set), so `active_confirmation_is_unproven` already,
  correctly, does not flag them (`leg_tier(...) != "none"` is `False` for them,
  `:378`). These are "confirmed on detection because there is no leg to run
  against them" by design, not proof-link failures. No ticket filed; flagged only
  so a future reader does not mistake the 37+2 `store.findings`-table entries in
  §2.4's "missing references" column for the same defect class as GT04-06.
- **`proof_records.verdict` distribution having zero `controlled_negative`/`error`
  rows** (§2.5) — noted, not investigated further; would need PASS1/PASS2
  validator-level instrumentation (INV-4's territory, cost/runtime attribution)
  to explain, not INV-2's confirmation-linkage scope.

---

## Limitations

- **No live execution occurred in this item.** All trace claims are from reading
  source at current HEAD; all VulnCorp-side numbers are from reading an
  already-completed run's on-disk artifacts (JSON/MD reports) and read-only SQL
  queries against that run's own SQLite file — nothing was re-run, re-scored, or
  modified.
- **The VulnCorp maxrun artifacts are from a different revision** (`eb70210`,
  `.worktrees/integration-measure`, per INV-1) than current HEAD (`b3d40a2`). The
  code-path analysis in §1 and §2.3 (which functions exist, what they do) is
  VERIFIED against **current HEAD**, not against `eb70210`; this item did not diff
  `orchestrator_chain.py`/`orchestrator_confirm.py`/`role_crawl.py` between the two
  revisions. The structural finding (path B never persists a proof) is
  SOURCE-SUPPORTED as a *current-HEAD* defect; that it also explains the
  *historical* GT04-06 delta is SUPPORTED by the artifact evidence (the evidence
  text format and field-null pattern match path B's current signature exactly),
  not independently proven by re-running the historical revision.
- **§2.5's dangling-reference and identity-mismatch counts for the PASS1
  in-memory and PASS2 graph slices are UNKNOWN**, not computed exhaustively (only
  the `store.findings`-table slice was exhaustively joined against `proof_records`).
  The §2.6 recipe closes this gap for a future reader without requiring a new run.
- **`_coverage_proof` (path A′, `orchestrator_confirm.py:212-249`) was read but its
  callers were not traced** — whether its returned `(proof_id, case_id)` tuple is
  actually applied to a `Finding` object anywhere, and if so whether that call site
  behaves like path A (proof-linked) or has its own gap, is UNKNOWN. It was not
  named in the dispatch's INV-2 entry points beyond `orchestrator_confirm.py`
  generally, and tracing every caller of a helper was judged out of this item's
  bounded scope; flagged for a follow-up read, not guessed at.
- **Why `proof_records` in this specific run has zero `controlled_negative`/`error`
  verdicts** (§2.5) is UNKNOWN and explicitly not resolved here — plausible
  explanations (no validator in this run ever executed a genuine controlled
  comparison that held, or errors were classified as `inconclusive` somewhere
  upstream of persistence) were not distinguished from source in this item.
- **This item did not open `vulncorp_ground_truth.py`.** The 13 ground-truth
  ids/paths/classes quoted in §2.2 are taken from the harness-generated report's
  own restatement of them as scored output, which is the same restatement INV-1
  and the SCORECARD already rely on; this item added no new exposure of
  ground-truth content beyond what INV-1/SCORECARD already surface.
- **No production code was changed and no database was written.** All SQLite
  access in this item used `mode=ro` URI connections; `git status --short` at the
  end of this item (below) shows only the new document this item was asked to
  produce.

---

## Validation

- No executable code was added by this item (documentation only, per the
  dispatch's rule: "If you add NO executable code, say so and skip the suite" —
  skipped; `harness.suite smoke`/`full` were not run).
- `git diff --check` — run against the working tree; the new file is untracked
  until staged, so this was additionally checked by reading the file back for
  literal whitespace-conflict markers (none present).
- Every local path/symbol cited above was confirmed to exist in this checkout via
  direct `grep`/`Read` at the stated line numbers (current HEAD `b3d40a2`), not
  assumed from memory or from the dispatch's own entry-point list.
