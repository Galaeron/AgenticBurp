# Prioritized work list and I01–I17 reconciliation — PROPOSED, 2026-10-21

This is a proposal. Nothing here is implemented, and no existing tracker was edited. The canonical
dispatch order in `docs/REMAINING_IMPLEMENTATION_PLAN_2026-10-17.md` and
`docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md` stays in force. Section 3 lists the exact amendments
proposed for the owner to accept or reject. Evidence IDs (E…, H…) refer to
[EVIDENCE_INDEX.md](EVIDENCE_INDEX.md). Acceptance cases (X1–X7) and arms refer to
[CROSS_REQUEST_ACCEPTANCE_SPEC.md](CROSS_REQUEST_ACCEPTANCE_SPEC.md).

Status vocabulary, per the existing completion rules: **implemented**, **caller-verified**,
**live-validated**, **released**. A helper that exists, or a mocked test that passes, closes nothing.

## 1. Sequence

Each stage depends on the one before. Within a stage, tickets that touch disjoint files can run in
parallel, with at most three sessions at once, per AGENTS.md.

| Stage | Goal | Tickets | Needs live authorization? |
|---|---|---|---|
| S0 | Reproducible candidate and trustworthy evidence | WL-01, WL-05, WL-04, WL-10, WL-13 | No |
| S1 | Cross-request attribution and retrieval with real consumers | WL-02, WL-03, WL-09 | No |
| S2 | Usable advisory workflow and bounded automated integration | WL-06, WL-07, WL-08, WL-11, WL-12, WL-16 | No (JDK needed for WL-08) |
| S3 | Comparative efficacy | WL-14 (offline, local model), then WL-15 (live) | WL-15 only |
| S4 | Release and operator proof | existing I15, I16, I17 with the amendments in §3 | Burp walkthrough |

The existing open batches (RV-K, RV-O, RV-P, RV-Q, I05-D) keep their order. WL tickets touch
these files: `role_crawl.py`, `engagement.py`, `engagement_builder.py`, `store.py` (observation
functions only), `api_surface_discovery.py`/`orchestrator_chain.py` (sensitive-file block),
`validators/registry.py`/`cross_identity_validator.py`, `knowledge.py`, `config.yaml` (new keys
default-safe), and Java models. `store.py` and `HarnessPanel.java` carry I01 W-split WIP
on the owner's machine (E01, CURRENT_STATE). So WL-03, WL-09 and WL-10 must wait for the W-split,
or rebase onto it, and WL-08 must wait for RV-K.

### First executable batch: offline, no live authorization, no WIP files

1. **WL-01:** reproduce the suites from a clean, lockfile-installed environment.
2. **WL-05:** stop status-only `sensitive_file_exposure` confirmations.
3. **WL-02:** principal-keyed access matrix plus one shared ID normalizer. It touches `role_crawl.py`,
   `engagement.py` and `engagement_builder.py`; none of these carries WIP according to the I01 manifest.
4. **WL-13:** freeze the acceptance spec into I12. This is a docs commit.

The batch is about 1–2 engineer-weeks, assuming one engineer who knows the codebase, with owner
review. Everything in it runs on owned loopback fixtures. WL-04 can start alongside it once the owner
decides where ownership declarations come from (§4, D1).

## 2. Tickets

Fields follow the requested template. "Root-cause confidence" refers to the code path described,
not to its effect on any particular target.

---

### WL-01 — Reproducible verification environment for the committed candidate

| Field | Value |
|---|---|
| Type | Evidence gap |
| Mode | Both |
| User-visible outcome | Anyone can reproduce precondition, smoke and full from a clean checkout and get the reported counts, and a mismatch is visible |
| Evidence status | VERIFIED NOW: blocked in a clean container (E02, E03). The reported green run is HISTORICAL/REPORTED (H08) and was produced on the owner's Windows checkout with an in-repo venv. Referenced handoffs, overlays and logs are not in Git (E01). |
| Boundaries | `harness/requirements.lock`, `harness/suite.py`, CI workflow; no product code |
| Root-cause confidence | High (absent dependencies; artifacts outside Git) |
| Smallest change | A documented, scripted `python -m venv` + `pip install -r harness/requirements.lock` + Flask/werkzeug recipe for Linux Python 3.13/3.14. A runner wrapper writes `exit codes + counts + skip reasons + source sha` to a summary file. Record the candidate as an exact commit; overlays are not accepted as candidates. |
| Dependencies | None; touches I01/I15 scope |
| Effort | 0.5–1.5 days (assumes the lockfile resolves on Linux; if not, add a Linux lock) |
| Acceptance | Clean container: the three commands reproduce H08's counts at the candidate sha (± documented platform skips) |
| Negative control | Removing one dependency makes the wrapper report BLOCKED, not PASS |
| Fault injection | n/a |
| Metric | The summary matches CI on the same sha |
| Completion artifact | Summary file plus a CI run link for the sha |
| Regression risk | Low |
| Rollout/rollback | Docs and script only; remove to roll back |
| Non-goal | Changing test selection or weakening any check |

### WL-02 — Principal-keyed role/access matrix and one shared object-ID normalizer

| Field | Value |
|---|---|
| Type | Defect |
| Mode | Automated (also feeds advisory via WL-09) |
| User-visible outcome | Two accounts with the same role are compared. A same-role BOLA lead appears, and the matrix cell is never self-contradictory. UUID-addressed objects are treated as objects. |
| Evidence status | VERIFIED NOW at the stubbed boundary (E33): the real same-role BOLA produced 0 leads, and an owner-scoped cell read `{'user': 403}` with `reachable: ['user']`. SOURCE-SUPPORTED (E32, E34). |
| Boundaries | Producers `role_crawl.crawl_roles`, `engagement_builder.build_engagement`; readers `_derive_candidates`, `_compare_identities`, `engagement.ingest_role_crawl`, `SurfaceEndpoint.fused_score`, `coverage_tracker`, investigation worklist ranking |
| Root-cause confidence | High |
| Smallest change | Key `by_role`, `reachable_roles` and `fingerprints` by `RoleSession.principal_id()`, keep `role` per principal as metadata (as `coverage_tracker._identities_of` already does), and record per cell `{status, session_ref, observed_at}`. Replace the three templating regexes with one normalizer that recognizes digits, ≥8 hex and hyphenated UUIDs. Make `ingest_role_crawl` merge per principal instead of replacing the cell. |
| Dependencies | WL-01 (to verify) |
| Effort | 3–5 days, with an API-shape migration for `by_role` consumers (Burp `HarnessToolsPanel` reads `/crawl-roles` output) |
| Acceptance | X2 through `POST /engagement/{host}/investigate` against an owned loopback app: the vulnerable route gives a lead with alice and bob as distinct columns; the owner-scoped route records bob as denied; a UUID route is object-scoped |
| Negative control | X2 shared resource is not *confirmed* (lead text keeps the "confirm ownership" caveat; confirmation is WL-04) |
| Fault injection | Collapse principals back to the role label; X2 vulnerable must fail |
| Metric | Same-role BOLA lead recall on the X2 family, plus the false-lead rate on owner-scoped twins |
| Completion artifact | Caller test module with positive, control and fault cases, and a full-suite summary |
| Regression risk | Medium: worklist scores and Burp matrix display change |
| Rollout/rollback | Additive keys; the old `by_role` view is derived for one release; revert the commit to roll back |
| Non-goal | New graph storage; inferring tenants or ownership from role names |

### WL-03 — Deterministic relation records for observations (advisory cross-request core)

| Field | Value |
|---|---|
| Type | Evidence gap / opportunity |
| Mode | Advisory (shared with automated via WL-09) |
| User-visible outcome | When an analyst sends related captures (a list that discloses IDs and a later request using one; the same route as two principals), the analysis receives *cited relation records* and returns them in `observation_context.relations` |
| Evidence status | VERIFIED NOW at the reader boundary (E14): exact-path, same-context only; related rows are invisible, and only key names are rendered (E13). The model framing is "PRIOR FINDINGS … do not re-report" (E16). |
| Boundaries | Writer `store.record_observation`; reader `store.select_observations`; consumer `_analyze_inner` prompt assembly; output `AnalysisResponse.observation_context`; export `/report` |
| Root-cause confidence | High (design scope of I02-C) |
| Smallest change | (1) Store a `route_template` column next to `normalized_endpoint`, using WL-02's normalizer. (2) At write time, index identifier-like values (path segments, ID-like query values, values of ID-like JSON keys up to a bound) as keyed HMAC tokens with their location, never raw. (3) Add `select_relations`. It returns bounded records of type `identifier_disclosed_then_used`, `same_route_other_principal`, `same_object_other_principal` and `temporal_successor`, each with both observation IDs, locations and response fingerprints (status, size, keyed body hash, ownership-key *presence*). (4) Render them as a separate "OBSERVED RELATIONSHIPS (evidence; cite obs ids)" block. Cross-principal relations are a **comparison** class and never history-sharing. Declared different tenants or piles never relate. |
| Dependencies | WL-02 (normalizer), owner decision D2, I01 W-split (`store.py`) |
| Effort | 4–7 days (migration additive: new columns/table + `state_metadata` marker, as in I02-C) |
| Acceptance | X1 and X2 through `POST /analyze` (ASGI) with real SQLite and a canned consumer: relations cite both IDs; each capture alone yields none; restart and re-read gives the same relations |
| Negative control | X5 (other tenant or pile) yields no relation; the public twin does not produce an access-control relation |
| Fault injection | Sever `select_relations` gives `status: unavailable` and `degraded`; drop A gives no relation |
| Metric | Relation precision and recall on the frozen corpus; prompt-token delta per analysis |
| Completion artifact | Caller tests plus a migration test plus a design note updated in `docs/OBSERVATION_MEMORY.md` |
| Regression risk | Medium: prompt changes, cache keys change through the digest |
| Rollout/rollback | Behind `observations.relations: true` (default to be decided by the owner, D2); drop the new table to roll back |
| Non-goal | Graph database; model-inferred relations; rendering raw identifier values or PII to the model |

### WL-04 — Cross-identity confirmation requires declared ownership (shared-resource control)

| Field | Value |
|---|---|
| Type | Defect (false-confirmation risk) |
| Mode | Automated |
| User-visible outcome | A resource that is legitimately shared with all logged-in users is never reported as confirmed BOLA |
| Evidence status | SOURCE-SUPPORTED (E38). Not executed (E02). |
| Boundaries | `ValidatorRegistry._build_cross_identity` / auto-arm, `CrossIdentityValidator.validate`, `orchestrator_confirm` downgrade, persistence and export |
| Root-cause confidence | High that the gate is absent; the false-positive prevalence on real targets is UNKNOWN |
| Smallest change | With no ownership evidence, a similarity match with anonymous denied returns `supported` (lead) with `manual_verification` text, not `confirmed`. Wire `principals.OwnershipLedger` from operator or engagement declarations (D1) so that a declared owner/non-entitled pair can confirm. |
| Dependencies | D1; coordinates with the open owner question on IDOR in CURRENT_STATE |
| Effort | 2–3 days |
| Acceptance | X2 vulnerable plus declared ownership gives confirmed; without a declaration, supported only |
| Negative control | X2 shared resource with or without declaration gives not confirmed |
| Fault injection | Ignore the ownership result; the shared control must fail the test |
| Metric | False confirmations on shared and public twins (gate: 0) |
| Completion artifact | Caller test through `investigate_engagement` plus storage/export check, as in I02-A |
| Regression risk | Medium: recall loss where ownership is undeclared (intended; measured in WL-14) |
| Rollout/rollback | Strict by default; revert to roll back |
| Non-goal | Inferring ownership from IDs, URLs or role rank |

### WL-05 — No status-only confirmation of sensitive files

| Field | Value |
|---|---|
| Type | Defect (false-confirmation risk) |
| Mode | Automated |
| User-visible outcome | `sensitive_file_exposure` appears as a candidate unless the body proves the artifact (a type-appropriate content check). A redirect is never reported as "HTTP 200". |
| Evidence status | SOURCE-SUPPORTED (E39) |
| Boundaries | `SurfaceDiscovery._probe_sensitive_files` → `RoleCrawlResult.sensitive_file_hits` → `investigate_engagement` ingest → job result and worklist |
| Root-cause confidence | High |
| Smallest change | Record the hit's status and body fingerprint. Only 2xx with a content signature specific to the artifact class may set `confirmed`; otherwise ingest `confirmed: False` with "existence only" evidence text that quotes the real status. |
| Dependencies | None |
| Effort | 1–2 days |
| Acceptance | Owned fixture serving a benign synthetic artifact with its expected signature gives confirmed |
| Negative control | A 302 to login, a catch-all 200 HTML shell and an empty 200 each give not confirmed |
| Fault injection | Restore the status-only rule; the negative controls must fail |
| Metric | False confirmations on controls (0) |
| Completion artifact | Caller test via `investigate_engagement`, with discovery driven against the loopback fixture |
| Regression risk | Low |
| Rollout/rollback | Revert |
| Non-goal | Expanding the sensitive-file wordlist |

### WL-06 — Advisory answer contract and explicit outcome states

| Field | Value |
|---|---|
| Type | Opportunity (with an evidence gap) |
| Mode | Advisory |
| User-visible outcome | Each analysis says which question it answered, which observations it relied on, the assumptions and missing evidence, a ranked next step, and whether the result is `answer`, `no_finding`, `insufficient_evidence` or `analysis_failed` |
| Evidence status | SOURCE-SUPPORTED (E20: there is no insufficient-evidence state; E17: no structured citation) |
| Boundaries | `models.AnalysisResponse`, `_analyze_inner` tail, `store` (new `analysis_answers` table linking answer to cited observations), `report_generator`, `sarif_adapter` |
| Root-cause confidence | n/a (missing capability) |
| Smallest change | A deterministic answer assembler that runs after agents and critique. It derives the outcome state and missing evidence from WL-03 relations, observation status and agent health. It persists cited observation IDs per finding and answer. The model may supply prose only *inside* fields whose citations are validated against the selected set. |
| Dependencies | WL-03 |
| Effort | 4–6 days |
| Acceptance | X1 and X4 answers carry exactly the required citations and the correct outcome; an `analysis_failed` answer when the model is down sets `degraded` |
| Negative control | A model citing an unselected observation ID is rejected and counted as an unsupported claim |
| Fault injection | Bypass the citation validator; the unsupported-claim test must fail |
| Metric | Unsupported-claim rate; citation correctness and completeness; abstention accuracy |
| Completion artifact | Caller tests plus an export parity test (API, Markdown, SARIF) |
| Regression risk | Medium (response shape is additive) |
| Rollout/rollback | Additive fields; Burp ignores unknown fields |
| Non-goal | Conversational chat; generic checklists |

### WL-07 — Bounded multi-capture advisory request

| Field | Value |
|---|---|
| Type | Opportunity |
| Mode | Advisory |
| User-visible outcome | The analyst selects 2–8 captures in Burp and asks one supported question (Q1–Q3) about them as a set, and gets one answer that cites them, instead of N unrelated analyses |
| Evidence status | SOURCE-SUPPORTED: `/analyze` takes one exchange (E10); Burp multi-select fans out (E21) |
| Boundaries | New `POST /analyze/compare`, or `selection_id` on `/analyze`; `HarnessContextMenu`; the same run/pile and zero-target-traffic rules |
| Root-cause confidence | n/a |
| Smallest change | A route that records each capture as an observation (same idempotency), then runs WL-03 and WL-06 restricted to the selection. It runs no validators unless `active_enabled`. |
| Dependencies | WL-03, WL-06; Burp part needs WL-08 |
| Effort | 2–4 days backend; Burp part in WL-08 |
| Acceptance | X1, X2 and X4 via the route: zero fixture-side requests; answer persisted |
| Negative control | Selecting captures from two declared tenants returns `insufficient_evidence` with the reason |
| Fault injection | Drop one selected capture before analysis; the answer must cite only what exists and say what is missing |
| Metric | Time to a justified decision (arm H vs M) |
| Completion artifact | Caller tests plus an OpenAPI description |
| Regression risk | Low (new route) |
| Rollout/rollback | Remove the route |
| Non-goal | Unbounded selections; automatic grouping of history |

### WL-08 — Burp contract parity and degraded-state presentation

| Field | Value |
|---|---|
| Type | Defect / evidence gap |
| Mode | Both (operator boundary) |
| User-visible outcome | Burp shows when the model failed or a stage was skipped, which earlier observations were used, and validation and proof status. It sends capture time, completeness, an optional named pile and attribution. It can start, poll and cancel an investigation and view its result. |
| Evidence status | SOURCE-SUPPORTED (E21, E22); Java not built (E04); W3 health WIP exists only on the owner's machine (E01) |
| Boundaries | `AnalysisModels.java`, `HarnessClient.java`, `HarnessContextMenu.java`, `HarnessPanel.java` (WIP, RV-K) |
| Root-cause confidence | High |
| Smallest change | Add the missing fields to the Java request and response models. Render `degraded`, `agent_errors` and `observation_context` in the result pane. Send `captured_at` (Burp message time when available, else unset), `completeness` (`binary_unsupported` when the body is replaced) and `capture_id`. Add investigate start, poll and cancel calls and a result view. |
| Dependencies | RV-K, I01 W-split, JDK build (I15) |
| Effort | 4–8 days including Java tests |
| Acceptance | Java tests deserialize real API JSON fixtures; one manual Burp walkthrough (I16) shows a degraded result and an observation-cited result |
| Negative control | A healthy response shows no degraded banner |
| Fault injection | Drop `degraded` from the model; the Java test fails |
| Metric | Operator task-completion checklist (I16) |
| Completion artifact | `gradle clean test shadowJar` log plus a walkthrough record |
| Regression risk | Medium (UI) |
| Rollout/rollback | Extension version bump; previous JAR to roll back |
| Non-goal | A Burp-native issue integration rewrite |

### WL-09 — Shared evidence across modes: retain investigation traffic as labelled observations; persist matrix snapshots

| Field | Value |
|---|---|
| Type | Evidence gap |
| Mode | Both |
| User-visible outcome | After an automated investigation, advisory analysis of the same site can cite what the investigation observed, labelled as harness-fetched with its run ID and permissions. The access and coverage matrices survive the job and appear in `/engagement/{host}` and exports. |
| Evidence status | SOURCE-SUPPORTED (E11, E30, E31, E36) |
| Boundaries | `orchestrator_helpers.review_captured_exchanges`, `investigate_engagement` tail, `store` observations, engagement state |
| Root-cause confidence | High (design exclusion in I02-C) |
| Smallest change | Record discovery and role-crawl captures as observations with `capture_source=harness:<run_id>` and the principal they were sent as, in the pile the job names. This needs a new optional `engagement_id` on `InvestigateRequest`; the default stays the site pile. Save a bounded access/coverage snapshot via `store.save_engagement` at job end. |
| Dependencies | WL-02, WL-03, D3, I01 W-split |
| Effort | 3–5 days |
| Acceptance | X7 mode parity: the same supplied captures give identical facts and provenance in both modes; harness-fetched observations are labelled |
| Negative control | Advisory analysis in another pile cannot see them |
| Fault injection | Skip the snapshot save; the `/engagement/{host}` test fails |
| Metric | Parity mismatches (0) |
| Completion artifact | Caller test spanning both routes |
| Regression risk | Medium (storage growth; bounded) |
| Rollout/rollback | Flag `observations.retain_harness_traffic` |
| Non-goal | Resuming an interrupted job mid-run (separate; needs the execution ledger) |

### WL-10 — Scope knowledge notes to host and pile; reset state between evaluation repeats

| Field | Value |
|---|---|
| Type | Defect (isolation and evaluation independence) |
| Mode | Both |
| User-visible outcome | A confirmed finding on one client's site never steers analysis of another site. Evaluation repeats start from clean state. |
| Evidence status | SOURCE-SUPPORTED (E23); existed at `06a128fc` (H07: whether repeats reset the DB is UNKNOWN) |
| Boundaries | `knowledge.remember_finding`, `knowledge.retrieve` (`base_agent.py:269` passes no engagement), `store.save_knowledge_note`; evaluation drivers |
| Root-cause confidence | High |
| Smallest change | Always pass host plus pile to `remember_finding` and `retrieve`; never write global notes from analyses. Have the evaluation drivers wipe or point to a fresh `harness_state.db` and record its digest. |
| Dependencies | I01 W-split (W2 touches `knowledge.py` and `base_agent.py`) |
| Effort | 1–2 days |
| Acceptance | Site A's confirmation is not retrieved for site B; it is retrieved for A |
| Negative control | Built-in methodology corpus still retrieved everywhere |
| Fault injection | Global write restored; the cross-site test fails |
| Metric | Cross-site note leaks (0) |
| Completion artifact | Caller test plus a driver change |
| Regression risk | Low |
| Rollout/rollback | Migration leaves old global notes; an opt-in cleanup command |
| Non-goal | Removing the methodology corpus |

### WL-11 — Inventory and gate non-target egress in "passive" analysis

| Field | Value |
|---|---|
| Type | Evidence gap (privacy) |
| Mode | Advisory primarily |
| User-visible outcome | The operator knows, and can switch off with one setting, that component names seen in client traffic are looked up at GitHub, npm, PyPI, Aikido and CISA |
| Evidence status | SOURCE-SUPPORTED (E19); undocumented |
| Boundaries | `github_advisories`, `package_registry_checks`, `kev_check`, `config.yaml`, `docs/LIMITATIONS.md`, `/health` or `/settings` |
| Root-cause confidence | High |
| Smallest change | Document the behaviour now. Add `privacy.external_lookups` (default per owner decision D4) and report external calls in `telemetry` and `AnalysisResponse` with counts per service. |
| Dependencies | D4 |
| Effort | 1–2 days |
| Acceptance | With the flag off, zero sockets to those hosts during X1 analysis (counted at the boundary) |
| Negative control | With the flag on, lookups still occur and are counted |
| Fault injection | A lookup path bypassing the flag fails the counter test |
| Metric | External calls per analysis |
| Completion artifact | Test plus a docs update |
| Regression risk | Low |
| Rollout/rollback | Config flag |
| Non-goal | Removing the advisory lookups |

### WL-12 — `/engagement/{host}/run` with `execute=true` owns a bounded, cancellable run

| Field | Value |
|---|---|
| Type | Defect (containment) |
| Mode | Automated |
| User-visible outcome | The plan-execute driver obeys one request ceiling and can be cancelled like the other routes |
| Evidence status | SOURCE-SUPPORTED (E40); double-gated off by default |
| Boundaries | `server.engagement_run`, `orchestrator_chain.run_engagement` |
| Root-cause confidence | High |
| Smallest change | Wrap execution in `_crawl_route_run()` (the RV-G pattern) and pass the context to `analyze`, so each page analysis borrows it |
| Dependencies | None; fits I05 or the RV-G scope |
| Effort | 0.5–1 day |
| Acceptance | Owned fixture: request count ≤ ceiling; cancellation stops sends |
| Negative control | `execute=false` sends nothing |
| Fault injection | Unwrap the context; the ceiling test fails |
| Metric | Requests beyond the ceiling (0) |
| Completion artifact | Caller test |
| Regression risk | Low |
| Rollout/rollback | Revert |
| Non-goal | Enabling `driver_execute` by default |

### WL-13 — Freeze the cross-request evaluation specification in I12

| Field | Value |
|---|---|
| Type | Evidence gap |
| Mode | Both |
| User-visible outcome | Improvement claims are judged against predeclared baselines, metrics and thresholds |
| Evidence status | Proposal in [CROSS_REQUEST_ACCEPTANCE_SPEC.md](CROSS_REQUEST_ACCEPTANCE_SPEC.md) |
| Boundaries | `docs/` plus I12 runner configuration |
| Root-cause confidence | n/a |
| Smallest change | The owner accepts or edits §7–§9 of the spec; it is committed as the I12 protocol addendum with a hash |
| Dependencies | Owner decisions D5 (thresholds), custodian named |
| Effort | 0.5 day plus owner review |
| Acceptance | Hash recorded before any WL-14 run |
| Negative control | n/a |
| Fault injection | n/a |
| Metric | n/a |
| Completion artifact | Committed protocol plus hash |
| Regression risk | None |
| Rollout/rollback | Amendments recorded with a date and reason |
| Non-goal | Moving thresholds after results |

### WL-14 — Offline cross-request efficacy experiment (fixed corpus)

| Field | Value |
|---|---|
| Type | Evidence gap |
| Mode | Both (advisory arms A0–A2-pad, D, M; automated arm A3 on owned fixtures) |
| User-visible outcome | A measured answer to whether relation records (and the matrix) improve justified conclusions beyond more context, at what token cost |
| Evidence status | No current measurement (I14 open) |
| Boundaries | Production routes only, with a local Ollama model, a fresh DB and cache per arm |
| Root-cause confidence | n/a |
| Smallest change | Build the X1–X7 corpus (≥30 pairs per family, ≥3 schemas). Run the arms per spec §7. Have adjudicators score per §8. |
| Dependencies | WL-01, WL-02, WL-03, WL-06, WL-10, WL-13; GPU host with Ollama |
| Effort | 1.5–3 weeks (corpus build is most of it); adjudication 2–4 person-days |
| Acceptance | Report with per-arm metrics, CIs, failed runs and per-context results |
| Negative control | A2-shuffle and A2-pad arms |
| Fault injection | Spec §6 injections run as a pre-flight |
| Metric | Spec §8 and §9 |
| Completion artifact | Results bundle plus adjudication sheets plus protocol hash |
| Regression risk | None (measurement) |
| Rollout/rollback | n/a |
| Non-goal | Live targets; generalizing from crAPI-like cases |

### WL-15 — Live crAPI re-run under I13, both workflows, with recorded provenance

| Field | Value |
|---|---|
| Type | Evidence gap (live validation) |
| Mode | Both |
| User-visible outcome | A current, adjudicated answer to whether the historical no-go still holds, per workflow |
| Evidence status | Historical no-go (H01); cause unresolved (H06, H07) |
| Boundaries | I13 prerequisites: authorized scope, owned crAPI instance with frozen state, registered identities (≥2 same-role users plus admin), working model service, adjudicator, independent proxy request counter |
| Root-cause confidence | n/a |
| Smallest change | Run advisory (captured analysis plus WL-07 sets) and automated (investigate) separately against the same frozen state with matched budgets, recording source sha, config hash, DB/cache reset, model digest and stage health |
| Dependencies | WL-14 passed its gates; owner authorization |
| Effort | 2–4 days plus adjudication |
| Acceptance | Spec §9 gates; the zero-false-confirmation no-go applies |
| Negative control | Secure controls in the corpus |
| Fault injection | n/a (live) |
| Metric | Spec §8 |
| Completion artifact | Adjudicated report |
| Regression risk | Target state changes (owned instance; reset after) |
| Rollout/rollback | n/a |
| Non-goal | Tuning on the evaluation target |

### WL-16 — Prompt framing and context-cost accounting for cross-request blocks

| Field | Value |
|---|---|
| Type | Defect (minor) / evidence gap |
| Mode | Both |
| User-visible outcome | The model is told to compare and cite observations rather than "not re-report" them. Each analysis reports the tokens spent on context blocks. Truncation risk is explicit. |
| Evidence status | SOURCE-SUPPORTED (E16, E42, E05: `num_ctx` unset) |
| Boundaries | `base_agent._user_prompt`, `orchestrator_detect` prompt assembly, effort ledger |
| Root-cause confidence | Medium (effect on model quality unmeasured) |
| Smallest change | Separate headers for prior findings and observations or relations, plus a citation instruction. Count block tokens via the provider's prompt-token delta (or an estimate labelled as such). Warn when the assembled prompt exceeds the configured or known `num_ctx`. |
| Dependencies | WL-03 |
| Effort | 1–2 days |
| Acceptance | Prompt snapshot test; reported block-token fields |
| Negative control | An endpoint with no history gives a prompt byte-identical to before |
| Fault injection | Remove the citation instruction; the WL-14 pre-flight citation rate drops (measured, not asserted) |
| Metric | Tokens per analysis by block; truncation warnings |
| Completion artifact | Tests plus a WL-14 cost table |
| Regression risk | Low–medium (prompt change, so re-baseline needed) |
| Rollout/rollback | Prompt version bump (cache keys include prompt versions) |
| Non-goal | Prompt caching; context compression before measurement |

## 3. Reconciliation against I01–I17 and older aliases

Valid completed work is preserved. Only the acceptance scope named in each row is reopened.
"Amendment" is the exact text proposed for insertion under the ticket in the plan.

| Ticket | Plan status | This audit | Proposed amendment (exact text) | Canonical owner of the new gap |
|---|---|---|---|---|
| I01 | [~] | Candidate reproducible only on the owner's machine; overlay and handoffs outside Git (E01, E03) | "**Amendment 2026-10-21:** a candidate is an exact commit. Reproduction from a clean lockfile install (WL-01) is part of Done. References in CURRENT_STATE to untracked files are marked as such." | I01 (WL-01) |
| I02 | [~] B, A, C done | C verified at the reader boundary (E14). Scope limits: exact path, same context, key names only, no structured citation (E12–E17). Global knowledge notes (E23). | "**I02-D (proposed):** relation records across route template, identifiers and principals (comparison class), WL-03. **I02-E:** persisted answer citations, WL-06 storage half. **I02-F:** harness-fetched observations and matrix snapshot, WL-09 (needs D3). **I02-G:** knowledge notes scoped to host and pile, WL-10. Batch C's completed acceptance (C01, C03, C04, C08, C09) is retained." | I02 |
| I03 | [~] | Not re-verified (E03) | None | — |
| I04 | [~] | Not re-verified | None | — |
| I05 | [~] | `/engagement/{host}/run` execute escapes (E40); non-target egress (E19) | "**I05-E (proposed):** WL-12, the run route owns a run. **I05-F:** WL-11, non-target egress inventory and flag." | I05 |
| I06 | [ ] | Matrix role-keyed; UUID templating (E32–E34); `owned_object_ids` uncalled (E35) | "**Amendment:** Done also requires principal-keyed access cells with session and time (WL-02). Same-role principals are never merged." | I06 (WL-02) |
| I07 | [ ] | Burp sends no capture-contract fields (E21, E22) | "**Amendment:** the Burp sender populates `captured_at`, `completeness` and `capture_id` (WL-08 Java half)." | I07 → delivered in WL-08 |
| I08 | [ ] | Not examined | None | — |
| I09 | [~] | Not examined | None | — |
| I10 | [ ] | Ownership-less cross-identity confirmation (E38); status-only sensitive files (E39) | "**Amendment:** add the X2 shared-resource twin and the sensitive-file redirect and catch-all twins to the paired cases (WL-04, WL-05)." | I10 |
| I11 | [~] | Coverage matrix principal-keyed but unexported (E36) | None (export belongs to I16) | — |
| I12 | [ ] | No predeclared cross-request protocol | "**Amendment:** adopt CROSS_REQUEST_ACCEPTANCE_SPEC §5–§9 as a protocol addendum (WL-13). A fresh `harness_state.db` per arm is required (E23)." | I12 |
| I13 | [ ] | Historical cause unresolved (H06, H07) | "**Amendment:** run and report the advisory and automated workflows separately; record DB reset and knowledge-note state (WL-15)." | I13 |
| I14 | [ ] | No measurement of context or relation value | "**Amendment:** include arms A0–A3, A2-shuffle and A2-pad, D, M and H (WL-14)." | I14 |
| I15 | [ ] | Java build not run here (E04) | Covers WL-01's install half | I15 |
| I16 | [ ] | Burp lacks degraded state, observation context and investigate (E21); coverage unexported (E36) | "**Amendment:** WL-08 is the Burp contract-parity scope. Coverage matrix export is in scope. The task graph is documented as display-only (E37)." | I16 |
| I17 | [ ] | — | Readiness verdicts per mode (DECISION_REPORT §6) | I17 |
| **I18 (new)** | — | No owner exists for the advisory answer contract or the multi-capture question | "**I18 — Advisory comparison workflow:** WL-06 (answer contract, outcome states) and WL-07 (bounded multi-capture request). Depends on I02-D. Not a live ticket." | I18 |

**Older aliases**

| Alias | Location | Status per this audit |
|---|---|---|
| R10 (distinct principal ids) | `role_crawl.py:202-216` docstring | `principal_id()` exists, but the matrix ignores it (E32). Reopen the matrix acceptance only, under I06/WL-02. |
| R02 (coverage identities) | `coverage_tracker.py:498` | Holds for coverage. It disagrees with the access matrix (E36). Fixed by WL-02. |
| T02/R27 (principal and ownership model) | `principals.py:2`, `cross_identity_validator.py:221` | Model exists; no production `OwnershipLedger` (E38). Reopen under I10/WL-04. |
| P1.3 (cross-role matrix with real ids) | `role_crawl.py:300-385`, `:700` | No production caller (E35). Fold into WL-02 or explicitly defer; do not count as delivered. |
| W-12 (cross-identity auto-arm) | `validators/registry.py:442-468` | Arms on active mode plus identities; inherits E38. |
| P2.3 (engagement-private knowledge) | `knowledge.py:143-178` | Private notes exist only for named piles; default pile is global (E23). Reopen under I02/WL-10. |
| R22 (`path_ids`) | `engagement.py:87` | Present; uses the 12-hex normalizer (E34). Covered by WL-02. |
| LB-2 / DET-* / BM-2 / P1-3 / Part B | plan | Mappings unchanged; WL-04 and WL-05 add twins to BM-2 (I10). |

## 4. Owner decisions needed

| ID | Decision | Default proposed by this audit |
|---|---|---|
| D1 | Where ownership declarations come from (operator API, engagement config, fixture). It overlaps the triage's open question "whether a declared victim id counts as ownership evidence". | Operator-declared per object or route pattern; none means no confirmation |
| D2 | Whether cross-principal observations may be *compared* (not shared as history) within one pile; default of `observations.relations` | Allow the comparison class within a pile; never across declared tenants; on by default after WL-14 |
| D3 | Whether harness-fetched traffic becomes observations (reverses I02-C's exclusion) | Yes, labelled and pile-scoped |
| D4 | Default for third-party lookups in passive mode | Documented now; default decided by the owner |
| D5 | Thresholds in spec §9; independent label custodian | As proposed; custodian named before WL-14 |

## 5. 30/60/90-day view

Staffing assumption: one engineer full-time (human or supervised agent sessions, at most three in
parallel), owner review up to one day a week, a GPU host with Ollama from day 30, and one
independent adjudicator for 4–6 days in the 60–90 window. Halve the scope if the engineer is half-time.

- **Day 0–30:**
  - WL-01, WL-05, WL-02 and WL-13 (first batch).
  - D1–D5 decided.
  - WL-04 and WL-12.
  - WL-03 design note, and its implementation if the W-split has landed.
- **Day 31–60:** WL-03, WL-06, WL-07, WL-10, WL-11 and WL-16 caller-verified. WL-08 if RV-K, the W-split and a JDK build are available.
- **Day 61–90:**
  - WL-09.
  - WL-14 corpus and arms run and adjudicated.
  - WL-15 only if the WL-14 gates pass and the owner authorizes.
  - I15–I17 release work for the advisory mode alone if its gates pass.

These are estimates, not commitments. The largest uncertainties are the W-split timing and the corpus build.

## 6. Global non-goals

- A new graph database or a rewrite of the engagement model.
- Forcing the task graph into decisions.
- Adding agents, validators or competitor features before WL-14 shows value.
- Default changes that enable active traffic.
- Any claim of superiority without a shared evaluation.
