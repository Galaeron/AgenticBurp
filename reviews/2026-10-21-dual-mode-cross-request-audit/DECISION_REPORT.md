# Decision report — AgenticVibe as automated tester and evidence-grounded advisor

**Audit date:** 2026-10-21.
**Candidate:** `f5637308e2e4f387aedcc6442ad856754b69565e` (`reconciliation-backlog`, clean tree).
**Type:** audit and planning only. No product code, defaults, trackers or targets were changed. No
scan was launched. Every claim cites [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) and carries a label:
VERIFIED NOW, SOURCE-SUPPORTED, HISTORICAL/REPORTED, INFERRED, or UNKNOWN/BLOCKED.

Companion files:
- [CROSS_REQUEST_ACCEPTANCE_SPEC.md](CROSS_REQUEST_ACCEPTANCE_SPEC.md): fixtures, controls, arms, metrics and thresholds;
- [WORK_LIST.md](WORK_LIST.md): tickets and the I01–I17 reconciliation;
- [PRACTITIONER_AND_ALTERNATIVES.md](PRACTITIONER_AND_ALTERNATIVES.md): practitioner assessments and the eight-alternative comparison;
- [artifacts/](artifacts/): sanitized traces and the verification summary.

## 0. Coverage map and method

| Area | Depth | Notes |
|---|---|---|
| `/analyze` path: context assembly, observations, prior findings, prompts, persistence, response | Deep | Source plus reader-boundary execution (E14) |
| Engagement investigation: build, role crawl, worklist, legs, coverage, job lifecycle | Deep for data flow; medium for individual legs | Source plus stubbed matrix execution (E33) |
| The four structures (relations, task graph, access matrix, coverage) | Deep | Producer → storage → reader → decision → UI traced |
| Java ↔ Python contract | Medium | Models, client endpoints and the context menu; Java not built (E04) |
| Safety, scope and egress | Medium | Gate, scope, no-run routes, third-party egress |
| Inference efficiency | Medium | Call sites, context assembly, accounting |
| Individual validator oracles; RV-O/P/Q residuals | Light | Out of the cross-request focus; tracked by existing batches |
| I03/I04/I08/I09 acceptance | Not examined | No claim made |

**Method.** One agent ran separate passes from six perspectives: architecture, reliability,
enterprise pentester, bug bounty, LLM efficiency and product. These were not independent
reviewers. One delegated subagent did only the competitor research (§11 of the brief), and its
output is marked provisional.

Answer keys, blind-target implementations, `testing/blind-target-2/` and `testing/vulncorp-helpdesk/`
implementation files were not opened. The `git fetch --unshallow` added history objects only (E00a).

## 1. Five consequential findings

1. **The historical crAPI workflow never had working cross-request memory, and it never touched the graph or the matrices.**
   - **Workflow:** the driver of record sent each capture to `POST /analyze` by itself, in the default pile (H02), with active validators armed (H03). This is the passive analysis path, not the engagement investigation, so no role crawl or access matrix was built.
   - **Prior findings were unreadable:** at the run's commit the default-pile writer stored principal `""` while the reader filtered by `"anonymous"`/`"captured:…"`, so no analysis could read any earlier finding (H04). Captures without findings were not kept at all (H05).
   - **The one surviving channel:** global "CONFIRMED at a path-shaped endpoint" notes, which false confirmations could also seed (E23).
   - **Verdict on the owner's hypothesis:** consistent with source (SOURCE-SUPPORTED), but **not verified as the cause** of 0–1/20 recall. Acquisition independently missed ≥6/20 cases (H01). Six false confirmations per run are a separate precision failure. Identities, stage health and any WIP in the running server are UNKNOWN (H06, H07).
2. **Today, the earliest verified break in advisory cross-request use is retrieval: "related to other exchanges."**
   - **Join rule:** observation memory (I02-C) joins only captures with the *exact same path*, no ID templating, and the *same credential context* or analyst-declared same tenant (E12).
   - **What that excludes:**
     - a request for another object on the same route;
     - an identifier disclosed by one endpoint and used at another;
     - the same request made by another principal.

     The first two are invisible even to the exclusion counts (VERIFIED NOW, reader boundary, E14).
   - **What the model sees when rows do join:** status, size and JSON key names only (E13), under a "do not re-report" prior-findings header (E16).
   - **What persists afterwards:** no structured citation (E17).
3. **The automated role/access matrix cannot compare two accounts that share a role.**
   - **Keying:** cells are keyed by role label, not principal, and replaced on each ingest without session or time (E32).
   - **Execution:** with alice and bob both `user`, a real same-role BOLA produced **0 IDOR leads**, and an owner-scoped cell recorded `{'user': 403}` alongside `reachable: ['user']` (VERIFIED NOW, stubbed boundary, E33).
   - **Object recognition:** UUID-addressed objects are not recognized as objects (E34).
   - **Unused paths:** the coverage matrix above it is principal-keyed, so the two disagree (E36). The real-object-ID cross-role probe has no production caller (E35).
4. **Two automated paths can confirm from evidence that cannot carry the claim.**
   - **Cross-identity:** it confirms BOLA from response similarity plus an anonymous denial, with `ownership=None` in every production construction. A resource legitimately shared with all logged-in users would confirm (SOURCE-SUPPORTED, E38).
   - **Sensitive files:** discovery marks `sensitive_file_exposure` *confirmed*, 0.95, high, from status 200–399 alone, and the evidence text says "HTTP 200" even for a redirect (E39).
   - **Status:** both contradict the standing zero-false-confirmation no-go. Neither appears among the open items in `docs/CODE_REVIEW_02_TRIAGE_2026-10-19.md`. The batch briefs themselves are not in Git (E01).
   - **Related open decision:** the triage asks the owner "whether a declared victim id counts as ownership evidence". That is the natural place to decide D1 (WORK_LIST §4).
5. **The operator cannot see or steer cross-request evidence, and the two modes do not share it.**
   - **Burp contract:** Burp's client model omits `degraded`, `agent_errors`, `stage_outcomes`, `observation_context`, `validation_reports` and `proof_records`. It sends no capture time, completeness, pile or attribution, and fans a multi-selection out into unrelated analyses. It cannot start or read an investigation (E21, E22).
   - **Mode separation:** investigation results never become observations. The job's state, matrix and coverage live only in the job record and manifest (E30, E31). Advisory and automated modes therefore cannot cite each other's evidence (X7).
   - **Privacy:** "passive" analysis also sends component names to five third-party services by default, and the docs do not say so (E19).

## 2. Architecture and mode map

```
Burp extension (Java, not built here: E04)          Python harness  harness/server.py (127.0.0.1:8787)
──────────────────────────────────────────          ─────────────────────────────────────────────────────────
Context menu "Send to LLM Harness"  ── N calls ──►  POST /analyze ─► Orchestrator.analyze  (own run, ceiling 1000)
  (one call per selected item, E21)                   ├ prior_findings_summary  (same principal, other URLs)    E15
  sends exchange + force_agents only                  ├ select_observations     (exact path, same context)      E12
                                                      ├ fast_path / coordinator ─► agents ─► critique (Ollama)
                                                      ├ validators: passive unless active_enabled  ─► TargetTransport ─► target
                                                      ├ record_observation / persist_findings / persist_proof ─► SQLite
                                                      ├ knowledge.remember_finding (default pile ⇒ GLOBAL note)  E23
                                                      └ mutate_engagement  (write; read only by opt-in auto-escalate) E24
  shows summary + findings  ◄──────────────────────  AnalysisResponse (degraded, observation_context … not read by Burp)

Tools tab ── /crawl-roles, /engagement/{h}, /advance ─► role_crawl (matrix keyed by ROLE, E32) ─► EngagementState (replace cell)
                                                      GET /engagement/{h} ◄─ worklist(fused_score) + ready/blocked tasks (E37)

(no Burp caller) ── POST /engagement/{h}/investigate ─► job ─► investigate_engagement
                                                        build_engagement (fresh state, E30) → role_crawl → worklist_investigator
                                                        → legs/validators (run budget, scope, cancel) → analyze per capture (E31)
                                                        → chain_linker → coverage (principal-keyed, E36) → job record + manifest
                                                        (state / matrix / coverage NOT written to the store; proofs are)
```

### Mode capability table

| Workflow | Advisory (`POST /analyze`) | Automated (`POST /engagement/{host}/investigate`) |
|---|---|---|
| Single captured exchange | **Supported** (E10). Zero target traffic under defaults (E18, SOURCE-SUPPORTED). Degraded flag when all agents fail or a stage fails (E20). | Supplied as `seed_exchanges`; imported only if its credentials match a declared role (`engagement_builder.py:109-121`) |
| Multiple selected exchanges | **Unsupported as a set.** N independent analyses (E21) | n/a |
| Incremental history | **Partial:** same exact path and same credential context only; key names only (E12–E14) | **Unsupported:** fresh state per job (E30) |
| Role / principal comparison | **Unsupported by default:** another principal's rows are excluded unless both declare the same tenant (E14). No Burp field for declaring it (E21). | **Partial:** distinct role *labels* only; same-role principals collapse (E33). Cross-identity validator replay needs registered identities; confirmation lacks ownership (E38). |
| Resumed engagement | Pile history persists (I02-B/C). Corrections via `/observations/*` are API-only (E21). | **Unsupported:** jobs are not resumed after restart (E30) |
| Automated investigation | n/a | **Supported by API only.** Bounded by the run budget, scope and cancel (I03/I05, HISTORICAL/REPORTED). No Burp entry point (E21). |

### Per-mode record

| Aspect | Advisory | Automated |
|---|---|---|
| Entry point | `server.py:615` → `orchestrator_detect.py:473` | `server.py:1483` → `orchestrator_chain.py:509` |
| Session/run ownership | Own `RunContext`, ceiling `analyze.max_requests` (1000). Credentials bound only in active mode. | Job-owned `RunContext` (`runs.max_requests`); declared roles registered as sessions |
| Inputs | One exchange, optional pile and attribution | Base URL, roles (role, headers, name, tenant, expected permissions), seed exchanges, limits |
| Retained observations | Supplied captures (E11) | None as observations (E31); proofs and ledger events |
| Graph/matrix producers | Engagement state, findings only (E24) | Access matrix, engagement state, task graph, coverage (in-memory) |
| Graph/matrix consumers | **None** for the analysis itself (only the opt-in, off-by-default auto-escalation re-crawl reads it afterwards, E24) | Worklist ranking (`fused_score`), IDOR/auth-bypass candidates, coverage report; task graph display-only |
| Permissions | Passive by default; active validators only with `validators.active_enabled` | Same gates plus scope pre-authorization (`server.py:1522-1529`) |
| Outputs | `AnalysisResponse`; findings in `/report` and SARIF | Job result (≤2 MB) plus manifest; proofs; findings from per-capture analysis in the default pile |
| Current evidence | Reader-boundary trace (E14); caller tests reported but not runnable here (E03) | Stubbed matrix trace (E33); caller tests reported (I03), not runnable here |

## 3. crAPI failure funnel

### 3.1 Historical run (`06a128fc`, three repeats, same capture set)

| Boundary | Status | Evidence |
|---|---|---|
| Capture available | **Break for ≥6 of 20** ground-truth cases: their endpoints were absent from the capture set. Capture-set size UNKNOWN. | H01 |
| Ingested | Each capture was posted to `/analyze` after a cache clear; per-exchange errors and timeouts UNKNOWN | H02, H07 |
| Correctly attributed | Credential context computed; no declared attribution; registered identities UNKNOWN | H02, H07 |
| Retained | Non-finding captures **not retained** (feature absent). Findings stored with principal `""`. | H04, H05 |
| Related to other exchanges | **Broken:** prior findings unreadable by any later analysis. Only global knowledge notes crossed requests. | H04, E23 |
| Graph/matrix updated | `/analyze` wrote findings into engagement state, which no analysis read. No role crawl, so no access matrix. | E24, H02 |
| Relevant evidence retrieved | 0 by construction (cross-request) | INFERRED from H04, H05 |
| Analysis/planning consumes it | n/a | — |
| Check/advice produced | Single-exchange agents. Active validators armed. The cross-identity replay (single-request, Autorize-style) needs registered identities, and whether it ran is UNKNOWN. Six false confirmations per run (reported). | H01, H03; `validators/registry.py:442-468` |
| Evidence persisted / inspectable | Findings in the store and report; the external report is not in the repo | E01 |

**Earliest proven break (source level):** *retained / related*. This was a design gap plus a defect
(H04, H05), not a disconnected consumer: no graph or matrix was on this workflow's path at all.
Acquisition (≥6/20) is an independent upstream break.

**Alternative explanations still open:**
- **Request shape:** body SQLi and JWT dispatch were deferred on 2026-10-15 and fixed later (I09, reported).
- **Label routing:** 51.64% of class labels missed at the then-committed candidate (`docs/DECISIVE_FIX_VERIFICATION.md`).
- **Missing second identity:** the "second crAPI failure mode" comment at `validators/registry.py:460-467`.
- **Model capability:** `qwen3:8b`.
- **Time per run:** about 4,100 s.
- **SSRF:** collaborator reachability (DET-SSRF).

None can be ruled in or out without the external report and its provenance (H06, H07).

### 3.2 Present-day controlled case (VERIFIED NOW at the reader boundary, E14)

The setup uses synthetic `lab.invalid` captures, two credential contexts (alice, bob), no attribution
(as Burp sends today) and no network:

- **o1:** alice lists recent posts. The response discloses bob's vehicle id.
- **o2:** alice reads her own vehicle.
- **o4:** bob reads his vehicle.
- **o3:** alice requests bob's vehicle id. This is the question.

| Boundary | Count / result |
|---|---|
| Captures available | 4 relevant (o1, o2, o4 stored; o3 is the current analysis) |
| Ingested and retained | 3/3 `stored` |
| Attributed | 2 credential contexts recognized; 0/4 declared attributions |
| **Related to other exchanges** | **Rows the reader considers: 1 (o4). Selected: 0** (`unattributed-context`). o1 (disclosure) and o2 (same route, other id) are invisible, filtered by exact-path SQL. |
| Relevant evidence retrieved | 0 |
| Consumed / advice | No cross-request basis is available to the model |
| Persisted | Observation rows only; no relation or citation (E17) |
| Operator can inspect | API: `observation_context.excluded_counts = {"unattributed-context": 1}`. Burp: nothing (E21). |

**Expected and actual for o3**, both sanitized:

```
EXPECTED (spec X1/Q1)                                   ACTUAL (store.select_observations + observation_context_block)
outcome: answer (hypothesis, not confirmed)              selected: []
cites: o1 (identifier disclosed at posts[].vehicleid),   excluded_counts: {"unattributed-context": 1}
       o3 (identifier used in path), o4 (owner baseline) block: ""   (o1, o2 never considered: different exact path)
relation: identifier_disclosed_then_used;                prior findings for o3: none (other principal's finding
          same_object_other_principal                        filtered; same-URL findings always excluded)
missing: ownership declaration / access policy
next step: declare owner of the vehicle id, or compare against bob's baseline
```

When both sides *do* declare the same tenant, the block shows o4 as
`status 200, application/json, 65 bytes, keys carId,owner`. That is not enough to tell whose
vehicle it is (E13, E14).

**Relevant structures for this case:**
- the application/evidence relationship structure: identifier reuse across endpoints, plus the same object requested by two principals;
- the principal-keyed role/access matrix, in automated mode.

**Not relevant to the conclusion:**
- the task graph;
- the coverage matrix, which matters only for reporting what went untested.

An active investigation result would not show that the passive `/analyze` workflow works. The two are separate paths (§2).

## 4. Reliability, safety, privacy and inference

| Area | Observation | Evidence |
|---|---|---|
| Shared limits in automated paths | Investigations, crawls and advance own a run with scope, budget and cancel (reported, I03/I05/RV-G). **Exception:** `/engagement/{host}/run` with `execute=true` uses an unbounded standalone context (off by default). | E40; WL-12 |
| Advisory does not enable execution | Defaults are passive; validators are filtered by `active` (SOURCE-SUPPORTED). HTTP method is not treated as proof of safety: the gate text says side effects are not established. | E18, E41 |
| Degraded states | Explicit when all agents fail, the breaker is open or a stage fails. A partial agent failure does not set `degraded`. Burp does not read the flag. | E20, E21 |
| Model output vs policy | Agents cannot mint confirmations (`sanitize_agent_finding`; validators confirm). This was not re-tested here. | `models.py:173` `sanitize_agent_finding`; `orchestrator_detect.py:383-385` |
| Isolation | Default-pile knowledge notes are global across hosts and engagements | E23 |
| Third-party egress | Five external services are on by default in passive analysis, undocumented | E19 |
| Restart/recovery | Interrupted jobs are marked ended and not resumed; job results over 2 MB are dropped from polling | E30 |
| Inference call sites per analysis | Coordinator (unless fast path), N agents (sequential at `max_parallel_agents: 1`), critique, optional rediscovery. `fail_open_mode: all` dispatches every agent when routing fails. | E05; `coordinator.py:259-338` |
| Context cost | Up to 8 prior findings and 8 observations are prepended to *every* agent prompt. No per-block token accounting. `num_ctx` is unset, which risks silent front truncation (documented open/verify in LIMITATIONS). | E16, E42, E05 |
| Observed cost | About 4,100 s per historical crAPI run (H01); 80–100 s per model call on one consumer GPU (USER_MANUAL, reported) | H01 |

Every optimization below is a proposal only. Local prompt caching is not assumed to save anything.

| Optimization | Expected benefit (assumption) | Quality risk | Validation gate |
|---|---|---|---|
| O1: deterministic relation records instead of raw context (WL-03) | Fewer tokens than rendering bodies; decisive facts kept | Lost facts the model would have used | WL-14: A2 ≥ A1 at ≤1.5× tokens; A2 > A2-pad |
| O2: explicit `num_ctx` plus a block-size warning (WL-16) | Avoids silent instruction loss | Higher memory and latency | Truncation warnings 0 on the corpus; latency measured |
| O3: answer only Q1–Q3 on multi-capture sets without fan-out to all agents (WL-07) | One structured call instead of N×agents | Missed single-exchange issues | Run single-exchange analysis separately; compare recall |
| O4: `routing_mode: families` (exists, off) | Fewer calls (reported) | Class coverage loss | Matched-budget ablation under I14 |

## 5. Source and reproducibility limits

- **Suites blocked.** All three required suites are BLOCKED in this container by absent
  dependencies, which were not installed per the brief. The only tier that ran was
  `evaluation_integrity` (59 OK). The reported green run at `b8e8057` is HISTORICAL (E03, H08).
- **No Java build.** `gradle shadowJar` was not run (E04). Java findings are source reading only.
- **Missing references.** The candidate manifest's overlay, the I01–I17 implementation guide, the
  code-review-02 report, handoffs and logs, the remediation register and the external crAPI report
  are not in Git (E01). CURRENT_STATE points at them, so its claims about them are
  HISTORICAL/REPORTED.
- **No services.** Ollama, Docker and the harness were unavailable (E02), so no model behaviour was
  observed and no end-to-end caller test was run. The two executions in this audit are a
  reader-boundary trace and a stubbed-boundary trace. Neither is a production-caller proof.

## 6. Readiness verdicts

These verdicts are kept separate per mode. Readiness in one mode does not transfer to the other.

| Context | Advisory mode | Automated mode |
|---|---|---|
| Local research (owner's machine, own lab) | **READY WITH CONDITIONS.** Scope: single-exchange triage, plus same-path, same-identity history. Conditions: green suites reproduced on that machine (WL-01); Ollama health checked; third-party lookups accepted or disabled (WL-11). | **READY WITH CONDITIONS.** Scope: owned lab targets only, explicit scope, the operator watching. Conditions as for advisory, plus E38 and E39 treated as leads, never as confirmations. |
| Supervised pilot (real engagement, expert reviewer) | **NOT READY** for the cross-request claim (finding 2). **INSUFFICIENT EVIDENCE** for single-exchange value: no measured model usefulness (I14). Burp does not show degraded results (E21). | **NOT READY.** The historical no-go stands (H01); open false-confirmation paths (E38, E39); same-role comparison is broken (E33); no fresh adjudicated run. |
| Routine professional use | **NOT READY** | **NOT READY** |
| External distribution | **NOT READY:** no reproducible build here (E03, E04), undocumented egress (E19), global notes (E23) | **NOT READY** |

**Measurable gates for the next verdict:**

- **Advisory pilot:**
  - WL-01 reproduced;
  - WL-03, WL-06 and WL-08 caller-verified;
  - WL-14 meets spec §9 for Q1–Q3;
  - zero target requests counted at the fixture.
- **Automated pilot:**
  - WL-02, WL-04 and WL-05 caller-verified;
  - WL-14 arm A3 with 0 false confirmations;
  - WL-15 adjudicated under I13.

## 7. Conclusion

- **What each mode supports now.**
  - Advisory: single-exchange review with passive deterministic checks. Its only cross-request memory is same-path, same-identity history plus same-identity prior-finding summaries. It cannot answer "does this pair of requests show one user reaching another's object?"
  - Automated: bounded discovery, a role-*label* access matrix and validator legs on owned targets. It cannot compare two same-role accounts, and two of its confirmation paths can overstate evidence.
- **Earliest verified break in the cross-request path.** Today it is the observation reader's join (exact path, same context), VERIFIED NOW at the reader boundary. For the historical crAPI run it was retention and the prior-findings join, SOURCE-SUPPORTED at `06a128fc`. Acquisition was an independent upstream loss.
- **Smallest next improvement.** WL-03: deterministic relation records keyed by a shared route template and keyed-hash identifier index, returned and cited as a comparison class. This needs WL-02's normalizer and owner decision D2. For automated mode, WL-02's principal keying is the matching smallest fix.
- **Experiment that could falsify the benefit.** WL-14 on the frozen X1–X3 corpus. The benefit is falsified if any of these holds:
  - A2 does not beat A1 by the predeclared margin;
  - A2 is not better than A2-shuffle and A2-pad, so the gain would come from more context rather than correct relations;
  - unsupported claims or false confirmations rise.
