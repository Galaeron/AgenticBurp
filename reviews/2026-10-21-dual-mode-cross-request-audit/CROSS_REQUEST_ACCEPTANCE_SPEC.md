# Cross-request acceptance specification — PROPOSED, 2026-10-21

**Status.** This is a proposal. It is not implemented, and nothing in it has been run against
a live target. It is frozen as written here. Any change after improvement work starts must be
recorded as an amendment with its date and reason. The owner sets every threshold marked
**[owner]**. The values given are proposals only.

All fixtures are synthetic and benign. They use reserved hosts (`*.invalid`, `127.0.0.1`
owned loopback servers), synthetic tokens and synthetic object IDs. No fixture contains an exploit payload.
Automated-mode arms run only against owned loopback fixtures until a separately authorized
live evaluation (I13) exists.

## 1. Minimum evidence contract, and what exists today

| Contract field | Required behaviour | Today (evidence) |
|---|---|---|
| Stable exchange/evidence reference | Stable `exchange_id` and resolvable evidence ref; deleted → `unavailable` | **Present** for supplied captures (E12, E14). Burp sends no `capture_id`, so the content hash is used (E21). |
| Capture time and provenance | `captured_at` kept separate from ingest time; `capture_source`; harness-fetched vs supplied | **Partial**. The fields exist. Burp sends neither (E21). Harness-fetched traffic is never an observation (E11). |
| Engagement / principal / role / tenant / session attribution, unknown allowed | Explicit unknowns; analyst revisions; no credential values stored | **Partial**. It is modelled in `observation_attributions`. Burp does not send it and has no correction UI (E21). The investigation's roles are not linked to observations (E31). |
| Method, normalized route, concrete object IDs, original request shape | Both the exact path and a route template; concrete IDs addressable without exposing raw values in prompts | **Missing route template**. The observation key is the exact path (E12). The matrices use three different templating rules, and none handles hyphenated UUIDs (E34). |
| Relevant response facts | Status, size and keys, plus the facts that decide the question (ownership-bearing fields, identifiers, body fingerprint) | **Insufficient**: only status, type, size and key names are kept (E13). |
| Application state/version and temporal relationships | Supplied `state_version`; order by capture time; contradictions flagged | **Partial**. The ordering exists (C03 tests, reported). No contradiction detector exists. |
| Observed / inferred / conflicting / stale / unavailable states | Each fact carries its state | **Partial**. `evidence_status` and `deleted` exist. There are no conflicting or stale fact states. |
| Bounded retention, retrieval, redaction, deletion, cache invalidation | Retrieval bounded; redaction before prompt; deletion and correction invalidate caches | **Present** for the same-endpoint reader (C09 reported; digest in cache key, `orchestrator_detect.py:652-656`) |

## 2. The four structures and their acceptance questions

| Structure | Question it must answer | Required producer → storage → reader → decision → UI | Today |
|---|---|---|---|
| Application/evidence relationships | Which observed entities, exchanges and states are related, and why? | observations + relation index → SQLite → `select_observations` / relation reader → advisory prompt and deterministic rules → API `observation_context`, `/report`, Burp | Relations exist only for exact path and same context (E12, E14). The engagement state is written by `/analyze` but never read by it (E24). |
| Task/dependency graph | Which tasks depend on other tasks or on missing evidence? | `task_graph` → engagement state → *(no decision reader)* → `ready_tasks` / `blocked_tasks` lists | Display only (E37). **Non-goal:** do not force it into decisions until a case needs it. |
| Role/access matrix | What was observed for each **principal**/resource/action, under which session and when? | `role_crawl` → `EndpointAccess` → `EngagementState.access` → `fused_score`, `_derive_candidates`, `_compare_identities` → investigation result | Keyed by role label, replaced on each ingest, with no session or time (E32, E33). |
| Coverage matrix | Which applicable checks were attempted, blocked, inconclusive, refuted, confirmed or untested? | `coverage_tracker` → job result → *(no store/export)* | Principal-keyed, automated mode only, not persisted or exported (E36). Advisory mode has none. |

## 3. Fixture families

Each case carries a machine-readable **expectation record**. It holds the declared ownership,
sharing and permission facts, the expected conclusion class, the observation IDs that must be
cited, and the IDs that must *not* be cited. An independent custodian holds the expectation
records for the blind subset (§8).

### X1. Pair-only conclusion: an ID disclosed by one endpoint and used at another

- **A:** principal P1 lists a collection. The response discloses object identifiers belonging to P2. Alone, A is not a finding.
- **B:** P1 requests one of those identifiers at a different route. The response's owner field is not P1. Alone, B shows only a 200 with data.
- **Expected (advisory):** an `access-control hypothesis` that cites A and B. It states the
  relation ("identifier first seen in A's response at key K, then requested in B's path").
  Assumption: the owner field means ownership. Missing evidence: the access policy and a
  P2 baseline. Next step: compare with a P2-owned baseline, or have the analyst declare
  ownership. It is **not** `confirmed`.
- **Controls:**
  - A alone and B alone each yield no cross-request conclusion.
  - Secure twin: B returns 403/404, or P1's own object. The result is "this pair shows the control held", never "endpoint secure".
  - Public twin: the object is declared public, so nothing is flagged.

### X2. Same role, different owner

- **Setup:** principals alice and bob, both with role `user`, and anonymous. Three routes:
  - an owner-scoped object: bob is denied;
  - a vulnerable object: bob receives alice's object;
  - a resource **declared shared** with all authenticated users.
- **Expected:**
  - **Vulnerable:** a lead is produced. Automated mode confirms only with declared ownership evidence (owner = alice, bob not entitled) plus a principal-keyed comparison.
  - **Owner-scoped:** control held.
  - **Shared:** never confirmed and never flagged as BOLA. It is reported as "authorized sharing (declared)".
- **Today:** the vulnerable case yields 0 leads (E33). With distinct labels the shared control is flagged (E33). The automated confirmation path has no ownership input (E38).

### X3. Different-role comparison

- **Setup:** admin and user on an admin-namespaced function with **declared** expected permissions, and a route that is public by design.
- **Expected:**
  - User allowed, against the declaration: a function-level candidate.
  - User denied: control held.
  - Public route: not flagged.
- **Rule:** an undeclared permission is "expectation unknown", never inferred from role rank.

### X4. Temporal state and contradiction

- **Setup:** an object goes from placed to shipped. A later capture shows `placed` with a later `captured_at`, which contradicts a known one-way workflow.
- **Variants:** out-of-order arrival, with t2 ingested before t1; unknown capture time.
- **Expected:**
  - Interpretation follows capture time and the declared workflow order.
  - The contradiction is reported with both citations.
  - With an unknown time, the answer is qualified as "ingest order only".
  - Arrival order never decides.

### X5. Same-looking IDs in different tenants or engagements

- **Setup:** object `1001` appears in tenant T1 and in T2, and in engagement piles E1 and E2.
- **Expected:**
  - Never merged and never compared across a declared tenant or pile boundary.
  - The exclusion appears as counts only.
  - A matching ID or URL alone never establishes common ownership.

### X6. Degraded inputs

| Case | Expected |
|---|---|
| Missing identity: no credential header and no attribution | Identity is `unknown`. This is not "anonymous access", and no cross-principal claim is made. |
| Expired session: 401 or login page for a previously valid principal | Labelled `session_expired`. It is not a denial that proves protection, and not a successful observation. |
| Truncated or binary capture | `completeness` is `truncated` or `binary_unsupported`. A key that is absent from a truncated body is not evidence of absence. |
| Duplicate input | Idempotent: one observation, status `duplicate` |
| Out-of-order arrival | As X4 |
| Restart/resume | Observations and relations survive restart. A cut-off investigation is reported as `ended`, never `complete`. |
| Stale cache after an attribution correction | The answer changes, and the old cached answer is not served |
| Deleted evidence | The citation resolves as `deleted`, and the conclusion is downgraded to "evidence unavailable" |

### X7. Mode parity

- **Setup:** the same supplied captures go to advisory mode and to automated mode (`seed_exchanges`).
- **Expected:**
  - Both modes produce identical exchange IDs, attribution, facts and relations for the supplied captures.
  - Automated mode may add harness-fetched observations, labelled with the run ID and `capture_source=harness:<run>`.
  - Permitted actions differ. Facts and provenance about the shared captures must not.

## 4. Advisory answer contract

A supported advisory answer is a structured object, persisted and exported, with these parts:

1. **question:** the question being answered, from a closed list (§4.1).
2. **observations:** cited observation IDs, each resolvable, with its evidence status.
3. **relationship:** the deterministic relation records used, such as identifier reuse,
   same route with another principal, or a temporal order.
4. **comparison:** the per-principal facts being compared.
5. **assumptions:** explicit, such as "owner field denotes ownership".
6. **contradictions**
7. **uncertainty:** `hypothesis`, `supported`, `confirmed` or `refuted`, plus the reason.
8. **missing_evidence:** a typed list.
9. **next_steps:** ranked, each with its expected information value. A step is one of:
   - which captured exchange to obtain;
   - which identity to add;
   - which declaration to make;
   - which validator would apply, and whether it needs active authorization.
10. **actions:** `proposed` and `executed`, kept separate. Advisory mode executes none against the target.
11. **outcome:** one of:
    - `answer`;
    - `no_finding` (enough relevant evidence, nothing found);
    - `insufficient_evidence`;
    - `analysis_failed` (model or storage failure; must also set `degraded`).

### 4.1 Supported questions, first release (proposed)

- **Q1.** Do these captures show a principal receiving an object that the evidence attributes to another principal? (X1, X2)
- **Q2.** Do role or principal responses differ from the declared expectations? (X3)
- **Q3.** Do these captures contradict each other or the declared workflow order? (X4)

Other questions return `insufficient_evidence` with a reason. They must not produce a generic checklist.

## 5. Assertions and boundaries

- **Production callers only.** Tests drive `POST /analyze` (ASGI), a proposed multi-capture
  route if one is added (WL-05), `POST /engagement/{host}/investigate` against owned loopback
  fixtures, and `GET /report` and SARIF. Helper assertions are additional, never a substitute.
- **Persistence:**
  - Each assertion is repeated after a process restart (new `store` connection, fresh cache).
  - Each assertion is repeated through `/report` and SARIF.
  - Each is also checked by a Java deserialization test of the API JSON into the Burp model, with a JDK (I15).
- **Zero new target requests in advisory mode,** asserted at two independent boundaries:
  1. a counter on the owned fixture server (socket accept and request count);
  2. the run's `TargetTransport` count.
- **Inference calls** are a separate boundary. Record the model call count, prompt and
  completion tokens per call kind, and wall time. Inference is not "target traffic", but it
  must be reported.
- **Third-party egress** (advisory, registry and KEV lookups, E19) is counted separately
  and must be zero when the proposed `privacy.external_lookups: false` is set (WL-11).

## 6. Fault injections

Each injection must make its acceptance test fail, or expose the precise degraded state. The
"relevant to" column marks which case actually depends on the component. Injections are not
applied to cases where the component is irrelevant.

| Injection | Relevant to | Expected detection |
|---|---|---|
| Drop the earlier exchange (do not write A) | X1, X4 | No relation. The outcome is `insufficient_evidence`, never a confident answer. |
| Sever the relation lookup (reader raises) | X1, X2 | `observation_context.status = unavailable`, the "Do not assume none exist" text, `degraded` set |
| Disable the role/access-matrix reader | X2, X3 (automated) | Lead lost, *and* a coverage cell reads `blocked`/`not_tested`, not `refuted` |
| Discard identity (strip attribution and credential context) | X2, X5 | No cross-principal claim; identity `unknown` |
| Reuse stale retrieval (ignore the digest in the cache key) | X6 stale-cache | Test fails: the old answer is served after a correction |
| Collapse principals to role label (the current behaviour, as a regression guard) | X2 | Vulnerable case missed, so the test fails |
| Remove the ownership declaration | X2 shared | The shared resource must **not** confirm. The test fails if it confirms. |
| Restore status-only sensitive-file confirmation | Discovery control (WL-04) | A 3xx or catch-all 200 must not be `confirmed` |

The existing `test_pipeline_gate.py` defect-injection controls stay as they are.

## 7. Evaluation arms

Fixed-corpus **reasoning** experiments (identical supplied captures, no acquisition) are kept
separate from end-to-end **acquisition** experiments (discovery and role crawl against owned
fixtures; live only under I13).

| Arm | Description | Purpose |
|---|---|---|
| A0 | Single-exchange analysis, no prior context | Baseline |
| A1 | Today's bounded context: prior findings plus same-path, same-context observations | Current product |
| A2 | A1 plus deterministic relation records (WL-03) | Candidate improvement |
| A2-shuffle | A2 with relation records re-pointed to wrong observations, same token volume | Separates "relevant relation" from "more context" |
| A2-pad | A1 plus irrelevant observations of equal token volume | Separates context volume from relevance |
| A3 | A2 plus a principal-keyed access-matrix consumer (WL-02), automated corpus only | Matrix contribution |
| D | Deterministic relation rules only, no model | Deterministic baseline |
| M | Model-assisted A2 vs D | Model value |
| H | Human-only analyst using Burp and a comparison workflow (e.g. Autorize-style replay), same captures | Analyst-effort baseline, where staffing allows |

Every arm uses the same model and configuration identity, seed, temperature 0, matched token
and request budgets, a fresh cache **and a fresh `harness_state.db`**. The knowledge notes in that
database cross runs (E23). Repeats measure stability. They are not independent samples. If an arm
gets privileged captures or labels, that advantage must be reported.

## 8. Metrics, rubric and adjudication

**Automated mode** (each with explicit numerator and denominator):

- **Acquisition funnel:** declared cases → reachable → acquired → applicable → attempted → completed.
- **Results:** precision and recall over all *declared* cases, plus conditional rates on acquired cases. Both are reported, and the denominator never shrinks to hide acquisition misses.
- **Error and gap rates:** false confirmations (count and rate); inconclusive and untested rates; stage failures.
- **Evidence completeness:** valid evidence completeness, i.e. confirmations with a resolvable proof.
- **Cost:** independent request counts (fixture-side), time and tokens.

**Advisory mode:**

- **Conclusions:** correct cross-request conclusions per supported question.
- **Unsupported claims:** the share of claims not traceable to a cited observation.
- **Citations:** correctness (cited IDs are relevant) and completeness (required IDs are cited).
- **Abstention:** `insufficient_evidence` returned where it is expected.
- **Next steps:** relevance, rated on a 3-point rubric.
- **Analyst effort:** corrections needed, time to a justified decision, and report preparation time (arm H).

**Rubric and adjudication:**

- Two independent adjudicators, neither of them the producing model, score blind to arm.
- Disagreements go to a third adjudicator, and Cohen's κ is reported.
- Expectation records for the held-out subset stay with a custodian outside the reviewing agent's view.
- Uncertain hypotheses are scored separately from false confirmations.

## 9. Proposed thresholds [owner]

| Gate | Proposal | Note |
|---|---|---|
| False confirmations | **0 observed** (existing no-go, unchanged) | Zero in N cases bounds the rate at about 3/N (95%, rule of three). It does not prove zero. |
| Advisory unsupported-claim rate | ≤ 5%, with the 95% upper bound reported | — |
| Citation correctness / completeness | ≥ 95% / ≥ 90% | — |
| Minimum meaningful improvement, A2 vs A1 | +20 percentage points correct Q1–Q3 conclusions, 95% CI lower bound > 0 | Also requires A2 > A2-shuffle and A2 > A2-pad by a margin of ≥ 10 pp each |
| Cost ceiling | ≤ 1.5× prompt tokens per analysis and ≤ +30% wall time vs A1 | Measured, not estimated |
| Sample size | ≥ 30 independent case pairs per family across ≥ 3 distinct synthetic application schemas; crAPI-like cases are at most one context | Results reported per context |

Business thresholds for precision versus recall trade-offs and for cost are the owner's
decision. Reports must include sample sizes, intervals, failed runs, contamination
exclusions and per-context results.
