# Principal review implementation path (PR-1..PR-13)

Date: 2026-09-24. Planning baseline: `reconciliation-backlog`, HEAD `ca4ee15`.
Status: implementation tasks pending; this document is not a benchmark result and
does not start automation or change any default.

Source: [principal review](../reviews/2026-09-24/principal-review/REVIEW.md) and its
[verification record](../reviews/2026-09-24/principal-review/VERIFICATION.md). This
session independently re-verified R01, R04, R05, R06, R07 and R14 against source
before filing. Findings R01–R16 in that review map to the PR items below; the
review's own roadmap tiers (P0-A..P3-B) are preserved in the mapping column.

## Objective and scope

Make AgenticBurp trustworthy to rely on and safe to run actively, in this order:
(1) restore reproducible offline execution, (2) make detection scores mean
supported vulnerability discovery, (3) make silent degradation and incomplete
evidence visible, (4) contain every execution plane, then (5) the owner/live
efficacy and product work. Execute PR-1..PR-9 and the offline halves of
PR-10/PR-11 unattended (loop-consumable). PR-A..PR-E are OWNER/LIVE — leave `[ ]`.

Read AGENTS.md and CURRENT_STATE.md before implementation. Preserve existing edits,
regression coverage (especially `test_pipeline_gate.py`), and benchmark artifacts.
Never read answer-key files or blind-target implementations. Keep passive defaults
and active validators off; new capability ships OFF, live toggles go only in the
git-ignored `config.local.yaml`. Every new pipeline behavior needs a caller-level
test AND a negative control. Do not flip a `config.yaml` default that carries a
documented recall trade-off. Do not delete historical artifacts; annotate them.

## Do-not-duplicate map (reuse, do not re-file)

- **R03 DNS address binding** → already **P1-10** (address-bound connect-time pin).
- **R10 evidence completeness** → already **P0-6** (resolvable evidence for
  reproduction). PR-7 (stage health) is the sibling; extend, do not fork.
- **R04 Burp/API token pairing** → already **RB-1b** (OWNER/LIVE, needs JDK/Burp).
- **R06/R14 scoring & config drift** → the **BP-0..BP-3** path in
  [Benchmark precision implementation path](BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md).
  PR-2..PR-6 below promote those BP stages to loop-consumable checklist items so
  the unattended loop has concrete offline work; keep the BP doc as the spec.
- **R07 ablation validity** → extends **P2-2 / RB-7** (OWNER/LIVE).
- **R11/R12 pipeline duplication** → extends **P1-3** (unify evaluation layers).

---

## PR-1 — Portable, injectable audit sink (R05)

Roadmap: P0-B. Mode: **offline**. Depends on: none. Files: `harness/audit_logger.py`
(and any construction site that hardcodes `/var/log`). Effort: S. Impact: High —
this currently blocks the whole suite in a restricted environment (VERIFIED:
`smoke` 30 errors, `full` 183 errors, all tracing to `PermissionError` opening
`C:\var\log\agentic_burp\audit.log`).

Implement:
- Default the audit file to a platform-appropriate per-user data directory, not
  `/var/log/{name}`. Keep the value injectable (the existing setter stays the
  supported override).
- Wrap the `RotatingFileHandler` construction (file open), not only
  `os.makedirs`, in a guarded block: on `OSError`/`PermissionError`, disable file
  logging, emit ONE explicit startup diagnostic, and continue. Construction of
  `OllamaClient`/the pipeline must not raise because audit storage is unwritable.
- Add a deliberate policy hook for "required audit storage unavailable" so a
  future strict mode can choose to fail loudly; default is degrade-with-warning.

Acceptance: caller-level tests construct the logger AND a pipeline entry point
with (a) an unwritable directory and (b) an unwritable EXISTING file — both
degrade to `enable_file=False` with a diagnostic and no exception. Negative
control: a writable path still attaches the file handler and writes a record.
`python -m harness.suite smoke` and `full` reach a green tier in a restricted
(non-admin, no `C:\var`) workspace. Do not disable audit checks or require admin.

## PR-2 — Seed exact-class label manifest (R06 / BP-0)

Roadmap: P0-D. Mode: **offline**. Depends on: none. Files: new
`testing/labels/*` manifest + loader; provenance notes. Effort: S/M. Impact:
Transformational (load-bearing input for all strict scoring).

Implement the BP-0 manifest: per-exchange stable IDs, one or more expected exact
classes, explicitly tested-negative classes, label scope, and
`positive|negative|inconclusive|setup` status — hand-seeded from PERMITTED
captured evidence only (never answer-key or blind `app.py`), with a provenance
field per label. A benign SQL query is not proof the endpoint is secure against
every other class. Unknown/unresolved labels stay visible and unscored.

Acceptance: loader tests prove multiple expected classes are supported, negatives
are per-class not per-exchange, unresolved labels are surfaced (not dropped or
treated as secure), and setup rows never count as positives or FPs. Negative
control: a malformed/label-leaking manifest is rejected with a clear error.

## PR-3 — Strict exact-class scorer + indiscriminate baselines (R06 / BP-1a)

Roadmap: P0-D. Mode: **offline**. Depends on: PR-2. Files: new versioned scorer
module (do NOT mutate `testing/score.py`'s legacy contract; keep it as an
explicitly labelled coarse/historical metric), `testing/test_score.py` siblings.
Effort: M. Impact: Transformational.

Implement exact-class aliases distinct from OWASP reporting buckets — separate
SQLi, XSS, SSTI, command injection, SSRF and CSRF (today "cross-site request
forgery" collapses into SSRF and literal `csrf` is unmapped; SQLi and XSS share
A03). Emit three metric families side by side: any-alert coverage, exact-class
precision/recall, evidence-supported precision/recall. Define matching and dedup
units explicitly; duplicates must not inflate recall; absent predictions for known
positives are misses; missing labels are not negatives.

Acceptance: synthetic fixtures prove a wrong-class alert is not a TP, SQLi cannot
satisfy XSS, CSRF cannot satisfy SSRF, and dedup holds. Baselines are mandatory:
**always-alert**, **all-classes-on-every-exchange**, and **silent**. On a balanced
fixture the two indiscriminate baselines MUST fail the exact-class precision gate
even at perfect coverage; the silent baseline MUST fail recall. These baseline
assertions are the negative controls.

## PR-4 — Evidence-supported grading (R06 / BP-1b)

Roadmap: P0-D. Mode: **offline**. Depends on: PR-3. Files: scorer module +
`evaluation_integrity/evidence_audit.py` (reuse; do not build a second reader).
Effort: M. Impact: High.

Grade evidence tiers: captured support, differential/reproduced support,
unsupported, insufficient-artifacts. Reuse `evidence_audit.py`'s confirmation-claim
contract — a proof reference existing does not by itself establish validity. When
evidence is inadequate, emit `unavailable`, never a fabricated zero (today
`confirmed_tp/confirmed_fp` default to 0 and read as "evidence scoring works").

Acceptance: fixtures show a bare-`true` confirmation with no proof is graded
unsupported; a proof resolving to a different case is unsupported; an adequate
proof is supported. Negative control: a run with NO evidence instrumentation
reports `unavailable`, distinguishable from a genuine zero.

## PR-5 — One maintained runner + read-only rescoring (R06 / BP-2)

Roadmap: P0-D. Mode: **offline**. Depends on: PR-3. Files:
`testing/blind-target-2/run_blind_eval.py`, `testing/test-target/run_ablation_live.py`,
`harness/ablation_harness.py`, `harness/score_provenance.py`, new shared CLI under
`testing/`. Effort: M/L. Impact: High.

One shared adapter/schema for both drivers. Attribute findings by exchange
observations (reuse AR-3); mark legacy ambiguous attribution unresolved, never
assign a finding to all URL-sharing requests. Export finding IDs/classes at raw,
surfaced and lead stages, deriving visibility from the real report decision
(including the generic-confidence gate) so scorer and report cannot disagree.
Record checkout/dirty state, corpus+scorer hashes, effective config + overrides,
model identity/settings, run IDs, calls/tokens, elapsed, failures, starvation and
exclusions. Missing token instrumentation → `unavailable`, not zero. Strip scoring
annotations before `analyze()`. Support read-only historical rescoring with no
model or target traffic.

Acceptance: caller-level tests drive the real driver→orchestrator→store→report
path with synthetic exchanges and controlled model output. Negative controls
detect label leakage, dropped findings, wrong-exchange joins, and scorer/report
visibility disagreement. A synthetic CLI run produces valid artifacts with no
Docker/Ollama/network/target reads.

## PR-6 — Rescore and correct the historical benchmark + config-drift manifest (R06/R14 / BP-3)

Roadmap: P0-D. Mode: **offline**. Depends on: PR-5. Outputs: new versioned
assessment under `reviews/2026-09-23/benchmark/`; a config-diff manifest. Effort:
S/M. Impact: High.

Keep original JSON/logs unchanged; recompute only what artifacts support; mark
rescoring historical, never fresh inference. Generate a manifest comparing saved
run fingerprints (`fail_open_mode: curated`, `quarantine_leads: true`) against
shipped `config.yaml` defaults (`fail_open_mode: all`, `quarantine_unverified_leads:
false`, `routing_mode: agents`) so no one markets or tunes the wrong profile.
Remove/annotate unsupported claims (recall "solved", quarantine "buys nothing",
commercial parity). Preserve the original report with a dated correction pointer.

Acceptance: generated totals reconcile with each input file (including the
`tokens=0` vs `model_tokens=447k` and `breaker_failures=2` vs "no run starved"
contradictions); strict scores are never inferred from broad categories; control
units (exchange vs method/URL vs issue) are documented. This deliverable is a
report, so its "test" is a reconciliation script asserting totals match inputs.

## PR-7 — Typed stage health; degradation is never a clean result (R08)

Roadmap: P0-E. Mode: **offline**. Depends on: none (coordinate with P0-6). Files:
`harness/analysis_pipeline.py` (the `(0,0)`-on-error return), `harness/models.py`
(response/report status), report generator. Effort: M. Impact: High.

Replace the ambiguous `(0,0)` return with typed stage outcomes carrying
attempted/completed/failed/skipped counts and affected finding IDs. Surface a
`degraded` response/report status when critique (or any stage) fails, is disabled,
or ships findings unreviewed. A circuit breaker NOT opening is an insufficient
health predicate — do not equate "no starvation" with success. Preserve useful
partial results, visibly labelled.

Acceptance: caller-level tests show no-candidates, disabled-critique, and
FAILED-critique produce DISTINCT, inspectable stage outcomes (not identical
counters). Negative control: a healthy full run reports no degradation and the
same findings as before (no false-degraded). Report/response must never read
"clean" when a stage failed.

## PR-8 — (cross-ref) evidence completeness = existing P0-6 (R10)

Mode: offline. This is **P0-6**, not a new item. PR-7 surfaces stage health;
P0-6 enforces the ledger completeness/reproduction contract. Extend the existing
ledger; do not build a second provenance subsystem. Keep proof-before-confirmation.

## PR-9 — Schema-aware recursive redaction across sinks (R09)

Roadmap: P0-F. Mode: **offline** (synthetic canaries). Depends on: none. Files:
`harness/security.py` (`redact_headers`), `harness/audit_logger.py`
(`_sanitize_data`), `harness/agents/base_agent.py` (`_user_prompt`). Effort: L.
Impact: High.

Classify sinks (prompt/agent egress, audit/event store, export). Add schema-aware
RECURSIVE redaction so nested dict credentials and body/URL/query secrets are
handled, not only top-level bearer headers (today a JSON password, query token and
nested password dict survive into prompts/events; the header bearer is correctly
withheld — preserve that). Keep prompt logs storing hashes/lengths, not full
prompts. Do not claim all sensitive data can be auto-removed; provide an explicit
egress preview/policy.

Acceptance: synthetic canaries planted in header, URL, query, JSON body and nested
state are ABSENT from every prohibited sink (agent prompt, audit event, export)
across each provider/export boundary. Negative control: a task-relevant non-secret
field is preserved (redaction is not blanket deletion). No real credentials used.

## PR-10 — Policy-bound browser adapter (R01)

Roadmap: P0-C. Mode: **offline half loop-consumable; live verification OWNER**.
Depends on: transport/capability contracts. Files: `harness/browser_driver.py`,
`harness/validators/browser_xss_validator.py`. Effort: L. Impact: High.

Implement a run-bound browser adapter that intercepts EVERY context request
(Playwright routing), enforces scheme/origin/method/address policy per request,
attaches credentials only to approved origins (today captured `Authorization` is
projected to context `extra_http_headers` with no interception), blocks
uncontrolled service-worker/download/WebSocket paths, and honors cancellation.

Acceptance (OFFLINE, loop-consumable): unit tests drive the interception decision
function over synthetic requests — off-origin subresource BLOCKED, credential
attached only to approved origin, redirect to a new origin re-checked, cancel
stops dispatch. Negative control: an in-scope same-origin GET is allowed with
expected headers. **OWNER/LIVE (leave `[ ]`):** two-origin real-browser run
proving an owned off-scope listener receives zero requests/credentials.

## PR-11 — External-tool egress boundary (R02)

Roadmap: P0-C. Mode: **offline half loop-consumable; live verification OWNER**.
Depends on: transport/capability contracts. Files: `harness/validators/sqlmap.py`,
`harness/tool_runner.py`. Effort: L. Impact: High.

Add a per-run egress-proxy/network-sandbox seam so tool-generated requests are
policy-controlled, not just the initial check; scoped container identity;
cancellation/cleanup in `finally`; tool/version/digest and request receipts. Route
the direct sqlmap path through the runner cleanup wrapper rather than raw
`docker_cmd`. Keep structured argv (no shell-interpolation defect was found).

Acceptance (OFFLINE): tests assert the tool invocation is constructed WITH the
egress-proxy/sandbox parameters and that cancellation triggers cleanup in
`finally`; a receipt is recorded. Negative control: a run without the proxy seam
configured refuses to launch (fails closed) rather than sending uncontrolled.
**OWNER/LIVE (leave `[ ]`):** container run proving redirected/off-scope egress is
blocked and killed on cancel.

## PR-12 — (cross-ref) DNS address binding = existing P1-10 (R03)

Mode: mixed. This is **P1-10**. Reuse the DNS-boundary backlog work; support
explicitly authorized private/loopback lab targets rather than blanket-denying.

---

## OWNER / LIVE items (NOT loop-consumable — leave `[ ]`)

- **PR-A (R04 / RB-1b, P0-A):** secure local Burp↔API token pairing/refresh,
  token-file permissions, actionable 401 UI. Needs JDK/Burp build.
- **PR-B (R07 / P2-A):** true A–G ablations — real generalist (not `force_agents=
  ['sqli']`), a no-model provider that RAISES on any inference, a genuinely
  stronger model for F, an interaction corpus for E, stage-level invocation
  assertions, predeclared noninferiority margins. Needs real model/GPU.
- **PR-C (R13 / P1-A):** Gradle wrapper/toolchain + PR Java build/tests, wheel/JAR
  install smoke, SBOM, checksummed release manifest, digest-pinned tool images.
  (Committing the wrapper is offline; verification needs a JDK.)
- **PR-D (R15 / P1-D / BP-5C):** independent labeled corpus expansion, clustered
  splits, frozen sampling/decision design, untouched curated holdout. Case
  authoring — not automatable.
- **PR-E (R16):** five-practitioner design-partner pilot measuring analyst minutes
  saved per accepted reproducible issue. Non-code.

## Execution order (loop)

PR-1 → PR-2 → PR-3 → PR-4 → PR-5 → PR-6 → PR-7 → PR-9 → PR-10(offline) →
PR-11(offline). P0-6 (PR-8) and P1-10 (PR-12) sequence per their existing entries.
No GPU/Docker/JDK/blind-target run is required for any loop-consumable slice; the
loop skips every OWNER/LIVE item and note in its report why it was skipped.

First slice: PR-1 (unblocks the suite), then PR-2/PR-3 (strict scoring spine).
