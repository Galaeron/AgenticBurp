# Current state — 2026-09-24

## Checkout and review

Branch `reconciliation-backlog`; reviewed HEAD
`ca4ee15f0b45edc271363a53d6733c90bcde7127`.
The workspace contains pre-existing untracked evidence/runtime artifacts and
documentation changes. Preserve them; no production code or safety defaults
were changed by the 2026-09-24 review. Do not assume parity with remote main.

Current review: [principal review](reviews/2026-09-24/principal-review/REVIEW.md).
Commands, outcomes and limits:
[verification](reviews/2026-09-24/principal-review/VERIFICATION.md).
Previous onboarding state is preserved as historical evidence in
[the snapshot](reviews/2026-09-24/principal-review/CURRENT_STATE_before_review.md).
Durable implementation records remain in [IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md).

## Fresh verification (2026-09-24)

Repository root, `.venv-rationalisation/Scripts/python.exe`, Python 3.12.14:

- At review time `full`/`smoke` failed (exit 1, 183/30 errors) — dominant blocker
  was the audit logger opening `C:\var\log\agentic_burp\audit.log` in this
  restricted environment. **Fixed by PR-1 (`c26d769`)**; the loop batch now runs
  `full` green (harness 2625 OK skip 2 / testing 148 OK / evaluation_integrity 42 OK).
- Synthetic probes reproduced coarse scoring errors and prompt/nested-log
  redaction gaps (now addressed by PR-3/PR-9). Scripts are beside the review.
- Ollama version endpoint responded 0.34.3; no fresh model efficacy run.
  Docker access denied; readiness unknown. JDK/Gradle not found in checked
  locations; Java build and real Burp workflow remain unverified.

## Decisions and open work

- The review identifies browser/tool execution-boundary gaps, absent connect-time
  DNS pinning, default Java/API token-pairing mismatch, and hidden critique
  degradation as high-priority trust/operability work. See R01–R10 for evidence.
- **Cycle-1 principal-review batch (2026-09-24):** path
  [docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md](docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md);
  commits/details per-item in IMPROVEMENT_BACKLOG.md ("Principal review batch").
  Landed `c26d769`..`8afa49d`: PR-1 portable audit sink (R05 closed) · PR-2 exact-class
  label manifest · PR-3 strict scorer + baselines (csrf≠ssrf) · PR-4 evidence grading ·
  PR-5 eval adapter + rescoring · PR-6 benchmark reconciliation/drift · PR-7 typed stage
  health + `degraded` (wired) · PR-9 recursive/URL/body redaction (wired) · PR-10 `[~]`
  policy-bound browser adapter (offline) · PR-11 `[~]` tool-egress seam (offline) ·
  PR-13 `[~]` corpus contamination sanitizer (offline). Suite green: harness 2625 OK
  (skip 2) / testing 148 OK / evaluation_integrity 42 OK; `config.yaml` untouched.
- **Cycle-1 offline loop = LOOP_DONE (2026-09-24):** every loop-consumable item
  landed (PR-1..PR-11 + PR-13). **Sonnet coder hit its weekly limit (resets
  2026-09-28)** → PR-11/PR-13 were Opus-authored.
- **Cycle-2 re-review done (2026-09-24):**
  [reviews/2026-09-24/principal-review-r2/REVIEW.md](reviews/2026-09-24/principal-review-r2/REVIEW.md)
  + [VERIFICATION.md](reviews/2026-09-24/principal-review-r2/VERIFICATION.md). Verdict:
  the batch raised the trust *floor* (suite green, R05 closed; redaction + stage
  health wired into prod, R08/R09 mitigated) but not the *ceiling*. Key honest
  findings: **N01** the strict eval toolkit (PR-3/4/5/6) is correct+tested but NO
  `harness/` runner imports it — not load-bearing; **N02** the egress boundary is a
  fail-closed seam, not enforcement (`proxy_url=None`, `network=bridge` → container
  unconfined); **N03** R03 address pinning still open, now explicitly "deliberately
  not built", and PR-10's per-request browser checks inherit the same address-blind
  scope. Cycle-2 batch spec:
  [.../principal-review-r2/IMPLEMENTATION_PATH.md](reviews/2026-09-24/principal-review-r2/IMPLEMENTATION_PATH.md).
- **Cycle-2 offline loop = LOOP_DONE (2026-09-24):** NC-1..NC-4 all landed (Opus-authored).
  **NC-1 `[x]` `ed555dd`** strict scorer applied in a runner + baseline gate (closes N01);
  **NC-2 `[x]` `d505bd6`** browser interception plane locked in (13 guards + anti-bypass source
  scan; N04 corrected — plane already single-source); **NC-3 `[x]` `b8c573d`** regenerable config
  safety-defaults drift manifest + snapshot; **NC-4 `[x]` `0f0f107`** per-sink secret canaries —
  found + fixed a real leak (report chains section emitted evidence/suggested_test unredacted).
  Suite: harness 2645 OK (skip 2) / testing 163 OK / evaluation_integrity 42 OK; `config.yaml` untouched.
- **Remaining work is OWNER/LIVE only** (NC-O1..NC-O5, PR-A..PR-E, live halves of PR-10/11/13):
  tool-egress proof, connect-time address pinning, two-origin browser proof, recall re-measure +
  independent corpus, Java pairing/build. None loop-consumable. Canonical re-review spec:
  [reviews/PRINCIPAL_REVIEW_PROMPT.md](reviews/PRINCIPAL_REVIEW_PROMPT.md).
- Benchmark path: [BP-0 through BP-7](docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md).
  Seed exact labels first; BP-1a strict scorer and BP-1b evidence grading are
  separate. BP-2 restores the runner. BP-5C corpus expansion is mandatory before
  confirmatory GPU evaluation. This plan does not dispatch an automation.
- Saved five-app scores and P2-2 A/B/C/G results are **historical/reported**.
  “Any finding” and broad OWASP-category recall are not supported exact-class
  recall. B defaults to a SQLi specialist, C still records model calls, and F
  changes fail-open policy rather than selecting a stronger single model.
- Prior P2-2 COLLAPSE decision remains historical; valid generalist/no-model/
  graph comparisons and adequate labels are required before treating it as
  established equivalence. Family routing remains an opt-in existing candidate.
- Saved blind runs used curated fail-open/quarantine-on; checked-in defaults
  are all-agent fail-open/quarantine-off. Do not call those measurements default.
- Existing B2/AR/ER implementations are not reopened by this review. Their
  efficacy/owner-live residuals stay distinct from implementation completion.
- Prior open work includes Java token reader/shared execution trail, DNS pinning,
  privacy/redaction, practitioner UX, repeated precision/recall evaluation and
  default-change gates. Resolve against current source before picking tickets.
- Do not resume superseded `.worktrees/astra-*`, `supplemental-evidence`,
  `t08-final` or `../AgenticVibe-impl` drafts from historical notes.

Keep this file under 100 lines. Record detailed findings/results in their linked
documents rather than appending session histories here.
