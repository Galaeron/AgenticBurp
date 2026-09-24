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
- **Principal-review implementation path (2026-09-24):**
  [docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md](docs/PRINCIPAL_REVIEW_IMPLEMENTATION_PATH.md);
  loop-consumable **PR-1..PR-11** filed in IMPROVEMENT_BACKLOG.md (order
  PR-1→2→3→4→5→6→7→9→10→11). R01/R04/R05/R06/R07/R14 independently re-verified.
  An unattended improve-loop is draining the offline PR batch (**PR-1 `[x]`
  `c26d769`** portable audit sink; **PR-2 `[x]` `b8fd09b`** exact-class label
  manifest/loader; **PR-3 `[x]` `809dd9c`** strict exact-class scorer + baselines
  (fixes R06 csrf≠ssrf/sqli≠xss; indiscriminate baselines fail the precision gate);
  **PR-4 `[x]` `112a884`** evidence-supported grading tier (supported TP needs
  exact-class AND resolvable proof; `unavailable`≠0); **PR-5 `[x]` `81558ab`**
  shared eval adapter (raw/surfaced/lead + provenance, visibility can't drift from
  the report) + read-only historical rescoring; **PR-6 `[x]` `605863b`** benchmark
  reconciliation + config-drift manifest + dated corrected assessment (originals
  preserved; strict recall refused where no manifest); **PR-7 `[x]` `a33a1ab`**
  typed stage health (`StageOutcome` + `degraded`; a failed critique can no longer
  read as clean; findings never dropped); **PR-9 `[x]` `07d1e13`** schema-aware
  recursive secret redaction (nested audit dicts; URL/body secret-name redaction
  that preserves injection payloads verbatim); **PR-10 offline half `[~]` `4913488`**
  policy-bound browser adapter (per-request interception; no cross-origin credential
  forwarding — live two-origin proof stays OWNER); **PR-11 offline half `[~]` `d82aab9`**
  tool-egress seam (fail-closed EgressPolicy + force-clean wrapper + receipts; sqlmap
  container path rerouted — live container-egress proof stays OWNER);
  **PR-13 offline half `[~]` `2d66c5e`** corpus contamination audit + sanitizer
  (PR-2 surfaced PixelMart TP10 embedding `testing/test-target/app.py` source with
  19 `BUG:`/`ANSWER_KEY` ground-truth markers → detector can cheat; `corpus_sanitize.py`
  audits read-only and strips ONLY annotations, keeping the disclosed source
  byte-for-byte; VERIFIED PixelMart 19 markers, DVWA/WebGoat 0; live recall-inflation
  re-measure stays OWNER). Suite green: harness 2625 OK (skip 2) / testing 148 OK /
  evaluation_integrity 42 OK.
- **Offline loop = LOOP_DONE (2026-09-24):** every loop-consumable item landed
  (PR-1..PR-11 + PR-13). Remaining work is OWNER/LIVE only: the live halves of
  PR-10/11/13 and PR-A..PR-E. **Sonnet coder hit its weekly limit (resets
  2026-09-28)**, so PR-11 and PR-13 were Opus-authored; any further unattended
  coding loop must wait for that quota or continue Opus-hands-on. Next per the
  user's standing instruction: full principal re-review against
  [reviews/PRINCIPAL_REVIEW_PROMPT.md](reviews/PRINCIPAL_REVIEW_PROMPT.md), then
  translate its findings into a fresh implementation path + backlog batch and
  restart the loop.
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
