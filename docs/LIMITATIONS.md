# Limitations, known issues & roadmap

An honest accounting of what this prototype does **not** yet do well. It exists
so the project stops over-claiming: the software runs and its parts are tested,
but its real-world effectiveness is unproven and several rough edges matter on a
real engagement. Status tags: **[fixed]**, **[partial]**, **[open]**,
**[by-design]**.

## Effectiveness is unproven

- **[open] No real-model accuracy measurement on unseen targets. This is the
  main gap.** Be precise about what *is* and *isn't* tested:
  - The **confirmation/validator layer IS live-verified.**
    `harness/test_leg_live_verification.py` runs the real validators over real
    HTTP against an owned loopback Flask fixture, each vulnerable case paired
    with a secure control that must produce no finding — covering SSTI, SSRF,
    command injection, stored + headless-browser reflected XSS, pickle-callback
    deserialization, JWT key confusion, session fixation / weak passwords /
    username enumeration, open redirect and mass assignment. (SQL injection goes
    through sqlmap, which needs Docker; path traversal has a separate
    operator-driven fixture. Browser/shell cases skip cleanly without
    Playwright/curl.)
  - What is **NOT** tested is the step before that: whether the **LLM agents
    detect the issue from real traffic in the first place.** The live suite
    confirms a leg *given the right hypothesis*; it is also a known owned
    fixture, not a blind/unseen target. Real-model **precision/recall of the
    agents on an unfamiliar app has never been measured.**
  - The one scorer that would measure detection (`testing/score.py`) needs a
    local model + a corpus you build, and its corpora are tuning corpora with
    committed answer keys (`testing/test-target/ANSWER_KEY.md`,
    `testing/blind-target-2/ANSWER_KEY.md`), so good scores there may reflect
    tuning, not capability. Measure against an untuned app
    (WebGoat/DVWA/PortSwigger); runbook in [USER_MANUAL.md](USER_MANUAL.md) §7.
  - Note: the in-flight scope migration (below) currently blocks the live-leg
    suite in a working tree with no scope set — the fixture host is refused as
    out of scope — so run it with `server.allowed_hosts` including the loopback
    fixture host.
- **[partial] The coverage ledger under-reports what exists.** `harness/
  coverage_manifest.py` only has **two** requirements registered (mass assignment
  and open redirect), so every other requirement is reported as
  `gap_unimplemented` — which means "not registered in this ledger," **not** "no
  test exists." Real live validator evidence for many more classes lives in
  `test_leg_live_verification.py` (above); it just isn't wired into the ledger.
  Two honest issues remain: the ledger should register the tests that exist, and
  the coverage report does **not** block (it is a report, not a gate).
- **[open] "Blind" is a misnomer for the committed targets.** `test-target`
  (PixelMart) and `blind-target-2` are developed-against tuning corpora. The only
  genuinely-blind mechanism is `testing/blind-test-kit/` (its target has no
  committed answer key); it is also the kit most likely to need rewiring — see
  below.

## Fits into a tester's workflow poorly

- **[open] Results live outside Burp.** Findings appear as prose in two custom
  tabs, not as Burp issues with request/response highlighting, severity, and
  send-to-Repeater; they do not merge into Burp's report and ignore Burp's own
  target scope. Every finding is copy-paste work. (Burp-issue integration is
  tracked but blocked on exercising the extension in Burp.)
- **[open] Manual, one-request-at-a-time, and slow.** The only entry points are
  right-click "Send to LLM Harness"; there is no background passive mode, and a
  single analysis can take minutes (see performance). Slow + interactive is the
  worst combination for manual testing.
- **[open] Duplicates Burp Scanner.** CORS/CSP/missing-headers/verbose-error/JWT
  checks overlap what Burp Pro already does deterministically. The LLM's real
  edge is access control across roles, business logic and multi-step workflows;
  the 36-agent spread dilutes that focus. (A header-noise gate already caps the
  low-value classes to "low".)
- **[open] Noise ranks next to real issues.** Findings like "[Unconfirmed]
  Multiple anomalies detected" or a medium "suspicious pattern: `Error:`" read as
  noise to an expert. Confirmed findings should each carry a reproducible proof
  request; the project's own notes acknowledge some confirmations lack proof
  records (see below).

## Safety & scope

- **[fixed] Crawler fetched any host with an empty scope.** `/crawl` and
  `/crawl-roles` now fail closed on an empty `allowed_hosts` and require
  `active_enabled`, with a clear 403; `crawler._host_allowed` fails closed at the
  chokepoint. Regression-tested.
- **[partial] Empty scope is handled inconsistently across the codebase.** The
  main analysis path and crawler fail closed in active mode, but `scope_lock`,
  `safety_gate` and several validators' own inline checks are mid-migration to
  the same fail-closed contract. The safety guarantee currently leans on the
  top-level check; set `server.allowed_hosts` explicitly and do not rely on a
  single backstop. (This migration is in-flight in the working tree and is why
  some active-gate unit tests are red.)
- **[partial] A legacy, unscoped transport path still exists.** ~20 modules have
  both the new scoped executor and a legacy raw HTTP client used when no run
  context is passed; `subdomain_takeover`'s legacy path can follow scraped
  redirects without a scope check. The normal pipeline uses the scoped path.
- **[by-design] Scope is hostname-only.** The port is not part of the check, so
  anything else on the same host is technically in scope. Documented in
  `config.yaml`.
- **[fixed] sqlmap destructive-flag / risk / level guard was a Python `assert`**
  (stripped under `python -O`). Converted to `if … raise RuntimeError`; tested to
  reject the assert form.
- **[open] No request rate limit by default** (`throttle.max_requests_per_second:
  0`). Set one for any real engagement (USER_MANUAL §3).
- **[open] Active tests can change/leave state on the target.** Mutating replays
  (race/TOCTOU bursts, mass-assignment) and the OOB deserialization RCE proof run
  once active+mutating are enabled and burst caps raised; file-upload/stored-XSS
  tests can leave artifacts with no automatic cleanup or change-list. RCE-class
  proofs may need explicit rules-of-engagement sign-off.

## Model backend & data

- **[fixed] Silent model failure.** `/health` now probes Ollama and reports
  `degraded` with specifics; `/analyze` sets `degraded`, lists `agent_errors`,
  and warns in the summary when every agent failed. (Previously `/health` said
  "ok" with no model and failures hid in per-agent `raw_error`.)
- **[fixed] Ten agents silently pinned the default model.** Redundant per-agent
  `model: qwen3:8b` pins removed; startup now warns on a shadowing override and
  `/health` exposes `agent_models`.
- **[open] Model-outage circuit breaker lingers ~60 s.** After 3 failures the
  shared breaker opens for 60 s before a half-open retry, so a model you just
  restarted still fails until the window elapses. `/health` now lets you confirm
  recovery; tuning the window is a follow-up.
- **[open/verify] `num_ctx` is not set.** A worst-case prompt may exceed the
  model's default context window, and Ollama truncates from the start (where the
  agent's instructions are) with no error. Verify your Ollama default and set
  `num_ctx` if needed. Not yet confirmed as a live failure.
- **[open] Bodies sent to the model unredacted; cloud egress needs a policy.**
  Only auth headers are masked. `cloud_reasoning` sends real content off-host.
  See USER_MANUAL §5. Redaction before cloud is not implemented.
- **[open] Data on disk is unencrypted** with no per-engagement separation; a
  wipe endpoint exists (`enable_wipe_endpoint`) but is not automatic.

## Reproducibility & portability

- **[fixed] Windows-only evaluation paths.** `detection_fixture.py`,
  `capture_exchanges.py` and `run_blind_eval.py` no longer hardcode `C:\tmp`;
  they use the OS temp dir + env overrides and a repo-relative corpus path. The
  Docker CLI fallback in `tool_runner.py` is now cross-platform.
- **[fixed] Dangling doc links / missing script reference.** Broken links in the
  doc map, ARCHITECTURE and testing READMEs removed/repointed; the `config.yaml`
  reference to an uncommitted `ab_routing_recall.py` softened.
- **[open] CI cannot run the real-model gate.** The scored tier needs a GPU /
  self-hosted runner and a locally-built fixture, so it only runs on manual/
  scheduled dispatch; PR CI runs the scoring *math* and component tests. The
  stubbed root `SCORECARD.md` is not an accuracy artifact and is git-ignored.
- **[open] Supported-Python matrix is informal.** CI pins 3.14; core runs on
  3.11–3.13; the 3.12 proxy-extra `typing-extensions` conflict is fenced in
  USER_MANUAL §8.

## Architecture debt (roadmap, not bugs)

- **[open] Orchestrator import cycle.** ~10 orchestrator/chain/attribution modules
  import each other; many imports are inside functions to dodge cycles; `store`,
  `evidence_ledger` and `confirmation_gate` form a cycle. Split by size, not
  responsibility.
- **[open] Process-wide shared state.** `global_throttle`, a default safety gate
  and run context are process singletons, so two engagements can't be cleanly
  isolated. (Opt-in per-run scoping primitives exist but aren't the default.)
- **[open] Flat package + oversized files.** 114 modules sit flat in `harness/`;
  `server.py` and `store.py` are ~1,400 lines.
- **[open] Overlapping agents.** `business_logic`/`business_logic_enhanced` and
  `ai_llm`/`ai_security` are new-beside-old rather than replacements.
- **[open] Broad exception handling.** Many `except Exception` blocks; the proof-
  record persistence failure was promoted from `debug` to `warning` (a missing
  proof record is an integrity gap), but the pattern is widespread.
- **[open] Safety routing partly policed by source-grep tests** rather than the
  design forcing all traffic through the gate.
- **[by-design, minor] `/health` and `/telemetry` need no auth** (DNS-rebinding
  protection applies; the other ~47 routes require the token).

## What is solid

Independent plug-in agents/validators (no orchestrator/server imports); a shared
`harness.models` vocabulary; careful model calls (JSON mode, thinking disabled,
typed errors, token logging); SQLite in WAL mode with per-call connections and
lock retries; and a large, real test suite (~2,400 Python + ~230 Java tests).
