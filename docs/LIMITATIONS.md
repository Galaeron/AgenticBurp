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
  - Note: the live-leg tests pass the loopback fixture host as each validator's
    `allowed_hosts` themselves, so they do not depend on `server.allowed_hosts`.
- **[partial] The coverage ledger still under-reports what exists.** `harness/
  coverage_manifest.py` registers loopback confirm/control tests for **20 of 67**
  requirements, plus 3 manual-only ones; the other 44 are `gap_unimplemented`,
  which means "no test registered in this ledger," **not** "no test exists" and
  never "verified absent." `covered_partial` means one scenario of the
  requirement passed on an owned loopback fixture in this run, not that the
  requirement is covered. The smoke and full tiers run
  `coverage_manifest --check` after their unit tests; it **blocks** when a registered test fails, is
  skipped, or left no fresh evidence; manual, N/A and unregistered rows do not
  block. Still unregistered: live tests that need Playwright or sqlmap, slow
  loopback modules kept out of smoke (write integrity, business flows, exposure
  leads), and legs with no paired control. The `HS-*` harness safety properties
  are reported in their own section and are not WSTG coverage.
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
  the wide agent spread dilutes that focus. (A header-noise gate already caps the
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
- **[partial] Empty scope is not one contract everywhere.** Every route that sends
  target traffic needs `active_enabled`, and a run's transport
  (`run_context.ScopePolicy`) permits nothing on an empty `allowed_hosts`. The
  crawlers, the missing-auth probe, API-surface discovery and the standalone
  active probe (`transport_for`, `standalone_context`) also fail closed on an
  empty scope. `scope_lock.host_in_scope`, which the safety gate and the validators'
  inline checks call, still reads an empty list as "no restriction", and the raw
  no-run clients below are not scope-checked at all. Set `server.allowed_hosts`
  explicitly and do not rely on a single backstop.
- **[partial] A legacy, unscoped transport path still exists in some
  validators.** ARC-7 removed the raw HTTP clients from the crawlers, discovery,
  feature workflow, the missing-auth probe and the cross-identity probe; they send
  only through a run's transport. These validators still fall back to a raw client
  when called without a run context: csp, header_injection, http_request_smuggling,
  jwt_forge, oauth, race_condition, rate_limit, recon, sqlmap (its boolean-probe
  fallback), subdomain_takeover, toctou and web_cache_poisoning. The no-run
  `safety_gate.GatedAsyncClient` is gate-authorised but has no run budget or
  address pin. `subdomain_takeover`'s fallback follows redirects with no scope
  check. The normal pipeline passes a run context and uses the scoped path;
  `transport_inventory.RAW_CLIENT_ALLOWLIST` lists every remaining raw client with
  its reason, and a test fails on any new one.
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

- **[fixed] Silent model failure.** `/health/details` (authenticated) probes
  Ollama and reports `degraded` with specifics; `/analyze` sets `degraded`, lists `agent_errors`,
  and warns in the summary when every agent failed. (Previously `/health` said
  "ok" with no model and failures hid in per-agent `raw_error`.)
- **[fixed] Some agents silently pinned the default model.** Redundant per-agent
  `model: qwen3:8b` pins removed; startup now warns on a shadowing override and
  `/health/details` exposes `agent_models`.
- **[open] Model-outage circuit breaker lingers ~60 s.** After 3 failures the
  shared breaker opens for 60 s before a half-open retry, so a model you just
  restarted still fails until the window elapses. `/health/details` lets you confirm
  recovery; tuning the window is a follow-up.
- **[mitigated] Prompts larger than a small `num_ctx`.** Ollama truncates an
  oversized prompt from the start (where the agent's instructions are) with no
  error; r3 (gemma4 at `num_ctx` 4096) logged 88 truncations. When `num_ctx` (or
  `prompt_budget.model_context_tokens`) is set, agent and critique prompts are
  now fitted to it, every cut marked and listed in `review_stats.elided`. With
  `num_ctx` unset, the harness asks the model server for the window it has
  (llama-server `/props`; Ollama `/api/ps`, then `/api/show`) and fits to the
  window it reports, never above the model's trained maximum; with none known it fits to
  `prompt_budget.unknown_context_tokens` (4096), never unfitted. Token counts are
  estimated, not measured; the discovered window is not refreshed after a server
  restart; families routing (`coordinator.routing_mode: families`) is not fitted.
- **[partial] Redaction is by name only; PII is not redacted.** Every model call
  passes `security.sanitize_for_inference`, which withholds the values of
  secret-named fields, URL parameters and inline assignments, and of the
  Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token and
  Proxy-Authorization headers. It scans no values: personal data (names, e-mail,
  phone, address, card and ID numbers) and a secret under an unlisted name or in
  prose reach the model as captured. The exact classes are in USER_MANUAL §5, and
  `harness/test_data_handling_docs.py` checks them against `security.py`.
- **[mitigated] Cloud egress is opt-in and refused by default (SEC-1).**
  `cloud_reasoning` sends the real, name-redacted content off-host, and an Ollama
  cloud model (`*-cloud`, `*:cloud`) is refused unless `ollama.allow_cloud_models`
  is true; the flag does not cover a role routed to another provider. A client
  data-handling statement still needs the policy decision (USER_MANUAL §5).
- **[open] "Passive" analysis looks up components at third-party services.**
  With the shipped config (`github_advisories`, `package_registry_checks` and
  `kev_check` all enabled), a component that an agent names and that is literally
  present in the captured exchange (a `Server`/`X-Powered-By` banner, a library
  banner, a manifest in a response body) is looked up off-host. The package name
  and ecosystem are sent to `api.github.com` (advisory search) and, for npm/PyPI
  names, to `registry.npmjs.org` or `pypi.org` (package age); any
  `GITHUB_TOKEN` or `github_advisories.token` goes to GitHub as well. The
  version is compared locally and is not sent. The CISA KEV catalog
  (`www.cisa.gov`) is downloaded whole and matched locally, and the Aikido
  malware-feed loader (`malware-list.aikido.dev`, same switch) is not called by
  the analysis path today. These services can still infer which technologies a
  client's target runs, and see the analyst's IP. To stop all of it, set
  `privacy: {external_lookups: false}` in git-ignored `harness/config.local.yaml`
  and restart; the value must be an unquoted boolean (a quoted `"false"` is
  rejected at startup). With it off, those analysis stages produce no report
  at all, so absence means "not checked", not "clean"; a local
  `github_advisories.snapshot_path` or `kev_check.local_file` still works because
  it makes no network call. Requests per service are counted under `events` in
  `/telemetry` as `external_lookup:<service>` (service names only). The default
  stays on, matching earlier behaviour; whether it should default off is an open
  owner decision. The `passive-only` operating profile does not change it.
- **[partial] Data on disk is unencrypted; engagements can now be separated and
  closed (OPS-5).** The tool encrypts nothing at rest, so it must run on a disk
  with full-disk encryption that also covers the export directory. With
  `HARNESS_ENGAGEMENT_ID` set, a process stores into its own
  `harness/engagements/<key>/` store. Closing an engagement (the
  `data_maintenance close-engagement` CLI, or `POST /engagements/close` behind
  the bearer token, `server.enable_wipe_endpoint` and a repeated-ID
  confirmation) exports first, then removes that store and the single store's
  rows attributed to that ID. Still open: separation is opt-in (without the
  variable everything goes to the single legacy store, as before); there is one
  engagement per process; the exchange cache (`harness_cache.db`) stays shared;
  in the single store, tables without an engagement column (test plans,
  validation runs, proof records, finding inputs and similar) keep their rows
  when an engagement is closed, so use a per-engagement store; removal
  is a file delete, not secure erasure; and the optional
  `store.engagement_retention_days` TTL ships off and only runs from the
  explicit `retention --apply` command.

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

- **[open] Orchestrator import cycle.** The orchestrator/chain/attribution modules
  import each other; many imports are inside functions to dodge cycles; `store`,
  `evidence_ledger` and `confirmation_gate` form a cycle. Split by size, not
  responsibility.
- **[open] Process-wide shared state.** `global_throttle`, a default safety gate
  and run context are process singletons, so two engagements can't be cleanly
  isolated. (Opt-in per-run scoping primitives exist but aren't the default.)
- **[open] Flat package + oversized files.** The modules sit flat in `harness/`;
  `server.py`, `store.py` and `orchestrator_chain.py` are each thousands of lines.
- **[open] Overlapping agents.** `business_logic`/`business_logic_enhanced` and
  `ai_llm`/`ai_security` are new-beside-old rather than replacements.
- **[open] Broad exception handling.** Many `except Exception` blocks; the proof-
  record persistence failure was promoted from `debug` to `warning` (a missing
  proof record is an integrity gap), but the pattern is widespread.
- **[open] Safety routing partly policed by source-grep tests** rather than the
  design forcing all traffic through the gate.
- **[by-design, minor] `/health` needs no auth** (DNS-rebinding protection
  applies). It is liveness only (ARC-8): no outbound request and no model or
  agent names. Readiness, the agent/model map and the model egress state are at
  the authenticated `/health/details`; the other routes require the token.

## What is solid

Independent plug-in agents/validators (no orchestrator/server imports); a shared
`harness.models` vocabulary; careful model calls (JSON mode, thinking disabled,
typed errors, token logging); SQLite in WAL mode with per-call connections and
lock retries; and a large, real test suite (Python and Java; see `docs/TESTING.md`).
