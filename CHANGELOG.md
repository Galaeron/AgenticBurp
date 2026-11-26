# Changelog

All notable changes are recorded here, newest first, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) layout. The project follows
[Semantic Versioning](https://semver.org/) once it cuts releases; both the Python package
(`pyproject.toml`) and the Burp extension jar (`burp-extension/build.gradle`) are at 0.1.0, and
no release tag exists yet. How a release is meant to be cut: [docs/RELEASING.md](docs/RELEASING.md).

## [Unreleased]

The principal audit of 2026-11-19 (`reviews/2026-11-19-principal-audit/`) and its remediation
batches. The IDs are the audit's; each line names the behaviour that changed.

### Upgrade notes

- **Upgrade the harness and the Burp jar together.** Plan dispatch (ARC-4), the readiness
  call (ARC-8) and the settings call (ARC-15) changed on both sides; an older harness fails
  dispatch with a version hint.
- Every route that sends target traffic now needs `validators.active_enabled` (ARC-1).
- A run that would use an Ollama cloud model is refused unless `ollama.allow_cloud_models` is
  true (SEC-1).
- Burp's readiness check needs the pairing token: `/health` is liveness only (ARC-8).
- `POST /settings` rejects malformed values with a 422 and applies nothing (ARC-15).
- The harness runs with `runs.max_requests: 100000` and a per-origin request throttle (ARC-3).

### Security and safety

- ARC-1: `/crawl`, `/crawl-roles`, `/probe-missing-auth`, `/active-probe`,
  `/engagement/{host}/advance`, `/engagement/{host}/investigate` and `/engagement/{host}/run`
  with `execute` answer 403 before sending unless `validators.active_enabled` is on.
- ARC-2: standalone probes fail closed on an empty scope; `standalone_context` defaults to active mode.
- SEC-1: new `ollama.allow_cloud_models` (default `false`). A model named `*-cloud` or `*:cloud`
  is refused unsent, a run that would use one is refused at start (HTTP 409), and the run
  manifest and `/health/details` record `model_egress`.
- ARC-3: one process-wide request bucket per origin, enforced in the target transport on every
  redirect hop, and a run request ceiling (`runs.max_requests`) recorded in the manifest.
- ARC-14: target transports ignore proxy environment variables (`trust_env=False`).
- ARC-15: `/settings` `retry_budget` and `throttle_rps` are validated (422, nothing applied);
  removing a live throttle needs `confirm_unlimited`; Burp's throttle field starts blank.
- ARC-5: agent JSON cannot choose a finding's identity (an allowlist of settable fields replaces
  a denylist); a `principal_id` stands only if it is a session principal of the run.
- ARC-6: a model's `set_header` cannot set Host, hop-by-hop, `Proxy-*`, `Content-Length`,
  `Transfer-Encoding` or identity credentials; the transport drops the same names for every caller.
- ARC-11: standalone probes run through a per-call gate that reads the live `active_enabled`;
  auto-escalation reserves its host slot before the first await; the manifest records
  `active_enabled` changes.
- ARC-4: `POST /test-plans/{plan_id}/dispatch` issues a single-use nonce and the live policy; the
  Burp plane accepts a result only under that nonce, and `PlanePolicy` (Java) decides every send.
- ARC-12: plane refusals carry a typed `{"detail": {"reason", "message"}}` body (404 unknown plan,
  409 plan state, 422 content mismatch); Burp shows the reason.
- ARC-7: the raw HTTP clients are gone from the crawlers, discovery, the feature workflow, the
  missing-auth probe and the cross-identity probe; a function-level inventory test lists every
  remaining one (the validators' no-run fallbacks are still open, see `docs/LIMITATIONS.md`).
- ARC-8: `/health` is liveness only (no probe, no names); readiness moved to the authenticated
  `/health/details`.
- ARC-10: the seven library-only modules are marked `EXPERIMENTAL`.

### Verdicts and reports

- EFF-1: a control outcome is held, failed or unknown; only a held control refutes a finding.
- EFF-2: one class reading (`categories.finding_class`) and one class gate on every confirmation path.
- EFF-3: issue counts have named units (occurrences, issues, root causes); the report and job
  result carry them. `evaluation_integrity`'s report line says "Issues (distinct `issue_id`s)"
  instead of "Unique issues".
- EFF-4: the report drops "very likely" and its siblings; the status line leads with status,
  evidence maturity, verification and severity, and labels the model score uncalibrated.
- EFF-5: LEAD findings carry a reason (refuted, untested, rejected, environment) in the report
  and the lifecycle counts.

### Model cost and routing

- TOK-2: agent routing matches parameter names and URL path segments by token, not substring.
- TOK-3: the iterative agent shows the latest 8 steps in full (`iterative_agent.history_window`)
  and summarises earlier ones.
- TOK-4: prompts fit the context window the model server reports (`/props`, `/api/ps`,
  `/api/show`), capped by `ollama.num_ctx`; with none known they fit `prompt_budget.unknown_context_tokens`.
- TOK-5: the coordinator fences response bodies with a per-call nonce and counts every routing call.
- TOK-6: the sanitised view of an exchange is built once and shared by every agent.
- TOK-7: classifier payloads are pruned structurally, never cut mid-token.
- O11: the model-call pacer is configurable as `ollama.rate_limit` (`enabled`, `burst_calls`,
  `calls_per_minute`, `max_wait_seconds`). The shipped values are the old behaviour (10 calls, then
  10 a minute); the 300 s wait bound is new, and the manifest records `model_rate_limit`.

### Build, supply chain and tests

- OPS-1: a blocking `pip-audit` job runs on pushes to `main` and `v*` tags, with a reviewed allowlist.
- OPS-1 follow-up: `harness/requirements.lock` moves past the known vulnerabilities in cryptography
  (50.0.2, with pyOpenSSL 26.4.0), h2, msgpack, pyasn1, tornado (6.5.10), urllib3, urwid (4.0.13) and
  Werkzeug. Four tornado advisories fixed only in 6.6+ are allowlisted until 2027-01-31: mitmproxy
  12.3.1 caps tornado at 6.5.10, and the harness runs no tornado server.
- OPS-2: Gradle 8.7 wrapper with a pinned checksum and a Java 17 toolchain; CI builds with it.
- OPS-3: `python -m harness.lock_preflight` and a startup warning when installed packages differ
  from `harness/requirements.lock`.
- DOC-2: the `dev` extra and the CI section of `docs/TESTING.md` match `ci.yml`.
- GAP-4: loopback tests for five live safety properties (`HS-*`), reported in their own ledger section.
- GAP-2: five more live confirm/control pairs registered in the coverage ledger.

### Documentation and project state

- DOC-1: the README states no inventory counts.
- DOC-3: one six-step first-run list in the README and the user manual.
- DOC-4: the data-handling docs say exactly what `sanitize_for_inference` redacts and what it does not.
- DOC-5: `IMPROVEMENT_BACKLOG.md` is a generated list of open items; the full text is in
  `docs/IMPROVEMENT_BACKLOG_ARCHIVE.md`.
- OPS-4: this file, `SECURITY.md` and `docs/RELEASING.md`.
- STATE-2: one handoff file named by both onboarding files; `CURRENT_STATE.md` is at most 100 lines.
- STATE-4: the `sitecustomize.py` header matches its tracked status; `docs/TESTING.md` explains the hook.
