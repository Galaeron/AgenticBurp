# Batch AR-08b — route-independent issue identity beyond jwt_forge (2026-11-02)

Backlog: `IMPROVEMENT_BACKLOG.md` "AR-08b — Route-independent issue identity beyond jwt_forge".
Base: AR-08a (`37bcb62` + backlog `66e7724`, not yet reviewed/merged). Branch:
`claude/ar-08b-issue-identity-6bc8b0`. Mode: offline LOOP. The AR-08a migration is unchanged.

## Problem
Batch 08 made `jwt_forge` route-independent in `assessment_health.confirmed_issue_accounting`
only. The report path (`report_generator.export_issues_for_host` → `issues.issue_key`, which
backs `/issues`, SARIF and the MCP issues resource, plus the Markdown collapse
`_dedup_key`) still keyed every non-header finding on endpoint family. A jwt finding has no
attributed input, so it also got the per-finding disambiguator: one JWT verifier flaw
proven on `/api/me` and `/api/orders` was two issues, and a retest on a third route opened
a third. Separately, E2 csp/cors grouping read `Finding.header_fingerprint`, which the
findings table does not keep, so store-read csp/cors findings also split per route.

## Per-mechanism decisions
Route-independent means the proven flaw is one host trust policy that every route
applies, and a sound identity of that policy is recorded with the proof. Without the
identity a mechanism stays route-scoped (unknown never merges).

| Mechanism (validator) | Decision | Reason |
|---|---|---|
| `jwt_forge` | **route-independent** (key) | The flaw is the token verifier accepting forgeries. The fingerprint (alg/kid/typ/iss/aud) identifies the policy; another issuer or key is another fingerprint. |
| `csp_validator`, `cors_validator` (classes csp/cors) | **route-independent** (E2, existing) — now also from the store | A response-header policy repeated on routes. They now read the fingerprint persisted with the proof (AR-08a), so store-only findings group like in-run ones. |
| dependency/banner classes | route-independent (RB-3, unchanged) | Host-level software fact; identity is the component string. |
| `crypto_validator` (TLS) | route-scoped for now | Host:port-level in nature, but no persisted policy fingerprint (protocol/cipher/cert). Follow-up, not merged on a guess. |
| `http_request_smuggling_validator` | route-scoped | The desync depends on the request path through proxy/back end; route-specific back ends are common. |
| `web_cache_poisoning_validator` | route-scoped | Cache keys and unkeyed inputs are per route/cache rule. |
| `rate_limit_validator`, `csrf_validator`, `verb_tamper_validator` | route-scoped | Enforcement may be middleware, but a proof on one route does not show it is shared; each route is its own claim. |
| `oauth_validator`, `reset_token_validator`, `auth_sequence_validator`, `websocket_validator`, `subdomain_takeover_validator` | route-scoped | Tied to one flow endpoint, WS endpoint or hostname (the hostname is already in the key). |
| `verbose_error_validator`, `deserialization_validator`, `recon_validator` | route-scoped | Passive, per-response observations. |
| injection / access-control / file / race legs (sqli, nosql, xss variants, ssti, ssrf, xxe, command injection, path traversal, open redirect, header injection, idor, cross_identity, client_trust, sequence, file_upload, race, toctou, api_security, deserialization_oob) | route-scoped | The flaw is in one route's handling of one input; per-input key unchanged. |

## Design
- `issues.ROUTE_INDEPENDENT_MECHANISMS = {"jwt_forge"}` is the single set;
  `assessment_health` imports it (same object, same behavior).
- `issues._policy_of(f)`: the proof's persisted `policy_fingerprint` wins over
  `header_fingerprint` (same precedence as AR-08a's accounting).
- `issues.issue_key`: for a route-independent validator with a known policy the key is
  `(host, "", "", class, affected input, read/write boundary,
  "mechanism|validator|policy|principal_id|workflow_state_id")`. No endpoint family, no
  method, no per-finding disambiguator. Header-policy classes use `_policy_of`.
- Trust boundaries kept in the key: host, principal, workflow state, carrier (affected
  input), read/write boundary, policy. The read/write boundary is kept on purpose: it is
  the module's documented invariant. This is stricter than the accounting key (which does
  not split read/write), so the report can show a GET and a POST route of one JWT policy
  as two issues where the accounting shows one group. Conservative direction only.
- `_ISSUE_VERSION` stays 2. Bumping it would re-key every unrelated issue and break retest
  linkage. The new key shape (empty family plus a `mechanism|…` slot) cannot equal any
  v2 key. Previously stored jwt issues get a new id once their proofs carry a fingerprint.
- `store.all_host_findings` gains additive keys `validator`, `workflow_state_id`,
  `policy_fingerprint` (LEFT JOIN on the finding's exact `proof_id` and
  `proof_identity` at `identity_version = 1`). A read-only query change; no schema change.
- Markdown report: `ReportFinding` carries the same fields; `_dedup_key` passes them, so
  the collapse equals the export's key. A collapsed route-independent survivor lists every
  location (redacted URLs) instead of the "endpoint family" sentence.
- Export: `affected_routes` is also emitted for route-independent mechanism issues.

## Tests — `harness/test_issue_identity_routes.py`
Caller-level (real JwtForgeValidator, real confirm path inside one RunContext, findings
persisted with `store.persist_findings`; read through `export_issues_for_host` and
`generate_report_for_host`):
- `test_equivalent_policy_on_two_routes_is_one_issue_with_both_locations` (export: one issue,
  both instances, both routes, both proof refs; Markdown: one issue block naming both URLs).
- `test_stable_issue_id_across_runs` (a second run on another route maps to the same id).
- Negative controls: `test_distinct_token_policies_stay_separate`,
  `test_distinct_principals_stay_separate` (real principal on the case),
  `test_proof_without_persisted_fingerprint_never_merges`.
Store path for E2 (real `persist_proof_record` / `persist_findings`, real export):
`test_one_stored_policy_on_two_routes_is_one_issue`, `test_distinct_stored_policies_stay_separate`,
`test_unfingerprinted_stored_proofs_keep_one_issue_per_route`.

Red first: before the change the two jwt positives failed (2 issues; 2 ids) and the
controls passed. Defect injection after the change: disabling the route-independent
identity fails the 2 jwt positives; ignoring the persisted fingerprint fails those 2 plus
the csp store positive. Both restored.

## Gates
`run_gates.sh <label> <python>` writes `<label>.status` (exit codes only) and logs under
`logs/` (not committed). Results: HANDOFF.md.
