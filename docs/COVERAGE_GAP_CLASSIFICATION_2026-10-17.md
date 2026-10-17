# Coverage-gap classification — 2026-10-17 (I11)

The requirement-coverage gate (`python -m harness.coverage_manifest --check`) reports
38 requirements: 2 `covered_partial` (AV-MASSASSIGN-01, WSTG-INPV-17) and 36 gaps
(33 `gap_unimplemented`, 3 `gap_manual`). Here `gap_unimplemented` means that **no
`EvidenceCase` aspect is declared** in `coverage_manifest.REQUIREMENT_TESTS`. It does not
mean the product lacks the check. This table classifies each gap against the source at
`1be5ed04`. Nothing here changes what the gate counts: a gap closes only when a test
records fresh run-bound evidence for a declared aspect.

**Method.** Each check's `confirmation` field (from `coverage_model.CHECK_CATALOG`) is
mapped to the validator module of the same name. Tracked `harness/test_*.py` modules that
reference that validator class are then counted. A module counts as caller/fixture
evidence when it drives a production caller or owned fixture (`test_leg_live_verification`,
`test_pipeline_gate`, `test_smoke_*`). This is a name-based heuristic: it shows where
evidence could be wired, not that a given test already proves the aspect.

Regenerate the table with `python testing/classify_coverage_gaps.py` from the repository root.

| Requirement | Name | Confirmation | Validator | Classification | Caller/fixture tests | Test modules |
|---|---|---|---|---|---|---|
| WSTG-CRYP-01 | TLS/SSL configuration | crypto | CryptoValidator | implemented; no tests found | - | 0 |
| WSTG-CONF-07 | HTTP Strict Transport Security | crypto | CryptoValidator | implemented; no tests found | - | 0 |
| WSTG-CONF-05 | Content Security Policy | csp | CspValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-CONF-08 | CORS policy | cors | CorsValidator | implemented; unit tests only; caller evidence missing | - | 3 |
| WSTG-INFO-02 | Server fingerprinting | recon | ReconValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-INFO-05 | Information in comments/metadata | recon | ReconValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-CONF-06 | HTTP methods | recon | ReconValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-CONF-02 | Security headers | recon | ReconValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-CONF-09 | Test File Permission | manual | - | manual prerequisite | - | 0 |
| WSTG-ATHZ-04 | IDOR / Broken Object-Level Authorization | cross_identity | CrossIdentityValidator | implemented; caller/fixture tests exist; evidence not wired | test_pipeline_gate, test_smoke_authorization_workflow | 6 |
| WSTG-ATHZ-02 | Broken Function-Level Authorization | cross_identity | CrossIdentityValidator | implemented; caller/fixture tests exist; evidence not wired | test_pipeline_gate, test_smoke_authorization_workflow | 6 |
| WSTG-ATHN-01 | Authentication bypass | auth_sequence | AuthSequenceValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-ATHN-07 | Weak password policy | auth_sequence | AuthSequenceValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-ATHN-03 | Weak lockout mechanism | rate_limit | RateLimitValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-ATHN-09 | Weak password-reset token | reset_token | ResetTokenValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-SESS-01 | Session management | auth_sequence | AuthSequenceValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-SESS-03 | Session fixation | auth_sequence | AuthSequenceValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-BUSL-09 | File upload | manual | - | manual prerequisite | - | 0 |
| WSTG-ATHZ-01 | Path traversal | path_traversal | PathTraversalValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-ERRH-01 | Error handling / stack traces | recon | ReconValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-BUSV-04 | HTTP request smuggling | http_request_smuggling | HttpRequestSmugglingValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-INPV-14 | HTTP header injection / CRLF | header_injection | HeaderInjectionValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-SESS-05 | CSRF | manual | - | manual prerequisite | - | 0 |
| WSTG-INPV-05 | SQL injection | sqlmap | SqlmapValidator | implemented; unit tests only; caller evidence missing | - | 4 |
| WSTG-INPV-01 | Reflected XSS | browser_xss | BrowserXssValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 3 |
| WSTG-INPV-02 | Stored XSS | stored_xss | StoredXssValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-CLNT-01 | DOM-based XSS | dom_xss | DomXssValidator | implemented; unit tests only; caller evidence missing | - | 1 |
| WSTG-INPV-12 | Command injection | command_injection | CommandInjectionValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-INPV-18 | Server-side template injection | ssti | SstiValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 3 |
| WSTG-INPV-07 | XXE | xxe | XxeValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-INPV-19 | SSRF | ssrf | SsrfValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 3 |
| WSTG-INPV-06 | NoSQL injection | agent | - | no deterministic validator (agent/manual confirmation) | - | 0 |
| WSTG-CRYP-04 | JWT weaknesses | jwt_forge | JwtForgeValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-INPV-11 | Insecure deserialization | deserialization_oob | DeserializationOobValidator | implemented; caller/fixture tests exist; evidence not wired | test_leg_live_verification | 2 |
| WSTG-BUSL-07 | Race conditions | race_condition | RaceConditionValidator | implemented; unit tests only; caller evidence missing | - | 2 |
| WSTG-BUSL-08 | TOCTOU privilege-escalation race | toctou | ToctouValidator | implemented; unit tests only; caller evidence missing | - | 1 |

## Summary

| Classification | Count | Next step |
|---|---|---|
| Implemented; caller/fixture tests exist; evidence not wired | 14 | Convert the existing positive test and its negative control to `@evidence_for` aspects (harness_confirmation + harness_control), as the mass-assignment and open-redirect slices do. |
| Implemented; unit tests only; caller evidence missing | 16 | First add a caller-level fixture test with a negative control, then wire it as evidence. |
| Implemented; no tests found | 2 | WSTG-CRYP-01 and WSTG-CONF-07 (`CryptoValidator`): no tracked test references the class. Add tests before any evidence claim. |
| Manual prerequisite | 3 | WSTG-CONF-09 (host access), WSTG-SESS-05 (CSRF: confirmation only via the default-off LB-5 browser PoC since I04), WSTG-BUSL-09 (file-upload oracle retired). These stay manual gaps. |
| No deterministic validator per catalog | 1 | WSTG-INPV-06 is catalogued as `agent`, but `harness/validators/nosql_validator.py` exists. This is catalog drift; reconcile the `confirmation` field before wiring evidence. |

## Notes

- Requirement status is evidence bookkeeping. An implemented validator does not count as
  covered, and none of this establishes detection efficacy on a real target (I13).
- The 14 "evidence not wired" rows are the cheapest honest wins. Each needs the paired
  positive and negative control, not just the positive.
