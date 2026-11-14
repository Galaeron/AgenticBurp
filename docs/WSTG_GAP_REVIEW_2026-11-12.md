# WSTG gap review: 2026-11-12

Every test in the current OWASP WSTG checklist (`checklists/checklist.json` on the default
branch: 117 tests, INPV renamed INJT, CONF-08/CLNT-08 dropped, WASM-01 added) is compared with
this checkout. The WSTG v4.2 workbook (97 tests) was used to check the catalog's IDs.
Method: a keyword map over non-test `harness/**/*.py`, then reading module docstrings and code at
each candidate site. Keyword hits in agent prompts alone count as **A**, not coverage. The Burp
extension's executors were checked through `harness/execution_planes.py`; only the Java-only
capabilities (logout invalidation, workflow boundary replay, reflected-XSS context) change a tier.
Filed as WG-1..WG-6 in IMPROVEMENT_BACKLOG.md.
Status: VERIFIED against code on this date. Detection quality on live targets stays OWNER/LIVE.

Tiers: **V** = a validator leg confirms it with a deterministic oracle. **D** = deterministic
passive or detect-only check (no exploit proof). **P** = a leg covers one slice only.
**A** = only an agent prompt can raise it; nothing confirms it. **N** = nothing.
**X** = out of reach by design (OSINT, network, host access).

| Tier | Count |
|---|---|
| V | 36 |
| D | 12 |
| P | 20 |
| A | 16 |
| N | 30 |
| X | 3 |

## Per-test coverage

| WSTG | Test | Tier | Covered by / missing |
|---|---|---|---|
| INFO-01 | Search engine recon | X | Needs third-party search; outside scope lock |
| INFO-02 | Fingerprint web server | D | `recon_validator._analyze_header_for_tech` |
| INFO-03 | Webserver metafiles | D | recon probes robots.txt, sitemap.xml; no `.well-known/security.txt` |
| INFO-04 | Attack surface identification | P | In-scope mapping (engagement_builder, api_surface_discovery); no vhost/port enumeration |
| INFO-05 | Page content leakage | P | `confidential_info_detector` (secrets, internal hosts); no HTML-comment or source-map pass |
| INFO-06 | Entry points | D | crawler, api_surface_discovery, OpenAPI ingest |
| INFO-07 | Execution paths | D | crawler, role_crawl, feature_workflow |
| INFO-08 | Framework fingerprint | D | recon header/x-generator analysis |
| INFO-09 | Fingerprint web application | P | recon WordPress path probes only (`recon_validator.py:727`) |
| INFO-10 | Map architecture (WAF/CDN/LB) | A | Agent prompts only |
| CONF-01 | Network infrastructure | X | Port scanning out of scope |
| CONF-02 | Application platform config | P | recon probes `.env`, `.git/HEAD`, build files; verbose_error debug pages |
| CONF-03 | File extension handling | N | — |
| CONF-04 | Old/backup/unreferenced files | P | Fixed list only; no `.bak`/`.old`/`~` variants of discovered paths |
| CONF-05 | Admin interfaces | P | recon probes admin/, manager/, console/, wp-admin/ (detect only) |
| CONF-06 | HTTP methods | V | `verb_tamper_validator` |
| CONF-07 | HSTS | D | `crypto_validator` |
| CONF-09 | File permissions | X | Needs host access (catalog: manual) |
| CONF-10 | Subdomain takeover | V | `subdomain_takeover_validator` (not in catalog) |
| CONF-11 | Cloud storage | P | Unclaimed-bucket fingerprints only; no public list/write ACL check |
| CONF-12 | CSP | D | `csp_validator` |
| CONF-13 | Path confusion | P | Cache-deception suffix leg in `web_cache_poisoning_validator` |
| CONF-14 | Other security headers | A | No validator checks nosniff, Referrer-Policy, Permissions-Policy |
| CONF-15 | Feature flag bypass | N | — |
| IDNT-01 | Role definitions | A | Roles are tester-supplied; no role-matrix derivation |
| IDNT-02 | User registration | P | auth_sequence weak-password-at-registration leg |
| IDNT-03 | Account provisioning | A | — |
| IDNT-04 | Account enumeration | V | auth_sequence `username_enumeration` (not in catalog) |
| IDNT-05 | Username policy | N | — |
| ATHN-01 | Credentials over encrypted channel | A | Crypto agent; no leg (catalog misuses this ID) |
| ATHN-02 | Default credentials | N | Only report text mentions it |
| ATHN-03 | Lockout | V | `rate_limit_validator` |
| ATHN-04 | Bypass authentication | V | `missing_auth_probe`, cross_identity anonymous replay |
| ATHN-05 | Remember password | N | No remember-me/autocomplete logic anywhere |
| ATHN-06 | Browser cache weaknesses | N | No Cache-Control/no-store check on authenticated responses |
| ATHN-07 | Weak authentication methods | V | auth_sequence `weak_password_policy` |
| ATHN-08 | Security questions | N | — |
| ATHN-09 | Password change/reset | P | `reset_token_validator` (predictability only); no reset-flow logic legs |
| ATHN-10 | Alternative channels | N | — |
| ATHN-11 | MFA | V | auth_sequence 2fa_bypass (manifest binds it to ATHN-01) |
| ATHN-12 | SAML | N | — |
| ATHZ-01 | Traversal / file include | V | `path_traversal_validator` |
| ATHZ-02 | Bypass authorization | V | `cross_identity_validator` |
| ATHZ-03 | Privilege escalation | V | sequence self-assignment, toctou, cross_identity |
| ATHZ-04 | IDOR | V | cross_identity, idor_read |
| ATHZ-05 | OAuth | P | `oauth_validator`: passive state/PKCE/token-in-URL + one redirect_uri probe |
| SESS-01 | Session management schema | P | reset_token `analyze_tokens` (catalog routes to auth_sequence) |
| SESS-02 | Cookie attributes | D | `crypto_validator` Secure/HttpOnly/SameSite (not in catalog) |
| SESS-03 | Session fixation | V | auth_sequence |
| SESS-04 | Exposed session variables | A | Tokens in URLs are redacted, never reported |
| SESS-05 | CSRF | V | `csrf_validator` (catalog says manual; docstring says SESS-09) |
| SESS-06 | Logout | P | Java plane only: `SessionLifecycleLogic.java` (`execution_planes.py:219`); no Python leg, so no SafetyGate |
| SESS-07 | Session timeout | A | — |
| SESS-08 | Session puzzling | N | — |
| SESS-09 | Session hijacking | A | Preconditions only (cookie flags, HSTS) |
| SESS-10 | JWT | V | `jwt_forge_validator` (catalog files it as CRYP-04) |
| SESS-11 | Concurrent sessions | N | — |
| INJT-01 | Reflected XSS | V | `browser_xss_validator` |
| INJT-02 | Stored XSS | V | `stored_xss_validator` |
| INJT-03 | HTTP verb tampering | V | `verb_tamper_validator` |
| INJT-04 | HTTP parameter pollution | N | SKL-4 (deprioritized) |
| INJT-05 | SQL injection (incl. NoSQL) | V | sqlmap (Docker), `nosql_validator` |
| INJT-06 | LDAP injection | N | — |
| INJT-07 | XML injection | P | `xxe_validator`; no XML tag/structure injection |
| INJT-08 | SSI injection | N | — |
| INJT-09 | XPath injection | N | — |
| INJT-10 | IMAP/SMTP injection | N | header_injection explicitly excludes mail headers |
| INJT-11 | Code injection | A | Adjacent legs (cmdi, SSTI, deserialization); no eval/RFI leg |
| INJT-12 | Command injection | V | `command_injection_validator` |
| INJT-13 | Format string | N | — |
| INJT-14 | Incubated (second-order) | V | `second_order.py`, stored_xss |
| INJT-15 | HTTP response splitting | V | `header_injection_validator` |
| INJT-16 | HTTP request smuggling | V | `http_request_smuggling_validator` |
| INJT-17 | Host header injection | P | X-Forwarded-Host cache leg only; no Host-based reset poisoning or routing check |
| INJT-18 | SSTI | V | `ssti_validator` |
| INJT-19 | SSRF | V | `ssrf_validator` |
| INJT-20 | Mass assignment | V | api_security, sequence (catalog uses internal AV-MASSASSIGN-01) |
| INJT-21 | CSV injection | N | — |
| INJT-22 | Prototype pollution | N | SKL-3 (deprioritized) |
| INJT-23 | Insecure deserialization | V | deserialization_oob, deserialization |
| ERRH-01 | Improper error handling | D | `verbose_error_validator` (passive) |
| ERRH-02 | Stack traces | D | `verbose_error_validator` (passive) |
| CRYP-01 | Weak TLS | V | `crypto_validator` real handshake |
| CRYP-02 | Padding oracle | N | — |
| CRYP-03 | Sensitive data over unencrypted channel | A | No mixed-content or http:// form-action check |
| CRYP-04 | Weak cryptographic primitives | A | `crypto_agent.py:13` calls it a confirmed gap |
| BUSL-01 | Business data validation | P | Java plane only: `WorkflowReplayLogic.java` numeric boundary differential |
| BUSL-02 | Forge requests | V | `client_trust_validator` |
| BUSL-03 | Integrity checks | A | — |
| BUSL-04 | Process timing | A | — |
| BUSL-05 | Function-use limits | V | `race_condition_validator` (catalog files it as BUSL-07) |
| BUSL-06 | Workflow circumvention | A | No step-skip / out-of-order leg |
| BUSL-07 | Defenses against misuse | V | `rate_limit_validator` |
| BUSL-08 | Unexpected file types | V | `file_upload_validator` benign-extension oracle (docstring says BUSL-09) |
| BUSL-09 | Malicious files | P | Benign-only by design; catalog says manual |
| BUSL-10 | Payment functionality | P | client_trust price tamper, race on single-use values |
| CLNT-01 | DOM XSS | V | `dom_xss_validator` |
| CLNT-02 | JavaScript execution | P | dom_xss `javascript:` sinks |
| CLNT-03 | HTML injection | N | XSS legs require script execution |
| CLNT-04 | Client-side URL redirect | P | `open_redirect_validator` is server-side Location only |
| CLNT-05 | CSS injection | N | — |
| CLNT-06 | Client-side resource manipulation | N | — |
| CLNT-07 | CORS | V | `cors_validator` (catalog files it as CONF-08) |
| CLNT-09 | Clickjacking | D | csp_validator XFO / frame-ancestors (not in catalog) |
| CLNT-10 | WebSockets | V | `websocket_validator` cross-origin handshake (not in catalog) |
| CLNT-11 | Web messaging | N | — |
| CLNT-12 | Browser storage | N | — |
| CLNT-13 | XSSI | N | — |
| CLNT-14 | Reverse tabnabbing | N | — |
| CLNT-15 | Client-side template injection | N | SSTI leg is server-side only |
| CLNT-16 | DOM clobbering | N | — |
| APIT-01 | API reconnaissance | D | api_surface_discovery, OpenAPI ingest |
| APIT-02 | API BOLA | V | cross_identity, idor_read |
| APIT-03 | Excessive data exposure | A | api_security_validator leaves it agent-only by design |
| APIT-04 | API BFLA | V | cross_identity |
| APIT-99 | GraphQL | A | graphql agent; no introspection or batching leg |
| WASM-01 | WebAssembly recon | N | — |

## Catalog ID errors (`harness/coverage_model.py` CHECK_CATALOG, all tagged v4.2)

| Catalog ID | Catalog name | Actual WSTG test at that ID | Correct ID (latest) |
|---|---|---|---|
| CONF-05 | Content Security Policy | Admin interfaces | CONF-12 |
| CONF-08 | CORS policy | RIA cross-domain policy (dropped) | CLNT-07 |
| CONF-02 | Security headers | Application platform config | CONF-14 |
| ATHN-01 | Authentication bypass | Credentials over encrypted channel | ATHN-04 (MFA legs: ATHN-11) |
| BUSV-04 | HTTP request smuggling | No such category | INJT-16 (v4.2 INPV-15) |
| INPV-14 | Header injection / CRLF | Incubated vulnerability | INJT-15 (v4.2 INPV-15) |
| INPV-06 | NoSQL injection | LDAP injection | INJT-05 (sub-test 05.6) |
| INPV-17 | Open redirect | Host header injection | CLNT-04 (closest) |
| CRYP-04 | JWT weaknesses | Weak encryption | SESS-10 |
| INPV-11 | Insecure deserialization | Code injection | INJT-23 |
| BUSL-07 | Race conditions | Defenses against misuse | BUSL-05 |
| BUSL-08 | TOCTOU race | Unexpected file types | BUSL-05 / ATHZ-03 |
| AV-MASSASSIGN-01 | Mass assignment | (internal ID) | INJT-20 |

Related drift: `coverage_manifest.py:174` calls INPV-17 "a genuine WSTG id"; it binds the MFA legs
to ATHN-01 (`:203-206`). `csrf_validator` docstring says SESS-09, `toctou_validator` says BUSL-07,
and `file_upload_validator` says BUSL-09. Catalog confirmation kinds are stale: CSRF and file upload
say `manual` and NoSQL says `agent`, although validators exist for all three. Validators with
no catalog row: SESS-02, CLNT-09, CONF-10, CLNT-10, ATHZ-05, IDNT-04, ATHN-04, ATHN-11, INJT-03,
BUSL-02, INJT-14, INJT-17/CONF-13, ATHZ-03.
