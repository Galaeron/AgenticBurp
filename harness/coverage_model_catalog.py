"""The WSTG / PortSwigger Academy check catalog: CHECK_CATALOG (the code-defined rows), the
caller-independent set that marks rows, and CHECKS_BY_ID.

Part of the ARC-9 split of harness.coverage_model. Import these names from
harness.coverage_model, the facade, not from this module.
"""
from __future__ import annotations

import dataclasses

from harness.coverage_model_cells import Phase
from harness.coverage_model_checks import (
    Check, ExternalRef, _accepts_body, _accepts_create, _accepts_input, _accepts_xml,
    _always_applicable, _flow_shape, _has_auth_endpoint, _has_auth_endpoint_or_lookup,
    _has_client_value_field, _has_denied_role, _has_file_path_segment, _has_oauth_params,
    _has_url_param, _is_authed, _is_authed_get, _is_file_upload_write, _is_get, _is_object_scoped,
    _is_websocket_endpoint, _issues_session_cookie,
)


# ---------------------------------------------------------------------------
# The catalog — the fixed check list (I1)
# ---------------------------------------------------------------------------

CHECK_CATALOG: tuple[Check, ...] = (
    # === DOMAIN phase ===
    Check("WSTG-CRYP-01", "TLS/SSL configuration", Phase.DOMAIN,
          "crypto", _always_applicable, "crypto",
          "Verify TLS versions, cipher suites, certificate validity",
          "Server-side TLS", origin_scoped=True,
          specific_classes=(
              "tls", "ssl", "ssl/tls", "weak tls", "weak_tls", "tls configuration",
              "tls_configuration", "tls misconfiguration", "tls_misconfiguration",
              "weak cipher", "weak_cipher", "weak ciphers", "weak_ciphers",
          )),
    Check("WSTG-CONF-07", "HTTP Strict Transport Security", Phase.DOMAIN,
          "misconfig", _always_applicable, "crypto",
          "Check HSTS header presence and configuration",
          specific_classes=(
              "hsts", "missing hsts", "missing_hsts", "strict transport security",
              "strict-transport-security", "strict_transport_security",
              "http strict transport security", "http_strict_transport_security",
          )),
    # WG-2: CONF-12 is the natural primary row for a bare "csp" finding (it names the
    # policy itself), so "csp" is one of its specific_classes; framing goes to CLNT-09.
    Check("WSTG-CONF-12", "Content Security Policy", Phase.DOMAIN,
          "csp", _always_applicable, "csp",
          "Evaluate CSP header directives",
          "Content security policy",
          specific_classes=(
              "csp", "content security policy", "content_security_policy", "missing csp",
              "missing_csp", "weak csp", "weak_csp", "csp bypass", "csp_bypass",
          )),
    Check("WSTG-CLNT-07", "CORS policy", Phase.DOMAIN,
          "cors", _always_applicable, "cors",
          "Test Cross-Origin Resource Sharing configuration",
          "CORS"),
    Check("WSTG-INFO-02", "Server fingerprinting", Phase.DOMAIN,
          "recon", _always_applicable, "recon",
          "Identify web server software and version",
          specific_classes=(
              "server fingerprinting", "server_fingerprinting", "web server fingerprinting",
              "fingerprinting", "server banner", "server_banner", "banner grabbing",
              "version disclosure", "version_disclosure", "technology fingerprinting",
          )),
    Check("WSTG-INFO-05", "Information in comments/metadata", Phase.DOMAIN,
          "info_disclosure", _always_applicable, "recon",
          "Check for sensitive data in HTML comments, headers, metadata",
          specific_classes=(
              "html comments", "html_comments", "information in comments",
              "information_in_comments", "sensitive comments", "sensitive_comments",
              "source code comments", "source_code_comments", "metadata", "metadata leakage",
              "metadata_leakage",
          )),
    Check("WSTG-CONF-06", "HTTP methods", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Test which HTTP methods are enabled",
          specific_classes=(
              "http methods", "http_methods", "dangerous http methods",
              "dangerous_http_methods", "unsafe http methods", "unsafe_http_methods", "trace",
              "trace method", "trace_method", "http trace", "http_trace", "trace enabled",
              "trace_enabled", "cross-site tracing", "cross_site_tracing", "xst",
          )),
    # The passive security_headers adapter (main, dbb0dab7) judges this row; WG-1
    # moved it from v4.2 CONF-02 to current CONF-14.
    Check("WSTG-CONF-14", "Security headers", Phase.DOMAIN,
          "misconfig", _always_applicable, "security_headers",
          "Check the captured response's X-Content-Type-Options and Referrer-Policy "
          "(CSP: WSTG-CONF-12; framing: WSTG-CLNT-09; HSTS: WSTG-CONF-07)",
          specific_classes=(
              "security headers", "security_headers", "security header", "security_header",
              "missing security headers", "missing_security_headers",
              "missing security header", "missing_security_header", "x-content-type-options",
              "x_content_type_options",
          )),
    # WG-2: the csp validator also audits framing (X-Frame-Options / CSP
    # frame-ancestors); phased and scoped like its CONF-12 sibling.
    Check("WSTG-CLNT-09", "Clickjacking", Phase.DOMAIN,
          "clickjacking", _always_applicable, "csp",
          "Check that responses forbid framing (X-Frame-Options or CSP frame-ancestors)",
          "Clickjacking",
          specific_classes=(
              "clickjacking", "click jacking", "click_jacking", "x-frame-options",
              "x_frame_options", "missing x-frame-options", "missing_x_frame_options",
              "frame-ancestors", "frame_ancestors", "ui redressing", "ui_redressing",
          )),
    # WG-2: host-level like CRYP-01; the subdomain_takeover validator checks dangling
    # DNS / unclaimed-service fingerprints for the engagement's hosts.
    Check("WSTG-CONF-10", "Subdomain takeover", Phase.DOMAIN,
          "subdomain_takeover", _always_applicable, "subdomain_takeover",
          "Check in-scope hosts for dangling DNS records pointing at unclaimed services"),
    # The genuine WSTG-CONF-09. It is a host/deployment file-permission review, not
    # something a black-box HTTP client can confirm -- so it is a MANUAL check.
    Check("WSTG-CONF-09", "Test File Permission", Phase.DOMAIN,
          "misconfig", _always_applicable, "manual",
          "Verify server files/directories use least privilege (config, key material, "
          "backups, source not world-readable/writable). Requires host access.",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-09",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission",
                          "Test File Permission", version="4.2"),
          ), origin_scoped=True,
          specific_classes=(
              "file permission", "file_permission", "file permissions", "file_permissions",
              "insecure file permissions", "insecure_file_permissions",
          )),

    # === ENDPOINT phase ===
    # WG-2: ATHZ-04 is the natural primary row for a bare "idor" finding; BFLA and
    # function-level wording names ATHZ-02. The tokens include coverage_tracker's
    # access-control free-text words, which resolve through specific_classes too.
    Check("WSTG-ATHZ-04", "IDOR / Broken Object-Level Authorization", Phase.ENDPOINT,
          "idor", _is_object_scoped, "cross_identity",
          "Test access to other users' objects by varying identifiers",
          "Insecure direct object references (IDOR)",
          specific_classes=(
              "idor", "bola", "broken object level authorization",
              "broken_object_level_authorization", "insecure direct object reference",
              "insecure_direct_object_reference", "insecure direct object references",
              "insecure_direct_object_references", "object level authorization",
              "object_level_authorization", "object-level", "object level",
              "insecure direct object",
          )),
    Check("WSTG-ATHZ-02", "Broken Function-Level Authorization", Phase.ENDPOINT,
          "idor", _is_authed, "cross_identity",
          "Access admin/privileged functions as a lower-privilege user",
          "Access control vulnerabilities",
          specific_classes=(
              "bfla", "broken function level authorization",
              "broken_function_level_authorization", "function level authorization",
              "function_level_authorization", "function-level", "function level",
              "broken function", "broken_function",
          )),
    # WG-2: the five rows of class "auth" have no primary row: a bare "auth" finding
    # is attributed to none of them as CONFIRMED. Tokens come from auth_sequence's
    # finding_classes; leg_class routes the driver to the matching sub-check.
    Check("WSTG-ATHN-04", "Authentication bypass", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test for authentication bypass techniques",
          "Authentication vulnerabilities",
          specific_classes=(
              "authentication bypass", "authentication_bypass", "auth bypass", "auth_bypass",
              "login bypass", "login_bypass", "bypass authentication",
              "bypass_authentication",
          )),
    Check("WSTG-ATHN-07", "Weak password policy", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test password complexity requirements",
          "Authentication vulnerabilities",
          specific_classes=(
              "weak_password", "weak password", "weak passwords", "weak_passwords",
              "weak password policy", "weak_password_policy", "password policy",
              "password_policy",
          ),
          leg_class="weak_password"),
    # WG-2: auth_sequence's username-enumeration and second-factor legs. Every row
    # class must canonicalize, and no canonical class or synonym names enumeration
    # or MFA, so both carry "auth" like ATHN-04/07. The coverage driver passes that
    # class to the leg, which routes bare "auth" to no check; a narrower synonym in
    # categories.py is the follow-up that lets the driver fire these legs.
    Check("WSTG-IDNT-04", "Account enumeration", Phase.ENDPOINT,
          "auth", _has_auth_endpoint_or_lookup, "auth_sequence",
          "Test whether login/registration/reset responses distinguish existing from "
          "unknown usernames",
          "Authentication vulnerabilities",
          specific_classes=(
              "username_enumeration", "username enumeration", "user enumeration",
              "user_enumeration", "account enumeration", "account_enumeration",
              "email enumeration", "email_enumeration",
          ),
          leg_class="username_enumeration"),
    Check("WSTG-ATHN-11", "Multi-factor authentication", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test whether a session that passed only the first factor reaches pages the "
          "second factor gates",
          "Authentication vulnerabilities",
          specific_classes=(
              "2fa_bypass", "2fa bypass", "mfa_bypass", "mfa bypass", "two_factor_bypass",
              "two-factor bypass", "two factor bypass", "multi_factor_bypass",
              "multi-factor bypass", "multi factor bypass", "second factor bypass",
              "second_factor_bypass", "mfa", "2fa", "multi-factor authentication",
              "multi_factor_authentication", "two-factor authentication",
              "two_factor_authentication",
          ),
          leg_class="2fa_bypass"),
    Check("WSTG-ATHN-03", "Weak lockout mechanism", Phase.ENDPOINT,
          "rate_limit", _has_auth_endpoint, "rate_limit",
          "Test account lockout / rate limiting after repeated attempts",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-09", "Weak password-reset token", Phase.ENDPOINT,
          "reset_token", _has_auth_endpoint, "reset_token",
          "Test password-reset tokens for predictability (sequential, timestamp, "
          "below-entropy-floor, or derived from a known value)",
          "Authentication vulnerabilities"),
    # WG-2: SESS-01's deterministic check is token predictability
    # (reset_token_validator.analyze_tokens), so it confirms via reset_token, not
    # auth_sequence. That leg replays a token-issuing POST to sample tokens, so the
    # row is scoped to auth endpoints like ATHN-09, not every session-bearing one.
    Check("WSTG-SESS-01", "Session management", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "reset_token",
          "Test issued tokens for predictability (sequential, timestamp-derived, "
          "below the entropy floor, or derived from a known value)",
          "Authentication vulnerabilities",
          specific_classes=(
              "session management", "session_management", "broken session management",
              "broken_session_management", "session management schema",
              "session token predictability", "session_token_predictability",
              "predictable session token", "predictable_session_token",
              "predictable session id", "predictable_session_id", "weak session token",
              "weak_session_token",
          ),
          leg_class="token entropy"),
    Check("WSTG-SESS-02", "Cookie attributes", Phase.ENDPOINT,
          "crypto", _issues_session_cookie, "crypto",
          "Audit Set-Cookie for the Secure, HttpOnly and SameSite attributes",
          specific_classes=(
              "cookie attributes", "cookie_attributes", "insecure cookie", "insecure_cookie",
              "insecure cookie attributes", "insecure_cookie_attributes", "cookie flags",
              "cookie_flags", "cookie security", "cookie_security", "secure flag",
              "secure_flag", "missing secure flag", "missing_secure_flag", "httponly",
              "httponly flag", "httponly_flag", "missing httponly", "missing_httponly",
              "samesite", "samesite flag", "samesite_flag", "missing samesite",
              "missing_samesite",
          )),
    Check("WSTG-SESS-03", "Session fixation", Phase.ENDPOINT,
          "session_fixation", _has_auth_endpoint, "auth_sequence",
          "Test if session tokens are regenerated after login"),
    # WG-3: auth_sequence's logout leg (session_timeout class) mints a fresh throwaway
    # login from a captured login and never logs the operator out, so the row is
    # scoped to auth endpoints like SESS-03. Idle/absolute timeout waits have no leg; SESS-07
    # below checks only that the session token expires at all.
    Check("WSTG-SESS-06", "Logout functionality", Phase.ENDPOINT,
          "session_timeout", _has_auth_endpoint, "auth_sequence",
          "Test whether logout invalidates the session server-side (the pre-logout "
          "cookie must stop reaching authenticated pages)"),
    # R11-8 (b): a session JWT with no exp claim never expires. auth_sequence's expiry
    # check decodes the tokens the run holds (the login's token, the identities'
    # credentials) and sends nothing. Its own class, so the logout row is not proved by it.
    Check("WSTG-SESS-07", "Session timeout (token expiry)", Phase.ENDPOINT,
          "session_expiry", _has_auth_endpoint, "auth_sequence",
          "Decode the session bearer JWT (the login's token, the run identities' "
          "credentials) and check that it carries an exp claim; nothing is sent"),
    # R11-8 (b): a run-owned identity's token kept across its own password change
    # (and restored). A write: needs the mutating ceiling for this check >= 2.
    Check("AV-PWCHANGE-01", "Session token survives a password change", Phase.ENDPOINT,
          "session_after_password_change", _has_auth_endpoint, "password_change_session",
          "For a run-owned identity: log in (token T1), change its password through the "
          "captured change-password flow, read its account with T1, then change the "
          "password back and verify the original logs in. T1 still accepted confirms",
          external_refs=(
              ExternalRef("WSTG", "WSTG-ATHN-09",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/04-Authentication_Testing/"
                          "09-Testing_for_Weak_Password_Change_or_Reset_Functionalities",
                          "Testing for Weak Password Change or Reset Functionalities",
                          version="4.2"),
              ExternalRef("CWE", "CWE-613", "https://cwe.mitre.org/data/definitions/613.html",
                          "Insufficient Session Expiration"),
          )),
    # The file_upload leg uploads only a BENIGN disallowed-extension (.html) file and
    # checks it is stored and served back: BUSL-08 (unexpected file types). In
    # scheme-1 data (pre-WG-1, unmarked) "WSTG-BUSL-08" meant the TOCTOU row and still
    # resolves to ATHZ-03; see CHECK_ID_SCHEME and REUSED_LEGACY_IDS.
    Check("WSTG-BUSL-08", "Upload of unexpected file types", Phase.ENDPOINT,
          "file_upload", _is_file_upload_write, "file_upload",
          "Upload a benign file of a disallowed type (.html) and check whether the "
          "server stores it and serves it back as an active context",
          "File upload vulnerabilities",
          specific_classes=(
              "unrestricted file upload", "unrestricted_file_upload",
              "upload of unexpected file types", "upload_of_unexpected_file_types",
              "unexpected file type", "unexpected_file_type", "unexpected file types",
              "unexpected_file_types", "disallowed file type", "disallowed_file_type",
              "file type bypass", "file_type_bypass", "file extension bypass",
              "file_extension_bypass", "upload filter bypass", "upload_filter_bypass",
          )),
    # BUSL-09 is malicious-file upload and stays manual; the benign leg is BUSL-08.
    Check("WSTG-BUSL-09", "File upload", Phase.ENDPOINT,
          "file_upload", _has_file_path_segment, "manual",
          "Test upload endpoints against malicious files (manual). The benign "
          "disallowed-extension leg (file_upload) belongs to WSTG-BUSL-08.",
          "File upload vulnerabilities",
          specific_classes=(
              "malicious file upload", "malicious_file_upload", "upload of malicious files",
              "upload_of_malicious_files", "malicious file", "malicious_file",
              "webshell upload", "webshell_upload", "web shell upload", "web_shell_upload",
              "malware upload", "malware_upload", "eicar",
          )),
    Check("WSTG-ATHZ-01", "Path traversal", Phase.ENDPOINT,
          "path_traversal", _has_file_path_segment, "path_traversal",
          "Test for directory traversal in file-serving endpoints",
          "Path traversal",
          specific_classes=(
              "path traversal", "path_traversal", "directory traversal",
              "directory_traversal", "file path traversal", "dot dot slash", "lfi",
              "local file inclusion", "arbitrary file read",
          )),
    Check("WSTG-ERRH-01", "Error handling / stack traces", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "error_handling",
          "Check captured error responses for stack traces and framework error pages "
          "(passive: errors are not provoked)",
          specific_classes=(
              "verbose_error", "verbose error", "verbose errors", "verbose_errors",
              "verbose_error_disclosure", "verbose error disclosure", "stack_trace",
              "stack trace", "stack trace disclosure", "stack_trace_disclosure", "debug_info",
              "debug info", "debug_mode", "debug mode", "error_disclosure",
              "error disclosure", "error handling", "error_handling",
              "improper error handling", "improper_error_handling",
          )),
    # r5: /ftp, /metrics and whoami?callback= only met recon (WSTG-INFO-05), which is
    # not a verdict. No single WSTG v4.2 test owns these, so the id is internal.
    Check("AV-EXPOSURE-01", "Directory index, metrics or JSONP exposure", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "content_exposure",
          "Check captured 2xx responses for a directory index, a Prometheus metrics "
          "exposition or a JSONP callback wrapper (passive: nothing is sent)",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-04",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/"
                          "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                          "Review Old Backup and Unreferenced Files for Sensitive Information",
                          version="4.2"),
              ExternalRef("CWE", "CWE-548", "https://cwe.mitre.org/data/definitions/548.html",
                          "Exposure of Information Through Directory Listing"),
          ),
          specific_classes=(
              "content_exposure", "content exposure", "jsonp", "jsonp exposure",
              "jsonp_exposure", "jsonp callback", "jsonp_callback",
          )),
    # r9: the model raised listing, backup and metrics leads that no leg decided, and
    # AV-EXPOSURE-01 judged the same captures with no exchange behind its verdict.
    # These legs send GETs (validators.active_enabled) and keep the exchanges as proof.
    # Their shape gate (a listing / an exposition) is in capability_for_check.
    Check("AV-EXPOSURE-02", "Sensitive files served from a directory listing", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "listing_exposure",
          "When a captured 2xx response is a directory listing (HTML index or JSON file "
          "list), GET each listed file and classify its content: backups, configuration, "
          "keys and keystores, credentials, documents marked confidential, data dumps, "
          "package manifests",
          external_refs=(
              ExternalRef("WSTG", "WSTG-CONF-04",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/"
                          "4-Web_Application_Security_Testing/"
                          "02-Configuration_and_Deployment_Management_Testing/"
                          "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                          "Review Old Backup and Unreferenced Files for Sensitive Information",
                          version="4.2"),
              ExternalRef("CWE", "CWE-530", "https://cwe.mitre.org/data/definitions/530.html",
                          "Exposure of Backup File to an Unauthorized Control Sphere"),
              ExternalRef("CWE", "CWE-538", "https://cwe.mitre.org/data/definitions/538.html",
                          "Insertion of Sensitive Information into Externally-Accessible File or Directory"),
          ),
          specific_classes=(
              "listing_exposure", "directory listing", "directory_listing",
              "directory indexing", "directory_indexing", "exposed_directory_listing",
              "directory index",
          )),
    Check("AV-FILTER-01", "File-extension filter bypass (NUL encoding)", Phase.ENDPOINT,
          "path_filter_bypass", _always_applicable, "filter_bypass",
          "When a directory listing names a file the server refuses while it serves a "
          "sibling, GET the refused name with a NUL encoding before an allowed extension "
          "(name%2500.ext, name%00.ext). Positive control: the same encoding on a served "
          "listed file returns its exact bytes. Negative control: on a nonexistent name it "
          "returns no file",
          external_refs=(
              ExternalRef("CWE", "CWE-158", "https://cwe.mitre.org/data/definitions/158.html",
                          "Improper Neutralization of Null Byte or NUL Character"),
              ExternalRef("CWE", "CWE-20", "https://cwe.mitre.org/data/definitions/20.html",
                          "Improper Input Validation"),
          ),
          specific_classes=(
              "path_filter_bypass", "filter_bypass", "extension_filter_bypass",
              "null_byte_injection", "poison_null_byte", "null byte",
          )),
    Check("AV-EXPOSURE-03", "Metrics endpoint exposed without authentication", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "metrics_exposure",
          "When a captured 2xx response is a metrics exposition, GET it without "
          "credentials (must still be an exposition) and GET a nonexistent sibling (must "
          "not be one); record the families, label keys and versions it reveals",
          external_refs=(
              ExternalRef("CWE", "CWE-200", "https://cwe.mitre.org/data/definitions/200.html",
                          "Exposure of Sensitive Information to an Unauthorized Actor"),
              ExternalRef("CWE", "CWE-306", "https://cwe.mitre.org/data/definitions/306.html",
                          "Missing Authentication for Critical Function"),
          ),
          specific_classes=(
              "metrics_exposure", "metrics exposure", "exposed_metrics_endpoint",
              "public_metrics_endpoint", "unauthenticated_metrics",
          )),
    Check("AV-EXPOSURE-04", "Sensitive file served without authentication", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "sensitive_file",
          "When a captured 2xx GET is a single file whose name and content classify as "
          "sensitive (backup, key, credentials, dump, confidential document, manifest), GET "
          "it without credentials (must still classify) and GET a nonexistent sibling with "
          "the same extension (must not serve it); file values are never recorded",
          external_refs=(
              ExternalRef("CWE", "CWE-538", "https://cwe.mitre.org/data/definitions/538.html",
                          "Insertion of Sensitive Information into Externally-Accessible File or Directory"),
              ExternalRef("CWE", "CWE-530", "https://cwe.mitre.org/data/definitions/530.html",
                          "Exposure of Backup File to an Unauthorized Control Sphere"),
          ),
          specific_classes=(
              "sensitive_file", "exposed_backup_file", "config_file_exposure",
              "exposed_configuration", "credential_exposure",
              "confidential_document_exposure", "exposed_file",
          )),
    Check("AV-WELLKNOWN-01", "security.txt and CSAF provider metadata", Phase.DOMAIN,
          "recon", _always_applicable, "well_known",
          "Once per origin, GET /.well-known/security.txt (RFC 9116) and "
          "/.well-known/csaf/provider-metadata.json; what is published is an observation, "
          "not a vulnerability",
          external_refs=(
              ExternalRef("RFC", "RFC 9116", "https://www.rfc-editor.org/rfc/rfc9116",
                          "A File Format to Aid in Security Vulnerability Disclosure"),
              ExternalRef("OASIS", "CSAF 2.0",
                          "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
                          "Common Security Advisory Framework Version 2.0"),
          ), origin_scoped=True,
          specific_classes=(
              "well_known", "well known", "security.txt", "security_txt", "csaf",
              "csaf_provider_metadata",
          )),
    # Mass assignment had NO WSTG v4.2 test, so it carried the internal id
    # AV-MASSASSIGN-01 (still an alias); current WSTG adds it as INJT-20. The
    # API-layer sources stay in external_refs. See coverage_manifest.
    Check("WSTG-INJT-20", "Mass assignment (server-controlled field protection)", Phase.ENDPOINT,
          "api_security", _accepts_body, "sequence",
          "An ordinary update must not let a client set server-controlled fields "
          "(role, is_admin, balance); send those fields and verify they do not persist.",
          academy_ref="Mass assignment",
          external_refs=(
              ExternalRef("PortSwigger Academy", "",
                          "https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerabilities",
                          "Exploiting mass assignment vulnerabilities"),
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization (subsumes mass assignment)"),
              ExternalRef("OWASP API Security Top 10 2019", "API6:2019",
                          "https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/",
                          "Mass Assignment"),
          ),
          specific_classes=(
              "mass assignment", "mass_assignment", "mass assignment update",
              "mass_assignment_update",
          )),
    Check("WSTG-INJT-16", "HTTP request smuggling", Phase.ENDPOINT,
          "http_request_smuggling", _accepts_body, "http_request_smuggling",
          "Test CL/TE and TE/CL desync",
          "HTTP request smuggling"),
    Check("WSTG-INJT-15", "HTTP header injection / CRLF", Phase.ENDPOINT,
          "header_injection", _accepts_input, "header_injection",
          "Inject CRLF sequences in header-reflected parameters"),
    # WSTG-SESS-05 is the current WSTG id for CSRF (was mislabelled SESS-09 --
    # weakness #7). WG-2: the row names the registered csrf leg, which runs the
    # token-strip/SameSite property check. Its verdict is still retired to an
    # observation (ORACLE_RETIREMENTS.md), so a CONFIRMED CSRF needs a browser PoC;
    # the manifest keeps the manual aspect for that.
    Check("WSTG-SESS-05", "CSRF", Phase.ENDPOINT,
          "csrf", _accepts_body, "csrf",
          "Test state-changing requests for anti-CSRF protections",
          "Cross-site request forgery (CSRF)"),
    # WG-2 rows for registered validators that had none.
    Check("WSTG-ATHZ-05", "OAuth weaknesses", Phase.ENDPOINT,
          "oauth", _has_oauth_params, "oauth",
          "Test OAuth flows for redirect_uri validation, state/PKCE and token leakage",
          "OAuth authentication"),
    Check("WSTG-CLNT-10", "WebSockets", Phase.ENDPOINT,
          "websocket", _is_websocket_endpoint, "websocket",
          "Test whether the WebSocket handshake accepts a cross-origin Origin "
          "(cross-site WebSocket hijacking)",
          "WebSockets"),
    # WG-2: "http method" (singular) is a verb_tamper_validator finding class, so it
    # names this row; the plural "http methods" / TRACE wording names CONF-06.
    Check("WSTG-INJT-03", "HTTP verb tampering", Phase.ENDPOINT,
          "misconfig", _has_denied_role, "verb_tamper",
          "Replay a denied request with read-only method alternates and override headers",
          specific_classes=(
              "verb tamper", "verb_tamper", "verb tampering", "verb_tampering",
              "http verb tampering", "http_verb_tampering", "method tampering",
              "method_tampering", "http method", "http_method", "method override",
              "method_override",
          )),
    Check("WSTG-BUSL-02", "Ability to forge requests", Phase.ENDPOINT,
          "business_logic", _has_client_value_field, "client_trust",
          "Tamper a server-owned value field (price/amount/total) and check whether an "
          "independent read reflects it",
          "Business logic vulnerabilities",
          specific_classes=(
              "client_trust", "client trust", "client-side controls", "client_side_controls",
              "price manipulation", "price_manipulation", "excessive trust",
          )),
    # The web_cache_poisoning validator has two legs: an unkeyed X-Forwarded-Host
    # reflection (host header injection) and a static-suffix cache-deception probe
    # (path confusion).
    Check("WSTG-INJT-17", "Host header injection", Phase.ENDPOINT,
          "web_cache_poisoning", _is_get, "web_cache_poisoning",
          "Test whether X-Forwarded-Host / Host values are reflected into cacheable responses",
          "Web cache poisoning",
          specific_classes=(
              "host header injection", "host_header_injection", "host header poisoning",
              "host_header_poisoning", "x-forwarded-host", "x_forwarded_host",
              "unkeyed header", "unkeyed_header",
          )),
    Check("WSTG-CONF-13", "Path confusion", Phase.ENDPOINT,
          "web_cache_poisoning", _is_authed_get, "web_cache_poisoning",
          "Test whether a static-looking path suffix makes authenticated content cacheable "
          "(web cache deception)",
          "Web cache deception",
          specific_classes=(
              "cache deception", "cache_deception", "web cache deception",
              "web_cache_deception", "path confusion", "path_confusion",
          )),

    # === PARAMETER phase ===
    Check("WSTG-INJT-05", "SQL injection", Phase.PARAMETER,
          "sqli", _accepts_input, "sqlmap",
          "Test all input parameters for SQL injection",
          "SQL injection"),
    Check("WSTG-INJT-01", "Reflected XSS", Phase.PARAMETER,
          "xss", _accepts_input, "browser_xss",
          "Test input reflection in HTML responses for script injection",
          "Cross-site scripting (XSS)",
          specific_classes=(
              "reflected xss", "reflected_xss", "reflected cross-site scripting",
              "reflected_cross_site_scripting", "non-persistent xss",
          )),
    Check("WSTG-INJT-02", "Stored XSS", Phase.PARAMETER,
          "xss", _accepts_body, "stored_xss",
          "Test stored input rendered in HTML context",
          "Stored cross-site scripting",
          specific_classes=(
              "stored xss", "stored_xss", "persistent xss", "persistent_xss",
              "second order xss", "second_order_xss", "stored cross-site scripting",
              "stored_cross_site_scripting",
          )),
    Check("WSTG-CLNT-01", "DOM-based XSS", Phase.PARAMETER,
          "dom_xss", _accepts_input, "dom_xss",
          "Test client-side sources (location.hash/.search) flowing to a DOM sink",
          "DOM-based cross-site scripting"),
    Check("WSTG-INJT-12", "Command injection", Phase.PARAMETER,
          "command_injection", _accepts_input, "command_injection",
          "Test for OS command injection in parameters",
          "OS command injection"),
    Check("WSTG-INJT-18", "Server-side template injection", Phase.PARAMETER,
          "ssti", _accepts_input, "ssti",
          "Test for template expression evaluation",
          "Server-side template injection (SSTI)"),
    Check("WSTG-INJT-07", "XXE", Phase.PARAMETER,
          "xxe", _accepts_xml, "xxe",
          "Test XML-accepting endpoints for external entity processing",
          "XML external entity (XXE) injection"),
    Check("WSTG-INJT-19", "SSRF", Phase.PARAMETER,
          "ssrf", _has_url_param, "ssrf",
          "Test URL parameters for server-side request forgery",
          "Server-side request forgery (SSRF)"),
    # WSTG has no server-side open-redirect test; CLNT-04 (Client-side URL Redirect)
    # is the closest. NoSQL is the INJT-05 sub-test 05.6, so it cannot collide with
    # the SQL-injection row.
    Check("WSTG-CLNT-04", "Open redirect", Phase.PARAMETER,
          "open_redirect", _has_url_param, "open_redirect",
          "Test redirect parameters for off-site redirection",
          "Open redirection"),
    Check("WSTG-INJT-05.6", "NoSQL injection", Phase.PARAMETER,
          "nosql", _accepts_input, "nosql",
          "Test for NoSQL query manipulation",
          "NoSQL injection"),
    Check("WSTG-SESS-10", "JWT weaknesses", Phase.PARAMETER,
          "jwt", _is_authed, "jwt_forge",
          "Test JWT algorithm confusion, key disclosure, claim tampering",
          "JWT attacks"),
    Check("WSTG-INJT-23", "Insecure deserialization", Phase.PARAMETER,
          "deserialization", _accepts_body, "deserialization_oob",
          "Test for unsafe deserialization of user-supplied data",
          "Insecure deserialization"),
    Check("WSTG-BUSL-05", "Race conditions", Phase.PARAMETER,
          "race_condition", _accepts_body, "race_condition",
          "Test for TOCTOU and concurrent-request bugs",
          "Race conditions"),
    # The TOCTOU row confirms a privilege field flipped, so it is ATHZ-03 (Privilege
    # Escalation); BUSL-05 is already the generic race row above.
    Check("WSTG-ATHZ-03", "TOCTOU privilege-escalation race", Phase.ENDPOINT,
          "toctou", _accepts_body, "toctou",
          "Concurrent copies of an authority-changing write race a check-then-write "
          "window; confirm a privilege field flipped under concurrency via re-read",
          "Race conditions"),
    # Write-path checks (write_integrity): each create is answered by a plain-create
    # control, read back by every registered identity, and DELETEd again before the
    # verdict; a path with no restore route is skipped, never written.
    Check("AV-WRITE-XID-01", "Cross-identity write (another principal's object referenced)",
          Phase.ENDPOINT, "cross_identity_write", _accepts_body, "write_integrity",
          "A write must not attach to, or create under, an object another principal owns; "
          "swap the owner reference for the second identity's id and read the result back.",
          "Access control vulnerabilities",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API1:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                          "Broken Object Level Authorization"),
          ),
          specific_classes=(
              "cross_identity_write", "cross_identity_create", "cross_user_write",
              "bola_write", "idor_write", "foreign_reference_write",
          )),
    Check("AV-WRITE-AUTHOR-01", "Forged authorship (author/owner field set by the client)",
          Phase.ENDPOINT, "forged_authorship", _accepts_body, "write_integrity",
          "The server must derive an author or owner field from the session; send another "
          "identity's value and verify the stored object keeps the caller's own.",
          "Access control vulnerabilities",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization"),
          ),
          specific_classes=(
              "forged_authorship", "authorship_forgery", "author_spoofing", "forged_owner",
              "owner_spoofing", "impersonated_write",
          )),
    Check("AV-WRITE-BIZ-01", "Business-rule tampering (quantity, rating or amount bounds)",
          Phase.ENDPOINT, "business_rule_tamper", _accepts_body, "write_integrity",
          "A write must reject a negative or out-of-range quantity, rating or amount; send the "
          "in-range control and the tampered value, read both back, and restore the original.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-01",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                          "Test Business Logic Data Validation", version="4.2"),
          ),
          specific_classes=(
              "business_rule_tamper", "business_rule_bypass", "numeric_tamper",
              "negative_quantity", "quantity_tampering", "rating_tampering",
              "out_of_bounds_value", "negative_total",
          )),
    Check("AV-MASSASSIGN-02", "Mass assignment at create (privileged field on a new object)",
          Phase.ENDPOINT, "mass_assignment_create", _accepts_create, "write_integrity",
          "A create must not let a client set server-controlled fields; create once plainly and "
          "once with role/admin fields, read both back, and delete both.",
          "Mass assignment",
          external_refs=(
              ExternalRef("OWASP API Security Top 10 2023", "API3:2023",
                          "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                          "Broken Object Property Level Authorization (subsumes mass assignment)"),
          ),
          specific_classes=(
              "mass_assignment_create", "mass assignment create",
              "mass_assignment_at_create", "registration_mass_assignment",
          )),
    Check("AV-WRITE-VALID-01", "Weak create validation (empty required fields, duplicates)",
          Phase.ENDPOINT, "create_validation", _accepts_create, "write_integrity",
          "A create must reject empty required fields and a duplicate of a unique field; "
          "send each, read the stored objects back, and delete them.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-01",
                          "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                          "Test Business Logic Data Validation", version="4.2"),
          ),
          specific_classes=(
              "create_validation", "weak_create_validation", "duplicate_registration",
              "empty_required_fields", "missing_required_field_validation",
          )),
    # R11-7 business flows (business_flow_validator): replay the run's own captured
    # flow on a run-owned identity, read the resulting state back, restore what can be.
    Check("WSTG-BUSL-10", "Payment functionality (settlement tamper, payment skip)",
          Phase.ENDPOINT, "payment_tamper", _flow_shape("payment_tamper"), "business_flow",
          "Replay the captured cart steps and settlement untampered, then with a client-chosen "
          "amount, quantity or delivery value (or the payment dropped); confirm only when the "
          "read-back order total or balance shows less was charged than the control.",
          "Business logic vulnerabilities",
          specific_classes=(
              "payment_tamper", "payment tamper", "payment_tampering", "payment tampering",
              "checkout_tamper", "checkout tampering", "settlement_tamper", "payment_bypass",
              "payment bypass", "payment_skip", "order_total_tamper", "wallet_payment_skip",
          )),
    Check("AV-BUSL-COUPON-01", "Coupon or voucher misuse (forged, expired, another user's code)",
          Phase.ENDPOINT, "coupon_misuse", _flow_shape("coupon_misuse"), "business_flow",
          "Apply a forged code, an expired code and another run identity's code to the captured "
          "coupon write; confirm when the basket or order read-back shows the discount, then "
          "clear the code again.",
          "Business logic vulnerabilities",
          external_refs=(
              ExternalRef("WSTG", "WSTG-BUSL-10",
                          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality",
                          "Test Payment Functionality"),
          ),
          specific_classes=(
              "coupon_misuse", "coupon misuse", "coupon_forgery", "coupon forgery",
              "coupon_reuse", "expired_coupon", "voucher_misuse", "promo_code_abuse",
              "discount_code_abuse", "cross_user_coupon",
          )),
    Check("WSTG-BUSL-06", "Circumvention of work flows (2FA disable without step-up)",
          Phase.ENDPOINT, "mfa_disable_stepup", _flow_shape("mfa_disable_stepup"), "business_flow",
          "Replay the captured 2FA-disable request with its password or TOTP field dropped or "
          "wrong; confirm when the status read-back shows 2FA off, then re-enable it from the "
          "run's captured enable request or name it as left disabled.",
          "Authentication vulnerabilities",
          specific_classes=(
              "mfa_disable_stepup", "mfa disable stepup", "2fa_disable", "2fa disable",
              "mfa_disable", "two_factor_disable", "mfa_step_up_bypass",
              "2fa_disable_without_password",
          )),
)

# R11-10: rows whose verdict does not depend on the caller (Check.caller_independent).
# Every row NOT named here is identity-bound. Kept out on purpose, though the
# leg may look caller-blind:
# - every WSTG-ATHZ / ATHN / SESS row, AV-EXPOSURE-* and AV-WRITE-XID / AUTHOR
#   (owner's list: the verdict is about who may do it);
# - WSTG-INJT-20 and AV-MASSASSIGN-02: whether a privileged field may be set
#   depends on the caller's privilege (an admin may set it);
# - WSTG-INJT-03 (verb tampering): tests an access-control bypass;
# - WSTG-CLNT-10 (WebSockets): cross-site hijacking rides the caller's session;
# - WSTG-BUSL-05, BUSL-06, BUSL-10, AV-BUSL-COUPON-01: limits, step-up and
#   payment rules are often per account;
# - manual rows (WSTG-CONF-09, WSTG-BUSL-09): no leg runs them.
_CALLER_INDEPENDENT_CHECKS = frozenset({
    # Transport, policy headers and server configuration.
    "WSTG-CRYP-01", "WSTG-CONF-07", "WSTG-CONF-12", "WSTG-CLNT-07", "WSTG-INFO-02",
    "WSTG-INFO-05", "WSTG-CONF-06", "WSTG-CONF-14", "WSTG-CLNT-09", "WSTG-CONF-10",
    "AV-WELLKNOWN-01", "WSTG-ERRH-01", "AV-FILTER-01",
    # Injection and request handling.
    "WSTG-INJT-16", "WSTG-INJT-15", "WSTG-INJT-17", "WSTG-CONF-13", "WSTG-INJT-05",
    "WSTG-INJT-01", "WSTG-INJT-02", "WSTG-CLNT-01", "WSTG-INJT-12", "WSTG-INJT-18",
    "WSTG-INJT-07", "WSTG-INJT-19", "WSTG-CLNT-04", "WSTG-INJT-05.6", "WSTG-INJT-23",
    # Input handling that is the same for any caller.
    "WSTG-IDNT-04", "WSTG-BUSL-08", "WSTG-BUSL-02", "AV-WRITE-BIZ-01",
    "AV-WRITE-VALID-01",
})
CHECK_CATALOG = tuple(
    dataclasses.replace(c, caller_independent=True) if c.id in _CALLER_INDEPENDENT_CHECKS else c
    for c in CHECK_CATALOG)

CHECKS_BY_ID: dict[str, Check] = {c.id: c for c in CHECK_CATALOG}
