"""WG-1: a vendored copy of the current OWASP WSTG test IDs.

The coverage catalog (`harness/coverage_model.py` CHECK_CATALOG) cites WSTG
test IDs. This module pins the list it is checked against, so tests can prove
every catalog ID names a real, current WSTG test WITHOUT a network fetch.

Source (fetched once by hand, not at runtime or test time):
  repository  https://github.com/OWASP/wstg
  commit      4d58b98e50bb8462491d7fd226864352d489c979 (master, 2026-11-11,
              "Publish Latest checklists 2026-11-10 (#1659)")
  tests       checklists/checklist.json -- every category's `tests[].id`/`name`
  sub-tests   document/4-Web_Application_Security_Testing/**/NN.M-*.md files

The upstream checklist carries no release number: the newest numbered release
is still v4.2 (2020-12-03), and the IDs below are the "latest" (master) set
that re-numbered v4.2's INPV-* family as INJT-* and added CONF-12..15,
SESS-10/11, INJT-20..23, CLNT-14..16, APIT-* and WASM-*. Refresh this file by
re-reading those two upstream sources at a newer commit; never edit an entry
by hand.
"""
from __future__ import annotations

WSTG_SOURCE_REPO = "https://github.com/OWASP/wstg"
WSTG_SOURCE_COMMIT = "4d58b98e50bb8462491d7fd226864352d489c979"
WSTG_SOURCE_DATE = "2026-11-11"
WSTG_RELEASE_LABEL = "latest"

# id -> upstream test name, in checklist order (117 tests).
WSTG_LATEST_TESTS: dict[str, str] = {
    "WSTG-INFO-01": "Conduct Search Engine Reconnaissance for Information Leakage",
    "WSTG-INFO-02": "Fingerprint Web Server",
    "WSTG-INFO-03": "Review Webserver Metafiles for Information Leakage",
    "WSTG-INFO-04": "Attack Surface Identification",
    "WSTG-INFO-05": "Review Web Page Content for Information Leakage",
    "WSTG-INFO-06": "Identify Application Entry Points",
    "WSTG-INFO-07": "Map Execution Paths Through Application",
    "WSTG-INFO-08": "Fingerprint Web Application Framework",
    "WSTG-INFO-09": "Fingerprint Web Application",
    "WSTG-INFO-10": "Map Application Architecture",
    "WSTG-CONF-01": "Network Infrastructure Configuration",
    "WSTG-CONF-02": "Application Platform Configuration",
    "WSTG-CONF-03": "File Extensions Handling for Sensitive Information",
    "WSTG-CONF-04": "Review Old Backup and Unreferenced Files for Sensitive Information",
    "WSTG-CONF-05": "Enumerate Infrastructure and Application Admin Interfaces",
    "WSTG-CONF-06": "HTTP Methods",
    "WSTG-CONF-07": "HTTP Strict Transport Security",
    "WSTG-CONF-09": "File Permissions",
    "WSTG-CONF-10": "Subdomain Takeover",
    "WSTG-CONF-11": "Cloud Storage",
    "WSTG-CONF-12": "Content Security Policy",
    "WSTG-CONF-13": "Path Confusion",
    "WSTG-CONF-14": "Other HTTP Security Header Misconfigurations",
    "WSTG-CONF-15": "Feature Flag Security Bypass",
    "WSTG-IDNT-01": "Role Definitions",
    "WSTG-IDNT-02": "User Registration Process",
    "WSTG-IDNT-03": "Account Provisioning Process",
    "WSTG-IDNT-04": "Account Enumeration and Guessable User Account",
    "WSTG-IDNT-05": "Weak or Unenforced Username Policy",
    "WSTG-ATHN-01": "Credentials Transported over an Encrypted Channel",
    "WSTG-ATHN-02": "Default Credentials",
    "WSTG-ATHN-03": "Weak Lock Out Mechanism",
    "WSTG-ATHN-04": "Bypassing Authentication Schema",
    "WSTG-ATHN-05": "Vulnerable Remember Password",
    "WSTG-ATHN-06": "Browser Cache Weaknesses",
    "WSTG-ATHN-07": "Weak Authentication Methods",
    "WSTG-ATHN-08": "Weak Security Question Answer",
    "WSTG-ATHN-09": "Weak Password Change or Reset Functionalities",
    "WSTG-ATHN-10": "Weaker Authentication in Alternative Channel",
    "WSTG-ATHN-11": "Multi-Factor Authentication (MFA)",
    "WSTG-ATHN-12": "SAML Authentication",
    "WSTG-ATHZ-01": "Directory Traversal and File Include",
    "WSTG-ATHZ-02": "Bypassing Authorization Schema",
    "WSTG-ATHZ-03": "Privilege Escalation",
    "WSTG-ATHZ-04": "Insecure Direct Object References",
    "WSTG-ATHZ-05": "OAuth Weaknesses",
    "WSTG-SESS-01": "Session Management Schema",
    "WSTG-SESS-02": "Cookies Attributes",
    "WSTG-SESS-03": "Session Fixation",
    "WSTG-SESS-04": "Exposed Session Variables",
    "WSTG-SESS-05": "Cross Site Request Forgery",
    "WSTG-SESS-06": "Logout Functionality",
    "WSTG-SESS-07": "Session Timeout",
    "WSTG-SESS-08": "Session Puzzling",
    "WSTG-SESS-09": "Session Hijacking",
    "WSTG-SESS-10": "JSON Web Tokens",
    "WSTG-SESS-11": "Concurrent Sessions",
    "WSTG-INJT-01": "Reflected Cross Site Scripting",
    "WSTG-INJT-02": "Stored Cross Site Scripting",
    "WSTG-INJT-03": "HTTP Verb Tampering",
    "WSTG-INJT-04": "HTTP Parameter Pollution",
    "WSTG-INJT-05": "SQL Injection",
    "WSTG-INJT-06": "LDAP Injection",
    "WSTG-INJT-07": "XML Injection",
    "WSTG-INJT-08": "SSI Injection",
    "WSTG-INJT-09": "XPath Injection",
    "WSTG-INJT-10": "IMAP SMTP Injection",
    "WSTG-INJT-11": "Code Injection",
    "WSTG-INJT-12": "Command Injection",
    "WSTG-INJT-13": "Format String Injection",
    "WSTG-INJT-14": "Incubated Vulnerability",
    "WSTG-INJT-15": "HTTP Response Splitting",
    "WSTG-INJT-16": "HTTP Request Smuggling",
    "WSTG-INJT-17": "Host Header Injection",
    "WSTG-INJT-18": "Server-side Template Injection",
    "WSTG-INJT-19": "Server-Side Request Forgery",
    "WSTG-INJT-20": "Mass Assignment",
    "WSTG-INJT-21": "CSV Injection",
    "WSTG-INJT-22": "Prototype Pollution",
    "WSTG-INJT-23": "Insecure Deserialization",
    "WSTG-ERRH-01": "Improper Error Handling",
    "WSTG-ERRH-02": "Stack Traces",
    "WSTG-CRYP-01": "Weak Transport Layer Security",
    "WSTG-CRYP-02": "Padding Oracle",
    "WSTG-CRYP-03": "Sensitive Information Sent via Unencrypted Channels",
    "WSTG-CRYP-04": "Weak Cryptographic Primitives",
    "WSTG-BUSL-01": "Business Logic Data Validation",
    "WSTG-BUSL-02": "Ability to Forge Requests",
    "WSTG-BUSL-03": "Integrity Checks",
    "WSTG-BUSL-04": "Process Timing",
    "WSTG-BUSL-05": "Number of Times a Function Can Be Used Limits",
    "WSTG-BUSL-06": "Circumvention of Work Flows",
    "WSTG-BUSL-07": "Defenses Against Application Misuse",
    "WSTG-BUSL-08": "Upload of Unexpected File Types",
    "WSTG-BUSL-09": "Upload of Malicious Files",
    "WSTG-BUSL-10": "Payment Functionality",
    "WSTG-CLNT-01": "DOM-Based Cross Site Scripting",
    "WSTG-CLNT-02": "JavaScript Execution",
    "WSTG-CLNT-03": "HTML Injection",
    "WSTG-CLNT-04": "Client-side URL Redirect",
    "WSTG-CLNT-05": "CSS Injection",
    "WSTG-CLNT-06": "Client-side Resource Manipulation",
    "WSTG-CLNT-07": "Cross Origin Resource Sharing",
    "WSTG-CLNT-09": "Clickjacking",
    "WSTG-CLNT-10": "WebSockets",
    "WSTG-CLNT-11": "Web Messaging",
    "WSTG-CLNT-12": "Browser Storage",
    "WSTG-CLNT-13": "Cross Site Script Inclusion",
    "WSTG-CLNT-14": "Reverse Tabnabbing",
    "WSTG-CLNT-15": "Client-side Template Injection",
    "WSTG-CLNT-16": "DOM Clobbering",
    "WSTG-APIT-01": "API Reconnaissance",
    "WSTG-APIT-02": "API Broken Object Level Authorization",
    "WSTG-APIT-03": "Excessive Data Exposure",
    "WSTG-APIT-04": "API Broken Function Level Authorization",
    "WSTG-APIT-99": "GraphQL",
    "WSTG-WASM-01": "WebAssembly Reconnaissance",
}

# Sub-test pages ("NN.M-*.md") that refine a parent test. They are not in the
# checklist, so an ID here is only valid together with its parent.
WSTG_LATEST_SUBTESTS: dict[str, str] = {
    "WSTG-ATHZ-05.1": "OAuth Authorization Server Weaknesses",
    "WSTG-ATHZ-05.2": "OAuth Client Weaknesses",
    "WSTG-INJT-05.1": "Oracle",
    "WSTG-INJT-05.2": "MySQL",
    "WSTG-INJT-05.3": "SQL Server",
    "WSTG-INJT-05.4": "PostgreSQL",
    "WSTG-INJT-05.5": "MS Access",
    "WSTG-INJT-05.6": "NoSQL Injection",
    "WSTG-INJT-05.7": "ORM Injection",
    "WSTG-INJT-05.8": "Client-side",
    "WSTG-INJT-11.1": "File Inclusion",
    "WSTG-CLNT-01.1": "Self DOM Based Cross Site Scripting",
}


def is_current_wstg_id(check_id: str) -> bool:
    """True when `check_id` is a current WSTG test or a sub-test whose parent
    test is also current."""
    if check_id in WSTG_LATEST_TESTS:
        return True
    if check_id in WSTG_LATEST_SUBTESTS:
        return check_id.rsplit(".", 1)[0] in WSTG_LATEST_TESTS
    return False
