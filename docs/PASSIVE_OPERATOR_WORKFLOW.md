# Passive operator workflow and release limits

This describes the remediation's supplied-capture workflow. It is not a released
installation guarantee: R19 intact packaging is blocked by the recorded Defender
detection during installation, and R28 final candidate verification is open.
Do not bypass endpoint protection, remove source files to force a package hash,
or treat an old JAR as proof that this checkout builds.

Use a dedicated Python environment. The recorded environment is Python 3.12.14;
other interpreter/platform combinations are unverified here. Build instructions,
Java17/Gradle8.7 identities and the intermediate artifacts are in
[build evidence](REMEDIATION_BUILD_EVIDENCE.md). A reviewed intact wheel must pass
installation and module/resource checks outside the checkout before release.
The Montoya compile API is 2023.12.1; actual compatibility with the operator's
Burp version still needs a supported UI check.

Start an owned instance with `python -m harness.server` on loopback, with
`reload=False`. Configuration is module-relative: packaged `harness/config.yaml`
then optional ignored `harness/config.local.yaml`; the local mapping wins.
Operating profiles are applied with explicit local keys preserved. Keep the
shipped passive defaults; the `passive-only` local profile makes the supplied-
capture boundary explicit. Check the [captured-only policy](CAPTURED_ONLY_POLICY.md)
for how endpoint exclusions and blocked fetch operations are represented.
This profile is not a promise of no network egress: review
[privacy boundaries](PRIVACY_BOUNDARIES.md) for provider/advisory integrations.
Do not copy a live local override into a release package.

Follow [pairing](PAIRING.md) to bind the extension's origin and masked credential
to this instance. Configured `server.auth_token` takes precedence over
`HARNESS_BEARER_TOKEN`; otherwise startup generates an ephemeral credential.
Public health reports liveness and model status, while pairing checks permission.
Neither proves a completed analysis. Sensitive reads require the same credential.

Supply a benign ordinary HTTP capture; do not trigger discovery, crawl, replay
or confirmation for this workflow. Preserve request method, URL, headers, body
and response metadata. For API use, retain the returned engagement identifier
when continuing that engagement; an omitted identifier creates independent
analysis context. Captured-principal fingerprints separate recognized credential
contexts but do not prove the user's real identity or authorization. Explicit
engagement-wide reports aggregate those contexts; choose the principal filter
when reviewing one credential context. See the register for remaining legacy
host-only caller limitations.

Inspect completion/error/evidence state before interpreting findings. Empty
findings after a failed model call are not a clean assessment. Malformed Java
responses, expired credentials, throttling and disconnects are explicit errors.
A client timeout/interruption stops waiting; server completion and cancellation
remain unknown. Do not blindly resubmit after a lost response: job submission
has no idempotency guarantee. [Job recovery](JOB_STATUS_RECOVERY.md) describes
durable interrupted status and bounded metadata retention, without automatic
reexecution. A missing evidence reference is unavailable, not verified proof.

Export sanitized Markdown/SARIF/structured results only after reviewing evidence
maturity and the [data lifecycle](DATA_LIFECYCLE.md). Redaction covers recognized
secret structures; raw captures, DBs, audit material and arbitrary free text need
operator access controls. Token-file ACL protection does not encrypt other data.

For an upgrade, preserve the previous reviewed artifact and config fingerprint,
stop only the owned server, follow the explicit backup procedure, install the
new artifact in a separate environment, then verify pairing and a fresh benign
capture/cache. Do not carry tokens into shared artifacts. For rollback, restore
the previous artifact with its compatible verified backup into a separate
destination; do not point old code at an unverified migrated database. Restart
with `reload=False`, re-pair rotated credentials, and use a fresh cache.
Backup verification proves bounded database integrity, not restoration of every
external export/log or an untested version migration.

For support, provide source/content identity, Python/JDK/Gradle/Burp versions,
sanitized error kind, run/engagement ID and a non-sensitive reproduction. Do not
attach bearer tokens, raw traffic, local overrides or databases. CURRENT_STATE
and the remediation register separate fresh caller evidence from historical
claims. The final candidate walkthrough, live Burp UI, full regression gates and
practical effectiveness study remain unverified here.
