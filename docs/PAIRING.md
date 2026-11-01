# Pairing the Burp extension with the harness

Start the supported passive harness with `python -m harness.server` from its
installed environment. Keep the server on loopback for local use. The harness
requires a bearer token for state changes, including passive `/analyze` calls.

Choose one credential flow:

- Set `HARNESS_BEARER_TOKEN` in the environment used to start both the harness
  and Burp. The Java client reads it on construction for its initial loopback
  URL. An explicit `server.auth_token` local override takes precedence on the
  server, so both processes must use the same effective value.
- Supply the effective server credential in the masked **Pairing token** field
  beside **Harness URL**, then click **Test Connection**. With no configured
  credential, the server generates one per process and writes it to
  `harness/.harness_token.lock` beside the installed server module. Read only
  the file belonging to the intended running service using your local editor;
  paste its value directly into the masked field. Avoid terminal output,
  screenshots, shell history, shared logs and committed configuration.

The extension does not search directories or automatically read token files.
The entry is erased after application; the client retains the credential only
in memory. A blank entry retains the credential for the same service. **Clear
token** removes it explicitly. Changing the URL to another origin clears it;
apply the credential intended for that service and reconnect. Equivalent
scheme/host/default-port spellings identify the same origin.

**Authenticated** means public `/health` responded and `/pairing/check` accepted
the credential. It does not establish inference availability or successful
analysis. Missing, wrong or stale credentials produce a reconnect message.
An ephemeral credential changes after a server restart; enter the current
credential again. Configured environment credentials remain stable unless the
operator rotates them. Nothing in this flow automatically retries analysis.

The Java client accepts loopback HTTP and HTTPS URLs without user information,
paths, queries or fragments. A remote service requires HTTPS with a certificate
trusted by the JVM and an explicitly supplied credential. Remote cleartext
HTTP is refused. The client does not relax certificate validation or follow
redirects to transfer credentials.

Sensitive reads require authentication; the old `require_read_auth: false`
setting does not disable that policy. On Windows the token writer verifies a
private DACL before writing the secret; POSIX uses private permissions. If that
step fails, startup logs a failure and any old token file may be stale. Do not
interpret a stale file as the current credential. This bounded file check does
not certify permissions for databases, logs or exports. See [data lifecycle](DATA_LIFECYCLE.md).

R02's real Java client reached production Python routes on an owned loopback
server with fake passive inference and temporary SQLite: captured analysis,
stored SARIF, denied credentials and restart rotation passed. Actual Java builds
also passed at the recorded intermediate revisions. These are API integration
controls, not real-model accuracy, final package or live Burp UI verification.
See [build evidence](REMEDIATION_BUILD_EVIDENCE.md) for identities and open gates.
