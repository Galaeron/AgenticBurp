# Callback listener configuration

The default OOB collaborator binds an ephemeral IPv4 loopback port. It can prove
callbacks from a local target, but its absence of hits is not a clean negative
for a target on another network.

For an approved Docker-host callback, put these settings in the ignored
`harness/config.local.yaml` (the shipped defaults need no changes):

```yaml
collaborator:
  bind_host: 0.0.0.0
  advertise_host: host.docker.internal
  port: 38698
  approved_origin: http://host.docker.internal:38698
```

The equivalent launcher environment variables are `AGENTICVIBE_OOB_BIND_HOST`,
`AGENTICVIBE_OOB_ADVERTISE_HOST`, `AGENTICVIBE_OOB_PORT` and
`AGENTICVIBE_OOB_APPROVED_ORIGIN`. Environment values override local configuration.
An external bind or advertised host requires an explicit port and an exactly
matching HTTP origin. URLs, paths, credentials and wildcards are not host names.
Malformed settings fail registry construction. Bind failures are errors; the
listener never silently chooses another port or origin.

The registry owns one lazy listener for its four OOB validators: SSRF, XXE,
command injection and deserialization. Separate registries do not adopt another
registry's listener on the same fixed port. Use `registry.collaborator.stop()`
when its owner is finished; process exit also closes it. Do not stop another
registry's listener. A stopped collaborator is not reusable.

Before a container assessment, start `registry.collaborator.start()`, generate a
token with `token()`, and fetch `url(token)` from the owned target's container or
network. After that request, `record_preflight(token, target_url)` verifies the exact hit;
`health()` reports listener availability and verified target origins. Evidence is
scoped to the target's scheme, host and port; it does not authorize another target. A host
fetch does not establish container reachability. Retain the preflight result with
the assessment evidence; do not set verification based on a successful bind.

An exact registered callback proves the specific probe even without preflight.
Unrelated requests, token substrings and query parameters cannot confirm it.
Without verified remote reachability, an absent callback remains inconclusive;
independent in-band evidence may still confirm. Target scope is unchanged by
callback approval: approval authorizes the callback dependency, not more targets.

This release supports IPv4 bind addresses and DNS host names, HTTP only. External
DNS/HTTPS OOB services and automatic target-network preflight are not implemented.
