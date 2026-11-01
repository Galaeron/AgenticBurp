# Captured-only operation and endpoint exclusions

Select the existing `operating_profile: passive-only` in ignored local
configuration for analysis of supplied HTTP exchanges without target fetching.
The profile forces active/discovery/browser-capture/engagement features off,
including the iterative agent. The immutable run target policy additionally
blocks all target requests, including GET/HEAD/OPTIONS/TRACE, before client
creation, budget reservation or I/O. Setting `transport.captured_only: false`
cannot override this profile. `transport.captured_only: true` can restrict another
profile without enabling any feature. This is not a no-egress claim: local or
remote inference/advisory services are separate from target transports.

No committed feature default is broadened. Existing `none` operation without
the new optional restriction retains its prior scope/gate behavior. Captured-only
is an explicit mode, not a claim that disabling validators makes every possible
target-fetch API passive. A nominally safe HTTP method alone does not establish
the absence of application side effects.

Optional `transport.excluded_path_prefixes` is a list of absolute path prefixes,
for example `/logout` or `/account/delete`. It excludes the path itself and
descendants at slash boundaries, across all target hosts and HTTP methods. It
does not exclude a nearby `/logout-help`. Query text is not a path constraint;
query/fragment-bearing configured prefixes are rejected. Percent encodings and
dot segments are normalized for comparison; malformed or excessively nested
encoding is denied. This is a textual request policy, not a guarantee about
server-specific routing or semantic aliases. Malformed configuration fails
before any client is created.

TargetTransport applies endpoint policy before every redirect hop. SafetyGate
uses the same run policy; a caller-supplied legacy gate cannot bypass the separate
transport restriction. API endpoints which fetch targets (/crawl, /crawl-roles,
/probe-missing-auth, /active-probe, engagement execution/advance/investigate)
reject captured-only operation with HTTP 403 before entering their adapters.
The legacy raw crawl/browser/bulk adapters cannot enforce per-hop endpoint
exclusions; when any such exclusions are configured the API rejects those entire
operations conservatively. This limitation is explicit rather than claiming
partial support. Nonexecuting engagement planning is still available.

The authenticated `/settings` response includes `target_policy` with captured-only
mode, fetching status, exclusions and an explanation that blocked fetching is
not a negative test result. Transport denial says `blocked` and supplies the
policy reason. Analysis still accepts captured supplied data; those observations
do not mean an active test was executed or the target is clean. Java UI rendering
of this status requires separate build/integration verification.

Verification uses synthetic supplied responses through actual orchestrator
analysis, a silent fake inference provider, temporary SQLite/cache stores, direct
deny-before-await transport controls, guarded ordinary MockTransport redirects
and direct API coroutine admission controls. It launches no target/model service,
browser/container or validator/probe. Whole-program raw adapter migration and
arbitrary in-process caller containment are separate work; this policy is not
a process/network sandbox.
