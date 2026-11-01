# Scope normalization and containment

`harness.scope_lock` owns URL parsing, entry parsing and matching. `ScopePolicy`,
`HostAllowScope`, scope discovery admission and SafetyGate use this same boundary.
This policy authorizes hostnames and declared literal addresses. DNS aliases,
`localhost`/`127.0.0.1` equivalence and connect-time DNS address authorization are
not inferred. Optional existing connect-address pinning remains a separate policy.

HTTP(S) URLs must have a valid hostname and port. Userinfo, backslashes, control
characters, whitespace, invalid ports, empty explicit ports and malformed IPv6 are
denied before sending. Default HTTP port 80 and HTTPS port 443 normalize for origin
comparison; distinct ports and schemes remain distinct credential destinations.
IPv6 origins retain brackets. A trailing DNS dot remains distinct for matching.
Hostnames use lowercase IDNA spelling; IP literals use canonical address spelling.
These are textual normalization rules, not permission to resolve hostname aliases.

All production scope adapters authorize the conservative intersection: exact
hostname or literal address entries. The extended parser remains available for
inspection/compatibility, but no production adapter uses it to grant authority.
This tightens former discovery admission instead of expanding the strict gate.

| Entry | ScopePolicy / scope_lock / SafetyGate / discovery / HostAllowScope |
| --- | --- |
| `target.test` | Exact hostname, HTTP(S), any valid port |
| `::1` / `127.0.0.1` | Exact literal address |
| `target.test:443` | Denied |
| `https://target.test:8443` | Denied |
| `https://target.test` | Denied |
| `*.target.test` | Denied |
| `10.0.0.0/24` | Denied |
| Bracketed IPv6 entry with port | Denied |
| Malformed entry / path suffix | Denied; suffixes are never discarded |

An empty strict scope and an empty active scope fail closed. Historical standalone
passive admission can still accept an unset scope for a valid HTTP(S) URL; this is
not an authorization for captured-only analysis to fetch. R05 defines that caller
boundary separately. SafetyGate with active_enabled true refuses an unset scope.
TargetTransport checks both run scope and gate before each hop. All configured
entry decisions now agree across the shared adapters. ScopePolicy remains closed
when unset; passive admission adapters' compatibility allowance for unset scope
is distinct from authorization to fetch. Captured-only transport enforcement is
the separate R05 gate.

Migration tightening: a bare hostname no longer grants implicit subdomain access
in discovery. Extended entries previously accepted by discovery are now denied
there as well as by the strict gate. List required subdomains or literal addresses
explicitly only when the operator authorizes those exact hosts. Do not replace a
port/scheme-constrained entry with a bare host: that would broaden its restriction.
Port/scheme-constrained configured entries currently authorize no destination;
supporting them requires a separate capability decision that preserves prior
denials. No wildcard is automatically added. Malformed/non-HTTP URLs and userinfo
URLs that older checks accepted are now denied; supply a valid URL and credentials
through the existing session mechanism. No feature flags are enabled by migration.
Existing tests expecting implicit subdomain admission or active sends with an empty
scope describe superseded permissive behavior; preserve their coverage while
updating expectations under the reviewed containment contract.

Verification uses benign decision tables and the actual TargetTransport with
MockTransport ordinary responses, scope/gate traces, no-socket guards, cross-origin
synthetic credential controls and defect injection. It adds no discovery, target
probing, validator or replay capability. Full/smoke execution remains governed by
the reconciled loop's active-fixture restriction.
