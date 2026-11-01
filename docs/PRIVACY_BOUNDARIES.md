# Privacy boundaries and pairing migration

R03 source contract, checked on 2026-10-05 with synthetic captured traffic.
These boundaries reduce recognized credential disclosure. They do not establish
NDA compliance, complete secret detection, or application-wide zero egress.

## Sensitive API reads

All GET/HEAD routes require the effective bearer token except `/health`, API
documentation/schema routes, and `/pairing/check` (which authenticates in its
handler). This includes reports/SARIF, telemetry, plans, settings, models,
knowledge, tools, engagement/job state, activity, effort, identities/sessions,
suppressions, finding evidence, merge state and cache statistics. The central
middleware also covers future GET routes. Origin and Host defenses remain
independent, and mutations retain their existing mandatory token check.

Legacy `server.require_read_auth: false` and `_READ_AUTH_ENABLED = False` no
longer allow sensitive reads. Configure the same bearer credential in the
extension/client and server, or use the generated local token. Call
`/pairing/check` to verify it; restart-generated credentials require re-pairing.
Public health means liveness only. Never distribute the generated lockfile or
commit local overrides. Windows token-file ACL verification remains R14 work.

## Shared sanitation

`security.sanitize_for_inference` covers coordinator, specialist/family,
methodology/business context, critique and the local/remote provider adapters.
`sanitized_exchange` creates a prompt copy; authoritative captures are retained.
The shared policy masks recognized secret names in nested JSON, body assignments,
header lines, URL userinfo/query/fragment, and encoded nested URL parameters.
JWT metadata exposes only allowlisted algorithm/type, not payload/signature/kid.
Explicit `known_values` can mask opaque values when a caller knows them.

`issues.export_issue` sanitizes the final structured view, including metadata and
proof references. Local replay keeps session placeholders, with sanitized
metadata and evidence. Markdown sanitizes its final output including headlines
and chain sections. `/report/sarif` consumes the same sanitized canonical export.
Provider diagnostics use structural sanitation and expose key presence only.
Expected provider/server failures withhold arbitrary upstream text; HTTP
diagnostics and existing server logging handlers sanitize recognized structures.

Unlabelled prose, application-specific names, opaque/binary encodings and secrets
embedded in path segments remain outside this contract. New logging handlers
must install the shared filter. Raw stores/caches/evidence and browser/Burp
captures are sensitive; authentication is not storage sanitation. Retention,
backups, deletion and ACLs remain separate R14 requirements.

## Outbound inventory and offline profile

| Dependency/caller | Destination/data | Control and limitation |
| --- | --- | --- |
| OllamaClient / OllamaProvider | Configured Ollama base URL; sanitized inference prompts, model listing | Localhost is default; operator may choose a remote host. Local inference is still network activity. |
| OpenAI / Anthropic adapters | Configured endpoint; sanitized prompts, provider key in required wire auth | Explicit role/provider selection and key required; cloud model/reasoning toggles remain opt-in. Keys must reach their selected provider. |
| GitHubAdvisoryClient | GitHub advisory API; component name/ecosystem, optional GitHub token | Disable `github_advisories.enabled`, or use `offline: true` with a local snapshot. Default lookup can use network. |
| KevClient | CISA KEV catalog | Disable `kev_check.enabled`, or supply a local catalog; default `local_file: null` can fetch. |
| PackageRegistryClient | npm/PyPI component lookup; package identity | Disable `package_registry_checks.enabled`. Module also contains Aikido malware-feed fetch capability; do not infer no egress from its registry-age label. |
| Discovery/crawl/role/missing-auth/worklist/feature workflows and validators | Captured target origins; authorization/session material when explicitly replaying | Separate target transport/scope/safety policy. No target requests were executed for R03 verification. |
| Browser driver / Playwright, Docker tool runner / sqlmap | Browser resources, container networking, target sends/tool dependencies | Optional capabilities; keep active execution and tools disabled for an offline passive profile. External tools have their own logging/storage. |
| Burp extension and MCP/local interfaces | Harness API and local resources | Sensitive reads require pairing; external clients can export their returned data. |
| Build/package installation/model downloads | Package/model registries | Environment preparation is separate from assessment egress. |

For captured-only work: choose a controlled local Ollama endpoint, omit remote
provider selection, keep cloud/active/browser/tool workflows off, disable the
three external lookup blocks above (or use validated local advisory/catalog
files), and enforce an OS/network deny policy if zero external egress is needed.
Use ignored local overrides; committed defaults are unchanged by this document.

The fake recorder test covers actual Ollama adapter/HTTP serialization plus an
offline advisory caller and sees only `http://localhost:11434/api/chat`. Other
tests use fake inference, temporary SQLite, real report routes and defect
injection. This is bounded caller evidence, not a full production egress audit.
The mandatory smoke/full suite includes excluded active fixtures and remains an
unverified release gate; focused R03 results do not imply the full suite is green.
