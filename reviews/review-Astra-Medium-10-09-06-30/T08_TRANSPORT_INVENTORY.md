# T08 — Transport-adapter inventory & routing-gap audit

Inventory of every outbound-transport call-site in `harness/`, its routing
against the T03 run-scoped executor, and the specific gaps still to migrate. This
is **inventory + audit only** — it changes no transport behavior. The machine copy
is `harness/transport_inventory.py`; `harness/test_transport_inventory.py` enforces
that a new direct send cannot be added without either routing it through the
executor or recording it here with an owner.

Baseline: branch `astra-t05-t08` (off `codex/astra-review-fixes`). Source-derived
via targeted `rg` over `httpx.(AsyncClient|Client)(`, `subprocess`/`docker`,
`async_playwright`, and raw `socket` upgrades. **32 production sites** (29 http,
1 container, 1 browser, 1 raw-socket) across 4 scopes (24 target, 4 infra, 3
egress, 1 llm); **23 target-directed routing gaps** (the 24th target site,
`api_security_validator.py`, already sends through the gate).

## The routed transport (infra adapters)

| Module | Channel | Role |
|---|---|---|
| `run_context.py` | http | `RunContext.Executor` + `ManagedSession` — the run-scoped, scope/cookie/credential-aware transport target sends migrate onto (T03). |
| `safety_gate.py` | http | `SafetyGate` + `GatedAsyncClient` — the mutation/scope gate the executor and mutating validators send through. |
| `tool_runner.py` | container | docker/subprocess adapter (sqlmap/ffuf); force-removes the container on timeout. |
| `browser_driver.py` | browser | Playwright/Chromium adapter for browser_xss/dom_xss/stored_xss. |

## Out of target-executor scope (correctly direct)

These do **not** hit the target and must not be counted as routing gaps:

- **Egress (public intel APIs):** `github_advisories.py`, `kev_check.py`, `package_registry_checks.py`.
- **LLM plane:** `ollama_client.py` (Ollama chat/tags).

## Target-directed routing gaps (owned migration work)

Each is a direct target send **not yet** on the run-scoped executor. Migrating
means: scope-check every hop (incl. redirects), per-session cookie jars, explicit
credential-forwarding rules, mutation ceilings, cancellation, and captured outcome
artifacts — the executor already provides these; these sites bypass them today.

### Discovery / crawl / agent
| Module | Gap | Owner |
|---|---|---|
| `api_surface_discovery.py` | surface discovery sends directly; hops not scope-checked or captured | astra-identity (T03/T08) |
| `crawler.py` | crawl sends with `follow_redirects=True`; redirect hops not scope-gated | astra-identity (T03/T08) |
| `role_crawl.py` | **review F01** — role crawl remains on old transport; should source identities from the run and send per-session through the executor | astra-identity (F01/T03) |
| `scope_discovery.py` | scope-probe sends directly | astra-identity (T03/T08) |
| `feature_workflow.py` | stateful workflow crawl fetches directly; T07 workflow engine routes steps through the executor with per-session state | astra-identity (T07) |
| `missing_auth_probe.py` | unauthenticated-access probe sends directly | astra-identity (T03/T08) |
| `iterative_agent.py` | agent tool-fetch sends directly; route so agent hops obey scope/budget/cancellation | agents (T09) |
| `orchestrator.py` | second-order / discovery-confirm / coverage-seed sends open ad-hoc clients; route through the executor and carry the run's evidence sink | astra-identity (T03/T08) |

### Confirmation legs (validators)
Mutating legs pass through `GatedAsyncClient` (e.g. `api_security_validator.py`);
read-only legs open their own client. Full migration to the executor (per-session
isolation, cancellation, artifact capture) is F01/F04/T08 follow-on. Highlights:

- **`validators/cross_identity_validator.py` — review F04.** Partially migrated (T03),
  but even with a context it sends `session_ref=None`, so identities share one cookie
  jar and read process-global headers. Bind every identity/anon call to isolated
  session state sourced from the run. **This is the highest-value gap — it feeds F01/F04.**
- `validators/http_request_smuggling_validator.py` — CL/TE desync needs its **own raw-protocol
  adapter**; ordinary HTTP response anomalies do not qualify it (keep non-confirming until then).
- `validators/sqlmap.py` — container leg via `tool_runner`, plus a direct httpx boolean-probe
  fallback when Docker is unavailable.
- Read-only probes: `jwt_forge`, `cors`, `csp`, `oauth`, `header_injection`, `recon`,
  `subdomain_takeover`, `web_cache_poisoning`. Provisional oracles: `rate_limit`, `toctou`,
  `race_condition`.

### Raw socket
| Module | Note | Owner |
|---|---|---|
| `validators/websocket_validator.py` | hand-rolled WebSocket upgrade over `socket`+`ssl` (no ws library); CSWSH origin check — its own raw-socket adapter | confirmation |

## Oracle re-qualification (per-leg, deferred)

The handoff's per-oracle re-qualification (read `ORACLE_RETIREMENTS.md`, implement
each retired oracle's control, add a paired **actual-transport** fixture, wire its
proof contract, update qualification metadata only with recorded evidence) is
**not** done here — it needs live vulnerable/patched fixtures per leg and overlaps
the executor migration above. This inventory names the owners and gaps that work
starts from. Prioritise **CSRF** and **method authorization** (they reuse the
workflow/identity foundations), per the handoff.

## Verification

`python -m unittest test_transport_inventory` — 9 tests. The enforcement test
(`test_scan_matches_registry`) scans the tree for httpx client constructions and
fails if any production module is un-inventoried or any registry entry is stale, so
this audit cannot silently drift from the source.
