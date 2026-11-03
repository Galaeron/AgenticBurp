# Crawl loop — handoff (2026-11-03)

Branch `claude/elegant-shtern-356515`, nothing is pushed. This work addresses the coverage gaps from the 8-hour Juice Shop run, recorded in `.test-work/juice-shop-8h-20261103/COVERAGE_QA.md` and `YIELD_ANALYSIS.md` in worktree `i16-persist-77da6a`.

## Root causes found
- **One role swept.** `role_crawl._distinct_discovery_roles` keeps one role per feature key. The run had eval-user-1 and eval-user-2, both of role `user`, so they collapsed into one sweep ("swept 1 role").
- **One page visited.** The browser loaded the start page once and followed no in-app link. XHRs fired for `/` only.
- **No route feedback.** Routes first seen after discovery were never fed back. The worklist was fixed about 5 minutes into the run.
- **No session refresh in production.** The E5a session-health machinery existed, but no production code registered a refresh or a probe. A token expiring mid-run turned every later 401 into an access-control reading.
- **Review starved the chain rounds.** `capture_review_seconds: 0` with no per-phase slicing let review hold the rest of the run, so the chain rounds never started.

## What changed (all off by default; `harness/config.yaml` defaults unchanged in effect)
| Item | Config key | Code |
|---|---|---|
| SPA navigation | `driver_capture.spa_navigation` (+ `max_views` 30, `max_depth` 4) | new `harness/spa_navigation.py` (engine-free BFS `crawl_views`, `resolve_view`); `PlaywrightDriver.crawl_spa` (same `_IdentityRouter`, one context, NC-2 kept); `driver_capture.crawl_spa`; `build_engagement` uses it per crawl role |
| Route feed + re-crawl | `engagement.recrawl` {enabled, max_rounds 2, min_new_routes 1, max_new_routes 200, max_routes_per_round 50} | new `harness/route_feed.py`. The transport offers every response, and `_IdentityRouter._offer_route` offers browser XHRs. `engagement_builder.recrawl_state` re-GETs each new route as every principal. `orchestrator_chain._recrawl_rounds` runs after the worklist and merges into state. |
| Per-principal crawl | `engagement.crawl_per_principal` | `role_crawl.crawl_roles_for` / `_principal_discovery_roles`, used by build_engagement (browser + role crawl) and feature_crawl_captures |
| Session freshness | `transport.session_freshness` {enabled, window 20, min_denials 6, min_routes 2, denial_rate 0.6} | new `harness/session_freshness.py`. `TargetTransport._freshness_feedback` / `_session_stale`: refresh via `RoleSession.login` (`login_refresher`, registered by `register_role_sessions`; `server._role_sessions` passes `login`), else health `stale`. Both outcomes log `session_refresh` / `session_stale` events with counts only. Stale sessions are refused like expired ones. |
| Phase slices | `engagement.phase_slices` {worklist, recrawl, capture_review, chain_rounds: share} | new `harness/phase_schedule.py`. Each phase gets its share of the time remaining when it starts. Explicit caps (`capture_review_seconds`) still bind. Active only with `investigation_seconds > 0`. |

The `recrawl.enabled` and `crawl_per_principal` keys were added to `config_schema._PASSIVE_FORCE_OFF_KNOBS`. The result gains a `crawl_loop` block containing per_principal, spa_views, recrawl, phase_schedule and session_events.

## Tests
New file `harness/test_crawl_loop.py` has 40 tests, and every behaviour has a negative control:
- a fake SPA adapter;
- a real Chromium crawl of a fake hash-routed SPA;
- a build_engagement caller test;
- RouteFeed units, the transport hook and recrawl_state against a 127.0.0.1 target;
- freshness units plus an expiring-token target, covering refresh through a POST login, stale-and-refused, feature off, and never-served routes;
- PhaseSchedule units;
- investigate_engagement caller tests for recrawl and slices.

Gate results are in `gates-py312.txt` and `gates-py314.txt`, written by `gates.sh <python> <tag>`.

Results: 3.12 venv and 3.14 both green. Precondition 74 OK, touched (crawl_loop, transport_health, stage_reservations, config_schema, browser gate and isolation callers, engagement_policy, worklist, deterministic_first, driver_capture, engagement_builder, role_crawl) 249 OK, smoke 149 OK. `git diff --check` is clean.

## Owner questions
1. **Login refresh vs the safety gate.** A POST login refresh goes through the gate and needs `validators.allow_mutating_replay`. Should `capability="session_refresh"` get a narrow gate exemption for the operator-declared login only?
2. **Source of the login flow.** Should it be derived from seed captures (the recorded login XHR) when `RoleSession.login` is absent? Today it is declared by the operator only.
3. **Deadline the slices divide.** Phase slices need `investigation_seconds`. The 8-hour run was soft-cancelled by external `monitor.py`, and the harness does not know that deadline. Should the request or monitor deadline be passed in as `investigation_seconds`?
4. **Anonymous binding in `capture_requests` (pre-existing, not fixed).** Playwright's `request.headers` lack the identity that `_IdentityRouter` adds, so authenticated browser captures are bound to anonymous or unbound. `crawl_spa` fixes this with `_with_identity`. Apply the same to `capture_requests`?
5. **Re-crawl timing.** Re-crawl rounds run only after the worklist. Should another round also run after the chain rounds and capture review?
6. **Remaining `== "expired"` checks.** `experiment.py`, `orchestrator_chain.py` (around line 744) and `browser_driver.execute_browser_step` check only `== "expired"`, not `"stale"`. The transport already refuses stale sends. Should they be widened for clearer reporting?
7. **Denial attribution in validators.** The idor/cross_identity validators could consult session health or the `session_expired` outcome, so a stale principal's denials are never read as access control. These files belong to the self-observed-ownership session.
8. **Limits of browser link discovery.** Production Angular `routerLink` on non-anchor elements leaves no DOM attribute, so the browser crawl cannot see those routes. JS route extraction, owned by the request-budget session, is the complement. Feed its routes through `extra_views` or the RouteFeed.
9. **sqlmap.** It is bounded by slices only at worklist-node granularity.

## Overlap with parallel sessions
- `role_crawl.py`: a small addition (new `login` field, `crawl_roles_for`, `per_principal` param).
- No edits to `issues.py`, `categories.py`, `report_generator.py`, the idor/cross_identity validators, api_surface_discovery, ffuf/ToolBroker or plan dispatch.

## Next step
Owner: answer questions 1–3, then run a live Juice Shop run with all five features enabled in `config.local.yaml`, and compare surface coverage against COVERAGE_QA.md.
