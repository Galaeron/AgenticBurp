# Click exploration in the SPA crawl — handoff (2026-11-26)

Branch `worktree-agent-a3605a396f2de61eb` (off main `0fb8cd5`), nothing pushed. Brief:
`.test-work/click-explore-20261126/BATCH.md` on main (not copied here). It addresses
CURRENT_STATE open work 0: content behind a click (Juice Shop's product-review dialog) was
invisible to discovery and to the stored XSS read-back.

## What changed (off by default; `harness/config.yaml` defaults unchanged in effect)
| Item | Config key | Code |
|---|---|---|
| Click exploration | `driver_capture.click_explore: false` (+ `max_clicks_per_view` 8, `max_clicks` 60, `click_seconds` 120); needs `enabled` and `spa_navigation` | `spa_navigation.py`: `CLICK_CANDIDATES_JS`, `click_refusal`/`click_hints`/`click_label`, `ClickBudget`, `_explore_clicks`, `crawl_views(clicks_per_view=, max_clicks=, click_seconds=)`; new `SpaCrawlResult` fields `clicks`, `click_skips`, `click_calls`, `click_stopped_by`. `browser_driver.py`: `_IdentityRouter.click_hold` + `_hold_click_write`, `_click_control`, `_end_click`, adapter methods `click_candidates/click/restore/end_click` in `crawl_spa`, `crawl_spa(clicks_per_view=, max_clicks=, click_seconds=)`. `engagement_builder._click_kwargs` passes them only when on; `spa_views[]` gains `clicks`, `click_skips`, `click_stopped_by` only when on. |
| Click recipes in the route map | (same switch) | `client_routes.ClientRouteMap.api_clicks` ("GET path" -> [[kind, document, route, selector]]), `add_click`, `clicks_for_api`; persisted in `to_dict` only when non-empty (old snapshots unchanged), merged, read back. `engagement_builder._collect_spa_routes` feeds `crawl.click_calls`. |
| Stored XSS read-back replays a recipe | (same switch; nothing recorded otherwise) | `PlaywrightDriver.visit(clicks=...)` (at most 4 selectors; `obs.clicks`, `obs.held_writes`). `stored_xss_validator._client_click_views`, `_confirm_in_views` loads up to `_MAX_CLICK_VIEWS` (2) recipes per payload shape besides the plain views, `_browser_confirm(clicks=)`. A recipe click that cannot be made is "check manually" (inconclusive), never a negative. |
| Passive-only | `driver_capture.click_explore` added to `config_schema._PASSIVE_FORCE_OFF_KNOBS` | |

Behaviour:
- Candidates: buttons, `input[type=button]`, roles button/tab/menuitem/option/switch/treeitem,
  inline `onclick`, `summary`, anchors without a real href (`#`, `javascript:`), and li/tr/
  mat-card/[tabindex] styled `cursor: pointer`. Links and routerLink-style elements are views
  (the walk follows them) and are skipped. Hidden or zero-size elements are skipped. DOM order;
  selector = unique id, else a unique `data-testid`/`aria-label`/`name`/`title`, else an
  nth-of-type path from the nearest unique-id ancestor.
- Never clicked: inside any `<form>`, disabled, type submit/reset/file/image, or a whole-word
  denylist hit on text, aria-label, title, id, class, name, data-*, onclick, href (camelCase and
  `-_./` split): delete, remove, erase, destroy, logout/sign out, unsubscribe, pay, checkout,
  place order, buy, submit, send, post, save, apply, confirm, reset, clear, empty, cancel, add,
  add to basket, create, upload, download, like, vote, follow, subscribe, update, rate, report,
  ... (full list `spa_navigation._CLICK_DENY`). The element the selector names is described and
  checked again right before each click (crawl and recipe replay).
- One try per control per crawl (same selector and label on a later view is not clicked again).
- After a click that changed anything (calls, URL, new text, a dialog/overlay, DOM size, a
  popup, or the click failed) the view is reloaded as a new document (`open_fresh`). If it
  cannot be put back, the view's remaining candidates are skipped. Popups a click opens are
  closed.
- Requests: every request goes through the crawl's `_IdentityRouter`. Reads take the normal
  route (scope, same-origin credentials, gate for nothing, budget). Writes, from the click until
  the view is put back, are checked (scope/same-origin, then `gate.authorize`) for the record
  and then **held: dropped, never sent, whatever the gate says**. No budget or mutating ceiling
  is spent on them. Each click entry lists `held` and `blocked` with the reason.
- Click calls join `exchanges` (note `... (click on <selector>)`) and so discovery, but NOT
  `view_calls`: a call only a click makes is no evidence the plain view renders that API, so
  `views_for_api` is not polluted (the read-back would otherwise load the view without the click
  and report a false negative).

## Deviations from the brief (code wins; stated plainly)
1. **Writes during clicks are stricter than "exactly as the SPA crawl does today".** Today a
   page-load write the gate allows is sent. A click-fired write is never sent even with
   `allow_mutating_replay` on. This follows requirement 2 (no state-changing clicks), and a
   test pins both sides. Not done: recording a held click write as a capture template (as
   file uploads do).
2. A write fired more than `wait_ms` after a click but after the view was put back (and
   `end_click` cleared the hold) takes the normal crawl path, i.e. today's gate decision. The
   hold covers the click, its settle time, and the reload.
3. "Elements with click handlers" means inline `onclick` or a pointer cursor. A listener
   added with addEventListener on an element without either is invisible from the DOM. This is
   the same limit as noted for routerLink in the crawl-loop handoff.
4. "Newly rendered content" is recorded as counts (`revealed` visible characters, `dialog`),
   not text, to keep values out of results and the persisted map.

## Stored XSS read-back: wired
Yes (it was small). A test (`BuildEngagementClicksTest.test_the_read_back_replays_the_click_recipe`)
runs the full path: a real crawl with clicks builds the map, the registry dispatches
stored_xss, the validator re-reads the JSON API, loads `/#/products`, clicks the recorded
product card, and the dialog runs the payload, so the result is confirmed. The control is a
crawl without clicks: no view for the API, so not_confirmed.

## Tests
New `harness/test_click_explore.py`, 25 tests, each behaviour with a negative control:
- `ClickRefusalTest` (4): the denylist on text/aria/id/class/name/onclick/data; forms, submit,
  reset, disabled; neutral labels allowed.
- `CrawlViewsClicksTest` (4, fake adapter): recording, restore only after a change, one try per
  control across views; per-view, per-crawl and time budgets; the default (0) never asks.
- `ClickRecipeMapTest` (2): keep by route, value-free, persist/merge; other origin, excluded
  view, and an unchanged snapshot without clicks.
- `ClickConfigTest` (1): default off, passive-only knob, `_click_kwargs`.
- `PlaywrightClickCrawlTest` (10, real Chromium, 127.0.0.1 fixture + a 127.0.0.2 off-scope
  server): the dialog fetch to `/api/reviews` is recorded with the option on and not off. The
  identity reaches the server on the click's read. Delete, Logout and the in-form button get
  0 hits, while "Open details" gets 1. The off-scope GET is blocked (0 hits; control: in scope,
  1 hit). The click POST is held with a permissive gate (0 hits; control: the page-load POST is
  sent) and with a closed gate (gate denied). A recipe replay through `visit(clicks=)` clicks
  and holds its write; a recipe naming Delete is refused. Budgets stop clicking (max_clicks,
  click_seconds 0) and the crawl still completes; control: per-view 3.
- `BuildEngagementClicksTest` (4): through build_engagement, the click capture becomes an
  endpoint and the recipe is in `state.client_routes`; control: switch off. Stored XSS
  confirmed via the recipe; control: not confirmed without one.

Commands (worktree root, `/home/user/.venv-agb/bin/python`, `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`):
- `python -m unittest harness.test_click_explore`: 25 OK (about 85 s).
- `python -m unittest harness.test_orchestrator_precondition`: 74 OK.
- `python -m harness.suite smoke`: exit 0, 182 OK.
- Every harness test module that imports browser_driver, spa_navigation, client_routes,
  stored_xss_validator, driver_capture or engagement_builder, plus test_pipeline_gate, under
  (102 modules), under `python -m pytest -q -p no:cacheprovider <modules>`: 1885 passed,
  50 failed, 1 error. Every one is a pytest incompatibility, not a test failure: all 50 are
  in `test_leg_live_verification.py` (`'TestCaseFunction' object has no attribute
  'failures'`), and the error is `test_tested_parameters.py::tested_inputs` (a helper pytest
  takes for a test: "fixture 'finding' not found"). Those two modules under unittest
  (`python -m unittest harness.test_leg_live_verification harness.test_tested_parameters`):
  63 OK.
- `python -m harness.suite full`: NOT run (the orchestrator runs it after merging).
- `git diff --check` clean.

## Unverified
- No live run (no Juice Shop here). Whether Juice Shop's product card is a candidate (it should
  be: a `mat-card`/button with a pointer cursor and an aria-label like "Click for more
  information about the product") and whether its review dialog's `GET /rest/products/:id/reviews`
  is recorded is unverified. Its "Add to Basket" button is denied by design.
- Java not touched. No CDP-browser run (`cdp_endpoint`).

## Next steps
1. Live check on an owned Juice Shop (:3002) with `driver_capture: {enabled, spa_navigation,
   click_explore: true}` in config.local.yaml. Confirm that `spa_views[].clicks` has the product
   dialog and that a review XSS planted via `PUT /rest/products/:id/reviews` is confirmed by the
   recipe.
2. Owner: should a held click write be kept as a capture template (as file uploads are), so
   the write legs get its real shape? Today it is only listed.
3. Owner: the denylist is conservative (`add`, `update`, `like`, `rate`, `report` included).
   Loosen it if the live run shows lost coverage.
4. The route feed (`engagement.recrawl`) does not click; recrawl rounds re-GET routes only.
