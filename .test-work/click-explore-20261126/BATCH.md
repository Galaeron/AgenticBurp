# Batch: click-driven SPA exploration (2026-11-26)

## Problem
CURRENT_STATE open work 0: Juice Shop product reviews render only in a dialog that a click
opens, and no crawl records it. The SPA crawl (`harness/spa_navigation.py` `crawl_views`,
`PlaywrightDriver.crawl_spa` in `harness/browser_driver.py`, `driver_capture.spa_navigation`)
follows routes, not clicks, so content behind a click is invisible to discovery and to stored
XSS read-back.

## Idea (from ARTEX, not its code)
ARTEX lets a worker drive a browser by clicking element references from a page snapshot, and its
built-in intercept rules refuse deletion-style endpoints. Here the clicker is deterministic and
bounded, not model-driven.

## Requirements
1. New `driver_capture` option (off by default) that, on each crawled view, clicks bounded
   candidates: buttons, `[role=button]`, elements with click handlers, list items that open
   detail. Budgets: clicks per view, clicks per run, time. Deterministic order.
2. Never click destructive or state-changing controls: a label/attribute denylist (delete,
   remove, erase, destroy, logout/sign out, unsubscribe, pay, checkout, place order, submit,
   reset, clear basket...) matched case-insensitively on text, aria-label, title, id/class
   hints. Never submit forms (forms have their own path). Restore the view after each click.
3. Every request a click fires goes through the existing `_IdentityRouter` and the run's gate:
   off-scope hosts blocked, mutating methods held/refused exactly as the SPA crawl does today.
   Confirm this by test, not by reading.
4. Record what clicks reveal: new XHR captures feed discovery like other browser XHRs; newly
   rendered content and the click recipe (view + stable selector) are recorded in the route map
   so a later read-back can reproduce "open view, click element". Wire the stored XSS read-back
   to use a recipe only if it is small; otherwise leave it as the HANDOFF's next step.
5. Add the option to `config_schema._PASSIVE_FORCE_OFF_KNOBS` (clicks send traffic).

## Tests (real Chromium against a 127.0.0.1 fixture SPA, each with a negative control)
- A dialog that opens on click and fetches `/api/reviews`: recorded with the option on, not off.
- A "Delete" button and a "Logout" link are never clicked (fixture counts hits: 0).
- A click that fires an off-scope request is blocked; one that fires a POST is held/refused.
- Budgets stop clicking; the run still completes.
