# Budget and evidence slice — handoff (2026-11-03)

Source evidence: the 8h juice-shop run in
`.claude/worktrees/i16-persist-77da6a/.test-work/juice-shop-8h-20261103/YIELD_ANALYSIS.md`.
Its DB was read only through a `mode=ro` URI. No answer keys were read, and no config defaults changed.

## What changed

### 1. SPA soft-404 pruning in discovery (commit `bcc9199`)

Files: `harness/api_surface_discovery.py`, `harness/test_discovery_spa_wildcards.py`

- **Root cause.** Calibration already worked: only 52 `__harness_missing_` controls were sent. The waste was that the wordlist kept enumerating namespaces that only ever returned the catch-all, about 3.4k probes each under `/admin/`, `/v1/` and `/internal/`, per role sweep.
- **Fingerprint.** Calibration now records a soft-404 signature: status, main content type, body hash and length. The length is raw, with only the echoed path removed and digits kept, so a hex nonce does not change it. When the two random controls hash differently, the match falls back to length.
- **Matching.** `_soft404_match` requires the same status and content type. `_prefix_wildcard` signatures now include the content type too, so a JSON 200 is never collapsed into an HTML shell.
- **Pruning.** After `soft404_prune_after` matches (a constructor kwarg, default 16; not config.yaml) under an ancestor prefix that has no found route, the prefix is marked dead. Unreferenced candidates under it are then skipped.
  - Referenced candidates (seeds, routes the app names) are still probed.
  - A found route un-deads its ancestors.
- **Reporting.** The result reports `soft404_pruned_prefixes` and `soft404_candidates_pruned`, plus an errors note.
- **Test.** A real threaded HTTP fixture serves a catch-all HTML shell with a nonce, plus real JSON routes. The pruned sweep keeps every referenced route and prunes `/v1/` in at most 16 requests. Total requests drop from 1199 to 614.
- **Trade-off, documented in the test.** A late-alphabet real route in an unreferenced namespace (`/v1/items`) is now missed.

### 2. sqlmap re-runs and the lost verdict (commit `d70aba2`)

Files: `harness/execution_registry.py`, `harness/validators/sqlmap.py`, plus tests in `test_execution_registry.py` and `test_sqlmap_validator.py`

- **Collapse.** New `TOOL_SCAN_KEYED = {"sqlmap"}`. Unless the finding is `parameter_only`, the execution key drops the named parameter, because sqlmap without `-p` tests every parameter anyway.
  - Identity (R03) and workflow state are still part of the key.
  - `parameter_only` runs keep `(location, name, "only")`.
  - Other shape-keyed validators (ssti and the rest) still split on the parameter.
  - Findings naming path `id`, query `d` or nothing now get one sqlmap run plus "covered by" copies.
- **Verdict.** `verdict_lines(output)` returns the last 6 distinct `[WARNING]`/`[CRITICAL]`/`[ERROR]`/"injectable"/"is vulnerable" lines, without timestamps.
  - Non-confirmed results put a `sqlmap verdict:` block before the full log, so the ledger's `evidence[:1000]` cut keeps it. The cut is at `orchestrator_confirm.py` around line 721 and `orchestrator_chain.py` around lines 1406 and 1423.
  - The same lines become `ValidationResult.limitation`.
  - `raw_output` stays the untouched log.
  - Confirmed results are unchanged.

### 3. Proof rows keep the validator's reason (commit `d70aba2`)

Files: `harness/validators/base.py`, `harness/orchestrator_confirm.py`, `harness/test_evidence.py`

- **New field.** `ValidationResult.limitation: str = ""` is a new trailing default field.
- **Formatting.** `proof_limitation_of(result)` returns `"<status>[ [control]]: <limitation | summary | first evidence line>"`, capped at 500 chars. It returns `""` for confirmed results.
- **Wiring.** `_persist_confirmation_proof` now passes this as `limitation=`, from both `_validate_findings` and `_coverage_proof`. The crashed-validator proof passes its summary.
- **Result.** `ProofRecord.from_validation_result` already appends the legacy note, so a row now reads `"not_confirmed: sqlmap: [CRITICAL] all tested parameters ...; legacy/unstructured result: ..."`.
- **Not changed.** The `orchestrator_chain.py` proof call site is confirmed-only.

### 4. ffuf inside pipeline runs (added scope, from the parent session; this commit)

Files:
- `harness/api_surface_discovery.py`, `harness/ffuf_runner.py`, `harness/tool_proxy.py`
- `harness/js_endpoint_extractor.py`
- `harness/role_crawl.py`, `harness/engagement_builder.py`, `harness/orchestrator_chain.py`
- `harness/config.yaml`, `harness/config_schema.py`
- tests: `test_discovery_ffuf_in_run.py` (new), `test_js_endpoint_extractor.py`, `test_config_schema.py`

**Opt-in key.** `engagement.discovery_ffuf: false` is new and off by default, so behaviour is unchanged.
- It is listed in the passive-only force-off knobs and in the safe-default guard test.
- `orchestrator_chain` passes it to `build_engagement`, then `crawl_roles`, then `SurfaceDiscovery(ffuf_in_runs=...)`, and only when it is enabled.

**Charging.** In a run, ffuf is pointed at a loopback `ToolProxy`, the same I05 mechanism sqlmap uses.
- Every ffuf request is replayed through the run transport, so the count is exact, not an estimate.
- Each request spends one run budget unit and passes the run's scope, gate and cancellation.
- The container gets an enforced egress policy (`host.docker.internal` only) through the existing `ToolBroker` in `ffuf_runner.run_sync`.

**Share cap.** ffuf gets at most four fifths of the discovery phase budget that remains, through the new `ToolProxy(max_forwarded=...)`.
- Past the cap the proxy answers 404 and sends nothing. ffuf filters 404s and finishes with the hits it has, instead of being killed mid-scan.
- ffuf's requests count as discovery probes.

**Python sweep after ffuf.** The proxy records the paths it actually sent (`forwarded_paths`). The Python sweep skips unreferenced guesses ffuf already sent, so it only covers what ffuf can't:
- prefixes derived from the app;
- deep nesting under found routes;
- query and Allow mining;
- spec probing;
- anything past ffuf's share.

ffuf hits are still re-checked once by the harness's own `_check`.

**Soft-404 agreement.** Calibration now also records the catch-all's raw byte length when both random controls agree. It is passed to ffuf as `-fs <bytes>` next to `-ac`.
- The harness re-check applies its own fingerprint to every ffuf hit.
- Hits the harness calls soft-404 are dropped and counted in `ffuf_soft404_disagreements`, with an errors note.

**JS routes.** These already existed: `js_endpoint_extractor.py` regex-mines quoted `/...` literals from the bundles the crawler fetched, with no execution, and role_crawl seeds them into discovery.
- The gap filled here: slash-less `"api/..."` and `"rest/..."` literals, as in `this.hostServer + "api/Quantitys"`.

**Tests.** A fake ffuf, swapped in at `subprocess.Popen` so the real runner, broker and `tool_runner.run` path runs, against a real SPA catch-all fixture. They cover:
- budget accounting (`budget.used == probes_sent`);
- the share cap;
- no re-sends;
- `-fs` from calibration;
- the disagreement counter;
- default off;
- forwarding-loss fault injection.

## Gates

`gates.sh` in this folder writes `gates-summary.txt`, with exit codes and counts only. It runs on venv 3.12 and system 3.14:

- `harness.test_orchestrator_precondition`
- the 8 touched or adjacent test modules
- `harness.suite smoke`
- `git diff --check`

For the ffuf slice, run it with `GATE_SUMMARY=gates-ffuf.txt` and `GATE_TESTS` set to the 24 discovery, tool, config, crawl and run-wiring modules listed in the commit. Results go to `gates-ffuf.txt`.

`gates-ffuf.txt` records the outcome:
- precondition, smoke and diff-check were green on both interpreters.
- The touched run had 2 failures, both in `test_sensitive_file_confirmation`.
  - Cause: its catch-all fixture shell relied on a constant-length body slipping past calibration, and bcc9199's soft-404 length fallback now catches it.
  - Fix: the fixture shell's length now also varies per response, so it still models a shell that defeats calibration.
  - After the fix that module passes on both interpreters: 11 OK.

## Owner questions

### ffuf / wordlist (added scope)

- **A. Turn on `engagement.discovery_ffuf` for local live runs?** It stays off in the committed config. With it on, each role sweep spends up to ~4/5 of its discovery phase budget on ffuf through the proxy. That is faster wall-clock, but not fewer requests: ffuf cannot prune soft-404 branches the way the Python sweep now does.
- **B. ANSWERED (yes) and done in the "second ffuf wordlist" commit.**
  - **Pin.** The pin is SecLists commit `0c618cfc28d1e68811b95c61cc9ab05bc10b0a02` (2026-06-21, the last change to common.txt; all four lists are at their latest there). It covers:
    - `Discovery/Web-Content/common.txt`
    - `api/api-endpoints.txt`
    - `api/api-endpoints-res.txt`
    - `api/objects.txt`
    - The case variants and vendor-specific api lists are left out.
  - **Lock and files.** The sha256 and size of each file are in `tools/ffuf-seclists.lock.json`. The sources live in `tools/seclists/`. The merged, deduplicated list is `tools/ffuf-wordlist-seclists.txt`: 13,947 lines, with a leading `/` stripped, and it is a pure function of the sources.
  - **Fetching.** `tools/fetch_seclists.py` fetches only `raw.githubusercontent.com/danielmiessler/SecLists/<sha>/...`. In non-`--pin` mode it refuses on any hash mismatch.
  - **Hash check.** The first pin was checked independently: the git blob SHA of each local file equals the blob SHA GitHub's contents API reports at that commit.
  - **Verification.** `python -m harness.supply_chain wordlists` verifies offline: the lock pins a full SHA, each source sha256 matches, and the merged list hash matches and equals the re-derived merge. CI now runs it in the dependency-audit job.
  - **Line endings.** `.gitattributes` marks the files `-text`, so autocrlf cannot change the hashes.
  - **Image.** It COPYs the merged list to `/wordlist-seclists.txt`.
  - **Config.** `engagement.discovery_ffuf_wordlist: harness` is the default and maps to `/wordlist.txt`. `seclists` selects the second list. It is only read when `discovery_ffuf` is on, and unknown names are refused in the `SurfaceDiscovery` constructor.
  - **Size and timeout.** About 14k lines is close to the harness list's 12,950. ffuf's per-run share cap and its 180 s container timeout still apply, so on a slow target a run may time out before the list ends. Watch this in the live run.
- **B (original question). Wordlist.** `tools/gen_ffuf_wordlist.py` bakes in 12,950 lines, all from the harness's own vocabulary: prefixes × nouns, `/1`, nested collections, actions and sensitive files, plus about 50 curated common-web paths. It is not small, but it is not a well-known list either.
  - Proposal: add a pinned subset of SecLists, for example `Discovery/Web-Content/common.txt` plus `api/api-endpoints.txt` and `api/objects.txt`.
  - Pin it to a SecLists commit SHA, with a sha256 per file recorded beside `ffuf.Dockerfile`, checked by `harness.supply_chain`.
  - COPY it into the image as a second wordlist, so runs can pick it.
  - Nothing was downloaded or vendored here. Which lists, and what size cap?
- **C. Image pinning.** The ffuf image is built locally, but its base images are still not digest-pinned (the P3-2 OWNER/LIVE note in `tools/ffuf.Dockerfile`). Pin them before enabling ffuf in runs, and re-run `python -m harness.supply_chain images --require-digest`.
- **D. Container to proxy reachability.** The proxy binds 127.0.0.1 on the host. The container reaches it as `host.docker.internal`, which works on Docker Desktop and is the same assumption sqlmap's proxied container run makes. VERIFIED after B: a real Docker 29.8.2 run of the rebuilt image, through the proxy, against the owned SPA fixture. Every request was charged (budget_used == probes_sent, target GETs <= budget) for both wordlists; see `live-ffuf-proxy.txt` and `live_ffuf_proxy_check.py`. At a 3000-probe budget, ffuf's ~1652-request share ends partway through either alphabetical list. The SecLists run therefore never reached the fixture's `/api/items`, which is the truncation trade-off. A target with real juice-shop budgets still needs the live run.
- **E. A budget stop loses ffuf's partial hits.** When the run budget or a cancel stops ffuf mid-scan, its partial JSON is discarded as an error. The paths it sent are still marked covered. Should partial hits be salvaged?

### Earlier items

1. **Per-role discovery sweeps each get the full budget.** role_crawl runs one discovery per distinct role, which is about a 3× multiplier on 19,439 probes. Should later sweeps reuse the first sweep's dead-prefix and soft-404 state, or share one budget? This was not changed here.
2. **Should sqlmap collapse across identities?** The R03 invariant keeps identity in the key, so the same request under alice and bob still runs twice. Some of the run's captcha re-runs came from different source captures, possibly different identities. Is SQLi identity-dependent enough to keep this?
3. **Pruning threshold.** The value 16 is a kwarg, not config. Pruning can miss a real route late in the wordlist under an unreferenced namespace. Expose it in config.yaml (default unchanged), or keep it internal?
4. **Account creation. ANSWERED ("Light sqlmap, capped") and done in its own commit.**
   - **What counts as a create** (`create_endpoint_reason` in `validators/sqlmap.py`):
     - a POST/PUT whose base capture answered 201;
     - a POST to a non-id path that answered with a new object id (top-level or `data.id`), excluding responses that carry a token, which are logins;
     - a POST to a plural collection path such as `/api/Users` or `/api/BasketItems`.
     - A registration counts even though its body has a password. The juice-shop `POST /api/Users` is auth-shaped, so an auth-shape exclusion would have missed it.
   - **The light scan:**
     - `--level 1 --risk 1 --technique BE`, whatever the configured level/risk;
     - a hard cap of `validators.sqlmap.create_endpoint_max_requests` requests, default 200 in config.yaml;
     - the cap is enforced by the run's ToolProxy through `max_forwarded` plus the new `cap_stops`. At the cap nothing more is sent, the proxy stop ends the container, and the verdict is "incomplete", never a negative.
   - **Outside a run:** a create endpoint is not scanned at all. The result is skipped with that reason, because nothing could enforce the cap.
   - **Proof reason:** the limitation and the evidence lead with `light sqlmap (create endpoint: <why>): level 1, risk 1, techniques BE, at most N requests; M request(s) sent[, cap reached]`.
   - **Tests:** `test_sqlmap_create_endpoints.py` covers:
     - detection, with negatives for GET, update, login and action endpoints;
     - the cap bounding a 40-request stand-in tool at 5;
     - level/risk/technique;
     - the proof reason;
     - an under-cap scan;
     - no run means no scan;
     - an update endpoint keeping the full scan;
     - fault injection: a proxy without the cap lets all 20 requests through.
5. **Other validators still lose their tails.** The ledger `[:1000]` head-cut remains for every validator except sqlmap's verdict block. Should we store a head and a tail, or a per-validator digest?
6. **Confirm-path fallback.** The fallback `RunContext` has no execution registry, so the collapse does not apply there. Is that intended?

## Not done / not verified

- No live run against juice-shop to measure the probe and request savings end to end. The numbers come from the fixture.
- ffuf in runs: the unit tests use a stand-in ffuf. The real image and proxy path was checked once against the owned fixture (live-ffuf-proxy.txt), not against juice-shop.
- Nothing pushed.
