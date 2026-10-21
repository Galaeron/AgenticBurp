# Owner runbook — the four live/owner priorities

The offline improvement loop is exhausted; everything left needs a live
environment or a human decision. This runbook makes each of the four priorities
turnkey. Each has an **offline-verifiable instrument** (built + tested in
`testing/`, runs in `python -m harness.suite full`) that your live environment
then drives. Nothing here changes committed safe defaults; live scope/toggles stay
in the git-ignored `harness/config.local.yaml`.

Run everything from the repo root with the isolated interpreter
`.venv-rationalisation/Scripts/python.exe` (written below as `PY`).

**Do them in order** — Priority 1 gates the rest: the containment/build/evidence
work is only worth finishing once the efficacy numbers exist.

---

## Priority 1 — Prove it works (efficacy) · needs Ollama

**Why first:** no credibility claim is meaningful until there are clean,
repeatable, false-confirmation-free numbers on independent objectives.

**Instruments:**
- `testing/run_web_objective_smoke.py` — one authorized attempt → an `attempt.json`.
- `testing/run_web_objective_efficacy.py` — orchestrates N attempts per case +
  fixed controls, assembles the run record, and scores it via
  `testing/web_objective_benchmark.py`.

**Steps:**
1. `ollama serve` (model `qwen3:8b` pulled). Grab **fresh, unsolved** lab URLs.
2. One-off single attempt (sanity):
   ```
   PY testing/run_web_objective_smoke.py <FRESH_LAB_URL> \
      --output reviews/<date>/web-objective/clean-1 --run-id clean-1
   ```
3. Full efficacy pass (3 attempts/case from the manifest + fixed controls):
   ```
   PY testing/run_web_objective_efficacy.py \
      --manifest testing/web-objective-benchmark/manifest.json \
      --targets targets.json --oracle oracle.json \
      --output-dir reviews/<date>/web-objective/efficacy
   ```
   - `targets.json` = `{ "<case_id>": "<fresh_lab_url>", ... }`
   - `oracle.json` = `{ "<case_id>": [true,false,true], ... }` — **your** out-of-band
     lab-solved verdict per attempt. The runner never treats model output as proof;
     a lab-solved-but-timed-out attempt is excluded, not counted (attempt-4 rule).

**Done when:** `scorecard.json` shows `eligible: true` with three first-attempt
successes and **zero** fixed-control false confirmations, from one checkout/config
(the orchestrator refuses a run whose attempts span multiple checkouts/config
hashes). The A–G ablation (PR-B) and the reasoning-class recall (BM-3) are the
follow-on live measurements once this baseline is trustworthy.

---

## Priority 2 — Prove it's contained (egress) · needs Docker

**Why:** NC-O1 — egress *metadata* is not network confinement. Prove a confined
tool sends zero packets off-scope.

**Instrument:** `testing/egress_probe.py` — a control listener + `assert_contained()`.

**Steps:**
1. Start the sentinel on an address the confined tool must NOT reach:
   ```
   PY testing/egress_probe.py --host 0.0.0.0 --port 9999 --duration 120
   ```
2. Within that window, run sqlmap in the pinned container with egress cut
   (`--network none`, or a per-run egress proxy allowing only the target), against
   your owned target — e.g. image `harness/sqlmap:1.10.9` (your `config.local.yaml`
   already pins it).
3. Read the probe's JSON: `contained: true` and `connection_count: 0` = pass.

**Done when:** the sentinel logs zero connections while the container ran a real
job. NC-O3 (two-origin browser credential-forwarding) and NC-O2 (connect-time
address pinning; `security.pin_connect_address` in `config.local.yaml`, verified
live) are the sibling proofs.

---

## Priority 3 — Ship it (build/release) · needs JDK/Gradle + Burp

**Why:** SC-6/SC-14/NC-O5 — the artifact must boot outside the checkout and build
reproducibly.

**Instrument:** `testing/release_doctor.py` — tiered readiness (executable /
dependency / file / service, plus the runtime-only tiers surfaced honestly).

**Steps:**
1. Environment readiness (add `--runtime` to also probe Ollama/API):
   ```
   PY testing/release_doctor.py --runtime
   ```
   Fix any **required** failure (harness deps + shipped files). Optional tools
   (docker/java/gradlew/playwright) are reported, not fatal.
2. Build the JAR under JDK 17 (`burp-extension/`, `gradle shadowJar`) and load it in
   a supported Burp version — the live half (OWNER/LIVE, per P1-5).
3. Build the wheel and confirm it imports from an unrelated directory in a fresh
   venv (SC-6's real acceptance — a wheel-*building* job alone does not satisfy it).

**Done when:** `release_doctor` reports `ready: true`, the JAR builds in CI, and a
fresh-venv wheel install imports `harness.server` outside the checkout.

---

## Priority 4 — Evidence base (independent corpus) · people + data

**Why:** PR-D/BP-5C — model repeats can't replace independent cases; a frozen,
leakage-free holdout is mandatory *before* any confirmatory validation.

**Instrument:** `testing/corpus_holdout.py` — frozen, clustered train/holdout split
with a `verify_split` leakage guard.

**Steps:**
1. Author independent labeled cases (JSON list; each needs an `id` and a grouping
   key — `pair_id` for vuln/fixed twins, else `host`/`app`/`cluster`).
2. Freeze the split BEFORE any tuning:
   ```
   PY testing/corpus_holdout.py --cases cases.json --seed <frozen-seed> \
      --holdout-fraction 0.3 --out split.json
   ```
   Same seed → identical split; twins never straddle the boundary; the holdout is
   flagged untouched.
3. Tune/threshold only on `train`; report final numbers on the untouched `holdout`.

**Done when:** a frozen `split.json` exists with `verify_split` passing (no
leakage), and the curated holdout stays untouched through tuning. PR-E (the
design-partner pilot measuring analyst-minutes-saved) is the non-code companion.

---

## Config toggles cheat-sheet

Committed `harness/config.yaml` ships safe (`validators.active_enabled: false`,
`allow_mutating_replay: false`, `oracle.enabled: false`,
`autonomous_discovery.enabled: false`, `coordinator.cloud_*: false`,
`server.allowed_hosts: []`). Put every live flip in `harness/config.local.yaml`
(git-ignored) — which you already maintain. Per task:

| Task | Overlay flips (in `config.local.yaml`, or armed at runtime via `POST /settings`) |
|------|-------------------------------------------------|
| Efficacy runs | `server.allowed_hosts`, `validators.active_enabled: true` (the smoke runner sets active mode + target scope in-memory) |
| Containment | as above + sqlmap `container_image` (already set) |
| Build/release | none (readiness only) |
| Evidence base | none (offline data work) |

Never commit a flipped default or `config.local.yaml` itself.
