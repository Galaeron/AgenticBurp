# Improvement backlog: open items

This file lists the items still open (`[ ]`, `[~]` or `[!]`): each one's heading and its
metadata line, as they are in the archive. It is **generated**; do not edit it by hand
(`python tools/backlog_index.py --write`; a test fails when it drifts, or passes 30,000
characters). The full text of every item, open or closed, with its evidence, acceptance
criteria and `Result:` lines, is in
[docs/IMPROVEMENT_BACKLOG_ARCHIVE.md](docs/IMPROVEMENT_BACKLOG_ARCHIVE.md), together with
the 2026-09 to 2026-11 dispatch notes that used to open this file. IDs are stable.

To read an item, grep its heading in the archive and read that section only, for example
`grep -n "### \[ \] P1-3" docs/IMPROVEMENT_BACKLOG_ARCHIVE.md`. To close one, edit it in the
archive (flip the checkbox, add the `Result:` line), then run `--write`. Where the rules
below say "under the item" or "this file", they mean the item in the archive.

## How to use it

1. Work top-down: finish all `P0` items before `P1`, etc. Within a tier, respect
   `Depends on`.
2. Pick the first item whose checkbox is `[ ]` and whose dependencies are all `[x]`.
3. Implement it on a focused branch/commit. Honour the project's non-negotiables:
   - Keep `harness/config.yaml` at **safe defaults**; new capabilities ship OFF.
     Live toggles go in the git-ignored `config.local.yaml`.
   - Every new pipeline behavior needs a **caller-level test AND a negative
     control** (AGENTS.md). Do not delete `test_pipeline_gate.py` or its
     defect-injection controls.
   - Never read `*ANSWER_KEY*` or a blind target's `app.py`.
   - Run `python -m harness.suite full` (from repo root, isolated venv) before
     marking an item done; label any accuracy/recall claim **owner-reported**
     unless produced by a real-model/blind run in the same session.
4. When done, flip the checkbox to `[x]`, add a one-line `Result:` under the item
   (commit SHA + what was verified, with the VERIFIED/SUPPORTED/CLAIMED tag), and
   update `CURRENT_STATE.md`.
5. If an item is partially done, leave it `[ ]` and record progress in `Result:`.

Evidence tags: **VERIFIED** (ran/read directly), **SUPPORTED**, **CLAIMED**,
**INFERRED**. Do not promote a tag without new evidence.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked (say why).

---

55 open items.

## P1 — Product blockers (before regular practitioner use)

### [ ] P1-3 — Unify the evaluation layers into one driver
- **Domain:** Evaluation / Maintainability · **Effort:** M · **Depends on:** P0-3

### [ ] P1-5 — Verify and document the Burp UX end-to-end
- **Domain:** UX / DX · **Effort:** M · **Depends on:** none

## P2 — Differentiators (create competitive advantage)

### [ ] P2-3 — Surface the reproduction recipe in Burp + export (SARIF/markdown)
- **Domain:** UX / Trust · **Effort:** M · **Depends on:** P0-1, P1-5

## P3 — Scale / commercialization (only once adoption + efficacy exist)

### [ ] P3-2 — Supply-chain hardening (lockfile audit, SBOM, pinned tool/image digests)
- **Domain:** Security / Enterprise · **Effort:** M · **Depends on:** none

### [ ] P3-3 — Team mode groundwork (shared findings DB, RBAC, audit log, resume)
- **Domain:** Product / Enterprise · **Effort:** XL · **Depends on:** P0-1, P3-1

## Follow-up recommendations — 2026-09-20 (after the paused item)

### [~] P1-10 — Address-bound connect-time resolution pin (DNS-rebinding enforcement)
- **Domain:** Security · **Effort:** M · **Depends on:** P1-9 [x]

## External-review borrow batch -- 2026-09-22 (ER-1..ER-5)

### [ ] ER-3 -- Time-based blind-injection fallback confirmation leg (provisional tier)  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** Efficacy / Coverage - **Effort:** L - **Depends on:** P2-2 [ ] (new-validator freeze) - **Mode:** LOOP-BUILD (gated)

### [ ] ER-5 -- Per-class methodology priming for specialist agents  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** AI / Efficacy - **Effort:** M - **Depends on:** P2-2 [ ] (new-surface freeze) - **Mode:** LOOP-BUILD (gated)

## Principal review batch — 2026-09-24 (PR-*)

### [~] PR-10 — Policy-bound browser adapter (offline half done; live half OWNER) (R01)
- **Domain:** Security / execution - **Effort:** L - **Depends on:** transport/capability contract - **Mode:** LOOP (offline half done); OWNER/LIVE (two-origin verification)

### [~] PR-11 — External-tool egress boundary (offline half done; live half OWNER) (R02)
- **Domain:** Security / reliability - **Effort:** L - **Depends on:** transport/capability contract - **Mode:** LOOP (offline half done); OWNER/LIVE (container egress verification)

### [~] PR-13 — Corpus ground-truth contamination audit + sanitized benchmark corpora (offline half done `2d66c5e`; OWNER re-measure) (new, from PR-2)
- **Domain:** Evaluation integrity - **Effort:** M - **Depends on:** none - **Mode:** LOOP (audit + sanitize offline); OWNER re-run to re-measure

### [ ] PR-A — Secure local Burp<->API token pairing (R04 / RB-1b)  — **Mode: OWNER/LIVE (skip)**
- Needs JDK/Burp build. Server writes an ephemeral token to `.harness_token.lock`; `HarnessClient.java:63`
  reads only `HARNESS_BEARER_TOKEN` env (no lockfile reader / setter caller). Finish pairing/refresh,
  token-file perms, actionable 401 UI. Do not weaken API auth. Leave `[ ]` for the owner.

### [ ] PR-B — True A–G ablations (R07 / P2-2)  — **Mode: OWNER/LIVE (skip)**
- Needs real model/GPU. Real generalist (not `force_agents=['sqli']`), a no-model provider that
  RAISES on any inference, a genuinely stronger model for F, an interaction corpus for E,
  stage-level invocation assertions, predeclared noninferiority margins. Leave `[ ]`.

### [ ] PR-C — Reproducible Java build + release gate (R13)  — **Mode: OWNER/LIVE (skip)**
- Gradle wrapper/toolchain, PR Java build/tests, wheel/JAR install smoke, SBOM, checksummed release
  manifest, digest-pinned tool images. Verification needs a JDK. Leave `[ ]`.

### [ ] PR-D — Independent labeled corpus expansion (R15 / BP-5C)  — **Mode: OWNER/LIVE (skip)**
- Independent case authoring, clustered splits, frozen sampling/decision design, untouched curated
  holdout. Not automatable; mandatory before confirmatory live validation. Leave `[ ]`.

### [ ] PR-E — Evidence-workflow design-partner pilot (R16)  — **Mode: OWNER (skip)**
- Five practitioners, paired tasks, measure analyst minutes saved per accepted reproducible issue.
  Non-code. Leave `[ ]`.

## Re-review cycle-2 batch — 2026-09-24 (NC-*)

### [ ] NC-O1 — Prove tool egress containment (N02 / R02)  — **Mode: OWNER/LIVE (skip)**
- Seam only today: sqlmap caller passes `proxy_url=None`, `network="bridge"` → container keeps full
  egress, `allowed_hosts` inert. Stand up per-run proxy (or `--network none` + host alias); prove an
  off-scope listener receives zero packets. Needs Docker. Leave `[ ]`.

### [ ] NC-O2 — Connect-time address pinning (N03 / R03)  — **Mode: OWNER/LIVE (skip)**
- `run_context.py:64-75` states the scope "deliberately does not build" address pinning; PR-10's
  per-request browser checks inherit the same address-blind `ScopePolicy`. Build shared HTTP+browser
  address pinning, or a gated lab-mode; prove with a two-origin/DNS-rebinding test. Leave `[ ]`.

### [ ] NC-O3 — Two-origin browser credential-forwarding proof (R01 live)  — **Mode: OWNER/LIVE (skip)**
- Live proof that PR-10's adapter attaches credentials only to approved origins and forwards none to
  a second owned origin. Needs a browser engine + two owned origins. Leave `[ ]`.

### [ ] NC-O4 — Recall re-measure + independent corpus (PR-13 live / R15)  — **Mode: OWNER/LIVE (skip)**
- Quantify sanitized-vs-contaminated PixelMart recall inflation with a real model; BP-4/BP-5C
  independent labeled-case collection + holdout. Needs GPU/Ollama. Leave `[ ]`.

### [ ] NC-O5 — Java/API pairing + reproducible build gate (R04 / R13)  — **Mode: OWNER/LIVE (skip)**
- Supersedes PR-A/PR-C: secure local token pairing/refresh + Gradle wrapper/toolchain + PR Java
  build/test + checksummed release. Needs JDK/Gradle. Leave `[ ]`.

## Benchmark-driven batch — 2026-09-25 (BM-*)

### [ ] BM-1 — Tame the two catch-all false-positive classes (precision)  — **SUPERSEDED by FR-4 (2026-09-25)**
- **Domain:** Detection precision - **Effort:** M - **Mode:** LOOP

### [~] BM-2 — Same-class secure-vs-vulnerable discriminator (stop firing on clean controls)  — **PARTIAL (2026-11-02)**
- **Domain:** Detection precision - **Effort:** L - **Mode:** LOOP (harder; may be partly research)

### [ ] BM-3 — Reasoning-heavy class recall (auth_bypass / business_logic / ssrf)  — **Mode: OWNER/LIVE (skip)**
- **Evidence (VERIFIED):** these three classes are missed (R=0) on BOTH PixelMart and Juice Shop — the
  classes needing multi-step inference about intent/state. Unlikely to close with an 8B local model alone.

## Swarm-comparison batch — 2026-09-27 (SC-*)

### [ ] SC-6 — The built wheel must import outside the checkout (package resources + entry points) (A5)

### [~] SC-9 — Per-tool bounded execution broker (reinforces PR-11 / NC-O1) (A6)
- **Domain:** Security / Safety · **Effort:** M · **Depends on:** PR-11 · **Mode:** LOOP (offline broker/args); container-confinement proof = OWNER/LIVE (see NC-O1)

### [ ] SC-10 — Governed ToolAdapter contract + one high-value adapter (borrow #1)
- **Domain:** Extensibility / Discovery · **Effort:** L · **Depends on:** SC-1..SC-3, SC-9 · **Mode:** build LOOP; retention OWNER/LIVE (measured)

### [ ] SC-14 — Install / doctor / serve + aligned release (borrow #5)
- **Domain:** Product / DX · **Effort:** M · **Depends on:** SC-6 · **Mode:** offline build LOOP; Burp load + fresh-machine matrix OWNER/LIVE (see P1-5)

## Live-loop build batch — LB-* (2026-10-01, from the detect-and-prove loop)

### [ ] LB-6 — Runner objective-completion wiring (benchmark oracle only; owner-gated to turn on)
- **Domain:** Benchmark runner / objective completion · **Effort:** M · **Depends on:** none ·
  **Mode:** LOOP for the typed wiring + fixture; turning it on against a live lab is OWNER/LIVE

### [ ] LB-7 — Single-packet / last-byte-sync race dispatch in the transport  ·  Mode: OWNER/LIVE (skip)
- **Domain:** Transport (concurrency) · **Effort:** L · **Depends on:** none · **Mode:**
  OWNER/LIVE — not loop-consumable; left `[ ]` and skipped by the loop.

## Deterministic-check deferrals — 2026-10-15 (Part A split-outs)

### [ ] DET-SSRF — Resolve SSRF collaborator reachability for live confirmation
- **Domain:** Deterministic-first validator soundness · **Effort:** M · **Depends on:** an
  in-process collaborator reachable from the target · **Mode:** OWNER/LIVE (needs `active_enabled` +
  a reachable callback).

## Architecture-repair follow-ups — 2026-10-31

### [ ] AR-PKG — Repackage and restart from the fixed source
- **Domain:** Release/verification · **Effort:** S · **Mode:** OWNER.

### [ ] AR-10 — Batch 10: integrated acceptance and model-evaluation specification
- **Domain:** Evaluation · **Effort:** L · **Depends on:** all prior batches incl. AR-09 ·
  **Mode:** LOOP for the spec; OWNER/LIVE for any target run or model A/B (each needs its own
  execution task). Spec: "Batch 10" in IMPLEMENTATION_TASK.md.

## Human-utility batch — 2026-11-09 (HU-*)

### [ ] HU-1 — Operator access matrix: infer a draft, ask the tester, test every answered cell  ★
- **Domain:** Authorization / human input · **Effort:** L · **Depends on:** none for the matrix
  API; T2 (write leg) for write cells · **Mode:** LOOP (offline); live acceptance OWNER.

### [ ] HU-2 — Burp-native findings and a ranked lead queue with ready-to-send requests
- **Domain:** Workflow fit · **Effort:** M-L · **Depends on:** none (Python half); P1-5 for the
  Burp load · **Mode:** LOOP (Python + Java unit tests); OWNER for loading the JAR in Burp.

### [ ] HU-5 — End-of-run handoff: what was not tested and what changed on the target
- **Domain:** Coverage honesty / target safety · **Effort:** M · **Depends on:** none ·
  **Mode:** LOOP.

### [ ] HU-3 — Show the application map to the tester
- **Domain:** Understanding / human support · **Effort:** M · **Depends on:** none ·
  **Mode:** LOOP.

### [ ] HU-6 — Draft write-ups for proven issues, bound to the proof facts
- **Domain:** Reporting · **Effort:** M · **Depends on:** HU-2 (recipe surfacing) ·
  **Mode:** LOOP.

### [ ] HU-4 — Workflow misuse testing from captured flows
- **Domain:** Business logic · **Effort:** L · **Depends on:** T9 (merged), HU-5 change log;
  HU-1/HU-3 for operator confirmation of derived workflows · **Mode:** LOOP offline; live OWNER.

### [ ] HU-8 — Keep scanner-equivalent noise out of the tester's main view
- **Domain:** Precision / attention · **Effort:** S-M · **Depends on:** none · **Mode:** LOOP.

### [ ] HU-7 — Stronger reasoning on structure only, for the planning passes
- **Domain:** Model capacity · **Effort:** M · **Depends on:** HU-1, HU-3 · **Mode:** LOOP for
  the seam and canary; OWNER for the A/B.

### [ ] HU-9 — Incremental passive results while the tester browses
- **Domain:** Workflow fit · **Effort:** M · **Depends on:** HU-2 (panel) · **Mode:** LOOP for
  the Java unit tests; OWNER for loading in Burp.

## External skills-library read — 2026-11-12 (SKL-*)

### [~] SKL-1 — Tighten and measure the race-condition burst's dispatch window
- **Domain:** Validator soundness · **Effort:** S-M · **Depends on:** none ·
  **Mode:** LOOP (offline, stubbed transport); efficacy on a real race stays OWNER/LIVE.

### [~] SKL-2 — Give every specialist agent a matching built-in knowledge note
- **Domain:** AI grounding · **Effort:** S-M · **Depends on:** none ·
  **Mode:** LOOP (offline retrieval test); effect on detection quality stays OWNER/LIVE.

### [ ] SKL-3 — Server-side prototype pollution (JSON `__proto__` / `constructor.prototype`)  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** Coverage · **Effort:** M-L · **Mode:** design LOOP; any live leg OWNER/LIVE.

### [ ] SKL-4 — HTTP parameter pollution (duplicated query/body parameters)  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** Coverage · **Effort:** M · **Mode:** design LOOP; live leg OWNER/LIVE.

### [~] SKL-5 — Family prompts carry only the first member's knowledge note
- **Domain:** AI grounding · **Effort:** S · **Depends on:** SKL-2 ·
  **Mode:** LOOP (offline prompt test); effect on detection quality stays OWNER/LIVE.

## OWASP WSTG gap review — 2026-11-12 (WG-*)

### [~] WG-1 — Re-key the coverage catalog to current WSTG IDs, keeping v4.2 aliases
- **Domain:** Reporting correctness · **Effort:** M · **Depends on:** none · **Mode:** LOOP.

### [~] WG-2 — Give existing validators catalog rows and fix stale confirmation kinds
- **Domain:** Reporting correctness · **Effort:** M · **Depends on:** WG-1 · **Mode:** LOOP.

### [~] WG-3 — Python leg for logout invalidation (WSTG-SESS-06); end its Java-only status
- **Domain:** Validator coverage / Safety · **Effort:** M · **Depends on:** none ·
  **Mode:** LOOP (fixture with matched control); efficacy on a real target stays OWNER/LIVE.

### [ ] WG-4 — Passive hygiene checks: headers, caching, tokens in URLs, cleartext forms  [NEEDS OWNER DECISION — adds passive detection surface]
- **Domain:** Coverage (passive) · **Effort:** S-M · **Mode:** LOOP once the owner approves.

### [ ] WG-5 — Password-reset flow logic and Host-header reset poisoning (ATHN-09, INJT-17)  [BLOCKED — needs an owner-provided mail sink]
- **Domain:** Validator coverage · **Effort:** M-L · **Mode:** design LOOP; live legs OWNER/LIVE.

### [ ] WG-6 — WSTG tests with no confirming leg (new detection work)  [DEPRIORITIZED — P2-2 decided COLLAPSE]
- **Domain:** Coverage · **Mode:** design LOOP per class; live legs OWNER/LIVE.

## r11 post-mortem batch — 2026-11-18 (R11-*)

### [ ] R11-7b — Live trial of the business_flow leg  [OWNER/LIVE]
- **Mode:** LIVE on a fresh container. Use `config.local.yaml` with `active_enabled`,
  `allow_mutating_replay` and `mutating_ceiling_by_check.business_flow: 8`.

### [ ] R11-8 — Detection gaps behind Strix findings r11 sent requests for but never reported
- **Domain:** Detection · **Effort:** M per sub-item · **Mode:** LOOP (offline); (b) and (c)
  change confirmation policy, so they need OWNER sign-off.
