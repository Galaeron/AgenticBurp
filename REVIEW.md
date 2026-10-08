# Architecture & OWASP Security Review

> **Historical, founding review — dated 2026-08-30, never updated since.**
> Numbers below are a snapshot of that day (e.g. "15 validators", "one squashed
> commit", "506 tests"): the registry now registers 35 validators, the repo has
> a full dated commit history, and the suite is thousands of tests across
> unittest/pytest/evaluation tiers — see [CURRENT_STATE.md](CURRENT_STATE.md)
> and [docs/TESTING.md](docs/TESTING.md) for the current counts and how to
> reproduce them. Several headline problems here were subsequently addressed
> (an evidence ledger, a scored precision/recall harness, a full leg-
> verification pass, CI, package layout) — check [IMPROVEMENT_BACKLOG.md](IMPROVEMENT_BACKLOG.md)
> and [ORACLE_RETIREMENTS.md](ORACLE_RETIREMENTS.md) before assuming any item
> below is still open. Kept at this path, unedited below this banner, because
> `harness/scope_discovery.py`'s module docstring cross-references it by
> numbered item (`REVIEW.md's #3/#8`); renumbering or moving it would break
> that pointer.
>
> Senior review of the Burp LLM Harness project, written to be handed directly
> to an implementing agent. Every claim below was checked against the actual
> code, config, tests, and repo state — not inferred from docs. File references
> are clickable (`path:line`).
>
> Reviewer stance: decades of OWASP/appsec + software architecture. Do-not-code
> review; this is the *what and why*, ordered so an agent can execute it.

---

## Verdict up front

The **design thinking is genuinely strong** — better than most commercial "AI
security" tooling at avoiding the obvious LLM traps. The **engineering
discipline around proving it works, and around repo hygiene, is weak.** This is
a thoughtfully-architected prototype that has never been validated as a product.

The single most important fact, stated by the project itself, is that **there is
no scored accuracy baseline** — the thing the tool exists to do is unmeasured.

Current objective state (verified this review):
- `python -m unittest discover -p "test_*.py"` → **506 tests pass in ~6s, all mocked** (no live model).
- Git history: **one squashed commit** (`Add brand new release files`).
- 36 agents, 15 validators, 33 Python test files, ~19.6k LOC Python (harness) + ~8k LOC Java (extension).

---

## What's genuinely good (keep, protect, don't rewrite)

- **The core epistemic architecture is correct.** The LLM is a *planner and
  evidence-extractor*; the "is this actually vulnerable?" question is answered by
  deterministic/authoritative layers: GitHub Advisory DB, CISA KEV, registry-age,
  sqlmap. Agents are explicitly forbidden from asserting CVEs from memory
  (`harness/agents/base_agent.py` common rules), and
  `orchestrator._verify_component_observation` (`harness/orchestrator.py:178`)
  requires a component be *literally observed* in the exchange before any lookup.
  This is the right answer to LLM hallucination in security tooling.
- **Three-axis finding model**: `confidence` (is it real) vs `severity` (does it
  matter) vs `basis` (derived/recalled/assumed) in `harness/models.py`. Disciplined and rare.
- **The tool threat-models itself.** `harness/safety_gate.py` has hard ceilings
  config can only *tighten* via `min()`, a `_HARD_DENY_PATTERNS` deny-list, double
  opt-in for mutating replay, a GET default, and the sqlmap adapter asserts
  destructive flags are absent regardless of how the command was built
  (`harness/validators/sqlmap.py`). Mature dual-use hygiene.
- **Prompt-injection posture** is deliberate: untrusted-data framing throughout,
  and `harness/security.py` redacts secret headers before they reach the model —
  with a JWT-header-only disclosure so `alg:none` detection survives redaction.
- **Auth posture**: `harness/server.py` refuses a non-loopback bind without a bearer token.
- **Cost/determinism engineering**: content-hash cache keyed on prompt version,
  effort budget, fast-path that avoids LLM calls for the common case.
- **Comment quality** is exceptional — rationale-rich, "why not just what," often
  citing the live bug that motivated the code. Protect this culture.

---

## What's bad / wrong (headline problems)

1. **Unproven core efficacy.** By the project's own admission (README "Known
   limitations"; HANDOVER §0, §6.4, §7.1) a live run exists but was **never scored
   into precision/recall** against `testing/test-target/ANSWER_KEY.md`. All 506
   tests are mocked — they prove plumbing, not detection. For an OWASP tool, false
   negatives are silent and catastrophic, and this tool has no measurement of them.

2. **Detection has repeatedly been silently zero while tests were green.**
   HANDOVER §0 catalogs it: a system-prompt validator rejecting every agent; a
   prompt-validator false positive killing all agents on disclosed source; **12 of
   13 active validators broken** until `active_enabled` was finally exercised;
   `anomaly_detector.py` "almost completely non-functional." The pattern — *green
   mocked tests, dead real pipeline* — is a test-strategy failure, not bad luck.

3. **"Pentest" is a scope mismatch.** It analyzes one request/response at a time
   and (except opt-in validators) never sends traffic. Access-control/IDOR/
   business-logic — the categories the routing prompt itself says now dominate —
   need multi-request, multi-identity differential testing. The identity/session
   scaffolding is a partial nod, but the core loop is single-shot.

4. **8B local models on the hardest reasoning.** Business-logic and authz are
   exactly where `llama3.1:8b`/`gemma2:9b` are weakest, and the *coordinator
   routing* call — which silently decides whether an agent runs at all, failing
   open to all 36 on error — is the highest-leverage failure point and is unmeasured.

5. **The "deterministic confirmation" leg is often unavailable in practice.**
   GitHub Advisory is 60/hr unauthenticated, KEV live-fetch is "not verified
   working from this build," and sqlmap "is not installed anywhere in this
   project's history." The marketed strength frequently degrades to unconfirmed.

6. **`Finding.confirmed` diverges from the durable `validation_runs` ledger**
   (HANDOVER §6.9): CORS results marked confirmed in-memory never reach the ledger
   because the confirmation allowlist is under-inclusive. A data-integrity bug in
   the exact record meant to be authoritative.

---

## Repo hygiene — needs fixing / needs to go

- **Single squashed git commit** — no history, no bisect, no provenance.
  Unacceptable for a security tool going forward.
- **Binaries and runtime state tracked in git**: the built `.jar`,
  `harness/harness_cache.db`, `harness/harness_state.db` (both currently showing
  as modified). `.gitignore` covers only `__pycache__`. → untrack, gitignore,
  treat DBs as runtime state and the jar as a release artifact.
- **A full, divergent duplicate of the harness** at `testing/blind-test-kit/harness/`
  (32 `.py` files; `fast_path.py` already differs from the real one). Two sources
  of truth. → replace with an import/install of the real package.
- **Experiment cruft in-tree**: `phase_real_run.py`, `_v5`, `_juiceshop`,
  `run-1-results`, `run-2-results`. → archive or delete.
- **Documentation rot**: README points to `RESEARCH_NOTES.md` (missing at root);
  `harness/security.py` cites `DISCOVERY_RUN_RESULTS.md` as if at root. HANDOVER is
  119KB/~1900 lines of session log that itself says "don't read the other 20
  markdown files." → split into a short `ARCHITECTURE.md` + `KNOWN_ISSUES.md`, move
  the narrative to `archive/`.
- **Committed target secrets** (`secret_config.txt`, `helpdesk.db`, uploads,
  `server.log`) — fine as deliberate vuln fixtures, but quarantine clearly.

---

## Code-level smells (minor, real)

- `__import__("asyncio")` and inline `import cache` / `import report_generator`
  scattered through `harness/server.py` instead of top-level imports.
- `sys.path` manipulation in `harness/agents/base_agent.py` to reach `security` —
  the `agents/` subpackage isn't a clean package.
- ~26 broad `except Exception` sites; several log-and-drop (e.g. validator
  failures). Given the "silently zero findings" history, audit each for
  silent-failure risk.
- Hard-coded early-termination batch size of `3` in `harness/orchestrator.py:702`,
  a separate magic number from `concurrency.max_parallel_agents`.

---

## What's missing

- **A scored eval wired into CI.** The corpus exists (`ANSWER_KEY.md`,
  blind-test-kit); it was never tallied. #1 gap.
- **A full-path smoke test against a stub Ollama** returning canned JSON,
  asserting `analyze()` yields the expected findings on a known-vulnerable fixture
  — the one test that would have caught every §0 incident.
- **Multi-request/stateful orchestration** for authz/IDOR/business-logic.
- **Packaging & CI**: unpinned `requirements.txt` (`>=`), `pytest` missing from
  it, no `pyproject`, no lockfile, no workflow running Python or Java tests, no
  self-SAST/dependency audit.
- **Observability of the coordinator fail-open path** (currently silent).
- **Audit-logger PII/secret review** — `harness/audit_logger.py` persists
  prompts/responses; confirm redaction and retention apply there too.

---

## How to improve — priority order (for the implementing agent)

1. **Prove it works.** Run blind-test-kit + `ANSWER_KEY.md` against a pinned local
   model; publish precision/recall per OWASP category; make it a CI regression
   gate. Nothing else matters until this exists.
2. **Add the stub-model end-to-end smoke test** to kill the "green tests, dead
   pipeline" class permanently.
3. **Hygiene sweep**: untrack `.jar`/`.db`, expand `.gitignore`, delete the
   duplicate `testing/blind-test-kit/harness/`, archive experiment scripts, split
   HANDOVER, fix stale doc links.
4. **Packaging + CI**: `pyproject` with pinned deps, `pytest` as dev-dep, GitHub
   Actions running Python + Java tests + a dependency/SAST scan of the tool itself.
5. **Harden the coordinator decision**: make fail-open observable/metered,
   consider a stronger model just for routing, and test that an empty/garbage
   coordinator response is surfaced loudly.
6. **Make `validation_runs` the single source of truth for "confirmed"** and
   reconcile `Finding.confirmed` against it.
7. **Clean the smells**: proper package imports (drop the `sys.path` hack and
   `__import__`), top-level imports in `server.py`, audit broad excepts.
8. **Longer term**: stateful multi-request mode for authz/business-logic;
   determinism/seed controls.

---

## Bottom line for an OWASP-minded owner

The philosophy is sound enough to build on — **don't rewrite it.** The work is to
(a) measure detection quality, (b) stop the pipeline from silently dying, and
(c) impose basic repo/release discipline. Until (a) and (b) exist, treat every
"N vulnerabilities found" number this tool emits as unvalidated.
