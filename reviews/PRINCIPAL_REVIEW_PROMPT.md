# Principal review — canonical mission prompt (reusable)

This is the exact, user-supplied review specification. The improvement cycle uses
it: after the loop drains the offline backlog, run this review afresh, write the
result to `reviews/<YYYY-MM-DD>/principal-review/REVIEW.md` + `VERIFICATION.md`
(model the format on the 2026-09-24 review), then translate its new findings into
a fresh implementation path + PR/backlog batch and restart the loop ("start over").

Ground rules that persist across cycles: no production safety default is changed
by a review; never read `*ANSWER_KEY*` files or blind-target `app.py`; label every
conclusion VERIFIED / SUPPORTED / CLAIMED / INFERRED / UNKNOWN and never silently
promote one; verify important claims against source; record exact commands, exits
and limits in `VERIFICATION.md`; historical run artifacts stay historical even when
their arithmetic is re-checked.

---

# Mission

You are acting as a combined: Principal Software Architect; Staff/Principal Security
Engineer; AI/Agent Systems Engineer; Penetration-Testing Platform Expert;
Reliability & Quality Engineer; Developer Experience Engineer; Product Manager;
Technical Product Strategist; Open-Source Maintainer; Commercialization / Business
Strategy Advisor.

Perform an exhaustive, evidence-driven review of the AgenticBurp / AgenticVibe
project (repo `https://github.com/ArthurTesta/AgenticBurp`; reviewed against the
local checkout). This is not merely a code review. Determine whether the project is:
(1) architecturally sound, (2) correctly implemented, (3) secure and safe, (4)
trustworthy, (5) effective at its intended job, (6) measurably better than simpler
alternatives, (7) maintainable and extensible, (8) operationally usable, (9) useful
to real penetration testers, (10) differentiated enough to deserve adoption, (11)
suitable for open-source growth and/or commercialization, (12) built around the
right product architecture and workflow, (13) focused on the right problems, (14)
missing capabilities that would materially improve outcomes, (15) over-engineered
where simpler approaches would perform better. Challenge the project; do not
validate assumptions. Answer: "If this were my own product, what would I keep,
change, remove, build next, and what evidence would I require before trusting or
commercializing it?"

## Core principle

Do not confuse: implemented with working; tested with effective; plausible with
demonstrated; sophisticated with valuable; agentic with better; high recall with
good performance; finding generation with vulnerability discovery; detection with
confirmation; confirmation with exploitability; exploitability with business
impact; feature quantity with product quality. Back every important conclusion with
evidence, tagged VERIFIED / SUPPORTED / CLAIMED / INFERRED / UNKNOWN.

## Reading rules

Start with CLAUDE.md, CURRENT_STATE.md, README.md, REVIEW.md,
COMPETITIVE_LANDSCAPE.md, and relevant config/CI. Treat CLAUDE.md and
CURRENT_STATE.md as current orientation; do not assume archived handovers describe
current behavior. Respect blind-evaluation constraints (never inspect hidden answer
keys or target implementations). Do not alter safety defaults to make tests pass.
Do not interact with unauthorized systems.

## Phases (produce all)

1. Reconstruct the product before judging it (intended user, job, workflow fit,
   capture→finding flow, passive vs active, discovery, prioritization, agent
   selection, LLM vs deterministic boundaries, confirmation/rejection, chaining,
   feedback, scope/safety, state, external deps, Java vs Python). Architecture
   diagram Burp→extension→API→orchestration→discovery→routing→agents→validators→
   evidence→graph→reporting, plus trust boundaries. Verify against source.
2. Architecture review: separation of concerns; control flow; agent architecture
   (justify every LLM use; is "36/38 specialists" a measured advantage?); graph/
   engagement architecture; extensibility.
3. Code quality & engineering: correctness, error handling, async/concurrency,
   state, schemas, dead/duplicate code, silent-failure/false-pos/false-neg/unsafe
   paths. 10–20 highest-leverage improvements with severity/evidence/failure/fix/
   effort/payoff.
4. Security of the tool itself (hostile input everywhere): input trust/prompt
   injection; tool execution (network/browser/subprocess/Docker/sqlmap/callbacks);
   scope enforcement (redirects, DNS rebinding, IP literals, nested URLs,
   per-tool enforcement, credential cross-host); API exposure; secrets/sensitive
   data; supply chain. Attacker-oriented threat model + prioritized mitigations.
5. Trustworthiness: can users trust findings/severity/confidence/evidence/
   confirmation/negatives/chains/coverage? Confidence vs calibration. The 11
   reproduce-a-finding questions. Recommend an evidence/provenance ledger if needed.
6. Efficacy & evaluation: evaluate the evaluation (representativeness,
   contamination, negative controls, precision/recall/FP/FN/confirmation/severity/
   coverage/latency/cost/reproducibility, model & ablation comparisons). Watch for
   green unit tests + broken real detection.
7. Ablation design: A current; B one general model + tools; C deterministic only;
   D no critique; E no graph; F stronger single model. Compare precision/recall/
   confirmed/FP/FN/latency/calls/tokens/VRAM/CPU-GPU/wall/intervention/repro. If
   unrunnable, specify exact construction. Which complexity earns its cost?
8. Test strategy: classify tests; find gaps (traffic reaches target, findings
   through real pipeline, validators execute, evidence preserved, negatives stay
   negative, scope cannot escape, unsafe methods gated, cache invalidation, model
   failure ≠ success, tool failure visible, active cannot self-activate). CI pyramid;
   separate ordinary-runner from GPU/live.
9. Performance & resource: latency, LLM calls, concurrency, VRAM, context, cache,
   SQLite, Burp responsiveness, Docker/tool overhead, runtime. Cliffs; operating
   profiles (laptop/workstation/deep/passive/CI).
10. Pentester UX: install, config, Burp UX, verifiability, Repeater integration,
    approve/reject, observability, stop, dedup, FP marking, retest, resume, export,
    audit trail. Ideal vs actual workflow; recommend effort-reducing changes.
11. Product review: ICPs (bounty, independent, consultancy, AppSec, red team,
    researcher, enterprise, Burp Community/Pro) — pain, adoption, willingness to
    pay, constraints, competitors, differentiators. Best initial wedge.
12. Business applicability: OSS / paid extension / desktop / open-core / enterprise
    self-hosted / managed / team / API-SDK / platform. Buyer, pricing unit,
    deployment, support, margin, defensibility, sales friction, what users pay for.
13. Competitive review (current sources w/ links + retrieval dates): Burp AI/AT,
    Scanner+human, PentestGPT, Nebula, AI-OPS, XBOW, Shannon, Strix, ZAP/DAST.
    Why should this exist? Sharper position.
14. Scope & complexity: remove/merge/simplify/postpone/rewrite/extract/promote.
    Does it need 36 agents / every validator / overlapping engagement concepts?
    Which 20% delivers 80%? Minimum lovable product architecture.
15. Missing capabilities (with the user/business outcome for each).
16. Documentation & DX: can a new contributor understand purpose/architecture/
    execution/safety/config/testing/extension? Drift. Minimum canonical doc set + ADRs.
17. Operational & enterprise readiness. Classify: research prototype / advanced
    prototype / developer tool / usable OSS product / production-ready / enterprise.
18. Roadmap P0 (trust blockers) → P1 (product blockers) → P2 (differentiators) →
    P3 (scale). Each: problem, solution, architecture, impact, effort S/M/L/XL,
    risk, dependency, success metric. Plus "do NOT build yet".
19. Quantitative scorecard (0–10) for the 23 categories; for each: why not higher,
    why not lower, what raises it two points. No inflated scores.
20. Findings in the required format (ID, Domain, Severity, Confidence, Evidence
    status, Evidence, Problem, Why it matters, Failure scenario, Recommendation,
    Implementation, Effort, Impact).

## Final deliverable order

1 Executive verdict (~2 pages) · 2 Product reconstruction · 3 Architecture (+
diagrams) · 4 What is unusually good · 5 Critical weaknesses ranked · 6 Code/
engineering findings · 7 Security & threat model · 8 Trustworthiness · 9 Efficacy
& benchmark · 10 Agent/LLM architecture · 11 Testing & quality · 12 Performance ·
13 Pentester UX · 14 Product-market · 15 Competitive · 16 Business · 17 Target
architecture (KEEP/CHANGE/REMOVE/ADD; evolve from current, not from zero) · 18
Roadmap P0→P3 · 19 Scorecard · 20 Top 10 (Impact × confidence ÷ effort) · 21
30/60/90-day plan · 22 Experiments required before major investment · 23 Final
answer to the founder (real problem? first customer? strongest differentiator now &
future? unnecessary complexity? missing? distrust sources? remove? build next?
architecture appropriate? agent approach justified? commercially viable? another 6
months? what would change that?).

## Review behavior

Adversarial but constructive. Do not reward complexity, assume the current
architecture is correct, prioritize a repo TODO by default, repeat documentation,
or report an issue without its consequence. Do not recommend a rewrite unless
incremental improvement is genuinely inferior. Seek leverage: eliminating five
components can beat adding a sixth; precision/evidence/workflow gains beat cosmetics;
demonstrable trustworthiness is especially valuable.

## Evidence discipline

Provide repo path, class/function, test, command, observed output, benchmark, or
external source. If execution is impossible, state exactly what is unverified.
Never invent benchmark results or test outcomes; never claim to have executed what
was only inspected. For external claims, use current sources with links + retrieval
dates.

## Final standard

Complete only when a technical founder could decide: what to fix, simplify, stop
building, build next; what architecture to move toward; which performance claims to
trust; what must be proven experimentally; who the first customer is; why they
choose this over alternatives; what must happen before it is a credible product.
Produce the highest-leverage set of evidence-backed decisions, not the longest report.
