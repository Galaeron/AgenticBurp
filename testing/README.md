# Testing

Two distinct things live here, for two distinct purposes. Don't
conflate them.

## `test-target/` — self-graded, for iterating on the harness itself

A small deliberately-vulnerable app (PixelMart) with a known answer key
(`test-target/ANSWER_KEY.md`), built specifically because OWASP Juice
Shop's vulnerabilities are so publicly documented that any LLM's
"success" against it is contaminated by training-data recognition
rather than genuine reasoning. Use this when you're changing
`fast_path.py`, an agent's specialty prompt, or anything else in
`harness/` and want a quick, repeatable check of whether dispatch and
detection still work — you already know the answers, so this measures
"did I break something," not "does this actually work."

Three-phase methodology: `capture_exchanges.py` → `phase1_record.py`
(real dispatch) → `phase2_answers.py` (genuine per-agent answers,
already written) → `phase3_run.py` (real end-to-end pipeline). See
`test-target/README.md` and `test-target/DISCOVERY_RUN_RESULTS.md` for
the existing results and exact reproduction commands.

## `blind-test-kit/` — for a genuine, uncontaminated measurement

A self-contained package (own harness copy, a sanitized target with
every hint stripped, a generalized version of the same three-phase
driver) meant to be handed to a **different agent who did not build the
target and does not have the answer key.** This is the only way to get
a real signal on detection quality rather than a self-graded regression
check — see `blind-test-kit/METHODOLOGY.md` for the full procedure and
`blind-test-kit/run-1-results/`, `blind-test-kit/run-2-results/` for
what's come out of it so far (one run produced no usable signal due to
shallow exploration; the next produced a real, verified result after
fixing two bugs in the tester's own answers file — see
`blind-test-kit/run-2-results/RUN_2_CORRECTED_RESULTS.md`).

**If you're about to hand this to someone for a blind run:** zip
`blind-test-kit/` and send that — don't send `test-target/` (it has the
answer key and the exploit-payload capture script sitting right in it),
and don't send the `run-*-results/` folders inside `blind-test-kit/`
either (they'd leak a prior run's discovered endpoints to a fresh
tester, undercutting their own exploration).

## `blind-target-2/` — a second, independently-built blind target

Same rules as `test-target/`: **never open, read, or grep `app.py` or
`ANSWER_KEY.md`** in here — see `blind-target-2/README.md`. A helpdesk-style
app used for the strict/exact-class benchmark runs (see below), captured and
scored the same way as the other blind runs.

## `labels/` + `score.py`/`pool_strict_runs.py`/`reconcile_benchmark.py` — multi-target strict scoring

A ground-truth manifest per target (`labels/*.labels.json` — currently
`pixelmart`, `dvwa`, `juiceshop`, `webgoat`, `blindtarget2`), loaded and
validated by `labels/manifest.py`. Unlike `score.py`'s coarse OWASP-category
grading, a manifest records the **exact** vulnerability class per exchange
plus per-class negative controls, and leaves a label `inconclusive` (never a
silent secure/negative) where the permitted public sources
(`score.py`'s `_LABEL_CATEGORY`, `test-target/bench.py`'s `KEYWORDS`, the
corpus's own self-describing labels) don't pin one down. This is the ground
truth for the strict-scoring path (`BP-1a`) — see
[docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md](../docs/BENCHMARK_PRECISION_IMPLEMENTATION_PATH.md)
for the implementation path and current status, and `reviews/*/benchmark/`
for dated run outputs. DVWA/Juice Shop/WebGoat are the standard public
vulnerable apps (no answer-key secrecy concern); run your own instance of
each — none is bundled or auto-started by this repo.

For fast agent/routing/gating iteration specifically on `test-target/`
(PixelMart) without re-running the full ~2h LLM pass every time, see the
caching methodology in [test-target/detection_fixture.py](test-target/detection_fixture.py)'s
module docstring (keyed by agent+model+prompt hash) and
[test-target/README.md](test-target/README.md).
