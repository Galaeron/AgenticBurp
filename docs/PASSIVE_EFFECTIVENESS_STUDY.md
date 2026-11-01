# Passive effectiveness study protocol — R25

Status: protocol and synthetic accounting only. No practical model or analyst
study has been performed by this remediation. No quality or efficiency defaults
change on the strength of synthetic tests. R19 packaging and R13 cache gates
must be satisfied for a release-quality study candidate.

The study owner supplies an approved sanitized captured-traffic corpus, an
independent annotation team, declared local model/hardware and participating
analysts. These inputs have not been provided to this loop. Analysis gets only
sanitized captures and allowed analyst context, never annotations. Do not use
repository answer keys or blind-target implementations. No target requests,
active confirmation, collection/crawler expansion or automatic replay is part
of this protocol.

Before running, freeze source/resource hashes, model digest, provider/config and
prompt hashes, hardware/driver versions, seeds where available, case IDs and
sanitized capture hashes. Stratify roles/auth, API, SPA/fetch, GraphQL, ordinary
multipart, WebSocket limitations and business context. Include paired benign
negative cases, custom security headers, encoded/binary bodies and tail evidence.
Unsupported shapes remain in the planned matrix as unsupported. Freeze labels
with an independent custodian; record disagreements separately and adjudicate
without seeing the model output. Revisions require a new study ID.

Run at least three independent repeats for every model/config and every planned
case, each with a distinct empty cache and explicit engagement. Capture all
attempts, failures and unknowns. Store raw results access-controlled; export
only sanitized references and bounded metrics. An evaluator separately maps
reported hypotheses to expected class labels and verifies evidence completeness
against the supplied capture. This is passive detection evidence, never proof
of successful exploitation or confirmed target vulnerability.

`python -m testing.passive_study_summary PLAN.json RESULTS.json` summarizes
offline, independently adjudicated records. It never runs a model. Plan schema:
`repeats` (at least 3), `profiles` with `profile_id`, `model`, `config_hash`,
`hardware`; `cases` with `case_id`, `stratum`, `expected` unique class labels and
optional `annotation_disagreement`. Result records supply profile/case/repeat
(zero based), `status` (complete/failed/inconclusive/unsupported), a unique
`fresh_cache_id`, `predicted` class labels and boolean `evidence_complete`.
Optional `latency_ms`, `prompt_tokens`, `completion_tokens`, `peak_memory_bytes`
are nonnegative measurements; absent values stay unknown. The utility validates
declarations, not the truth of freshness, blinding or hardware metadata.

Every planned case/repeat remains in the denominator. Completed cases yield
class-level TP/FP/FN; a wrong class is both FP and FN. Missing/failed/unsupported
or disputed cells are unscored with unresolved positive labels, never clean
negatives. Negative-case TN is separate from label counts.
Disputed expected positive labels are counted separately from adjudicated
unresolved labels; per-stratum TP/FP/FN and unavailable counts remain visible.
Report known-token
lower bounds and measurement coverage; p50/p95 use nearest rank on observed
values, with unknown count alongside. Do not treat three repeats as a precise
population percentile. The utility's `quality_eligible` only indicates complete
adjudicated coverage with evidence, not a passing accuracy threshold.

Predeclared decision gates for this first study: zero exported synthetic-secret
leaks; zero cross-engagement/principal attribution; all planned cells accounted
for; all unresolved/unsupported strata excluded from general capability claims.
For an R21 tuning candidate, require no loss of correctly evidenced positive
labels and no increase in false positives on the frozen cases across repeats,
compared with unchanged defaults. Report all failures; no default change if
comparison is ineligible. Study owners must register minimum sample size and
uncertainty method before unblinding; none is invented from absent participants.

For analyst value, independently randomize analysts to manual-then-assisted or
assisted-then-manual order using matched disjoint cases, counterbalanced by
stratum and experience. Avoid showing the same case twice to one analyst.
Record elapsed active review time, pauses, unresolved cases, final adjudicated
quality and duplicates per case; retain withdrawals and tool failures. Compare
paired time and duplicate burden only alongside quality, reporting sample size
and uncertainty. No time-saving claim until the planned sample, both orders and
quality gates are satisfied. The offline summary does not compute this absent
human study or turn incomplete participant data into a success.

R25 practical gate remains blocked on the named corpus/custodian, model setup
and participants. R21 measured optimization remains blocked on that study.
