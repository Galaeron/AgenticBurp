# Corpus ground-truth contamination audit — 2026-09-24 (PR-13)

Generated from `testing/corpus_sanitize.py` (`audit_corpus_file`). Read-only; no
`*ANSWER_KEY*` file or blind-target `app.py` was read. This audit detects
ground-truth ANNOTATIONS (`BUG:` / `ANSWER_KEY` / `# vuln` / `TODO … SECURITY`)
embedded in exchange RESPONSE bodies — the train-on-the-test contamination that
PR-2's label seeding surfaced.

| corpus | present in tree | exchanges | marker hits | contaminated exchanges |
|---|---|--:|--:|---|
| PixelMart (`C:/tmp/pixelmart_exchanges.json`) | yes (untracked) | 22 | **19** | `TP10: path traversal on invoice download` |
| DVWA (`reviews/2026-09-23/benchmark/dvwa_exchanges.json`) | yes (untracked) | 14 | 0 | (none — clean) |
| WebGoat (`reviews/2026-09-23/benchmark/webgoat_exchanges.json`) | yes (untracked) | 7 | 0 | (none — clean) |

## Finding

- **PixelMart is contaminated, in exactly one exchange.** Its path-traversal
  exploit (`TP10`) legitimately discloses the test-target's own source in its
  response body — but that source carries **19 ground-truth annotation markers**
  (`bug:` and `answer_key`): inline `# BUG:` comments naming each endpoint's
  planted vulnerability, plus an `ANSWER_KEY` reference. Because the harness
  analyses this corpus, the detector model reads TP10's response and thereby sees
  the answer key for the **whole app**, which can inflate recall on the other
  exchanges. A real attacker would see the disclosed *source*; it is the
  annotations, which a production app would never ship, that are the contamination.
- **DVWA and WebGoat are clean** (0 markers) — real applications with no embedded
  ground truth.

## Remediation (this PR)

- `corpus_sanitize.sanitize_exchanges()` strips the annotations while preserving
  the realistic disclosed source byte-for-byte (a full-line `# BUG:` comment is
  dropped; an inline one is removed but the code before it kept; a prose
  `ANSWER_KEY` reference is redacted). A clean body is returned byte-identical.
  `audit_exchanges()` over the sanitized output then reports `clean`.
- The evaluation runner/scorer (PR-5 / PR-6) should consume the **sanitized**
  PixelMart corpus and flag any corpus that still carries annotations.

## OWNER / LIVE follow-up (not automatable)

Re-measure detection on the sanitized vs. contaminated PixelMart corpus with a real
model to **quantify** the recall inflation. Until that is done, treat any PixelMart
recall number as an upper bound that includes contamination.
