# Dual-mode and cross-request audit — 2026-10-21

This is an audit and planning record. Product code, defaults, trackers and targets were left
unchanged, no scan was launched, and no dependency was installed.

- **Candidate:** `f5637308e2e4f387aedcc6442ad856754b69565e` on `reconciliation-backlog`, clean tree.
- **Labels:** VERIFIED NOW, SOURCE-SUPPORTED, HISTORICAL/REPORTED, INFERRED, UNKNOWN/BLOCKED (definitions in the evidence index).

| File | Contents |
|---|---|
| [DECISION_REPORT.md](DECISION_REPORT.md) | Five consequential findings, architecture and mode map, crAPI failure funnel with an expected-vs-actual trace, reliability and inference notes, reproducibility limits, readiness verdicts per mode |
| [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) | Every claim, with its label, source location, command or artifact; historical evidence kept separate |
| [CROSS_REQUEST_ACCEPTANCE_SPEC.md](CROSS_REQUEST_ACCEPTANCE_SPEC.md) | Evidence contract, structures, fixture families X1–X7, advisory answer contract, fault injections, evaluation arms, metrics, proposed thresholds |
| [WORK_LIST.md](WORK_LIST.md) | Tickets WL-01–WL-16, sequence and first batch, exact amendments to I01–I17 and aliases, owner decisions, 30/60/90-day view |
| [PRACTITIONER_AND_ALTERNATIVES.md](PRACTITIONER_AND_ALTERNATIVES.md) | Enterprise-pentester and bug-bounty assessments per mode; eight-alternative comparison (provisional) |
| [ALTERNATIVES_RESEARCH_PROVISIONAL.md](ALTERNATIVES_RESEARCH_PROVISIONAL.md) | Full delegated research record with source URLs |
| [artifacts/](artifacts/) | Verification run summary; the two benign traces (scripts and JSON outputs) |

## Reproducing the traces

Both traces use synthetic `lab.invalid` data, no network and a scratch SQLite DB:

```sh
git worktree add --detach <wt> f5637308e2e4f387aedcc6442ad856754b69565e
python -I artifacts/trace_observation_reader.py <wt> out.json
python -I artifacts/trace_role_matrix.py <wt> out.json [owner-scoped|bola|bola-distinct-labels]
```

`trace_role_matrix.py` substitutes empty stand-in modules for `httpx`/`httpcore` (import only) and
patches `crawler.crawl` and `role_crawl._probe`. It demonstrates how the matrix is keyed. It is not a
production-caller test. `trace_observation_reader.py` drives the production store functions that
`analyze()` calls. It does not exercise `analyze()` itself.
