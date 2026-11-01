# Current state — 2026-11-01

## Checkouts
- Main: reconciliation-backlog, HEAD f563730; extensive pre-existing WIP preserved.
- Existing implementation: .test-work/wt-cors-r1; observed HEAD 1e2c9f8.
- This batch changed dependency declarations and documentation in both checkouts.

## Brotli security update
- CVE-2026-111497: Brotli 1.2.1, mitmproxy 12.3.1 and required companion dependencies.
- Lock installation and compatibility check passed in a fresh Python 3.13.13 environment.
- Benign decoding through Brotli, HTTPX and mitmproxy passed; proxy addon 22 tests passed.
- Smoke/full/precondition attempted but did not complete; owned test processes stopped.
- Full regression status is unverified. Existing deployed environments need upgrade/restart.
- Handoff: .test-work/brotli-security-20261101/HANDOFF.md.
- Deployment guidance: docs/BROTLI_SECURITY_UPDATE.md.

## Preserved work and evidence
- Previous state preserved verbatim: .test-work/brotli-security-20261101/CURRENT_STATE.before.md.
- Earlier architecture verification and acceptance records remain historical/reported.
- Architecture milestone and final-freeze decisions remain unresolved; see prior state pointers.
- Safe configuration and unrelated WIP preserved; no commit, push or deployment.
