# P3-2 supply-chain hardening — offline half (2026-11-02)

Branch `claude/p3-2-supply-chain-c706a9`, base `origin/main` `9b02511` (0 behind).
Commits: `886bf73` (code, tests, CI), `1325af9` (backlog note, Dockerfile OWNER notes),
plus this handoff. Not pushed.

## What landed
- `harness/tool_runner.py`: `parse_image_ref` / `validate_image_ref` / `ImageRef` /
  `ImageReferenceError` for `name[:tag]@sha256:<64hex>` and bare `sha256:<id>` (local
  image ID, the only way to pin a locally built image). `run()` validates before
  launch: a malformed digest is refused, and `require_digest=True` (opt-in, default
  off) refuses an unpinned image. A pinned ref is passed to docker unchanged, and the
  receipt gains `tool_image_digest`. `verify_pinned_digest()` checks a local image's
  Id/RepoDigests via `docker image inspect` and never pulls.
- `harness/supply_chain.py` (stdlib, offline): `sbom` emits a CycloneDX 1.5 JSON of
  `requirements.lock` + `requirements-proxy.txt` + Dockerfile `FROM` images. Output is
  deterministic: the serial is bound to the content, and there is a timestamp only when
  SOURCE_DATE_EPOCH/`--timestamp` is set. `images [--require-digest]` reports base-image
  pinning (exit 1 unpinned with the flag, 2 malformed).
- `.github/workflows/ci.yml`: new `dependency-audit` job (ubuntu, Py 3.14). The SBOM
  and image report are blocking on a script error only. `pip-audit==2.9.0 -r
  harness/requirements.lock --no-deps --disable-pip` is **ADVISORY** (`continue-on-error`).
  `sbom.cdx.json` + `pip-audit.json` are uploaded as artifacts. Not run on GitHub yet:
  its first CI run is its first execution.
- `harness/test_supply_chain.py`: 26 test methods, including caller-level tests through
  `ffuf_runner.run_sync` and a CI-shape test. Defect injection (validation stubbed
  out): 4 tests fail, as expected.
- No config default changed; `config.yaml`, the validators and AR-10 files are untouched.

## Gates (PYTHONPATH=worktree; statuses in gates-py312/py314.status)
| gate | venv 3.12 | system 3.14 |
|---|---|---|
| unittest harness.test_orchestrator_precondition | 0 | 0 |
| unittest harness.test_supply_chain | 0 | 0 |
| harness.suite smoke | 0 | 0 |
| harness.suite full | 0 (5082 OK; native 38; eval 440/17 skip; integrity 59) | 0 (same counts) |
| git diff --check | 0 | — |
Smoke/full started before `1325af9`, which only adds comments to the Dockerfiles and
backlog. `test_supply_chain` was re-run after it: OK on both interpreters.

## OWNER/LIVE (why P3-2 stays `[ ]`)
1. Pin the Dockerfile base images (`tools/sqlmap.Dockerfile`, `tools/ffuf.Dockerfile`)
   to `@sha256:` on a docker host. Placeholder comments there give the command. No
   digests were invented or pulled.
2. In `config.local.yaml`, set `validators.sqlmap.container_image` to the built image's
   `sha256:<id>` (or `name@sha256:` if pushed to a registry), then confirm with
   `tool_runner.verify_pinned_digest(...)`.
3. There is no "browser image" the harness launches: the browser is either local
   Playwright or a remote CDP endpoint. Pinning applies only if you run browserless.
4. Decide whether pip-audit becomes blocking after its first CI runs prove stable.
5. Optional follow-up: wire `require_digest` to a config key (`config.yaml` is owned
   by AR-10 and was not touched).
