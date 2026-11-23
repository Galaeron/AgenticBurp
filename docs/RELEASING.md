# Releasing: the intended process

This is a plan, not a record. No `v*` tag exists yet, so no step below has been run end to end.
The version scheme, the tag format and which artifacts to publish are the owner's decisions
(listed at the end). `SECURITY.md` says only the latest release and `main` receive fixes.

## What exists today

- Both versions are `0.1.0`: `version` in `pyproject.toml` and in `burp-extension/build.gradle`.
  `harness/test_security_and_changelog.py` fails when they differ.
- CI (`.github/workflows/ci.yml`): the `full` job and the `burp-extension-build` job run on every
  push and pull request. `dependency-audit-blocking` runs on pushes to `main` and on `v*` tags, fails on
  any known vulnerability that is not in `.github/pip-audit-allowlist.toml`, and on a tag also
  uploads the CycloneDX SBOM. Nothing in CI builds or publishes a release jar.
- `CHANGELOG.md` has an `[Unreleased]` section that collects changes as they land.

## Steps

1. Choose the version (Semantic Versioning) and set it in `pyproject.toml` and
   `burp-extension/build.gradle`.
2. Rename `[Unreleased]` in `CHANGELOG.md` to `[X.Y.Z] - YYYY-MM-DD`, add a fresh empty
   `[Unreleased]` above it, and keep the upgrade notes.
3. On a clean checkout of the commit to release, run the checks CI runs plus the release-only ones:

   ```bash
   python -m harness.suite full
   python -m harness.lock_preflight --strict
   python -m harness.audit_allowlist check
   python testing/release_doctor.py
   ```

4. Build the Burp extension with the pinned toolchain (JDK 17; see `docs/USER_MANUAL.md` section 6):

   ```bash
   cd burp-extension
   ./gradlew clean test shadowJar     # Windows: gradlew.bat
   ```

5. Checksum the jar, and keep the checksum file with it:

   ```bash
   sha256sum build/libs/*-all.jar > build/libs/SHA256SUMS      # PowerShell: Get-FileHash -Algorithm SHA256
   ```

6. Walk through the README Quick Start on a clean machine as someone new to the tool, and record
   the time to a first `/analyze` result in the release notes. Until that is done the notes say
   "first-run walk-through: unverified".
7. Tag the commit `vX.Y.Z` on `main` and push the tag. The `v*` tag runs the blocking dependency
   audit and uploads the SBOM; wait for it to pass.
8. Create the GitHub release for the tag with the `CHANGELOG.md` entry as its notes and attach the
   jar, `SHA256SUMS` and the SBOM.

## Owner decisions

- The first version number and whether to keep the jar and the Python package on one version.
- Whether the tag job should also require the `full` job (`needs`), so a tag cannot publish an
  audit pass over a red suite.
- Signed tags and signed checksums, and where the jar is hosted.
- A maximum lifetime for entries in `.github/pip-audit-allowlist.toml`.
- Enabling private vulnerability reporting in the repository settings, which `SECURITY.md` relies on.
