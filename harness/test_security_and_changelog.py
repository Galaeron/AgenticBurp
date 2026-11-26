"""OPS-4: SECURITY.md, CHANGELOG.md and docs/RELEASING.md exist and say what the audit asks.

- SECURITY.md routes reports to GitHub private vulnerability reporting and carries no e-mail address
  (a contact, if the owner wants one, is a placeholder and an owner decision).
- CHANGELOG.md has an Unreleased section that names every remediated audit ID and the model-pacer
  config, so a reader can tell which build fixes what.
- The two version fields (Python package, Burp jar) agree, since a user tells builds apart by them.
- RELEASING.md describes only mechanisms the repository has (the `v*` tag job, the Gradle build).

Each guard is a function over text with a control that feeds it the defective shape.
"""
import re
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
RELEASING = (ROOT / "docs/RELEASING.md").read_text(encoding="utf-8")

# Every ID the 2026-11-19 remediation program fixed (batches a1 to e1), plus O11.
AUDIT_IDS = (
    "ARC-1", "ARC-2", "EFF-1", "EFF-5", "EFF-4", "SEC-1", "TOK-4", "ARC-8", "TOK-7",
    "ARC-3", "ARC-15", "ARC-14", "TOK-2", "TOK-5", "TOK-6", "OPS-2", "OPS-3", "OPS-1", "DOC-2",
    "ARC-5", "EFF-2", "EFF-3", "ARC-4", "ARC-12", "ARC-6", "TOK-3", "ARC-11", "ARC-7", "ARC-10",
    "GAP-4", "GAP-2", "O11",
    "DOC-1", "DOC-3", "DOC-4", "DOC-5", "OPS-4", "STATE-2", "STATE-4",
)
# A mailbox, but not an obviously fictional one.
_EMAIL = re.compile(r"[\w.+-]+@(?!example\.|[\w-]+\.test\b)[\w-]+\.[\w.-]+")


def email_addresses(text: str) -> list[str]:
    return [m.group(0) for m in _EMAIL.finditer(text)]


def unreleased_section(text: str) -> str:
    match = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## \[|\Z)", text, flags=re.S | re.M)
    return match[1] if match else ""


def missing_ids(text: str) -> list[str]:
    section = unreleased_section(text)
    return [i for i in AUDIT_IDS if not re.search(rf"(?<![\w-]){re.escape(i)}(?![\w-])", section)]


class SecurityPolicyTests(unittest.TestCase):
    def test_reports_go_through_github_private_vulnerability_reporting(self):
        self.assertIn("private vulnerability reporting", SECURITY)
        self.assertIn("Report a vulnerability", SECURITY)
        self.assertRegex(SECURITY, r"(?i)do not open a\s+public issue")

    def test_no_document_in_the_set_carries_an_email_address(self):
        for name in ("SECURITY.md", "CHANGELOG.md", "docs/RELEASING.md", "README.md", "docs/USER_MANUAL.md"):
            with self.subTest(doc=name):
                self.assertEqual(email_addresses((ROOT / name).read_text(encoding="utf-8")), [])

    def test_the_guard_finds_a_mailbox_and_ignores_fictional_ones(self):
        self.assertEqual(email_addresses("write to someone@gmail.com"), ["someone@gmail.com"])
        self.assertEqual(email_addresses("a@b.test and jo@example.com"), [])

    def test_the_in_scope_paths_it_names_exist(self):
        for path in ("docs/LIMITATIONS.md", "docs/USER_MANUAL.md", "docs/RELEASING.md", "CHANGELOG.md",
                     "testing/test-target", "testing/blind-target-2", "testing/blind-test-kit",
                     "harness/requirements.lock"):
            self.assertTrue((ROOT / path).exists(), path)
        for route in ("/pairing/check", "/run-provenance"):
            self.assertIn(f'"{route}"', (ROOT / "harness/server.py").read_text(encoding="utf-8"))


class ChangelogTests(unittest.TestCase):
    def test_unreleased_names_every_remediated_id(self):
        self.assertEqual(missing_ids(CHANGELOG), [])

    def test_the_pacer_config_is_listed_with_the_audit_ids(self):
        section = unreleased_section(CHANGELOG)
        self.assertIn("ollama.rate_limit", section)
        self.assertIn("model_rate_limit", section)

    def test_the_guard_reports_an_id_missing_from_unreleased(self):
        stripped = CHANGELOG.replace("- ARC-14:", "- ARC-X:", 1)
        self.assertEqual(missing_ids(stripped), ["ARC-14"])
        self.assertEqual(missing_ids("# Changelog\n\n## [0.1.0]\n- ARC-1\n"), list(AUDIT_IDS))

    def test_the_package_and_the_jar_share_one_version(self):
        package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        jar = re.search(r"^version = '([^']+)'", (ROOT / "burp-extension/build.gradle").read_text(encoding="utf-8"),
                        flags=re.M)[1]
        self.assertEqual(package, jar)
        self.assertRegex(package, r"^\d+\.\d+\.\d+$")


class ReleasingDocTests(unittest.TestCase):
    def test_the_release_process_matches_the_ci_it_relies_on(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        blocking = jobs["dependency-audit-blocking"]
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", str(blocking["if"]))   # the `v*` tags the doc names
        self.assertIn("refs/heads/main", str(blocking["if"]))
        for needle in ("dependency-audit-blocking", "SHA256SUMS", "./gradlew clean test shadowJar",
                       "python -m harness.audit_allowlist check", "python -m harness.lock_preflight --strict",
                       "unverified"):
            self.assertIn(needle, RELEASING)
        self.assertTrue((ROOT / "testing/release_doctor.py").is_file())

    def test_the_document_says_it_is_a_plan(self):
        self.assertIn("This is a plan, not a record", RELEASING)


if __name__ == "__main__":
    unittest.main()
