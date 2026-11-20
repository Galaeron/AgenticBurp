"""OPS-2: the Gradle wrapper (distribution pinned by checksum), the Java 17 toolchain, and the CI
job that builds through them.

Each guard is a small function over text or parsed data, so every one has a negative control
that feeds it the broken shape (no checksum, no toolchain, bare `gradle` in CI, no wrapper
validation) and requires it to report that defect. The committed files are then checked with
the same functions. None of this runs Gradle or CI: the offline wrapper build and the
workflow's own runs are separate evidence.
"""
import copy
import re
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "burp-extension"
# Gradle 8.7 bin distribution, as published at
# https://downloads.gradle.org/distributions/gradle-8.7-bin.zip.sha256. Upgrading Gradle is a
# reviewed change: update this record together with distributionSha256Sum.
GRADLE_8_7_BIN_SHA256 = "544c35d6bd849ae8a5ed0bcea39ba677dc40f49df7d1835561582da2009b961d"
HAS_GIT = (ROOT / ".git").exists()


# --------------------------------------------------------------------------- OPS-2 guards

def wrapper_problems(properties: str) -> list[str]:
    props = dict(line.split("=", 1) for line in properties.splitlines()
                 if "=" in line and not line.lstrip().startswith("#"))
    problems = []
    url = props.get("distributionUrl", "").replace("\\", "")
    if not re.fullmatch(r"https://services\.gradle\.org/distributions/gradle-\d+(\.\d+)*-bin\.zip", url):
        problems.append(f"distributionUrl is not a pinned https gradle-X.Y-bin.zip: {url!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", props.get("distributionSha256Sum", "")):
        problems.append("distributionSha256Sum is missing or not a sha256")
    return problems


def toolchain_problems(build_gradle: str) -> list[str]:
    code = "\n".join(re.sub(r"//.*$", "", line) for line in build_gradle.splitlines())
    if not re.search(r"java\s*\{[^{}]*toolchain\s*\{[^{}]*languageVersion\s*=\s*"
                     r"JavaLanguageVersion\.of\(\s*17\s*\)", code):
        return ["build.gradle does not declare a Java 17 toolchain"]
    return []


def java_job_problems(job: dict) -> list[str]:
    steps = job.get("steps", [])
    runs = [s.get("run", "") for s in steps]
    problems = []
    if not any(re.match(r"\./gradlew\b", r.strip()) for r in runs):
        problems.append("no step runs ./gradlew")
    if any(re.search(r"(?<![./\w-])gradle\s", r) for r in runs):
        problems.append("a step still runs a bare `gradle`")
    uses = [s.get("uses", "") for s in steps]
    validate = next((i for i, u in enumerate(uses) if "wrapper-validation" in u), None)
    build = next((i for i, r in enumerate(runs) if "./gradlew" in r), None)
    if validate is None:
        problems.append("the wrapper jar is not validated")
    elif build is not None and validate > build:
        problems.append("the wrapper jar is validated after it is executed")
    return problems


class GradleWrapperTests(unittest.TestCase):
    def properties(self):
        return (EXT / "gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")

    def test_wrapper_files_are_committed(self):
        for name in ("gradlew", "gradlew.bat", "gradle/wrapper/gradle-wrapper.jar",
                     "gradle/wrapper/gradle-wrapper.properties"):
            self.assertTrue((EXT / name).is_file(), name)

    def test_the_distribution_is_pinned_by_checksum(self):
        self.assertEqual(wrapper_problems(self.properties()), [])
        self.assertIn(f"distributionSha256Sum={GRADLE_8_7_BIN_SHA256}", self.properties())
        self.assertIn("gradle-8.7-bin.zip", self.properties())

    def test_wrapper_guard_catches_an_unpinned_distribution(self):
        text = self.properties()
        no_sum = "\n".join(l for l in text.splitlines() if not l.startswith("distributionSha256Sum"))
        self.assertTrue(any("sha256" in p for p in wrapper_problems(no_sum)))
        bad_sum = text.replace(GRADLE_8_7_BIN_SHA256, "not-a-hash")
        self.assertTrue(any("sha256" in p for p in wrapper_problems(bad_sum)))
        plain_http = text.replace("https\\://", "http\\://")
        self.assertTrue(any("distributionUrl" in p for p in wrapper_problems(plain_http)))
        floating = text.replace("gradle-8.7-bin.zip", "gradle-latest-bin.zip")
        self.assertTrue(any("distributionUrl" in p for p in wrapper_problems(floating)))

    def test_build_gradle_declares_the_java_17_toolchain(self):
        text = (EXT / "build.gradle").read_text(encoding="utf-8")
        self.assertEqual(toolchain_problems(text), [])

    def test_toolchain_guard_catches_each_way_to_lose_the_pin(self):
        text = (EXT / "build.gradle").read_text(encoding="utf-8")
        self.assertTrue(toolchain_problems(text.replace("JavaLanguageVersion.of(17)", "JavaLanguageVersion.of(21)")))
        without = re.sub(r"java \{\s*toolchain \{.*?\}\s*\}", "", text, flags=re.S)
        self.assertNotEqual(without, text)
        self.assertTrue(toolchain_problems(without))
        # The word in a comment is not a declaration.
        self.assertTrue(toolchain_problems("// java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }"))

    def test_ci_builds_through_the_wrapper(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        job = jobs["burp-extension-build"]
        self.assertEqual(java_job_problems(job), [])
        java = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/setup-java"))
        self.assertEqual(java["with"]["java-version"], "17")

    def test_ci_guard_catches_a_bare_gradle_and_a_missing_validation(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        job = jobs["burp-extension-build"]
        bare = copy.deepcopy(job)
        for step in bare["steps"]:
            step["run"] = step.get("run", "").replace("./gradlew", "gradle")
        self.assertTrue(any("bare `gradle`" in p for p in java_job_problems(bare)))
        self.assertTrue(any("no step runs ./gradlew" in p for p in java_job_problems(bare)))
        unvalidated = copy.deepcopy(job)
        unvalidated["steps"] = [s for s in unvalidated["steps"] if "wrapper-validation" not in s.get("uses", "")]
        self.assertTrue(any("not validated" in p for p in java_job_problems(unvalidated)))
        late = copy.deepcopy(job)
        late["steps"].append(late["steps"].pop(1))
        self.assertTrue(any("after it is executed" in p for p in java_job_problems(late)))

    @unittest.skipUnless(HAS_GIT, "needs a git checkout")
    def test_gradlew_keeps_its_executable_bit_and_line_endings_in_git(self):
        staged = subprocess.run(["git", "ls-files", "-s", "burp-extension/gradlew"], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout
        self.assertTrue(staged.startswith("100755 "), f"gradlew is not tracked as executable: {staged!r}")
        attrs = subprocess.run(["git", "check-attr", "eol", "burp-extension/gradlew", "burp-extension/gradlew.bat"],
                               cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertIn("gradlew: eol: lf", attrs)
        self.assertIn("gradlew.bat: eol: crlf", attrs)

    @unittest.skipUnless(HAS_GIT, "needs a git checkout")
    def test_the_wrapper_jar_is_not_swallowed_by_the_jar_ignore_rule(self):
        # `*.jar` is ignored repo-wide; the wrapper jar must be the one exception.
        ignored = subprocess.run(["git", "check-ignore", "-q", "burp-extension/gradle/wrapper/gradle-wrapper.jar"],
                                 cwd=ROOT).returncode
        self.assertEqual(ignored, 1, "gradle-wrapper.jar is git-ignored")
        built = subprocess.run(["git", "check-ignore", "-q", "burp-extension/build/libs/x-all.jar"],
                               cwd=ROOT).returncode
        self.assertEqual(built, 0, "build output must stay ignored (control for the rule above)")


if __name__ == "__main__":
    unittest.main()
