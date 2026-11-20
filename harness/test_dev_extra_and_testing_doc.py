"""DOC-2: the `dev` extra that makes `pip install -e ".[dev]"` cover the suite's test-only
imports, exact pins that agree with the CI lock, and the CI section of docs/TESTING.md.

Each guard is a function over parsed data with a negative control that feeds it the broken
shape (an undeclared or unmapped import, a diverging pin, the pre-fix doc) and requires it
to report that defect; the committed files are then checked with the same functions. This
is a static check: a clean-virtualenv install of the extra is not run here.
"""
import ast
import copy
import re
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

from harness import lock_preflight

ROOT = Path(__file__).resolve().parent.parent


# test-import root -> the distribution that provides it. A root missing here is a NEW
# third-party import: map it and declare its distribution in pyproject.toml.
IMPORT_PROVIDER = {
    "yaml": "pyyaml", "httpx": "httpx", "fastapi": "fastapi", "pydantic": "pydantic",
    "uvicorn": "uvicorn", "starlette": "fastapi", "h11": "uvicorn",
    "pytest": "pytest", "flask": "flask", "werkzeug": "flask", "jinja2": "flask",
    "cryptography": "cryptography", "brotli": "brotli", "mitmproxy": "mitmproxy",
    "playwright": "playwright",
}
_TEST_FILES = ("harness/test_*.py", "harness/testing_fixtures/*.py", "testing/test_*.py",
               "evaluation_integrity/tests/test_*.py")


def third_party_roots(root: Path) -> dict[str, list[str]]:
    """Top-level third-party modules imported by the suite's test files under `root`."""
    stdlib = set(sys.stdlib_module_names)
    local = {"harness", "testing", "evaluation_integrity"}
    for folder in ("harness", "testing", "evaluation_integrity", "evaluation_integrity/tests",
                   "harness/testing_fixtures"):
        base = root / folder
        if base.is_dir():
            local |= {p.stem for p in base.glob("*.py")} | {p.name for p in base.iterdir() if p.is_dir()}
    found: dict[str, list[str]] = {}
    for pattern in _TEST_FILES:
        for path in sorted(root.glob(pattern)):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    top = name.split(".")[0]
                    if top not in stdlib and top not in local:
                        found.setdefault(top, []).append(path.relative_to(root).as_posix())
    return found


def _dist_name(requirement: str) -> str:
    return lock_preflight.canonical(re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement).group(1))


def declared_dists(pyproject: dict) -> set[str]:
    project = pyproject["project"]
    return {_dist_name(r) for r in [*project["dependencies"], *project["optional-dependencies"]["dev"]]}


def undeclared_test_imports(roots: dict[str, list[str]], pyproject: dict) -> list[str]:
    declared = declared_dists(pyproject)
    problems = []
    for top, files in sorted(roots.items()):
        provider = IMPORT_PROVIDER.get(top)
        if provider is None:
            problems.append(f"{top} (imported by {files[0]}) has no provider mapped")
        elif provider not in declared:
            problems.append(f"{top} needs {provider}, which is not in the core or dev dependencies")
    return problems


def pin_drift(pyproject: dict, lock_text: str) -> list[str]:
    locked = {lock_preflight.canonical(p.name): p.version for p in lock_preflight.parse_lock(lock_text)
              if p.marker is None}
    project = pyproject["project"]
    requirements = [*project["dependencies"], *(r for extra in project["optional-dependencies"].values() for r in extra)]
    problems = []
    for req in requirements:
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;,]+)", req)
        if not match:
            continue
        name, version = lock_preflight.canonical(match[1]), match[2]
        if name in locked and locked[name] != version:
            problems.append(f"{name}: pyproject pins {version}, lock pins {locked[name]}")
    return problems


class DevExtraTests(unittest.TestCase):
    def setUp(self):
        self.pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_dev_extra_declares_what_the_suite_imports(self):
        roots = third_party_roots(ROOT)
        # The scan sees the real suite, not an empty tree.
        for expected in ("httpx", "yaml", "cryptography", "brotli", "mitmproxy", "playwright", "pytest", "werkzeug"):
            self.assertIn(expected, roots)
        self.assertEqual(undeclared_test_imports(roots, self.pyproject), [])

    def test_flask_is_declared(self):
        dev = {_dist_name(r) for r in self.pyproject["project"]["optional-dependencies"]["dev"]}
        self.assertIn("flask", dev)

    def test_guard_catches_an_undeclared_dependency(self):
        roots = third_party_roots(ROOT)
        without_flask = copy.deepcopy(self.pyproject)
        dev = without_flask["project"]["optional-dependencies"]["dev"]
        dev[:] = [r for r in dev if not r.lower().startswith("flask")]
        problems = undeclared_test_imports(roots, without_flask)
        self.assertTrue(any("werkzeug needs flask" in p for p in problems), problems)
        for module in ("cryptography", "brotli", "mitmproxy", "playwright"):
            stripped = copy.deepcopy(self.pyproject)
            dev = stripped["project"]["optional-dependencies"]["dev"]
            dev[:] = [r for r in dev if not r.lower().startswith(module)]
            self.assertTrue(undeclared_test_imports(roots, stripped), module)

    def test_guard_catches_a_new_unmapped_third_party_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "harness").mkdir()
            (Path(tmp) / "harness/test_new.py").write_text(
                "import requests\nimport json\nfrom harness import thing\n", encoding="utf-8")
            roots = third_party_roots(Path(tmp))
        self.assertEqual(list(roots), ["requests"])
        self.assertTrue(any("requests" in p and "no provider" in p
                            for p in undeclared_test_imports(roots, self.pyproject)))

    def test_exact_pins_agree_with_the_ci_lock(self):
        lock = (ROOT / "harness/requirements.lock").read_text(encoding="utf-8")
        self.assertEqual(pin_drift(self.pyproject, lock), [])

    def test_pin_drift_guard_catches_a_diverging_pin(self):
        lock = (ROOT / "harness/requirements.lock").read_text(encoding="utf-8")
        drifted = copy.deepcopy(self.pyproject)
        drifted["project"]["optional-dependencies"]["dev"].append("Flask==0.0.1")
        self.assertEqual(pin_drift(drifted, lock), [f"flask: pyproject pins 0.0.1, lock pins "
                                                    f"{next(p.version for p in lock_preflight.parse_lock(lock) if p.name == 'Flask')}"])


def ci_doc_problems(doc: str, jobs: dict) -> list[str]:
    """Defects in the 'CI and live evidence' section of TESTING.md, judged against ci.yml."""
    match = re.search(r"^## CI and live evidence\n(.*?)(?=^## |\Z)", doc, flags=re.S | re.M)
    if not match:
        return ["no 'CI and live evidence' section"]
    section = match[1]
    problems = [f"job `{job}` is not described" for job in jobs if f"`{job}`" not in section]
    for needle in ("every push and pull request", "self-hosted", "pip-audit-allowlist.toml", "./gradlew"):
        if needle not in section:
            problems.append(f"does not mention {needle!r}")
    for stale in ("Fast CI runs smoke", "Nightly/manual CI runs full", "separate manual boundary"):
        if stale in section:
            problems.append(f"still says {stale!r}")
    return problems


class TestingDocTests(unittest.TestCase):
    def setUp(self):
        self.jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        self.doc = (ROOT / "docs/TESTING.md").read_text(encoding="utf-8")

    def test_the_ci_section_matches_the_workflow(self):
        self.assertEqual(ci_doc_problems(self.doc, self.jobs), [])

    def test_the_documented_install_path_is_the_declared_one(self):
        self.assertIn('python -m pip install -e ".[dev]"', self.doc)
        self.assertIn("python -m playwright install chromium", self.doc)
        self.assertNotIn("Flask==3.1.3\n```", self.doc)  # Flask now comes from the dev extra

    def test_guard_catches_the_pre_fix_section(self):
        stale = ("## CI and live evidence\n\nFast CI runs smoke, native and evaluation tiers plus the "
                 "requirement-evidence gate.\nNightly/manual CI runs full unittest discovery. The Java job "
                 "is a\nseparate manual boundary.\n\n## Maintenance rules\n")
        problems = ci_doc_problems(stale, self.jobs)
        self.assertTrue(any("still says 'Fast CI runs smoke'" in p for p in problems), problems)
        self.assertTrue(any("`full` is not described" in p for p in problems), problems)
        self.assertTrue(any("self-hosted" in p for p in problems), problems)

    def test_guard_catches_a_job_added_to_the_workflow_but_not_the_doc(self):
        jobs = dict(self.jobs, **{"brand-new-job": {}})
        self.assertEqual(ci_doc_problems(self.doc, jobs), ["job `brand-new-job` is not described"])


if __name__ == "__main__":
    unittest.main()
