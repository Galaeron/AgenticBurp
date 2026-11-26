"""STATE-4: the header of the root sitecustomize.py says what the file is, and docs/TESTING.md mentions it.

The audit found the header calling the file "untracked" when it is tracked and is loaded by the suite's
child processes, so the test environment differs from an installed one. The header guard is a function
over text with a control that feeds it the old header; the committed file is then checked with it, plus
the file's behaviour (it drops editable finders), its tracked status, and that it is not packaged.
"""
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "sitecustomize.py"
OLD_HEADER = (
    "# Verification-only (untracked): drop the venv's editable-install finder so a\n"
    "# module missing from this worktree fails here instead of loading from the\n"
    "# main checkout.\n"
)


def header_problems(text: str) -> list[str]:
    header = text.split("\nimport sys\n", 1)[0]
    problems = [f"header does not say {needle!r}" for needle in
                ("This file is tracked", "not packaged", "PYTHONPATH", "editable", "docs/TESTING.md")
                if needle not in header]
    if "untracked" in header.lower():
        problems.append("header still calls the file untracked")
    return problems


class _EditableFinder:
    """Named like setuptools' editable-install finder; finds nothing."""
    @staticmethod
    def find_spec(name, path=None, target=None):
        return None


def _EditableHook(path):
    raise ImportError("not a path this hook handles")


class HeaderTests(unittest.TestCase):
    def test_the_committed_header_matches_the_files_status(self):
        self.assertEqual(header_problems(HOOK.read_text(encoding="utf-8")), [])

    def test_the_guard_reports_the_old_header(self):
        found = header_problems(OLD_HEADER + "import sys\n")
        self.assertIn("header still calls the file untracked", found)
        self.assertIn("header does not say 'This file is tracked'", found)

    def test_the_file_is_tracked(self):
        try:
            tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "sitecustomize.py"],
                                     capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git is not available")
        if tracked.returncode != 0 and "not a git repository" in tracked.stderr:
            self.skipTest("not a git checkout")
        self.assertEqual(tracked.returncode, 0, tracked.stderr)

    def test_it_is_not_packaged(self):
        find = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(find["include"], ["harness*"])


class BehaviourTests(unittest.TestCase):
    def _run_hook(self):
        exec(compile(HOOK.read_text(encoding="utf-8"), str(HOOK), "exec"), {"__name__": "sitecustomize"})

    def test_running_it_drops_the_editable_finders(self):
        with patch.object(sys, "meta_path", [_EditableFinder, *sys.meta_path]),                 patch.object(sys, "path_hooks", [_EditableHook, *sys.path_hooks]):
            self._run_hook()
            self.assertNotIn(_EditableFinder, sys.meta_path)
            self.assertNotIn(_EditableHook, sys.path_hooks)

    def test_control_a_hook_that_filters_nothing_leaves_the_finder(self):
        inert = HOOK.read_text(encoding="utf-8").replace('"Editable" not in', '"No such name" not in')
        self.assertNotEqual(inert, HOOK.read_text(encoding="utf-8"))
        with patch.object(sys, "meta_path", [_EditableFinder, *sys.meta_path]):
            exec(compile(inert, str(HOOK), "exec"), {"__name__": "sitecustomize"})
            self.assertIn(_EditableFinder, sys.meta_path)

    def test_the_suite_exports_its_path_to_child_processes(self):
        source = (ROOT / "harness/suite.py").read_text(encoding="utf-8")
        self.assertIn("env['PYTHONPATH'] = os.pathsep.join(", source)


class DocTests(unittest.TestCase):
    def test_testing_md_documents_the_hook(self):
        doc = (ROOT / "docs/TESTING.md").read_text(encoding="utf-8")
        self.assertIn("## Import isolation (`sitecustomize.py`)", doc)
        for needle in ("tracked", "editable-install finders", "harness/test_sitecustomize_header.py"):
            self.assertIn(needle, doc)

    def test_the_header_points_at_the_section_that_exists(self):
        self.assertIn("Import isolation", HOOK.read_text(encoding="utf-8"))
        self.assertIn("Import isolation", (ROOT / "docs/TESTING.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
