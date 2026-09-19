"""P1.6: structural regression guard for the scored-tier provenance status job
in .github/workflows/ci.yml.

Can't run a real CI trigger from here, so this parses the committed workflow
YAML and asserts the four-status contract stays wired: the status job always
runs after `scored`, treats skipped/cancelled as not_run (never as passing),
and fails the job when scored genuinely failed -- so a future edit can't
silently collapse "didn't run" and "ran and passed" back into one green
checkmark without this test going red.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

_CI_YAML = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def _load_ci_config() -> dict:
    with open(_CI_YAML, encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestScoredStatusJobWiring(unittest.TestCase):
    def setUp(self):
        self.config = _load_ci_config()
        self.jobs = self.config["jobs"]

    def test_scored_status_job_exists_and_depends_on_scored(self):
        self.assertIn("scored-status", self.jobs)
        job = self.jobs["scored-status"]
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else (needs or [])
        self.assertIn("scored", needs)

    def test_scored_status_job_always_runs(self):
        """Negative control against the historical bug this closes: without
        `if: always()`, a skipped/failed `scored` job would make this status
        job itself skip, and a skipped status report is exactly the
        "unavailable reads as fine" failure mode being fixed."""
        job = self.jobs["scored-status"]
        self.assertEqual(str(job.get("if", "")).strip(), "always()")

    def test_status_script_maps_all_four_outcomes(self):
        script = self.jobs["scored-status"]["steps"][0]["run"]
        # The four distinct status labels the plan requires must all appear,
        # each attached to a real GitHub Actions job-result case.
        for needle in ("STATUS=\"historical\"", "STATUS=\"failed\"", "STATUS=\"not_run\""):
            self.assertIn(needle, script)
        self.assertIn('"${{ needs.scored.result }}"', script)

    def test_skipped_and_cancelled_map_to_not_run_not_passing(self):
        script = self.jobs["scored-status"]["steps"][0]["run"]
        lines = script.splitlines()

        def _status_after(marker: str) -> str:
            idx = next(i for i, l in enumerate(lines) if marker in l)
            # STATUS="..." is set on the next non-blank line in each case arm.
            for l in lines[idx:idx + 2]:
                if "STATUS=" in l:
                    return l.strip()
            raise AssertionError(f"no STATUS= line found after {marker!r}")

        self.assertIn('STATUS="not_run"', _status_after("skipped)"))
        self.assertIn('STATUS="not_run"', _status_after("cancelled)"))
        self.assertIn('STATUS="historical"', _status_after("success)"))
        self.assertIn('STATUS="failed"', _status_after("failure)"))

    def test_status_script_exits_nonzero_only_on_failed(self):
        script = self.jobs["scored-status"]["steps"][0]["run"]
        self.assertIn('if [ "$STATUS" = "failed" ]; then', script)
        self.assertIn("exit 1", script)

    def test_orphan_test_tripwire_still_collectable_by_full_suite(self):
        """P1.6 must not silently drop the test_no_orphan_test_files.py
        tripwire while editing this workflow. It is a plain test_*.py file
        picked up by unittest discover -- confirm the file (and its
        discoverable test class) still exist, and that the nightly tier
        still runs full discovery (which is what actually executes it)."""
        orphan_test = Path(__file__).resolve().parent / "test_no_orphan_test_files.py"
        self.assertTrue(orphan_test.exists())
        nightly_steps = self.jobs["nightly"]["steps"]
        discover_cmds = [s.get("run", "") for s in nightly_steps]
        self.assertTrue(any("unittest discover" in cmd for cmd in discover_cmds))


if __name__ == "__main__":
    unittest.main()
