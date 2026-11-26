"""STATE-2: one canonical session-handoff file, named identically by CLAUDE.md and AGENTS.md, and a
CURRENT_STATE.md that stays within the line budget AGENTS.md sets.

The audit found three documents describing contradictory "current" states, a state file over its
100-line rule and a handoff file referenced from only one onboarding file. Each guard below is a
function over text with a control that feeds it the defective shape; the committed files are then
checked with the same functions. Not covered: that a commit hash CURRENT_STATE.md names exists (a
file cannot name its own commit, and a shallow CI checkout cannot resolve older ones).
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_LINES = 100        # AGENTS.md: "Keep it under 100 lines" (CURRENT_STATE.md), and the audit's CI rule
ONBOARDING_LINES = 100
HANDOFF_LINES = 40       # AGENTS.md: the session handoff stays within 40 lines
_HANDOFF = re.compile(r"Session handoff file: \[([^\]]+)\]\(([^)]+)\)")


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def handoff_files(text: str) -> list[str]:
    """Targets of every `Session handoff file: [name](target)` marker in `text`."""
    return [m[2] for m in _HANDOFF.finditer(text)]


def line_count(text: str) -> int:
    return len(text.splitlines())


def state_problems(claude: str, agents: str, state: str, handoff_name: str | None = None) -> list[str]:
    problems = []
    if line_count(state) > STATE_LINES:
        problems.append(f"CURRENT_STATE.md has {line_count(state)} lines; the limit is {STATE_LINES}")
    for name, text in (("CLAUDE.md", claude), ("AGENTS.md", agents)):
        if line_count(text) > ONBOARDING_LINES:
            problems.append(f"{name} has {line_count(text)} lines; the limit is {ONBOARDING_LINES}")
    named = {"CLAUDE.md": handoff_files(claude), "AGENTS.md": handoff_files(agents)}
    for name, files in named.items():
        if len(files) != 1:
            problems.append(f"{name} names {len(files)} session handoff files; it must name exactly one")
    if all(len(files) == 1 for files in named.values()) and named["CLAUDE.md"] != named["AGENTS.md"]:
        problems.append(f"CLAUDE.md names {named['CLAUDE.md'][0]} but AGENTS.md names {named['AGENTS.md'][0]}")
    if handoff_name is not None and named["CLAUDE.md"] != [handoff_name]:
        problems.append(f"the handoff file {handoff_name} is not the one CLAUDE.md names")
    return problems


class OnboardingStateTests(unittest.TestCase):
    def test_the_committed_files_pass(self):
        self.assertEqual(state_problems(read("CLAUDE.md"), read("AGENTS.md"), read("CURRENT_STATE.md")), [])

    def test_both_onboarding_files_name_the_same_existing_handoff_file(self):
        claude, agents = handoff_files(read("CLAUDE.md")), handoff_files(read("AGENTS.md"))
        self.assertEqual(claude, agents)
        self.assertEqual(len(claude), 1)
        self.assertTrue((ROOT / claude[0]).is_file(), f"{claude[0]} is the named handoff file but does not exist")

    def test_the_handoff_file_stays_within_its_budget(self):
        name = handoff_files(read("CLAUDE.md"))[0]
        self.assertLessEqual(line_count(read(name)), HANDOFF_LINES)

    def test_current_state_is_within_the_line_budget(self):
        self.assertLessEqual(line_count(read("CURRENT_STATE.md")), STATE_LINES)

    def test_current_state_has_no_unresolved_merge_markers(self):
        for name in ("CLAUDE.md", "AGENTS.md", "CURRENT_STATE.md", "NOTES.md"):
            with self.subTest(file=name):
                self.assertNotRegex(read(name), r"(?m)^(<{7}|>{7}|={7})( |$)")


class ControlTests(unittest.TestCase):
    CLAUDE = "Session handoff file: [NOTES.md](NOTES.md)\n"
    AGENTS = "- Session handoff file: [NOTES.md](NOTES.md). Overwrite it.\n"

    def test_a_state_file_over_the_limit_is_reported(self):
        state = "line\n" * (STATE_LINES + 1)
        found = state_problems(self.CLAUDE, self.AGENTS, state)
        self.assertEqual(found, [f"CURRENT_STATE.md has {STATE_LINES + 1} lines; the limit is {STATE_LINES}"])
        self.assertEqual(state_problems(self.CLAUDE, self.AGENTS, "line\n" * STATE_LINES), [])

    def test_the_audits_145_line_state_file_would_fail(self):
        self.assertTrue(state_problems(self.CLAUDE, self.AGENTS, "line\n" * 145))

    def test_two_different_handoff_files_are_reported(self):
        found = state_problems(self.CLAUDE, "Session handoff file: [HANDOFF.md](HANDOFF.md)\n", "x\n")
        self.assertEqual(found, ["CLAUDE.md names NOTES.md but AGENTS.md names HANDOFF.md"])

    def test_a_handoff_file_named_by_only_one_file_is_reported(self):
        found = state_problems(self.CLAUDE, "No handoff here.\n", "x\n")
        self.assertEqual(found, ["AGENTS.md names 0 session handoff files; it must name exactly one"])

    def test_the_pre_fix_onboarding_files_fail(self):
        pre_fix_claude = "Read [AGENTS.md](AGENTS.md) and [CURRENT_STATE.md](CURRENT_STATE.md).\n"
        self.assertEqual(len(state_problems(pre_fix_claude, pre_fix_claude, "x\n")), 2)


if __name__ == "__main__":
    unittest.main()
