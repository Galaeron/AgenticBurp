"""DOC-1: the README and LIMITATIONS carry no hard inventory counts, and the inventory they do list
(the agent families) is the one the code defines.

The audit found the README's counts wrong in every row (routes "about 50" vs 65, agents 36 vs 37,
validators 35 vs 44). The fix removes the counts instead of generating them, so the guard is a
function over text that reports a stated count of agents, validators, routes, tests, modules,
mixins or families. Each guard has a negative control that feeds it the pre-fix wording and
requires it to report that defect; the committed files are then checked with the same function.
"""
import re
import unittest
from pathlib import Path

from harness import agent_families

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "docs/LIMITATIONS.md")

_NUMBER_WORDS = r"(?:two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)"
_NOUNS = r"(?:agents?|validators?|endpoints?|routes?|tests?|test modules?|modules?|mixins?|families)"
_COUNT = re.compile(
    rf"(?<![\w.`/-])(?:~|about |roughly |nearly |over )?(?:\d[\d,]*\+?|{_NUMBER_WORDS})[\s-]+"
    rf"(?:[A-Za-z/-]+\s+){{0,2}}?{_NOUNS}\b"
    rf"|\b{_NOUNS}\s*\(\d+\)",
    flags=re.IGNORECASE,
)


def hard_counts(text: str) -> list[str]:
    """Every stated count of a code inventory in `text`, as 'line N: matched text'."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        found.extend(f"line {number}: {m.group(0).strip()!r}" for m in _COUNT.finditer(line))
    return found


# The README and LIMITATIONS lines the audit named, before the fix.
PRE_FIX_LINES = (
    "runs and ~2,400 Python / ~230 Java tests pass, but nothing in the repo",
    "|                   |                 |    +-> Agents (36)|",
    "Optionally, agents can be grouped into 6 families for fewer model calls",
    "installs trusted-host and CSRF middleware. ~50 endpoints including:",
    "Assembled from four mixins. `__init__` constructs",
    "36 specialist agents, each a `BaseAgent` subclass with a `name` attribute",
    "groups all 36 into 6 families and issues one composed call per family:",
    "35 validators registered in `ValidatorRegistry.__init__()`, each togglable.",
    "- **`logic/` package** -- 32 client-side modules: most are",
    "|   +-- agents/              # 36 specialist agents (plugin-discovered)",
    "|   +-- validators/          # 35 deterministic validators",
    "- **[open] Flat package + oversized files.** 114 modules sit flat in `harness/`;",
    "lock retries; and a large, real test suite (~2,400 Python + ~230 Java tests).",
    "the 36-agent spread dilutes that focus.",
    "- **[open] Orchestrator import cycle.** ~10 orchestrator/chain/attribution modules",
    "- **[partial] A legacy, unscoped transport path still exists.** ~20 modules have",
    "- **[fixed] Ten agents silently pinned the default model.** Redundant per-agent",
)


def readme_family_table(text: str) -> dict[str, list[str]]:
    """`| family | a, b, c |` rows under the README's family routing paragraph."""
    start = text.index("| Family | Members |")
    families = {}
    for line in text[start:].splitlines()[2:]:
        match = re.fullmatch(r"\|\s*(\w+)\s*\|\s*(.+?)\s*\|", line)
        if not match:
            break
        families[match[1]] = [name.strip() for name in match[2].split(",")]
    return families


class InventoryCountTests(unittest.TestCase):
    def test_the_committed_docs_state_no_hard_count(self):
        for doc in DOCS:
            with self.subTest(doc=doc):
                text = (ROOT / doc).read_text(encoding="utf-8")
                self.assertEqual(hard_counts(text), [], f"{doc} states an inventory count that will go stale")

    def test_the_guard_reports_every_pre_fix_line(self):
        for line in PRE_FIX_LINES:
            with self.subTest(line=line):
                self.assertTrue(hard_counts(line), f"the guard misses: {line}")

    def test_the_guard_ignores_a_count_that_is_not_an_inventory(self):
        for line in ("the 5xx answers to the run's own requests", "retry rounds re-sweep the nodes",
                     "`max_lead_confirmations` leads go to that class's leg", "Python 3.14 in CI",
                     "one composed call per family", "2 suite tabs"):
            with self.subTest(line=line):
                self.assertEqual(hard_counts(line), [])


class FamilyTableTests(unittest.TestCase):
    def test_the_readme_family_table_is_the_one_the_code_defines(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(readme_family_table(text), agent_families.DEFAULT_FAMILIES)

    def test_the_guard_notices_a_member_the_code_does_not_group(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8").replace("sqli, nosql,", "sqli,", 1)
        self.assertNotEqual(readme_family_table(text), agent_families.DEFAULT_FAMILIES)


if __name__ == "__main__":
    unittest.main()
