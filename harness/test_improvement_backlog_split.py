"""DOC-5: the improvement backlog is an open file under 30,000 characters plus an archive, and every
open ID resolves.

`IMPROVEMENT_BACKLOG.md` is generated from `docs/IMPROVEMENT_BACKLOG_ARCHIVE.md` by
`tools/backlog_index.py`. The committed pair is checked with the tool's own `problems()`; each
control feeds that function a pair with one defect (a dropped item, a stale index, a closed item
still listed, an oversized file, a duplicate ID, an edited heading) and requires it to be reported.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_tool():
    spec = importlib.util.spec_from_file_location("backlog_index", ROOT / "tools" / "backlog_index.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # dataclasses resolves annotations through it
    spec.loader.exec_module(module)
    return module


tool = _load_tool()
ARCHIVE = tool.read(tool.ARCHIVE)
OPEN = tool.read(tool.OPEN)


def with_item(archive: str, item_id: str, mark: str) -> str:
    """`archive` with item `item_id` carrying checkbox `mark`."""
    return re.sub(rf"^### \[.\] {re.escape(item_id)}\b", f"### [{mark}] {item_id}", archive, count=1, flags=re.M)


class CommittedPairTests(unittest.TestCase):
    def test_the_open_file_is_under_the_limit(self):
        self.assertLess(len(OPEN), 30_000)
        self.assertEqual(tool.LIMIT, 30_000)

    def test_every_open_id_resolves_and_no_open_item_is_hidden(self):
        self.assertEqual(tool.problems(ARCHIVE, OPEN), [])

    def test_the_open_file_lists_no_closed_item_and_every_open_one(self):
        archive_open = [i.id for i in tool.parse(ARCHIVE) if i.mark != "x"]
        listed = [i.id for i in tool.parse(OPEN)]
        self.assertEqual(listed, archive_open)
        self.assertTrue(archive_open, "the backlog still has open items")
        self.assertTrue(all(i.mark != "x" for i in tool.parse(OPEN)))

    def test_ids_are_unique_across_the_archive(self):
        ids = [i.id for i in tool.parse(ARCHIVE)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_archive_keeps_the_pre_split_text(self):
        marker = "---\n\n# Improvement backlog\n"
        body = ARCHIVE[ARCHIVE.index(marker) + len("---\n\n"):]
        self.assertTrue(body.startswith("# Improvement backlog\n\nA prioritized, loop-consumable list"))
        self.assertIn("### [x] P0-1 — Wire the EvidenceLedger into the live detection/confirmation path", body)
        self.assertIn("## r11 post-mortem batch — 2026-11-18 (R11-*)", body)

    def test_the_command_line_check_passes(self):
        self.assertEqual(tool.main(["--check"]), 0)


class ControlTests(unittest.TestCase):
    """Each defect must be reported; otherwise the check above proves nothing."""

    def test_an_item_dropped_from_the_archive_no_longer_resolves(self):
        start = ARCHIVE.index("### [ ] P1-5 — ")
        end = ARCHIVE.index("\n### ", start + 5)
        dropped = ARCHIVE[:start] + ARCHIVE[end + 1:]
        found = tool.problems(dropped, OPEN)
        self.assertTrue(any("open id P1-5 does not resolve" in line for line in found), found)

    def test_a_new_open_item_makes_the_committed_index_stale(self):
        grown = ARCHIVE.replace("### [x] P0-1 — ", "### [ ] P0-1 — ", 1)
        found = tool.problems(grown, OPEN)
        self.assertTrue(any("archive item P0-1 is open but not listed" in line for line in found), found)
        self.assertTrue(any("stale" in line for line in found), found)

    def test_closing_an_item_in_the_archive_requires_regenerating(self):
        closed = with_item(ARCHIVE, "P1-5", "x")
        found = tool.problems(closed, OPEN)
        self.assertTrue(any("P1-5 is closed in the archive but listed as open" in line for line in found), found)
        self.assertEqual(tool.problems(closed, tool.render_open(closed)), [])
        self.assertIn("### [ ] P1-5 — ", tool.render_open(ARCHIVE))
        self.assertNotIn("P1-5 — Verify", tool.render_open(closed), "a closed item leaves the open file")

    def test_an_oversized_open_file_is_reported(self):
        bloated = OPEN + "x" * 30_000
        self.assertTrue(any("limit is 30000" in line for line in tool.problems(ARCHIVE, bloated)))

    def test_a_duplicate_id_is_reported(self):
        duplicated = ARCHIVE + "\n### [x] P0-1 — a second item with an existing id\n"
        self.assertIn("duplicate item id P0-1", tool.problems(duplicated, OPEN))

    def test_a_heading_edited_in_the_open_file_is_reported(self):
        edited = OPEN.replace("### [ ] P1-5 — Verify and document", "### [ ] P1-5 — Check and document", 1)
        self.assertTrue(any("heading differs from the archive" in line for line in tool.problems(ARCHIVE, edited)))

    def test_the_old_single_file_would_fail_the_size_limit(self):
        self.assertGreater(len(ARCHIVE), 400_000)
        self.assertTrue(any("limit is 30000" in line for line in tool.problems(ARCHIVE, ARCHIVE)))


if __name__ == "__main__":
    unittest.main()
