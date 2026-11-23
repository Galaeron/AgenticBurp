"""DOC-5: the open view of the improvement backlog.

`docs/IMPROVEMENT_BACKLOG_ARCHIVE.md` holds the full text of every backlog item, open or
closed, as the single file `IMPROVEMENT_BACKLOG.md` held it before the split (about 470,000
characters, too large to read in one context). `IMPROVEMENT_BACKLOG.md` is now generated
from the archive and lists only the items whose checkbox is not `[x]`: each one's heading
line, verbatim, and its metadata line (Domain / Effort / Depends on / Mode) where it has
one. IDs are the heading's first word and never change; a heading is the same text in both
files, so `grep -n "### \\[ \\] P1-3" docs/IMPROVEMENT_BACKLOG_ARCHIVE.md` finds the item.

    python tools/backlog_index.py --write   # regenerate IMPROVEMENT_BACKLOG.md from the archive
    python tools/backlog_index.py --check   # exit 1 if it is stale, over the limit, or inconsistent

To work an item: read its section in the archive, then flip its checkbox and add its
`Result:` line there, and run `--write`. `harness/test_improvement_backlog_split.py` runs the
same check, so a stale or oversized open file fails the suite.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "docs" / "IMPROVEMENT_BACKLOG_ARCHIVE.md"
OPEN = ROOT / "IMPROVEMENT_BACKLOG.md"
LIMIT = 30_000          # characters, counted with LF line ends
CLOSED = "x"
_ITEM = re.compile(r"^### \[(?P<mark>[ ~x!])\] (?P<id>\S+)")
_SECTION = re.compile(r"^## ")
_FIRST_BULLET_MAX = 700  # an item with no Domain line shows its first bullet only when this short


@dataclass
class Item:
    id: str
    mark: str
    heading: str
    section: str
    detail: list[str] = field(default_factory=list)


def read(path: Path) -> str:
    """Text with LF line ends, whatever the checkout's autocrlf did."""
    return path.read_text(encoding="utf-8")


def _detail(body: list[str]) -> list[str]:
    """The item's metadata: its `- **Domain:**` line and continuation lines, else a short
    first bullet. Lines are copied verbatim."""
    def bullet_at(start: int) -> list[str]:
        out = [body[start]]
        for line in body[start + 1:]:
            if line.startswith("  ") and not line.lstrip().startswith("- "):
                out.append(line)
            else:
                break
        return out

    for i, line in enumerate(body):
        if line.startswith("- **Domain:**"):
            return bullet_at(i)
    for i, line in enumerate(body):
        if line.startswith("- "):
            first = bullet_at(i)
            return first if sum(len(x) + 1 for x in first) <= _FIRST_BULLET_MAX else []
    return []


def parse(text: str) -> list[Item]:
    """Every `### [m] ID ...` item heading, in order, with its section and metadata."""
    items: list[Item] = []
    section = ""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if _SECTION.match(line):
            section = line
        m = _ITEM.match(line)
        if m:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("#"):
                j += 1
            items.append(Item(m["id"], m["mark"], line, section, _detail(lines[i + 1:j])))
            i = j
            continue
        i += 1
    return items


def _rules(archive: str) -> str:
    """The loop rules and status legend, verbatim from the archive's preamble."""
    start = archive.index("1. Work top-down")
    return archive[start:archive.index("\n---\n", start)].rstrip("\n")


HEADER = """# Improvement backlog: open items

This file lists the items still open (`[ ]`, `[~]` or `[!]`): each one's heading and its
metadata line, as they are in the archive. It is **generated**; do not edit it by hand
(`python tools/backlog_index.py --write`; a test fails when it drifts, or passes 30,000
characters). The full text of every item, open or closed, with its evidence, acceptance
criteria and `Result:` lines, is in
[docs/IMPROVEMENT_BACKLOG_ARCHIVE.md](docs/IMPROVEMENT_BACKLOG_ARCHIVE.md), together with
the 2026-09 to 2026-11 dispatch notes that used to open this file. IDs are stable.

To read an item, grep its heading in the archive and read that section only, for example
`grep -n "### \\[ \\] P1-3" docs/IMPROVEMENT_BACKLOG_ARCHIVE.md`. To close one, edit it in the
archive (flip the checkbox, add the `Result:` line), then run `--write`. Where the rules
below say "under the item" or "this file", they mean the item in the archive.

## How to use it

"""


def render_open(archive: str) -> str:
    """The open file for `archive`: header, the loop rules, then the open items by section."""
    out = [HEADER + _rules(archive) + "\n"]
    open_items = [item for item in parse(archive) if item.mark != CLOSED]
    out.append(f"\n---\n\n{len(open_items)} open items.\n")
    section = None
    for item in open_items:
        if item.section != section:
            section = item.section
            out.append(f"\n{section}\n")
        out.append(f"\n{item.heading}\n")
        if item.detail:
            out.append("\n".join(item.detail) + "\n")
    return "".join(out)


def problems(archive: str, open_text: str) -> list[str]:
    """Defects of `open_text` as the open view of `archive`; an empty list is a pass."""
    found = []
    items = parse(archive)
    ids = [item.id for item in items]
    found += [f"duplicate item id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    if len(open_text) >= LIMIT:
        found.append(f"the open file is {len(open_text)} characters; the limit is {LIMIT}")
    open_ids = [item.id for item in parse(open_text) if item.mark != CLOSED]
    expected = [item.id for item in items if item.mark != CLOSED]
    found += [f"open id {i} does not resolve to an archive item" for i in open_ids if i not in ids]
    found += [f"archive item {i} is open but not listed" for i in expected if i not in open_ids]
    found += [f"{i} is closed in the archive but listed as open" for i in open_ids
              if i in ids and i not in expected]
    archive_headings = {item.heading for item in items}
    found += [f"heading differs from the archive: {item.heading[:70]}" for item in parse(open_text)
              if item.heading not in archive_headings]
    if open_text != render_open(archive):
        found.append("the open file is not what --write generates from the archive (stale)")
    return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate IMPROVEMENT_BACKLOG.md")
    mode.add_argument("--check", action="store_true", help="exit 1 on a stale or oversized open file")
    args = parser.parse_args(argv)
    archive = read(ARCHIVE)
    if args.write:
        OPEN.write_text(render_open(archive), encoding="utf-8", newline="\n")
        print(f"wrote {OPEN.name}: {len(render_open(archive))} characters")
        return 0
    found = problems(archive, read(OPEN))
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
