"""OPS-1: the reviewed allowlist behind the blocking ``pip-audit`` gate.

CI audits ``harness/requirements.lock`` twice. The pull-request job is advisory (an
upstream CVE must not turn an unrelated PR red). The ``dependency-audit-blocking`` job
runs on pushes to ``main`` and on ``v*`` tags and FAILS on any vulnerability that is not
listed in ``.github/pip-audit-allowlist.toml``. This module is that job's logic, so it
can be unit-tested without a workflow run:

    python -m harness.audit_allowlist check [PATH]        # validate; exit 1 on a problem
    python -m harness.audit_allowlist ignore-args [PATH]  # validate, then print
                                                          # "--ignore-vuln ID ..." for pip-audit

Every entry needs an ``id``, an ``owner``, a ``reason`` and an ``expires`` date. An entry
past its expiry date FAILS the check even if the vulnerability is still unfixed, so an
accepted risk is re-reviewed instead of carried silently. ``expires`` is the last day the
entry is valid. IDs are restricted to a safe character set because ``ignore-args`` output
is expanded on a shell command line. Stdlib only (``tomllib``, Python 3.11+).
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / ".github" / "pip-audit-allowlist.toml"
FIELDS = ("id", "owner", "reason", "expires")
_OPTIONAL = ("package",)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")  # GHSA-xxxx-xxxx-xxxx, CVE-2026-1234, PYSEC-2026-1


@dataclass(frozen=True)
class Entry:
    id: str
    owner: str
    reason: str
    expires: dt.date
    package: str = ""


class AllowlistError(ValueError):
    """The file is unreadable or not valid TOML; ``problems`` lists every defect found."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def _as_date(value) -> dt.date | None:
    if isinstance(value, dt.datetime):  # a TOML datetime is not a plain date
        return None
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def parse(text: str, today: dt.date | None = None) -> tuple[list[Entry], list[str]]:
    """(entries, problems). A problem is a defect that must fail the check: an unknown
    key, a missing or blank field, an unsafe or duplicate id, a bad date, an expired entry."""
    today = today or dt.date.today()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise AllowlistError([f"not valid TOML: {error}"]) from error
    problems: list[str] = []
    for key in sorted(set(data) - {"ignore"}):
        problems.append(f"unknown top-level key {key!r} (entries are [[ignore]] tables)")
    raw_entries = data.get("ignore", [])
    if not isinstance(raw_entries, list):
        raise AllowlistError(["`ignore` must be an array of tables ([[ignore]])"])
    entries: list[Entry] = []
    seen: dict[str, int] = {}
    for index, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict):
            problems.append(f"entry {index}: not a table")
            continue
        label = f"entry {index}" + (f" ({raw['id']})" if isinstance(raw.get("id"), str) else "")
        for key in sorted(set(raw) - set(FIELDS) - set(_OPTIONAL)):
            problems.append(f"{label}: unknown key {key!r}")
        bad = False
        for key in FIELDS:
            value = raw.get(key)
            if key == "expires":
                continue
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label}: `{key}` is required and must be non-empty text")
                bad = True
        expires = _as_date(raw.get("expires"))
        if "expires" not in raw:
            problems.append(f"{label}: `expires` is required (a date, e.g. 2027-02-01)")
            bad = True
        elif expires is None:
            problems.append(f"{label}: `expires` must be a calendar date (YYYY-MM-DD)")
            bad = True
        ident = raw.get("id")
        if isinstance(ident, str) and ident.strip():
            if not _ID.fullmatch(ident):
                problems.append(f"{label}: `id` {ident!r} is not a vulnerability id "
                                "(letters, digits, '.', '_', '-' only)")
                bad = True
            elif ident in seen:
                problems.append(f"{label}: duplicate id (also entry {seen[ident]})")
                bad = True
            else:
                seen[ident] = index
        if bad:
            continue
        if expires < today:
            problems.append(f"{label}: expired on {expires.isoformat()} "
                            f"(today {today.isoformat()}); renew it with a fresh review or delete it")
            continue
        entries.append(Entry(ident, raw["owner"].strip(), raw["reason"].strip(), expires,
                             str(raw.get("package", "")).strip()))
    return entries, problems


def load(path: Path | str = ALLOWLIST_PATH, today: dt.date | None = None) -> tuple[list[Entry], list[str]]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise AllowlistError([f"cannot read {path}: {error}"]) from error
    return parse(text, today)


def ignore_args(entries: list[Entry]) -> list[str]:
    """pip-audit arguments that suppress exactly the allowlisted ids."""
    args: list[str] = []
    for entry in entries:
        args += ["--ignore-vuln", entry.id]
    return args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the pip-audit allowlist.")
    parser.add_argument("command", choices=("check", "ignore-args"))
    parser.add_argument("path", nargs="?", default=str(ALLOWLIST_PATH))
    parser.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests")
    args = parser.parse_args(argv)
    today = dt.date.fromisoformat(args.today) if args.today else None
    try:
        entries, problems = load(args.path, today)
    except AllowlistError as error:
        entries, problems = [], error.problems
    if problems:
        for problem in problems:
            print(f"pip-audit allowlist: {problem}", file=sys.stderr)
        return 1
    if args.command == "check":
        print(f"pip-audit allowlist OK: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, none expired")
    else:
        print(" ".join(ignore_args(entries)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
