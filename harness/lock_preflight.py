"""OPS-3: compare the installed packages with ``harness/requirements.lock``.

The lock is the dependency set CI tests (Windows, Python 3.14). Nothing used to
compare an environment against it, so a host running mitmproxy 12.2.3 and
brotli 1.2.0 instead of the locked 12.3.1 and 1.2.1 (the brotli pin carries a
decoder CVE fix, see the ``proxy`` extra in pyproject.toml) ran without any signal.

The check is advisory by design: it never raises and never blocks startup. A
pin whose package is not installed at all is reported as ``missing``, not as a
mismatch: the lock freezes the full test environment, so a core-only install
legitimately lacks Flask, pytest or mitmproxy. Only an INSTALLED package with a
different version is a mismatch.

Documented install path (README Quick Start)::

    pip install -r harness/requirements.lock
    pip install -e . --no-deps

Run it directly: ``python -m harness.lock_preflight [--json] [--strict]``.
Stdlib only (``packaging`` is used for environment markers only if present).
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

LOCK_PATH = Path(__file__).resolve().parent / "requirements.lock"
_LOCK_HINT = "pip install -r harness/requirements.lock"

_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;#]+)"
    r"\s*(?:;\s*(?P<marker>[^#]+?))?\s*(?:#.*)?$")


def canonical(name: str) -> str:
    """PEP 503 name normalisation: ``Flask``/``flask``, ``pyyaml``/``PyYAML``."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    marker: str | None = None


@dataclass(frozen=True)
class Mismatch:
    name: str
    installed: str
    pinned: str

    def message(self) -> str:
        return f"{self.name}: installed {self.installed}, lock pins {self.pinned}"


@dataclass
class LockReport:
    lock_path: str
    lock_found: bool
    checked: int = 0
    mismatches: list[Mismatch] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # marker not applicable / not evaluable

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def warnings(self) -> list[str]:
        if not self.mismatches:
            return []
        lines = [f"dependency lock mismatch: {m.message()}" for m in self.mismatches]
        lines.append(f"installed packages differ from harness/requirements.lock; "
                     f"to reproduce the tested environment run `{_LOCK_HINT}`")
        return lines

    def to_dict(self) -> dict:
        return {
            "lock_found": self.lock_found,
            "checked": self.checked,
            "ok": self.ok,
            "mismatches": [{"package": m.name, "installed": m.installed, "pinned": m.pinned}
                           for m in self.mismatches],
            "missing_count": len(self.missing),
            "skipped_count": len(self.skipped),
        }


def parse_lock(text: str) -> list[Pin]:
    """The ``name==version [; marker]`` pins of a pip-freeze style lock. Comments,
    blank lines and option lines (``-r``, ``--hash``) are ignored."""
    pins: list[Pin] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = _PIN.match(line)
        if match:
            pins.append(Pin(match["name"], match["version"], match["marker"]))
    return pins


def _installed_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception:  # a damaged dist-info must not crash a preflight
        return None


def _marker_applies(marker: str) -> bool | None:
    """True/False when the environment marker can be evaluated, None when it cannot
    (``packaging`` absent or an unparseable marker): such a pin is skipped, never
    guessed."""
    try:
        from packaging.markers import Marker
        return bool(Marker(marker).evaluate())
    except Exception:
        return None


def check_lock(lock_path: Path | str = LOCK_PATH, *,
               installed: Callable[[str], str | None] = _installed_version,
               marker_applies: Callable[[str], bool | None] = _marker_applies) -> LockReport:
    """Compare every applicable lock pin with the installed version. Never raises."""
    path = Path(lock_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        # An installed wheel does not ship the lock; there is nothing to compare.
        return LockReport(str(path), lock_found=False)
    report = LockReport(str(path), lock_found=True)
    for pin in parse_lock(text):
        if pin.marker is not None and marker_applies(pin.marker) is not True:
            report.skipped.append(pin.name)
            continue
        report.checked += 1
        have = installed(pin.name)
        if have is None:
            report.missing.append(pin.name)
        elif have != pin.version:
            report.mismatches.append(Mismatch(pin.name, have, pin.version))
    return report


def log_report(report: LockReport, logger: logging.Logger) -> LockReport:
    """Log the mismatches as warnings (nothing for a clean or lock-less install)."""
    for line in report.warnings():
        logger.warning(line)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Warn when installed packages differ from harness/requirements.lock.")
    parser.add_argument("--lock", default=str(LOCK_PATH), help="path to the lock file")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when any installed package differs from its pin")
    args = parser.parse_args(argv)
    report = check_lock(args.lock)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif not report.lock_found:
        print(f"lock file not found: {report.lock_path} (nothing to compare)")
    elif report.ok:
        print(f"installed packages match the lock ({report.checked} pins checked, "
              f"{len(report.missing)} not installed, {len(report.skipped)} skipped)")
    else:
        for line in report.warnings():
            print(line, file=sys.stderr)
    return 1 if (args.strict and not report.ok) else 0


if __name__ == "__main__":
    raise SystemExit(main())
