"""AR-10 part C: freeze every repeat's export after the last repeat (spec 4.4).

For each repeat it copies result.json and replay-audit.json from the run directory,
computes that run's acceptance.json (harness.ar10_acceptance), hashes the three
files and writes the `ar10-freeze/1` manifest the sealed scorer checks first:

    <out-dir>/freeze.json
    <out-dir>/<repeat_id>/{result.json, replay-audit.json, acceptance.json}

The sealed mapping is never opened: its sha256 is pre-registered with
`--mapping-sha256` before repeat 1. Everything is read and evaluated before
anything is written, and an existing manifest or export directory is never
overwritten. Exit codes: 0 frozen, 2 refused (nothing written).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness import ar10_acceptance, ar10_scorer

MANIFEST_NAME = "freeze.json"


class Refusal(Exception):
    """The freeze cannot be written; nothing was."""


def build(repeats: list[tuple[str, str, Path]], mapping_sha256: str,
          canaries: dict[str, Path] | None = None) -> tuple[dict, dict[str, dict[str, bytes]]]:
    """(manifest, {repeat_id: {file name: bytes}}) for the repeats, in memory."""
    if not ar10_scorer._HEX64.fullmatch(mapping_sha256 or ""):
        raise Refusal("--mapping-sha256 is not a lowercase sha256")
    if not repeats:
        raise Refusal("no repeat given")
    canaries = canaries or {}
    ids = [rid for rid, _, _ in repeats]
    if len(set(ids)) != len(ids) or not all(ids):
        raise Refusal("every repeat needs a unique repeat_id")
    unknown = set(canaries) - set(ids)
    if unknown:
        raise Refusal(f"{len(unknown)} --canaries entry(ies) name no repeat")
    entries, exports = [], {}
    for rid, arm, run_dir in repeats:
        if not arm:
            raise Refusal(f"repeat {rid}: no arm")
        if Path(rid).name != rid or rid in (".", ".."):
            raise Refusal(f"repeat {rid}: repeat_id must be a plain directory name")
        blobs = {}
        for name in ar10_scorer.REQUIRED_FILES:
            try:
                blobs[name] = (Path(run_dir) / name).read_bytes()
            except OSError:
                raise Refusal(f"repeat {rid}: {name} missing from its run directory") from None
        try:
            canary_list = (ar10_acceptance.canaries_from(canaries[rid]) if rid in canaries else None)
        except (OSError, ValueError):
            raise Refusal(f"repeat {rid}: canary file unreadable") from None
        acceptance = ar10_acceptance.evaluate(Path(run_dir), canaries=canary_list)
        blobs["acceptance.json"] = (json.dumps(acceptance, indent=2) + "\n").encode("utf-8")
        exports[rid] = blobs
        entries.append({"repeat_id": rid, "arm": arm, "export_dir": rid,
                        "files": {n: ar10_scorer.sha256_bytes(b) for n, b in sorted(blobs.items())}})
    manifest = {"schema": ar10_scorer.MANIFEST_SCHEMA, "mapping_sha256": mapping_sha256,
                "repeats": entries}
    return manifest, exports


def write(out_dir: Path, manifest: dict, exports: dict[str, dict[str, bytes]]) -> Path:
    out_dir = Path(out_dir)
    path = out_dir / MANIFEST_NAME
    if path.exists() or any((out_dir / rid).exists() for rid in exports):
        raise Refusal("the freeze manifest or a repeat's export directory already exists")
    out_dir.mkdir(parents=True, exist_ok=True)
    for rid, blobs in exports.items():
        (out_dir / rid).mkdir()
        for name, data in blobs.items():
            (out_dir / rid / name).write_bytes(data)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--mapping-sha256", required=True)
    ap.add_argument("--repeat", nargs=3, action="append", required=True,
                    metavar=("REPEAT_ID", "ARM", "RUN_DIR"))
    ap.add_argument("--canaries", nargs=2, action="append", default=[],
                    metavar=("REPEAT_ID", "CANARY_FILE"), help="operator-named L10 canary file")
    args = ap.parse_args(argv)
    try:
        manifest, exports = build([(r, a, Path(d)) for r, a, d in args.repeat],
                                  args.mapping_sha256, {r: Path(p) for r, p in args.canaries})
        path = write(args.out_dir, manifest, exports)
    except Refusal as exc:
        print(f"ar10_freeze: refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"manifest": str(path), "repeats": len(exports)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
