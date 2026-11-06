#!/usr/bin/env python3
"""
Fetch the pinned SecLists subset for the ffuf image's second wordlist, verify
every file against tools/ffuf-seclists.lock.json, and build the merged list.

Only https://raw.githubusercontent.com/danielmiessler/SecLists/<pinned sha>/<path>
is ever fetched -- the commit SHA in the lock, never a branch -- and a file is
written into tools/seclists/ only after its sha256 matches the lock. The merged
list tools/ffuf-wordlist-seclists.txt is a pure function of the verified files
(`merge_lines`), so `python -m harness.supply_chain wordlists` re-derives and
checks it offline.

  python tools/fetch_seclists.py           # fetch + verify + merge (refuses on mismatch)
  python tools/fetch_seclists.py --pin     # first pin only: record the hashes at the SHA
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS.parent))

# One merge rule, shared with the offline check in harness.supply_chain.
from harness.supply_chain import merge_wordlist_lines as merge_lines  # noqa: E402
from harness.supply_chain import wordlist_source_name as local_name  # noqa: E402
LOCK = TOOLS / "ffuf-seclists.lock.json"
SOURCE_DIR = TOOLS / "seclists"
MERGED = TOOLS / "ffuf-wordlist-seclists.txt"
_RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"
_REPO = "danielmiessler/SecLists"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch(url: str) -> bytes:
    if not url.startswith(f"https://raw.githubusercontent.com/{_REPO}/"):
        raise ValueError(f"refusing to fetch outside the pinned repo: {url}")
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 -- fixed https host
        return r.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python tools/fetch_seclists.py")
    ap.add_argument("--pin", action="store_true",
                    help="record the sha256 of each file at the lock's commit (first pin only)")
    args = ap.parse_args(argv)
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if lock["repo"] != _REPO or len(lock["commit"]) != 40:
        print("lock must name danielmiessler/SecLists at a full commit SHA", file=sys.stderr)
        return 2
    SOURCE_DIR.mkdir(exist_ok=True)
    blobs = []
    for entry in lock["files"]:
        data = _fetch(_RAW.format(repo=lock["repo"], commit=lock["commit"], path=entry["path"]))
        digest = sha256(data)
        if args.pin:
            entry["sha256"], entry["bytes"] = digest, len(data)
        elif digest != entry.get("sha256"):
            print(f"MISMATCH {entry['path']}: got {digest}, lock {entry.get('sha256')}", file=sys.stderr)
            return 1
        (SOURCE_DIR / local_name(entry["path"])).write_bytes(data)
        blobs.append(data)
        print(f"ok {entry['path']} {len(data)} bytes")
    merged = merge_lines(blobs)
    if args.pin:
        lock["merged"] = {"file": MERGED.name, "sha256": sha256(merged),
                          "lines": merged.count(b"\n")}
        LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")
    elif sha256(merged) != lock["merged"]["sha256"]:
        print("MISMATCH merged wordlist", file=sys.stderr)
        return 1
    MERGED.write_bytes(merged)
    lines = merged.count(b"\n")
    print(f"ok {MERGED.name} {lines} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
