"""ARC-13: verify that the durable evidence ledger has not been edited.

    python tools/verify_evidence_ledger.py                      # the live store
    python tools/verify_evidence_ledger.py --db path/to/harness_state.db
    python tools/verify_evidence_ledger.py --json               # machine-readable report
    python tools/verify_evidence_ledger.py --strict             # unchained legacy rows fail
    python tools/verify_evidence_ledger.py --check-blobs        # also hash and redaction-check blobs
    python tools/verify_evidence_ledger.py --expect-digest HEX  # compare with a recorded digest

Reads the store read-only. Exit 0: every chained row verifies; 1: a check failed (the first
bad row is named); 2: the store could not be read. Each ledger event has a row in the
ledger_chain table holding the hash of the previous event of its finding and a hash of its own
content, so an edited, deleted, inserted or reordered row breaks the chain at that point. Events
written before the chain existed have no chain row and are reported as unchained legacy rows,
not failures (use --strict to fail them).

The chain is unkeyed. It does not show removal of the newest rows of a finding, a deleted
finding, or a rewrite by someone who recomputes every later hash. To cover those, record the
`digest` this prints when you hand a ledger over, and pass it back with --expect-digest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _render(report: dict) -> str:
    lines = [
        f"ledger rows: {report['rows']}  chained: {report['chained']}  "
        f"unchained legacy: {report['legacy_unchained']}  findings: {report['findings']}",
        f"digest: {report['digest']}",
    ]
    for problem in report["problems"]:
        lines.append(f"BAD ROW seq={problem['seq']} event_id={problem['event_id']} "
                     f"finding_ref={problem['finding_ref']}: {', '.join(problem['reasons'])}")
    if report["problem_count"] > len(report["problems"]):
        lines.append(f"... and {report['problem_count'] - len(report['problems'])} more")
    if report["legacy_unchained"]:
        lines.append(f"note: {report['legacy_unchained']} legacy row(s) have no hash and cannot "
                     "be verified")
    if "strict_failure" in report:
        lines.append(f"strict: {report['strict_failure']}")
    if report.get("digest_matches") is False:
        lines.append("digest does NOT match the expected digest")
    blobs = report.get("blobs")
    if blobs:
        lines.append(f"blobs checked: {blobs['checked']}  corrupt: {blobs['corrupt_count']}  "
                     f"unredacted: {blobs['unredacted_count']}")
        lines += [f"CORRUPT BLOB {digest}" for digest in blobs["corrupt"]]
        lines += [f"UNREDACTED BLOB {item['sha256']}: {', '.join(item['kinds'])}"
                  for item in blobs["unredacted"]]
    lines.append("RESULT: " + ("OK" if report["ok"] else "FAILED"))
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify the hash chain of the evidence ledger.")
    parser.add_argument("--db", help="store file to verify (default: the live store)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--strict", action="store_true", help="treat unchained legacy rows as failures")
    parser.add_argument("--check-blobs", action="store_true",
                        help="also verify every evidence blob's hash and redaction")
    parser.add_argument("--expect-digest", help="the chain digest recorded earlier")
    args = parser.parse_args(argv)
    from harness import evidence_ledger
    try:
        report = evidence_ledger.verify_ledger(
            args.db, strict=args.strict, check_blobs=args.check_blobs,
            expect_digest=args.expect_digest)
    except (OSError, ValueError) as exc:
        print(f"cannot read the store: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:       # sqlite3.DatabaseError and friends: a damaged file
        print(f"cannot verify the store: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else _render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
