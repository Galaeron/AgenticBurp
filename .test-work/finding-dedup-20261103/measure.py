"""Before/after counts of the report collapse and issue export on the 8 h Juice Shop run.

Reads ONLY the analysis session's existing DB copy (never the live job DB): copies it
into db/<label>.db here (the store migrates whatever it opens) and runs the same path
as dedup_report_path.py. Prints counts and class labels only -- no summaries,
evidence, bodies or tokens.

Usage (from the worktree root):
  PYTHONPATH=.test-work/finding-dedup-20261103/before-src python <this> before
  PYTHONPATH=. python <this> after
"""
import collections
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = Path(r"C:\Users\arthu\Documents\AgenticVibe\.claude\worktrees\i16-persist-77da6a"
              r"\.test-work\juice-shop-8h-20261103\dedup-db-copy\harness_state.db")


def main(label: str) -> None:
    db = HERE / "db" / f"{label}.db"
    db.parent.mkdir(exist_ok=True)
    shutil.copyfile(SOURCE, db)
    from harness import issues, store, report_generator as rg
    store._DB_PATH = db
    rows = store.all_host_findings("http://127.0.0.1:3003", include_suppressed=True)
    rfs = [rg._from_store_dict(d) for d in rows]
    survivors, removed = rg._collapse_duplicates(list(rfs))
    exported = rg.issue_exports(rows)
    grouped = issues.group_findings_into_issues(rows)
    by_class = collections.Counter(g.vulnerability_class for g in grouped)
    out = {
        "code": str(Path(issues.__file__).resolve().parent.parent),
        "store_rows": len(rows),
        "chain_rows": sum(1 for f in rfs if f.is_chain),
        "report_collapse_survivors": len(survivors),
        "report_collapse_removed": removed,
        "report_survivors_non_chain": sum(1 for s in survivors if not s.is_chain),
        "issue_export_count": len(exported),
        "issue_groups": len(grouped),
        "issue_groups_by_class": dict(by_class.most_common()),
        "largest_issue_groups": sorted(
            ([g.vulnerability_class, g.method, g.endpoint_family, len(g.members)]
             for g in grouped), key=lambda x: -x[3])[:12],
    }
    (HERE / f"counts-{label}.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k != "largest_issue_groups"}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
