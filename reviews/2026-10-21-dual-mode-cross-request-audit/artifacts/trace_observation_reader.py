"""Benign present-day trace of the production observation reader (audit 2026-10-21).

Drives harness.store.record_observation / select_observations /
observation_context_block / persist_findings / prior_findings_summary -- the
functions Orchestrator._analyze_inner calls -- against a scratch SQLite DB with
synthetic captures on a reserved `.invalid` host. No network, no target, no
model. It establishes reader-boundary behaviour only; analyze() itself cannot
be imported here (httpx is not installed).

Usage: python -I trace_observation_reader.py <worktree-root> <out.json>
"""
import json
import re
import sys
import tempfile
from pathlib import Path

root, out_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
from harness import store  # noqa: E402
from harness.models import Finding, HttpExchange  # noqa: E402

tmp = tempfile.mkdtemp(prefix="audit_obs_")
store._DB_PATH = Path(tmp) / "state.db"

HOST = "http://lab.invalid"
TOKEN_A = {"Authorization": "Bearer synthetic-token-alice"}
TOKEN_B = {"Authorization": "Bearer synthetic-token-bob"}
VEH_A = "0f6c1a52-1111-4a1a-9a1a-aaaaaaaaaaaa"   # synthetic object ids (UUID-shaped)
VEH_B = "7d2e9b13-2222-4b2b-9b2b-bbbbbbbbbbbb"


def ex(path, headers, body, cid, t, status=200):
    return HttpExchange(url=HOST + path, method="GET", request_headers=dict(headers),
                        response_status=status,
                        response_headers={"Content-Type": "application/json"},
                        response_body=body, capture_id=cid, captured_at=t)


def principal(e):
    return store.captured_principal_id(e)


def record(e, attribution=None):
    return store.record_observation(e, captured_principal=principal(e),
                                    attribution=store.clean_observation_attribution(attribution))


def select(e, attribution=None):
    sel = store.select_observations(
        e.url, captured_principal=principal(e),
        attribution=store.clean_observation_attribution(attribution),
        exclude_exchange_id=store.exchange_identity(e)[0])
    return {"selected": [o["observation_id"] for o in sel["selected"]],
            "excluded_counts": sel["excluded_counts"],
            "block": store.observation_context_block(sel)}


results = {}

# Observation 1: Alice reads a list endpoint that discloses another user's vehicle id.
o1 = ex("/community/posts/recent", TOKEN_A,
        json.dumps({"posts": [{"author": "bob", "vehicleid": VEH_B}]}), "c1", 100.0)
# Observation 2: Alice reads her own vehicle.
o2 = ex(f"/vehicle/{VEH_A}/location", TOKEN_A, json.dumps({"carId": VEH_A, "owner": "alice"}), "c2", 110.0)
# Observation 3: Alice requests Bob's vehicle id on the same route (the relationship of interest).
o3 = ex(f"/vehicle/{VEH_B}/location", TOKEN_A, json.dumps({"carId": VEH_B, "owner": "bob"}), "c3", 120.0)
# Observation 4: Bob reads his own vehicle (same exact path as o3, different principal).
o4 = ex(f"/vehicle/{VEH_B}/location", TOKEN_B, json.dumps({"carId": VEH_B, "owner": "bob"}), "c4", 90.0)
# Observation 5: Alice re-reads her own vehicle later (same exact path, same principal).
o5 = ex(f"/vehicle/{VEH_A}/location", TOKEN_A, json.dumps({"carId": VEH_A, "owner": "alice"}), "c5", 130.0)

for name, e in (("o1", o1), ("o2", o2), ("o4", o4)):
    results[f"write_{name}"] = record(e)["status"]

results["P1_same_path_same_principal_temporal"] = select(o5)          # expect o2 joined
# P2/P5 first, while only o1 (list disclosure) and o2 (own object) exist besides o4.
# o3's path differs from o2 only by the object id; o1 is a different endpoint.
# Neither can be considered: the SQL filter is the exact normalized endpoint, so
# they are invisible (not even counted). o4 (same exact path, Bob) is counted.
results["P2_P5_rows_considered_for_o3"] = select(o3)
results["P3_same_path_other_principal_undeclared"] = results["P2_P5_rows_considered_for_o3"]
# P4: both sides declare the same tenant -> joins
store.correct_observation_attribution(store.record_observation(o4, captured_principal=principal(o4))["observation_id"],
                                      expected_revision=1, attribution={"tenant": "t1", "principal_ref": "bob"})
results["P4_same_path_other_principal_declared_same_tenant"] = select(o3, {"tenant": "t1", "principal_ref": "alice"})
results["P6_same_path_declared_different_tenants"] = select(o3, {"tenant": "t2", "principal_ref": "alice"})

# Prior-findings channel: a finding recorded for Bob's capture; is it visible to Alice's analysis?
store.persist_findings(o4, "idor", [Finding(vulnerability_class="idor", confidence=0.5,
                                            summary="synthetic finding", evidence="synthetic",
                                            suggested_test="synthetic", basis="derived")])
results["F1_prior_findings_visible_to_other_principal"] = bool(
    store.prior_findings_summary(o3.url, exclude_url=o3.url, captured_principal=principal(o3)))
results["F2_prior_findings_visible_to_same_principal_other_url"] = bool(
    store.prior_findings_summary(HOST + "/profile", exclude_url=HOST + "/profile", captured_principal=principal(o4)))
results["F3_prior_findings_same_url_same_principal"] = bool(
    store.prior_findings_summary(o4.url, exclude_url=o4.url, captured_principal=principal(o4)))
blocks = "\n".join((v.get("block") or "") for v in results.values() if isinstance(v, dict))
# Response-body VALUES (e.g. the owner field, or the vehicle id disclosed in o1's
# body) are never rendered; only key names. Checked on a value that appears only
# in response bodies, never in a path or an analyst label.
results["body_only_value_rendered"] = '"owner": "bob"' in blocks or "author" in blocks
results["rendered_json_keys"] = sorted(set(re.findall(r"keys ([A-Za-z_,]+)", blocks)))

Path(out_path).write_text(json.dumps(results, indent=2))
print(json.dumps({k: (v if not isinstance(v, dict) else {"selected": len(v["selected"]),
                                                          "excluded": v["excluded_counts"]})
                  for k, v in results.items()}, indent=1))
