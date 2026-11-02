"""Disconnect each I16 wire in turn, run the regression, restore byte for byte.
Run from the worktree root: python .test-work/i16-wiring-20261102/fault/run_faults.py"""
import subprocess
import sys
from pathlib import Path

FAULTS = [
    ("F1 state merge dropped", "harness/orchestrator_chain.py",
     "            if _declared:\n                _have", "            if False:\n                _have",
     "ProtectedPathsReachTheChainTests.test_listed_route_confirms_from_the_engagement_list"),
    ("F2 owners not merged", "harness/orchestrator_chain.py",
     '(("protected_paths", protected_paths), ("owners", owners))', '(("protected_paths", protected_paths),)',
     "OwnersReachTheChainTests.test_declared_owners_confirm_only_the_declared_crossing"),
    ("F3 hint not produced", "harness/orchestrator_chain.py",
     "if _hint and _hint not in _previous:", "if False:",
     "ProtectedPathsReachTheChainTests.test_unlisted_route_stays_a_candidate_with_a_declaration_hint"),
    ("F4 route does not forward", "harness/server.py",
     "**({'protected_paths': req.protected_paths} if req.protected_paths else {}),", "",
     "InvestigateRouteForwardsDeclarationsTests.test_declared_lists_are_forwarded"),
    ("F5 empty list always forwarded", "harness/server.py",
     "**({'owners': req.owners} if req.owners else {}),", "owners=req.owners,",
     "InvestigateRouteForwardsDeclarationsTests.test_omitted_or_empty_lists_are_not_passed"),
    ("F6 journal key always includes lists", "harness/server.py",
     "    if declared:\n        key_inputs.append(declared)", "    key_inputs.append(declared)",
     "InvestigateRouteForwardsDeclarationsTests.test_journal_key_changes_only_when_a_list_is_declared"),
    ("F7 issue export drops suggested_test", "harness/issues.py",
     '"suggested_test": redact((best.get("suggested_test") or "")[:1200]),', "",
     "SuggestedTestExportParityTests.test_issue_export_sarif_and_import_carry_the_next_step"),
    ("F8 sarif import ignores it", "harness/sarif_adapter.py",
     '"suggested_test": props.get("suggestedTest", "") or "",', '"suggested_test": "",',
     "SuggestedTestExportParityTests.test_issue_export_sarif_and_import_carry_the_next_step"),
]
CRLF = "\r\n"

caught = 0
for name, path, old, new, test in FAULTS:
    p = Path(path)
    original = p.read_bytes()
    text = original.decode("utf-8")
    if CRLF in text:  # autocrlf working tree
        old, new = old.replace("\n", CRLF), new.replace("\n", CRLF)
    assert text.count(old) == 1, (name, "anchor not unique")
    try:
        p.write_bytes(text.replace(old, new).encode("utf-8"))
        r = subprocess.run([sys.executable, "-m", "unittest", f"harness.test_i16_wiring.{test}"],
                           capture_output=True, text=True, timeout=600)
    finally:
        p.write_bytes(original)
    ok = r.returncode != 0
    caught += ok
    last = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else ""
    print(f"{name}: {'CAUGHT' if ok else 'MISSED'} ({last})")
    assert p.read_bytes() == original
print(f"{caught} of {len(FAULTS)} caught, sources restored")
