"""AR-10 P3: the sealed scorer, driven through its CLI on synthetic fixtures only.

Every mapping and export here is invented for the test. No real mapping, answer key,
blind label or target implementation is read.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness import ar10_scorer
from harness.ar10_scorer import decide

ROOT = Path(__file__).resolve().parent.parent

# Synthetic mapping. Ids, notes and the routes only the mapping knows carry canaries;
# none of them may reach any scorer output.
CANARIES = ("CANARY-ID-jwt-7f3a", "CANARY-NOTE-b81c", "CANARY-ID-sqli-2e90",
            "CANARY-ID-unavail-44d1", "/canary-unavail-5d1e", "CANARY-ID-cors-c0de",
            "CANARY-ID-never-9a9a", "/canary-never-hit-0b0b")
LOGIN = "/rest/synthetic-login"


def mapping(*, equivalents=True, unavailable=True, total=None):
    entries = [
        {"id": "CANARY-ID-jwt-7f3a", "note": "CANARY-NOTE-b81c", "available": True,
         "match": {"validator": "jwt_forge"}},
        {"id": "CANARY-ID-sqli-2e90", "available": True,
         "match": {"validator": "sqlmap", "route": LOGIN},
         **({"equivalents": [{"validator": "time_based_sqli", "route": LOGIN}]}
            if equivalents else {})},
        {"id": "CANARY-ID-unavail-44d1", "available": not unavailable,
         "match": {"validator": "xss_dialog", "route": "/canary-unavail-5d1e"}},
        {"id": "CANARY-ID-cors-c0de", "available": True,
         "match": {"validator": "cors_validator", "class": "cors"}},
        {"id": "CANARY-ID-never-9a9a", "available": True,
         "match": {"validator": "ssti", "route": "/canary-never-hit-0b0b"}},
    ]
    out = {"schema": "ar10-mapping/1", "mechanisms": entries}
    if total is not None:
        out["challenges_total"] = total
    return out


def claim(validator, url, verdict="confirmed", cls=""):
    return {"validator": validator, "class": cls, "method": "GET",
            "url": f"http://127.0.0.1:9/{url.lstrip('/')}", "proof_ids": ["p"],
            "verdict": verdict}


JWT = claim("jwt_forge", "/rest/basket/1")
SQLI = claim("sqlmap", LOGIN)
EQUIV = claim("time_based_sqli", LOGIN)
XSS_UNAVAILABLE = claim("xss_dialog", "/canary-unavail-5d1e")
CORS = claim("cors_validator", "/api/x", cls="cors")
CORS_FP = claim("cors_validator", "/api/y", verdict="false_positive", cls="cors")
SQLI_INCONCLUSIVE = claim("sqlmap", LOGIN, verdict="inconclusive")


def result_json(useful=4, calls=20):
    return {"engagement": {"worklist_summary": {"iterative_diagnostics": {
        "probes": 2, "probes_without_diagnostics": 0,
        "totals": {"parse_errors": 1, "refusals": 0, "rejected_proposals": 2,
                   "unavailable_selections": 1, "duplicate_proposals": 3,
                   "blocked_attempts": 0, "useful_unique_actions": useful,
                   "evidence_attempts": 2, "evidence_attempt_ids": ["a1", "a2"]},
        "by_stop_reason": {"budget": {"probes": 2}}}}},
        "costs": {"model_calls": calls, "model_errors": 0, "retries": 1, "wall_seconds": 60}}


ALL_PASS = {c: "pass" for c in ar10_scorer.HARD_CRITERIA}


class _Fixture:
    """A freeze manifest, its exports and a sealed mapping under one temp folder."""

    def __init__(self, root: Path, repeats: dict[str, tuple[str, list, dict | None]],
                 mapping_doc: dict):
        self.root = root
        self.mapping_path = root / "sealed" / "mapping.json"
        self.mapping_path.parent.mkdir(parents=True)
        self.mapping_path.write_text(json.dumps(mapping_doc), encoding="utf-8")
        rows = []
        for rid, (arm, claims, acceptance) in repeats.items():
            export = root / "exports" / rid
            export.mkdir(parents=True)
            files = {"replay-audit.json": {"claims": claims}, "result.json": result_json()}
            if acceptance is not None:
                files["acceptance.json"] = acceptance
            hashes = {}
            for name, doc in files.items():
                data = json.dumps(doc).encode()
                (export / name).write_bytes(data)
                hashes[name] = hashlib.sha256(data).hexdigest()
            rows.append({"repeat_id": rid, "arm": arm, "export_dir": f"exports/{rid}",
                         "files": hashes})
        self.manifest = {"schema": "ar10-freeze/1", "repeats": rows,
                         "mapping_sha256": hashlib.sha256(self.mapping_path.read_bytes()).hexdigest()}
        self.manifest_path = root / "freeze.json"
        self.write_manifest()
        self.out = root / "scores" / "scores.json"

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def run(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = ar10_scorer.main(["--manifest", str(self.manifest_path), "--mapping",
                                     str(self.mapping_path), "--out", str(self.out), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def report(self):
        return json.loads(self.out.read_text(encoding="utf-8"))


def better_repeats():
    # A verifies jwt only (1 each); B verifies jwt + sqli (+ cors in B3): 2, 2, 3.
    return {
        "A1": ("A", [JWT, SQLI_INCONCLUSIVE], ALL_PASS),
        "B1": ("B", [JWT, SQLI], ALL_PASS),
        "A2": ("A", [JWT], ALL_PASS),
        "B2": ("B", [JWT, SQLI], ALL_PASS),
        "A3": ("A", [JWT], ALL_PASS),
        "B3": ("B", [JWT, SQLI, CORS], ALL_PASS),
    }


class ScorerCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def reset(self):
        for child in list(self.root.iterdir()):
            shutil.rmtree(child) if child.is_dir() else child.unlink()

    def fixture(self, repeats=None, mapping_doc=None):
        return _Fixture(self.root, repeats or better_repeats(), mapping_doc or mapping())

    def test_module_entrypoint_scores_frozen_exports_per_repeat(self):
        fx = self.fixture()
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            [str(ROOT), *filter(None, [os.environ.get("PYTHONPATH")])]))
        proc = subprocess.run(
            [sys.executable, "-m", "harness.ar10_scorer", "--manifest", str(fx.manifest_path),
             "--mapping", str(fx.mapping_path), "--out", str(fx.out)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = fx.report()
        values = {r["repeat_id"]: r["primary_verified_mechanisms"] for r in report["repeats"]}
        self.assertEqual(values, {"A1": 1, "A2": 1, "A3": 1, "B1": 2, "B2": 2, "B3": 3})
        b3 = next(r for r in report["repeats"] if r["repeat_id"] == "B3")
        self.assertEqual(b3["expected_available"], 4)
        self.assertEqual(b3["unavailable_excluded"], 1)
        self.assertEqual(b3["first_failing_boundary"],
                         {"no_matching_claim": 1, "claim_not_audited": 0, "audited_not_confirmed": 0})
        self.assertEqual(b3["secondary"]["useful_unique_actions"], 4)
        self.assertEqual(b3["secondary"]["useful_unique_actions_per_model_call"], 0.2)
        self.assertEqual(b3["secondary"]["stop_reasons"], {"budget": 2})
        self.assertIsNone(b3["secondary"]["duplicate_share"])  # no step count in the export
        self.assertEqual(b3["hard_failures"]["overall"], "pass")
        a1 = next(r for r in report["repeats"] if r["repeat_id"] == "A1")
        self.assertEqual(a1["first_failing_boundary"]["claim_not_audited"], 1)
        self.assertEqual(report["arms"]["A"]["median"], 1)
        self.assertEqual(report["arms"]["B"]["range"], [2, 3])
        self.assertEqual(report["decision"]["verdict"], "better")
        self.assertIn("better", proc.stdout)

    def test_no_recall_percentage_without_a_mapping_denominator(self):
        fx = self.fixture()
        self.assertEqual(fx.run()[0], 0)
        for row in fx.report()["repeats"]:
            self.assertIsNone(row["recall"]["value"])
            self.assertNotIn("denominator", row["recall"])

    def test_modified_export_refuses_before_the_mapping_is_read(self):
        fx = self.fixture()
        target = self.root / "exports" / "B2" / "replay-audit.json"
        target.write_text(json.dumps({"claims": [JWT, SQLI, CORS]}), encoding="utf-8")
        with patch.object(ar10_scorer, "read_sealed_mapping") as read_mapping:
            code, out, err = fx.run()
        self.assertEqual(code, ar10_scorer.EXIT_REFUSED)
        read_mapping.assert_not_called()
        self.assertIn("B2: replay-audit.json does not match its frozen sha256", err)
        self.assertFalse(fx.out.exists())

    def test_unfrozen_exports_refuse(self):
        cases = {
            "unlisted file": lambda fx: (self.root / "exports" / "A1" / "late.json").write_text("{}"),
            "missing file": lambda fx: (self.root / "exports" / "A3" / "result.json").unlink(),
            "no mapping hash": lambda fx: (fx.manifest.pop("mapping_sha256"), fx.write_manifest()),
            "required file not hashed": lambda fx: (
                fx.manifest["repeats"][0]["files"].pop("result.json"), fx.write_manifest()),
        }
        for label, damage in cases.items():
            with self.subTest(label):
                self.reset()
                fx = self.fixture()
                damage(fx)
                with patch.object(ar10_scorer, "read_sealed_mapping") as read_mapping:
                    code, _, err = fx.run()
                self.assertEqual(code, ar10_scorer.EXIT_REFUSED, label)
                read_mapping.assert_not_called()
                self.assertIn("refused", err)
                self.assertFalse(fx.out.exists())

    def test_mapping_that_differs_from_the_preregistered_hash_refuses(self):
        fx = self.fixture()
        fx.mapping_path.write_text(json.dumps(mapping(equivalents=False)), encoding="utf-8")
        code, _, err = fx.run()
        self.assertEqual(code, ar10_scorer.EXIT_REFUSED)
        self.assertIn("pre-registered mapping_sha256", err)
        self.assertFalse(fx.out.exists())

    def test_fewer_than_three_repeats_per_arm_refuses(self):
        repeats = better_repeats()
        del repeats["B3"]
        code, _, err = self.fixture(repeats).run()
        self.assertEqual(code, ar10_scorer.EXIT_REFUSED)
        self.assertIn("arm B has fewer than 3", err)

    def test_output_inside_a_frozen_export_refuses(self):
        fx = self.fixture()
        fx.out = self.root / "exports" / "A1" / "scores.json"
        code, _, err = fx.run()
        self.assertEqual(code, ar10_scorer.EXIT_REFUSED)
        self.assertFalse(fx.out.exists())

    def test_unavailable_challenge_is_excluded_from_numerator_and_denominator(self):
        repeats = {rid: (arm, [*claims, XSS_UNAVAILABLE], acc)
                   for rid, (arm, claims, acc) in better_repeats().items()}
        fx = self.fixture(repeats, mapping(total=10))
        self.assertEqual(fx.run()[0], 0)
        b3 = next(r for r in fx.report()["repeats"] if r["repeat_id"] == "B3")
        self.assertEqual(b3["primary_verified_mechanisms"], 3)
        self.assertEqual(b3["recall"], {"value": round(3 / 9, 4), "denominator": 9})

        # Control: the same proof counts once the mapping marks the challenge available.
        self.reset()
        fx = self.fixture(repeats, mapping(total=10, unavailable=False))
        self.assertEqual(fx.run()[0], 0)
        b3 = next(r for r in fx.report()["repeats"] if r["repeat_id"] == "B3")
        self.assertEqual(b3["primary_verified_mechanisms"], 4)
        self.assertEqual(b3["recall"], {"value": 0.4, "denominator": 10})

    def test_recorded_equivalence_counts_and_unrecorded_does_not(self):
        repeats = dict(better_repeats(), B1=("B", [JWT, EQUIV], ALL_PASS))
        fx = self.fixture(repeats)
        self.assertEqual(fx.run()[0], 0)
        b1 = next(r for r in fx.report()["repeats"] if r["repeat_id"] == "B1")
        self.assertEqual(b1["primary_verified_mechanisms"], 2)
        self.assertEqual(b1["verified_via_recorded_equivalence"], 1)

        self.reset()
        fx = self.fixture(repeats, mapping(equivalents=False))
        self.assertEqual(fx.run()[0], 0)
        b1 = next(r for r in fx.report()["repeats"] if r["repeat_id"] == "B1")
        self.assertEqual(b1["primary_verified_mechanisms"], 1)
        self.assertEqual(b1["verified_via_recorded_equivalence"], 0)
        self.assertEqual(b1["first_failing_boundary"]["no_matching_claim"], 3)

    def test_hard_failure_or_unknown_criteria_block_a_better_verdict(self):
        failing = dict(ALL_PASS, L1="fail")
        repeats = dict(better_repeats(), B2=("B", [JWT, SQLI], failing))
        fx = self.fixture(repeats)
        self.assertEqual(fx.run()[0], 0)
        self.assertEqual(fx.report()["decision"]["verdict"], "no_difference_shown")
        self.assertTrue(fx.report()["arms"]["B"]["hard_failure_any"])

        self.reset()
        # A replay-audit false positive is an L8 failure even if acceptance.json says pass;
        # a repeat with no acceptance record is unknown, never a pass.
        repeats = dict(better_repeats(), B2=("B", [JWT, SQLI, CORS_FP], ALL_PASS),
                       B3=("B", [JWT, SQLI, CORS], None))
        fx = self.fixture(repeats)
        self.assertEqual(fx.run()[0], 0)
        rows = {r["repeat_id"]: r for r in fx.report()["repeats"]}
        self.assertEqual(rows["B2"]["hard_failures"]["criteria"]["L8"], "fail")
        self.assertEqual(rows["B3"]["hard_failures"]["overall"], "unknown")
        self.assertEqual(fx.report()["decision"]["verdict"], "no_difference_shown")

    def test_worse_verdict_end_to_end(self):
        repeats = {rid: ("B" if arm == "A" else "A", claims, acc)
                   for rid, (arm, claims, acc) in better_repeats().items()}
        fx = self.fixture(repeats)
        self.assertEqual(fx.run()[0], 0)
        self.assertEqual(fx.report()["decision"]["verdict"], "worse")

    def test_outputs_contain_no_mapping_entry_text(self):
        fx = self.fixture(mapping_doc=mapping(total=10))
        code, out, err = fx.run()
        self.assertEqual(code, 0)
        written = fx.out.read_text(encoding="utf-8")
        for canary in CANARIES:
            for label, text in (("output file", written), ("stdout", out), ("stderr", err)):
                self.assertNotIn(canary, text, f"{canary} leaked into {label}")
        # Control: the canaries really are in the mapping the scorer read.
        sealed = fx.mapping_path.read_text(encoding="utf-8")
        self.assertTrue(all(c in sealed for c in CANARIES))

    def test_malformed_mapping_error_does_not_echo_entries(self):
        doc = mapping()
        doc["mechanisms"][0]["match"] = {"route": "", "secret": "CANARY-ID-jwt-7f3a"}
        fx = self.fixture(mapping_doc=doc)
        code, out, err = fx.run()
        self.assertEqual(code, ar10_scorer.EXIT_BAD_INPUT)
        self.assertNotIn("CANARY", out + err)
        self.assertFalse(fx.out.exists())


class DecisionRuleTests(unittest.TestCase):
    def test_better_when_median_higher_and_worst_repeat_reaches_baseline_median(self):
        self.assertEqual(decide([1, 2, 3], [3, 4, 5], baseline_hard_failure=False,
                                candidate_hard_failure=False), "better")
        self.assertEqual(decide([1, 2, 3], [2, 3, 3], baseline_hard_failure=False,
                                candidate_hard_failure=False), "better")

    def test_worse_is_the_mirror(self):
        self.assertEqual(decide([3, 4, 5], [1, 2, 3], baseline_hard_failure=False,
                                candidate_hard_failure=False), "worse")

    def test_no_difference_shown_otherwise(self):
        # Higher median but the worst repeat falls below the baseline median.
        self.assertEqual(decide([2, 2, 2], [1, 3, 3], baseline_hard_failure=False,
                                candidate_hard_failure=False), "no_difference_shown")
        self.assertEqual(decide([2, 2, 2], [2, 2, 2], baseline_hard_failure=False,
                                candidate_hard_failure=False), "no_difference_shown")

    def test_hard_failure_blocks_the_arm_that_would_win(self):
        self.assertEqual(decide([1, 1, 1], [3, 3, 3], baseline_hard_failure=False,
                                candidate_hard_failure=True), "no_difference_shown")
        self.assertEqual(decide([3, 3, 3], [1, 1, 1], baseline_hard_failure=True,
                                candidate_hard_failure=False), "no_difference_shown")
        # The losing arm's hard failure does not change the verdict.
        self.assertEqual(decide([1, 1, 1], [3, 3, 3], baseline_hard_failure=True,
                                candidate_hard_failure=False), "better")

    def test_empty_arm_is_an_error(self):
        with self.assertRaises(ValueError):
            decide([], [1], baseline_hard_failure=False, candidate_hard_failure=False)


if __name__ == "__main__":
    unittest.main()
