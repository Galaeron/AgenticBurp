"""AR-10 P3 (owner decision Q4): part B's frozen acceptance.json and the freeze manifest.

Driven through the CLIs the operator runs: `harness.ar10_freeze` after the last
repeat, then `harness.ar10_scorer` on what it froze. Each criterion is shown passing
on a clean synthetic run directory, failing when its artifact violates it, and
unknown when its input is missing. Synthetic fixtures only: no live run, no real
mapping, no private file of a real run.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import ar10_acceptance, ar10_freeze, ar10_scorer
from harness.test_ar10_scorer import JWT, LOGIN, SQLI, mapping
from harness import test_issue_accounting as tia   # module access: its tests are not re-collected

CANARY_TOKEN = "CANARY-TOKEN-e7d2f9a1"
CANARY_COOKIE = "CANARY-COOKIE-11aa22bb"
MAPPING_SHA = "0" * 64


def _issue_accounting():
    """The real producer's block: one resolved proof and one finding whose proof is
    missing, so the export carries one orphaned link."""
    p = tia.proof("p1", "c1")
    ghost = tia.finding(tia.proof("ghost", "c9"))
    block = tia.IssueAccountingTests.account(None, [tia.finding(p), ghost], [p])
    return json.loads(json.dumps(block, default=str))


def _claims():
    audited = dict(SQLI, audit_state="audited", reason="replayed")
    return [audited,
            dict(JWT, verdict="not_audited", audit_state="not_audited",
                 reason="the claimed route could not be resolved"),
            dict(JWT, verdict="unsupported_audit", audit_state="unsupported_audit",
                 reason="no procedure for this class")]


def _totals(claims):
    audited = sum(c["audit_state"] == "audited" for c in claims)
    fps = sum(c["verdict"] == "false_positive" for c in claims)
    return {"claims": len(claims), "audited": audited,
            "not_audited": sum(c["audit_state"] == "not_audited" for c in claims),
            "unsupported_audit": sum(c["audit_state"] == "unsupported_audit" for c in claims),
            "false_positives": fps if audited else None}


def clean_result():
    return {
        "experiment_preflight": {
            "schema_version": 2, "enabled": True,
            "tasks": [{"task_id": "t1", "status": "completed", "blocked_on": None},
                      {"task_id": "t2", "status": "deferred",
                       "blocked_on": {"category": "budget",
                                      "inputs": ["owning request budget exhausted"]}}],
            # A chain hypothesis with no compiler is advisory by design; not an experiment task.
            "advisory_tasks": [{"task_id": "h1", "status": "advisory"}]},
        "experiment_final_pass": {"ready": 1, "requeued": 0, "failed_unchanged": 0,
                                  "completed": 1, "failed": 0, "runs": 1, "stopped_by": None},
        "issue_accounting": _issue_accounting(),
        "coverage": {"requests_by_label": {"auth": 3, "csrf": 1}},
        "errors": [],
    }


class _RunDir:
    """A synthetic part-B run directory. Integrity files follow result.json unless a
    test breaks them on purpose."""

    def __init__(self, root: Path, name: str):
        self.path = root / name
        self.path.mkdir(parents=True)
        self.result = clean_result()
        claims = _claims()
        self.audit = {"accounts": [{"tag": "a", "fresh": True}], "claims": claims,
                      "audit_totals": _totals(claims)}
        for pin, doc in {"live-settings.json": {"model": "synthetic"},
                         "effective-config.json": {"engagement": {"experiments": True}},
                         "enabled-features.json": {"engagement_experiments": True}}.items():
            self.put(pin, json.dumps(doc))
        self.put("loaded-package.txt", "harness @ synthetic\n")
        self.canaries = self.path / "operator-canaries.json"
        self.canaries.write_text(json.dumps({"accounts": [
            {"username": "alice-synthetic", "token": f"Bearer {CANARY_TOKEN}",
             "cookie": f"sid={CANARY_COOKIE}; theme=dark"}]}), encoding="utf-8")
        self.save()

    def put(self, name, text):
        (self.path / name).write_text(text, encoding="utf-8")

    def save(self, *, integrity=True):
        data = json.dumps(self.result).encode()
        (self.path / "result.json").write_bytes(data)
        self.put("replay-audit.json", json.dumps(self.audit))
        if integrity:
            digest = hashlib.sha256(data).hexdigest()
            self.put("job-status.json", json.dumps({"status": "done", "result_sha256": digest,
                                                     "result_size_bytes": len(data)}))
            self.put("result-integrity.json", json.dumps({"delivery": "paged", "bytes": len(data),
                                                           "sha256": digest}))

    def evaluate(self, canaries=True):
        found = ar10_acceptance.canaries_from(self.canaries) if canaries else None
        return ar10_acceptance.evaluate(self.path, canaries=found)


EXPECTED_CLEAN = {"L1": "pass", "L2": "pass", "L3": "pass", "L4": "pass", "L5": "pass",
                  "L7": "pass", "L9": "unknown", "L10": "pass"}


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_dir(self, name="run"):
        return _RunDir(self.root, name)

    def statuses(self, doc):
        return {c: doc[c] for c in ar10_acceptance.CRITERIA}


class AcceptanceCriteriaTests(_Base):
    def test_clean_run_passes_every_computable_criterion_and_l9_is_unknown(self):
        doc = self.run_dir().evaluate()
        self.assertEqual(doc["schema"], ar10_acceptance.SCHEMA)
        self.assertEqual(self.statuses(doc), EXPECTED_CLEAN)
        self.assertIn("seed-capture binding", doc["reasons"]["L9"])
        # The real producer's orphan is listed for repair, so L5 passes on it.
        self.assertEqual(clean_result()["issue_accounting"]["counts"]["orphaned_proof_links"], 1)

    def _assert_only(self, run, criterion, status, canaries=True):
        doc = run.evaluate(canaries)
        expected = dict(EXPECTED_CLEAN, **{criterion: status})
        if not canaries and criterion != "L10":
            expected["L10"] = "unknown"
        self.assertEqual(self.statuses(doc), expected, doc["reasons"])
        return doc

    def test_each_violation_fails_its_criterion_only(self):
        def first_task(r):
            return r.result["experiment_preflight"]["tasks"][1]

        cases = {
            "L1 job not done": ("L1", lambda r: r.put("job-status.json", json.dumps({"status": "failed"}))),
            "L1 result changed after delivery": ("L1", lambda r: (
                r.result.update(extra=1), r.save(integrity=False))),
            "L1 same-size tamper": ("L1", lambda r: (r.path / "result.json").write_bytes(
                (r.path / "result.json").read_bytes().replace(b'"runs": 1', b'"runs": 2'))),
            "L2 feature manifest missing": ("L2", lambda r: (r.path / "enabled-features.json").unlink()),
            "L2 package pin empty": ("L2", lambda r: r.put("loaded-package.txt", "  \n")),
            "L3 ready task left advisory": ("L3", lambda r: (
                first_task(r).update(status="advisory", reason="ready experiment not selected"),
                r.save())),
            "L3 untyped blocked_on": ("L3", lambda r: (first_task(r).update(blocked_on=None), r.save())),
            "L4 no final pass, no reason": ("L4", lambda r: (
                r.result.update(experiment_final_pass=None), r.save())),
            "L5 orphan silently dropped": ("L5", lambda r: (
                r.result["issue_accounting"].update(orphaned_proof_links=[]), r.save())),
            "L5 orphan dropped, count adjusted": ("L5", lambda r: (
                r.result["issue_accounting"].update(orphaned_proof_links=[]),
                r.result["issue_accounting"]["counts"].update(orphaned_proof_links=0), r.save())),
            "L5 shown link unresolved": ("L5", lambda r: (
                r.result["issue_accounting"]["groups"][0]["proof_ids"].append("p-missing"), r.save())),
            "L7 claim without audit state": ("L7", lambda r: (
                r.audit["claims"][1].pop("audit_state"), r.save())),
            "L7 unaudited claim without reason": ("L7", lambda r: (
                r.audit["claims"][2].update(reason=""), r.save())),
            "L7 zero false positives without a procedure": ("L7", lambda r: (
                r.audit.update(claims=r.audit["claims"][1:],
                               audit_totals=dict(_totals(r.audit["claims"][1:]), false_positives=0)),
                r.save())),
            "L10 token leaked": ("L10", lambda r: (
                r.result.update(note=f"header was {CANARY_TOKEN}"), r.save())),
            "L10 cookie value leaked": ("L10", lambda r: (
                r.audit["claims"][0].update(observed=CANARY_COOKIE), r.save())),
            "L10 csrf metric redacted": ("L10", lambda r: (
                r.result["coverage"]["requests_by_label"].update(csrf="[REDACTED-SECRET]"), r.save())),
        }
        for label, (criterion, breaks) in cases.items():
            with self.subTest(label):
                run = self.run_dir(label.replace(" ", "-"))
                breaks(run)
                doc = self._assert_only(run, criterion, "fail")
                self.assertNotIn(CANARY_TOKEN, json.dumps(doc))
                self.assertNotIn(CANARY_COOKIE, json.dumps(doc))

    def test_a_recorded_reason_for_no_final_pass_passes_l4(self):
        for label, change in {
            "experiments disabled": lambda r: r.result["experiment_preflight"].update(enabled=False),
            "final pass error recorded": lambda r: r.result["errors"].append(
                {"phase": "experiments_final", "error": "RuntimeError: synthetic"}),
        }.items():
            with self.subTest(label):
                run = self.run_dir(label.replace(" ", "-"))
                run.result["experiment_final_pass"] = None
                change(run)
                run.save()
                self._assert_only(run, "L4", "pass")

    def test_a_missing_input_is_unknown_never_pass(self):
        cases = {
            "L1": lambda r: (r.path / "result-integrity.json").unlink(),
            "L3": lambda r: (r.result.pop("experiment_preflight"), r.save()),
            "L4": lambda r: (r.result.pop("experiment_final_pass"), r.save()),
            "L5": lambda r: (r.result.pop("issue_accounting"), r.save()),
            "L7": lambda r: (r.path / "replay-audit.json").unlink(),
        }
        for criterion, removes in cases.items():
            with self.subTest(criterion):
                run = self.run_dir(f"missing-{criterion}")
                removes(run)
                self._assert_only(run, criterion, "unknown")
        with self.subTest("L10 without a canary source"):
            self._assert_only(self.run_dir("no-canaries"), "L10", "unknown", canaries=False)
        with self.subTest("no result.json"):
            run = self.run_dir("no-result")
            (run.path / "result.json").unlink()
            doc = run.evaluate()
            for c in ("L3", "L4", "L5", "L9"):
                self.assertEqual(doc[c], "unknown", c)

    def test_canaries_come_from_secret_fields_only(self):
        found = ar10_acceptance.canaries_from(self.run_dir().canaries)
        self.assertIn(CANARY_TOKEN, found)
        self.assertIn(CANARY_COOKIE, found)
        self.assertNotIn("alice-synthetic", found)   # a username is not a secret field


class _Cli:
    @staticmethod
    def call(main, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()


class FreezeThenScoreTests(_Base):
    def _freeze(self, runs, out, *, sha=None, canaries=True):
        argv = ["--out-dir", str(out), "--mapping-sha256", sha or self.mapping_sha]
        for rid, arm, run in runs:
            argv += ["--repeat", rid, arm, str(run.path)]
            if canaries:
                argv += ["--canaries", rid, str(run.canaries)]
        return _Cli.call(ar10_freeze.main, argv)

    def setUp(self):
        super().setUp()
        self.mapping_path = self.root / "sealed" / "mapping.json"
        self.mapping_path.parent.mkdir()
        self.mapping_path.write_text(json.dumps(mapping()), encoding="utf-8")
        self.mapping_sha = hashlib.sha256(self.mapping_path.read_bytes()).hexdigest()

    def _score(self, out):
        scores = self.root / "scores.json"
        code, _, err = _Cli.call(ar10_scorer.main, ["--manifest", str(out / "freeze.json"),
                                                    "--mapping", str(self.mapping_path),
                                                    "--out", str(scores)])
        self.assertEqual(code, ar10_scorer.EXIT_OK, err)
        return {r["repeat_id"]: r for r in json.loads(scores.read_text(encoding="utf-8"))["repeats"]}

    def _check_end_to_end(self):
        runs = [(rid, rid[0], self.run_dir(rid)) for rid in ("A1", "B1", "A2", "B2", "A3", "B3")]
        broken = runs[1][2]
        broken.result["experiment_preflight"]["tasks"][1]["status"] = "advisory"   # B1 breaks L3
        broken.save()
        out = self.root / "frozen"
        code, stdout, err = self._freeze(runs, out)
        self.assertEqual(code, 0, err)
        manifest = json.loads((out / "freeze.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["mapping_sha256"], self.mapping_sha)
        for row in manifest["repeats"]:
            self.assertEqual(sorted(row["files"]),
                             ["acceptance.json", "replay-audit.json", "result.json"])
            self.assertEqual(sorted(p.name for p in (out / row["export_dir"]).iterdir()),
                             sorted(row["files"]))
        frozen_text = stdout + err + "".join(p.read_text(encoding="utf-8")
                                             for p in out.rglob("acceptance.json"))
        self.assertNotIn(CANARY_TOKEN, frozen_text)
        self.assertNotIn(CANARY_COOKIE, frozen_text)
        report = self._score(out)
        hard_a = report["A1"]["hard_failures"]
        # The scorer reads what the freeze computed; L8 it takes from the audit itself.
        self.assertEqual(hard_a["criteria"], dict(EXPECTED_CLEAN, L8="pass"))
        self.assertEqual(hard_a["overall"], "unknown")   # L9 is not exported yet
        self.assertEqual(report["B1"]["hard_failures"]["criteria"]["L3"], "fail")
        self.assertEqual(report["B1"]["hard_failures"]["overall"], "fail")
        return report

    def test_freeze_writes_acceptance_the_scorer_reads(self):
        self._check_end_to_end()

    def test_control_without_computed_acceptance_the_scorer_sees_only_unknowns(self):
        with patch.object(ar10_acceptance, "evaluate", lambda run_dir, canaries=None: {}):
            with self.assertRaises(AssertionError):
                self._check_end_to_end()

    def test_the_freeze_refuses_and_writes_nothing(self):
        cases = {
            "bad mapping sha": dict(sha="not-a-sha"),
            "missing replay audit": dict(prep=lambda r: (r.path / "replay-audit.json").unlink()),
            "canary file unreadable": dict(prep=lambda r: r.canaries.unlink()),
        }
        for label, case in cases.items():
            with self.subTest(label):
                fresh = self.run_dir(label.replace(" ", "-"))
                (case.get("prep") or (lambda r: None))(fresh)
                out = self.root / ("out-" + label.replace(" ", "-"))
                code, _, err = self._freeze([("A1", "A", fresh)], out, sha=case.get("sha"))
                self.assertEqual(code, 2, label)
                self.assertIn("refused", err)
                self.assertFalse(out.exists(), label)

    def test_an_existing_freeze_is_never_overwritten(self):
        run = self.run_dir("A1")
        out = self.root / "frozen"
        self.assertEqual(self._freeze([("A1", "A", run)], out)[0], 0)
        before = {p: p.read_bytes() for p in out.rglob("*") if p.is_file()}
        run.result["note"] = "changed"
        run.save()
        code, _, err = self._freeze([("A1", "A", run)], out)
        self.assertEqual(code, 2, err)
        self.assertEqual({p: p.read_bytes() for p in out.rglob("*") if p.is_file()}, before)


if __name__ == "__main__":
    unittest.main()
