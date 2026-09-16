"""
`EvidenceCase` -- a unittest base that records coverage evidence FROM THE RUNNER.

The reviewer's issue 2: evidence must reflect what actually happened in the run, and
a failed or skipped test must not leave an old passing artifact standing. So the
STATUS is captured by the test runner (by observing the shared TestResult around this
test), not asserted by the test body. The test body records only the reproducible
OBSERVATION; whether it passed, failed, or skipped is determined by `run()` and
written into the run-specific, run-id-bound evidence directory.

Usage:

    class MyTest(EvidenceCase):
        @evidence_for(check_id="AV-X", aspect="...", label="fixture_invariant",
                      invariant="...")
        def test_thing(self):
            ...
            self.record_observation({...})   # reproducible data (optional)
            self.assertTrue(...)             # a failure here -> a 'fail' artifact

A decorated test that fails or errors writes a `fail` artifact; one that is skipped
writes a `skipped` artifact; only a clean pass writes a `pass` artifact. Tests can
override `evidence_dir_override` (used by the mechanism's own tests) to redirect the
output; production tests leave it None to use the run-specific directory.
"""
from __future__ import annotations

import logging
import unittest

import harness.coverage_manifest as cm

log = logging.getLogger("harness.coverage_evidence_case")


def evidence_for(*, check_id: str, aspect: str, label: str = "automated",
                 invariant: str = ""):
    """Mark a test method as the regression behind one requirement aspect."""
    def deco(fn):
        fn.__coverage_evidence__ = {"check_id": check_id, "aspect": aspect,
                                    "label": label, "invariant": invariant}
        return fn
    return deco


class EvidenceCase(unittest.TestCase):
    #: tests may point this at a temp dir; None -> the run-specific evidence dir.
    evidence_dir_override = None

    def record_observation(self, observation: dict) -> None:
        """Record the reproducible observation for this test's evidence artifact."""
        self._coverage_observation = dict(observation or {})

    def _coverage_test_id(self) -> str:
        cls = type(self)
        return f"{cls.__module__}.{cls.__qualname__}.{self._testMethodName}"

    def run(self, result=None):
        created = result is None
        if created:
            result = self.defaultTestResult()
        meta = getattr(getattr(self, self._testMethodName, None),
                       "__coverage_evidence__", None)
        before = (len(result.failures), len(result.errors), len(result.skipped))
        super().run(result)
        if not meta:
            return result
        after = (len(result.failures), len(result.errors), len(result.skipped))
        if after[1] > before[1]:            # unexpected exception
            status, reason = cm.TestStatus.FAIL, "test errored"
        elif after[0] > before[0]:          # assertion failed
            status, reason = cm.TestStatus.FAIL, "assertion failed"
        elif after[2] > before[2]:          # skipped
            status, reason = cm.TestStatus.SKIPPED, "test skipped"
        else:
            status, reason = cm.TestStatus.PASS, "assertions held"
        try:
            cm.write_evidence(
                check_id=meta["check_id"], aspect=meta["aspect"], status=status,
                test_id=self._coverage_test_id(), kind=meta["label"],
                invariant=meta.get("invariant", ""), reason=reason,
                observation=getattr(self, "_coverage_observation", {}) or {},
                evidence_dir=self.evidence_dir_override)
        except Exception as e:  # never let evidence-writing mask the test result
            log.warning("EvidenceCase: failed to write evidence for %s: %s",
                        self._coverage_test_id(), e)
        return result
