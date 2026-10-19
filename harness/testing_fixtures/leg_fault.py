"""Fault injection for evidence-bound confirmation tests (I11).

A control that stays green when its leg is disconnected is hollow evidence: a
validator that never reached the target also "does not confirm". This helper
severs the async HTTP egress every validator and RunContext transport rides on
(`httpx.AsyncClient.send`) and re-runs the bound tests of an `EvidenceCase`; each
must then FAIL or ERROR. A bound test that still passes with the leg cut is not
evidence for that leg.

The inner runs write their (failing) evidence into a throwaway directory, never
into the run's evidence directory, so the fault runs cannot clobber real evidence.
"""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx


@contextlib.contextmanager
def severed_egress():
    """Every async HTTP send raises ConnectError: the leg cannot reach its target."""
    async def _refuse(self, request, *args, **kwargs):
        raise httpx.ConnectError("leg disconnected by fault injection", request=request)

    with mock.patch.object(httpx.AsyncClient, "send", _refuse):
        yield


def bound_test_names(case_cls: type[unittest.TestCase]) -> list[str]:
    """Names of the test methods carrying an `@evidence_for` binding, sorted."""
    return sorted(name for name in dir(case_cls)
                  if name.startswith("test")
                  and hasattr(getattr(case_cls, name), "__coverage_evidence__"))


def outcomes_with_leg_severed(case_cls: type[unittest.TestCase],
                              names: list[str]) -> dict[str, str]:
    """Run each bound test with egress severed: name -> failed | errored | skipped | passed.

    Class-level fixtures (`setUpClass`) must already be up; per-test `setUp` and
    cleanups run normally inside each inner run."""
    outcomes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="leg_fault_") as tmp:
        for name in names:
            inner = case_cls(name)
            inner.evidence_dir_override = Path(tmp)   # keep fault runs out of the run's evidence
            result = unittest.TestResult()
            with severed_egress():
                inner.run(result)
            if result.errors:
                outcomes[name] = "errored"
            elif result.failures:
                outcomes[name] = "failed"
            elif result.skipped:
                outcomes[name] = "skipped"
            else:
                outcomes[name] = "passed"
    return outcomes
