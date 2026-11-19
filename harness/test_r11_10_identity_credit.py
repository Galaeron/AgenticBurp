"""R11-10: an identity's missing capture is not a gap for a caller-independent check.

The coverage matrix has one cell per (identity, endpoint, check). An identity with no
capture of an endpoint used to end every one of its cells there as
`missing_principal`, whatever the check. For a check whose verdict does not depend on
the caller (`Check.caller_independent`, set in the catalog), the cell is now credited
to the identity that holds the capture: `covered_by_identity` when that identity's
cell has a conclusive verdict, `open_on_identity` when it has none yet (the gap is
counted once, on that cell). The credited cell is neither a gap nor a send of its
own identity. Identity-bound checks (access control, sessions, authentication,
exposure, cross-identity writes) keep `missing_principal`: nothing replays another
identity's capture with this identity's credentials.

Through the production builder (`build_coverage_driven`) and, at caller level,
`investigate_engagement` with the real builder and crawl (the R11 identity-probe
fixture), where an identity the crawl never ran holds no capture.
"""
import asyncio
import unittest
from types import SimpleNamespace

import harness.test_identity_probe_variants as probe_fixture
from harness.coverage_model import CHECK_CATALOG, CHECKS_BY_ID, _CALLER_INDEPENDENT_CHECKS
from harness.coverage_tracker import CoverageTracker, build_coverage_driven

_EP = "POST /search"
_NO_CAPTURE = {"status": "needs_prerequisite", "reason_code": "missing_principal",
               "reason": "capture the request as this identity"}
# Rows whose verdict is about who calls (the owner's list in IMPROVEMENT_BACKLOG R11-10).
_BOUND_PREFIXES = ("WSTG-ATHZ-", "WSTG-ATHN-", "WSTG-SESS-", "AV-EXPOSURE-",
                   "AV-WRITE-XID-", "AV-WRITE-AUTHOR-")


def _state():
    return SimpleNamespace(endpoints={_EP: SimpleNamespace(
        path="/search", method="POST", access={}, reachable_roles=[], object_scoped=False,
        findings=[], template=None)})


def _only_a_holds_the_capture(identity, method, path, check):
    """The readiness r11 recorded: B has no capture, so every B cell is blocked."""
    return dict(_NO_CAPTURE) if identity == "userB" else {"status": "ready"}


def _leg(status="not_confirmed", calls=None):
    async def run_leg(identity, method, path, check):
        if calls is not None:
            calls.append((identity, check.id))
        return SimpleNamespace(status=status, summary=f"{check.confirmation} ran", sent_count=1,
                               validator=check.confirmation)
    return run_leg


def _drive(readiness=_only_a_holds_the_capture, *, status="not_confirmed", calls=None,
           tracker_out=None):
    return asyncio.run(build_coverage_driven(
        _state(), ["userA", "userB"], _leg(status, calls), readiness=readiness, budget=500,
        tracker_out=tracker_out))


def _rows(report, identity=None):
    rows = {(c["identity"], c["check"]): c for c in report["phase_ledger"]["cells"]}
    return rows if identity is None else {k[1]: v for k, v in rows.items() if k[0] == identity}


class CatalogSplitTests(unittest.TestCase):
    """The split comes from the catalog rows, not from the cell."""

    def test_every_named_row_exists_and_only_those_rows_are_caller_independent(self):
        self.assertLessEqual(_CALLER_INDEPENDENT_CHECKS, set(CHECKS_BY_ID))
        self.assertEqual({c.id for c in CHECK_CATALOG if c.caller_independent},
                         set(_CALLER_INDEPENDENT_CHECKS))

    def test_identity_bound_rows_are_never_caller_independent(self):
        bound = [c.id for c in CHECK_CATALOG if c.id.startswith(_BOUND_PREFIXES)]
        self.assertTrue(bound)
        self.assertEqual([cid for cid in bound if CHECKS_BY_ID[cid].caller_independent], [])
        # Caller-dependent beyond the owner's list (an admin may set a privileged
        # field; verb tampering is an access-control bypass), and manual rows.
        for cid in ("WSTG-INJT-20", "AV-MASSASSIGN-02", "WSTG-INJT-03", "WSTG-CONF-09",
                    "WSTG-BUSL-09"):
            self.assertFalse(CHECKS_BY_ID[cid].caller_independent, cid)

    def test_injection_rows_are_caller_independent(self):
        for cid in ("WSTG-INJT-05", "WSTG-INJT-01", "WSTG-INJT-12", "WSTG-ERRH-01",
                    "WSTG-CONF-14"):
            self.assertTrue(CHECKS_BY_ID[cid].caller_independent, cid)


class CreditTests(unittest.TestCase):
    """Endpoint captured only as A; B holds no capture of it."""

    def test_a_injection_verdict_covers_b_cell(self):
        calls = []
        report = _drive(calls=calls)
        b = _rows(report, "userB")["WSTG-INJT-05"]
        self.assertEqual(_rows(report, "userA")["WSTG-INJT-05"]["terminal_reason"], "conclusive")
        self.assertEqual(b["terminal_reason"], "covered_by_identity")
        self.assertEqual(b["covered_by"], "userA")
        self.assertTrue(b["detail"].startswith("covered_by_identity:userA:"), b["detail"])
        self.assertNotEqual(b["terminal_reason"], "missing_principal")
        # Not B's own send: nothing ran as B, and the cell has no execution.
        self.assertEqual([c for c in calls if c[0] == "userB"], [])
        for field in ("attempted", "sent", "fresh_sent", "conclusive"):
            self.assertFalse(b[field], field)
        self.assertEqual(b["fresh_sends"], 0)
        self.assertEqual(b["observation_status"], "inconclusive")

    def test_negative_control_access_control_check_stays_missing_principal(self):
        report = _drive()
        rows = _rows(report, "userB")
        for cid in ("WSTG-ATHZ-03", "AV-WRITE-XID-01", "AV-WRITE-AUTHOR-01", "WSTG-SESS-05"):
            self.assertEqual(rows[cid]["terminal_reason"], "missing_principal", cid)
            self.assertNotIn("covered_by", rows[cid])
            self.assertEqual(_rows(report, "userA")[cid]["terminal_reason"], "conclusive", cid)

    def test_credited_cells_are_not_gaps_and_not_sends(self):
        tracker_out = []
        report = _drive(tracker_out=tracker_out)
        tracker = tracker_out[0]
        credited = {k[2] for k in tracker.credited}
        self.assertIn("WSTG-INJT-05", credited)
        gaps = {(r["identity"], r["check"]) for r in report["not_tested"]}
        self.assertFalse({("userB", cid) for cid in credited} & gaps)
        # The identity-bound cells are still listed as gaps.
        self.assertIn(("userB", "WSTG-ATHZ-03"), gaps)
        b_rows = _rows(report, "userB")
        self.assertEqual(report["credited_by_identity"]["cells"], len(credited))
        self.assertEqual(report["credited_by_identity"]["by_cell_identity"], {"userB": len(credited)})
        self.assertEqual(report["credited_by_identity"]["by_covering_identity"],
                         {"userA": len(credited)})
        self.assertEqual(sum(b_rows[cid]["terminal_reason"] == "missing_principal"
                             for cid in b_rows),
                         sum(1 for cid in b_rows if b_rows[cid]["terminal_reason"]
                             not in {"covered_by_identity", "open_on_identity",
                                     "not_applicable_on_identity", "not_applicable"}))
        # B sent nothing: the run's sends and attempts are A's alone.
        self.assertEqual(sum(r["fresh_sends"] for r in b_rows.values()), 0)
        self.assertEqual(report["phase_ledger"]["counts"]["attempted"],
                         sum(r["attempted"] for r in _rows(report, "userA").values()))
        self.assertEqual(report["attempted"], report["conclusive"])
        self.assertEqual(report["conclusive"], sum(r["conclusive"] for r in _rows(report).values()
                                                   if r["identity"] == "userA"))

    def test_no_verdict_on_a_is_open_on_that_identity_and_counted_once(self):
        report = _drive(status="skipped")
        self.assertEqual(_rows(report, "userB")["WSTG-INJT-05"]["terminal_reason"],
                         "open_on_identity")
        gaps = [(r["identity"], r["check"]) for r in report["not_tested"]
                if r["check"] == "WSTG-INJT-05"]
        self.assertEqual(gaps, [("userA", "WSTG-INJT-05")])

    def test_no_identity_holds_the_capture_stays_missing_principal(self):
        report = _drive(lambda *a: dict(_NO_CAPTURE))
        self.assertEqual(report["credited_by_identity"]["cells"], 0)
        for ident in ("userA", "userB"):
            self.assertEqual(_rows(report, ident)["WSTG-INJT-05"]["terminal_reason"],
                             "missing_principal")

    def test_orchestrator_disposition_is_credited_the_same_way(self):
        def readiness(identity, method, path, check):
            if identity == "userA":
                return {"status": "ready"}
            if check.caller_independent:
                return {"status": "needs_prerequisite", "reason_code": "covered_by_identity",
                        "covered_by": "userA", "reason": "userA holds the capture"}
            return dict(_NO_CAPTURE)
        a, b = _drive(), _drive(readiness)
        self.assertEqual({k: r["terminal_reason"] for k, r in _rows(a).items()},
                         {k: r["terminal_reason"] for k, r in _rows(b).items()})

    def test_an_open_credit_becomes_covered_when_the_peer_concludes_and_is_idempotent(self):
        tracker_out = []
        _drive(status="skipped", tracker_out=tracker_out)
        tracker = tracker_out[0]
        key = ("userB", _EP, "WSTG-INJT-05")
        self.assertEqual(tracker.credited[key]["outcome"], "open_on_identity")
        tracker._record_leg_result("userA", _EP, CHECKS_BY_ID["WSTG-INJT-05"], SimpleNamespace(
            status="not_confirmed", summary="ran later", sent_count=1, validator="sqlmap"))
        first = tracker.report()
        self.assertEqual(tracker.credited[key]["outcome"], "covered_by_identity")
        second = tracker.report()
        self.assertEqual(first["credited_by_identity"], second["credited_by_identity"])
        self.assertEqual(first["not_tested"], second["not_tested"])

    def test_a_tracker_with_no_readiness_credits_nothing(self):
        tracker = CoverageTracker()
        tracker.build({_EP: {"method": "POST", "path": "/search", "methods": ("POST",)}},
                      ["userA", "userB"], {})
        self.assertEqual(tracker.credit_caller_independent(), 0)


class DriveCallerTests(probe_fixture._EngagementCallerBase, unittest.TestCase):
    """investigate_engagement with the real builder and crawl: the crawl runs as
    anonymous and user1 only, so ghost holds no capture of either endpoint."""

    _investigate = probe_fixture.DriveCallerTests._investigate
    cells = staticmethod(probe_fixture.DriveCallerTests.cells)

    def test_ghost_caller_independent_cells_are_credited_and_bound_cells_stay_blocked(self):
        result, calls = self._investigate([probe_fixture.ANON, probe_fixture.USER1,
                                           probe_fixture.GHOST],
                                          crawled=[probe_fixture.ANON, probe_fixture.USER1])
        ghost = [c for c in self.cells(result, "ghost") if c["shape_applicable"]]
        credited = [c for c in ghost if "covered_by" in c]
        blocked = [c for c in ghost if c["terminal_reason"] == "missing_principal"]
        self.assertTrue(credited)
        self.assertTrue(all(CHECKS_BY_ID[c["check"]].caller_independent for c in credited))
        self.assertTrue(all(c["covered_by"] in {"anonymous", "user1"} for c in credited))
        self.assertTrue(any(c["terminal_reason"] == "covered_by_identity" for c in credited))
        # The negative control: every identity-bound cell of ghost stays blocked.
        self.assertTrue(blocked)
        self.assertTrue(all(not CHECKS_BY_ID[c["check"]].caller_independent for c in blocked))
        self.assertTrue({"WSTG-ATHZ-02", "WSTG-ATHZ-04"} <= {c["check"] for c in blocked})
        # Nothing ran as ghost, and its credited cells are not its sends.
        self.assertFalse([c for c in calls if c[1] == "Bearer ghost-token"], calls)
        self.assertTrue(all(not c["attempted"] and not c["sent"] and not c["fresh_sends"]
                            for c in credited))
        # The prerequisite blocks count only the identity-bound checks.
        blocks = [b for b in result["prerequisite_blocks"] if b["identity"] == "ghost"]
        self.assertEqual(sum(b["checks_affected"] for b in blocks), len(blocked))
        # And the gap list does not name a credited cell.
        gaps = {(r["identity"], r["endpoint"], r["check"]) for r in result["coverage"]["not_tested"]}
        self.assertFalse({("ghost", c["endpoint"], c["check"]) for c in credited} & gaps)
        self.assertEqual(result["coverage"]["credited_by_identity"]["cells"], len(credited))


if __name__ == "__main__":
    unittest.main()
