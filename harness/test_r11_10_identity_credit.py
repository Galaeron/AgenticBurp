"""R11-10: an identity's missing capture is not a gap for a caller-independent check.

The coverage matrix has one cell per (identity, endpoint, check). An identity with no
capture of an endpoint used to end every one of its cells there as
`missing_principal`, whatever the check. For a check whose verdict does not depend on
the caller (`Check.caller_independent`, set in the catalog), the cell is now credited
to the identity that holds the capture: `covered_by_identity` when that identity's
cell has a conclusive verdict, `open_on_identity` when it has none yet (the gap is
counted once, on that cell). The credited cell is neither a gap nor a send of its
own identity. Identity-bound checks (access control, sessions, authentication,
exposure, cross-identity writes) keep `missing_principal` unless credential
substitution (owner decision 2026-11-19, below) replays another identity's capture
with only this identity's credentials.

Through the production builder (`build_coverage_driven`) and, at caller level,
`investigate_engagement` with the real builder and crawl (the R11 identity-probe
fixture), where an identity the crawl never ran holds no capture.
"""
import asyncio
import unittest
from types import SimpleNamespace
from urllib.parse import urlsplit

import harness.test_identity_probe_variants as probe_fixture
from harness import safety_gate, worklist_investigator
from harness.coverage_model import CHECK_CATALOG, CHECKS_BY_ID, _CALLER_INDEPENDENT_CHECKS
from harness.coverage_tracker import CoverageTracker, build_coverage_driven
from harness.engagement import capture_identity_key, capture_variant, substituted_variant
from harness.validators.base import ValidationResult

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
                                          crawled=[probe_fixture.ANON, probe_fixture.USER1],
                                          substitution=False)
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


# --- Credential substitution (owner decision 2026-11-19) -------------------------

_ACCESS_CHECKS = {"WSTG-ATHZ-02", "WSTG-ATHZ-04"}   # the cross_identity leg


def _sending_recorder(calls, confirm_as=None):
    """The cross_identity leg, replaced: it sends the exchange it is handed through
    the safety gate (inside the run, so the run's transport and gate admit it) and
    records the request's headers and the response it was handed."""
    async def validate(self, finding, exchange, *args, **kwargs):
        async with safety_gate.GatedAsyncClient(safety_gate.get_default_gate(),
                                                "cross_identity") as client:
            await client.request(exchange.method, exchange.url,
                                 headers=exchange.request_headers)
        calls.append((urlsplit(exchange.url).path, dict(exchange.request_headers),
                      exchange.response_status, exchange.response_body))
        confirmed = (confirm_as is not None
                     and exchange.request_headers.get("Authorization") == confirm_as)
        return ValidationResult("cross_identity", "confirmed" if confirmed else "not_confirmed",
                                "idor", confirmed=confirmed, confidence=0.9 if confirmed else 0.0,
                                summary="recorded")
    return validate


def _credentials(headers):
    return {k.lower(): v for k, v in headers.items() if k.lower() != "content-type"}


class SubstitutionDriveTests(probe_fixture._EngagementCallerBase, unittest.TestCase):
    """The crawl runs without one identity, so it holds no capture of either
    endpoint; its access-control cells replay another identity's capture."""

    _investigate = probe_fixture.DriveCallerTests._investigate
    cells = staticmethod(probe_fixture.DriveCallerTests.cells)

    def test_a_substituted_read_carries_only_the_target_identity_credentials(self):
        result, calls = self._investigate(
            [probe_fixture.ANON, probe_fixture.USER1, probe_fixture.GHOST],
            crawled=[probe_fixture.ANON, probe_fixture.USER1], validate=_sending_recorder)
        ghost = [c for c in calls if c[1].get("Authorization") == "Bearer ghost-token"]
        self.assertEqual(sorted({c[0] for c in ghost}), ["/api/Products/1", "/api/Users"])
        for path, headers, status, body in ghost:
            # Only ghost's credential, never the source capture's.
            self.assertEqual(_credentials(headers), {"authorization": "Bearer ghost-token"})
            self.assertFalse(any("user1-token" in str(v) for v in headers.values()))
            # The source identity's response is not handed over as ghost's.
            self.assertIsNone(status)
            self.assertEqual(body, "")
        rows = [c for c in self.cells(result, "ghost") if c["check"] in _ACCESS_CHECKS]
        self.assertTrue(rows)
        self.assertTrue(all(c["sent"] and c["terminal_reason"] != "missing_principal"
                            for c in rows), rows)
        # Provenance on the cell: whose capture, whose credentials.
        self.assertTrue(all(c["detail"].startswith("substituted_from:")
                            and "with ghost's credentials substituted" in c["detail"]
                            for c in rows), rows)
        # Only the passive leg (it judges the captured response) stays blocked.
        blocked = [c for c in self.cells(result, "ghost")
                   if c["terminal_reason"] == "missing_principal"]
        self.assertTrue(blocked)
        self.assertEqual({c["confirmation"] for c in blocked}, {"content_exposure"})

    def test_an_anonymous_target_is_no_longer_missing_principal(self):
        """The crawl ran as user1 only. Anonymous's access-control cells get past
        the missing capture (user1's is substituted) and stop at the leg's own
        prerequisite, and nothing is sent as anonymous with user1's token."""
        result, calls = self._investigate([probe_fixture.ANON, probe_fixture.USER1],
                                          crawled=[probe_fixture.USER1],
                                          validate=_sending_recorder)
        rows = [c for c in self.cells(result, "anonymous") if c["check"] in _ACCESS_CHECKS]
        self.assertTrue(rows)
        self.assertFalse([c for c in rows if c["terminal_reason"] == "missing_principal"], rows)
        self.assertFalse([b for b in result["prerequisite_blocks"]
                          if b["identity"] == "anonymous" and b["checks_affected"] > 1])
        self.assertTrue(all(c[1].get("Authorization") == "Bearer user1-token" for c in calls))

    def test_the_switch_off_keeps_missing_principal(self):
        result, calls = self._investigate(
            [probe_fixture.ANON, probe_fixture.USER1, probe_fixture.GHOST],
            crawled=[probe_fixture.ANON, probe_fixture.USER1], validate=_sending_recorder,
            substitution=False)
        self.assertFalse([c for c in calls if c[1].get("Authorization") == "Bearer ghost-token"])
        rows = [c for c in self.cells(result, "ghost") if c["check"] in _ACCESS_CHECKS]
        self.assertTrue(rows)
        self.assertTrue(all(c["terminal_reason"] == "missing_principal" and not c["sent"]
                            for c in rows), rows)

    def test_a_confirmed_finding_says_it_was_substituted(self):
        def confirming(calls):
            return _sending_recorder(calls, confirm_as="Bearer ghost-token")
        result, calls = self._investigate(
            [probe_fixture.ANON, probe_fixture.USER1, probe_fixture.GHOST],
            crawled=[probe_fixture.ANON, probe_fixture.USER1], validate=confirming)
        mine = [f for f in result["findings"] if f.get("identity") == "ghost"
                and f.get("confirmation_method") == "cross_identity"]
        self.assertTrue(mine, [sorted(f) for f in result["findings"]])
        for finding in mine:
            self.assertTrue(finding["credential_substitution"])
            self.assertIn(finding["replayed_from_identity"], {"anonymous", "user1"})
            self.assertTrue(finding["summary"].startswith("substituted_from:"))
        # No finding of an identity's own replay claims a substitution.
        self.assertFalse([f for f in result["findings"] if f.get("identity") != "ghost"
                          and f.get("credential_substitution")])


_SOURCE = {"Authorization": "Bearer source-secret-token", "Cookie": "sid=cookie-secret-value"}
_TARGET = {"Authorization": "Bearer target-token"}


def _post_capture(body, url="http://127.0.0.1:9/api/items"):
    return capture_variant({"url": url, "method": "POST",
                            "request_headers": dict(_SOURCE, **{"Content-Type": "application/json"}),
                            "request_body": body, "response_status": 201,
                            "response_headers": {}, "response_body": '{"ok": true}'})


class SubstitutedVariantTests(unittest.TestCase):
    def test_the_variant_is_rekeyed_and_carries_its_provenance(self):
        source = _post_capture('{"name": "x"}')
        moved = substituted_variant(source, capture_identity_key(_TARGET), "src", _SOURCE)
        self.assertEqual(moved["identity_key"], capture_identity_key(_TARGET))
        self.assertEqual(moved["substituted_from"], "src")
        self.assertEqual(moved["substituted_capture_id"], source["capture_id"])
        self.assertNotEqual(moved["capture_id"], source["capture_id"])
        self.assertEqual((moved["response_status"], moved["response_body"]), (None, ""))
        self.assertEqual(moved["template"], source["template"])

    def test_a_capture_carrying_a_credential_is_not_substituted(self):
        target = capture_identity_key(_TARGET)
        for body in ('{"csrfToken": "abc", "name": "x"}', "_csrf=abc&name=x",
                     '{"password": "pw1"}', '{"note": "cookie-secret-value"}',
                     '{"x": "source-secret-token"}'):
            with self.subTest(body=body):
                self.assertIsNone(substituted_variant(_post_capture(body), target, "src", _SOURCE))
        self.assertIsNone(substituted_variant(
            _post_capture("{}", url="http://127.0.0.1:9/api/items?session=abc"),
            target, "src", _SOURCE))
        # A field that only looks alike is kept.
        self.assertIsNotNone(substituted_variant(
            _post_capture('{"author": "a", "inside": 1}'), target, "src", _SOURCE))

    def test_a_substituted_write_is_refused_without_allow_mutating_replay(self):
        """The substituted exchange is built like any replay (target headers only)
        and the gate classifies it as the mutating send it is."""
        variant = substituted_variant(_post_capture('{"name": "x"}'),
                                      capture_identity_key(_TARGET), "src", _SOURCE)
        role = SimpleNamespace(role="user", headers=dict(_TARGET))
        node, = worklist_investigator.captured_nodes(
            {"method": "POST", "path": "/api/items", "capture_variants": [variant]},
            "http://127.0.0.1:9", [role], include_probes=True)
        ex = worklist_investigator._seed_exchange("http://127.0.0.1:9", node, role.headers, "")
        self.assertEqual(_credentials(ex.request_headers), {"authorization": "Bearer target-token"})
        for allow, expected in ((False, False), (True, True)):
            gate = safety_gate.SafetyGate(safety_gate.SafetyGateConfig(
                active_enabled=True, allow_mutating_replay=allow,
                allowed_hosts=frozenset({"127.0.0.1"})))
            decision = gate.authorize(validator_name="write_integrity", method=ex.method,
                                      url=ex.url, body=ex.request_body, finding_id="f")
            with self.subTest(allow_mutating_replay=allow):
                self.assertEqual(decision.allowed, expected, decision.reason)
                self.assertEqual(decision.tier, safety_gate.ActionRiskTier.MUTATING)

    def test_an_anonymous_target_sends_no_credentials(self):
        variant = substituted_variant(_post_capture('{"name": "x"}'),
                                      capture_identity_key({}), "src", _SOURCE)
        anonymous = SimpleNamespace(role="anonymous", headers={})
        node, = worklist_investigator.captured_nodes(
            {"method": "POST", "path": "/api/items", "capture_variants": [variant]},
            "http://127.0.0.1:9", [anonymous], include_probes=True)
        self.assertIs(node["probe_session"], anonymous)
        ex = worklist_investigator._seed_exchange("http://127.0.0.1:9", node, anonymous.headers, "")
        self.assertEqual(_credentials(ex.request_headers), {})
        self.assertFalse(any(secret in str(ex.request_headers) + ex.url + ex.request_body
                             for secret in ("source-secret-token", "cookie-secret-value")))

    def test_passive_mode_forces_the_switch_off(self):
        from harness.config_schema import _PASSIVE_FORCE_OFF_KNOBS
        self.assertIn("engagement.coverage_identity_substitution", _PASSIVE_FORCE_OFF_KNOBS)


if __name__ == "__main__":
    unittest.main()
