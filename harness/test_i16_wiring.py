"""I16 wiring (Python side): operator declarations reach the engagement, and a
finding's next step reaches every export.

RV-S made an engagement's `protected_paths` confirmable and RV-T did the same for
`owners`, but nothing set either list: `investigate_engagement` builds its state
fresh, so only the config source was live. The investigate request now carries both
lists to `investigate_engagement`, which merges them into the state after discovery.

The chain cases drive the real `investigate_engagement`, `_confirm` dispatcher and
`missing_auth_probe` against RV-S's owned loopback server, passing the lists as the
new keyword arguments (the builder double no longer seeds the state). Ownership uses
RV-T's X2 fixture. The route cases go through `POST /engagement/{host}/investigate`.

W1  a route listed in the request's `protected_paths` confirms (source "engagement").
W2  an unlisted route stays a candidate, and its next step says how to declare it.
W3  an empty list changes nothing: the same requests and findings as no list.
W4  a listed route that denies anonymous access gives no finding.
W5  `owners` passed to the engagement confirms the declared crossing only.
W6  the route forwards the lists; omitted lists are not passed; wrong types are 422;
    the journal context key is unchanged unless a list is declared.
W7  the issue export and SARIF carry `suggested_test`; a SARIF import reads it back.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from harness import issues, sarif_adapter
from harness import test_principal_access_matrix as matrix_fixture
from harness import test_protected_routes_rvs as rvs
from harness.orchestrator import Orchestrator


def _declaring(**declarations):
    """Pass `declarations` to every `investigate_engagement` call, as the
    investigate route does with the request's lists."""
    real = Orchestrator.investigate_engagement

    async def declared(self, *args, **kwargs):
        return await real(self, *args, **kwargs, **declarations)
    return patch.object(Orchestrator, "investigate_engagement", declared)


def _denied(path, headers):
    """A protected route: anonymous requests are refused."""
    if headers.get("authorization") == rvs._TOKEN:
        return 200, rvs._REPORT
    return 401, '{"error": "login required"}'


# ------------------------------------------------------------------ W1-W4
class ProtectedPathsReachTheChainTests(rvs._ChainCase, unittest.TestCase):
    # unittest.TestCase is listed so test_no_orphan_test_files proves the ancestry statically.

    def test_listed_route_confirms_from_the_engagement_list(self):
        with _declaring(protected_paths=["/reports/*"]):
            found, server = self._run_chain(rvs._leak, ["/reports/q3"])
        self._assert_confirmed(found["/reports/q3"], "/reports/*", "engagement")
        self._assert_anonymous_then_baseline(server.sent_to("/reports/q3"))

    def test_unlisted_route_stays_a_candidate_with_a_declaration_hint(self):
        with _declaring(protected_paths=["/admin/**"]):
            found, server = self._run_chain(rvs._leak, ["/reports/q3"], via="label")
        self._assert_not_confirmed(found["/reports/q3"], "label")
        self.assertEqual(len(server.sent_to("/reports/q3")), 1, "only the anonymous replay")
        hint = found["/reports/q3"][0].get("suggested_test", "")
        self.assertIn("authz.protected_paths", hint)
        self.assertIn(repr(server.key), hint, "the hint names this target's config key")
        self.assertIn("GET /reports/q3", hint)
        self.assertIn("protected_paths", hint.split("authz.protected_paths", 1)[1],
                      "the hint also names the investigate request's field")

    def test_listed_route_has_no_declaration_hint(self):
        with _declaring(protected_paths=["/reports/*"]):
            found, _ = self._run_chain(rvs._leak, ["/reports/q3"], via="label")
        self.assertTrue(found["/reports/q3"][0].get("confirmed"))
        self.assertNotIn("authz.protected_paths", found["/reports/q3"][0].get("suggested_test", ""))

    def test_empty_list_changes_nothing(self):
        runs = {}
        for name, declarations in (("absent", {}), ("empty", {"protected_paths": [], "owners": []})):
            with self.subTest(name), _declaring(**declarations):
                for via in ("shape", "label"):
                    found, server = self._run_chain(rvs._leak, ["/reports/q3"], via=via)

                    def portless(text, server=server):  # each run has its own port
                        return (text or "").replace(server.key, "TARGET")
                    runs[(name, via)] = (
                        [(f.get("confirmed"), portless(f.get("evidence")),
                          portless(f.get("suggested_test"))) for f in found["/reports/q3"]],
                        [(p, h.get("authorization")) for p, h in server.requests])
        for via in ("shape", "label"):
            self.assertEqual(runs[("empty", via)], runs[("absent", via)])
        self.assertEqual(runs[("absent", "shape")][0], [], "no list: the shape leg keeps nothing")

    def test_listed_route_that_denies_gives_no_finding(self):
        with _declaring(protected_paths=["/reports/*"]):
            found, server = self._run_chain(_denied, ["/reports/q3"])
            self.assertEqual(found["/reports/q3"], [])
            labelled, _ = self._run_chain(_denied, ["/reports/q3"], via="label")
        self._assert_not_confirmed(labelled["/reports/q3"], "label")
        self.assertNotIn("authz.protected_paths",
                         labelled["/reports/q3"][0].get("suggested_test", ""),
                         "nothing was served anonymously, so there is nothing to declare")


# ------------------------------------------------------------------ W5
_OWNERS = [{"path": "/api/invoices/*", "owner": "alice"},
           {"path": "/api/announcements/**", "authenticated": True}]


class OwnersReachTheChainTests(unittest.TestCase):
    """RV-T's X2 app through the real `investigate_engagement`, with `owners` passed
    as the engagement's declaration instead of seeded by a builder double."""

    def _fixture(self):
        fx = matrix_fixture.X2InvestigateEngagementTests(
            "test_investigation_reports_the_same_role_lead_and_a_principal_matrix")
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        return fx

    def test_declared_owners_confirm_only_the_declared_crossing(self):
        fx = self._fixture()
        result = fx._investigate(faults=[lambda: _declaring(owners=_OWNERS)])
        self.assertTrue(fx._confirmed_idor(result, matrix_fixture.INVOICES))
        self.assertFalse(fx._confirmed_idor(result, matrix_fixture.SHARED))

    def test_no_owners_confirm_nothing(self):
        for declarations in ({}, {"owners": []}):
            with self.subTest(declarations=declarations):
                fx = self._fixture()
                result = fx._investigate(faults=[lambda: _declaring(**declarations)])
                self.assertFalse(fx._confirmed_idor(result, matrix_fixture.INVOICES))


# ------------------------------------------------------------------ W6
class InvestigateRouteForwardsDeclarationsTests(unittest.TestCase):

    def setUp(self):
        from harness.test_job_status_passive import DurableJobCallerTests
        self.fx = DurableJobCallerTests("test_export_retains_child_execution_without_parent_completion")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.server = self.fx.server
        self.calls: list[dict] = []

        async def recorder(*args, **kwargs):
            self.calls.append(kwargs)
            return {"summary": {}}
        self.server.orchestrator.investigate_engagement = recorder

    def _start(self, **extra):
        return self.fx.client.post("/engagement/captured.example/investigate",
                                   json={"base_url": "https://captured.example/app", **extra})

    def _run(self, **extra) -> dict:
        response = self._start(**extra)
        self.assertEqual(response.status_code, 200, response.text)
        self.fx.poll(response.json()["job_id"], "done")
        self.assertEqual(len(self.calls), 1)
        return self.calls[0]

    def test_declared_lists_are_forwarded(self):
        kwargs = self._run(protected_paths=["/admin/**", "GET /api/account/*"], owners=_OWNERS)
        self.assertEqual(kwargs["protected_paths"], ["/admin/**", "GET /api/account/*"])
        self.assertEqual(kwargs["owners"], _OWNERS)

    def test_omitted_or_empty_lists_are_not_passed(self):
        for extra in ({}, {"protected_paths": [], "owners": []}):
            with self.subTest(extra=extra):
                self.calls.clear()
                kwargs = self._run(**extra)
                self.assertNotIn("protected_paths", kwargs)
                self.assertNotIn("owners", kwargs)

    def test_wrong_types_are_rejected_before_any_job(self):
        for extra in ({"protected_paths": "/admin/**"}, {"protected_paths": [7]},
                      {"owners": ["alice"]}, {"owners": {"path": "/x"}}):
            with self.subTest(extra=extra):
                self.assertEqual(self._start(**extra).status_code, 422)
        self.assertEqual(self.calls, [])

    def test_journal_key_changes_only_when_a_list_is_declared(self):
        from harness.coverage_tracker import resume_context_key
        server, config = self.server, self.server.config
        bare = server.InvestigateRequest(base_url="https://captured.example/app")
        # The key as it was computed before the declaration fields existed.
        limits = bare.model_dump(exclude={"base_url", "roles", "seed_exchanges", "resume_job_id",
                                          "protected_paths", "owners"})
        inputs = json.dumps([bare.base_url, [], [], limits], sort_keys=True, default=str)
        before = f"{resume_context_key(config)}:{hashlib.sha256(inputs.encode()).hexdigest()[:16]}"
        empty = server.InvestigateRequest(base_url=bare.base_url, protected_paths=[], owners=[])
        self.assertEqual(server._journal_context_key(config, bare), before)
        self.assertEqual(server._journal_context_key(config, empty), before)
        for declared in (dict(protected_paths=["/admin/**"]), dict(owners=_OWNERS)):
            with self.subTest(declared=declared):
                request = server.InvestigateRequest(base_url=bare.base_url, **declared)
                self.assertNotEqual(server._journal_context_key(config, request), before)


# ------------------------------------------------------------------ W7
class SuggestedTestExportParityTests(unittest.TestCase):

    def _finding(self, **extra):
        return {"vulnerability_class": "missing_authentication", "severity": "high",
                "confidence": 0.75, "confirmed": False, "url": "https://app.example.test/reports/7",
                "method": "GET", "summary": "served anonymously", "evidence": "HTTP 200",
                "basis": "derived", **extra}

    def _exports(self, finding):
        return [issues.export_issue(i) for i in issues.group_findings_into_issues([finding])]

    def test_issue_export_sarif_and_import_carry_the_next_step(self):
        step = "Declare the route protected in authz.protected_paths, then re-run."
        exports = self._exports(self._finding(suggested_test=step))
        self.assertEqual([e["suggested_test"] for e in exports], [step])
        sarif = sarif_adapter.export_issues_to_sarif(exports)
        self.assertEqual(sarif_adapter.validate_sarif_shape(sarif), [])
        results = [r for run in sarif["runs"] for r in run["results"]]
        self.assertEqual([r["properties"]["suggestedTest"] for r in results], [step])
        imported = sarif_adapter.import_sarif_to_findings(sarif)
        self.assertEqual([f["suggested_test"] for f in imported], [step])
        self.assertFalse(imported[0]["confirmed"], "an import stays advisory")

    def test_missing_next_step_exports_empty(self):
        exports = self._exports(self._finding())
        self.assertEqual(exports[0]["suggested_test"], "")
        sarif = sarif_adapter.export_issues_to_sarif(exports)
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["suggestedTest"], "")

    def test_next_step_is_redacted(self):
        secret = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl"
        exports = self._exports(self._finding(suggested_test=f"Replay with Authorization: {secret}"))
        self.assertNotIn(secret, json.dumps(exports))
        self.assertNotIn(secret, json.dumps(sarif_adapter.export_issues_to_sarif(exports)))


if __name__ == "__main__":
    unittest.main()
