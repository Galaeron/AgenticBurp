"""E4: one run-scoped execution registry shared by every execution path.

The worklist (P1), the model-review path (P2) and the coverage drive (P3) each
ran the heavy validators on their own key, so one request shape was tested again
under another route id or another phase. These tests cover the key, the registry,
and the callers: `_validate_findings` (review) and `_ConfirmationCache` (worklist
and drive) sharing one registry through `run_context`, `investigate_engagement`
dispatching one sqlmap run for two route ids, and the worklist dropping a capture
identical to an earlier one. Each positive has a negative control that removes the
new logic; none of the dedup tests may drop a case that differs in identity,
method, object id or a shape-keyed field.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from harness import engagement, worklist_investigator
from harness.coverage_tracker import _fair_cells, build_coverage_driven
from harness.execution_registry import SHAPE_KEYED, ExecutionRegistry, execution_key
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_chain import _ConfirmationCache
from harness.orchestrator_helpers import confirmation_cache_key
from harness.role_crawl import RoleSession
from harness.run_context import RequestBudget, RunContext
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.test_engagement_transport_callers import _EngagementCallerBase, _config
from harness.validators.base import ValidationResult, Validator

_ALICE = {"Authorization": "Bearer alice-token"}
_BOB = {"Authorization": "Bearer bob-token"}


def _ex(url, method="GET", headers=None, body="", response_body='{"id": 1}') -> HttpExchange:
    return HttpExchange(url=url, method=method, request_headers=dict(headers or {}),
                        request_body=body, response_status=200,
                        response_headers={"Content-Type": "application/json"},
                        response_body=response_body)


def _finding_of(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


class _Counting(Validator):
    """A validator that counts how often it really runs. The call log is a list
    shared by the shallow per-dispatch copies the registry binds."""
    finding_classes = {"sqli"}
    active = True

    def __init__(self, name="sqlmap", *, status="confirmed", confirmed=True, delay=0.0,
                 sends=0, budget=None, fail=None):
        self.name = name
        self.calls: list[str] = []
        self.status, self.confirmed, self.delay = status, confirmed, delay
        self.sends, self.budget, self.fail = sends, budget, fail

    async def validate(self, finding, exchange):
        self.calls.append(exchange.url)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        if self.budget is not None:
            self.budget.reserve(self.sends)
        return ValidationResult(self.name, self.status, "sqli", confidence=0.9,
                                confirmed=self.confirmed, summary="injectable",
                                evidence="evidence").with_artifacts(
            baseline="art-b", attack="art-a", controls=["art-c"])


def _run(registry, validator, exchange, case_ref, finding_class="sqli"):
    finding = _finding_of(finding_class)
    return registry.run(validator, finding, exchange, case_ref=case_ref,
                        call=lambda: validator.validate(finding, exchange))


class ExecutionKeyTests(unittest.TestCase):
    def key(self, name, url, headers=None, method="GET", body="", cls="sqli"):
        return execution_key(name, _ex(url, method, headers, body), cls)

    def test_a_shape_keyed_leg_ignores_object_ids_and_parameter_values(self):
        a = self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE)
        b = self.key("sqlmap", "http://127.0.0.1/rest/basket/6?q=b", _ALICE)
        self.assertEqual(a, b)

    def test_a_different_identity_is_a_different_key(self):
        self.assertNotEqual(self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE),
                            self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _BOB))
        self.assertNotEqual(self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE),
                            self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a"))

    def test_a_different_query_parameter_name_is_a_different_key(self):
        self.assertNotEqual(self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE),
                            self.key("sqlmap", "http://127.0.0.1/rest/basket/1?search=a", _ALICE))
        self.assertNotEqual(self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE),
                            self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a&x=1", _ALICE))

    def test_method_host_route_and_class_family_each_make_a_different_key(self):
        base = self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a", _ALICE)
        self.assertNotEqual(base, self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a",
                                           _ALICE, method="POST"))
        self.assertNotEqual(base, self.key("sqlmap", "http://localhost/rest/basket/1?q=a", _ALICE))
        self.assertNotEqual(base, self.key("sqlmap", "http://127.0.0.1/rest/orders/1?q=a", _ALICE))
        self.assertNotEqual(base, self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a",
                                           _ALICE, cls="xss"))
        # ... while two spellings of one class are the same family.
        self.assertEqual(base, self.key("sqlmap", "http://127.0.0.1/rest/basket/1?q=a",
                                        _ALICE, cls="SQL Injection"))

    def test_body_parameter_names_not_values_key_json_and_form_bodies(self):
        json_headers = {**_ALICE, "Content-Type": "application/json"}
        form_headers = {**_ALICE, "Content-Type": "application/x-www-form-urlencoded"}
        url = "http://127.0.0.1/api/search"
        one = self.key("command_injection", url, json_headers, "POST", '{"q": "a", "page": 1}')
        self.assertEqual(one, self.key("command_injection", url, json_headers, "POST",
                                       '{"page": 9, "q": "zzz"}'))
        self.assertNotEqual(one, self.key("command_injection", url, json_headers, "POST",
                                          '{"q": "a", "sort": 1}'))
        form = self.key("command_injection", url, form_headers, "POST", "q=a&page=1")
        self.assertEqual(form, self.key("command_injection", url, form_headers, "POST",
                                        "page=2&q=b"))
        self.assertNotEqual(form, self.key("command_injection", url, form_headers, "POST", "q=a"))
        self.assertNotEqual(one, form)

    def test_an_opaque_body_keys_on_its_hash(self):
        url = "http://127.0.0.1/api/upload"
        xml_headers = {**_ALICE, "Content-Type": "application/xml"}
        a = self.key("xxe", url, xml_headers, "POST", "<a>1</a>")
        self.assertEqual(a, self.key("xxe", url, xml_headers, "POST", "<a>1</a>"))
        self.assertNotEqual(a, self.key("xxe", url, xml_headers, "POST", "<a>2</a>"))
        # A form-looking body with no declared content type is opaque too.
        self.assertNotEqual(self.key("nosql", url, _ALICE, "POST", "q=a"),
                            self.key("nosql", url, _ALICE, "POST", "q=b"))

    def test_object_and_identity_checks_keep_the_exact_confirmation_key(self):
        """The negative control for the object id: cross_identity on basket 1 and 6
        are different cases, and these checks never use the shape key."""
        one = _ex("http://127.0.0.1/rest/basket/1", headers=_ALICE)
        six = _ex("http://127.0.0.1/rest/basket/6", headers=_ALICE)
        self.assertNotEqual(execution_key("cross_identity", one, "idor"),
                            execution_key("cross_identity", six, "idor"))
        for name in ("cross_identity", "idor_read", "jwt_forge", "csrf", "sequence", "toctou",
                     "stored_xss", "browser_xss", "auth_sequence", "rate_limit"):
            self.assertNotIn(name, SHAPE_KEYED)
            # The exact key, plus the identity of every non-public header, then the
            # batch 04 reuse conditions (mechanism version, relevant state).
            self.assertEqual(execution_key(name, one, "idor")[-2:],
                             (("mechanism", "1"), ("state", "")))
            self.assertEqual(execution_key(name, one, "idor")[:-3],
                             confirmation_cache_key(name, one, "idor"), name)
            self.assertNotEqual(execution_key(name, one, "idor"), execution_key(name, six, "idor"))


    def test_value_chosen_checks_are_not_shape_keyed(self):
        """ssrf, open_redirect, path_traversal and deserialization_oob pick the
        parameter to attack by its value; the shape-keyed sqlmap is the control."""
        plain, url_valued = "http://127.0.0.1/go?u=abc", "http://127.0.0.1/go?u=http://x"
        for name in ("ssrf", "open_redirect", "path_traversal", "deserialization_oob"):
            self.assertNotIn(name, SHAPE_KEYED)
            self.assertNotEqual(self.key(name, plain), self.key(name, url_valued), name)
        self.assertEqual(self.key("sqlmap", plain), self.key("sqlmap", url_valued))

    def test_a_custom_credential_header_is_part_of_the_identity(self):
        alice, bob = {"X-Api-Key": "alice"}, {"X-Api-Key": "bob"}
        url = "http://127.0.0.1/rest/basket/1?q=a"
        for name in ("sqlmap", "cross_identity"):
            self.assertNotEqual(self.key(name, url, alice), self.key(name, url, bob), name)
            # Control: the same key value is the same identity.
            self.assertEqual(self.key(name, url, alice), self.key(name, url, dict(alice)), name)


class ExecutionRegistryTests(unittest.TestCase):
    def test_a_second_case_with_the_same_shape_is_covered_not_run(self):
        registry, validator = ExecutionRegistry(), _Counting()

        async def go():
            first = await _run(registry, validator, _ex("http://127.0.0.1/rest/basket/1?q=a"), "case-a")
            second = await _run(registry, validator, _ex("http://127.0.0.1/rest/basket/6?q=b"), "case-b")
            return first, second
        first, second = asyncio.run(go())
        self.assertEqual(len(validator.calls), 1)
        self.assertTrue(second.summary.startswith("covered by case-a "), second.summary)
        self.assertTrue(second.summary.endswith("injectable"))
        self.assertEqual((second.baseline_artifact_id, second.attack_artifact_id,
                          second.control_artifact_ids), ("", "", ()))
        self.assertEqual(second.status, first.status)
        # The original is untouched and still names its exchanges.
        self.assertEqual((first.baseline_artifact_id, first.attack_artifact_id,
                          first.control_artifact_ids), ("art-b", "art-a", ("art-c",)))
        self.assertTrue(first.confirmed)
        self.assertEqual(first.summary, "injectable")

    def test_a_confirmed_original_is_not_confirmed_in_the_copy_for_another_case(self):
        registry, validator = ExecutionRegistry(), _Counting()

        async def go():
            await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
            return await _run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b")
        copy = asyncio.run(go())
        self.assertEqual(copy.status, "confirmed")
        self.assertFalse(copy.confirmed)
        # Nothing was sent for case-b; the proof is named, not counted.
        self.assertEqual((copy.sent_count, copy.covered_by), (0, "case-a"))

    def test_a_not_confirmed_original_is_never_upgraded(self):
        registry = ExecutionRegistry()
        validator = _Counting(status="not_confirmed", confirmed=False)

        async def go():
            await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
            return await _run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b")
        copy = asyncio.run(go())
        self.assertEqual((copy.status, copy.confirmed), ("not_confirmed", False))

    def test_the_same_case_gets_the_stored_result_itself(self):
        registry, validator = ExecutionRegistry(), _Counting()

        async def go():
            first = await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
            again = await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
            return first, again
        first, again = asyncio.run(go())
        self.assertIs(again, first)
        self.assertEqual(len(validator.calls), 1)

    def test_concurrent_callers_of_one_key_share_a_single_run(self):
        registry, validator = ExecutionRegistry(), _Counting(delay=0.05)

        async def go():
            return await asyncio.gather(
                _run(registry, validator, _ex("http://127.0.0.1/rest/basket/1?q=a"), "case-a"),
                _run(registry, validator, _ex("http://127.0.0.1/rest/basket/6?q=b"), "case-b"))
        first, joined = asyncio.run(go())
        self.assertEqual(len(validator.calls), 1)
        stats = registry.stats()
        self.assertEqual((stats["misses"], stats["inflight_joins"], stats["hits"]), (1, 1, 1))
        self.assertEqual(first.attack_artifact_id, "art-a")
        self.assertTrue(joined.summary.startswith("covered by case-a "), joined.summary)
        self.assertEqual(joined.attack_artifact_id, "")

    def test_a_negative_control_with_no_sharing_runs_every_caller(self):
        validator = _Counting(delay=0.05)

        async def go():
            return await asyncio.gather(
                _run(ExecutionRegistry(), validator, _ex("http://127.0.0.1/a?q=1"), "case-a"),
                _run(ExecutionRegistry(), validator, _ex("http://127.0.0.1/a?q=2"), "case-b"))
        asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)

    def test_cases_that_differ_in_identity_method_or_a_shape_field_each_run(self):
        registry, validator = ExecutionRegistry(), _Counting()
        json_headers = {"Content-Type": "application/json"}
        cases = [
            _ex("http://127.0.0.1/rest/basket/1?q=a", headers=_ALICE),
            _ex("http://127.0.0.1/rest/basket/1?q=a", headers=_BOB),                 # identity
            _ex("http://127.0.0.1/rest/basket/1?q=a"),                                # anonymous
            _ex("http://127.0.0.1/rest/basket/1?q=a", "POST", _ALICE),                # method
            _ex("http://127.0.0.1/rest/basket/1?search=a", headers=_ALICE),           # query name
            _ex("http://127.0.0.1/rest/basket/1?q=a", "POST", {**_ALICE, **json_headers},
                body='{"name": "x"}'),                                                # body field
            _ex("http://127.0.0.1/rest/basket/1?q=a", "POST", {**_ALICE, **json_headers},
                body='{"title": "x"}'),                                               # other field
        ]

        async def go():
            for index, exchange in enumerate(cases):
                await _run(registry, validator, exchange, f"case-{index}")
        asyncio.run(go())
        self.assertEqual(len(validator.calls), len(cases), validator.calls)
        self.assertEqual(registry.stats()["hits"], 0)

    def _run_named(self, registry, validator, exchange, case_ref, location, name, *,
                   only=False, cls="sqli"):
        finding = _finding_of(cls)
        finding.parameter_location, finding.parameter_name = location, name
        finding.parameter_only = only
        return registry.run(validator, finding, exchange, case_ref=case_ref,
                            call=lambda: validator.validate(finding, exchange))

    def test_sqlmap_findings_naming_different_parameters_run_once(self):
        # The 8h juice-shop run: one request shape, findings naming path id,
        # query d, and nothing -- sqlmap (no -p) tests them all every time.
        registry, validator = ExecutionRegistry(), _Counting()
        named = [("path", "id"), ("query", "d"), ("", "")]

        async def go():
            return [await self._run_named(registry, validator,
                                          _ex("http://127.0.0.1/rest/track/1?d=x", headers=_ALICE),
                                          f"case-{index}", location, name)
                    for index, (location, name) in enumerate(named)]
        results = asyncio.run(go())
        self.assertEqual(len(validator.calls), 1, validator.calls)
        self.assertTrue(all(r.summary.startswith("covered by case-0 ") for r in results[1:]),
                        [r.summary for r in results])

    def test_sqlmap_still_reruns_for_another_identity_whatever_parameter_is_named(self):
        registry, validator = ExecutionRegistry(), _Counting()

        async def go():
            await self._run_named(registry, validator,
                                  _ex("http://127.0.0.1/rest/track/1?d=x", headers=_ALICE),
                                  "case-a", "query", "d")
            await self._run_named(registry, validator,
                                  _ex("http://127.0.0.1/rest/track/1?d=x", headers=_BOB),
                                  "case-b", "path", "id")
        asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)

    def test_parameter_only_sqlmap_runs_keep_the_parameter_in_the_key(self):
        # With parameter_only sqlmap passes -p, so each named parameter is its own scan,
        # and a -p scan never stands in for the full one.
        registry, validator = ExecutionRegistry(), _Counting()
        exchange = _ex("http://127.0.0.1/rest/track/1?d=x", headers=_ALICE)

        async def go():
            await self._run_named(registry, validator, exchange, "case-a", "query", "d", only=True)
            await self._run_named(registry, validator, exchange, "case-b", "path", "id", only=True)
            await self._run_named(registry, validator, exchange, "case-c", "query", "d")
            await self._run_named(registry, validator, exchange, "case-d", "query", "d", only=True)
        asyncio.run(go())
        self.assertEqual(len(validator.calls), 3, validator.calls)

    def test_negative_control_other_shape_keyed_validators_still_split_on_the_parameter(self):
        registry, validator = ExecutionRegistry(), _Counting("ssti")
        exchange = _ex("http://127.0.0.1/rest/track/1?d=x", headers=_ALICE)

        async def go():
            await self._run_named(registry, validator, exchange, "case-a", "query", "d")
            await self._run_named(registry, validator, exchange, "case-b", "path", "id")
        asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)

    def test_an_object_check_on_another_object_id_still_runs(self):
        registry, validator = ExecutionRegistry(), _Counting("cross_identity")

        async def go():
            await _run(registry, validator, _ex("http://127.0.0.1/rest/basket/1", headers=_ALICE),
                       "case-a", "idor")
            await _run(registry, validator, _ex("http://127.0.0.1/rest/basket/6", headers=_ALICE),
                       "case-b", "idor")
        asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)

    def test_a_run_that_did_not_happen_never_stands_in_for_the_check(self):
        for status in ("error", "skipped", "blocked", "inconclusive", "incomplete", "partial"):
            with self.subTest(status=status):
                registry, validator = ExecutionRegistry(), _Counting(status=status, confirmed=False)

                async def go():
                    first = await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
                    second = await _run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b")
                    return first, second
                first, second = asyncio.run(go())
                self.assertEqual(len(validator.calls), 2)
                self.assertEqual((first.status, second.status), (status, status))
                self.assertEqual(registry.stats()["hits"], 0)

    def test_every_answered_status_is_stored(self):
        for status, confirmed in (("confirmed", True), ("not_confirmed", False),
                                  ("controlled_negative", False), ("safe", False)):
            with self.subTest(status=status):
                registry, validator = ExecutionRegistry(), _Counting(status=status, confirmed=confirmed)

                async def go():
                    await _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a")
                    return await _run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b")
                copy = asyncio.run(go())
                self.assertEqual(len(validator.calls), 1)
                self.assertEqual((copy.status, copy.confirmed), (status, False))

    def test_an_exception_reaches_the_waiter_and_is_not_stored(self):
        registry = ExecutionRegistry()
        validator = _Counting(delay=0.05, fail=RuntimeError("boom"))

        async def go():
            outcomes = await asyncio.gather(
                _run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a"),
                _run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b"),
                return_exceptions=True)
            validator.fail = None
            later = await _run(registry, validator, _ex("http://127.0.0.1/a?q=3"), "case-c")
            return outcomes, later
        outcomes, later = asyncio.run(go())
        self.assertTrue(all(isinstance(o, RuntimeError) for o in outcomes), outcomes)
        self.assertEqual(len(validator.calls), 2)       # the failed run, then the retry
        self.assertTrue(later.confirmed)

    def test_a_cancelled_run_hands_the_check_to_its_waiter(self):
        registry = ExecutionRegistry()
        validator = _Counting(delay=0.2)

        async def go():
            owner = asyncio.ensure_future(_run(registry, validator, _ex("http://127.0.0.1/a?q=1"), "case-a"))
            await asyncio.sleep(0.02)
            waiter = asyncio.ensure_future(_run(registry, validator, _ex("http://127.0.0.1/a?q=2"), "case-b"))
            await asyncio.sleep(0.02)
            owner.cancel()
            return await waiter
        result = asyncio.run(go())
        self.assertEqual(len(validator.calls), 2)       # cancelled run, then the waiter's own
        self.assertTrue(result.confirmed)
        self.assertEqual(result.attack_artifact_id, "art-a")

    def test_sends_saved_counts_the_requests_each_hit_avoided(self):
        budget = RequestBudget(100)
        registry = ExecutionRegistry(budget=budget)
        validator = _Counting(budget=budget, sends=7)

        async def go():
            for index in range(3):
                await _run(registry, validator, _ex(f"http://127.0.0.1/rest/basket/{index + 1}?q=a"),
                           f"case-{index}")
        asyncio.run(go())
        stats = registry.stats()
        self.assertEqual((stats["misses"], stats["hits"], stats["sends_saved"]), (1, 2, 14))
        self.assertEqual(stats["by_validator"]["sqlmap"],
                         {"hits": 2, "misses": 1, "inflight_joins": 0, "sends_saved": 14,
                          "retry_limited": 0})
        self.assertEqual(budget.used, 7)


class CrossPathCallerTests(_CallerBase, unittest.TestCase):
    """The review path (`_validate_findings`) and the worklist/drive cache
    (`_ConfirmationCache`) share one registry through `run_context`."""
    HOSTS = ("127.0.0.1",)
    REVIEW = "http://127.0.0.1:9/rest/basket/1?q=a"
    DRIVE = "http://127.0.0.1:9/rest/basket/6?q=b"

    def _both_paths(self, *, shared: bool, drive_first: bool = False):
        """Run one sqlmap-named validator through the review path and the cache on
        the same request shape, in one run. `shared` is the only difference
        between the positive case and the negative control."""
        validator = _Counting()
        orch = self._orch(hosts=self.HOSTS)
        orch.validator_registry.validators = {"sqlmap": validator}
        report = AgentReport(agent="sqli", model="fake", findings=[_finding("sqli")])

        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=100,
                                         gate_config={"active_enabled": True,
                                                      "allow_mutating_replay": True}) as run:
                registry = ExecutionRegistry(budget=run.budget) if shared else None
                run.execution_registry = registry
                cache = _ConfirmationCache(run, lambda cls, exchange: "case-drive", registry=registry)

                async def review():
                    return await orch._validate_findings(_ex(self.REVIEW), [report], run_context=run)

                async def drive():
                    return await cache.validate(validator, _finding_of("SQL Injection"),
                                                _ex(self.DRIVE), case_ref="case-drive")
                if drive_first:
                    driven = await drive()
                    reviewed = await review()
                else:
                    reviewed = await review()
                    driven = await drive()
                return validator, reviewed, driven, registry
        return asyncio.run(go())

    def test_one_shape_is_validated_once_across_the_review_and_the_drive(self):
        validator, (reports, proofs), driven, registry = self._both_paths(shared=True)
        self.assertEqual(len(validator.calls), 1, validator.calls)
        self.assertTrue(reports[0].confirmed)
        self.assertTrue(driven.summary.startswith("covered by "), driven.summary)
        self.assertFalse(driven.confirmed)
        self.assertEqual(driven.attack_artifact_id, "")
        stats = registry.stats()
        self.assertEqual((stats["misses"], stats["hits"]), (1, 1))
        self.assertEqual(stats["by_validator"]["sqlmap"]["hits"], 1)

    def test_a_drive_that_ran_first_covers_the_review_without_confirming_it(self):
        validator, (reports, proofs), driven, _ = self._both_paths(shared=True, drive_first=True)
        self.assertEqual(len(validator.calls), 1, validator.calls)
        self.assertTrue(driven.confirmed)
        self.assertEqual(len(reports), 1)
        self.assertFalse(reports[0].confirmed)
        self.assertTrue(reports[0].summary.startswith("covered by case-drive "), reports[0].summary)
        # The covered review case records an inconclusive proof, not a confirmation.
        self.assertEqual([p["verdict"] for p in proofs], ["inconclusive"])

    def test_negative_control_without_a_shared_registry_validates_twice(self):
        validator, (reports, _), driven, _ = self._both_paths(shared=False)
        self.assertEqual(len(validator.calls), 2, validator.calls)
        self.assertTrue(reports[0].confirmed)
        self.assertTrue(driven.confirmed)

    def test_negative_control_patching_the_registry_out_validates_twice(self):
        async def pass_through(self_registry, validator, finding, exchange, *, case_ref, call):
            return await call()
        with patch.object(ExecutionRegistry, "run", pass_through):
            validator, *_ = self._both_paths(shared=True)
        self.assertEqual(len(validator.calls), 2, validator.calls)


class _Target:
    """Loopback target answering every GET with a small JSON object."""

    def __init__(self, *, cors=False, failed_requests=0):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.server.requests += 1
                malformed = self.server.requests <= failed_requests
                data = b'not gzip' if malformed else b'{"id": 1, "owner": "alice"}'
                self.send_response(200)
                if malformed:
                    self.send_header("Content-Encoding", "gzip")
                if cors:
                    self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                    self.send_header("Access-Control-Allow-Credentials", "true")
                    self.send_header("Vary", "Origin")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_OPTIONS = do_GET

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.requests = 0
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _builder(exchanges):
    """Stand-in for engagement_builder.build_engagement: no discovery traffic, and
    the captures recorded as templates the way the real builder records them."""
    def build(base_url, roles, **kw):
        state = engagement.EngagementState(host="127.0.0.1")
        for make in exchanges:
            exchange = make(base_url)
            state.record_template(exchange.url, exchange.method, exchange)
        for ep in state.endpoints.values():
            ep.reachable_roles = sorted({r.role for r in roles})
            ep.object_scoped = "{id}" in ep.path
        for r in roles:
            state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
        rc = SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[],
                             captured=[], errors=[], sensitive_file_hits=[], endpoints=[])
        return state, rc
    return build


class _SqlmapLaunches:
    """Stands in for tool_runner.run_process, the sqlmap validator's host launch."""

    def __init__(self):
        self.commands: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        return subprocess.CompletedProcess(
            cmd, 0, "all tested parameters do not appear to be injectable", "")

    def on(self, path_prefix):
        return [c for c in self.commands
                if any(path_prefix in part for part in c if isinstance(part, str))
                and "-u" in c]


class EngagementCallerTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement against a loopback target: two captures of one shape
    under different route ids, as the first real run measured."""

    ROLES = [RoleSession("anonymous", {})]

    def _investigate(self, exchanges, *, extra=(), coverage_drive=False, roles=None):
        launches = _SqlmapLaunches()
        target = self._target()
        patches = [patch("harness.tool_runner.run_process", side_effect=launches),
                   patch("harness.engagement_builder.build_engagement",
                         side_effect=_builder(exchanges)), *extra]
        result, rc, model = self._run(
            target, max_requests=500, roles=roles or self.ROLES, mutating=True,
            extra_patches=patches)
        return result, rc, model, launches, target

    @staticmethod
    def _items(path, query, headers=None, body=""):
        return lambda base: _ex(f"{base}{path}?{query}" if query else f"{base}{path}",
                                headers=headers, body=body)

    def test_two_route_ids_of_one_shape_launch_one_sqlmap_run(self):
        result, rc, model, launches, _ = self._investigate(
            [self._items("/api/items/1", "q=a"), self._items("/api/items/6", "q=b")])
        self.assertEqual(len(launches.on("/api/items/")), 1, launches.commands)
        stats = result["execution_registry"]
        self.assertGreaterEqual(stats["by_validator"]["sqlmap"]["hits"], 1, stats)
        self.assertGreaterEqual(stats["hits"], 1)
        self.assertEqual(rc.execution_registry.stats(), stats)

    def test_negative_control_without_the_registry_launches_sqlmap_for_each_id(self):
        async def pass_through(self_registry, validator, finding, exchange, *, case_ref, call):
            return await call()
        result, *_, launches, _ = self._investigate(
            [self._items("/api/items/1", "q=a"), self._items("/api/items/6", "q=b")],
            extra=[patch.object(ExecutionRegistry, "run", pass_through)])
        self.assertEqual(len(launches.on("/api/items/")), 2, launches.commands)

    def test_a_different_query_parameter_name_still_launches_its_own_run(self):
        result, *_, launches, _ = self._investigate(
            [self._items("/api/items/1", "q=a"), self._items("/api/items/6", "search=a")])
        self.assertEqual(len(launches.on("/api/items/")), 2, launches.commands)

    def test_a_different_identity_still_launches_its_own_run(self):
        roles = [RoleSession("anonymous", {}), RoleSession("alice", _ALICE)]
        result, *_, launches, _ = self._investigate(
            [self._items("/api/items/1", "q=a"), self._items("/api/items/6", "q=a", _ALICE)],
            roles=roles)
        self.assertEqual(len(launches.on("/api/items/")), 2, launches.commands)

    def test_the_coverage_drive_is_covered_by_the_worklist_run(self):
        """The drive reuses completed shape checks; incomplete checks stay eligible."""
        def drive_config(*, mutating):
            cfg = _config(mutating=mutating)
            cfg["engagement"]["coverage_drive_legs"] = True
            return cfg
        # The orchestrator is built from this config before any run patch starts.
        with patch("harness.test_engagement_transport_callers._config", drive_config):
            result, rc, model, launches, _ = self._investigate(
                [self._items("/api/items/1", "q=a"), self._items("/api/items/6", "q=b")])
        self.assertGreater(result["coverage"]["phase_ledger"]["counts"]["queued"], 0,
                           "the drive did not run")
        self.assertEqual(len(launches.on("/api/items/")), 1, launches.commands)
        stats = result["execution_registry"]
        # Only complete outcomes are reusable. This fixture completes sqlmap;
        # its incomplete command-injection checks must remain eligible later.
        self.assertGreaterEqual(stats["by_validator"]["sqlmap"]["hits"], 3, stats)
        self.assertEqual(stats["by_validator"]["command_injection"]["hits"], 0, stats)
        self.assertGreater(stats["by_validator"]["command_injection"]["misses"], 0, stats)


def _node_for(roles, *exchanges):
    state = engagement.EngagementState(host="127.0.0.1")
    for exchange in exchanges:
        state.record_template(exchange.url, exchange.method, exchange)
    for ep in state.endpoints.values():
        ep.reachable_roles = sorted({r.role for r in roles})
    return state


class WorklistDuplicateTests(unittest.TestCase):
    ROLES = [RoleSession("anonymous", {}), RoleSession("alice", _ALICE, name="alice")]
    BASE = "http://127.0.0.1:9"

    def investigate(self, state, *, roles=None):
        seen, summary = [], {}

        async def precondition(node, exchange):
            seen.append((node.get("path"), exchange.url, dict(exchange.request_headers)))
            return []

        async def probe(*args, **kwargs):
            return {}
        asyncio.run(worklist_investigator.investigate_worklist(
            probe, state, self.BASE, roles or self.ROLES, precondition_fn=precondition,
            max_nodes=0, summary_out=summary))
        return seen, summary

    def capture(self, url="/rest/user/whoami", headers=None, response='{"user": "alice"}',
                method="GET", body="", response_headers=None):
        exchange = _ex(f"{self.BASE}{url}", method, headers, body, response_body=response)
        exchange.response_headers = response_headers or {"Date": "x"}
        return exchange

    def test_two_identical_captures_are_investigated_once(self):
        first = self.capture(headers=_ALICE, response_headers={"Date": "10:00"})
        again = self.capture(headers=_ALICE, response_headers={"Date": "10:01"})
        state = _node_for(self.ROLES, first, again)
        self.assertEqual(len(state.endpoints["GET /rest/user/whoami"].capture_variants), 2,
                         "the two captures differ only in a response header, so both are recorded")
        seen, summary = self.investigate(state)
        self.assertEqual(len(seen), 1, seen)
        duplicates = summary["duplicates_skipped"]
        self.assertEqual(len(duplicates), 1, duplicates)
        variants = state.endpoints["GET /rest/user/whoami"].capture_variants
        self.assertEqual(duplicates[0]["covered_by"], variants[0]["capture_id"])
        self.assertEqual(duplicates[0]["capture_id"], variants[1]["capture_id"])
        self.assertEqual((duplicates[0]["method"], duplicates[0]["path"]),
                         ("GET", "/rest/user/whoami"))

    def test_negative_control_without_the_filter_investigates_both(self):
        state = _node_for(self.ROLES, self.capture(headers=_ALICE, response_headers={"Date": "10:00"}),
                          self.capture(headers=_ALICE, response_headers={"Date": "10:01"}))
        with patch.object(worklist_investigator, "_without_duplicate_captures",
                          lambda nodes, duplicates: nodes):
            seen, summary = self.investigate(state)
        self.assertEqual(len(seen), 2, seen)
        self.assertEqual(summary["duplicates_skipped"], [])

    def test_captures_with_different_response_bodies_are_both_investigated(self):
        state = _node_for(self.ROLES,
                          self.capture(headers=_ALICE, response='{"user": "alice"}'),
                          self.capture(headers=_ALICE, response='{"user": "alice", "x": 1}'))
        seen, summary = self.investigate(state)
        self.assertEqual(len(seen), 2, seen)
        self.assertEqual(summary["duplicates_skipped"], [])

    def test_captures_differing_only_in_identity_both_run(self):
        state = _node_for(self.ROLES, self.capture(headers=_ALICE), self.capture(headers=None))
        seen, summary = self.investigate(state)
        self.assertEqual(len(seen), 2, seen)
        self.assertEqual(summary["duplicates_skipped"], [])
        self.assertEqual({tuple(sorted(h)) for _, _, h in seen}, {("Authorization",), ()})

    def test_captures_differing_only_in_a_request_field_both_run(self):
        for left, right in [
                (self.capture("/api/search?q=a"), self.capture("/api/search?q=b")),
                (self.capture("/api/items/1"), self.capture("/api/items/6")),
                (self.capture("/api/search", method="POST", body='{"q": "a"}',
                              headers={"Content-Type": "application/json"}),
                 self.capture("/api/search", method="POST", body='{"q": "b"}',
                              headers={"Content-Type": "application/json"}))]:
            with self.subTest(left=left.url, right=right.url, body=right.request_body):
                state = _node_for([RoleSession("anonymous", {})], left, right)
                seen, summary = self.investigate(state, roles=[RoleSession("anonymous", {})])
                self.assertEqual(len(seen), 2, seen)
                self.assertEqual(summary["duplicates_skipped"], [])

    def test_a_route_id_and_method_are_never_merged_across_endpoints(self):
        state = _node_for([RoleSession("anonymous", {})],
                          self.capture("/api/things"), self.capture("/api/things", method="POST",
                                                                   body="{}"))
        seen, _ = self.investigate(state, roles=[RoleSession("anonymous", {})])
        self.assertEqual(len(seen), 2, seen)


class WorklistChainCallerTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement: the iterative agent (the costly step) runs once for
    two captures that are the same request and the same response."""

    def _probes(self, exchanges, *, extra=()):
        target = self._target()
        patches = [patch("harness.engagement_builder.build_engagement",
                         side_effect=_builder(exchanges)), *extra]
        result, rc, model = self._run(target, max_requests=500, mutating=False,
                                      roles=[RoleSession("anonymous", {})], extra_patches=patches)
        return result, model

    def capture(self, header_value):
        def make(base):
            exchange = _ex(f"{base}/api/items/1")
            exchange.response_headers = {"Date": header_value}
            return exchange
        return make

    def test_identical_captures_cost_one_agent_investigation(self):
        result, model = self._probes([self.capture("10:00"), self.capture("10:01")])
        summary = result["worklist_summary"]
        self.assertEqual(summary["investigated"], 1)
        self.assertEqual(len(summary["duplicates_skipped"]), 1, summary["duplicates_skipped"])
        self.assertEqual(len(result["outcomes"]), 1)

    def test_negative_control_without_the_filter_investigates_twice(self):
        result, model = self._probes(
            [self.capture("10:00"), self.capture("10:01")],
            extra=[patch.object(worklist_investigator, "_without_duplicate_captures",
                                lambda nodes, duplicates: nodes)])
        summary = result["worklist_summary"]
        self.assertEqual(summary["investigated"], 2)
        self.assertEqual(summary["duplicates_skipped"], [])


def _previous_fair_cells(items, unauthenticated=frozenset()):
    """The drive order before E4, kept as the negative control: groups in matrix
    order, which is identity-major (identities sorted by name)."""
    from collections import deque
    groups = {}
    for item in items:
        groups.setdefault(item[:2], []).append(item)
    queues = []
    for index, values in enumerate(groups.values()):
        offset = index % len(values)
        queues.append(deque(values[offset:] + values[:offset]))
    while queues:
        for queue in list(queues):
            yield queue.popleft()
            if not queue:
                queues.remove(queue)


class DriveOrderTests(unittest.TestCase):
    """The coverage drive rotates identities, signed-in principals first, instead
    of draining the first identity before another is reached."""

    ROLES = [RoleSession("anonymous", {}), RoleSession("user", _ALICE, name="alice"),
             RoleSession("user", _BOB, name="bob")]

    def state(self):
        state = engagement.EngagementState("shop.test")
        for path in ("/api/orders/1", "/api/profile/2", "/api/cart/3", "/api/wishlist/4"):
            exchange = HttpExchange(url="http://shop.test" + path, method="GET", response_status=200)
            state.record_template(exchange.url, "GET", exchange)
        for ep in state.endpoints.values():
            ep.reachable_roles = ["anonymous", "user"]
            ep.object_scoped = True
        return state

    def drive(self, budget):
        calls = []

        async def run(identity, method, path, check):
            calls.append((identity, path, check.id))
            return SimpleNamespace(status="not_confirmed", sent_count=1, summary="held")
        asyncio.run(build_coverage_driven(self.state(), self.ROLES, run,
                                          driveable={"cross_identity"}, budget=budget))
        return calls

    def test_signed_in_principals_are_served_before_anonymous_and_identities_rotate(self):
        calls = self.drive(budget=8)
        self.assertEqual(len(calls), 8)
        identities = [identity for identity, _, _ in calls]
        self.assertNotIn("anonymous", identities, calls)
        # Both signed-in identities reach the same routes, not one identity's routes.
        for path in {path for _, path, _ in calls}:
            self.assertEqual({i for i, p, _ in calls if p == path}, {"alice", "bob"}, calls)
        self.assertGreaterEqual(len({path for _, path, _ in calls}), 2, calls)

    def test_anonymous_is_still_driven_once_the_signed_in_cells_are(self):
        calls = self.drive(budget=1000)
        self.assertEqual(len(calls), len(set(calls)), "a cell was driven twice")
        self.assertEqual({identity for identity, _, _ in calls}, {"anonymous", "alice", "bob"})
        first_anonymous = next(i for i, (identity, _, _) in enumerate(calls) if identity == "anonymous")
        self.assertTrue(all(identity != "anonymous" for identity, _, _ in calls[:first_anonymous]))
        self.assertGreater(first_anonymous, 0)

    def test_negative_control_the_previous_order_drains_the_first_identity(self):
        with patch("harness.coverage_tracker._fair_cells", _previous_fair_cells):
            calls = self.drive(budget=8)
        identities = {identity for identity, _, _ in calls}
        self.assertEqual(identities, {"alice", "anonymous"}, calls)   # bob never reached
        self.assertEqual(len({path for _, path, _ in calls}), 4, calls)

    def test_ordering_never_drops_or_repeats_a_cell(self):
        cells = [(i, e, c) for i in ("a", "b") for e in ("e1", "e2", "e3") for c in (1, 2)]
        self.assertEqual(sorted(_fair_cells(cells, {"a"})), sorted(cells))


if __name__ == "__main__":
    unittest.main()


class CoveredCellTests(unittest.IsolatedAsyncioTestCase):
    """A covered copy reaching the coverage drive (P3) never makes a cell
    CONFIRMED or CONTROLLED_NEGATIVE: its artifacts belong to another case."""

    def fixture(self):
        from harness.test_assessment_coverage_repair import CoverageRepairTests
        return CoverageRepairTests.fixture(None)

    async def drive(self, builder, status, covered_by):
        state, roles = self.fixture()

        async def run(*args):
            result = SimpleNamespace(status=status, sent_count=0, summary="covered",
                                     confidence=0.9, evidence="")
            if covered_by:
                result.covered_by = covered_by
            return result
        return await builder(state, roles, run, driveable={"cross_identity"}, budget=1)

    async def test_a_covered_result_is_inconclusive_in_both_drivers(self):
        from harness.coverage_tracker import build_coverage_cases_driven
        for builder in (build_coverage_driven, build_coverage_cases_driven):
            for status in ("confirmed", "controlled_negative"):
                with self.subTest(builder=builder.__name__, status=status):
                    report = await self.drive(builder, status, "case-a")
                    self.assertEqual(report[status], 0, report["by_status"])
                    self.assertEqual(report["audited"]["executed"]["numerator"], 0)

    async def test_negative_control_an_uncovered_verdict_is_kept(self):
        from harness.coverage_tracker import build_coverage_cases_driven
        for builder in (build_coverage_driven, build_coverage_cases_driven):
            for status in ("confirmed", "controlled_negative"):
                with self.subTest(builder=builder.__name__, status=status):
                    report = await self.drive(builder, status, "")
                    self.assertEqual(report[status], 1, report["by_status"])


class IncompleteRecoveryCallerTests(unittest.TestCase):
    def _scenario(self, *, failing_requests, budget, calls):
        from harness.validators.cors_validator import CorsValidator
        target = _Target(cors=True, failed_requests=failing_requests)
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=budget,
                                gate_config={"active_enabled": True})
        registry = ExecutionRegistry(ctx.budget)
        cache = _ConfirmationCache(ctx, lambda *args: "unused", registry=registry)
        validator = CorsValidator(run_context=ctx, allowed_hosts=["127.0.0.1"])

        async def run():
            try:
                return [await cache.validate(validator, _finding_of("cors"),
                        _ex(target.base + "/cors?x=" + str(i)), case_ref="case-" + str(i))
                        for i in range(calls)]
            finally:
                await ctx.aclose()
        try:
            results = asyncio.run(run())
            return results, target.server.requests, registry.stats()
        finally:
            target.close()

    def test_incomplete_cors_recovers_then_reuses_successful_evidence_reference(self):
        results, sends, stats = self._scenario(failing_requests=8, budget=24, calls=3)
        self.assertEqual(results[0].status, "inconclusive")
        self.assertTrue(results[1].confirmed, results[1].summary)
        self.assertTrue(results[1].attack_artifact_id)
        self.assertEqual(results[2].covered_by, "case-1")
        self.assertFalse(results[2].confirmed)
        self.assertEqual(results[2].attack_artifact_id, "")
        self.assertEqual(results[2].sent_count, 0)
        self.assertEqual((sends, stats["misses"], stats["hits"]), (19, 2, 1))

    def test_repeated_incomplete_attempts_respect_existing_transport_budget(self):
        results, sends, stats = self._scenario(failing_requests=100, budget=12, calls=4)
        self.assertEqual([r.status for r in results],
                         ["inconclusive", "blocked", "blocked", "blocked"])
        self.assertFalse(any(r.confirmed for r in results))
        self.assertEqual((sends, stats["misses"], stats["hits"]), (12, 4, 0))

    def test_concurrent_callers_allow_bounded_recovery_and_join_completed_result(self):
        registry, validator = ExecutionRegistry(), _Counting(delay=0.02)
        calls = 0
        async def actual():
            nonlocal calls
            calls += 1
            result = await validator.validate(_finding_of("sqli"), _ex("http://fixture.invalid/a?q=1"))
            if calls == 1:
                result.status, result.confirmed = "inconclusive", False
            return result
        async def run():
            first, second = await asyncio.gather(*[
                registry.run(validator, _finding_of("sqli"), _ex("http://fixture.invalid/a?q=1"),
                             case_ref=case, call=actual) for case in ("a", "b")])
            third = await registry.run(validator, _finding_of("sqli"), _ex("http://fixture.invalid/a?q=1"),
                                       case_ref="c", call=actual)
            return first, second, third
        first, second, third = asyncio.run(run())
        self.assertEqual(first.status, "inconclusive")
        self.assertTrue(second.confirmed)
        self.assertEqual(third.covered_by, "b")
        self.assertEqual(calls, 2)
        self.assertEqual(registry.stats()["inflight_joins"], 1)


class TypedIncompleteReuseTests(unittest.TestCase):
    def test_explicit_legacy_incompleteness_is_not_reused_but_held_control_is(self):
        registry, validator = ExecutionRegistry(), _Counting(status="not_confirmed", confirmed=False)
        calls = 0
        async def actual():
            nonlocal calls
            calls += 1
            result = await validator.validate(_finding_of("sqli"), _ex("http://fixture.invalid/a"))
            result.control_outcome = "inconclusive" if calls == 1 else "control_held"
            return result
        async def run():
            return [await registry.run(validator, _finding_of("sqli"), _ex("http://fixture.invalid/a"),
                                       case_ref=str(i), call=actual) for i in range(3)]
        first, healthy, covered = asyncio.run(run())
        self.assertEqual(first.control_outcome, "inconclusive")
        self.assertEqual(healthy.control_outcome, "control_held")
        self.assertEqual(covered.covered_by, "1")
        self.assertEqual(calls, 2)

    def test_production_coverage_dispatch_budget_bounds_incomplete_calls(self):
        from harness.test_assessment_coverage_repair import CoverageRepairTests
        state, roles = CoverageRepairTests.fixture(None)
        registry, validator = ExecutionRegistry(), _Counting(status="inconclusive", confirmed=False)
        calls = []
        async def dispatch(identity, method, path, check):
            calls.append((identity, method, path, check.id))
            exchange = _ex("http://shop.test" + path, method)
            finding = _finding_of(check.vulnerability_class)
            return await registry.run(validator, finding, exchange, case_ref=str(len(calls)),
                                      call=lambda: validator.validate(finding, exchange))
        result = asyncio.run(build_coverage_driven(state, roles, dispatch,
                                                  driveable={"cross_identity"}, budget=2))
        self.assertEqual(len(calls), 2)
        self.assertEqual(registry.stats()["misses"], 2)
        self.assertEqual(registry.stats()["hits"], 0)
        self.assertTrue(result["pending"] or result["skipped"])


class ConditionalReuseCallerTests(unittest.TestCase):
    """Batch 04: reuse is conditional on the inputs that decide the verdict and
    linked to the original attempt. Every case dispatches through the production
    `_ConfirmationCache` against a real registry; CORS cases use the real
    validator and a loopback target."""

    def _cors(self, *, failing_requests, calls, budget=400, retry_limit=None):
        from harness.validators.cors_validator import CorsValidator
        target = _Target(cors=True, failed_requests=failing_requests)
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=budget,
                                gate_config={"active_enabled": True})
        registry = (ExecutionRegistry(ctx.budget) if retry_limit is None
                    else ExecutionRegistry(ctx.budget, retry_limit=retry_limit))
        cache = _ConfirmationCache(ctx, lambda *args: "unused", registry=registry)
        validator = CorsValidator(run_context=ctx, allowed_hosts=["127.0.0.1"])

        async def run():
            try:
                return [await cache.validate(validator, _finding_of("cors"),
                        _ex(target.base + "/cors"), case_ref="case")
                        for _ in range(calls)]
            finally:
                await ctx.aclose()
        try:
            return asyncio.run(run()), target.server.requests, registry.stats()
        finally:
            target.close()

    def _dispatch(self, pairs, validator=None):
        """[(finding, exchange, case)] through one cache; returns (results, validator)."""
        validator = validator or _Counting()
        ctx = RunContext.create(allowed_hosts=["fixture.invalid"])
        cache = _ConfirmationCache(ctx, lambda *args: "unused", registry=ExecutionRegistry())

        async def run():
            out = []
            for finding, exchange, case, v in pairs:
                out.append(await cache.validate(v or validator, finding, exchange, case_ref=case))
            return out
        return asyncio.run(run()), validator

    def test_partial_cors_then_recovery_gets_a_new_attempt_and_a_bounded_retry(self):
        results, sends, stats = self._cors(failing_requests=1000, calls=4)
        self.assertEqual([r.status for r in results[:2]], ["inconclusive", "inconclusive"])
        self.assertEqual(stats["misses"], 2, stats)
        # Nothing about the experiment changed: the third and fourth callers get a
        # reference to the last incomplete attempt, not another send.
        self.assertEqual(stats["retry_limited"], 2, stats)
        self.assertTrue(all(r.sent_count == 0 and not r.confirmed for r in results[2:]))
        self.assertEqual(results[3].referenced_attempt, results[1].attempt_id)
        self.assertEqual(sends, 2 * (sends // 2))

    def test_unchanged_successful_experiment_references_its_evidence_without_a_send(self):
        results, sends, stats = self._cors(failing_requests=0, calls=2)
        self.assertTrue(results[0].confirmed)
        self.assertIs(results[1], results[0])
        self.assertEqual((stats["misses"], stats["hits"], stats["sends_saved"] > 0), (1, 1, True))

    def test_a_changed_principal_runs_again(self):
        url = "http://fixture.invalid/a?q=1"
        f = _finding_of("sqli")
        _, v = self._dispatch([(f, _ex(url, headers=_ALICE), "c", None),
                               (f, _ex(url, headers=_BOB), "c", None)])
        self.assertEqual(len(v.calls), 2)

    def test_a_changed_relevant_state_runs_again_but_an_unrelated_one_does_not(self):
        url, other = "http://fixture.invalid/a?q=1", "http://fixture.invalid/b?q=1"
        s1, s2 = _finding_of("sqli"), _finding_of("sqli")
        s1.workflow_state_id, s2.workflow_state_id = "cart:empty", "cart:full"
        unrelated = _finding_of("sqli")
        unrelated.workflow_state_id = "profile:edited"
        results, v = self._dispatch([(s1, _ex(url), "c", None), (s2, _ex(url), "c", None),
                                     (unrelated, _ex(other), "d", None), (s1, _ex(url), "c", None)])
        self.assertEqual(v.calls, [url, url, other])
        self.assertIs(results[3], results[0])

    def test_a_changed_nested_json_body_does_not_collide(self):
        url = "http://fixture.invalid/api"
        h = {"Content-Type": "application/json"}
        a = json.dumps({"user": {"name": "x"}})
        b = json.dumps({"user": {"role": "x"}})
        c = json.dumps({"user": [{"name": "x"}]})
        f = _finding_of("sqli")
        _, v = self._dispatch([(f, _ex(url, "POST", h, a), "c", None),
                               (f, _ex(url, "POST", h, b), "c", None),
                               (f, _ex(url, "POST", h, c), "c", None),
                               (f, _ex(url, "POST", h, json.dumps({"user": {"name": "y"}})), "c", None)])
        # Shape-keyed: a different nested shape runs; only a nested VALUE change is
        # the declared equivalence of a shape-keyed mechanism.
        self.assertEqual(len(v.calls), 3)

    def test_a_nested_value_change_runs_again_for_an_exact_mechanism(self):
        url = "http://fixture.invalid/api"
        h = {"Content-Type": "application/json"}
        f = _finding_of("cross_identity")
        v = _Counting(name="cross_identity_validator")
        _, v = self._dispatch([(f, _ex(url, "POST", h, json.dumps({"o": {"id": 1}})), "c", v),
                               (f, _ex(url, "POST", h, json.dumps({"o": {"id": 2}})), "c", v)], v)
        self.assertEqual(len(v.calls), 2)

    def test_a_changed_mechanism_version_runs_again(self):
        url = "http://fixture.invalid/a?q=1"
        old, new = _Counting(), _Counting()
        new.calls = old.calls
        new.mechanism_version = "2"
        f = _finding_of("sqli")
        results, _ = self._dispatch([(f, _ex(url), "c", old), (f, _ex(url), "c", new),
                                     (f, _ex(url), "c", old)], old)
        self.assertEqual(len(old.calls), 2)
        self.assertIs(results[2], results[0])

    def test_a_cache_hit_for_another_case_manufactures_no_proof(self):
        url = "http://fixture.invalid/a?q=1"
        f = _finding_of("sqli")
        results, v = self._dispatch([(f, _ex(url), "one", None), (f, _ex(url), "two", None)])
        self.assertEqual(len(v.calls), 1)
        covered = results[1]
        self.assertFalse(covered.confirmed)
        self.assertEqual((covered.attack_artifact_id, covered.baseline_artifact_id,
                          tuple(covered.control_artifact_ids)), ("", "", ()))
        self.assertEqual(covered.referenced_attempt, results[0].attempt_id)
        self.assertTrue(results[0].confirmed and results[0].attack_artifact_id == "art-a")
