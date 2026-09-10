"""T05/R26 regressions: concrete per-input/per-state coverage CASE keys.

These exercise the child-case layer added to `coverage_model`:

  * input derivation from a REAL request (query occurrence, JSON Pointer, form,
    object id, case-insensitive headers) -- never invented parameters;
  * the aggregation contract "one confirmed child marks endpoint risk, never
    endpoint-wide completion" and sibling independence;
  * lazy budgeting that keeps un-run cases visible and never counted as tested;
  * the new blocked/inconclusive/controlled-negative semantics, and that an old
    `not_detected` is never re-read as a controlled negative;
  * additive serialization (an old matrix with no `cases` key still loads);
  * 1:1 alignment with evidence.TestCaseRef so a case id flows to a T01 proof.

The handoff's explicit test list is annotated inline.
"""
import unittest

import evidence
from coverage_model import (
    CaseKey, CellStatus, CoverageMatrix, NO_PARAMETER_CASE,
    derive_input_cases, derive_input_cases_from_template, _json_pointers,
)


# --------------------------------------------------------------------------- #
# CaseKey identity
# --------------------------------------------------------------------------- #

class CaseKeyTests(unittest.TestCase):
    def test_display_name_not_part_of_identity(self):
        a = CaseKey("header", "x-api-key", 0, "", "X-API-Key")
        b = CaseKey("header", "x-api-key", 0, "", "x-api-key")
        self.assertEqual(a.coord_id(), b.coord_id())

    def test_occurrence_distinguishes_identity(self):
        a = CaseKey("query", "id", 0)
        b = CaseKey("query", "id", 1)
        self.assertNotEqual(a.coord_id(), b.coord_id())

    def test_case_parameter_name_folds_occurrence(self):
        self.assertEqual(CaseKey("query", "id", 0).case_parameter_name(), "id")
        self.assertEqual(CaseKey("query", "id", 1).case_parameter_name(), "id[occ:1]")

    def test_occurrence_encoding_does_not_collide_with_literal_bracket_name(self):
        # R07: occurrence 1 of `id` must not equal occurrence 0 of a literal `id[1]`.
        self.assertNotEqual(CaseKey("query", "id", 1).case_parameter_name(),
                            CaseKey("query", "id[1]", 0).case_parameter_name())

    def test_no_parameter_case(self):
        self.assertTrue(NO_PARAMETER_CASE.is_no_parameter)
        self.assertEqual(NO_PARAMETER_CASE.label(), "<no-parameter>")

    def test_round_trip(self):
        ck = CaseKey("body_json", "/a/b", 0, "state1", "/a/b")
        self.assertEqual(CaseKey.from_dict(ck.to_dict()).coord_id(), ck.coord_id())


# --------------------------------------------------------------------------- #
# Input derivation -- from a REAL request, not invented
# --------------------------------------------------------------------------- #

class DeriveTests(unittest.TestCase):
    def test_query_search_vs_sort_are_distinct(self):
        # handoff: "query search vs sort"
        cases = derive_input_cases(query="search=x&sort=name")
        names = {(c.parameter_location, c.parameter_name) for c in cases}
        self.assertIn(("query", "search"), names)
        self.assertIn(("query", "sort"), names)
        self.assertEqual(len(cases), 2)

    def test_duplicate_query_names_get_occurrence_identity(self):
        # handoff: "duplicate query names"
        cases = derive_input_cases(query="id=1&id=2")
        occ = sorted(c.occurrence for c in cases if c.parameter_name == "id")
        self.assertEqual(occ, [0, 1])
        self.assertEqual(len({c.coord_id() for c in cases}), 2)

    def test_nested_json_body_fields_use_pointers(self):
        # handoff: "nested body fields"
        cases = derive_input_cases(body='{"a": {"b": 1}, "c": 2}',
                                   content_type="application/json")
        ptrs = {c.parameter_name for c in cases if c.parameter_location == "body_json"}
        self.assertEqual(ptrs, {"/a/b", "/c"})

    def test_json_pointer_escaping(self):
        ptrs = _json_pointers({"a/b": 1, "m~n": 2})
        self.assertIn("/a~1b", ptrs)
        self.assertIn("/m~0n", ptrs)

    def test_json_array_leaves(self):
        cases = derive_input_cases(body='{"xs": [10, 20]}', content_type="application/json")
        ptrs = {c.parameter_name for c in cases}
        self.assertEqual(ptrs, {"/xs/0", "/xs/1"})

    def test_form_body_params(self):
        cases = derive_input_cases(body="u=alice&p=secret",
                                   content_type="application/x-www-form-urlencoded")
        locs = {(c.parameter_location, c.parameter_name) for c in cases}
        self.assertEqual(locs, {("body_form", "u"), ("body_form", "p")})

    def test_headers_case_insensitive_and_filtered(self):
        cases = derive_input_cases(
            headers={"X-Forwarded-For": "1.2.3.4", "Host": "t", "Content-Length": "3"},
            include_headers=True)
        hdrs = {c.parameter_name: c.display_name for c in cases if c.parameter_location == "header"}
        # transport/hop-by-hop headers are excluded; identity is folded, original kept
        self.assertEqual(set(hdrs), {"x-forwarded-for"})
        self.assertEqual(hdrs["x-forwarded-for"], "X-Forwarded-For")

    def test_headers_excluded_by_default(self):
        cases = derive_input_cases(headers={"X-Test": "1"})
        self.assertFalse([c for c in cases if c.parameter_location == "header"])

    def test_object_id_becomes_path_case(self):
        cases = derive_input_cases(object_id="42")
        self.assertEqual([(c.parameter_location, c.parameter_name) for c in cases],
                         [("path", "object_id")])

    def test_derive_from_template(self):
        tmpl = {"method": "POST", "query": "q=1", "body": '{"x":1}',
                "content_type": "application/json", "object_id": "7"}
        cases = derive_input_cases_from_template(tmpl)
        locs = {c.parameter_location for c in cases}
        self.assertEqual(locs, {"query", "body_json", "path"})

    def test_no_invented_parameters(self):
        # a plain GET with no query/body yields NO parameter cases (I5: never invent)
        self.assertEqual(derive_input_cases(), [])


# --------------------------------------------------------------------------- #
# Child-case layer + aggregation
# --------------------------------------------------------------------------- #

class AggregationTests(unittest.TestCase):
    KEY = ("user", "GET /api/search", "WSTG-INPV-05")

    def _matrix_with_two_query_cases(self):
        m = CoverageMatrix()
        cases = derive_input_cases(query="search=x&sort=y")
        m.expand_cases(*self.KEY, cases)
        by_name = {c.parameter_name: c for c in cases}
        return m, by_name

    def test_confirming_one_input_does_not_mark_sibling_tested(self):
        # handoff: "A check of one input cannot mark its sibling tested."
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.CONFIRMED,
                      reason="sqlmap confirmed on search")
        # the cell shows endpoint RISK (confirmed) ...
        self.assertEqual(m.get(*self.KEY).status, CellStatus.CONFIRMED)
        # ... but the sort sibling is still pending, not tested
        sort_case = next(r for ck, r in m.cases_for_cell(*self.KEY)
                         if ck.parameter_name == "sort")
        self.assertEqual(sort_case.status, CellStatus.PENDING)
        nt = {c["parameter_name"] for c in m.cases_not_tested()}
        self.assertIn("sort", nt)

    def test_confirmed_child_marks_risk_but_never_completion(self):
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.CONFIRMED, reason="x")
        # exactly one confirmed case; the cell is CONFIRMED (risk), NOT not_detected
        self.assertEqual(m.case_summary()["confirmed"], 1)
        self.assertNotEqual(m.get(*self.KEY).status, CellStatus.NOT_DETECTED)

    def test_all_children_negative_marks_cell_not_detected(self):
        m, by_name = self._matrix_with_two_query_cases()
        for name in ("search", "sort"):
            m.record_case(*self.KEY, by_name[name], status=CellStatus.NOT_DETECTED, reason="clean")
        self.assertEqual(m.get(*self.KEY).status, CellStatus.NOT_DETECTED)

    def test_open_child_forbids_completion(self):
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.NOT_DETECTED, reason="clean")
        # sort still pending -> cell must stay PENDING (not not_detected)
        self.assertEqual(m.get(*self.KEY).status, CellStatus.PENDING)

    def test_negative_plus_error_child_is_not_completion(self):
        # R06: a controlled-negative sibling next to an errored one must NOT read as
        # "all tested" -- the unresolved error forbids a completion claim.
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.CONTROLLED_NEGATIVE, reason="held")
        m.record_case(*self.KEY, by_name["sort"], status=CellStatus.ERROR, reason="leg crashed")
        self.assertEqual(m.get(*self.KEY).status, CellStatus.ERROR)
        self.assertNotEqual(m.get(*self.KEY).status, CellStatus.NOT_DETECTED)

    def test_negative_plus_blocked_child_is_not_completion(self):
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.NOT_DETECTED, reason="clean")
        m.record_case(*self.KEY, by_name["sort"], status=CellStatus.BLOCKED, reason="gate denied")
        self.assertEqual(m.get(*self.KEY).status, CellStatus.PENDING)

    def test_all_controlled_negative_marks_controlled_negative(self):
        m, by_name = self._matrix_with_two_query_cases()
        for name in ("search", "sort"):
            m.record_case(*self.KEY, by_name[name], status=CellStatus.CONTROLLED_NEGATIVE,
                          reason="boundary held")
        self.assertEqual(m.get(*self.KEY).status, CellStatus.CONTROLLED_NEGATIVE)

    def test_two_workflow_states_are_distinct_cases(self):
        # handoff: "two workflow states"
        m = CoverageMatrix()
        s1 = derive_input_cases(query="q=1", workflow_state_id="draft")
        s2 = derive_input_cases(query="q=1", workflow_state_id="approved")
        m.expand_cases(*self.KEY, s1 + s2)
        self.assertEqual(len(m.cases_for_cell(*self.KEY)), 2)

    def test_two_principals_are_distinct_cells(self):
        # handoff: "two principals" -- principal == identity == distinct cell
        m = CoverageMatrix()
        cases = derive_input_cases(query="q=1")
        m.expand_cases("alice", "GET /x", "WSTG-INPV-05", cases)
        m.expand_cases("bob", "GET /x", "WSTG-INPV-05", cases)
        m.record_case("alice", "GET /x", "WSTG-INPV-05", cases[0],
                      status=CellStatus.CONFIRMED, reason="x")
        self.assertEqual(m.get("alice", "GET /x", "WSTG-INPV-05").status, CellStatus.CONFIRMED)
        self.assertEqual(m.get("bob", "GET /x", "WSTG-INPV-05").status, CellStatus.PENDING)

    def test_confirmed_case_not_overwritten(self):
        m, by_name = self._matrix_with_two_query_cases()
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.CONFIRMED, reason="proven")
        m.record_case(*self.KEY, by_name["search"], status=CellStatus.NOT_DETECTED, reason="retry")
        case = next(r for ck, r in m.cases_for_cell(*self.KEY) if ck.parameter_name == "search")
        self.assertEqual(case.status, CellStatus.CONFIRMED)


# --------------------------------------------------------------------------- #
# Lazy budget
# --------------------------------------------------------------------------- #

class BudgetTests(unittest.TestCase):
    KEY = ("user", "POST /api/x", "WSTG-INPV-05")

    def test_budget_exhausted_cases_visible_not_tested(self):
        # handoff: "skipped-required cases"; T05: budget-exhausted stays visible
        m = CoverageMatrix()
        cases = derive_input_cases(query="a=1&b=2&c=3")
        res = m.expand_cases(*self.KEY, cases, budget_remaining=1)
        self.assertEqual(res["added"], 1)
        self.assertEqual(res["budget_skipped"], 2)
        # the skipped cases are visible in the not-tested list with a reason
        skipped = [c for c in m.cases_not_tested() if c["status"] == "skipped"]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all("budget exhausted" in c["reason"] for c in skipped))

    def test_budget_skipped_not_counted_as_tested(self):
        m = CoverageMatrix()
        cases = derive_input_cases(query="a=1&b=2")
        m.expand_cases(*self.KEY, cases, budget_remaining=0)
        cs = m.case_summary()
        self.assertEqual(cs["attempted"], 0)
        self.assertEqual(cs["conclusive"], 0)
        self.assertEqual(cs["skipped"], 2)


# --------------------------------------------------------------------------- #
# New verdict semantics
# --------------------------------------------------------------------------- #

class VerdictSemanticsTests(unittest.TestCase):
    def test_controlled_negative_counts_as_conclusive(self):
        m = CoverageMatrix()
        ck = CaseKey("query", "q", 0)
        m.record_case("u", "GET /x", "WSTG-INPV-05", ck,
                      status=CellStatus.CONTROLLED_NEGATIVE, reason="held")
        self.assertEqual(m.case_summary()["conclusive"], 1)

    def test_blocked_and_inconclusive_not_attempted(self):
        m = CoverageMatrix()
        m.record_case("u", "GET /x", "C", CaseKey("query", "a"), status=CellStatus.BLOCKED, reason="gate")
        m.record_case("u", "GET /x", "C", CaseKey("query", "b"), status=CellStatus.INCONCLUSIVE, reason="skip")
        cs = m.case_summary()
        self.assertEqual(cs["attempted"], 0)
        self.assertEqual(cs["blocked"], 1)
        self.assertEqual(cs["inconclusive"], 1)

    def test_old_not_detected_is_not_a_controlled_negative(self):
        # the review's explicit rule: an old not_detected must never be re-read as
        # a controlled negative. The cell/case status is preserved verbatim.
        m = CoverageMatrix()
        m.record("u", "GET /x", "WSTG-INPV-05", status=CellStatus.NOT_DETECTED, reason="legacy")
        m2 = CoverageMatrix.from_dict(m.to_dict())
        self.assertEqual(m2.get("u", "GET /x", "WSTG-INPV-05").status, CellStatus.NOT_DETECTED)
        self.assertEqual(m2.summary()["controlled_negative"], 0)


# --------------------------------------------------------------------------- #
# Serialization back-compat + counts
# --------------------------------------------------------------------------- #

class SerializationTests(unittest.TestCase):
    def test_cases_round_trip(self):
        m = CoverageMatrix()
        cases = derive_input_cases(query="a=1&b=2")
        m.expand_cases("u", "GET /x", "WSTG-INPV-05", cases)
        m.record_case("u", "GET /x", "WSTG-INPV-05", cases[0],
                      status=CellStatus.CONFIRMED, reason="x")
        m2 = CoverageMatrix.from_dict(m.to_dict())
        self.assertEqual(len(m2.cases_for_cell("u", "GET /x", "WSTG-INPV-05")), 2)
        self.assertEqual(m2.get("u", "GET /x", "WSTG-INPV-05").status, CellStatus.CONFIRMED)

    def test_old_matrix_without_cases_key_loads(self):
        # handoff: "old matrix deserialization"
        old = {"cells": {"user|GET /x|WSTG-INPV-05": {"status": "not_detected", "reason": "r"}}}
        m = CoverageMatrix.from_dict(old)
        self.assertEqual(m.get("user", "GET /x", "WSTG-INPV-05").status, CellStatus.NOT_DETECTED)
        self.assertEqual(m.case_summary()["total_cases"], 0)

    def test_case_counts_agree_with_actual_attempts(self):
        # handoff: "counts agree with actual attempts"
        m = CoverageMatrix()
        cases = derive_input_cases(query="a=1&b=2&c=3")
        m.expand_cases("u", "GET /x", "WSTG-INPV-05", cases)
        m.record_case("u", "GET /x", "WSTG-INPV-05", cases[0], status=CellStatus.CONFIRMED, reason="x")
        m.record_case("u", "GET /x", "WSTG-INPV-05", cases[1], status=CellStatus.NOT_DETECTED, reason="x")
        cs = m.case_summary()
        # two attempts (confirm + not_detected), one still pending
        self.assertEqual(cs["attempted"], 2)
        self.assertEqual(cs["conclusive"], 2)
        self.assertEqual(cs["pending"], 1)


# --------------------------------------------------------------------------- #
# Alignment with evidence.TestCaseRef (the T01 proof identity)
# --------------------------------------------------------------------------- #

class TestCaseRefAlignmentTests(unittest.TestCase):
    def _case_id(self, ck):
        return evidence.TestCaseRef.make(
            run_id="run1", request_template_id="tmpl1", check_id="WSTG-INPV-05",
            principal_id="user",
            parameter_location=ck.parameter_location,
            parameter_name=ck.case_parameter_name(),
            workflow_state_id=ck.workflow_state_id).case_id

    def test_distinct_params_get_distinct_proof_case_ids(self):
        a, b = derive_input_cases(query="search=1&sort=2")
        self.assertNotEqual(self._case_id(a), self._case_id(b))

    def test_repeated_param_occurrences_get_distinct_proof_case_ids(self):
        a, b = derive_input_cases(query="id=1&id=2")
        self.assertNotEqual(self._case_id(a), self._case_id(b))

    def test_same_scenario_is_stable(self):
        (a,) = derive_input_cases(query="q=1")
        (b,) = derive_input_cases(query="q=1")
        self.assertEqual(self._case_id(a), self._case_id(b))


if __name__ == "__main__":
    unittest.main()
