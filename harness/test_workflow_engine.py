import unittest

from workflow_engine import (
    Assertion, Extractor, ExtractorKind, StepStatus, Workflow, WorkflowResult,
    WorkflowStep, bind_template, extract_all, json_pointer,
)


class ContractTests(unittest.TestCase):
    def test_versioned_workflow_requires_ordered_unique_dependencies(self):
        create = WorkflowStep("create", "POST", "/items", "alice")
        approve = WorkflowStep("approve", "POST", "/items/{{id}}/approve", "manager",
                               prerequisites=("create",))
        wf = Workflow("approval", (create, approve), version=2)
        self.assertEqual(wf.version, 2)
        with self.assertRaises(ValueError):
            Workflow("bad", (approve, create))
        with self.assertRaises(ValueError):
            Workflow("bad", (create, create))

    def test_cleanup_and_assertions_are_explicit_records(self):
        step = WorkflowStep("delete", "DELETE", "/items/{{id}}", "alice",
                            prerequisites=("create",), cleanup=True,
                            assertions=(Assertion("status", expected=204),))
        self.assertTrue(step.cleanup)
        self.assertEqual(step.assertions[0].expected, 204)

    def test_incomplete_result_is_never_complete(self):
        result = WorkflowResult("w", 1, steps=[
            type("S", (), {"status": StepStatus.BLOCKED})()
        ])
        self.assertFalse(result.complete)


class BindingTests(unittest.TestCase):
    def test_missing_value_blocks_instead_of_guessing(self):
        rendered, missing = bind_template("/items/{{item_id}}", {})
        self.assertEqual(rendered, "/items/{{item_id}}")
        self.assertEqual(missing, ("item_id",))

    def test_all_present_values_bind(self):
        rendered, missing = bind_template("/{{id}}?token={{token}}", {"id": "7", "token": "abc"})
        self.assertEqual(rendered, "/7?token=abc")
        self.assertEqual(missing, ())


class ExtractorTests(unittest.TestCase):
    def test_json_pointer_nested_and_escaped(self):
        self.assertEqual(json_pointer('{"a/b":{"~x":[3]}}', "/a~1b/~0x/0"), "3")

    def test_location_is_resolved(self):
        values, missing = extract_all((Extractor("item_url", ExtractorKind.LOCATION),),
                                      body="", headers={"Location": "/items/7"},
                                      response_url="http://t.test/items")
        self.assertEqual(values["item_url"], "http://t.test/items/7")
        self.assertEqual(missing, ())

    def test_hidden_field_extraction(self):
        ex = Extractor("csrf", ExtractorKind.HTML_HIDDEN, "csrf_token")
        values, missing = extract_all((ex,), body='<input type="hidden" name="csrf_token" value="T7">',
                                      headers={}, response_url="http://t.test/form")
        self.assertEqual(values, {"csrf": "T7"})
        self.assertEqual(missing, ())

    def test_required_missing_blocks_optional_missing_does_not(self):
        exs = (Extractor("id", ExtractorKind.JSON_POINTER, "/id"),
               Extractor("note", ExtractorKind.JSON_POINTER, "/note", required=False))
        values, missing = extract_all(exs, body="{}", headers={}, response_url="http://t.test")
        self.assertEqual(values, {})
        self.assertEqual(missing, ("id",))


if __name__ == "__main__":
    unittest.main()
