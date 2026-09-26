"""
Caller-level contract tests for the RB-6 capability-ownership matrix
(harness/execution_planes.py).

Three things are enforced, all against the REAL source (not a hardcoded
snapshot), so a future capability added to either plane and forgotten in the
matrix fails CI instead of silently drifting:

  1. Exclusivity (the RB-6 acceptance criterion): every matrix entry has
     EXACTLY ONE authoritative plane.
  2. Coverage / no-drift, both directions: every `case "<cap>" ->` label in
     ValidationExecutor.java's switch appears in the matrix with
     java_present=True, and vice versa (no stale/typo'd java_names); every
     ValidatorRegistry key and every `_val_by_conf` key in
     orchestrator_chain.py appears in the matrix with python_present=True,
     and vice versa (no stale/typo'd python_name).
  3. A focused assertion that the known dual-plane capability families named
     in the RB-6 backlog item are Python-authoritative.

This is a source-review test (regex/text parsing of .java/.py files), not a
build: it never compiles or runs Java, and never sends network traffic.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from harness import execution_planes
from harness.execution_planes import CAPABILITY_MATRIX

ROOT = Path(__file__).resolve().parent.parent
VALIDATION_EXECUTOR_JAVA = ROOT / "burp-extension" / "src" / "main" / "java" / "com" / "harness" / "llm" / "ValidationExecutor.java"
REGISTRY_PY = ROOT / "harness" / "validators" / "registry.py"
ORCHESTRATOR_CHAIN_PY = ROOT / "harness" / "orchestrator_chain.py"


def _extract_balanced(text: str, open_index: int) -> str:
    """Return the substring from text[open_index] (a '{') through its matching '}'."""
    assert text[open_index] == "{"
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index:i + 1]
    raise ValueError("unbalanced braces")


def _java_switch_case_labels() -> set[str]:
    """Every literal case "<cap>" label in ValidationExecutor.java's
    switch (plan.capability) block, skipping the `default ->` arm."""
    text = VALIDATION_EXECUTOR_JAVA.read_text(encoding="utf-8")
    switch_start = text.index("switch (plan.capability)")
    body_start = text.index("{", switch_start)
    body = _extract_balanced(text, body_start)
    labels: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("case "):
            continue
        arm = stripped[len("case "):]
        arm = arm.split("->", 1)[0]
        labels.update(re.findall(r'"([^"]+)"', arm))
    return labels


def _python_registry_keys() -> set[str]:
    """Every self.validators["<key>"] = ... registration in registry.py."""
    text = REGISTRY_PY.read_text(encoding="utf-8")
    return set(re.findall(r'self\.validators\[\s*"([A-Za-z0-9_]+)"\s*\]\s*=', text))


def _python_val_by_conf_keys() -> set[str]:
    """Every key of the `_val_by_conf` confirmation-name map in
    orchestrator_chain.py::investigate_engagement (dict literal + the one
    conditional `_val_by_conf["sqlmap"] = ...` assignment)."""
    text = ORCHESTRATOR_CHAIN_PY.read_text(encoding="utf-8")
    literal_start = text.index("_val_by_conf = {")
    brace_start = text.index("{", literal_start)
    body = _extract_balanced(text, brace_start)
    keys = set(re.findall(r'"([A-Za-z0-9_]+)"\s*:', body))
    keys.update(re.findall(r'_val_by_conf\[\s*"([A-Za-z0-9_]+)"\s*\]\s*=', text))
    return keys


class ExecutionPlaneMatrixSourceGroundingTests(unittest.TestCase):
    """Sanity-check the fixtures this module's tests depend on, so a broken
    parse fails loudly here instead of silently passing the real tests below
    with an empty set."""

    def test_java_source_file_exists(self):
        self.assertTrue(VALIDATION_EXECUTOR_JAVA.is_file(), VALIDATION_EXECUTOR_JAVA)

    def test_java_switch_extraction_is_non_trivial(self):
        labels = _java_switch_case_labels()
        self.assertGreaterEqual(len(labels), 25, labels)
        self.assertIn("cross_identity_compare", labels)
        self.assertIn("jwt_validation", labels)
        self.assertNotIn("plan.capability", labels)

    def test_python_registry_extraction_is_non_trivial(self):
        keys = _python_registry_keys()
        self.assertGreaterEqual(len(keys), 25, keys)
        self.assertIn("cross_identity", keys)
        self.assertIn("jwt_forge", keys)

    def test_val_by_conf_extraction_is_non_trivial(self):
        keys = _python_val_by_conf_keys()
        self.assertGreaterEqual(len(keys), 15, keys)
        self.assertIn("cross_identity", keys)
        self.assertIn("jwt_forge", keys)
        self.assertIn("sqlmap", keys)


class ExclusivityTests(unittest.TestCase):
    """RB-6 acceptance criterion: no capability is authoritative in both planes."""

    def test_every_capability_has_exactly_one_authoritative_plane(self):
        for canonical, cap in CAPABILITY_MATRIX.items():
            with self.subTest(canonical=canonical):
                self.assertIn(cap.authoritative, ("python", "java"))
                is_python_authoritative = cap.authoritative == "python"
                is_java_authoritative = cap.authoritative == "java"
                # exactly one of the two -- never both, never neither.
                self.assertEqual(
                    1, int(is_python_authoritative) + int(is_java_authoritative),
                    f"{canonical} must be authoritative in exactly one plane")

    def test_authoritative_plane_is_actually_present(self):
        # A capability can't be authoritative in a plane it doesn't exist in.
        for canonical, cap in CAPABILITY_MATRIX.items():
            with self.subTest(canonical=canonical):
                if cap.authoritative == "python":
                    self.assertTrue(cap.python_present)
                else:
                    self.assertTrue(cap.java_present)

    def test_no_capability_is_present_in_neither_plane(self):
        for canonical, cap in CAPABILITY_MATRIX.items():
            with self.subTest(canonical=canonical):
                self.assertTrue(cap.python_present or cap.java_present)


class JavaCoverageNoDriftTests(unittest.TestCase):
    """Every Java switch case label is accounted for in the matrix, and the
    matrix names no Java case label that doesn't actually exist -- both
    directions, so the test catches a future addition OR a stale/typo'd
    matrix entry."""

    def test_every_java_switch_case_label_is_in_the_matrix(self):
        source_labels = _java_switch_case_labels()
        matrix_labels = execution_planes.java_capability_names()
        missing = source_labels - matrix_labels
        self.assertEqual(set(), missing,
                          f"ValidationExecutor.java case label(s) not recorded in the matrix: {missing}")

    def test_matrix_names_no_java_case_label_that_does_not_exist(self):
        source_labels = _java_switch_case_labels()
        matrix_labels = execution_planes.java_capability_names()
        stale = matrix_labels - source_labels
        self.assertEqual(set(), stale,
                          f"matrix java_names not present in ValidationExecutor.java's switch: {stale}")

    def test_java_present_entries_match_the_java_names_field(self):
        for canonical, cap in CAPABILITY_MATRIX.items():
            with self.subTest(canonical=canonical):
                self.assertEqual(cap.java_present, bool(cap.java_names))


class PythonCoverageNoDriftTests(unittest.TestCase):
    """Every ValidatorRegistry key and every _val_by_conf key is accounted
    for in the matrix, and the matrix names no python_name that doesn't
    actually exist in the registry -- both directions."""

    def test_every_registry_key_is_in_the_matrix(self):
        source_keys = _python_registry_keys()
        matrix_names = execution_planes.python_capability_names()
        missing = source_keys - matrix_names
        self.assertEqual(set(), missing,
                          f"ValidatorRegistry key(s) not recorded in the matrix: {missing}")

    def test_every_val_by_conf_key_is_in_the_matrix(self):
        source_keys = _python_val_by_conf_keys()
        matrix_names = execution_planes.python_capability_names()
        missing = source_keys - matrix_names
        self.assertEqual(set(), missing,
                          f"_val_by_conf key(s) not recorded in the matrix: {missing}")

    def test_matrix_names_no_registry_key_that_does_not_exist(self):
        source_keys = _python_registry_keys()
        matrix_names = execution_planes.python_capability_names()
        stale = matrix_names - source_keys
        self.assertEqual(set(), stale,
                          f"matrix python_name(s) not present in ValidatorRegistry: {stale}")

    def test_python_present_entries_match_the_python_name_field(self):
        for canonical, cap in CAPABILITY_MATRIX.items():
            with self.subTest(canonical=canonical):
                self.assertEqual(cap.python_present, bool(cap.python_name))


class KnownDualPlaneCapabilitiesArePythonAuthoritativeTests(unittest.TestCase):
    """Focused assertion (RB-6 acceptance): the capability families the
    backlog item calls out by name are all present in both planes and
    Python-authoritative."""

    KNOWN_DUAL_PLANE = (
        "cross_identity", "jwt", "xxe", "csrf", "ssti", "command_injection",
        "open_redirect", "rate_limit", "file_upload", "sql_injection",
    )

    def test_known_dual_plane_capabilities_are_present_in_both_planes(self):
        for canonical in self.KNOWN_DUAL_PLANE:
            with self.subTest(canonical=canonical):
                self.assertIn(canonical, CAPABILITY_MATRIX)
                cap = CAPABILITY_MATRIX[canonical]
                self.assertTrue(cap.python_present, f"{canonical} should be python_present")
                self.assertTrue(cap.java_present, f"{canonical} should be java_present")

    def test_known_dual_plane_capabilities_are_python_authoritative(self):
        for canonical in self.KNOWN_DUAL_PLANE:
            with self.subTest(canonical=canonical):
                self.assertEqual("python", execution_planes.authoritative_plane(canonical))

    def test_dual_plane_capabilities_helper_is_a_superset_of_the_known_set(self):
        dual = execution_planes.dual_plane_capabilities()
        for canonical in self.KNOWN_DUAL_PLANE:
            self.assertIn(canonical, dual)


class MatrixConstructionNegativeControlTests(unittest.TestCase):
    """Negative control: CapabilityOwnership itself refuses the invalid
    shapes the exclusivity/coverage tests above are supposed to catch, so a
    change that broke __post_init__'s validation (rather than just failing
    to call it) would still be caught here."""

    def test_rejects_authoritative_plane_the_capability_is_not_present_in(self):
        with self.assertRaises(ValueError):
            execution_planes.CapabilityOwnership(
                canonical="bogus", python_present=False, java_present=True,
                authoritative="python", java_names=("bogus_case",))

    def test_rejects_absent_from_both_planes(self):
        with self.assertRaises(ValueError):
            execution_planes.CapabilityOwnership(
                canonical="bogus", python_present=False, java_present=False,
                authoritative="python")

    def test_rejects_invalid_authoritative_value(self):
        with self.assertRaises(ValueError):
            execution_planes.CapabilityOwnership(
                canonical="bogus", python_present=True, java_present=False,
                authoritative="both", python_name="bogus")

    def test_rejects_python_present_without_a_name(self):
        with self.assertRaises(ValueError):
            execution_planes.CapabilityOwnership(
                canonical="bogus", python_present=True, java_present=False,
                authoritative="python", python_name=None)

    def test_rejects_java_present_without_names(self):
        with self.assertRaises(ValueError):
            execution_planes.CapabilityOwnership(
                canonical="bogus", python_present=False, java_present=True,
                authoritative="java", java_names=())

    def test_accepts_a_well_formed_java_only_entry(self):
        cap = execution_planes.CapabilityOwnership(
            canonical="bogus", python_present=False, java_present=True,
            authoritative="java", java_names=("bogus_case",))
        self.assertEqual("java", cap.authoritative)


if __name__ == "__main__":
    unittest.main()
