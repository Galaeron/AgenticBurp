"""P1.4 -- MITRE-shaped attack tree over the task graph.

Covers: ATT&CK technique auto-mapping from a finding's vulnerability_class,
explicit overrides, evidence references, value-ordered (best-first) search over
READY tasks, and round-tripping the new fields through to_dict/from_dict.
"""
import unittest

from harness import task_graph
from harness.task_graph import TaskGraph, DONE, attack_technique_for


class AttackTechniqueMappingTests(unittest.TestCase):
    def test_known_class_maps_to_a_technique(self):
        tid, name = attack_technique_for("sqli")
        self.assertEqual(tid, "T1190")
        self.assertTrue(name)

    def test_case_and_whitespace_insensitive(self):
        self.assertEqual(attack_technique_for("  SQLi  "), attack_technique_for("sqli"))

    def test_unmapped_class_returns_none(self):
        self.assertIsNone(attack_technique_for("not_a_real_class"))

    def test_empty_class_returns_none(self):
        self.assertIsNone(attack_technique_for(""))
        self.assertIsNone(attack_technique_for(None))


class TaskCarriesAttackTechniqueTests(unittest.TestCase):
    def test_auto_derived_from_meta_vulnerability_class(self):
        g = TaskGraph()
        t = g.add("confirm", "/api/users/{id}", source="finding:idor-1",
                  meta={"vulnerability_class": "idor", "severity": "high", "confidence": 0.8})
        self.assertEqual(t.attack_technique, "T1078")
        self.assertEqual(t.attack_technique_name, "Valid Accounts")

    def test_unmapped_class_leaves_technique_blank_not_fabricated(self):
        g = TaskGraph()
        t = g.add("confirm", "/x", meta={"vulnerability_class": "totally_unknown"})
        self.assertEqual(t.attack_technique, "")
        self.assertEqual(t.attack_technique_name, "")

    def test_no_meta_leaves_technique_blank(self):
        g = TaskGraph()
        t = g.add("manual", "review-this")
        self.assertEqual(t.attack_technique, "")

    def test_explicit_override_wins_over_auto_derivation(self):
        g = TaskGraph()
        t = g.add("confirm", "/x", meta={"vulnerability_class": "sqli"},
                  attack_technique="T9999")
        self.assertEqual(t.attack_technique, "T9999")
        # explicit override does not also set the mapped name (caller-supplied
        # technique may not be in our small map at all)
        self.assertEqual(t.attack_technique_name, "")

    def test_evidence_ref_defaults_to_source(self):
        g = TaskGraph()
        t = g.add("confirm", "/x", source="https://t.test/api/x")
        self.assertEqual(t.evidence_ref, "https://t.test/api/x")

    def test_evidence_ref_explicit_overrides_source(self):
        g = TaskGraph()
        t = g.add("confirm", "/x", source="https://t.test/api/x",
                  evidence_ref="finding:abc123")
        self.assertEqual(t.evidence_ref, "finding:abc123")

    def test_no_source_or_evidence_ref_is_empty_not_fabricated(self):
        g = TaskGraph()
        t = g.add("manual", "review-this")
        self.assertEqual(t.evidence_ref, "")


class ValueDerivationTests(unittest.TestCase):
    def test_critical_outranks_high(self):
        g = TaskGraph()
        crit = g.add("confirm", "/crit", meta={"severity": "critical", "confidence": 1.0})
        high = g.add("confirm", "/high", meta={"severity": "high", "confidence": 1.0})
        self.assertGreater(crit.value, high.value)

    def test_confidence_scales_within_band(self):
        g = TaskGraph()
        hi_conf = g.add("confirm", "/a", meta={"severity": "high", "confidence": 1.0})
        lo_conf = g.add("confirm", "/b", meta={"severity": "high", "confidence": 0.1})
        self.assertGreater(hi_conf.value, lo_conf.value)

    def test_unscored_task_gets_neutral_value(self):
        g = TaskGraph()
        t = g.add("manual", "x")
        self.assertEqual(t.value, 1.0)

    def test_explicit_value_overrides_derivation(self):
        g = TaskGraph()
        t = g.add("confirm", "/x", meta={"severity": "info"}, value=99.0)
        self.assertEqual(t.value, 99.0)


class ReadyByValueSearchTests(unittest.TestCase):
    def test_orders_ready_tasks_highest_value_first(self):
        g = TaskGraph()
        g.add("confirm", "/low", meta={"severity": "low", "confidence": 1.0})
        g.add("confirm", "/crit", meta={"severity": "critical", "confidence": 1.0})
        g.add("confirm", "/med", meta={"severity": "medium", "confidence": 1.0})
        ordered = g.ready_by_value()
        self.assertEqual([t.target for t in ordered], ["/crit", "/med", "/low"])

    def test_blocked_tasks_are_excluded_even_if_high_value(self):
        g = TaskGraph()
        obtain = g.add("obtain", "cred")
        g.add("confirm", "/blocked-crit", depends_on=[obtain.id],
             meta={"severity": "critical", "confidence": 1.0})
        # low confidence so its value sits clearly below the unscored "cred"
        # task's neutral 1.0 -- this assertion is about ready/blocked filtering,
        # not about the value formula's own tie-breaking.
        g.add("confirm", "/ready-low", meta={"severity": "low", "confidence": 0.1})
        ordered = g.ready_by_value()
        self.assertEqual([t.target for t in ordered], ["cred", "/ready-low"])
        g.mark(obtain.id, DONE)
        ordered = g.ready_by_value()
        self.assertIn("/blocked-crit", [t.target for t in ordered])

    def test_equal_value_ties_break_deterministically_on_id(self):
        g = TaskGraph()
        g.add("confirm", "/b", meta={"severity": "medium", "confidence": 1.0})
        g.add("confirm", "/a", meta={"severity": "medium", "confidence": 1.0})
        first = [t.id for t in g.ready_by_value()]
        second = [t.id for t in g.ready_by_value()]
        self.assertEqual(first, second)              # stable across repeated calls
        self.assertEqual(first, sorted(first))        # and matches id order (the documented tie-break)

    def test_empty_graph_returns_empty_list(self):
        g = TaskGraph()
        self.assertEqual(g.ready_by_value(), [])


class RoundTripTests(unittest.TestCase):
    def test_to_dict_from_dict_preserves_new_fields(self):
        g = TaskGraph()
        g.add("confirm", "/x", source="https://t.test/x",
             meta={"vulnerability_class": "xxe", "severity": "high", "confidence": 0.9})
        d = g.to_dict()
        g2 = TaskGraph.from_dict(d)
        t2 = list(g2.tasks.values())[0]
        self.assertEqual(t2.attack_technique, "T1190")
        self.assertEqual(t2.attack_technique_name, "Exploit Public-Facing Application")
        self.assertEqual(t2.evidence_ref, "https://t.test/x")
        self.assertGreater(t2.value, 0)

    def test_from_dict_missing_new_fields_defaults_safely(self):
        # a graph serialized before P1.4 has none of the new keys -- must load
        # without KeyError and with harmless defaults (backward compatibility).
        legacy = {"tasks": {"analyze:/x": {"id": "analyze:/x", "kind": "analyze", "target": "/x"}}}
        g = TaskGraph.from_dict(legacy)
        t = g.tasks["analyze:/x"]
        self.assertEqual(t.attack_technique, "")
        self.assertEqual(t.evidence_ref, "")
        self.assertEqual(t.value, 0.0)


if __name__ == "__main__":
    unittest.main()
