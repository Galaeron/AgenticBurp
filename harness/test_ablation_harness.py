"""W-22: the A-F ablation harness runs variants reproducibly and tabulates
mean +/- variance across repeats -- verified without a live model via a stub
runner."""
import unittest

import ablation_harness as ah
from ablation_harness import RunMetrics, Variant, run_ablation


class VariantDefinitionTests(unittest.TestCase):
    def test_all_six_variants_present_and_tagged(self):
        keys = [v.key for v in ah.VARIANTS]
        self.assertEqual(keys, ["A", "B", "C", "D", "E", "F"])

    def test_config_transforms_tag_and_do_not_mutate_base(self):
        base = {"critique": {"enabled": True}}
        for v in ah.VARIANTS:
            cfg = v.config_transform(base)
            self.assertEqual(cfg[ah.MARKER], v.key)
        # base untouched (deepcopy)
        self.assertTrue(base["critique"]["enabled"])

    def test_minus_critique_is_pure_config(self):
        d = next(v for v in ah.VARIANTS if v.key == "D")
        cfg = d.config_transform({"critique": {"enabled": True}})
        self.assertFalse(cfg["critique"]["enabled"])
        self.assertFalse(d.needs_implementation)

    def test_non_config_variants_flagged_needs_implementation(self):
        for key in ("B", "C", "E", "F"):
            v = next(x for x in ah.VARIANTS if x.key == key)
            self.assertTrue(v.needs_implementation, f"{key} should be flagged needs_implementation")


class RunAndAggregateTests(unittest.TestCase):
    def _stub_runner(self):
        # Deterministic per-variant metrics with a little per-run spread so
        # variance is non-zero and testable.
        calls = {"n": 0}

        def runner(variant: Variant, config: dict, corpus) -> RunMetrics:
            calls["n"] += 1
            base_tp = {"A": 10, "B": 8, "C": 5, "D": 9, "E": 6, "F": 9}[variant.key]
            spread = calls["n"] % 2  # 0 or 1
            return RunMetrics(tp=base_tp + spread, fp=2, fn=13 - base_tp,
                              confirmed_tp=base_tp - 2, confirmed_fp=1,
                              discovery_coverage=0.5, time_to_first_finding_s=1.0 + spread,
                              cost_tokens=1000 * (1 if variant.key != "A" else 3),
                              wall_time_s=10.0)
        return runner

    def test_run_ablation_runs_every_variant_repeatedly(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=3)
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertEqual(len(r.runs), 3)

    def test_aggregate_reports_mean_and_variance(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=4)
        a = ah.aggregate(results[0])  # variant A
        self.assertEqual(a["tp"]["n"], 4)
        self.assertIsNotNone(a["tp"]["mean"])
        # the +0/+1 spread makes stdev strictly positive (variance is reported)
        self.assertGreater(a["tp"]["stdev"], 0.0)

    def test_render_table_covers_all_variants_and_flags_unbuilt(self):
        results = run_ablation("corpus", self._stub_runner(), repeats=2)
        table = ah.render_table(results)
        for v in ah.VARIANTS:
            self.assertIn(v.name, table)
        self.assertIn("needs runner impl", table)  # B/C/E/F flagged honestly
        self.assertIn("conf TP", table)            # confirmed-TP column present

    def test_variant_runner_receives_the_transformed_config(self):
        seen = {}

        def runner(variant, config, corpus):
            seen[variant.key] = config.get(ah.MARKER)
            return RunMetrics()

        run_ablation("corpus", runner, repeats=1)
        self.assertEqual(seen, {k: k for k in ("A", "B", "C", "D", "E", "F")})


if __name__ == "__main__":
    unittest.main()
