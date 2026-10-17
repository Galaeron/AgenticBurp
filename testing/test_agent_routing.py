"""Phase 2.2 agent-routing study: the measurable target for "2.1 re-run near zero".

Loads the committed study (testing/fixtures/crapi_agent_routing.json -- every
captured finding as an (agent, label) pair) and recomputes routing with the
CURRENT harness. It establishes, on real data, that routing by the reliable
producing agent (with a label fallback) collapses the miss rate from ~38% (label
only) to ~3% (combined), the residual being detection agents with no confirming
validator. This is the TARGET 2.2's production route-by-agent must hit; it is a
vocabulary study on captured output, not a measurement of production dispatch
(the harness route-by-agent change needs its own caller-level test).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))

import label_routing as lr  # noqa: E402

_FIXTURE = _HERE / "fixtures" / "crapi_agent_routing.json"


def _load():
    with open(_FIXTURE, encoding="utf-8") as f:
        return json.load(f)


class AgentRoutingStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = _load()
        cls.pairs = []
        for row in cls.fx["combos"]:
            cls.pairs.extend([(row["agent"], row["label"])] * row["count"])
        cls.summary = lr.classify_findings(cls.pairs)

    def test_fixture_is_substantive(self):
        self.assertEqual(len(self.pairs), self.fx["total_findings"])
        self.assertGreaterEqual(self.fx["total_findings"], 500)

    def test_combined_routing_is_near_zero(self):
        # The 2.2 target: routing by agent (with label fallback) reaches almost
        # every finding. "Near zero" with headroom for the detection residual.
        self.assertLessEqual(self.summary["combined_miss_rate"], 0.10,
                             f"combined route-by-agent miss is not near zero: {self.summary}")

    def test_combined_not_above_baseline(self):
        self.assertLessEqual(self.summary["combined_miss_rate"],
                             self.fx["baseline_combined_miss_rate"])
        self.assertLessEqual(self.summary["agent_miss_rate"],
                             self.fx["baseline_agent_miss_rate"])

    def test_agent_routing_beats_label_routing_substantially(self):
        # The whole point: the reliable agent recovers most of what the free-text
        # label loses. Require a large, not marginal, improvement.
        self.assertLess(self.summary["combined_miss_rate"],
                        self.summary["label_miss_rate"] / 2,
                        f"combined routing barely beats label routing: {self.summary}")

    def test_residual_misses_are_detection_agents_without_a_validator(self):
        # Every finding still unrouted under the combined strategy comes from an
        # agent that genuinely has no confirming validator -- an observation, not
        # a droppable hypothesis. None should be a core vuln agent.
        confirmable = {"sqli", "idor", "jwt", "xss", "ssrf", "nosql", "csrf",
                       "file_upload", "xxe", "command_injection", "ssti",
                       "open_redirect", "path_traversal", "crypto", "csp",
                       "cors", "rate_limit", "http_request_smuggling",
                       "api_security", "business_logic", "auth"}
        for agent in self.summary["residual_unrouted_agents"]:
            self.assertFalse(lr.routes_by_agent(agent),
                             f"{agent!r} is counted as a residual miss but DOES route")
            self.assertNotIn(agent, confirmable,
                             f"a confirmable-vuln agent {agent!r} is unrouted -- real loss")


class RoutesByAgentTests(unittest.TestCase):
    def test_core_vuln_agents_route(self):
        for agent in ("sqli", "idor", "jwt", "xss", "ssrf", "nosql", "crypto"):
            self.assertTrue(lr.routes_by_agent(agent), agent)

    def test_detection_agents_without_validators_do_not_route(self):
        for agent in ("anomaly", "ai_security", "chain_detector"):
            self.assertFalse(lr.routes_by_agent(agent), agent)


if __name__ == "__main__":
    unittest.main()
