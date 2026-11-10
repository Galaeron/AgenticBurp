"""Worklist ranking from the r7 live run: a route whose captures carried a query,
form or JSON parameter (a blank `?term=` included) must outrank a parameterless
static resource, so a time-bounded sweep reaches it. Driven through
investigate_worklist with a one-node agent budget; the probe is a stub.

Synthetic endpoints only, ranked by parameter presence, method and extension.
"""
import asyncio
import unittest

from harness import engagement
from harness import worklist_investigator as wi
from harness.models import HttpExchange
from harness.role_crawl import RoleSession

ROLES = [RoleSession("anonymous", {})]
BASE = "http://127.0.0.1:9"


def _state(other_path, other_capture=None):
    st = engagement.EngagementState(host="127.0.0.1")
    st.ingest_role_crawl({"endpoints": [
        {"method": "GET", "path": p, "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False}
        for p in (other_path, "/api/items/search")]})
    st.ingest_identity("anonymous", "anonymous", source="seed")
    # The other route carries borrowed signal: a privileged-looking path reached
    # anonymously and a high model rating.
    st.ingest_prioritization([{"method": "GET", "url": other_path, "ai_priority": "high",
                               "ai_score": 1.0}])
    for url in [BASE + "/api/items/search?term="] * 3 + ([other_capture] if other_capture else []):
        st.record_template(url, "GET", HttpExchange(url=url, method="GET",
                                                    response_status=200, response_body="[]"))
    return st


def _first_probed(st):
    calls = []

    async def probe(exchange, hypothesis, specialty, step_budget):
        calls.append((exchange.url, specialty))
        return {"iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}}
    asyncio.run(wi.investigate_worklist(probe, st, BASE, ROLES, max_nodes=1,
                                        max_precondition_legs=0))
    return calls


class ParameterRoutesOutrankStaticResourcesTests(unittest.TestCase):
    def test_a_blank_query_route_is_probed_before_a_static_asset(self):
        st = _state("/admin/theme.css")
        wl = st.worklist(10)
        self.assertEqual(wl[0]["path"], "/api/items/search", [(e["path"], e["score"]) for e in wl])
        self.assertTrue(any("captured parameter" in r for r in wl[0]["reasons"]))
        calls = _first_probed(st)
        self.assertEqual(len(calls), 1)
        self.assertIn("/api/items/search?term=", calls[0][0])
        self.assertEqual(calls[0][1], "injection")

    def test_control_a_parameterless_api_route_keeps_its_rank(self):
        # Not a static asset: the same borrowed signal still ranks it first.
        st = _state("/admin/theme")
        self.assertEqual(st.worklist(10)[0]["path"], "/admin/theme")
        calls = _first_probed(st)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith("/admin/theme"), calls)

    def test_control_a_static_asset_with_a_captured_parameter_is_not_demoted(self):
        st = _state("/admin/theme.css", other_capture=BASE + "/admin/theme.css?v=")
        ep = st.endpoints["GET /admin/theme.css"]
        self.assertFalse(ep.is_parameterless_static())
        self.assertEqual(st.worklist(10)[0]["path"], "/admin/theme.css")


if __name__ == "__main__":
    unittest.main()
