"""Tests for the A3 tool catalog + recommendation mechanism."""
import unittest

import harness.tool_catalog as tc
from harness.models import Finding


class CatalogTests(unittest.TestCase):
    def test_catalog_nonempty_and_well_formed(self):
        tools = tc.all_tools()
        self.assertGreater(len(tools), 15)  # not just ffuf
        for t in tools:
            self.assertTrue(t.name and t.category and t.purpose and t.url)

    def test_by_category_covers_content_discovery(self):
        cats = tc.by_category()
        self.assertIn("content_discovery", cats)
        names = {t.name for t in cats["content_discovery"]}
        self.assertIn("ffuf", names)
        self.assertIn("feroxbuster", names)  # generalized beyond ffuf

    def test_get_by_name_case_insensitive(self):
        self.assertIsNotNone(tc.get("SQLMAP"))
        self.assertIsNone(tc.get("does-not-exist"))

    def test_recommend_for_class_matches_taxonomy(self):
        # canonicalize maps "SQL Injection" -> sqli; sqlmap is tagged sqli.
        recs = tc.recommend_for("SQL Injection")
        self.assertIn("sqlmap", {t.name for t in recs})

    def test_recommend_for_xss(self):
        names = {t.name for t in tc.recommend_for("xss")}
        self.assertTrue({"dalfox", "XSStrike"} & names)

    def test_recommend_by_situation(self):
        names = {t.name for t in tc.recommend_for(None, situations=["content_discovery"])}
        self.assertIn("ffuf", names)

    def test_recommend_class_outranks_situation(self):
        recs = tc.recommend_for("ssrf", situations=["recon"])
        # SSRF-class tools (SSRFmap/interactsh) should rank above recon-only ones.
        self.assertIn(recs[0].name, {"SSRFmap", "interactsh"})


class RecommendationTests(unittest.TestCase):
    def test_command_templated_to_url(self):
        recs = tc.recommend_for_finding("sqli", "https://shop.test/item?id=1")
        sqlmap = next(r for r in recs if r.tool == "sqlmap")
        self.assertIn("https://shop.test/item?id=1", sqlmap.command)

    def test_origin_host_substitution(self):
        recs = tc.recommend_for_finding("subdomain_takeover", "https://app.shop.test/x")
        cmds = " ".join(r.command for r in recs)
        self.assertIn("app.shop.test", cmds)  # {host} filled

    def test_recommendations_for_findings_dedupes_and_bounds(self):
        findings = [
            Finding(vulnerability_class="sqli", confidence=0.8, summary="s", evidence="e",
                    suggested_test="t", basis="derived"),
            Finding(vulnerability_class="sqli", confidence=0.7, summary="s2", evidence="e",
                    suggested_test="t", basis="derived"),
            Finding(vulnerability_class="xss", confidence=0.6, summary="s3", evidence="e",
                    suggested_test="t", basis="derived"),
        ]
        recs = tc.recommendations_for_findings(findings, per_class_limit=2, max_total=12)
        # sqli appears twice but recs are deduped by (tool, class)
        keys = [(r.tool, r.for_finding) for r in recs]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(any(r.for_finding == "xss" for r in recs))

    def test_findings_as_dicts(self):
        recs = tc.recommendations_for_findings(
            [{"vulnerability_class": "ssrf", "url": "https://t.test/fetch?u=x"}])
        self.assertTrue(recs)
        self.assertEqual(recs[0].for_finding, "ssrf")

    def test_unknown_class_yields_no_recs(self):
        recs = tc.recommend_for_finding("totally_unknown_class", "https://t.test/x")
        self.assertEqual(recs, [])


class ToolEndpointTests(unittest.TestCase):
    def setUp(self):
        import harness.server as server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def test_get_tools_grouped(self):
        r = self.client.get("/tools")
        self.assertEqual(r.status_code, 200)
        self.assertIn("content_discovery", r.json()["by_category"])

    def test_get_tools_by_class(self):
        r = self.client.get("/tools", params={"vulnerability_class": "sqli"})
        self.assertIn("sqlmap", {t["name"] for t in r.json()["tools"]})

    def test_recommend_endpoint_single(self):
        r = self.client.post("/tools/recommend", json={
            "vulnerability_class": "xss", "url": "https://t.test/s?q=1"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["recommendations"])

    def test_recommend_endpoint_requires_input(self):
        r = self.client.post("/tools/recommend", json={})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
