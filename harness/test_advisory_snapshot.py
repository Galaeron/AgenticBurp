"""Tests for the Phase 3.3 offline advisory snapshot + its wiring into the
GitHub advisory client's fallback / offline paths."""
import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import httpx

from harness.advisory_snapshot import AdvisorySnapshot
from harness.github_advisories import GitHubAdvisoryClient, AdvisoryMatch
from harness.models import ComponentCandidate


_ENTRIES = [
    {"ecosystem": "pip", "package": "Werkzeug", "ghsa_id": "GHSA-xxxx-1111-aaaa",
     "cve_id": "CVE-2023-0001", "summary": "Werkzeug debugger RCE", "severity": "high",
     "vulnerable_range": "<2.2.3", "url": "https://github.com/advisories/GHSA-xxxx-1111-aaaa"},
    {"ecosystem": "npm", "package": "lodash", "ghsa_id": "GHSA-yyyy-2222-bbbb",
     "cve_id": "CVE-2021-0002", "summary": "Prototype pollution", "severity": "critical",
     "vulnerable_range": "<4.17.21", "url": "https://github.com/advisories/GHSA-yyyy-2222-bbbb"},
]


class SnapshotLookupTests(unittest.TestCase):
    def setUp(self):
        self.snap = AdvisorySnapshot(_ENTRIES)

    def test_len_and_bool(self):
        self.assertEqual(len(self.snap), 2)
        self.assertTrue(self.snap)
        self.assertFalse(AdvisorySnapshot([]))

    def test_lookup_matches_by_ecosystem_and_name_caseinsensitive(self):
        ms = self.snap.lookup("werkzeug", "pip", "2.1.0")
        self.assertEqual(len(ms), 1)
        self.assertIsInstance(ms[0], AdvisoryMatch)
        self.assertEqual(ms[0].ghsa_id, "GHSA-xxxx-1111-aaaa")
        # version_string_appears_in_range is only a crude substring signal:
        self.assertFalse(ms[0].version_string_appears_in_range)          # "2.1.0" not in "<2.2.3"
        self.assertTrue(self.snap.lookup("werkzeug", "pip", "2.2.3")[0]  # "2.2.3" is a substring
                        .version_string_appears_in_range)

    def test_lookup_wrong_ecosystem_misses(self):
        self.assertEqual(self.snap.lookup("werkzeug", "npm"), [])

    def test_from_file_roundtrip(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"advisories": _ENTRIES}, f)
        loaded = AdvisorySnapshot.from_file(path)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(len(loaded.lookup("lodash", "npm")), 1)


def _werkzeug():
    return ComponentCandidate(ecosystem="pypi", name="Werkzeug", version="2.1.0",
                              source="Server header", observed_in_exchange=True)


class ClientSnapshotIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_mode_uses_snapshot_no_network(self):
        client = GitHubAdvisoryClient(snapshot=AdvisorySnapshot(_ENTRIES), offline=True)
        # If it touched the network this would blow up; assert it doesn't.
        with patch.object(httpx.AsyncClient, "get",
                          side_effect=AssertionError("offline mode must not hit the network")):
            res = await client.lookup(_werkzeug())
        self.assertEqual(res.status, "matched")
        self.assertEqual(res.matches[0].ghsa_id, "GHSA-xxxx-1111-aaaa")
        self.assertIn("offline snapshot", res.detail)

    async def test_network_error_falls_back_to_snapshot(self):
        client = GitHubAdvisoryClient(snapshot=AdvisorySnapshot(_ENTRIES))
        with patch.object(httpx.AsyncClient, "get",
                          side_effect=httpx.ConnectError("no route to host")):
            res = await client.lookup(_werkzeug())
        self.assertEqual(res.status, "matched")
        self.assertIn("fallback", res.detail)

    async def test_network_error_with_no_snapshot_entry_returns_error(self):
        # Snapshot has no entry for this component -> the live error stands.
        client = GitHubAdvisoryClient(snapshot=AdvisorySnapshot(_ENTRIES))
        comp = ComponentCandidate(ecosystem="pypi", name="some-unknown-pkg", version="1.0",
                                  source="Server header", observed_in_exchange=True)
        with patch.object(httpx.AsyncClient, "get",
                          side_effect=httpx.ConnectError("no route to host")):
            res = await client.lookup(comp)
        self.assertEqual(res.status, "error")

    async def test_no_snapshot_configured_behaves_as_before(self):
        client = GitHubAdvisoryClient()  # no snapshot
        with patch.object(httpx.AsyncClient, "get",
                          side_effect=httpx.ConnectError("down")):
            res = await client.lookup(_werkzeug())
        self.assertEqual(res.status, "error")


if __name__ == "__main__":
    unittest.main()
