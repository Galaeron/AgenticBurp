"""
Tests for github_advisories.py.

No test file existed for this module before this one -- which is part
of why the bug these tests exist to catch went unnoticed: every lookup
for a component tagged with an ecosystem GitHub's API doesn't recognize
(most notably "generic", a value ComponentCandidate's own docstring
documents as a real, expected value -- see models.py) returned a
guaranteed HTTP 422, confirmed live during this project's first real
(non-substituted) Ollama run against testing/test-target/. GitHub
validates `ecosystem` server-side as a strict enum; the previous code
passed an unmapped value through verbatim instead of falling back to
GitHub's own documented catch-all value "other".
"""
import unittest
from unittest.mock import patch, AsyncMock

import httpx

from harness.github_advisories import GitHubAdvisoryClient, _ECOSYSTEM_MAP, _FALLBACK_ECOSYSTEM
from harness.models import ComponentCandidate


def _mock_response(status_code: int, json_body=None, text: str = ""):
    resp = httpx.Response(
        status_code=status_code,
        json=json_body if json_body is not None else None,
        text=text if json_body is None else None,
        request=httpx.Request("GET", "https://api.github.com/advisories"),
    )
    return resp


class TestEcosystemFallback(unittest.IsolatedAsyncioTestCase):
    """The core regression: an unmapped ecosystem must resolve to
    GitHub's real, confirmed-valid catch-all "other", never passed
    through verbatim."""

    async def test_unmapped_ecosystem_falls_back_to_other(self):
        client = GitHubAdvisoryClient()
        captured_params = {}

        async def fake_get(self, url, params=None, headers=None):
            captured_params.update(params)
            return _mock_response(200, json_body=[])

        with patch.object(httpx.AsyncClient, "get", new=fake_get):
            component = ComponentCandidate(ecosystem="generic", name="Werkzeug")
            result = await client.lookup(component)

        self.assertEqual(captured_params["ecosystem"], "other")
        self.assertEqual(result.status, "no_known_advisory")

    async def test_recognized_ecosystem_still_maps_correctly(self):
        client = GitHubAdvisoryClient()
        captured_params = {}

        async def fake_get(self, url, params=None, headers=None):
            captured_params.update(params)
            return _mock_response(200, json_body=[])

        with patch.object(httpx.AsyncClient, "get", new=fake_get):
            component = ComponentCandidate(ecosystem="python", name="flask")
            await client.lookup(component)

        self.assertEqual(captured_params["ecosystem"], "pip")

    def test_fallback_value_is_one_github_actually_accepts(self):
        """Confirmed live: GitHub's 422 error body for an invalid
        ecosystem value lists the exact accepted enum. "other" is in it
        -- this pins that fact so a future edit can't silently drift
        the fallback to a value GitHub would also reject."""
        github_documented_valid_values = {
            "rubygems", "npm", "pip", "maven", "nuget", "composer",
            "go", "rust", "erlang", "actions", "pub", "other", "swift",
        }
        self.assertIn(_FALLBACK_ECOSYSTEM, github_documented_valid_values)
        for mapped in _ECOSYSTEM_MAP.values():
            self.assertIn(mapped, github_documented_valid_values)


class TestRealConfirmed422IsSurfacedAsError(unittest.IsolatedAsyncioTestCase):
    """Even with the fallback fix, GitHub could still reject a request
    for some other reason -- confirm that path still surfaces cleanly
    as status="error" rather than being silently swallowed. Uses the
    real, exact response body captured live from the bug this file's
    other tests fix."""

    async def test_422_response_surfaces_as_error_with_detail(self):
        real_422_body = (
            '{"message":"Invalid request.\\n\\nInvalid input: `generic` is not a '
            'possible value. Must be one of the following: rubygems, npm, pip, '
            'maven, nuget, composer, go, rust, erlang, actions, pub, other, swift.",'
            '"documentation_url":"https://docs.github.com/rest/security-advisories'
            '/global-advisories#list-global-security-advisories"}'
        )

        async def fake_get(self, url, params=None, headers=None):
            return _mock_response(422, text=real_422_body)

        client = GitHubAdvisoryClient()
        with patch.object(httpx.AsyncClient, "get", new=fake_get):
            component = ComponentCandidate(ecosystem="totally-unmappable-value", name="whatever")
            result = await client.lookup(component)

        self.assertEqual(result.status, "error")
        self.assertIn("422", result.detail)


if __name__ == "__main__":
    unittest.main()
