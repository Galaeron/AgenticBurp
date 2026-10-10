"""Tests for the Phase 1.3 run-provenance stamp + git/Ollama lookups."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import run_provenance as rp  # noqa: E402


class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeClient:
    """Minimal httpx.Client stand-in recording GETs and returning canned bodies."""
    def __init__(self, routes):
        self._routes = routes          # path-suffix -> _FakeResp
        self.closed = False
        self.gets = []

    def get(self, url):
        self.gets.append(url)
        for suffix, resp in self._routes.items():
            if url.endswith(suffix):
                return resp
        return _FakeResp(404, {})

    def close(self):
        self.closed = True


class RunProvenanceStampTests(unittest.TestCase):
    def test_stamp_carries_all_required_fields(self):
        stamp = rp.run_provenance(
            model_name="qwen3:8b", config_hash="abc123", seed=1337, temperature=0,
            harness_commit="deadbeef", model_digest="sha256:aaa", runtime_version="0.5.0")
        # The 1.3 "done when" trio ...
        self.assertEqual(stamp["harness_commit"], "deadbeef")
        self.assertEqual(stamp["config_hash"], "abc123")
        self.assertEqual(stamp["model_name"], "qwen3:8b")
        # ... plus the reproducibility controls.
        self.assertEqual(stamp["effective_seed"], 1337)
        self.assertEqual(stamp["temperature"], 0)
        self.assertEqual(stamp["model_digest"], "sha256:aaa")
        self.assertEqual(stamp["runtime_version"], "0.5.0")
        self.assertTrue(stamp["created_at"])
        self.assertIn("not a guarantee", stamp["reproducibility_note"].lower())

    def test_seed_zero_is_recorded_not_dropped(self):
        stamp = rp.run_provenance(model_name="m", config_hash="h", seed=0,
                                  temperature=0, harness_commit="c")
        self.assertEqual(stamp["effective_seed"], 0)

    def test_no_seed_records_none(self):
        stamp = rp.run_provenance(model_name="m", config_hash="h", seed=None,
                                  temperature=0.1, harness_commit="c")
        self.assertIsNone(stamp["effective_seed"])

    def test_harness_commit_from_injected_git(self):
        commit = rp.current_harness_commit(
            run_fn=lambda args: SimpleNamespace(returncode=0, stdout="cafebabe\n"))
        self.assertEqual(commit, "cafebabe")

    def test_harness_commit_unknown_on_git_failure(self):
        self.assertEqual(
            rp.current_harness_commit(run_fn=lambda args: SimpleNamespace(returncode=128, stdout="")),
            "unknown")
        def _boom(args):
            raise OSError("git missing")
        self.assertEqual(rp.current_harness_commit(run_fn=_boom), "unknown")


class OllamaLookupTests(unittest.TestCase):
    def test_model_digest_matches_by_name(self):
        client = _FakeClient({"/api/tags": _FakeResp(200, {"models": [
            {"name": "other:1b", "digest": "sha256:zzz"},
            {"name": "qwen3:8b", "digest": "sha256:qqq"}]})})
        self.assertEqual(rp.ollama_model_digest("http://x:11434", "qwen3:8b", client=client),
                         "sha256:qqq")

    def test_model_digest_none_when_absent(self):
        client = _FakeClient({"/api/tags": _FakeResp(200, {"models": [
            {"name": "other:1b", "digest": "sha256:zzz"}]})})
        self.assertIsNone(rp.ollama_model_digest("http://x:11434", "qwen3:8b", client=client))

    def test_model_digest_none_on_unreachable(self):
        client = _FakeClient({})  # 404 for everything
        self.assertIsNone(rp.ollama_model_digest("http://x:11434", "qwen3:8b", client=client))

    def test_runtime_version_read(self):
        client = _FakeClient({"/api/version": _FakeResp(200, {"version": "0.5.0"})})
        self.assertEqual(rp.ollama_runtime_version("http://x:11434", client=client), "0.5.0")

    def test_runtime_version_none_on_error(self):
        client = _FakeClient({"/api/version": _FakeResp(500, {})})
        self.assertIsNone(rp.ollama_runtime_version("http://x:11434", client=client))


if __name__ == "__main__":
    unittest.main()
