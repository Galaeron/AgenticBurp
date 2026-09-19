"""Hermetic tests for pattern_memory.py (P2.5). No network, no live model --
pure file I/O against a temp JSONL path."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness import pattern_memory


class TestSignatures(unittest.TestCase):
    def test_same_shape_different_host_same_signature(self):
        sig_a = pattern_memory.signature_for("GET", "https://a.example.com/api/orders/42?sort=asc")
        sig_b = pattern_memory.signature_for("GET", "https://b.example.com/api/orders/999?sort=desc")
        self.assertEqual(sig_a, sig_b)  # host + query VALUES differ; shape is identical

    def test_different_path_shape_different_signature(self):
        sig_a = pattern_memory.signature_for("GET", "https://x.test/api/orders/42")
        sig_b = pattern_memory.signature_for("GET", "https://x.test/api/invoices/42")
        self.assertNotEqual(sig_a, sig_b)

    def test_different_param_names_different_signature(self):
        sig_a = pattern_memory.signature_for("GET", "https://x.test/api/search?q=widget")
        sig_b = pattern_memory.signature_for("GET", "https://x.test/api/search?filter=widget")
        self.assertNotEqual(sig_a, sig_b)

    def test_signature_never_contains_query_values(self):
        sig = pattern_memory.signature_for("GET", "https://x.test/api/search?token=SUPERSECRET123")
        self.assertNotIn("SUPERSECRET123", sig)
        self.assertIn("token", sig)  # the NAME is fine -- it's structural

    def test_reviewer_repro_private_path_token_never_survives(self):
        """R04 reproduction: a reset path containing an arbitrary,
        non-hex/non-numeric private token must not survive into the
        signature verbatim -- only normalize_path's numeric/hex collapse was
        applied before, and this token is neither."""
        sig = pattern_memory.signature_for(
            "GET", "https://victim.example.com/reset/SyntheticPrivateToken_xYz!")
        self.assertNotIn("SyntheticPrivateToken_xYz", sig)
        self.assertIn("{id}", sig)

    def test_reviewer_repro_private_query_param_name_never_survives(self):
        """R04 reproduction: an email-shaped query parameter NAME must not
        survive -- some applications put identifiers/private data in names,
        not just values."""
        sig = pattern_memory.signature_for(
            "GET", "https://victim.example.com/api/search?alice@example.invalid=1")
        self.assertNotIn("alice@example.invalid", sig)

    def test_ordinary_route_words_and_param_names_still_survive(self):
        """Positive control: the sanitizer must not gut ordinary structural
        signal -- ordinary lowercase route words/param names still pass."""
        sig = pattern_memory.signature_for("GET", "https://x.test/api/tickets/search?q=widget")
        self.assertIn("api", sig)
        self.assertIn("tickets", sig)
        self.assertIn("q", sig)


class TestAppendOnlyStore(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tmpdir.name) / "patterns.jsonl"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_record_and_read_back(self):
        sig = pattern_memory.signature_for("GET", "https://x.test/api/orders/1")
        pattern_memory.record_pattern("idor", sig, path=self.path)
        self.assertIn(("idor", sig), pattern_memory.known_patterns(self.path))

    def test_missing_file_reads_as_empty_not_an_error(self):
        missing = Path(self._tmpdir.name) / "does-not-exist.jsonl"
        self.assertEqual(pattern_memory.known_patterns(missing), set())

    def test_append_only_never_rewrites_prior_lines(self):
        sig1 = pattern_memory.signature_for("GET", "https://x.test/api/orders/1")
        sig2 = pattern_memory.signature_for("POST", "https://x.test/api/accounts")
        pattern_memory.record_pattern("idor", sig1, path=self.path)
        pattern_memory.record_pattern("mass_assignment", sig2, path=self.path)
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["vulnerability_class"], "idor")  # untouched by the 2nd write

    def test_duplicate_observations_collapse_at_read_time(self):
        sig = pattern_memory.signature_for("GET", "https://x.test/api/orders/1")
        pattern_memory.record_pattern("idor", sig, path=self.path)
        pattern_memory.record_pattern("idor", sig, path=self.path)
        pattern_memory.record_pattern("idor", sig, path=self.path)
        patterns = pattern_memory.known_patterns(self.path)
        self.assertEqual(patterns, {("idor", sig)})  # one entry despite 3 appends

    def test_reviewer_repro_synthetic_private_data_never_written_to_disk(self):
        """R04 reproduction, on disk: the exact synthetic private path token
        and email-shaped query param name from the review must not appear in
        the written JSONL record."""
        sig = pattern_memory.signature_for_finding(
            {},
            {"method": "GET",
             "url": "https://victim.example.com/reset/SyntheticPrivateToken_xYz!"
                    "?alice@example.invalid=1"},
        )
        pattern_memory.record_pattern("reset_token", sig, path=self.path)
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("SyntheticPrivateToken_xYz", raw)
        self.assertNotIn("alice@example.invalid", raw)

    def test_no_private_data_ever_written_to_the_store(self):
        """Negative control: recording a pattern derived from a request that
        carries a secret query VALUE must never write that value to disk --
        only the structural signature (method/path/param NAMES) is stored."""
        secret_url = "https://victim.example.com/api/search?token=SUPERSECRETVALUE999&user=alice"
        sig = pattern_memory.signature_for_finding(
            {"parameter_name": "token"},
            {"method": "GET", "url": secret_url},
        )
        pattern_memory.record_pattern("sqli", sig, path=self.path)
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("SUPERSECRETVALUE999", raw)
        self.assertNotIn("victim.example.com", raw)  # host never crosses either
        self.assertNotIn("alice", raw)


class TestSuggestClassesForExchange(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tmpdir.name) / "patterns.jsonl"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_matching_shape_on_a_new_host_is_suggested(self):
        # Confirmed on host A -- a path-scoped IDOR (no query/body param).
        sig = pattern_memory.signature_for_finding(
            {}, {"method": "GET", "url": "https://a.example.com/api/orders/42"},
        )
        pattern_memory.record_pattern("idor", sig, path=self.path)
        # ...a DIFFERENT host, same shape, gets the suggestion.
        suggestions = pattern_memory.suggest_classes_for_exchange(
            {"method": "GET", "url": "https://b.example.com/api/orders/999"}, path=self.path)
        self.assertEqual(suggestions, ["idor"])

    def test_no_match_for_an_unrelated_shape(self):
        """Negative control: an endpoint whose shape was never recorded must
        get no suggestion at all, never a guess."""
        sig = pattern_memory.signature_for_finding(
            {}, {"method": "GET", "url": "https://a.example.com/api/orders/42"},
        )
        pattern_memory.record_pattern("idor", sig, path=self.path)
        suggestions = pattern_memory.suggest_classes_for_exchange(
            {"method": "POST", "url": "https://b.example.com/api/completely/different"},
            path=self.path)
        self.assertEqual(suggestions, [])

    def test_empty_memory_suggests_nothing(self):
        suggestions = pattern_memory.suggest_classes_for_exchange(
            {"method": "GET", "url": "https://x.test/api/anything"}, path=self.path)
        self.assertEqual(suggestions, [])


class TestOrchestratorWiring(unittest.TestCase):
    """Integration: pattern_memory is actually consulted by
    orchestrator_detect.py's analyze() dispatch step (the "coordinator
    checks it FIRST" requirement), additively, behind the default-off
    pattern_memory.enabled flag."""

    def setUp(self):
        import asyncio, os, shutil, tempfile, yaml
        from pathlib import Path as _Path
        from harness import store, cache
        from harness.orchestrator import Orchestrator
        from harness.ollama_client import OllamaResult

        self._asyncio = asyncio
        self._tmp = tempfile.mkdtemp(prefix="pattern_memory_wiring_")
        self._orig_store_db = store._DB_PATH
        self._orig_cache = cache._cache
        store._DB_PATH = _Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        self._pm_path = _Path(self._tmp) / "patterns.jsonl"
        self._shutil = shutil

        harness_dir = _Path(__file__).resolve().parent
        with open(harness_dir / "config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
        cfg.setdefault("coordinator", {})["cloud_primary"] = False
        cfg.setdefault("critique", {})["enabled"] = False
        validators = cfg.setdefault("validators", {})
        validators["active_enabled"] = False
        validators["allow_mutating_replay"] = False
        cfg.setdefault("autonomous_discovery", {})["enabled"] = False
        cfg.setdefault("github_advisories", {})["enabled"] = False
        cfg.setdefault("kev_check", {})["enabled"] = False
        cfg.setdefault("package_registry_checks", {})["enabled"] = False
        cfg.setdefault("iterative_agent", {})["enabled"] = False
        cfg.setdefault("engagement", {})["auto_escalate"] = False
        cfg["server"] = dict(cfg.get("server") or {})
        cfg["server"]["allowed_hosts"] = ["a.example.com", "b.example.com"]
        cfg["oracle"] = {"enabled": False}
        cfg["pattern_memory"] = {"enabled": True, "path": str(self._pm_path)}

        class _StubOllama:
            async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
                return {"dispatch": ["misconfig"], "reason": "generic shape"}

            async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
                return OllamaResult(
                    data={"dispatch": ["misconfig"], "reason": "generic shape"},
                    prompt_tokens=1, completion_tokens=1)

        orch = Orchestrator(cfg)
        stub = _StubOllama()
        orch.ollama = stub
        for agent in orch.agent_manager.agents.values():
            agent.ollama = stub
        if getattr(orch, "analysis_pipeline", None) is not None:
            orch.analysis_pipeline.ollama_client = stub
        coord = getattr(orch, "coordinator", None)
        if coord is not None and hasattr(coord, "ollama"):
            coord.ollama = stub
        self.orch = orch

    def tearDown(self):
        from harness import store, cache
        store._DB_PATH = self._orig_store_db
        cache._cache = self._orig_cache
        self._shutil.rmtree(self._tmp, ignore_errors=True)

    def _bland_exchange(self, url):
        from harness.models import HttpExchange
        return HttpExchange(
            url=url, method="GET", request_headers={"User-Agent": "x"}, request_body="",
            response_status=200, response_headers={}, response_body="{}",
        )

    def test_pattern_memory_additively_suggests_a_specialist_on_a_new_host(self):
        # Pre-populate memory: idor was confirmed on host A for this shape.
        sig = pattern_memory.signature_for_finding(
            {}, self._bland_exchange("https://a.example.com/api/orders/42"))
        pattern_memory.record_pattern("idor", sig, path=self._pm_path)

        # A DIFFERENT host, the same bland shape -- fast_path has no signal
        # for it, and the stubbed coordinator would only pick "misconfig".
        resp = self._asyncio.run(self.orch.analyze(
            self._bland_exchange("https://b.example.com/api/orders/999"), bypass_cache=True))
        self.assertIn("misconfig", resp.dispatched_agents)  # the coordinator's own pick, untouched
        self.assertIn("idor", resp.dispatched_agents)        # ADDED by pattern_memory

    def test_no_pattern_memory_entry_never_adds_anything(self):
        """Negative control: with no matching pattern recorded for this
        shape, "idor" (the class only pattern_memory could add here) must
        never appear -- dispatch reflects only normal routing."""
        resp = self._asyncio.run(self.orch.analyze(
            self._bland_exchange("https://b.example.com/api/never/seen"), bypass_cache=True))
        self.assertNotIn("idor", resp.dispatched_agents)


if __name__ == "__main__":
    unittest.main()
