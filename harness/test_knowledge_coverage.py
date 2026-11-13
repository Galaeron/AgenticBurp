"""SKL-2: every registered specialist agent retrieves a built-in methodology note.

Caller-level: agent names come from the live plugin registry (the same discovery
`agent_families.verify_family_membership` uses), and retrieval goes through the
real `knowledge.retrieve` with external notes disabled, from a neutral exchange
whose URL/body carry no class-specific words. So any match must come from the
agent's own name. Negative controls show a neutral exchange does not pull an
unrelated class's note.
"""
from __future__ import annotations

import unittest

from harness import knowledge
from harness.models import HttpExchange


def _neutral():
    return HttpExchange(url="https://example.test/item?id=1", method="GET",
                        request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


def _registered_agents() -> list[str]:
    from harness.agents.plugin import get_plugin_system
    return sorted(get_plugin_system().list_agents())


def _builtin_notes() -> set[str]:
    return {entry["note"] for entry in knowledge._CORPUS}


def _note_for(tag: str) -> str:
    matches = [e["note"] for e in knowledge._CORPUS if tag in e["tags"]]
    assert len(matches) == 1, f"expected exactly one built-in note tagged {tag!r}, got {len(matches)}"
    return matches[0]


def _retrieved(agent_name: str) -> list[str]:
    out = knowledge.retrieve(agent_name, _neutral(), include_external=False)
    return [line[2:] for line in out.splitlines() if line.startswith("- ")]


class EveryAgentHasABuiltinNoteTests(unittest.TestCase):
    def test_registry_is_not_trivially_empty(self):
        # Guard against a discovery failure making the coverage loop vacuous.
        self.assertGreaterEqual(len(_registered_agents()), 30)

    def test_every_registered_agent_retrieves_a_builtin_note(self):
        builtin = _builtin_notes()
        missing = []
        for name in _registered_agents():
            notes = _retrieved(name)
            if not notes or not all(n in builtin for n in notes):
                missing.append(name)
        self.assertEqual(missing, [], f"agents with no built-in note from a neutral exchange: {missing}")

    def test_neutral_exchange_alone_matches_nothing(self):
        # Control for the test above: the neutral exchange itself contributes no
        # tag, so every hit there is due to the agent's own name.
        self.assertEqual(knowledge.retrieve("", _neutral(), include_external=False), "")

    def test_race_condition_agent_gets_the_race_note(self):
        # The original mismatch: the race note was tagged `race`, which never
        # equals the single token `race_condition`.
        self.assertIn(_note_for("race"), _retrieved("race_condition"))

    def test_class_agents_get_their_own_note_first(self):
        for agent, tag in [("deserialization", "deserialization"), ("ssti", "ssti"),
                           ("command_injection", "command_injection"), ("xxe", "xxe"),
                           ("csrf", "csrf"), ("oauth", "oauth"), ("ai_security", "ai_llm")]:
            with self.subTest(agent=agent):
                self.assertEqual(_retrieved(agent)[0], _note_for(tag))


class NoCrossClassLeakTests(unittest.TestCase):
    """Negative controls: a neutral exchange must not pull an unrelated class's note."""

    PAIRS = [
        ("xss", "deserialization"),
        ("sqli", "command_injection"),
        ("sqli", "nosql"),
        ("xss", "ssti"),
        ("command_injection", "ai_llm"),
        ("header_injection", "sqli"),
        ("csrf", "cors"),
        ("oauth", "jwt"),
        ("cors", "csp"),
        ("ssrf", "xxe"),
        ("recon", "supply_chain"),
        ("race_condition", "idor"),
    ]

    def test_unrelated_class_note_not_retrieved(self):
        for agent, foreign_tag in self.PAIRS:
            with self.subTest(agent=agent, foreign=foreign_tag):
                self.assertNotIn(_note_for(foreign_tag), _retrieved(agent))


class NoteShapeTests(unittest.TestCase):
    def test_notes_stay_small(self):
        # top_k=2 must stay well inside prompt budgets.
        for entry in knowledge._CORPUS:
            with self.subTest(tags=entry["tags"]):
                self.assertLessEqual(len(entry["note"]), 600)

    def test_tags_are_tokenizer_compatible(self):
        # A tag the tokenizer can never produce would be dead weight (the
        # supply-chain note's two-character "ci" tag was dropped for this).
        for entry in knowledge._CORPUS:
            for tag in entry["tags"]:
                with self.subTest(tag=tag):
                    self.assertEqual(knowledge._tokenize(tag), {tag})


if __name__ == "__main__":
    unittest.main()
