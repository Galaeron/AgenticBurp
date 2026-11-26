"""SKL-5 caller-level tests: a family call grounds every routed member.

Before SKL-5, `FamilyRunner.run` built the family's user prompt through the
primary member's `_user_prompt`, which retrieved methodology notes with that
member's name alone, so an `injection` family prompt carried the sqli note and
none of the nosql/xss/... notes. These tests drive the real
`AgentManager.run_multiple_agents` with a recording stub at the model boundary
(the same principle as harness.test_agent_families) and read the user prompt
the family call actually sent.

Negative control: in agents mode (the shipped default) every agent's prompt
still carries exactly `knowledge.retrieve(agent.name, ...)`, and nothing of the
other dispatched agents' notes.

No live model, no `*ANSWER_KEY*`, no blind target: synthetic fixtures only.
Stored (external) notes are patched, so no test reads the real store.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from harness import knowledge, store
from harness.agent_families import DEFAULT_FAMILIES
from harness.agent_manager import AgentManager
from harness.models import HttpExchange
from harness.ollama_client import OllamaResult
from harness.prompt_validator import PromptValidator

_KNOWLEDGE_HEADER = "METHODOLOGY NOTES"


class RecordingStubOllama:
    """Records (system_prompt, user_prompt) for every call; returns no findings."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        self.calls.append((system_prompt, user_prompt))
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        parsed = await self.chat_json(model, system_prompt, user_prompt, temperature)
        return OllamaResult(data=parsed, prompt_tokens=1, completion_tokens=1)


def _config(routing_mode: str) -> dict:
    # TOK-4: a configured window, as a deployment whose model server reports one.
    # Without it the prompt is fitted to the 4096-token unknown-window fallback,
    # which elides methodology notes first, and these are tests of the notes.
    return {
        "ollama": {"base_url": "http://localhost:11434", "num_ctx": 32768},
        "coordinator": {"model": "stub-model", "routing_mode": routing_mode},
        "agent_defaults": {"model": "stub-model", "temperature": 0.1},
        "agents": {},
    }


def _neutral(url: str = "https://example.test/item?id=1") -> HttpExchange:
    """No class-specific words in URL or body, so a note can only match a name."""
    return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


def _knowledge_lines(user_prompt: str) -> list[str]:
    """The notes in a prompt's METHODOLOGY NOTES block, without the "- " prefix."""
    lines = user_prompt.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith(_KNOWLEDGE_HEADER))
    except StopIteration:
        return []
    notes = []
    for line in lines[start + 3:]:  # the header is three lines long
        if not line.startswith("- "):
            break
        notes.append(line[2:])
    return notes


def _without_knowledge(user_prompt: str) -> str:
    """The prompt with its METHODOLOGY NOTES block removed."""
    lines = user_prompt.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith(_KNOWLEDGE_HEADER))
    except StopIteration:
        return user_prompt
    end = start + 3
    while end < len(lines) and lines[end].startswith("- "):
        end += 1
    return "\n".join(lines[:start] + lines[end:])


def _own_notes(name: str) -> set[str]:
    """Built-in notes tagged with a token of `name`, read straight off the corpus."""
    tokens = knowledge._tokenize(name)
    return {entry["note"] for entry in knowledge._CORPUS if tokens & set(entry["tags"])}


def _note_tagged(tag: str) -> str:
    matches = [entry["note"] for entry in knowledge._CORPUS if tag in entry["tags"]]
    assert len(matches) == 1, f"expected one built-in note tagged {tag!r}, got {len(matches)}"
    return matches[0]


def _run(routing_mode: str, dispatch: list[str], exchange: HttpExchange | None = None):
    stub = RecordingStubOllama()
    manager = AgentManager(_config(routing_mode), stub)
    reports = asyncio.run(manager.run_multiple_agents(dispatch, exchange or _neutral()))
    return stub, reports


class _NoExternalNotes(unittest.TestCase):
    """Stored notes off and a fixed fence nonce, so prompts are deterministic."""

    def setUp(self):
        for target, value in (("harness.knowledge._external_notes", []),
                              ("harness.agents.base_agent.secrets.token_hex", "0" * 16)):
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)


class FamilyPromptGroundsEveryMemberTests(_NoExternalNotes):
    def test_injection_family_prompt_has_a_note_per_routed_member(self):
        dispatch = ["sqli", "nosql", "xss"]
        stub, reports = _run("families", dispatch)
        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(reports[0].agent, "family:injection")
        notes = _knowledge_lines(stub.calls[0][1])
        self.assertEqual(notes, [_note_tagged("sqli"), _note_tagged("nosql"), _note_tagged("xss")])
        # The pre-SKL-5 block was the primary's own retrieval: sqli's note only.
        primary_only = knowledge.retrieve("sqli", _neutral(), include_external=False)
        self.assertNotIn(_note_tagged("nosql"), primary_only)
        self.assertNotIn(_note_tagged("xss"), primary_only)

    def test_cap_limits_a_full_family_in_dispatch_order(self):
        dispatch = DEFAULT_FAMILIES["injection"]
        self.assertGreater(len(dispatch), knowledge.FAMILY_NOTE_CAP)
        stub, _ = _run("families", dispatch)
        user_prompt = stub.calls[0][1]
        notes = _knowledge_lines(user_prompt)
        self.assertEqual(len(notes), knowledge.FAMILY_NOTE_CAP)
        for name, note in zip(dispatch, notes):
            self.assertIn(note, _own_notes(name))
        block = "\n".join(f"- {note}" for note in notes)
        self.assertLessEqual(len(block), knowledge.FAMILY_NOTE_MAX_CHARS)
        # Still inside the user-prompt limits the client enforces before sending.
        PromptValidator().validate_user_prompt(user_prompt)

    def test_every_family_covers_its_routed_members_up_to_the_cap(self):
        for family, members in DEFAULT_FAMILIES.items():
            with self.subTest(family=family):
                stub, _ = _run("families", members)
                self.assertEqual(len(stub.calls), 1)
                notes = _knowledge_lines(stub.calls[0][1])
                self.assertLessEqual(len(notes), knowledge.FAMILY_NOTE_CAP)
                self.assertEqual(len(notes), len(set(notes)))
                self.assertTrue(all(any(note in _own_notes(name) for name in members)
                                    for note in notes))
                # Each member adds at most one note, so the first CAP members
                # all had their turn; each is covered by an own-class note
                # (its own, or one an earlier member shares with it).
                for name in members[:knowledge.FAMILY_NOTE_CAP]:
                    self.assertTrue(_own_notes(name) & set(notes), name)

    def test_members_sharing_a_note_get_it_once_and_the_next_member_its_own(self):
        # auth and jwt share one note; business_logic and its enhanced twin share two.
        stub, _ = _run("families", ["auth", "jwt", "csrf"])
        notes = _knowledge_lines(stub.calls[0][1])
        self.assertEqual(notes, [_note_tagged("auth"), _note_tagged("csrf")])
        stub, _ = _run("families", ["business_logic", "business_logic_enhanced"])
        notes = _knowledge_lines(stub.calls[0][1])
        self.assertEqual(len(notes), 2)
        self.assertEqual(len(set(notes)), 2)
        self.assertTrue(set(notes) <= _own_notes("business_logic_enhanced"))

    def test_family_changes_only_the_knowledge_block(self):
        # Same exchange, same primary: outside the notes the family's user
        # prompt is the primary's own agents-mode prompt, byte for byte.
        family_stub, _ = _run("families", ["sqli", "nosql", "xss"])
        agents_stub, _ = _run("agents", ["sqli"])
        self.assertEqual(_without_knowledge(family_stub.calls[0][1]),
                         _without_knowledge(agents_stub.calls[0][1]))


class AgentsModeUnchangedTests(_NoExternalNotes):
    """Negative control: the shipped default (agents mode) is untouched."""

    def test_agents_prompt_carries_only_its_own_retrieval(self):
        dispatch = ["sqli", "nosql", "xss"]
        exchange = _neutral()
        stub, reports = _run("agents", dispatch, exchange)
        self.assertEqual(len(stub.calls), len(dispatch))
        self.assertEqual(sorted(r.agent for r in reports), sorted(dispatch))
        by_agent = {}
        for _, user_prompt in stub.calls:
            notes = _knowledge_lines(user_prompt)
            owner = next(name for name in dispatch if _note_tagged(name) in notes)
            by_agent[owner] = notes
        self.assertEqual(sorted(by_agent), sorted(dispatch))
        for name, notes in by_agent.items():
            with self.subTest(agent=name):
                expected = knowledge.retrieve(name, exchange, include_external=False)
                self.assertEqual("\n".join(f"- {n}" for n in notes), expected)
                for other in dispatch:
                    if other != name:
                        self.assertNotIn(_note_tagged(other), notes)

    def test_agents_prompt_never_calls_family_retrieval(self):
        with mock.patch("harness.knowledge.retrieve_for_family",
                        side_effect=AssertionError("family retrieval in agents mode")):
            stub, reports = _run("agents", ["sqli", "nosql"])
        self.assertEqual(len(stub.calls), 2)
        self.assertTrue(all(r.raw_error is None for r in reports))


class FamilyRetrievalUnitTests(unittest.TestCase):
    """retrieve_for_family's external-note fill and size caps."""

    _EXTERNAL = [{"tags": {"widget", "item"}, "note": "EXTERNAL widget note.", "source": "manual"}]

    def _retrieve(self, members, external=None, **kwargs):
        with mock.patch("harness.knowledge._external_notes",
                        return_value=self._EXTERNAL if external is None else external):
            out = knowledge.retrieve_for_family(
                members, _neutral("https://example.test/widget?id=1"), **kwargs)
        return [line[2:] for line in out.splitlines()]

    def test_leftover_slots_take_a_matching_external_note(self):
        notes = self._retrieve(["sqli", "xss"])
        self.assertEqual(notes, [_note_tagged("sqli"), _note_tagged("xss"), "EXTERNAL widget note."])

    def test_external_notes_off_keeps_built_ins_only(self):
        notes = self._retrieve(["sqli", "xss"], include_external=False)
        self.assertEqual(notes, [_note_tagged("sqli"), _note_tagged("xss")])

    def test_members_fill_the_cap_before_any_external_note(self):
        members = DEFAULT_FAMILIES["injection"]
        notes = self._retrieve(members)
        self.assertEqual(len(notes), knowledge.FAMILY_NOTE_CAP)
        self.assertNotIn("EXTERNAL widget note.", notes)

    def test_unmatched_external_note_is_not_added(self):
        external = [{"tags": {"unrelated"}, "note": "EXTERNAL unrelated.", "source": "manual"}]
        self.assertEqual(self._retrieve(["sqli"], external=external), [_note_tagged("sqli")])

    def test_oversized_external_note_is_skipped(self):
        external = [{"tags": {"widget"}, "note": "X" * knowledge.FAMILY_NOTE_MAX_CHARS, "source": "manual"},
                    {"tags": {"widget"}, "note": "EXTERNAL short.", "source": "manual"}]
        notes = self._retrieve(["sqli"], external=external)
        self.assertEqual(notes, [_note_tagged("sqli"), "EXTERNAL short."])

    def test_char_cap_fits_cap_built_in_notes_at_the_note_ceiling(self):
        # test_knowledge_coverage caps a built-in note at 600 characters; the
        # character cap must never drop a member's own built-in note.
        cap = knowledge.FAMILY_NOTE_CAP
        self.assertGreaterEqual(knowledge.FAMILY_NOTE_MAX_CHARS, cap * (600 + 2) + (cap - 1))

    def test_every_family_member_has_an_own_class_note(self):
        for members in DEFAULT_FAMILIES.values():
            for name in members:
                with self.subTest(member=name):
                    notes = self._retrieve([name], include_external=False)
                    self.assertEqual(len(notes), 1)
                    self.assertIn(notes[0], _own_notes(name))


class CapturedPrincipalTests(_NoExternalNotes):
    """A scoped passive analysis keeps stored notes out of a family prompt,
    exactly as it does for a single agent's prompt."""

    def test_captured_principal_excludes_external_notes(self):
        external = [{"tags": {"item"}, "note": "EXTERNAL item note.", "source": "manual"}]
        with mock.patch("harness.knowledge._external_notes", return_value=external):
            stub, _ = _run("families", ["sqli"])
            self.assertIn("EXTERNAL item note.", _knowledge_lines(stub.calls[0][1]))
            token = store._CURRENT_CAPTURED_PRINCIPAL.set("principal-a")
            try:
                stub, _ = _run("families", ["sqli"])
            finally:
                store._CURRENT_CAPTURED_PRINCIPAL.reset(token)
            self.assertNotIn("EXTERNAL item note.", _knowledge_lines(stub.calls[0][1]))


if __name__ == "__main__":
    unittest.main()
