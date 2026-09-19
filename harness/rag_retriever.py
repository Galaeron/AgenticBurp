"""
P1.2/P2.3 -- RAG retrieval with citations, over harness.knowledge's corpus.

`harness.knowledge` already implements the retrieval primitive VulnBot's
five-module architecture calls the Memory Retriever: keyword-overlap scoring
over a small hand-written methodology corpus, plus tester-authored writeups
and auto-remembered confirmed findings loaded from the store. This module
adds the two things a RAG layer needs on top of raw retrieval, without a new
corpus, embeddings, or a vector DB -- the same deliberate design choice
knowledge.py already made (inspectable, zero extra runtime deps, fails
toward "no context added" rather than "silently wrong context"):

  1. CITATIONS that resolve to a stable, versioned corpus snapshot -- a
     retrieved note can always be traced back to exactly what the corpus
     said at retrieval time, not just an untraceable block of prompt text.
  2. A tested guarantee that retrieved text is INERT with respect to a
     finding's verification_state -- retrieved text may shape what an agent
     TRIES, never what the harness believes was PROVEN. Retrieved text is
     untrusted application-adjacent data (the same status _COMMON_RULES
     already gives the raw HTTP exchange); models.sanitize_agent_finding is
     the actual enforcement point. This module's negative-control test exists
     to prove that enforcement holds even when the injection attempt is
     embedded in retrieved reference text specifically, not just in the
     exchange body -- a RAG layer is exactly the kind of new untrusted-input
     channel that could otherwise bypass a guard written before it existed.

Engagement isolation (P2.3's "no cross-engagement private retrieval") is
store.list_knowledge_notes's job, threaded through knowledge.retrieve's
optional `engagement_id`; this module just passes it through unchanged.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from harness import knowledge
from harness.models import HttpExchange


def corpus_version() -> str:
    """A stable id for the CURRENT built-in corpus content -- changes iff
    knowledge._CORPUS's text changes. One version for the whole corpus (not
    per-entry): it's small and hand-curated as a unit, the same way a short
    document has one revision even when only one paragraph changed."""
    blob = "\x1f".join(
        f"{','.join(sorted(e['tags']))}\x1e{e['note']}" for e in knowledge._CORPUS
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def _citation_id(note: str) -> str:
    """A stable id for one retrieved note's text, independent of
    corpus_version -- so the SAME note resolves to the same citation id
    across calls/versions even if an unrelated corpus entry changed
    elsewhere (a corpus_version bump alone would otherwise look like every
    existing citation changed, which is not true)."""
    return hashlib.sha256(note.encode("utf-8")).hexdigest()[:12]


@dataclass
class Citation:
    """One retrieved note plus the pointer needed to resolve it. `note` is
    UNTRUSTED reference text -- see the module docstring: it may inform what
    an agent tries, it can never move a Finding's verification_state on its
    own (that guarantee is enforced independently by
    models.sanitize_agent_finding, not by anything in this dataclass)."""
    note: str
    citation_id: str
    corpus_version: str

    def to_dict(self) -> dict:
        return {"note": self.note, "citation_id": self.citation_id,
                "corpus_version": self.corpus_version}


def retrieve_with_citations(
    agent_name: str, exchange: HttpExchange, top_k: int = 2, engagement_id: str = "",
) -> list[Citation]:
    """Like knowledge.retrieve, but returns structured, individually-citable
    notes instead of one prompt-ready text block. Each Citation's
    corpus_version is the CURRENT corpus_version() at call time -- callers
    that persist a citation alongside a finding can later tell whether the
    corpus has since moved on from what was actually shown to the agent.

    Returns [] when nothing scored (same "no context added" default as
    knowledge.retrieve returning "")."""
    text = knowledge.retrieve(agent_name, exchange, top_k=top_k, engagement_id=engagement_id)
    if not text:
        return []
    version = corpus_version()
    notes = [line[2:] for line in text.split("\n") if line.startswith("- ")]
    return [Citation(note=n, citation_id=_citation_id(n), corpus_version=version) for n in notes]


def prompt_block(citations: list[Citation]) -> str:
    """Render citations back into the same '- note' bullet form
    knowledge.retrieve's plain-text output uses, so a caller that wants the
    citation objects AND the exact prompt text doesn't have to re-derive one
    from the other."""
    return "\n".join(f"- {c.note}" for c in citations)


def resolve_citation(citation_id: str, agent_name: str, exchange: HttpExchange,
                     top_k: int = 2, engagement_id: str = "") -> Citation | None:
    """Look up one citation by id against a FRESH retrieval for the same
    query -- proves a citation_id actually resolves to real corpus/note
    content rather than being an opaque, unverifiable token. Returns None
    when no current retrieval produces a note with that id (the note may
    have been edited/removed, or the id was never valid)."""
    for c in retrieve_with_citations(agent_name, exchange, top_k=top_k, engagement_id=engagement_id):
        if c.citation_id == citation_id:
            return c
    return None
