"""Corpus ground-truth contamination audit + sanitizer (PR-13 / from PR-2).

Why this exists: a path-traversal exploit exchange can legitimately disclose a
target's own source in its response body -- a real attacker would see exactly
that. The problem is when that disclosed source carries GROUND-TRUTH ANNOTATIONS
a production app would never ship: inline ``# BUG:`` comments naming each
endpoint's planted vulnerability, or references to an ``ANSWER_KEY``. When the
harness analyses such a corpus, the detector model reads that one response and
thereby sees the answer key for the WHOLE app -- train-on-the-test contamination
that inflates recall on the other exchanges (the PixelMart TP10 case the PR-2
label-seeding surfaced; VERIFIED 19 marker hits in that corpus, 0 in DVWA/WebGoat).

This module (a) AUDITS a corpus for such annotations and (b) SANITIZES a response
body by removing ONLY the annotations while preserving the realistic disclosure
(so the vulnerability is still demonstrable). It reads corpus JSON as data; it
never reads an ``*ANSWER_KEY*`` file or a blind target's ``app.py``, and it never
uses an annotation's CONTENT as a label -- it only strips it.

Offline, deterministic, stdlib-only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Ground-truth annotation markers. These are the tells that a disclosed source
# body carries the answer key rather than only realistic application code. Kept
# deliberately narrow so ordinary application text is never mistaken for one.
_MARKER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bBUG\s*:", re.IGNORECASE),
    re.compile(r"ANSWER[_\- ]?KEY", re.IGNORECASE),
    re.compile(r"#\s*vuln(erabilit(y|ies))?\b", re.IGNORECASE),
    re.compile(r"\bTODO\b[^\n]{0,4}\bSECURITY\b", re.IGNORECASE),
    re.compile(r"#\s*SECURITY\s*:", re.IGNORECASE),
)

_REDACTION = "[annotation removed]"


def marker_hits(text: str) -> list[str]:
    """Every ground-truth-annotation marker found in `text` (verbatim matches)."""
    if not text:
        return []
    hits: list[str] = []
    for pat in _MARKER_PATTERNS:
        hits.extend(m.group(0) for m in pat.finditer(text))
    return hits


def _line_has_marker(line: str) -> bool:
    return any(pat.search(line) for pat in _MARKER_PATTERNS)


def sanitize_text(text: str) -> tuple[str, int]:
    """Return (sanitized_text, removed_count). Removes ground-truth annotations
    while preserving everything else byte-for-byte:

    * a ``#`` comment that contains a marker is stripped from its line (the code
      BEFORE the ``#`` is kept exactly; a full-line comment becomes empty);
    * a non-comment line that still contains a marker (e.g. a bare ``ANSWER_KEY``
      reference in prose) has the marker span replaced with a redaction token.

    A line with no marker is never touched. Returns the ORIGINAL string object
    (not a re-joined copy) when nothing matched, so a clean body is guaranteed
    byte-identical."""
    if not text or not any(pat.search(text) for pat in _MARKER_PATTERNS):
        return text, 0

    removed = 0
    # Preserve the text's own newline convention on rejoin.
    newline = "\r\n" if "\r\n" in text else "\n"
    out_lines: list[str] = []
    for line in text.split(newline):
        if not _line_has_marker(line):
            out_lines.append(line)
            continue
        hash_idx = line.find("#")
        if hash_idx != -1 and _line_has_marker(line[hash_idx:]):
            # Strip the annotation comment; keep any code before it (rstripped).
            kept = line[:hash_idx].rstrip()
            out_lines.append(kept)
            removed += 1
        else:
            # Marker outside a comment (prose / string): redact just the spans.
            new_line = line
            for pat in _MARKER_PATTERNS:
                new_line = pat.sub(_REDACTION, new_line)
            out_lines.append(new_line)
            removed += 1
    return newline.join(out_lines), removed


def _response_body_of(exchange: dict[str, Any]) -> str:
    """Best-effort extraction of an exchange's response body across the shapes
    the corpora use (top-level or nested under a `response`)."""
    for key in ("response_body", "responseBody"):
        if isinstance(exchange.get(key), str):
            return exchange[key]
    resp = exchange.get("response")
    if isinstance(resp, dict):
        for key in ("body", "content", "text"):
            if isinstance(resp.get(key), str):
                return resp[key]
    return ""


def _exchange_id_of(exchange: dict[str, Any], index: int) -> str:
    for key in ("label", "id", "exchange_id", "name"):
        v = exchange.get(key)
        if isinstance(v, str) and v:
            return v
    return f"index:{index}"


def audit_exchanges(exchanges: list[dict[str, Any]]) -> dict[str, Any]:
    """Audit a list of exchange dicts. Returns a report with per-exchange marker
    counts and a total. `contaminated` is the list of exchange ids that carry at
    least one ground-truth annotation in their response body."""
    per_exchange: list[dict[str, Any]] = []
    contaminated: list[str] = []
    total = 0
    for i, ex in enumerate(exchanges):
        body = _response_body_of(ex)
        hits = marker_hits(body)
        if hits:
            ex_id = _exchange_id_of(ex, i)
            contaminated.append(ex_id)
            per_exchange.append({"exchange_id": ex_id, "marker_count": len(hits),
                                 "markers": sorted(set(h.lower() for h in hits))})
            total += len(hits)
    return {
        "n_exchanges": len(exchanges),
        "total_marker_hits": total,
        "contaminated_exchange_ids": contaminated,
        "per_exchange": per_exchange,
        "clean": total == 0,
    }


def _load_exchanges(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        for key in ("exchanges", "captures", "items"):
            v = data.get(key)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
    return []


def audit_corpus_file(path: str | Path) -> dict[str, Any]:
    """Audit a corpus JSON file on disk. Never reads answer-key/app.py files."""
    p = Path(path)
    report = audit_exchanges(_load_exchanges(p))
    report["corpus"] = str(p)
    return report


def sanitize_exchanges(exchanges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Return (sanitized_copy, total_removed). Only response bodies carrying
    annotations are rewritten; every other field/exchange is deep-copied
    unchanged."""
    import copy
    out = copy.deepcopy(exchanges)
    total = 0
    for ex in out:
        body = _response_body_of(ex)
        if not body:
            continue
        clean, removed = sanitize_text(body)
        if removed:
            total += removed
            if isinstance(ex.get("response_body"), str):
                ex["response_body"] = clean
            elif isinstance(ex.get("responseBody"), str):
                ex["responseBody"] = clean
            elif isinstance(ex.get("response"), dict):
                resp = ex["response"]
                for key in ("body", "content", "text"):
                    if isinstance(resp.get(key), str):
                        resp[key] = clean
                        break
    return out, total
