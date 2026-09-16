"""
Offline advisory snapshot -- Phase 3.3.

The known-vulnerability lookup calls GitHub's live Advisory API, which
unauthenticated is capped at 60/hour and "mostly reports error: rate_limited
rather than useful results" (github_advisories' own docstring). A run without a
token, or an air-gapped engagement, therefore gets NO known-vuln matches at all.

This is a local, file-backed snapshot the client consults as a FALLBACK when the
network lookup errors (rate-limited / offline), or as the PRIMARY source in
offline mode. It never reaches the network. The snapshot is a plain JSON file the
operator curates or builds from a prior online run:

    {"advisories": [
        {"ecosystem": "pip", "package": "werkzeug", "ghsa_id": "GHSA-...",
         "cve_id": "CVE-2023-...", "summary": "...", "severity": "high",
         "vulnerable_range": "<2.2.3", "url": "https://github.com/advisories/..."},
        ...
    ]}

`ecosystem` uses GitHub's own enum values (pip/npm/maven/... -- what the client
maps to), so a snapshot entry lines up with a live lookup for the same component.
"""
from __future__ import annotations

import json

from harness.github_advisories import AdvisoryMatch


class AdvisorySnapshot:
    def __init__(self, entries: list[dict] | None = None):
        # (ecosystem, package.lower()) -> list[dict advisory]
        self._by_key: dict[tuple[str, str], list[dict]] = {}
        for e in entries or []:
            eco = str(e.get("ecosystem", "")).lower().strip()
            pkg = str(e.get("package", "")).lower().strip()
            if eco and pkg:
                self._by_key.setdefault((eco, pkg), []).append(e)

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_key.values())

    def __bool__(self) -> bool:
        return len(self) > 0

    @classmethod
    def from_file(cls, path: str) -> "AdvisorySnapshot":
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        entries = doc.get("advisories", []) if isinstance(doc, dict) else (doc or [])
        return cls(entries)

    def lookup(self, package: str, ecosystem: str, version: str = "") -> list[AdvisoryMatch]:
        """Advisories for a (mapped-ecosystem, package) pair. `ecosystem` must be
        the GitHub enum value the client already mapped to (pip/npm/...)."""
        entries = self._by_key.get((ecosystem.lower().strip(), (package or "").lower().strip()), [])
        out: list[AdvisoryMatch] = []
        for e in entries:
            vrange = str(e.get("vulnerable_range", "") or "")
            out.append(AdvisoryMatch(
                ghsa_id=str(e.get("ghsa_id", "unknown")),
                cve_id=e.get("cve_id"),
                summary=str(e.get("summary", "")),
                severity=str(e.get("severity", "unknown")),
                vulnerable_range=vrange,
                url=str(e.get("url", "")),
                version_string_appears_in_range=bool(version) and version in vrange,
            ))
        return out
