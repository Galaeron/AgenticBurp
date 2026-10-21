"""
Operator-declared protected routes (RV-S, I10).

An anonymous 200 alone cannot tell a public help page from a leaked report, so the
missing-authentication probe confirms only a route its caller declares protected
(RV-G R15). A model label or a privileged-looking path is a hypothesis, not that
declaration (RV-M M1). The declaration comes from the operator, as a list of path
patterns per target:

  - config (config.local.yaml), keyed by the target's host, or host:port when the
    port is not the scheme's default:

        authz:
          protected_paths:
            "app.example.test": ["/admin/**", "GET /api/account/*"]
            "127.0.0.1:8080": ["/reports/*"]

  - the engagement: EngagementState.protected_paths, a plain list of patterns for
    that engagement's own target.

Pattern syntax: an optional HTTP method, then a path starting with "/". The path is
matched against the whole normalized request path (engagement.normalize_path: query
and fragment dropped, numeric and long-hex segments collapsed to {id}); the pattern
is normalized the same way, so "/orders/42", "/orders/{id}" and "/orders/*" all
match /orders/7. `*` matches within one path segment; `**`, which must be a whole
segment, matches zero or more segments. Paths compare case-sensitively; the method
compares upper-cased. A glob, never a regex, and matched segment by segment with no
backtracking blow-up.

Fail closed: a malformed entry (wrong type, empty, unparsable) is ignored with a
logged warning and never makes a route protected. config_schema reports the same
problems as warnings.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from harness.engagement import normalize_path

log = logging.getLogger("harness.protected_routes")

CONFIG_SECTION = "authz"
CONFIG_KEY = "protected_paths"
SOURCE_CONFIG = "config"
SOURCE_ENGAGEMENT = "engagement"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_METHOD = re.compile(r"[A-Za-z]+")
_MAX_PATTERN_CHARS = 1024


@dataclass(frozen=True)
class RouteMatch:
    """Why a route counts as protected: the operator's pattern as written, and
    where it was declared."""
    pattern: str
    source: str      # SOURCE_CONFIG | SOURCE_ENGAGEMENT
    where: str       # e.g. "authz.protected_paths['app.example.test']"

    def describe(self) -> str:
        return f"pattern {self.pattern!r} from the {self.source} ({self.where})"

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "source": self.source, "where": self.where}


@dataclass(frozen=True)
class _Pattern:
    text: str
    method: str | None
    segments: tuple[str, ...]
    source: str
    where: str


def _segments(path: str) -> tuple[str, ...]:
    return tuple(path.split("/")[1:])


def parse_pattern(entry) -> tuple[str | None, tuple[str, ...]]:
    """(method or None, normalized path segments) for one entry, or ValueError
    saying why the entry is not a pattern."""
    if not isinstance(entry, str):
        raise ValueError(f"not a string ({type(entry).__name__})")
    text = entry.strip()
    if not text:
        raise ValueError("empty pattern")
    if len(text) > _MAX_PATTERN_CHARS:
        raise ValueError(f"longer than {_MAX_PATTERN_CHARS} characters")
    parts = text.split()
    if len(parts) == 2:
        method, path = parts
        if not _METHOD.fullmatch(method):
            raise ValueError(f"{method!r} is not an HTTP method")
        method = method.upper()
    elif len(parts) == 1:
        method, path = None, parts[0]
    else:
        raise ValueError("expected an optional method and one path")
    if not path.startswith("/"):
        raise ValueError("the path must start with '/'")
    if "?" in path or "#" in path:
        raise ValueError("a pattern matches the path only; the query and fragment are dropped")
    segments = _segments(normalize_path(path))
    for seg in segments:
        if "**" in seg and seg != "**":
            raise ValueError("'**' must be a whole path segment")
    return method, segments


def _segment_matches(glob: str, text: str) -> bool:
    """`*` matches any run of characters within one segment. Linear two-pointer
    wildcard match: one remembered star, so no exponential backtracking."""
    g = t = 0
    star = mark = -1
    while t < len(text):
        if g < len(glob) and glob[g] != "*" and glob[g] == text[t]:
            g += 1
            t += 1
        elif g < len(glob) and glob[g] == "*":
            star, mark = g, t
            g += 1
        elif star != -1:
            g = star + 1
            mark += 1
            t = mark
        else:
            return False
    while g < len(glob) and glob[g] == "*":
        g += 1
    return g == len(glob)


def _path_matches(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    """Segment-level match with `**` spanning zero or more segments. Dynamic
    programming over (pattern index, path index): at most len(pattern) * len(path)
    states."""
    n, m = len(pattern), len(path)
    # reach[j]: pattern[:i] matches path[:j]
    reach = [True] + [False] * m
    for i in range(n):
        seg = pattern[i]
        nxt = [False] * (m + 1)
        if seg == "**":
            seen = False
            for j in range(m + 1):
                seen = seen or reach[j]
                nxt[j] = seen
        else:
            for j in range(m):
                if reach[j] and _segment_matches(seg, path[j]):
                    nxt[j + 1] = True
        reach = nxt
    return reach[m]


def _parse_host_key(key) -> tuple[str, int | None]:
    """(lower-cased host, explicit port or None) for a config key, or ValueError."""
    if not isinstance(key, str):
        raise ValueError(f"the host key is not a string ({type(key).__name__})")
    text = key.strip().lower()
    if not text:
        raise ValueError("empty host key")
    if any(c in text for c in "/*?#@ \t") or "://" in text:
        raise ValueError("the key must be a host or host:port, not a URL or a wildcard")
    port_text = None
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError("unparsable bracketed host")
        port_text = rest[1:] if rest else None
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host = text    # a name, an IPv4 address or a bare IPv6 address
    if not host:
        raise ValueError("empty host")
    port = None
    if port_text is not None:
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ValueError(f"invalid port {port_text!r}")
        port = int(port_text)
    return host, port


def _target_of(url: str) -> tuple[str, int] | None:
    """(lower-cased host, effective port) of a URL, or None when it has neither a
    host nor a known port."""
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
        port = parts.port or _DEFAULT_PORTS.get((parts.scheme or "").lower())
    except ValueError:
        return None
    if not host or port is None:
        return None
    return host, port


def _key_matches(key: tuple[str, int | None], target: tuple[str, int], scheme: str) -> bool:
    host, port = key
    if host != target[0]:
        return False
    if port is None:
        return target[1] == _DEFAULT_PORTS.get(scheme)
    return port == target[1]


def _compile(entries, source: str, where: str, problems: list[str]) -> list[_Pattern]:
    out = []
    for entry in entries:
        try:
            method, segments = parse_pattern(entry)
        except ValueError as e:
            problems.append(f"{where}: entry {entry!r} ignored: {e}")
            continue
        out.append(_Pattern(text=entry.strip(), method=method, segments=segments,
                            source=source, where=where))
    return out


def _config_lists(config) -> tuple[list[tuple[object, object]], list[str]]:
    """The (key, entries) pairs of authz.protected_paths, plus structural problems.
    An absent section is an empty list, not a problem."""
    problems: list[str] = []
    section = (config or {}).get(CONFIG_SECTION) if isinstance(config, dict) else None
    if section is None:
        return [], problems
    if not isinstance(section, dict):
        problems.append(f"{CONFIG_SECTION} is not a mapping; ignored")
        return [], problems
    mapping = section.get(CONFIG_KEY)
    if mapping is None:
        return [], problems
    if not isinstance(mapping, dict):
        problems.append(f"{CONFIG_SECTION}.{CONFIG_KEY} is not a mapping of host to a list "
                        f"of patterns; ignored")
        return [], problems
    return list(mapping.items()), problems


def config_problems(config) -> list[str]:
    """Every malformed authz.protected_paths entry, for every host, as warning text."""
    pairs, problems = _config_lists(config)
    for key, entries in pairs:
        where = f"{CONFIG_SECTION}.{CONFIG_KEY}[{key!r}]"
        try:
            _parse_host_key(key)
        except ValueError as e:
            problems.append(f"{where} ignored: {e}")
            continue
        if not isinstance(entries, list):
            problems.append(f"{where} ignored: not a list of patterns")
            continue
        _compile(entries, SOURCE_CONFIG, where, problems)
    return problems


class ProtectedRoutes:
    """The operator's protected-route patterns that apply to one target."""

    def __init__(self, target_url: str, patterns: list[_Pattern], problems: list[str]):
        self.target_url = target_url
        self.patterns = patterns
        self.problems = problems

    @classmethod
    def for_target(cls, config, target_url: str, *, engagement_paths=None) -> "ProtectedRoutes":
        """The config entries keyed to `target_url`'s host[:port], plus the
        engagement's own list. Every problem is logged as a warning."""
        problems: list[str] = []
        patterns: list[_Pattern] = []
        target = _target_of(target_url)
        scheme = (urlsplit(target_url or "").scheme or "").lower()
        pairs, problems_ = _config_lists(config)
        problems.extend(problems_)
        for key, entries in pairs:
            where = f"{CONFIG_SECTION}.{CONFIG_KEY}[{key!r}]"
            try:
                parsed = _parse_host_key(key)
            except ValueError as e:
                problems.append(f"{where} ignored: {e}")
                continue
            if target is None or not _key_matches(parsed, target, scheme):
                continue
            if not isinstance(entries, list):
                problems.append(f"{where} ignored: not a list of patterns")
                continue
            patterns.extend(_compile(entries, SOURCE_CONFIG, where, problems))
        if engagement_paths is not None:
            where = "engagement protected_paths"
            if isinstance(engagement_paths, list):
                patterns.extend(_compile(engagement_paths, SOURCE_ENGAGEMENT, where, problems))
            else:
                problems.append(f"{where} ignored: not a list of patterns")
        for problem in problems:
            log.warning("protected routes: %s", problem)
        return cls(target_url, patterns, problems)

    def match(self, method: str, url: str) -> RouteMatch | None:
        """The first pattern declaring (method, url) protected, or None. A URL on
        another host or port than this target never matches."""
        target = _target_of(self.target_url)
        if target is None or _target_of(url) != target:
            return None
        method = (method or "GET").upper()
        path = _segments(normalize_path(url))
        for p in self.patterns:
            if p.method is not None and p.method != method:
                continue
            if _path_matches(p.segments, path):
                return RouteMatch(pattern=p.text, source=p.source, where=p.where)
        return None
