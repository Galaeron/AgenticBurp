"""Immutable target-I/O restrictions; captured data admission is separate."""
from dataclasses import dataclass
import posixpath
import re
from urllib.parse import unquote, urlsplit

from harness.scope_lock import parse_scope_url


def _decoded_path(path):
    if not isinstance(path, str) or not path.startswith('/') or '\\' in path:
        return None
    for _ in range(4):
        if re.search(r'%(?![0-9a-fA-F]{2})', path):
            return None
        decoded = unquote(path, errors='strict')
        if decoded == path:
            return path
        path = decoded
    return None  # ambiguous deeper encoding cannot bypass an exclusion


def _normalized(path):
    if '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return None
    return '/' + posixpath.normpath('/' + path.lstrip('/')).lstrip('/')


def _canonical_path(path):
    decoded = _decoded_path(path)
    return None if decoded is None else _normalized(decoded)


def _target_paths(path):
    """Every path a server may resolve this request path to, or None if ambiguous.

    A decoded NUL is the one control character that servers are known to read
    two ways. A C-string file layer stops at it, and a sanitizer may strip it.
    Both readings are returned so that an exclusion holds for either one. This
    lets a path-filter probe such as `name.bak%2500.md` be sent without it ever
    reaching an excluded path. Any other control character stays ambiguous.
    """
    decoded = _decoded_path(path)
    if decoded is None:
        return None
    if '\x00' not in decoded:
        single = _normalized(decoded)
        return None if single is None else (single,)
    readings = tuple(_normalized(r) for r in (decoded.split('\x00', 1)[0], decoded.replace('\x00', '')))
    return None if None in readings else readings


@dataclass(frozen=True)
class TargetRequestPolicy:
    captured_only: bool = False
    excluded_path_prefixes: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, config=None):
        config = config or {}
        transport = config.get('transport', {})
        if not isinstance(transport, dict):
            raise ValueError('transport must be a mapping')
        captured = transport.get('captured_only', False)
        if not isinstance(captured, bool):
            raise ValueError('transport.captured_only must be a boolean')
        profile = config.get('operating_profile', 'none')
        if not isinstance(profile, str):
            raise ValueError('operating_profile must be a string')
        captured = captured or profile.strip().lower() == 'passive-only'
        prefixes = transport.get('excluded_path_prefixes', [])
        if not isinstance(prefixes, (list, tuple)):
            raise ValueError('transport.excluded_path_prefixes must be a list')
        normalized = []
        for prefix in prefixes:
            if not isinstance(prefix, str) or '?' in prefix or '#' in prefix:
                raise ValueError('excluded path prefix must be an absolute path')
            try:
                path = _canonical_path(prefix)
            except (UnicodeError, ValueError):
                path = None
            if path is None:
                raise ValueError('excluded path prefix is malformed')
            normalized.append(path.rstrip('/') or '/')
        return cls(captured, tuple(sorted(set(normalized))))

    def denial_reason(self, url):
        if self.captured_only:
            return 'captured-only operation: target fetching is blocked; supplied traffic remains untested'
        if parse_scope_url(url) is None:
            return 'malformed target URL'
        try:
            paths = _target_paths(urlsplit(url).path or '/')
        except (UnicodeError, ValueError):
            paths = None
        if paths is None:
            return 'ambiguous target path'
        if any(prefix == '/' or path == prefix or path.startswith(prefix + '/')
               for path in paths for prefix in self.excluded_path_prefixes):
            return 'target endpoint excluded by path policy; no request sent'
        return ''

    def status(self):
        return {'captured_only': self.captured_only,
                'target_fetching': 'blocked' if self.captured_only else 'subject to scope/gate/endpoint policy',
                'excluded_path_prefixes': list(self.excluded_path_prefixes),
                'capture_analysis': 'supplied data only; blocked fetching is not a negative test result'}
