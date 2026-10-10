"""Immutable target-I/O restrictions; captured data admission is separate."""
from dataclasses import dataclass
import posixpath
import re
from urllib.parse import unquote, urlsplit

from harness.scope_lock import parse_scope_url


def _canonical_path(path):
    if not isinstance(path, str) or not path.startswith('/') or '\\' in path:
        return None
    for _ in range(4):
        if re.search(r'%(?![0-9a-fA-F]{2})', path):
            return None
        decoded = unquote(path, errors='strict')
        if decoded == path:
            break
        path = decoded
    else:
        return None  # ambiguous deeper encoding cannot bypass an exclusion
    if '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return None
    return '/' + posixpath.normpath('/' + path.lstrip('/')).lstrip('/')


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
            path = _canonical_path(urlsplit(url).path or '/')
        except (UnicodeError, ValueError):
            path = None
        if path is None:
            return 'ambiguous target path'
        if any(prefix == '/' or path == prefix or path.startswith(prefix + '/')
               for prefix in self.excluded_path_prefixes):
            return 'target endpoint excluded by path policy; no request sent'
        return ''

    def status(self):
        return {'captured_only': self.captured_only,
                'target_fetching': 'blocked' if self.captured_only else 'subject to scope/gate/endpoint policy',
                'excluded_path_prefixes': list(self.excluded_path_prefixes),
                'capture_analysis': 'supplied data only; blocked fetching is not a negative test result'}
