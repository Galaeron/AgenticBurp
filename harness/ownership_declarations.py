"""Operator declarations of concrete ownership and route entitlements (RV-T)."""
from __future__ import annotations
import logging
from urllib.parse import urlsplit
from harness.principals import OwnershipLedger, OwnershipFact
from harness.protected_routes import parse_pattern, _parse_host_key, _target_of, _key_matches

log = logging.getLogger(__name__)


def _entry(entry, known_names=None):
    if not isinstance(entry, dict):
        raise ValueError('entry must be a mapping')
    if set(entry) - {'path', 'owner', 'shared_with', 'public', 'authenticated'}:
        raise ValueError('unknown ownership field')
    method, _ = parse_pattern(entry.get('path'))
    # Reuse RV-S syntax/matcher, but ownership must preserve concrete object IDs.
    path = entry['path'].split()[-1]
    owner = entry.get('owner', '')
    shares = entry.get('shared_with', [])
    if not isinstance(owner, str) or (owner and not owner.strip()):
        raise ValueError('owner must be a nonempty identity name')
    if not isinstance(shares, list) or any(not isinstance(x, str) or not x.strip() for x in shares):
        raise ValueError('shared_with must be a list of identity names')
    for flag in ('public', 'authenticated'):
        if flag in entry and type(entry[flag]) is not bool:
            raise ValueError(f'{flag} must be a boolean')
    if not (owner or shares or entry.get('public') or entry.get('authenticated')):
        raise ValueError('no ownership or entitlement declared')
    if known_names is not None and any(n not in known_names for n in [owner, *shares] if n):
        raise ValueError('owner/shared identity is not registered for this target')
    return method, tuple("*" if segment == "{id}" else segment for segment in path.split('/')[1:])


def config_problems(config):
    section = (config or {}).get('authz', {})
    if not isinstance(section, dict):
        return ['authz must be a mapping']
    mapping = section.get('owners', {})
    if not isinstance(mapping, dict):
        return ['authz.owners must map target hosts to lists']
    problems = []
    for host, entries in mapping.items():
        try:
            _parse_host_key(host)
            if not isinstance(entries, list):
                raise ValueError('owners must be a list')
            for index, entry in enumerate(entries):
                try:
                    _entry(entry)
                except ValueError as exc:
                    problems.append(f'authz.owners[{host!r}][{index}]: {exc}')
        except ValueError as exc:
            problems.append(f'authz.owners[{host!r}]: {exc}')
    return problems


def load_ownership(config, target_url, identities, *, engagement_owners=None):
    ledger = OwnershipLedger()
    known = {i.get('name') for i in identities}
    target = _target_of(target_url)
    scheme = urlsplit(target_url).scheme.lower()
    problems = config_problems(config)
    authz = (config or {}).get('authz', {})
    mapping = authz.get('owners', {}) if isinstance(authz, dict) else {}
    lists = []
    if isinstance(mapping, dict):
        for host, entries in mapping.items():
            try:
                if target and _key_matches(_parse_host_key(host), target, scheme):
                    lists.append((f'config authz.owners[{host!r}]', entries))
            except ValueError:
                pass
    if engagement_owners is not None:
        lists.append(('engagement owners', engagement_owners))
    for source, entries in lists:
        if not isinstance(entries, list):
            problems.append(f'{source}: owners must be a list')
            continue
        for index, entry in enumerate(entries):
            try:
                method, segments = _entry(entry, known)
            except ValueError as exc:
                problems.append(f'{source}[{index}] ignored: {exc}')
                continue
            provenance = f"{source}[{index}] path {entry['path']!r}; most specific path wins, method wins ties; conflicting equal-specificity entries are unknown"
            fact = OwnershipFact(object_ref='', owner_principal_id=entry.get('owner', ''),
                shared_with=frozenset(entry.get('shared_with', [])), public=entry.get('public', False),
                authenticated=entry.get('authenticated', False), provenance=provenance)
            ledger.declare_pattern(target_url, method, segments, fact)
    for problem in dict.fromkeys(problems):
        log.warning('ownership: %s', problem)
    return ledger
