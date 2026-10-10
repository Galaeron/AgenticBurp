"""Run-owned HTTPS trust policy; verified defaults and isolated loopback fixtures."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
import ssl
from urllib.parse import urlsplit

from harness.scope_lock import parse_scope_url

log = logging.getLogger('harness.tls_policy')


@dataclass(frozen=True)
class TLSProfile:
    context: ssl.SSLContext
    pool_key: str = ''


class TLSPolicy:
    """A frozen declaration of trust for one run; no global insecure switch."""
    def __init__(self, context, *, ca_sha256=None, fixture_origins=()):
        self._verified = TLSProfile(context)
        self._ca_sha256 = ca_sha256
        self._fixture_origins = frozenset(fixture_origins)
        self._fixture_profiles = {}

    @classmethod
    def from_config(cls, config=None):
        config = {} if config is None else config
        transport = config.get('transport', {})
        if not isinstance(transport, dict):
            raise ValueError('transport must be a mapping')
        settings = transport.get('tls', {})
        if not isinstance(settings, dict):
            raise ValueError('transport.tls must be a mapping')
        if set(settings) - {'ca_bundle', 'fixture_insecure_origins', 'fixture_insecure_reason'}:
            raise ValueError('unsupported transport.tls setting; a global verification bypass is not supported')
        context = ssl.create_default_context()
        ca_sha256 = None
        ca_bundle = settings.get('ca_bundle')
        if ca_bundle is not None:
            if not isinstance(ca_bundle, str) or not ca_bundle or not Path(ca_bundle).is_absolute():
                raise ValueError('transport.tls.ca_bundle must be an absolute PEM bundle path')
            try:
                pem = Path(ca_bundle).read_bytes()
                context.load_verify_locations(cadata=pem.decode('ascii'))
            except (OSError, UnicodeError, ssl.SSLError):
                raise ValueError('transport.tls.ca_bundle could not be loaded as a trusted PEM bundle') from None
            ca_sha256 = hashlib.sha256(pem).hexdigest()
        raw_origins = settings.get('fixture_insecure_origins', [])
        if not isinstance(raw_origins, (list, tuple)) or any(not isinstance(origin, str) for origin in raw_origins):
            raise ValueError('transport.tls.fixture_insecure_origins must be a list of origins')
        if raw_origins:
            reason = settings.get('fixture_insecure_reason')
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError('isolated fixture trust exceptions require fixture_insecure_reason')
        origins = set()
        for origin in raw_origins:
            parsed = parse_scope_url(origin)
            if parsed is None or parsed.scheme != 'https':
                raise ValueError('fixture trust exceptions require valid HTTPS loopback origins')
            url = urlsplit(origin)
            try:
                loopback = ipaddress.ip_address(parsed.host).is_loopback
            except ValueError:
                loopback = False
            if not loopback or url.path not in ('', '/') or url.query or url.fragment:
                raise ValueError('fixture trust exceptions are restricted to literal loopback HTTPS origins')
            origins.add(parsed.origin)
        return cls(context, ca_sha256=ca_sha256, fixture_origins=origins)

    def profile_for(self, destination=None) -> TLSProfile:
        parsed = parse_scope_url(destination) if destination is not None else None
        origin = parsed.origin if parsed else ''
        if origin not in self._fixture_origins:
            return self._verified
        if origin not in self._fixture_profiles:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._fixture_profiles[origin] = TLSProfile(context, pool_key=origin)
            # Origins contain only validated loopback literals/ports; supplied
            # credentials, file paths, and free-text reason never reach this log.
            log.warning('TLS verification disabled for explicit isolated fixture origin %s', origin)
        return self._fixture_profiles[origin]

    def provenance(self, destination=None) -> dict:
        parsed = parse_scope_url(destination) if destination is not None else None
        origin = parsed.origin if parsed else ''
        return {'policy': 'verified-with-explicit-loopback-fixtures/v1',
                'ca_bundle_sha256': self._ca_sha256,
                'fixture_insecure_origins': sorted(self._fixture_origins),
                'applied_profile': 'fixture_insecure' if origin in self._fixture_origins else 'verified',
                'verification_required': origin not in self._fixture_origins}
