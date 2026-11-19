"""R11-6 (b): a write body built from an object's observed read representation.

r11 skipped 38 mass-assignment plans for want of a captured JSON write body, and
the role crawler's guessed body (`role_crawl._GENERIC_JSON_BODY`) stood in for the
real fields on every write it probed. When an update endpoint (PUT/PATCH of one
object) has no captured body, its own GET says which fields the object has.

Only settable fields are sent back. A field is read-only, and never sent, when it is:
- an identifier or reference (`id`, `uuid`, `*Id`, `*_id`);
- a timestamp or version (`createdAt`, `updated_at`, `version`, `etag`, `*Date`);
- server-computed or derived (a count, total, hash, digest, URL/link), or a
  nested object or list (an included association, not a column);
- a credential or secret (a password or its hash, a token, a TOTP seed): writing a
  hash back would set the password to the hash;
- null (no value to restore it to).
A read holding a masked value is not round-trippable: no body is built.
"""
from __future__ import annotations

import re

_TIMESTAMP_KEY = re.compile(
    r"(?:^|[_\-.])(?:at|on|date|time|timestamp|ts)$|(?:At|On|Date|Time|Timestamp)$")
# Matched as the END of the normalized key ("itemCount", "totalPrice" is not one,
# "accountType" is not a count).
_DERIVED_SUFFIXES = ("count", "total", "sum", "average", "avg", "checksum", "digest",
                     "hash", "salt", "url", "uri", "href", "link", "links", "etag")
_DERIVED_WORDS = ("computed", "derived", "calculated")
_SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "apikey",
                 "credential", "totp", "session", "cookie")


def _norm(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key or "").lower())


def read_only_field(key, value) -> bool:
    """True for a field a body built from a read never sends (module docstring)."""
    from .cross_identity_validator import _CAMEL_ID_FIELD, _ID_FIELD, _VOLATILE_KEY
    raw, norm = str(key or ""), _norm(key)
    if not norm or value is None or isinstance(value, (dict, list)):
        return True
    if _ID_FIELD.search(raw) or _CAMEL_ID_FIELD.search(raw):
        return True
    if _VOLATILE_KEY.match(norm) or _TIMESTAMP_KEY.search(raw):
        return True
    return (norm.endswith(_DERIVED_SUFFIXES) or norm in ("otp", "mfa", "pin")
            or any(w in norm for w in _DERIVED_WORDS + _SECRET_WORDS))


def read_object(doc):
    """The single object a read returns (an envelope unwrapped), else None: a
    listing is not one object."""
    from .cross_identity_validator import _unwrap_envelope
    obj = _unwrap_envelope(doc)
    if not isinstance(obj, dict) or not obj:
        return None
    if any(isinstance(v, list) and v and all(isinstance(i, dict) for i in v) for v in obj.values()) \
            and len(obj) <= 3:
        return None   # {"items": [...], "total": n}: a collection page
    return obj


def settable_fields(obj: dict) -> dict:
    """The top-level fields of `obj` a write may send back unchanged."""
    return {k: v for k, v in obj.items() if not read_only_field(k, v)}


def body_from_read(doc) -> tuple[dict | None, str]:
    """(settable fields, "") for a read `doc`, else (None, why no body is built)."""
    from .cross_identity_validator import _masked_paths
    obj = read_object(doc)
    if obj is None:
        return None, "the read is not one JSON object"
    if _masked_paths(obj):
        return None, "the read holds a masked value (not round-trippable)"
    fields = settable_fields(obj)
    if not fields:
        return None, "the read has no settable field (only ids, timestamps or derived values)"
    return fields, ""
