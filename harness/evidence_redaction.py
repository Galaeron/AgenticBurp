"""Redaction assertion for durable evidence blobs (ARC-13).

`store.put_evidence_blob` persists bytes verbatim; its callers (`run_context`,
`browser_driver`) redact BEFORE calling it. This module lets the store verify
that claim instead of trusting it: `redaction_findings(data)` re-applies the
project's own redactors to the blob and reports every place they would still
change something. A correctly redacted blob is a fixed point of those
redactors, so a clean blob yields no findings.

Scope is exactly the contract the callers use -- secret-NAMED fields and
headers, secret query parameters and URL userinfo, and nested JSON / "key=value"
body strings. It is NOT a content scanner: an unlabelled secret in prose, or a
secret under a field name the redactors do not know, is not detected (the same
limit `harness.security` documents). Findings carry a kind and a key path, never
a value, so reporting one cannot leak the secret it found.
"""
from __future__ import annotations

import json

from harness import security

# Kinds of finding. Stable strings: tests and log lines key on them.
SECRET_FIELD = "secret-field"      # a secret-named key holds a real value
SECRET_BODY = "secret-body"        # a string the body redactor would still change
SECRET_URL = "secret-url"          # a URL the URL redactor would still change

_MAX_DEPTH = 64
_MAX_FINDINGS = 50
_METRIC_NAMES = frozenset({"auth", "csrf"})   # security._METRIC_LABEL_SECRET_NAMES


def _is_placeholder(value) -> bool:
    """True for a value a redactor in this project could have left in place of a
    secret: the two placeholders, the harness's own `<REDACTED>` marker, or the
    restricted JWT-header form `redact_headers` emits."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return (value in (security.REDACTED_PLACEHOLDER, security.SECRET_VALUE_PLACEHOLDER,
                      "<REDACTED>", "")
            or security._safe_redacted_header(value))


def _is_metric(name, value) -> bool:
    return (isinstance(value, (bool, int, float))
            and str(name).strip().lower().replace("-", "_").replace(" ", "_") in _METRIC_NAMES)


def _walk(node, path: str, out: list, depth: int) -> None:
    if len(out) >= _MAX_FINDINGS or depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            child = f"{path}.{name}" if path else name
            secret_named = (security._is_secret_field_name(name)
                            or name.strip().lower() in security.SECRET_HEADER_NAMES)
            if secret_named:
                if not _is_placeholder(value) and not _is_metric(name, value):
                    out.append((SECRET_FIELD, child))
                continue          # a placeholder or a metric label: nothing below to check
            _walk(value, child, out, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{path}[{index}]", out, depth + 1)
    elif isinstance(node, str) and node:
        if node.lower().startswith(("http://", "https://")) and security.redact_secrets_in_url(node) != node:
            out.append((SECRET_URL, path))
        elif security.redact_secrets_in_body(node) != node:
            out.append((SECRET_BODY, path))


def redaction_findings(data) -> "list[tuple[str, str]]":
    """`[(kind, key_path), ...]` for everything the redactors would still change in
    `data`; `[]` means the blob is a fixed point of them (treated as redacted).

    JSON blobs (what both in-tree callers write) are walked structurally; anything
    else is checked as a body string. Undecodable bytes are decoded with
    replacement -- the redactors match field names, which survive that."""
    text = bytes(data).decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    out: list = []
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    if isinstance(document, (dict, list)):
        _walk(document, "", out, 0)
    elif security.redact_secrets_in_body(text) != text:
        out.append((SECRET_BODY, ""))
    return out
