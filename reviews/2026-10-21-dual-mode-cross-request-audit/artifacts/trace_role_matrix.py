"""Stubbed-boundary trace of role_crawl.crawl_roles' access matrix (audit 2026-10-21).

httpx/httpcore are not installed, so empty stand-in modules satisfy the imports
only; crawler.crawl and role_crawl._probe are replaced with synthetic responders.
No network. This shows how crawl_roles keys its matrix and what
_compare_identities / _derive_candidates derive for two principals that share a
role label. It is NOT a production-caller proof.

Usage: python -I trace_role_matrix.py <worktree-root> <out.json>
"""
import asyncio
import json
import sys
import types
from pathlib import Path

root, out_path = sys.argv[1], sys.argv[2]
# mode "owner-scoped" (default): bob is denied alice's order.
# mode "bola": bob receives alice's order (a real BOLA).
# mode "bola-distinct-labels": as "bola", but bob's role label is "member".
mode = sys.argv[3] if len(sys.argv) > 3 else "owner-scoped"
sys.path.insert(0, root)


class _Anything(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return type(name, (Exception,), {})


for mod in ("httpx", "httpcore"):
    sys.modules.setdefault(mod, _Anything(mod))

from harness import role_crawl  # noqa: E402
from harness import crawler  # noqa: E402

BASE = "http://lab.invalid"
ALICE = role_crawl.RoleSession(role="user", headers={"Authorization": "Bearer synthetic-alice"}, name="alice")
BOB = role_crawl.RoleSession(role="member" if mode == "bola-distinct-labels" else "user", headers={"Authorization": "Bearer synthetic-bob"}, name="bob")
ANON = role_crawl.RoleSession(role="anonymous", headers={})


class _Crawl:
    endpoints = {"/orders/1", "/shared/announcements/1",
                 "/vehicle/0f6c1a52-1111-4a1a-9a1a-aaaaaaaaaaaa/location"}
    call_shapes, forms, errors, suppressed_navigation = [], [], [], set()


async def fake_crawl(*a, **kw):
    return _Crawl()


# Synthetic application: /orders/1 belongs to alice (bob gets 403);
# /shared/announcements/1 is legitimately shared with every authenticated user.
def responder(url, headers):
    who = (headers.get("Authorization") or "").rsplit("-", 1)[-1] or "anon"
    if "/orders/" in url:
        allowed = who == "alice" or (mode != "owner-scoped" and who == "bob")
        return (200, json.dumps({"order": 1, "owner": "alice", "items": ["a" * 30]})) if allowed else (403, "denied")
    if "/shared/" in url:
        return (200, json.dumps({"text": "quarterly note " + "x" * 30})) if who != "anon" else (401, "login")
    return (200, json.dumps({"carId": "synthetic", "lat": 1.0, "pad": "y" * 30})) if who != "anon" else (401, "login")


async def fake_probe(method, url, headers, timeout, **kw):
    status, body = responder(url, headers)
    return status, body, {"Content-Type": "application/json"}


crawler.crawl = fake_crawl
role_crawl._probe = fake_probe

result = asyncio.run(role_crawl.crawl_roles(BASE, [ALICE, BOB, ANON], active_discovery=False))
out = {
    "mode": mode,
    "principal_ids": [r.principal_id() for r in (ALICE, BOB, ANON)],
    "endpoints": [e.to_dict() for e in result.endpoints],
    "fingerprint_keys": {e.path: sorted(e.fingerprints) for e in result.endpoints},
    "idor_findings": [f["summary"] for f in result.idor_findings],
    "idor_candidates": [(c["method"], c["path"], c["reached_by"]) for c in result.idor_candidates],
    "auth_bypass_candidates": [(c["method"], c["path"], c["reason"]) for c in result.auth_bypass_candidates],
}
Path(out_path).write_text(json.dumps(out, indent=2, default=str))
print(json.dumps(out, indent=1, default=str))
