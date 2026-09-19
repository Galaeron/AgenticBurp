"""Read-only MCP adapter (P2.1).

Exposes this harness's RESULT (issue exports), COVERAGE (engagement
summary), and PROVENANCE (run manifests) data as read-only, MCP-resource-
shaped objects -- `list_resources()`/`read_resource()`, mirroring the
Model Context Protocol's resource contract without pulling in the `mcp`
SDK package (not a project dependency; this module has zero new
dependencies and works standalone or behind an actual MCP server shim).

Hard boundary, load-bearing for this module's whole purpose: there is NO
method here that starts a scan, sends a probe, or executes anything against
a target. Every value this module returns is exactly the same
already-redacted data the normal exports produce (report_generator.
export_issues_for_host, engagement.EngagementState.summary(),
run_manifest's own redact()) -- this module adds no new redaction logic of
its own, it only re-serves what already exists, read-only, with auth,
tenant isolation, and pagination layered on top.

Tenant isolation: a bearer token authorizes exactly ONE tenant (host). A
request for a different host with that token is refused, even if the token
is otherwise valid -- this is what stops tenant A from reading tenant B's
data through a leaked/misconfigured token scope.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PAGE_SIZE = 50


class McpAuthError(PermissionError):
    """No token, or a token that does not resolve to any tenant."""


class McpTenantError(PermissionError):
    """A token resolves to a DIFFERENT tenant than the one requested."""


@dataclass(frozen=True)
class McpResource:
    uri: str
    name: str
    mime_type: str = "application/json"

    def to_dict(self) -> dict:
        return {"uri": self.uri, "name": self.name, "mimeType": self.mime_type}


_RESOURCE_KINDS = ("issues", "coverage", "provenance")


def _resource_uri(host: str, kind: str) -> str:
    return f"mcp://harness/{host}/{kind}"


def _parse_resource_uri(uri: str) -> tuple[str, str]:
    prefix = "mcp://harness/"
    if not uri.startswith(prefix):
        raise ValueError(f"not a harness MCP resource uri: {uri!r}")
    rest = uri[len(prefix):]
    host, _, kind = rest.rpartition("/")
    if not host or kind not in _RESOURCE_KINDS:
        raise ValueError(f"unrecognized harness MCP resource uri: {uri!r}")
    return host, kind


def latest_provenance_for_host(host: str, output_dir: Path | str) -> dict | None:
    """The most recently STARTED run manifest whose target_identifier
    matches `host`, or None if no manifest mentions this host at all.
    Manifests are already redacted (run_manifest.redact() at write time --
    see RunManifest.start), so this adds no redaction of its own."""
    out = Path(output_dir)
    if not out.is_dir():
        return None
    best: dict | None = None
    for path in out.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("target_identifier") != host:
            continue
        if best is None or (data.get("started_at") or 0) > (best.get("started_at") or 0):
            best = data
    return best


class ReadOnlyMcpAdapter:
    """A read-only MCP-shaped resource server. No `call_tool`/execution
    method exists on this class at all -- see module docstring."""

    def __init__(self, *, tokens_by_tenant: dict[str, str] | None = None,
                 run_output_dir: Path | str | None = None, page_size: int = DEFAULT_PAGE_SIZE):
        # {token: tenant_host}. Empty -> auth is OFF (matches server.py's own
        # _require_auth default: loopback-only deployments with no configured
        # bearer token are open). Non-empty -> every request needs a valid,
        # tenant-scoped token.
        self._tokens_by_tenant = dict(tokens_by_tenant or {})
        self._run_output_dir = Path(run_output_dir or Path(__file__).parent / "run-output")
        self.page_size = max(1, int(page_size))

    def _authorize(self, token: str, host: str) -> None:
        if not self._tokens_by_tenant:
            return
        tenant = self._tokens_by_tenant.get(token or "")
        if tenant is None:
            raise McpAuthError("invalid or missing bearer token")
        if tenant != host:
            raise McpTenantError(f"token is not authorized for tenant {host!r}")

    def list_resources(self, host: str, *, token: str = "") -> list[dict]:
        self._authorize(token, host)
        return [
            McpResource(_resource_uri(host, "issues"), f"{host} issues (T06 export)").to_dict(),
            McpResource(_resource_uri(host, "coverage"), f"{host} coverage summary").to_dict(),
            McpResource(_resource_uri(host, "provenance"), f"{host} run provenance").to_dict(),
        ]

    def read_resource(self, uri: str, *, token: str = "", page: int = 0) -> dict:
        """Returns {"uri", "mimeType", "page", "page_size", "total", "data"}.
        `data` is a list for "issues" (paginated) and a single dict/None for
        "coverage"/"provenance" (page is ignored for those)."""
        host, kind = _parse_resource_uri(uri)
        self._authorize(token, host)

        if kind == "issues":
            from harness import report_generator
            all_items = report_generator.export_issues_for_host(host)
            start = max(0, page) * self.page_size
            page_items = all_items[start:start + self.page_size]
            return {"uri": uri, "mimeType": "application/json", "page": page,
                    "page_size": self.page_size, "total": len(all_items), "data": page_items}

        if kind == "coverage":
            from harness import store, engagement
            snap = store.load_engagement(host)
            data = engagement.EngagementState.from_dict(snap).summary() if snap else None
            return {"uri": uri, "mimeType": "application/json", "page": 0,
                    "page_size": self.page_size, "total": 1 if data else 0, "data": data}

        # kind == "provenance"
        data = latest_provenance_for_host(host, self._run_output_dir)
        return {"uri": uri, "mimeType": "application/json", "page": 0,
                "page_size": self.page_size, "total": 1 if data else 0, "data": data}
