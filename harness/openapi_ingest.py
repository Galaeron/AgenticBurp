"""OpenAPI / Swagger ingestion (W-21 discovery slice).

Many APIs hand you their entire contract at /openapi.json, /swagger.json, or
/v3/api-docs. api_surface_discovery already PROBES for those, but only kept the
path KEYS -- it discarded the methods, parameters, and request-body fields the
spec spells out, which is exactly the per-operation detail a validator needs a
sink to test (a parameter is what SQLi/IDOR/SSRF probe). A perfect validator has
zero recall against a parameter the surface never surfaced.

This module extracts the full operation surface -- (path, method, parameters
with their location, request-body field names) -- from an OpenAPI 3 or Swagger 2
document, resolving top-level parameter $refs. It is a pure function of the spec
text, so it is tested offline with fixture specs; the reach improvement is that
every documented operation and its inputs enter discovery instead of just a bare
path list.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


@dataclass(frozen=True)
class Param:
    name: str
    location: str  # query | path | header | cookie | body


@dataclass(frozen=True)
class Operation:
    path: str
    method: str  # upper-case verb
    parameters: tuple[Param, ...] = ()

    @property
    def param_names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.parameters)


def _as_doc(spec) -> dict:
    if isinstance(spec, dict):
        return spec
    if isinstance(spec, (str, bytes)):
        try:
            doc = json.loads(spec)
            return doc if isinstance(doc, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _resolve_ref(ref: str, doc: dict):
    """Resolve a local JSON-pointer $ref (#/a/b/c) within the doc. Returns None
    for external or unresolvable refs -- never raises."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _schema_property_names(schema: dict, doc: dict, _depth: int = 0) -> list[str]:
    if not isinstance(schema, dict) or _depth > 3:
        return []
    if "$ref" in schema:
        resolved = _resolve_ref(schema["$ref"], doc)
        return _schema_property_names(resolved, doc, _depth + 1) if isinstance(resolved, dict) else []
    props = schema.get("properties")
    if isinstance(props, dict):
        return [k for k in props.keys() if isinstance(k, str)]
    # array of objects
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        return _schema_property_names(schema["items"], doc, _depth + 1)
    return []


def _params_for_operation(op: dict, doc: dict) -> list[Param]:
    params: list[Param] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, location: str):
        if isinstance(name, str) and name and (name, location) not in seen:
            seen.add((name, location))
            params.append(Param(name=name, location=location))

    for raw in op.get("parameters", []) or []:
        p = raw
        if isinstance(p, dict) and "$ref" in p:
            p = _resolve_ref(p["$ref"], doc)
        if not isinstance(p, dict):
            continue
        loc = p.get("in", "query")
        if loc == "body":  # Swagger 2 body parameter carries a schema
            for field in _schema_property_names(p.get("schema", {}), doc):
                _add(field, "body")
        else:
            _add(p.get("name", ""), loc)

    # OpenAPI 3 request body
    body = op.get("requestBody")
    if isinstance(body, dict):
        if "$ref" in body:
            body = _resolve_ref(body["$ref"], doc) or {}
        for _media, media_obj in (body.get("content", {}) or {}).items():
            if isinstance(media_obj, dict):
                for field in _schema_property_names(media_obj.get("schema", {}), doc):
                    _add(field, "body")
    return params


def operations_from_spec(spec) -> list[Operation]:
    """All (path, method, parameters) operations documented in an OpenAPI 3 or
    Swagger 2 spec (JSON string or dict). Empty list for anything unparseable."""
    doc = _as_doc(spec)
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    out: list[Operation] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            continue
        # path-level parameters apply to every operation under it
        shared = _params_for_operation({"parameters": item.get("parameters", [])}, doc)
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = list(shared) + _params_for_operation(op, doc)
            # de-dupe preserving order
            seen: set[tuple[str, str]] = set()
            uniq = []
            for p in params:
                if (p.name, p.location) not in seen:
                    seen.add((p.name, p.location))
                    uniq.append(p)
            out.append(Operation(path=path, method=method.upper(), parameters=tuple(uniq)))
    return out


def methods_by_path(spec) -> dict[str, tuple[str, ...]]:
    """{path: (METHOD, ...)} from a spec -- for surface routes that today carry
    no method because only the path key was kept."""
    by_path: dict[str, set[str]] = {}
    for op in operations_from_spec(spec):
        by_path.setdefault(op.path, set()).add(op.method)
    return {p: tuple(sorted(ms)) for p, ms in by_path.items()}
