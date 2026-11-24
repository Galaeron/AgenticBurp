"""Mining of SurfaceDiscovery: sensitive-file probes and records, and the routes mined from
responses, subresources, nested ids, query parameters and actions.

Part of the ARC-9 split of harness.api_surface_discovery. Import these names from
harness.api_surface_discovery, the facade, not from this module.

`_host_in_scope` and `sensitive_file_verdict` are read as `_asd.<name>` at call time (tests
patch them on the facade).
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse

from harness.api_surface_data import (
    Route, _BACKUP_BASES_PER_DIR, _BACKUP_SUFFIXES, _COMMON_BACKUP_BASES, _COMMON_PARAMS,
    _extract_html_links, _has_backup_suffix, _is_not_found, _looks_html_body,
)
from harness.api_surface_sensitive import _dotenv_has_credentials, sensitive_artifact_class


class _MiningMixin:
    """Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery."""

    async def _probe_sensitive_files(self) -> None:
        """Phase 0.2(c): probe generically-sensitive artifacts at their fixed
        conventional paths (a wordlist distinct from the REST nouns), then
        generate backup-suffix variants (.bak/~/.old/...) of common source files
        and of any discovered file-like route (a route whose last segment has an
        extension). The existence oracle is unchanged: only non-404s are kept.
        Hits are tracked in _sensitive_hits for downstream finding emission.

        WL-05 (E39): a 2xx/3xx is an EXISTENCE signal only. Each hit also gets an
        evidence record (_sensitive_record) whose `confirmed` flag is set only when
        the 2xx body carries the artifact's content signature. Redirects are not
        followed here, so a 302 to a login page is recorded as the 302 it is."""
        self._follow_redirects = False
        try:
            for f in self.sensitive_files:
                if not self._budget_left():
                    return
                path = "/" + f.lstrip("/")
                route = await self._check(path, "sensitive_file")
                if route is not None and 200 <= route.status < 400:
                    self._sensitive_hits.append(path)
                    self._sensitive_evidence.append(self._sensitive_record(path, route))

            # r5: a backup suffix belongs on the FILE, never on its query string
            # (`provider-metadata.json?id=1` -> `...?id=1.bak` is the same file),
            # and a name that already carries one is not a new base. Without both
            # rules each role sweep re-seeded the previous sweep's variants and
            # stacked one more suffix (`?id=1.bak.old.swp`): ~28k requests to one
            # static JSON file in the Juice Shop r5 run.
            discovered_bases: dict[str, list[str]] = {}
            for p in list(self._seen):
                path_only = p.split("?", 1)[0]
                seg = path_only.rsplit("/", 1)[-1]
                if ("." in seg and not seg.startswith(".")       # looks like <name>.<ext>
                        and not _has_backup_suffix(seg)):
                    parent = path_only.rsplit("/", 1)[0] + "/"
                    bases = discovered_bases.setdefault(parent, [])
                    if path_only.lstrip("/") not in bases:
                        bases.append(path_only.lstrip("/"))
            file_like = set(_COMMON_BACKUP_BASES)
            for parent, bases in discovered_bases.items():
                bases.sort()
                kept = bases[:_BACKUP_BASES_PER_DIR]
                file_like.update(kept)
                if len(bases) > len(kept):
                    self._backup_capped[parent] = len(bases) - len(kept)
            for base in sorted(file_like):
                base_path = "/" + base.lstrip("/")
                for suf in _BACKUP_SUFFIXES:
                    if not self._budget_left():
                        return
                    candidate = base_path + suf
                    route = await self._check(candidate, "sensitive_file")
                    if route is not None and self._mirrors(candidate, base_path):
                        # The server ignored the suffix and served the original:
                        # not a backup file, and its siblings will mirror it too.
                        self._seen.pop(candidate, None)
                        self._bodies.pop(candidate, None)
                        self._backup_mirrored += 1
                        break
        finally:
            self._follow_redirects = True

    def _mirrors(self, candidate: str, base_path: str) -> bool:
        """True when `candidate` answered with exactly its base file's body."""
        base_body = self._bodies.get(base_path)
        body = self._bodies.get(candidate)
        if base_body is None or body is None:
            return False
        return self._norm_body_hash(body, candidate) == self._norm_body_hash(base_body, base_path)

    def _sensitive_record(self, path: str, route: Route) -> dict:
        """The evidence record for one sensitive-file hit: the real status, content
        type, body length and fingerprint, and the content verdict. It never holds
        the body or any value from it."""
        status = int(route.status or 0)
        redirected_to = self._redirected_to.get(path)
        if redirected_to is not None:
            # Seen in an earlier phase whose transport followed a redirect: the
            # status and body belong to the target page, never to this path.
            return {"path": path, "status": None, "final_status": status,
                    "redirected_to": redirected_to,
                    "content_type": (self._content_types.get(path) or "")[:100],
                    "length": route.length, "fingerprint": "",
                    "expected_structure": sensitive_artifact_class(path) or "",
                    "structure": "", "confirmed": False, "outcome": "redirect",
                    "reason": (f"a redirect was followed to {redirected_to}, which answered "
                               f"HTTP {status}; not the file itself")}
        body = self._bodies.get(path, "") if 200 <= status < 300 else ""
        verdict = _asd.sensitive_file_verdict(path, status, body)
        return {
            "path": path, "status": status,
            "content_type": (self._content_types.get(path) or "")[:100],
            "length": route.length,
            "fingerprint": (hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
                            if body else ""),
            "expected_structure": sensitive_artifact_class(path) or "",
            "structure": verdict.structure or "",
            "contains_credentials": verdict.structure == "dotenv" and _dotenv_has_credentials(body),
            "confirmed": verdict.structure is not None,
            "outcome": verdict.outcome,
            "reason": verdict.reason,
        }

    async def _mine_responses(self) -> None:
        """Mine each 2xx body once for three candidate sources:
          - Phase 0.2(d): path-like strings and same-host URLs anywhere in the
            body (JSON payloads, HTML, help/error text), via js_endpoint_extractor
            generalized off the JS-crawl -- fed back as candidate routes so an
            internal path the app merely NAMES becomes probed surface.
          - HTML link/form mining: <a href>, <form action>, <link href> tags
            in HTML responses -- so the server-rendered navigation graph feeds
            discovery even when the surface isn't a JSON API.
          - id enumeration: a JSON list/object's `id` fields -> id-scoped siblings.
        All work off the SAME fetch, so this is one GET per seed."""
        import harness.js_endpoint_extractor as jse
        seeds = [p for p, r in list(self._seen.items()) if 200 <= r.status < 300]
        for p in seeds:
            if not self._budget_left():
                return
            r = await self._raw("GET", p)
            if not r or _is_not_found(r[0], r[1]):
                continue
            body = r[1]
            # (d) body path/URL mining -- runs on ANY body, not just parseable JSON.
            for path in sorted(jse.extract_endpoints(body, self.base_url).same_origin_paths):
                if not self._budget_left():
                    return
                await self._check(path.replace("{id}", "1"), "body")
            # HTML link/form mining: extract navigable hrefs and form actions from
            # HTML responses. The js_endpoint_extractor catches path-like strings
            # but misses proper HTML anchors that use relative hrefs or query params.
            if _looks_html_body(body):
                for href in _extract_html_links(body, self.base_url):
                    if not self._budget_left():
                        return
                    parsed = urlparse(href)
                    if _asd._host_in_scope(href, self.allowed_hosts) or not parsed.netloc:
                        path_only = parsed.path or "/"
                        if path_only.startswith("/"):
                            await self._check(path_only, "html")
            # id enumeration (JSON only).
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                continue
            items = data if isinstance(data, list) else [data]
            base_coll = re.sub(r"/\d+$", "", p)
            for it in items[:20]:
                if isinstance(it, dict) and "id" in it and self._budget_left():
                    await self._check(f"{base_coll}/{it['id']}", "response")

    def _representative_ids(self) -> dict[str, str]:
        """One representative (lowest) object id per collection, from routes of
        the shape /<collection>/<digits>. Shared by sub-resource and action
        mining: the SHAPE repeats across ids, so one id per collection is enough."""
        reps: dict[str, str] = {}
        for p in list(self._seen):
            m = re.match(r"^(.*)/(\d+)$", p)
            if m and (m.group(1) not in reps or int(m.group(2)) < int(reps[m.group(1)])):
                reps[m.group(1)] = m.group(2)
        return reps

    async def _mine_subresources(self) -> None:
        # Nest nouns under one representative id per collection.
        for coll, idv in self._representative_ids().items():
            for n in self.nouns:
                if not self._budget_left():
                    return
                await self._check(f"{coll}/{idv}/{n}", "subresource")

    async def _mine_deep_nested(self) -> None:
        """Three-segment nesting under collections that returned 2xx: if
        /api/admin/ has live routes, try /api/admin/<coll>/<noun> for each
        collection+noun pair. Adaptive: only fans out under namespaces that
        proved live, so a wordlist with 5 dead admin paths wastes nothing."""
        live_prefixes: set[str] = set()
        for p in list(self._seen):
            parts = [s for s in p.split("/") if s]
            if len(parts) >= 2:
                live_prefixes.add("/" + "/".join(parts[:2]) + "/")
        for pre in sorted(live_prefixes):
            for coll in self.collections:
                for n in self.nouns:
                    if not self._budget_left():
                        return
                    path = f"{pre}{coll}/{n}"
                    if path not in self._seen:
                        await self._check(path, "deep_nested")

    async def _probe_query_params(self) -> None:
        """Probe common query parameters on discovered GET endpoints. An endpoint
        that returns a distinct response with ?param=value vs. without means it
        accepts that parameter -- surfaces hidden input vectors (file=, path=,
        redirect=, org_id=) that the path-only wordlist never tests."""
        candidates = [p for p, r in list(self._seen.items())
                      if 200 <= r.status < 300 and "?" not in p]
        candidates.sort(key=lambda p: (not any(k in p.lower() for k in
                           ("search", "query", "filter", "find")), p))
        for p in candidates:
            if not self._budget_left():
                return
            base_r = await self._raw("GET", p)
            if not base_r or _is_not_found(base_r[0], base_r[1]):
                continue
            base_len = len(base_r[1])
            base_hash = self._norm_body_hash(base_r[1], p)
            params = (("q", "query", "search", "filter") +
                      tuple(x for x in _COMMON_PARAMS if x not in
                            ("q", "query", "search", "filter"))) if any(
                                k in p.lower() for k in ("search", "query", "filter", "find")) else _COMMON_PARAMS
            for param in params:
                if not self._budget_left():
                    return
                qpath = f"{p}?{param}=1"
                r = await self._raw("GET", qpath)
                if r is None or self._not_found(r[0], r[1], qpath):
                    continue
                if await self._prefix_wildcard("GET", qpath, r[0], r[1]):
                    continue
                r_hash = self._norm_body_hash(r[1], qpath)
                if r_hash != base_hash or abs(len(r[1]) - base_len) > 50:
                    if qpath not in self._seen:
                        self._seen[qpath] = Route(path=qpath, status=r[0],
                                                   methods=("GET",), length=len(r[1]),
                                                   source="param_probe")
                    break

    async def _mine_actions(self) -> None:
        """Phase 0.2(b): probe object-scoped ACTION suffixes (/tickets/1/lock),
        beyond the fixed noun list. Two sources: the built-in workflow-verb
        vocabulary, and verbs GENERATED from actions the app already exposes --
        an /api/tickets/{id}/escalate seen in a spec (or found on any object)
        makes `escalate` worth trying on every other object, catching actions
        specific to this app that no built-in list would name. Verbs already in
        the noun list are skipped -- sub-resource mining tried those already."""
        reps = self._representative_ids()
        if not reps:
            return
        harvested: set[str] = set()
        for p in list(self._seen):
            m = re.search(r"/(?:\d+|\{[^/]+\})/([A-Za-z][A-Za-z0-9_-]{1,29})$", p)
            if m:
                harvested.add(m.group(1).lower())
        noun_set = set(self.nouns)
        actions = [a for a in dict.fromkeys(list(self.actions) + sorted(harvested))
                   if a not in noun_set]
        for coll, idv in reps.items():
            for act in actions:
                if not self._budget_left():
                    return
                await self._check(f"{coll}/{idv}/{act}", "action")


from harness import api_surface_discovery as _asd  # noqa: E402
