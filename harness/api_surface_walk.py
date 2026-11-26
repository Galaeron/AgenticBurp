"""Directory walking of SurfaceDiscovery: the ffuf fast paths (direct and through the run), the
directory scan and its bounded recursion, and prefix derivation.

Part of the ARC-9 split of harness.api_surface_discovery. Import these names from
harness.api_surface_discovery, the facade, not from this module.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from harness.api_surface_data import SurfaceResult, _first_segment_prefix
from harness.api_surface_sensitive import _sig_directory_listing


class _WalkMixin:
    """Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery."""

    async def _ffuf_fast_path(self, result: SurfaceResult) -> int:
        """Run ffuf in a container and seed its discovered routes into _seen.
        Returns the number of routes found. Fails silently (returns 0) when
        Docker or the image is absent.

        Inside a run (only with ffuf_in_runs) ffuf is pointed at a loopback
        ToolProxy: every request it makes is replayed through the run, so it is
        charged to the run budget and checked against scope and the gate, and the
        container may reach nothing but that proxy. Its share is capped at most of
        the sweep budget it stands in for; the requests it sent count as probes,
        and the paths it sent are not guessed again by the Python sweep."""
        from harness import ffuf_runner
        if self.run_context is not None and not self.ffuf_in_runs:
            result.errors.append("ffuf skipped: external requests cannot spend the owning run budget")
            return 0
        ok, reason = ffuf_runner.ffuf_available(self.ffuf_image)
        if not ok:
            result.errors.append(f"ffuf skipped: {reason}")
            return 0
        covered: set[str] = set()
        if self.run_context is None:
            ffuf_result = await ffuf_runner.ffuf_discover(
                self.base_url, image=self.ffuf_image, headers=self.headers or None,
                filter_size=self._soft404_bytes, wordlist=self.ffuf_wordlist)
        else:
            remaining = min(self.max_probes, self._phase_limit) - self._probes
            # Leave a fifth for re-checking ffuf's hits and the sweep it cannot do.
            share = remaining - remaining // 5
            if share <= 0:
                result.errors.append("ffuf skipped: no discovery budget left")
                return 0
            # Inside a run ffuf launches only by digest (owner decision, #28): a
            # configured name@sha256 must match the local image, a tag is pinned to
            # its local image ID; the broker refuses anything unpinned.
            pinned, pin_reason = ffuf_runner.pin_image(self.ffuf_image)
            if pinned is None:
                result.errors.append(f"ffuf skipped: image not pinned by digest: {pin_reason}")
                return 0
            ffuf_result, covered, _capped = await self._ffuf_through_run(result, "/", share,
                                                                         pinned, pin_reason)
            if not ffuf_result.error:
                self._ffuf_in_run_image = (pinned, pin_reason)
        if ffuf_result.error:
            # ffuf's verdict on what it sent is lost: nothing counts as covered, so
            # the Python sweep still guesses those paths itself.
            result.errors.append(f"ffuf error: {ffuf_result.error}")
            return 0
        if ffuf_result.truncated:
            result.errors.append(f"ffuf timed out: kept {len(ffuf_result.routes)} hit(s) it "
                                 "printed before it was stopped (scan truncated)")
        count = 0
        matches_before = self._soft404_matches
        for route in ffuf_result.routes:
            if route.path not in self._seen:
                # External tool hits are candidates, not proof of existence.
                if await self._check(route.path, "ffuf") is not None:
                    count += 1
        result.ffuf_soft404_disagreements = self._soft404_matches - matches_before
        if result.ffuf_soft404_disagreements:
            result.errors.append(f"ffuf: {result.ffuf_soft404_disagreements} hit(s) matched the "
                                 "harness soft-404 fingerprint and were dropped")
        self._ffuf_covered = covered
        if count:
            result.errors.append(f"ffuf seeded {count} routes")
        return count

    async def _ffuf_through_run(self, result: SurfaceResult, dir_path: str, share: int,
                                pinned: str, pin_reason: str):
        """One in-run ffuf scan of `dir_path` (a directory under base_url, "/" for
        the root) through a loopback ToolProxy: every request it sends is replayed
        through the run (budget, scope, gate) and at most `share` are sent. The
        requests count as probes. Returns (ffuf result, paths it covered, wordlist
        requests past the share that were not sent)."""
        from harness import ffuf_runner, tool_runner
        from harness.tool_proxy import ToolProxy
        run = self.run_context
        proxy = await ToolProxy(run, self.base_url, capability="surface_discovery_ffuf",
                                max_forwarded=share).start()
        try:
            ffuf_result = await ffuf_runner.ffuf_discover(
                proxy.url_for(self.base_url + dir_path), image=pinned, require_digest=True,
                headers=self.headers or None, filter_size=self._soft404_bytes,
                wordlist=self.ffuf_wordlist,
                timeout=ffuf_runner.in_run_timeout(share),
                cancel=lambda: run.cancel.cancelled or proxy.stop_requested,
                egress=tool_runner.EgressPolicy(allowed_hosts=(tool_runner._HOST_ALIAS,)))
        finally:
            await proxy.close()
        self._probes += proxy.forwarded
        result.ffuf_requests += proxy.forwarded
        # Covered: only paths whose response came back through the run (a
        # transport error or a refused send is not), and only when ffuf's
        # verdict on them was not lost (the caller drops them on an error).
        base_path = urlsplit(self.base_url).path.rstrip("/")
        covered = {path[len(base_path):] for path in proxy.forwarded_paths
                   if path.startswith(base_path + "/")}
        capped = proxy.refused.get("tool_cap", 0)
        note = f"ffuf ({pin_reason}) sent {proxy.forwarded} request(s) through the run"
        if dir_path != "/":
            note += f" under {dir_path}"
        if capped:
            note += f"; {capped} wordlist request(s) past its share were not sent"
        if proxy.stop_reason:
            note += f"; stopped: {proxy.stop_reason}"
        result.errors.append(note)
        return ffuf_result, covered, capped

    def _directories(self, paths) -> list[str]:
        """The directories among discovered `paths`, each as "/dir/": a route that
        ends in "/", one whose GET redirected to itself plus "/", and one whose 2xx
        body is a web-server directory index. Only routes discovery saw answer
        (not spec-listed ones), never the root and never a query."""
        found: set[str] = set()
        for path in paths:
            route = self._seen.get(path)
            if route is None or not route.status or path == "/" or "?" in path or "{" in path:
                continue
            if path.endswith("/"):
                found.add(path)
            elif path + "/" in self._dir_redirects or (
                    path in self._bodies and _sig_directory_listing(self._bodies[path])):
                found.add(path + "/")
        return sorted(found)

    def _directory_pruned(self, directory: str) -> bool:
        """A directory under a namespace already shown to be a wildcard or a dead
        soft-404 branch: its guessed children would only be suppressed."""
        return (any(directory.startswith(p) for p in self._wildcard_prefixes)
                or any(p in self._soft404_dead
                       for p in self._ancestor_prefixes(directory + "x")))

    async def _scan_directory(self, result: SurfaceResult, directory: str,
                              words: list[str]) -> bool:
        """Probe the children of one directory within the current phase limit:
        through in-run ffuf when it already ran in this run, else the Python
        wordlist. True when every child was tried."""
        if self._ffuf_in_run_image is not None:
            remaining = min(self.max_probes, self._phase_limit) - self._probes
            # Keep a fifth for the harness re-check of ffuf's hits.
            share = remaining - remaining // 5
            if share > 0:
                pinned, pin_reason = self._ffuf_in_run_image
                ffuf_result, covered, capped = await self._ffuf_through_run(
                    result, directory, share, pinned, pin_reason)
                if not ffuf_result.error:
                    for route in ffuf_result.routes:
                        path = directory.rstrip("/") + route.path
                        if path not in self._seen:
                            await self._check(path, "ffuf")
                    self._ffuf_covered |= covered
                    return not (ffuf_result.truncated or capped)
                result.errors.append(f"ffuf error under {directory}: {ffuf_result.error}; "
                                     "the Python wordlist scanned it instead")
        for word in words:
            if not self._budget_left():
                return False
            await self._check(directory + word, "recursive")
        return True

    async def _recurse_directories(self, result: SurfaceResult) -> None:
        """Bounded recursive content discovery. Each level probes the wordlist (the
        REST nouns and the sensitive-file names, or in-run ffuf's own list) under
        every directory found so far that was not yet expanded, then the
        directories that turned up feed the next level, up to recursion_depth
        levels. Every probe goes through _check (one GET, scope- and gate-checked,
        wildcard/soft-404 controls included) and the whole recursion spends at
        most recursion_max_requests of the discovery budget, shared evenly by the
        directories of a level. Off (0) by default."""
        depth, cap = self.recursion_depth, self.recursion_max_requests
        if depth <= 0 or cap <= 0:
            return
        saved_limit, start = self._phase_limit, self._probes
        recursion_limit = min(saved_limit, start + cap)
        words = [w.lstrip("/") for w in dict.fromkeys(list(self.nouns) + list(self.sensitive_files))
                 if w.strip("/")]
        frontier = self._directories(list(self._seen))
        expanded: set[str] = set()
        level = deepest = found = scanned = pruned = partial = not_reached = 0
        try:
            while frontier and level < depth:
                level += 1
                before = set(self._seen)
                for index, directory in enumerate(frontier):
                    left = recursion_limit - self._probes
                    if left <= 0:
                        not_reached = len(frontier) - index
                        break
                    expanded.add(directory)
                    if self._directory_pruned(directory):
                        pruned += 1
                        continue
                    scanned += 1
                    deepest = level
                    # An even share of what is left for the directories still to go,
                    # so the first directory cannot spend the whole cap.
                    self._phase_limit = self._probes + max(1, left // (len(frontier) - index))
                    if not await self._scan_directory(result, directory, words):
                        partial += 1
                    self._phase_limit = recursion_limit
                new = [path for path in self._seen if path not in before]
                found += len(new)
                frontier = [d for d in self._directories(new) if d not in expanded]
                if not_reached:
                    break
        finally:
            self._phase_limit = saved_limit
        spent = self._probes - start
        note = (f"recursive discovery: {scanned} director(ies) expanded over {deepest} of {depth} "
                f"level(s); {spent} of {cap} request(s); {found} new route(s)")
        if pruned:
            note += f"; {pruned} under a wildcard or dead soft-404 namespace skipped"
        if partial or not_reached:
            why = ("its request cap" if recursion_limit == start + cap
                   else "the discovery budget")
            note += (f"; {partial + not_reached} director(ies) left partly or wholly "
                     f"unexpanded at {why}")
        if frontier and level >= depth:
            note += f"; {len(frontier)} director(ies) found at the depth cap were not expanded"
        result.errors.append(note)

    async def _derive_prefixes(self, max_new: int = 8) -> None:
        """Phase 0.2(a): sweep the namespaces the app actually exposes, not only
        the built-in prefix guesses. Collect the '/<segment>/' prefixes present
        across caller-supplied seed paths (the crawler's server-rendered links)
        and routes already found, and sweep the noun list (bare + id-scoped)
        under any prefix outside the built-in set. This reaches a non-API /
        server-rendered surface living under a different prefix as soon as
        anything reveals it -- a headless-API run with no seeds simply derives
        nothing and this is a no-op. Bounded by max_new prefixes and the probe
        budget so it can't fan out unboundedly."""
        known = set(self.prefixes)
        derived: list[str] = []
        seen_new: set[str] = set()
        for path in list(self.seed_paths) + list(self._seen.keys()):
            pre = _first_segment_prefix(path)
            if pre == "/" or pre in known or pre in seen_new:
                continue
            seen_new.add(pre)
            derived.append(pre)
            if len(derived) >= max_new:
                break
        # Record swept prefixes so a later call (e.g. after body mining reveals a
        # new namespace) doesn't re-sweep them -- makes this safe to call twice.
        self.prefixes.extend(derived)
        for pre in derived:
            for n in self.nouns:
                if not self._budget_left():
                    return
                for suffix in ("", "/1"):
                    await self._check(pre + n + suffix, "derived")
