"""Probing and not-found calibration of SurfaceDiscovery: the scoped, budgeted request, the
soft-404 / wildcard fingerprints and the existence check.

Part of the ARC-9 split of harness.api_surface_discovery. Import these names from
harness.api_surface_discovery, the facade, not from this module.

`_host_in_scope` is read as `_asd.<name>` at call time (a test patches it on the facade).
"""
from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import urlsplit

from harness.api_surface_data import Route, _header_value, _is_not_found


class _ProbeMixin:
    """Methods of SurfaceDiscovery moved verbatim; see harness.api_surface_discovery."""

    async def _probe(self, method: str, path: str):
        """One live request. A method seam so tests inject a canned responder and
        never touch the network. Returns (status, body, allow) or None on error.
        Throttled and scope-gated identically to the validator path."""
        url = self.base_url + path
        if not _asd._host_in_scope(url, self.allowed_hosts):
            return None
        if self.run_context is not None:
            from harness.run_context import TypedRequest
            request_headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
            outcome = await self.run_context.executor().execute(
                TypedRequest(method, url, headers=request_headers),
                capability="surface_discovery", session_ref=self.session_ref,
                **({} if self._follow_redirects else {"max_redirects": 0}))
            if not outcome.ok:
                return None
            if method == "GET":
                self._content_types[path] = _header_value(outcome.headers, "Content-Type")
                if outcome.final_url and outcome.final_url != url:
                    # The status and body are the redirect target's, not this path's.
                    self._redirected_to[path] = urlsplit(outcome.final_url).path or "/"
                    self._note_dir_redirect(path, outcome.final_url)
                elif 300 <= (outcome.status or 0) < 400:
                    self._note_dir_redirect(path, _header_value(outcome.headers, "Location"))
            return outcome.status or 0, outcome.body or "", _header_value(outcome.headers, "Allow")
        # ARC-7: no raw client. Without a run the probe sends through a standalone one
        # (transport_for): scope, budget and the connect-time pin apply, and an empty
        # scope admits no host.
        from harness import global_throttle
        from harness.run_context import transport_for
        await global_throttle.acquire()
        _tt, _owned = transport_for(None, allowed_hosts=list(self.allowed_hosts or []),
                                    active_mode=True, timeout=self.timeout)
        try:
            outcome = await _tt.send_creds(method, url, capability="surface_discovery",
                                           headers=self.headers or None, max_redirects=0)
        except Exception:
            return None
        finally:
            if _owned is not None:
                await _owned.aclose()
        if not outcome.ok:
            return None
        if method == "GET":
            self._content_types[path] = _header_value(outcome.headers, "Content-Type")
            if 300 <= (outcome.status or 0) < 400:
                self._note_dir_redirect(path, _header_value(outcome.headers, "Location"))
        return outcome.status or 0, outcome.body or "", _header_value(outcome.headers, "Allow")

    def _budget_left(self) -> bool:
        return self._probes < min(self.max_probes, self._phase_limit)

    async def _raw(self, method: str, path: str):
        """Budget-guarded, counted single probe -- every phase goes through this
        so max_probes bounds the whole run (spec + wordlist + allow + response),
        not just the wordlist. Returns None when the budget is spent."""
        if not self._budget_left():
            return None
        self._probes += 1
        return await self._probe(method, path)

    def _norm_body_hash(self, body: str, path: str) -> str:
        """A body fingerprint stable across the ECHOED PATH and numeric ids -- so
        two bogus paths that only differ by the path they echo hash the same, and
        a soft-404 is recognised whatever path it was probed with."""
        b = (body or "").replace(path, "PATH")
        b = re.sub(r"\d+", "N", b)
        return hashlib.sha1(b.encode("utf-8", "ignore")).hexdigest()[:16]

    async def _prefix_wildcard(self, method: str, path: str, status: int, body: str) -> bool:
        """Compare a candidate with two random siblings in its own namespace.

        Root-only calibration misses mounted catch-alls (e.g. /health/*). All
        controls consume the ordinary discovery and owning-run request budgets.
        Failed/inconsistent controls never establish a wildcard signature.
        """
        parent = path.split("?", 1)[0].rsplit("/", 1)[0] + "/"
        key = (method, parent)
        if parent == "/":
            return False  # already calibrated at discovery start
        if key not in self._prefix_controls:
            sigs = []
            for _ in range(2):
                bogus = parent + "__harness_missing_" + secrets.token_hex(12)
                control = await self._raw(method, bogus)
                if control is None:
                    return True  # insufficient budget: candidate existence remains unproven
                sigs.append((control[0], self._content_type(bogus),
                             self._norm_body_hash(control[1], bogus)))
            self._prefix_controls[key] = sigs[0] if sigs[0] == sigs[1] else None
        signature = self._prefix_controls[key]
        if signature is not None and (status, self._content_type(path),
                                      self._norm_body_hash(body, path)) == signature:
            self._wildcard_prefixes.add(parent)
            self._wildcard_suppressed += 1
            return True
        return False

    def _norm_body_len(self, body: str, path: str) -> int:
        # Digits are kept: collapsing digit runs would make a random hex nonce's
        # length vary with how its digits happen to cluster.
        return len((body or "").replace(path, "PATH"))

    def _content_type(self, path: str) -> str:
        return (self._content_types.get(path) or "").split(";", 1)[0].strip().lower()

    def _soft404_match(self, status: int, body: str, path: str) -> bool:
        """True when a response has the calibrated catch-all's shape: same status
        and content type, and the same normalized body -- or, when the two
        calibration controls differed only in content (a per-request nonce in an
        SPA shell), the same normalized length."""
        if self._soft404 is None:
            return False
        sig_status, sig_ctype, sig_hash, sig_len, hash_stable = self._soft404
        if status != sig_status or self._content_type(path) != sig_ctype:
            return False
        if self._norm_body_hash(body, path) == sig_hash:
            return True
        return not hash_stable and self._norm_body_len(body, path) == sig_len

    def _not_found(self, status: int, body: str, path: str) -> bool:
        """Existence oracle: a hard 404/framework marker, OR a match to the
        calibrated soft-404 signature (Phase 5 -- content/shape, not status)."""
        if _is_not_found(status, body):
            return True
        return self._soft404_match(status, body, path)

    @staticmethod
    def _ancestor_prefixes(path: str) -> list[str]:
        """'/a/b/c' -> ['/a/', '/a/b/']; a root leaf ('/login') has none, so the
        root namespace itself is never pruned."""
        segs = [s for s in path.split("?", 1)[0].split("/") if s]
        return ["/" + "/".join(segs[:i]) + "/" for i in range(1, len(segs))]

    def _note_soft404(self, path: str) -> None:
        for pre in self._ancestor_prefixes(path):
            n = self._soft404_counts.get(pre, 0) + 1
            self._soft404_counts[pre] = n
            if n >= self.soft404_prune_after and pre not in self._live_prefixes:
                self._soft404_dead.add(pre)

    def _note_live(self, path: str) -> None:
        for pre in self._ancestor_prefixes(path):
            self._live_prefixes.add(pre)
            self._soft404_dead.discard(pre)

    async def _calibrate_not_found(self) -> None:
        """Fingerprint the app's answer to KNOWN-BOGUS paths. A soft-404 signature
        is recorded ONLY if two independent random paths return the SAME non-404
        (status, normalized-body) -- otherwise responses genuinely vary and
        suppressing by shape would hide real routes. If the app returns honest
        404s (or a framework marker), nothing is recorded and behavior is
        unchanged."""
        sigs = []
        for _ in range(2):
            bogus = "/" + secrets.token_hex(12)
            r = await self._raw("GET", bogus)
            if r is None:
                return
            status, body, _allow = r
            if _is_not_found(status, body):
                continue  # honest not-found already handled by the oracle
            sigs.append((status, self._content_type(bogus), self._norm_body_hash(body, bogus),
                         self._norm_body_len(body, bogus), len(body.encode("utf-8"))))
        if len(sigs) != 2:
            return
        (s0, c0, h0, l0, b0), (s1, c1, h1, l1, b1) = sigs
        # Same status, content type and length: the catch-all. A differing hash
        # at the same length is a per-request nonce, so match on length there.
        if s0 == s1 and c0 == c1 and l0 == l1:
            self._soft404 = (s0, c0, h0, l0, h0 == h1)
            if b0 == b1:
                self._soft404_bytes = b0

    async def _check(self, path: str, source: str, method: str = "GET") -> Route | None:
        if path in self._seen:
            return self._seen[path]
        if (method, path) in self._attempted or not self._budget_left():
            return None
        # Stop guessed descendant expansion after a namespace proves wildcard.
        # App/capture references still get their own comparison, so a genuine
        # distinct endpoint in that namespace is not hidden by this pruning.
        referenced = source in {"seed", "body", "html"} or path in self.seed_paths
        if not referenced and any(path.startswith(p) for p in self._wildcard_prefixes):
            self._wildcard_suppressed += 1
            return None
        if not referenced and any(p in self._soft404_dead for p in self._ancestor_prefixes(path)):
            self._soft404_pruned += 1
            return None
        if not referenced and path in self._ffuf_covered:
            self._ffuf_covered_skips += 1
            return None
        self._attempted.add((method, path))
        r = await self._raw(method, path)
        if r is None:
            return None
        status, body, allow = r
        if _is_not_found(status, body):
            return None
        if self._soft404_match(status, body, path):
            self._soft404_matches += 1
            self._note_soft404(path)
            return None
        if await self._prefix_wildcard(method, path, status, body):
            return None
        methods = tuple(m.strip().upper() for m in allow.split(",") if m.strip()) or (method,)
        route = Route(path=path, status=status, methods=methods, length=len(body), source=source)
        self._seen[path] = route
        self._note_live(path)
        if 200 <= status < 300:
            self._bodies[path] = body
        return route


from harness import api_surface_discovery as _asd  # noqa: E402
