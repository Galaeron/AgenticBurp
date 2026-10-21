from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from harness import telemetry

log = logging.getLogger("harness.kev_check")

# WL-11: telemetry counter label for the one outbound call this module makes
# (the CISA feed download). Service name only; see telemetry.record_event.
_SERVICE = "cisa_kev"
EXTERNAL_LOOKUP_EVENT = f"external_lookup:{_SERVICE}"
# Status of a check NOT performed because privacy.external_lookups is false and
# there is no local_file to read instead. Not "not_listed": nothing was checked.
STATUS_SKIPPED_EXTERNAL_DISABLED = "skipped_external_lookups_disabled"

# Answers Horizon3.ai's third framing question from this project's own
# comparison notes: "are attackers actively using this." A GitHub
# Advisory match tells you a vulnerability is disclosed; a CISA KEV
# match tells you it's not theoretical -- CISA only adds a CVE to this
# catalog with evidence of active, in-the-wild exploitation. That's a
# meaningfully different, higher-urgency signal than "an advisory
# exists", so it's applied as a severity escalation on top of an
# existing github_advisories.py match, not a new standalone finding.
#
# HONESTY NOTE, more specific than usual: this integration could NOT be
# verified live in this build environment, for two independent,
# confirmed reasons (not just "didn't get around to it"):
#   1. Fetching the real feed URL was blocked by cisa.gov's bot
#      detection when tried directly.
#   2. cisa.gov is not in this sandbox's outbound network allowlist, so
#      the httpx path below has never actually executed here either.
# The JSON schema this module parses ("vulnerabilities" list, each with
# "cveID", "vendorProject", "product", "dateAdded",
# "knownRansomwareCampaignUse") is well-documented and has been stable
# for years -- but that's still *recalled*, not *derived*, until it's
# actually been fetched successfully from somewhere. The local-file
# fallback exists partly for exactly this scenario: an operator whose
# own network also can't reach cisa.gov directly can point this at a
# manually downloaded copy instead.

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevResult:
    cve_id: str
    # "listed" | "not_listed" | "error" | "skipped_external_lookups_disabled"
    status: str
    date_added: str | None = None
    known_ransomware_use: str | None = None
    detail: str = ""


class KevClient:
    def __init__(self, local_file: str | None = None, cache_ttl_hours: float = 24.0,
                 timeout_seconds: float = 15.0, external_lookups: bool = True):
        self.local_file = Path(local_file) if local_file else None
        # WL-11 (privacy.external_lookups): when not exactly True the CISA feed
        # is never fetched (`is True` so a stray truthy string fails closed). A
        # configured local_file still works -- reading it is not egress.
        self.external_lookups = external_lookups is True
        self.cache_ttl_hours = cache_ttl_hours
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, dict] | None = None  # cve_id -> entry
        self._cache_loaded_at: float = 0.0

    async def _ensure_loaded(self) -> str | None:
        """Returns an error string if loading failed, None on success."""
        if self._cache is not None and (time.time() - self._cache_loaded_at) < self.cache_ttl_hours * 3600:
            return None

        raw: dict | None = None
        if self.local_file is not None:
            if not self.local_file.exists():
                return f"configured local KEV file does not exist: {self.local_file}"
            try:
                raw = json.loads(self.local_file.read_text())
            except (json.JSONDecodeError, OSError) as e:
                return f"could not read/parse local KEV file: {e}"
        else:
            # Second, independent gate at the only network site (check() gates
            # first; this keeps a direct _ensure_loaded() caller from egressing).
            if not self.external_lookups:
                return "privacy.external_lookups is false and no local KEV file is configured"
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    telemetry.record_event(EXTERNAL_LOOKUP_EVENT)
                    resp = await client.get(_KEV_URL)
                if resp.status_code != 200:
                    return (f"CISA KEV feed returned HTTP {resp.status_code} "
                            f"(this live path is unverified in this build's dev environment -- see module docstring)")
                raw = resp.json()
            except httpx.RequestError as e:
                return f"network error reaching CISA KEV feed: {e}"
            except json.JSONDecodeError as e:
                return f"CISA KEV feed did not return valid JSON: {e}"

        try:
            if "vulnerabilities" not in raw:
                return "CISA KEV feed response had no 'vulnerabilities' key -- schema may have " \
                       "changed, or this isn't actually the KEV feed. Refusing to treat this as " \
                       "an empty-but-valid catalog."
            vulns = raw["vulnerabilities"]
            self._cache = {v["cveID"]: v for v in vulns if "cveID" in v}
            self._cache_loaded_at = time.time()
            return None
        except (AttributeError, TypeError, KeyError) as e:
            return f"CISA KEV feed had an unexpected shape (schema may have changed): {e}"

    async def check(self, cve_id: str | None) -> KevResult:
        if not cve_id:
            return KevResult(cve_id="", status="error", detail="no CVE ID provided")

        # Privacy gate (WL-11): with lookups off and no local feed file there is
        # nothing to check against -- say so instead of reporting "not_listed".
        if not self.external_lookups and self.local_file is None:
            return KevResult(
                cve_id=cve_id, status=STATUS_SKIPPED_EXTERNAL_DISABLED,
                detail="privacy.external_lookups is false; no KEV check was performed")

        error = await self._ensure_loaded()
        if error is not None:
            return KevResult(cve_id=cve_id, status="error", detail=error)

        entry = self._cache.get(cve_id) if self._cache else None
        if entry is None:
            return KevResult(cve_id=cve_id, status="not_listed")

        return KevResult(
            cve_id=cve_id,
            status="listed",
            date_added=entry.get("dateAdded"),
            known_ransomware_use=entry.get("knownRansomwareCampaignUse"),
        )
