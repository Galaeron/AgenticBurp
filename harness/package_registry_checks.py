from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import quote
from datetime import datetime, timezone

import httpx

from harness.models import ComponentCandidate

log = logging.getLogger("harness.package_registry_checks")

# This module integrates Aikido's Safe Chain intelligence feeds
# (https://intel.aikido.dev/ via https://malware-list.aikido.dev/)
# for real-time supply chain threat detection.
#
# It combines:
# 1. Direct npm/PyPI registry queries for package age (Safe Chain concept)
# 2. Aikido Intel malware/vulnerability feeds for known malicious packages
#
# The malware intelligence feeds provide:
# - malware_predictions.json: Cross-ecosystem malicious package detection
# - malware_pypi.json: Python-specific malicious package detection
#
# This is a FIRST-CLASS, separate step from LLM reasoning -- deterministic
# advisory-DB matching that runs AFTER agent extraction and BEFORE
# any rediscovery or critique passes.

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_REGISTRY = "https://pypi.org/pypi"

_NPM_LIKE_ECOSYSTEMS = {"npm", "javascript", "node"}
_PYPI_LIKE_ECOSYSTEMS = {"pypi", "python", "pip"}

# Aikido Intel malware feeds
_AIKIDO_MALWARE_FEED = "https://malware-list.aikido.dev/malware_predictions.json"
_AIKIDO_PYPI_FEED = "https://malware-list.aikido.dev/malware_pypi.json"

# Cache for malware feeds (loaded once per session)
_malware_feed_cache: dict[str, list] = {}
_malware_feed_last_load: datetime | None = None
_MALWARE_FEED_CACHE_TTL = 3600  # 1 hour


@dataclass
class RegistryAgeResult:
    component: ComponentCandidate
    status: str  # "checked" | "not_found" | "unsupported_ecosystem" | "error"
    published_at: datetime | None = None
    age_days: float | None = None
    detail: str = ""


@dataclass
class MalwareCheckResult:
    component: ComponentCandidate
    status: str  # "checked" | "malware_detected" | "error"
    is_malicious: bool = False
    reason: str = ""
    aikido_id: str | None = None
    detail: str = ""


class PackageRegistryClient:
    def __init__(self, timeout_seconds: float = 15.0, minimum_age_days: float = 2.0):
        self.timeout_seconds = timeout_seconds
        # Safe Chain's default is 48 hours; matched here as the default,
        # configurable the same way github_advisories' behavior is.
        self.minimum_age_days = minimum_age_days

    async def _load_malware_feeds(self) -> None:
        """Load Aikido malware intelligence feeds into cache."""
        global _malware_feed_cache, _malware_feed_last_load
        
        now = datetime.now(timezone.utc)
        if _malware_feed_cache and _malware_feed_last_load:
            if (now - _malware_feed_last_load).total_seconds() < _MALWARE_FEED_CACHE_TTL:
                return
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                # Load cross-ecosystem malware predictions
                resp = await client.get(_AIKIDO_MALWARE_FEED)
                if resp.status_code == 200:
                    _malware_feed_cache['cross_ecosystem'] = resp.json()
                    log.info(f"Loaded {len(_malware_feed_cache['cross_ecosystem'])} malware predictions from Aikido")
                else:
                    log.warning(f"Failed to load Aikido malware feed: {resp.status_code}")
                    _malware_feed_cache['cross_ecosystem'] = []
                
                # Load PyPI-specific malware predictions
                resp = await client.get(_AIKIDO_PYPI_FEED)
                if resp.status_code == 200:
                    _malware_feed_cache['pypi'] = resp.json()
                    log.info(f"Loaded {len(_malware_feed_cache['pypi'])} PyPI malware predictions from Aikido")
                else:
                    log.warning(f"Failed to load Aikido PyPI feed: {resp.status_code}")
                    _malware_feed_cache['pypi'] = []
        except Exception as e:
            log.error(f"Error loading Aikido malware feeds: {e}")
            _malware_feed_cache = {'cross_ecosystem': [], 'pypi': []}
        
        _malware_feed_last_load = now

    async def check_malware(self, component: ComponentCandidate) -> MalwareCheckResult:
        """
        Check if a component is known to be malicious via Aikido Intel feeds.
        
        This is a deterministic, authoritative lookup against Aikido's
        real-time supply chain intelligence.
        """
        if not component.name:
            return MalwareCheckResult(
                component=component,
                status="error",
                detail="no package name"
            )
        
        # Load feeds if not cached
        if not _malware_feed_cache:
            await self._load_malware_feeds()
        
        name = component.name.strip().lower()
        version = (component.version or "").strip().lower()
        ecosystem = component.ecosystem.strip().lower()
        
        # Check cross-ecosystem feed first
        for entry in _malware_feed_cache.get('cross_ecosystem', []):
            entry_name = entry.get('package_name', '').strip().lower()
            entry_version = entry.get('version', '').strip().lower()
            entry_reason = entry.get('reason', '')
            
            # Match by exact name and version
            if entry_name == name and entry_version == version:
                return MalwareCheckResult(
                    component=component,
                    status="malware_detected",
                    is_malicious=True,
                    reason=entry_reason,
                    aikido_id=entry.get('id') or entry.get('aikido_id'),
                    detail=f"Package {name}@{version} flagged as {entry_reason} by Aikido Intel"
                )
            
            # Match by name only (any version is malicious)
            if entry_name == name and not version:
                return MalwareCheckResult(
                    component=component,
                    status="malware_detected",
                    is_malicious=True,
                    reason=entry_reason,
                    aikido_id=entry.get('id') or entry.get('aikido_id'),
                    detail=f"Package {name} flagged as {entry_reason} by Aikido Intel (any version)"
                )
        
        # Check PyPI-specific feed
        if ecosystem in _PYPI_LIKE_ECOSYSTEMS:
            for entry in _malware_feed_cache.get('pypi', []):
                entry_name = entry.get('package_name', '').strip().lower()
                entry_version = entry.get('version', '').strip().lower()
                entry_reason = entry.get('reason', '')
                
                if entry_name == name and entry_version == version:
                    return MalwareCheckResult(
                        component=component,
                        status="malware_detected",
                        is_malicious=True,
                        reason=entry_reason,
                        aikido_id=entry.get('id') or entry.get('aikido_id'),
                        detail=f"PyPI package {name}@{version} flagged as {entry_reason} by Aikido Intel"
                    )
                
                if entry_name == name and not version:
                    return MalwareCheckResult(
                        component=component,
                        status="malware_detected",
                        is_malicious=True,
                        reason=entry_reason,
                        aikido_id=entry.get('id') or entry.get('aikido_id'),
                        detail=f"PyPI package {name} flagged as {entry_reason} by Aikido Intel (any version)"
                    )
        
        return MalwareCheckResult(
            component=component,
            status="checked",
            is_malicious=False,
            detail="No malware detected by Aikido Intel"
        )

    async def check(self, component: ComponentCandidate) -> RegistryAgeResult:
        """
        Check package registry age (Safe Chain concept).
        
        This implements the "minimum package age" signal from Safe Chain:
        a component published to its registry only hours or days ago is
        exactly the shape of a supply-chain-attack package.
        """
        eco = component.ecosystem.lower().strip()
        if not component.name:
            return RegistryAgeResult(component=component, status="error", detail="no package name")

        if eco in _NPM_LIKE_ECOSYSTEMS:
            return await self._check_npm(component)
        if eco in _PYPI_LIKE_ECOSYSTEMS:
            return await self._check_pypi(component)
        return RegistryAgeResult(component=component, status="unsupported_ecosystem",
                                   detail=f"registry-age check only covers npm/PyPI, got '{component.ecosystem}'")

    async def _check_npm(self, component: ComponentCandidate) -> RegistryAgeResult:
        url = f"{_NPM_REGISTRY}/{quote(component.name, safe='')}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = None
            for attempt in range(3):
                try:
                    resp = await client.get(url)
                except httpx.RequestError as e:
                    if attempt == 2:
                        return RegistryAgeResult(component=component, status="error", detail=f"network error: {e}")
                    await asyncio.sleep(0.25 * (2 ** attempt))
                    continue
                if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                await asyncio.sleep(0.25 * (2 ** attempt))
        if resp is None:
            return RegistryAgeResult(component=component, status="error", detail="registry request failed")

        if resp.status_code == 404:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail="package not found on npm registry")
        if resp.status_code != 200:
            return RegistryAgeResult(component=component, status="error",
                                       detail=f"npm registry returned HTTP {resp.status_code}")

        data = resp.json()
        version = component.version or data.get("dist-tags", {}).get("latest")
        time_str = data.get("time", {}).get(version) if version else None
        if not time_str:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail=f"version {version!r} not found in npm registry's time data")

        published = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
        return RegistryAgeResult(component=component, status="checked",
                                   published_at=published, age_days=age_days)

    async def _check_pypi(self, component: ComponentCandidate) -> RegistryAgeResult:
        url = f"{_PYPI_REGISTRY}/{quote(component.name, safe='')}/json"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = None
            for attempt in range(3):
                try:
                    resp = await client.get(url)
                except httpx.RequestError as e:
                    if attempt == 2:
                        return RegistryAgeResult(component=component, status="error", detail=f"network error: {e}")
                    await asyncio.sleep(0.25 * (2 ** attempt))
                    continue
                if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                await asyncio.sleep(0.25 * (2 ** attempt))
        if resp is None:
            return RegistryAgeResult(component=component, status="error", detail="registry request failed")

        if resp.status_code == 404:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail="package not found on PyPI")
        if resp.status_code != 200:
            return RegistryAgeResult(component=component, status="error",
                                       detail=f"PyPI returned HTTP {resp.status_code}")

        data = resp.json()
        version = component.version or data.get("info", {}).get("version")
        files = data.get("releases", {}).get(version, []) if version else []
        if not files:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail=f"version {version!r} not found in PyPI release data")

        upload_time = files[0].get("upload_time_iso_8601")
        if not upload_time:
            return RegistryAgeResult(component=component, status="error", detail="no upload timestamp in PyPI response")

        published = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
        return RegistryAgeResult(component=component, status="checked",
                                   published_at=published, age_days=age_days)
