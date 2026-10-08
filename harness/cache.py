"""
Exchange-level caching for the LLM harness.

This module provides intelligent caching of analysis results to avoid
re-processing identical HTTP exchanges. This is particularly valuable for:
- Repeated spidering of the same endpoints
- Re-analysis during active testing
- Batch operations where the same exchange appears multiple times

Design principles:
1. Cache key is based on exchange content hash, not URL alone
2. TTL-based expiration (configurable, default 24 hours)
3. Automatic invalidation when dependencies change (model, prompts)
4. Metrics for cache hit/miss rates
5. Optional bypass for testing/debugging

Token savings: eliminates repeat LLM calls for exchanges whose cache key
(see is_stale / the manifest) is unchanged -- the magnitude depends entirely on
how much a given workflow re-hits identical endpoints and is not a fixed figure
(no maintained benchmark backs a specific percentage -- review weakness #19).
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path
from contextlib import contextmanager

import sqlite3
from threading import Lock

from harness.models import HttpExchange, AnalysisResponse, AgentReport, StageOutcome

log = logging.getLogger("harness.cache")


@dataclass
class CacheStats:
    """Statistics for cache performance monitoring."""
    hits: int = 0
    misses: int = 0
    bypasses: int = 0
    evictions: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a percentage (0.0-100.0)."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return (self.hits / total) * 100.0
    
    @property
    def total_requests(self) -> int:
        """Total cache lookups (hits + misses + bypasses)."""
        return self.hits + self.misses + self.bypasses
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "bypasses": self.bypasses,
            "evictions": self.evictions,
            "hit_rate_percent": round(self.hit_rate, 2),
            "total_requests": self.total_requests,
        }


@dataclass
class CacheEntry:
    """A cached analysis result."""
    exchange_hash: str
    response: AnalysisResponse
    created_at: float
    ttl_seconds: float
    model: str
    prompt_versions: dict[str, str]  # agent_name -> prompt_version
    
    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        return time.time() > (self.created_at + self.ttl_seconds)
    
    def is_stale(self, current_model: str, current_prompts: dict[str, str]) -> bool:
        """Check if this entry is stale due to model or prompt changes."""
        if self.model != current_model:
            return True
        for agent, version in current_prompts.items():
            if agent in self.prompt_versions and self.prompt_versions[agent] != version:
                return True
        return False


@dataclass
class HypothesisCacheEntry:
    """FR-7 (F11): a run-INDEPENDENT cache entry for the *pre-proof* half of an
    analysis -- the model-inference-derived `reports` (list[AgentReport]) plus
    exactly the tail metadata Orchestrator.analyze() needs to finish the run
    (dispatch/reason/stage_outcomes/findings_reviewed/findings_rejected).

    This is deliberately NOT an AnalysisResponse and never carries one. It is
    captured at the point in analyze() BEFORE `_validate_findings` runs --
    i.e. before any Finding on these reports has a proof_id, case_id, or any
    oracle_* field (those are always "" / False / "candidate" at capture
    time, see models.Finding's defaults) -- so there is structurally nothing
    run-bound in here to leak across runs. put_hypothesis() additionally
    refuses at runtime to store any report whose findings already carry one
    of those fields, as a second, defensive guarantee.

    Keyed WITHOUT the run's cache_namespace (see ExchangeCache.get/put above,
    which use namespace=run_context.cache_namespace): this cache is meant to
    be hit across DIFFERENT runs on identical traffic, which the namespaced
    full-response cache (by design) can never do.
    """
    exchange_hash: str
    reports: list[AgentReport]
    dispatch: list[str]
    reason: str
    stage_outcomes: list[StageOutcome]
    findings_reviewed: int
    findings_rejected: int
    created_at: float
    ttl_seconds: float
    model: str
    prompt_versions: dict[str, str]
    config_fingerprint: str

    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        return time.time() > (self.created_at + self.ttl_seconds)

    def is_stale(
        self,
        current_model: str,
        current_prompts: dict[str, str],
        current_config_fingerprint: str,
    ) -> bool:
        """Mirrors CacheEntry.is_stale's model/prompt keying (same semantics:
        a prompt only invalidates if THIS entry actually recorded a version
        for that agent), plus a config_fingerprint check -- a config change
        can change what pre-proof `reports` a given exchange should produce
        (which agents run, which validators/detectors are active, etc.), so
        it must invalidate a hypothesis-cache entry too, not just a model or
        prompt-version change."""
        if self.model != current_model:
            return True
        if self.config_fingerprint != current_config_fingerprint:
            return True
        for agent, version in current_prompts.items():
            if agent in self.prompt_versions and self.prompt_versions[agent] != version:
                return True
        return False


class ExchangeCache:
    """
    SQLite-backed cache for analysis results.
    
    Features:
    - Content-based hashing of HTTP exchanges
    - Configurable TTL (default: 24 hours)
    - Automatic invalidation on model/prompt changes
    - Thread-safe operations
    - Cache statistics tracking
    - Optional bypass for testing
    
    The cache key is a hash of:
    - URL
    - Method
    - Request headers (redacted)
    - Request body
    - Response status
    - Response headers (redacted)
    - Response body
    
    This ensures that even minor changes to the exchange result in
    a new cache entry, while identical exchanges are cached.
    """
    
    _DB_PATH: Path
    _TTL_SECONDS: float
    _MAX_SIZE: int  # Maximum number of entries to keep
    _stats: CacheStats
    _lock: Lock
    _enabled: bool
    _bypass_token: Optional[str]
    
    def __init__(
        self,
        db_path: Path | str | None = None,
        ttl_seconds: float = 86400.0,  # 24 hours
        max_size: int = 10000,
        enabled: bool = True,
        bypass_token: Optional[str] = None,
    ):
        """
        Initialize the exchange cache.
        
        Args:
            db_path: Path to SQLite database file. Defaults to harness_cache.db
                     in the same directory as this module.
            ttl_seconds: Time-to-live for cache entries in seconds.
            max_size: Maximum number of entries to keep in the cache.
            enabled: Whether caching is enabled.
            bypass_token: If provided, requests with this header will bypass cache.
        """
        if db_path is None:
            db_path = Path(__file__).parent / "harness_cache.db"
        self._DB_PATH = Path(db_path)
        self._TTL_SECONDS = ttl_seconds
        self._MAX_SIZE = max_size
        self._stats = CacheStats()
        # FR-7: separate stats for the run-independent hypothesis cache
        # (get_hypothesis/put_hypothesis below) -- kept apart from the
        # full-response cache's own hits/misses/bypasses/evictions above so
        # a caller can tell "did the run-namespaced cache hit" from "did the
        # cross-run hypothesis cache hit" -- e.g. for hit-rate measurement.
        self._hyp_stats = CacheStats()
        self._lock = Lock()
        self._enabled = enabled
        self._bypass_token = bypass_token

        # Ensure database exists
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the SQLite database and tables."""
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    exchange_hash TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl_seconds REAL NOT NULL,
                    model TEXT NOT NULL,
                    prompt_versions_json TEXT NOT NULL DEFAULT '{}',
                    access_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_created ON cache_entries(created_at)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                )
            """)
            # Initialize stats if not present
            for field in ['hits', 'misses', 'bypasses', 'evictions']:
                conn.execute(
                    "INSERT OR IGNORE INTO cache_stats (key, value) VALUES (?, 0)",
                    (field,)
                )
            # FR-7: sibling table for the run-independent hypothesis cache.
            # Separate from cache_entries above -- never stores a
            # response_json / AnalysisResponse, only the pre-proof payload
            # (see HypothesisCacheEntry / put_hypothesis). Keyed by
            # exchange_hash computed WITHOUT a run namespace (namespace="").
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hypothesis_cache_entries (
                    exchange_hash TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl_seconds REAL NOT NULL,
                    model TEXT NOT NULL,
                    prompt_versions_json TEXT NOT NULL DEFAULT '{}',
                    config_fingerprint TEXT NOT NULL DEFAULT '',
                    access_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hypothesis_cache_created
                ON hypothesis_cache_entries(created_at)
            """)
            conn.commit()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with proper settings."""
        conn = sqlite3.connect(
            str(self._DB_PATH),
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode
        )
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        """Own one connection while preserving SQLite commit/rollback semantics."""
        conn = self._get_connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()
    
    # Headers that are pure transport/tracing noise: they change on every
    # single request/response regardless of whether the exchange is
    # analytically "the same" (same endpoint, same identity, same
    # behavior), and none of them carry authorization, session identity,
    # or content that any agent's finding would depend on. Deliberately
    # NOT included here: Cookie, Authorization, Set-Cookie, or any
    # CSRF-token-shaped header/value -- those can be identity-bearing
    # (this harness's IDOR/access-control detection depends on being able
    # to tell "same request, different user" apart) or were left as an
    # explicit, separate judgment call. See cache.py's module docstring
    # and CACHE_HASH_VOLATILITY.md for the reasoning and what was
    # deliberately left out.
    _VOLATILE_HEADER_NAMES = frozenset({
        "date", "age", "etag", "x-request-id",
        "x-correlation-id", "traceparent", "tracestate", "cf-ray",
        "server-timing", "via", "x-amzn-trace-id", "x-runtime",
        "x-response-time",
    })

    @classmethod
    def _strip_volatile_headers(cls, headers: dict[str, str]) -> list[tuple[str, str]]:
        """Drop pure transport/tracing headers before hashing, sorted for
        consistency. See _VOLATILE_HEADER_NAMES for what's excluded and why."""
        return sorted(
            (k, v) for k, v in headers.items()
            if k.lower() not in cls._VOLATILE_HEADER_NAMES
        )

    @classmethod
    def compute_exchange_hash(cls, exchange: HttpExchange, namespace: str = "") -> str:
        """
        Compute a content-based hash for an HTTP exchange.
        
        The hash includes all relevant parts of the exchange that would
        affect the analysis result. Headers are sorted for consistency,
        and a small set of pure transport/tracing headers (Date, ETag,
        X-Request-Id, traceparent, etc.) are excluded entirely -- they
        churn on every request regardless of whether the exchange is
        analytically identical, and defeated this cache almost entirely
        for real traffic before this fix (see CACHE_HASH_VOLATILITY.md).
        """
        # Sort headers for consistent hashing, dropping pure-noise ones
        req_headers = cls._strip_volatile_headers(exchange.request_headers)
        resp_headers = cls._strip_volatile_headers(exchange.response_headers)
        
        # Create a hashable representation
        hashable = {
            "namespace": namespace,
            "url": exchange.url,
            "method": exchange.method,
            "request_headers": req_headers,
            "request_body": exchange.request_body,
            "response_status": exchange.response_status,
            "response_headers": resp_headers,
            "response_body": exchange.response_body,
            "analyst_note": exchange.analyst_note,
        }
        
        # Convert to JSON string for hashing
        hash_str = json.dumps(hashable, sort_keys=True, default=str)
        return hashlib.sha256(hash_str.encode()).hexdigest()
    
    def get(
        self,
        exchange: HttpExchange,
        current_model: str,
        current_prompt_versions: dict[str, str],
        bypass: bool = False,
        namespace: str = "",
    ) -> Optional[AnalysisResponse]:
        """
        Get a cached analysis result for the given exchange.
        
        Args:
            exchange: The HTTP exchange to look up.
            current_model: The current model being used.
            current_prompt_versions: Current prompt versions for all agents.
            bypass: If True, bypass the cache (for testing).
        
        Returns:
            The cached AnalysisResponse if found and valid, None otherwise.
        """
        if not self._enabled or bypass:
            with self._lock:
                self._stats.bypasses += 1
                self._save_stats_to_db()
            return None
        
        exchange_hash = self.compute_exchange_hash(exchange, namespace)
        
        with self._lock:
            try:
                with self._connection() as conn:
                    row = conn.execute(
                        "SELECT * FROM cache_entries WHERE exchange_hash = ?",
                        (exchange_hash,)
                    ).fetchone()
                    
                    if row is None:
                        self._stats.misses += 1
                        self._save_stats_to_db()
                        return None
                    
                    # Deserialize the entry
                    entry = CacheEntry(
                        exchange_hash=row["exchange_hash"],
                        response=AnalysisResponse.model_validate_json(row["response_json"]),
                        created_at=row["created_at"],
                        ttl_seconds=row["ttl_seconds"],
                        model=row["model"],
                        prompt_versions=json.loads(row["prompt_versions_json"]),
                    )
                    
                    # Check expiration
                    if entry.is_expired():
                        conn.execute(
                            "DELETE FROM cache_entries WHERE exchange_hash = ?",
                            (exchange_hash,)
                        )
                        self._stats.misses += 1
                        self._stats.evictions += 1
                        self._save_stats_to_db()
                        return None
                    
                    # Check staleness (model or prompt changed)
                    if entry.is_stale(current_model, current_prompt_versions):
                        conn.execute(
                            "DELETE FROM cache_entries WHERE exchange_hash = ?",
                            (exchange_hash,)
                        )
                        self._stats.misses += 1
                        self._stats.evictions += 1
                        self._save_stats_to_db()
                        return None
                    
                    # Valid cache hit
                    self._stats.hits += 1
                    conn.execute(
                        "UPDATE cache_entries SET access_count = access_count + 1 WHERE exchange_hash = ?",
                        (exchange_hash,)
                    )
                    self._save_stats_to_db()
                    
                    log.debug(f"Cache hit for exchange {exchange_hash[:16]}...")
                    return entry.response
                    
            except Exception as e:
                log.warning(f"Cache lookup failed: {e}")
                self._stats.misses += 1
                self._save_stats_to_db()
                return None
    
    def put(
        self,
        exchange: HttpExchange,
        response: AnalysisResponse,
        model: str,
        prompt_versions: dict[str, str],
        namespace: str = "",
    ) -> None:
        """
        Store an analysis result in the cache.
        
        Args:
            exchange: The HTTP exchange that was analyzed.
            response: The analysis result to cache.
            model: The model used for analysis.
            prompt_versions: Prompt versions for all agents used.
        """
        if not self._enabled:
            return
        
        exchange_hash = self.compute_exchange_hash(exchange, namespace)
        
        with self._lock:
            try:
                with self._connection() as conn:
                    # Evict old entries if at capacity
                    self._evict_if_needed(conn)
                    
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO cache_entries 
                        (exchange_hash, response_json, created_at, ttl_seconds, model, prompt_versions_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            exchange_hash,
                            response.model_dump_json(),
                            time.time(),
                            self._TTL_SECONDS,
                            model,
                            json.dumps(prompt_versions),
                        )
                    )
                    log.debug(f"Cached result for exchange {exchange_hash[:16]}...")
                    
            except Exception as e:
                log.warning(f"Cache store failed: {e}")

    # ------------------------------------------------------------------
    # FR-7 (F11): run-independent hypothesis cache.
    #
    # Sibling of get()/put() above, but keyed WITHOUT a run namespace and
    # storing only the pre-proof half of an analysis (reports/dispatch/
    # reason/stage_outcomes/findings_reviewed/findings_rejected) instead of
    # a full AnalysisResponse. This is what lets two DIFFERENT runs (each
    # with their own cache_namespace) reuse the same model inference for
    # identical traffic, while proof/case/oracle identifiers are always
    # freshly minted per run by the caller's own tail (_validate_findings) --
    # never stored or replayed from here. See HypothesisCacheEntry's
    # docstring for the structural guarantee.
    # ------------------------------------------------------------------

    def get_hypothesis(
        self,
        exchange: HttpExchange,
        current_model: str,
        current_prompt_versions: dict[str, str],
        config_fingerprint: str,
        bypass: bool = False,
        namespace: str = "",
    ) -> Optional["HypothesisCacheEntry"]:
        """Look up a hypothesis-cache entry for this exchange. Returns None on
        a miss/expiry/staleness, exactly like get() above, but the returned
        entry (when present) carries `reports`/`dispatch`/`reason`/
        `stage_outcomes`/`findings_reviewed`/`findings_rejected` only --
        never an AnalysisResponse, never a proof/case/oracle field."""
        if not self._enabled or bypass:
            with self._lock:
                self._hyp_stats.bypasses += 1
            return None

        exchange_hash = self.compute_exchange_hash(exchange, namespace=namespace)

        with self._lock:
            try:
                with self._connection() as conn:
                    row = conn.execute(
                        "SELECT * FROM hypothesis_cache_entries WHERE exchange_hash = ?",
                        (exchange_hash,)
                    ).fetchone()

                    if row is None:
                        self._hyp_stats.misses += 1
                        return None

                    payload = json.loads(row["payload_json"])
                    entry = HypothesisCacheEntry(
                        exchange_hash=row["exchange_hash"],
                        reports=[AgentReport.model_validate(r) for r in payload["reports"]],
                        dispatch=list(payload["dispatch"]),
                        reason=payload["reason"],
                        stage_outcomes=[StageOutcome.model_validate(o) for o in payload["stage_outcomes"]],
                        findings_reviewed=payload["findings_reviewed"],
                        findings_rejected=payload["findings_rejected"],
                        created_at=row["created_at"],
                        ttl_seconds=row["ttl_seconds"],
                        model=row["model"],
                        prompt_versions=json.loads(row["prompt_versions_json"]),
                        config_fingerprint=row["config_fingerprint"],
                    )

                    if entry.is_expired():
                        conn.execute(
                            "DELETE FROM hypothesis_cache_entries WHERE exchange_hash = ?",
                            (exchange_hash,)
                        )
                        self._hyp_stats.misses += 1
                        self._hyp_stats.evictions += 1
                        return None

                    if entry.is_stale(current_model, current_prompt_versions, config_fingerprint):
                        conn.execute(
                            "DELETE FROM hypothesis_cache_entries WHERE exchange_hash = ?",
                            (exchange_hash,)
                        )
                        self._hyp_stats.misses += 1
                        self._hyp_stats.evictions += 1
                        return None

                    self._hyp_stats.hits += 1
                    conn.execute(
                        "UPDATE hypothesis_cache_entries SET access_count = access_count + 1 "
                        "WHERE exchange_hash = ?",
                        (exchange_hash,)
                    )
                    log.debug(f"Hypothesis cache hit for exchange {exchange_hash[:16]}...")
                    return entry

            except Exception as e:
                log.warning(f"Hypothesis cache lookup failed: {e}")
                self._hyp_stats.misses += 1
                return None

    def put_hypothesis(
        self,
        exchange: HttpExchange,
        *,
        dispatch: list[str],
        reason: str,
        reports: list[AgentReport],
        stage_outcomes: list[StageOutcome],
        findings_reviewed: int,
        findings_rejected: int,
        model: str,
        prompt_versions: dict[str, str],
        config_fingerprint: str,
        namespace: str = "",
    ) -> None:
        """Store the pre-proof, run-independent half of an analysis.

        `reports` MUST be captured before the caller's _validate_findings
        runs (before any proof/case/oracle field is minted) -- as a second,
        defensive guarantee (belt-and-suspenders on top of the caller-side
        structural guarantee), this refuses to persist anything if any
        finding already carries a non-empty proof_id/case_id or a set
        oracle_* field, rather than risk caching a run-bound value.
        """
        if not self._enabled:
            return

        for r in reports:
            for f in r.findings:
                if (f.proof_id or f.case_id or f.oracle_verified
                        or f.oracle_capsule_id or f.oracle_reason):
                    log.warning(
                        "Refusing hypothesis-cache put: a Finding already carries a "
                        "run-bound proof/oracle field -- these must never be cached."
                    )
                    return

        exchange_hash = self.compute_exchange_hash(exchange, namespace=namespace)
        payload = {
            "reports": [r.model_dump() for r in reports],
            "dispatch": list(dispatch),
            "reason": reason,
            "stage_outcomes": [o.model_dump() for o in stage_outcomes],
            "findings_reviewed": findings_reviewed,
            "findings_rejected": findings_rejected,
        }

        with self._lock:
            try:
                with self._connection() as conn:
                    self._evict_hypothesis_if_needed(conn)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO hypothesis_cache_entries
                        (exchange_hash, payload_json, created_at, ttl_seconds, model,
                         prompt_versions_json, config_fingerprint)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            exchange_hash,
                            json.dumps(payload),
                            time.time(),
                            self._TTL_SECONDS,
                            model,
                            json.dumps(prompt_versions),
                            config_fingerprint,
                        )
                    )
                    log.debug(f"Cached hypothesis for exchange {exchange_hash[:16]}...")

            except Exception as e:
                log.warning(f"Hypothesis cache store failed: {e}")

    def _evict_hypothesis_if_needed(self, conn: sqlite3.Connection) -> None:
        """Evict old hypothesis-cache entries if at capacity (mirrors
        _evict_if_needed for the full-response cache below)."""
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM hypothesis_cache_entries"
        ).fetchone()["cnt"]
        if count >= self._MAX_SIZE:
            delete_count = max(1, self._MAX_SIZE // 10)
            conn.execute(
                """
                DELETE FROM hypothesis_cache_entries
                WHERE exchange_hash IN (
                    SELECT exchange_hash FROM hypothesis_cache_entries
                    ORDER BY created_at ASC
                    LIMIT ?
                )
                """,
                (delete_count,)
            )
            self._hyp_stats.evictions += delete_count
            log.info(f"Evicted {delete_count} old hypothesis-cache entries")

    def hypothesis_stats(self) -> CacheStats:
        """Current hypothesis-cache statistics (separate from stats() above,
        which reports the full-response cache's own counters)."""
        with self._lock:
            return CacheStats(
                hits=self._hyp_stats.hits,
                misses=self._hyp_stats.misses,
                bypasses=self._hyp_stats.bypasses,
                evictions=self._hyp_stats.evictions,
            )

    def _evict_if_needed(self, conn: sqlite3.Connection) -> None:
        """Evict old entries if the cache is at capacity."""
        count = conn.execute("SELECT COUNT(*) as cnt FROM cache_entries").fetchone()["cnt"]
        if count >= self._MAX_SIZE:
            # Delete oldest 10% of entries
            delete_count = max(1, self._MAX_SIZE // 10)
            conn.execute(
                """
                DELETE FROM cache_entries 
                WHERE exchange_hash IN (
                    SELECT exchange_hash FROM cache_entries 
                    ORDER BY created_at ASC 
                    LIMIT ?
                )
                """,
                (delete_count,)
            )
            self._stats.evictions += delete_count
            self._save_stats_to_db()
            log.info(f"Evicted {delete_count} old cache entries")
    
    def _load_stats(self, conn: sqlite3.Connection) -> None:
        """Load statistics from the database."""
        for row in conn.execute("SELECT key, value FROM cache_stats"):
            if hasattr(self._stats, row["key"]):
                setattr(self._stats, row["key"], row["value"])
    
    def _save_stats_to_db(self) -> None:
        """Save statistics to the database."""
        try:
            with self._connection() as conn:
                for field in ['hits', 'misses', 'bypasses', 'evictions']:
                    conn.execute(
                        "UPDATE cache_stats SET value = ? WHERE key = ?",
                        (getattr(self._stats, field), field)
                    )
        except Exception as e:
            log.warning(f"Failed to save cache stats: {e}")
    
    def _save_stats(self, conn: sqlite3.Connection) -> None:
        """Save statistics to the database (internal)."""
        for field in ['hits', 'misses', 'bypasses', 'evictions']:
            conn.execute(
                "UPDATE cache_stats SET value = ? WHERE key = ?",
                (getattr(self._stats, field), field)
            )
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            try:
                with self._connection() as conn:
                    count = conn.execute(
                        "SELECT COUNT(*) as cnt FROM cache_entries"
                    ).fetchone()["cnt"]
                    conn.execute("DELETE FROM cache_entries")
                    # R5: hypothesis reuse lives in its own table; a full clear
                    # must miss on both.
                    hcount = conn.execute(
                        "SELECT COUNT(*) as cnt FROM hypothesis_cache_entries"
                    ).fetchone()["cnt"]
                    conn.execute("DELETE FROM hypothesis_cache_entries")
                    count += hcount
                    self._stats.evictions += count
                    self._save_stats(conn)
                log.info("Cache cleared")
            except Exception as e:
                log.warning(f"Cache clear failed: {e}")
    
    def stats(self) -> CacheStats:
        """Get current cache statistics."""
        with self._lock:
            try:
                with self._connection() as conn:
                    self._load_stats(conn)
            except Exception:
                pass
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                bypasses=self._stats.bypasses,
                evictions=self._stats.evictions,
            )
    
    def size(self) -> int:
        """Total cached entries (exchange cache + hypothesis cache, R5)."""
        return self.exchange_size() + self.hypothesis_size()

    def exchange_size(self) -> int:
        """Number of entries in the exchange cache."""
        try:
            with self._connection() as conn:
                return conn.execute(
                    "SELECT COUNT(*) as cnt FROM cache_entries"
                ).fetchone()["cnt"]
        except Exception as e:
            log.warning(f"Cache size check failed: {e}")
            return 0

    def hypothesis_size(self) -> int:
        """Number of entries in the hypothesis cache."""
        try:
            with self._connection() as conn:
                return conn.execute(
                    "SELECT COUNT(*) as cnt FROM hypothesis_cache_entries"
                ).fetchone()["cnt"]
        except Exception as e:
            log.warning(f"Hypothesis cache size check failed: {e}")
            return 0
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable caching."""
        self._enabled = enabled
        log.info(f"Cache {'enabled' if enabled else 'disabled'}")
    
    def is_enabled(self) -> bool:
        """Check if caching is enabled."""
        return self._enabled


# Global cache instance
_cache: Optional[ExchangeCache] = None


def get_cache() -> ExchangeCache:
    """Get the global cache instance."""
    global _cache
    if _cache is None:
        _cache = ExchangeCache()
    return _cache


def init_cache(
    db_path: Path | str | None = None,
    ttl_seconds: float = 86400.0,
    max_size: int = 10000,
    enabled: bool = True,
    bypass_token: Optional[str] = None,
) -> ExchangeCache:
    """
    Initialize the global cache with custom settings.
    
    Call this early in application startup to configure caching.
    """
    global _cache
    _cache = ExchangeCache(
        db_path=db_path,
        ttl_seconds=ttl_seconds,
        max_size=max_size,
        enabled=enabled,
        bypass_token=bypass_token,
    )
    return _cache
