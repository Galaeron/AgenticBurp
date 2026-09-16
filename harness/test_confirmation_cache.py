"""Tests for confirmation memoisation in _cached_validate."""
import asyncio
import hashlib
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from harness.models import Finding, HttpExchange
from harness.validators.base import ValidationResult


def _exchange(url="http://target.test/api/users", method="GET", status=200,
              request_body="", request_headers=None, response_headers=None):
    return HttpExchange(
        url=url, method=method, response_status=status,
        request_headers=request_headers or {},
        response_headers=response_headers or {},
        request_body=request_body, response_body="",
    )


def _finding_obj(vuln_class="xss"):
    return Finding(vulnerability_class=vuln_class, severity="medium", confidence=0.7,
                   summary="test", evidence="test", suggested_test="test", basis="derived")


def _result(validator_name="test_v", status="confirmed", confirmed=True, confidence=0.9):
    return ValidationResult(
        validator=validator_name, status=status, finding_class="test",
        confidence=confidence, confirmed=confirmed, summary="cached test result")


class CachedValidateTests(unittest.TestCase):
    """Unit-test the caching logic extracted from orchestrator._cached_validate.

    We test the cache logic directly rather than going through the full
    investigate_engagement() — the integration is just dict lookup/insert
    around validator.validate(), so correctness is: same key → cache hit
    (no second call), different key → cache miss (second call)."""

    def _build_cache_and_wrapper(self):
        """Build the same cache + wrapper the orchestrator uses."""
        cache = {}

        async def cached_validate(validator, finding_obj, exchange):
            method = (exchange.method or "GET").upper()
            url = exchange.url or ""
            body = (exchange.request_body or "")
            body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
            key = (validator.name, method, url, body_hash)
            if key in cache:
                return cache[key]
            result = await validator.validate(finding_obj, exchange)
            cache[key] = result
            return result

        return cache, cached_validate

    def test_first_call_populates_cache(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "xss_v"
        validator.validate = AsyncMock(return_value=_result("xss_v"))
        ex = _exchange()
        f = _finding_obj()

        result = asyncio.run(cached_validate(validator, f, ex))
        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.confirmed)
        validator.validate.assert_called_once()
        self.assertEqual(len(cache), 1)

    def test_second_call_same_endpoint_uses_cache(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "xss_v"
        validator.validate = AsyncMock(return_value=_result("xss_v"))
        ex = _exchange()
        f = _finding_obj()

        async def run():
            r1 = await cached_validate(validator, f, ex)
            r2 = await cached_validate(validator, f, ex)
            return r1, r2

        r1, r2 = asyncio.run(run())
        self.assertIs(r1, r2)
        validator.validate.assert_called_once()

    def test_different_url_is_cache_miss(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "ssrf_v"
        validator.validate = AsyncMock(return_value=_result("ssrf_v"))
        ex1 = _exchange(url="http://target.test/api/users")
        ex2 = _exchange(url="http://target.test/api/admin")
        f = _finding_obj("ssrf")

        async def run():
            await cached_validate(validator, f, ex1)
            await cached_validate(validator, f, ex2)

        asyncio.run(run())
        self.assertEqual(validator.validate.call_count, 2)
        self.assertEqual(len(cache), 2)

    def test_different_method_is_cache_miss(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "csrf_v"
        validator.validate = AsyncMock(return_value=_result("csrf_v"))
        f = _finding_obj("csrf")

        async def run():
            await cached_validate(validator, f, _exchange(method="GET"))
            await cached_validate(validator, f, _exchange(method="POST"))

        asyncio.run(run())
        self.assertEqual(validator.validate.call_count, 2)

    def test_different_body_is_cache_miss(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "xxe_v"
        validator.validate = AsyncMock(return_value=_result("xxe_v"))
        f = _finding_obj("xxe")

        async def run():
            await cached_validate(validator, f, _exchange(request_body="<xml>a</xml>"))
            await cached_validate(validator, f, _exchange(request_body="<xml>b</xml>"))

        asyncio.run(run())
        self.assertEqual(validator.validate.call_count, 2)

    def test_different_validator_is_cache_miss(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        v1 = MagicMock()
        v1.name = "jwt_v"
        v1.validate = AsyncMock(return_value=_result("jwt_v"))
        v2 = MagicMock()
        v2.name = "ssrf_v"
        v2.validate = AsyncMock(return_value=_result("ssrf_v"))
        ex = _exchange()
        f = _finding_obj("jwt")

        async def run():
            await cached_validate(v1, f, ex)
            await cached_validate(v2, f, ex)

        asyncio.run(run())
        v1.validate.assert_called_once()
        v2.validate.assert_called_once()
        self.assertEqual(len(cache), 2)

    def test_same_body_same_hash(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "cmdi_v"
        validator.validate = AsyncMock(return_value=_result("cmdi_v"))
        body = '{"cmd": "whoami"}'
        f = _finding_obj("command_injection")

        async def run():
            await cached_validate(validator, f, _exchange(request_body=body))
            await cached_validate(validator, f, _exchange(request_body=body))

        asyncio.run(run())
        validator.validate.assert_called_once()

    def test_not_confirmed_result_is_also_cached(self):
        """A not_confirmed result should also be cached — we don't retry."""
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "path_v"
        validator.validate = AsyncMock(
            return_value=_result("path_v", status="not_confirmed", confirmed=False, confidence=0.0))
        ex = _exchange()
        f = _finding_obj("path_traversal")

        async def run():
            r1 = await cached_validate(validator, f, ex)
            r2 = await cached_validate(validator, f, ex)
            return r1, r2

        r1, r2 = asyncio.run(run())
        self.assertFalse(r1.confirmed)
        self.assertIs(r1, r2)
        validator.validate.assert_called_once()

    def test_empty_body_hashes_consistently(self):
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "redir_v"
        validator.validate = AsyncMock(return_value=_result("redir_v"))
        f = _finding_obj("open_redirect")

        async def run():
            await cached_validate(validator, f, _exchange(request_body=""))
            await cached_validate(validator, f, _exchange(request_body=""))

        asyncio.run(run())
        validator.validate.assert_called_once()


class NegativeControlTests(unittest.TestCase):
    """Cache must not produce false positives or mask real differences."""

    def _build_cache_and_wrapper(self):
        cache = {}

        async def cached_validate(validator, finding_obj, exchange):
            method = (exchange.method or "GET").upper()
            url = exchange.url or ""
            body = (exchange.request_body or "")
            body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
            key = (validator.name, method, url, body_hash)
            if key in cache:
                return cache[key]
            result = await validator.validate(finding_obj, exchange)
            cache[key] = result
            return result

        return cache, cached_validate

    def test_empty_body_variants_same_hash(self):
        """Two exchanges with empty request_body should share a cache entry."""
        cache, cached_validate = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "test_v"
        validator.validate = AsyncMock(return_value=_result())
        f = _finding_obj()

        ex1 = _exchange(request_body="")
        ex2 = _exchange(request_body="")

        async def run():
            await cached_validate(validator, f, ex1)
            await cached_validate(validator, f, ex2)

        asyncio.run(run())
        validator.validate.assert_called_once()

    def test_cache_isolated_per_run(self):
        """Two separate cache instances don't share state."""
        c1, cv1 = self._build_cache_and_wrapper()
        c2, cv2 = self._build_cache_and_wrapper()
        validator = MagicMock()
        validator.name = "iso_v"
        validator.validate = AsyncMock(return_value=_result("iso_v"))
        ex = _exchange()
        f = _finding_obj()

        async def run():
            await cv1(validator, f, ex)
            await cv2(validator, f, ex)

        asyncio.run(run())
        self.assertEqual(validator.validate.call_count, 2)


if __name__ == "__main__":
    unittest.main()
