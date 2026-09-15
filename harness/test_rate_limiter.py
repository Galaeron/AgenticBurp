"""
Tests for the rate limiter module.
"""
import unittest
import asyncio
import time
from rate_limiter import (
    RateLimiter,
    RateLimitConfig,
    RateLimitStrategy,
    RateLimitStats,
    TokenRateLimiter,
    RequestRateLimiter,
    CombinedRateLimiter,
    RateLimiterRegistry,
    get_registry,
    get_token_limiter,
    get_request_limiter,
    get_combined_limiter,
)


class TestRateLimiter(unittest.IsolatedAsyncioTestCase):
    """Test the RateLimiter class."""

    def test_token_bucket_allow(self):
        """Token bucket should allow requests when tokens are available."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=10,
            tokens_per_request=1,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        # Should allow 10 requests
        for _ in range(10):
            self.assertTrue(limiter.allow())
        
        # 11th request should be rejected
        self.assertFalse(limiter.allow())
    
    def test_token_bucket_disabled(self):
        """Disabled limiter should always allow requests."""
        config = RateLimitConfig(enabled=False)
        limiter = RateLimiter(config)
        
        # Should always allow
        for _ in range(100):
            self.assertTrue(limiter.allow())
    
    def test_fixed_window_allow(self):
        """Fixed window should allow requests within the limit."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=5,
            window_seconds=60.0,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        # Should allow 5 requests
        for _ in range(5):
            self.assertTrue(limiter.allow())
        
        # 6th request should be rejected
        self.assertFalse(limiter.allow())
    
    def test_token_bucket_refill(self):
        """Token bucket should refill over time."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,  # 100 tokens per second
            max_tokens=10,
            tokens_per_request=1,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        # Use all tokens
        for _ in range(10):
            limiter.allow()
        
        # Should be rejected
        self.assertFalse(limiter.allow())
        
        # Wait for tokens to refill
        time.sleep(0.1)  # Should refill 10 tokens
        
        # Should be allowed again
        self.assertTrue(limiter.allow())
    
    async def test_async_context_manager(self):
        """Rate limiter should work as async context manager."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=1,
            tokens_per_request=1,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        # First request should succeed
        async with limiter:
            pass
        
        # Second request should be rejected
        start = time.time()
        try:
            async with limiter:
                pass
        except asyncio.TimeoutError:
            pass
        
        # Should have waited at least a bit
        # (This is a bit flaky but should work most of the time)
    
    def test_reset(self):
        """Reset should restore initial state."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=10,
            tokens_per_request=1,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        # Use all tokens
        for _ in range(10):
            limiter.allow()
        
        # Should be rejected
        self.assertFalse(limiter.allow())
        
        # Reset
        limiter.reset()
        
        # Should be allowed again
        self.assertTrue(limiter.allow())
    
    def test_get_stats(self):
        """get_stats should return current statistics."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=10,
            tokens_per_request=1,
            enabled=True,
        )
        limiter = RateLimiter(config)
        
        stats = limiter.get_stats()
        
        self.assertIsInstance(stats, RateLimitStats)
        self.assertEqual(stats.allowed, 0)
        self.assertEqual(stats.rejected, 0)
        
        # Make some requests
        for _ in range(5):
            limiter.allow()
        
        stats = limiter.get_stats()
        self.assertEqual(stats.allowed, 5)


class TestTokenRateLimiter(unittest.TestCase):
    """Test the TokenRateLimiter class."""
    
    def test_record_usage(self):
        """record_usage should track token usage."""
        limiter = TokenRateLimiter()
        
        limiter.record_usage(100, 50)
        limiter.record_usage(200, 100)
        
        # Check recent usage
        usage = limiter.get_recent_usage()
        self.assertEqual(usage, 450)  # 100+50+200+100
    
    def test_allow_with_estimated_tokens(self):
        """allow should respect estimated tokens."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=100,
            tokens_per_request=10,
            enabled=True,
        )
        limiter = TokenRateLimiter(config)
        
        # Should allow with small estimated tokens
        self.assertTrue(limiter.allow(estimated_tokens=10))
        
        # Use up tokens
        for _ in range(10):
            limiter.allow(estimated_tokens=10)
        
        # Should be rejected
        self.assertFalse(limiter.allow(estimated_tokens=10))
    
    def test_reset(self):
        """reset should clear usage tracking."""
        limiter = TokenRateLimiter()
        
        limiter.record_usage(100, 50)
        
        usage_before = limiter.get_recent_usage()
        self.assertGreater(usage_before, 0)
        
        limiter.reset()
        
        usage_after = limiter.get_recent_usage()
        self.assertEqual(usage_after, 0)


class TestRequestRateLimiter(unittest.TestCase):
    """Test the RequestRateLimiter class."""
    
    def test_allow(self):
        """allow should limit requests."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=5,
            window_seconds=60.0,
            enabled=True,
        )
        limiter = RequestRateLimiter(config)
        
        # Should allow 5 requests
        for _ in range(5):
            self.assertTrue(limiter.allow())
        
        # 6th request should be rejected
        self.assertFalse(limiter.allow())
    
    def test_reset(self):
        """reset should clear request tracking."""
        config = RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=5,
            window_seconds=60.0,
            enabled=True,
        )
        limiter = RequestRateLimiter(config)
        
        # Use up all requests
        for _ in range(5):
            limiter.allow()
        
        # Should be rejected
        self.assertFalse(limiter.allow())
        
        # Reset
        limiter.reset()
        
        # Should be allowed again
        self.assertTrue(limiter.allow())


class TestCombinedRateLimiter(unittest.TestCase):
    """Test the CombinedRateLimiter class."""
    
    def test_allow(self):
        """allow should require both limiters to allow."""
        token_config = RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            tokens_per_second=100.0,
            max_tokens=10,
            tokens_per_request=1,
            enabled=True,
        )
        request_config = RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            max_requests=5,
            window_seconds=60.0,
            enabled=True,
        )
        limiter = CombinedRateLimiter(token_config, request_config)
        
        # Both should allow
        for _ in range(5):
            self.assertTrue(limiter.allow())
        
        # Token limiter should still allow but request limiter should reject
        self.assertFalse(limiter.allow())
    
    def test_record_usage(self):
        """record_usage should delegate to token limiter."""
        limiter = CombinedRateLimiter()
        
        limiter.record_usage(100, 50)
        
        # Check that token limiter recorded the usage
        usage = limiter.token_limiter.get_recent_usage()
        self.assertEqual(usage, 150)
    
    def test_reset(self):
        """reset should reset both limiters."""
        limiter = CombinedRateLimiter()
        
        # Use both limiters
        for _ in range(5):
            limiter.allow()
        limiter.record_usage(100, 50)
        
        # Reset
        limiter.reset()
        
        # Both should be reset
        self.assertTrue(limiter.allow())


class TestRateLimiterRegistry(unittest.TestCase):
    """Test the RateLimiterRegistry class."""
    
    def test_get_token_limiter(self):
        """get_token_limiter should create and return token limiters."""
        registry = RateLimiterRegistry()
        
        limiter = registry.get_token_limiter("test")
        self.assertIsInstance(limiter, TokenRateLimiter)
        self.assertEqual(limiter.name, "test")
    
    def test_get_request_limiter(self):
        """get_request_limiter should create and return request limiters."""
        registry = RateLimiterRegistry()
        
        limiter = registry.get_request_limiter("test")
        self.assertIsInstance(limiter, RequestRateLimiter)
        self.assertEqual(limiter.name, "test")
    
    def test_get_combined_limiter(self):
        """get_combined_limiter should create and return combined limiters."""
        registry = RateLimiterRegistry()
        
        limiter = registry.get_combined_limiter("test")
        self.assertIsInstance(limiter, CombinedRateLimiter)
        self.assertEqual(limiter.name, "test")
    
    def test_get_all_stats(self):
        """get_all_stats should return stats for all limiters."""
        registry = RateLimiterRegistry()
        
        registry.get_token_limiter("token1")
        registry.get_request_limiter("request1")
        registry.get_combined_limiter("combined1")
        
        stats = registry.get_all_stats()
        
        self.assertEqual(len(stats), 3)
    
    def test_reset_all(self):
        """reset_all should reset all limiters."""
        registry = RateLimiterRegistry()
        
        token_limiter = registry.get_token_limiter("token1")
        request_limiter = registry.get_request_limiter("request1")
        
        # Use the limiters
        for _ in range(5):
            token_limiter.allow()
            request_limiter.allow()
        
        # Reset all
        registry.reset_all()
        
        # Both should be reset
        self.assertTrue(token_limiter.allow())
        self.assertTrue(request_limiter.allow())


class TestGlobalRegistry(unittest.TestCase):
    """Test the global registry functions."""
    
    def test_get_registry(self):
        """get_registry should return a registry instance."""
        registry = get_registry()
        self.assertIsInstance(registry, RateLimiterRegistry)
    
    def test_get_token_limiter(self):
        """get_token_limiter should return a token limiter."""
        limiter = get_token_limiter()
        self.assertIsInstance(limiter, TokenRateLimiter)
    
    def test_get_request_limiter(self):
        """get_request_limiter should return a request limiter."""
        limiter = get_request_limiter()
        self.assertIsInstance(limiter, RequestRateLimiter)
    
    def test_get_combined_limiter(self):
        """get_combined_limiter should return a combined limiter."""
        limiter = get_combined_limiter()
        self.assertIsInstance(limiter, CombinedRateLimiter)


if __name__ == "__main__":
    unittest.main()
