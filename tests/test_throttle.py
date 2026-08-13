import time


from app.core.throttle import RateLimiter


class TestRateLimiter:
    def should_allow_first_request(self):
        """Allow the very first request for a key."""
        limiter = RateLimiter()
        assert limiter.check("alice", max_count=5, window_seconds=10) is True

    def should_allow_requests_within_limit(self):
        """Allow requests as long as the count is within the limit."""
        limiter = RateLimiter()
        key = "bob"
        for _ in range(5):
            assert limiter.check(key, max_count=5, window_seconds=10) is True

    def should_block_exceeding_requests(self):
        """Block once the count exceeds the limit."""
        limiter = RateLimiter()
        key = "mallory"
        for _ in range(5):
            limiter.check(key, max_count=5, window_seconds=10)
        assert limiter.check(key, max_count=5, window_seconds=10) is False

    def should_allow_after_reset(self):
        """Allow requests again after the key is reset."""
        limiter = RateLimiter()
        key = "trudy"
        for _ in range(5):
            limiter.check(key, max_count=5, window_seconds=10)
        # blocked now
        assert limiter.check(key, max_count=5, window_seconds=10) is False
        limiter.reset(key)
        # allowed after reset
        assert limiter.check(key, max_count=5, window_seconds=10) is True

    def should_isolate_different_keys(self):
        """Rate limiting for one key should not affect another."""
        limiter = RateLimiter()
        key_a = "alice"
        key_b = "bob"
        for _ in range(5):
            limiter.check(key_a, max_count=5, window_seconds=10)
        # key_a is exhausted
        assert limiter.check(key_a, max_count=5, window_seconds=10) is False
        # key_b is unaffected
        assert limiter.check(key_b, max_count=5, window_seconds=10) is True

    def should_allow_after_window_expiry(self):
        """Allow requests once the time window has elapsed."""
        limiter = RateLimiter()
        key = "carol"
        for _ in range(5):
            limiter.check(key, max_count=5, window_seconds=0.1)
        assert limiter.check(key, max_count=5, window_seconds=0.1) is False
        time.sleep(0.15)
        assert limiter.check(key, max_count=5, window_seconds=0.1) is True
