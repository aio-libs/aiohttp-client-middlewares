"""Client middlewares for :mod:`aiohttp`.

This package is the canonical home for reusable aiohttp *client* middlewares,
starting with HTTP Digest authentication and client-side rate limiting.
"""

from .digest_auth import DigestAuthMiddleware
from .rate_limit import RateLimiter, RateLimitMiddleware, TokenBucket

__version__ = "0.1.0"

__all__ = ("DigestAuthMiddleware", "RateLimiter", "RateLimitMiddleware", "TokenBucket")
