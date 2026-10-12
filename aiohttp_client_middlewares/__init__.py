"""Client middlewares for :mod:`aiohttp`.

This package is the canonical home for reusable aiohttp *client* middlewares:
HTTP Digest authentication, client-side rate limiting and retries.
"""

from .digest_auth import DigestAuthMiddleware
from .rate_limit import RateLimiter, RateLimitMiddleware, TokenBucket
from .retry import RetryMiddleware

__version__ = "0.1.0"

__all__ = (
    "DigestAuthMiddleware",
    "RateLimiter",
    "RateLimitMiddleware",
    "RetryMiddleware",
    "TokenBucket",
)
