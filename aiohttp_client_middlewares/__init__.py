"""Client middlewares for :mod:`aiohttp`.

This package is the canonical home for reusable aiohttp *client* middlewares,
starting with HTTP Digest authentication, client-side rate limiting and
server-side request forgery (SSRF) protection.
"""

from .digest_auth import DigestAuthMiddleware
from .rate_limit import RateLimiter, RateLimitMiddleware, TokenBucket
from .ssrf import SSRFConnector, SSRFError, SSRFMiddleware, is_unsafe_address

__version__ = "0.1.0"

__all__ = (
    "DigestAuthMiddleware",
    "RateLimiter",
    "RateLimitMiddleware",
    "SSRFConnector",
    "SSRFError",
    "SSRFMiddleware",
    "TokenBucket",
    "is_unsafe_address",
)
