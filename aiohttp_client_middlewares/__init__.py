"""Client middlewares for :mod:`aiohttp`.

This package is the canonical home for reusable aiohttp *client* middlewares,
starting with HTTP Digest authentication and server-side request forgery
(SSRF) protection.
"""

from .digest_auth import DigestAuthMiddleware
from .ssrf import SSRFConnector, SSRFError, SSRFMiddleware

__version__ = "0.1.0"

__all__ = (
    "DigestAuthMiddleware",
    "SSRFConnector",
    "SSRFError",
    "SSRFMiddleware",
)
