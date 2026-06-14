"""Client middlewares for :mod:`aiohttp`.

This package is the canonical home for reusable aiohttp *client* middlewares,
starting with HTTP Digest authentication.
"""

from .digest_auth import DigestAuthMiddleware

__version__ = "0.1.0"

__all__ = ("DigestAuthMiddleware",)
