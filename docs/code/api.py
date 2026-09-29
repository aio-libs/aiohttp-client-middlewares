"""Examples included by :doc:`../api`."""

from aiohttp import ClientSession

from aiohttp_client_middlewares import (
    RateLimitMiddleware,
    SSRFConnector,
    SSRFMiddleware,
    TokenBucket,
)


async def rate_limit_usage() -> None:
    # At most 5 requests/second, bursting up to 2.
    rate_limit = RateLimitMiddleware(TokenBucket(rate=5.0, burst=2))
    async with ClientSession(middlewares=(rate_limit,)) as session:
        async with session.get("http://example.com") as resp:
            assert resp.status == 200


async def ssrf_usage() -> None:
    async with ClientSession(
        connector=SSRFConnector(),
        middlewares=(SSRFMiddleware(),),
    ) as session:
        # Raises SSRFError: metadata endpoints are blocked by default.
        await session.get("http://169.254.169.254/latest/meta-data/")
