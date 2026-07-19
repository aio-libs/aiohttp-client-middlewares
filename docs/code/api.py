"""Usage example for :class:`RateLimitMiddleware`."""

from aiohttp import ClientSession

from aiohttp_client_middlewares import RateLimitMiddleware, TokenBucket


async def rate_limit_usage() -> None:
    # At most 5 requests/second, bursting up to 2.
    rate_limit = RateLimitMiddleware(TokenBucket(rate=5.0, burst=2))
    async with ClientSession(middlewares=(rate_limit,)) as session:
        async with session.get("http://example.com") as resp:
            assert resp.status == 200
