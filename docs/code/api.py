"""Usage examples for the API reference."""

from aiohttp import ClientSession

from aiohttp_client_middlewares import RateLimitMiddleware, RetryMiddleware, TokenBucket


async def rate_limit_usage() -> None:
    # At most 5 requests/second, bursting up to 2.
    rate_limit = RateLimitMiddleware(TokenBucket(rate=5.0, burst=2))
    async with ClientSession(middlewares=(rate_limit,)) as session:
        async with session.get("http://example.com") as resp:
            assert resp.status == 200


async def retry_usage() -> None:
    # Up to 5 attempts, with no wait longer than 10 seconds.
    retry = RetryMiddleware(attempts=5, max_delay=10.0)
    async with ClientSession(middlewares=(retry,)) as session:
        async with session.get("http://example.com") as resp:
            assert resp.status == 200
