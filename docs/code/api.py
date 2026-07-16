"""Usage example for :class:`RateLimitMiddleware`."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import RateLimitMiddleware


async def main() -> None:
    # At most 5 requests/second, bursting up to 2.
    rate_limit = RateLimitMiddleware(rate=5.0, burst=2)
    async with ClientSession(middlewares=(rate_limit,)) as session:
        async with session.get("http://example.com") as resp:
            assert resp.status == 200


asyncio.run(main())
