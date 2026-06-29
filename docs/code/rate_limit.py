"""Quickstart example for the rate-limiting middleware."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import RateLimitMiddleware


async def main() -> None:
    # Throttle to at most 5 requests per second, allowing bursts of up to 2.
    rate_limit = RateLimitMiddleware(rate=5.0, burst=2)
    async with ClientSession(middlewares=(rate_limit,)) as session:
        for _ in range(10):
            async with session.get("https://httpbin.org/get") as resp:
                print("Status:", resp.status)


asyncio.run(main())
