"""Quickstart example for :mod:`aiohttp_client_middlewares`."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import DigestAuthMiddleware, RateLimitMiddleware


async def main() -> None:
    digest_auth = DigestAuthMiddleware(login="user", password="secret")
    # Throttle to at most 5 requests per second, allowing bursts of up to 2.
    # The rate limiter goes last so that internal replays (such as digest's
    # 401 handshake) are throttled too.
    rate_limit = RateLimitMiddleware(rate=5.0, burst=2)
    async with ClientSession(middlewares=(digest_auth, rate_limit)) as session:
        url = "https://httpbin.org/digest-auth/auth/user/secret"
        async with session.get(url) as resp:
            resp.raise_for_status()
            print(await resp.json())


asyncio.run(main())
