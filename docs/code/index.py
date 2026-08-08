"""Quickstart examples for :mod:`aiohttp_client_middlewares`."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import (
    DigestAuthMiddleware,
    SSRFConnector,
    SSRFMiddleware,
)


async def digest_auth_example() -> None:
    digest_auth = DigestAuthMiddleware(login="user", password="secret")
    async with ClientSession(middlewares=(digest_auth,)) as session:
        url = "https://httpbin.org/digest-auth/auth/user/secret"
        async with session.get(url) as resp:
            resp.raise_for_status()
            print(await resp.json())


async def ssrf_example() -> None:
    # Both layers: the connector judges resolved addresses, the middleware
    # judges the URL. Neither is sufficient alone.
    async with ClientSession(
        connector=SSRFConnector(), middlewares=(SSRFMiddleware(),)
    ) as session:
        async with session.get("https://example.com") as resp:
            print("Status:", resp.status)


asyncio.run(digest_auth_example())
