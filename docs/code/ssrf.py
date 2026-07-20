"""Quickstart example for SSRF protection."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import SSRFConnector, SSRFMiddleware


async def main() -> None:
    # Refuse any request that would reach a private or internal address.
    async with ClientSession(
        connector=SSRFConnector(), middlewares=(SSRFMiddleware(),)
    ) as session:
        async with session.get("https://example.com") as resp:
            print("Status:", resp.status)


asyncio.run(main())
