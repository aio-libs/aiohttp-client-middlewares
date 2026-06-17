"""Quickstart example for :mod:`aiohttp_client_middlewares`."""

import asyncio

from aiohttp import ClientSession

from aiohttp_client_middlewares import DigestAuthMiddleware


async def main() -> None:
    digest_auth = DigestAuthMiddleware(login="user", password="secret")
    async with ClientSession(middlewares=(digest_auth,)) as session:
        url = "https://httpbin.org/digest-auth/auth/user/secret"
        async with session.get(url) as resp:
            resp.raise_for_status()
            print(await resp.json())


asyncio.run(main())
