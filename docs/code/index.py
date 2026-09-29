"""Quickstart examples included into the index page."""

from aiohttp import ClientSession

from aiohttp_client_middlewares import (
    DigestAuthMiddleware,
    RateLimitMiddleware,
    SSRFConnector,
    SSRFMiddleware,
    TokenBucket,
)


async def digest_auth_example() -> None:
    digest_auth = DigestAuthMiddleware(login="user", password="secret")
    async with ClientSession(middlewares=(digest_auth,)) as session:
        url = "https://httpbin.org/digest-auth/auth/user/secret"
        async with session.get(url) as resp:
            resp.raise_for_status()
            print(await resp.json())


async def rate_limit_example() -> None:
    # At most 5 requests per second, allowing bursts of up to 2.
    rate_limit = RateLimitMiddleware(TokenBucket(rate=5.0, burst=2))
    async with ClientSession(middlewares=(rate_limit,)) as session:
        async with session.get("http://example.com") as resp:
            resp.raise_for_status()
            print(await resp.text())


async def ssrf_example() -> None:
    # Both layers: the connector judges resolved addresses, the middleware
    # judges the URL. Neither is sufficient alone.
    async with ClientSession(
        connector=SSRFConnector(), middlewares=(SSRFMiddleware(),)
    ) as session:
        async with session.get("https://example.com") as resp:
            print("Status:", resp.status)
