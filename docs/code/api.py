"""Examples included by :doc:`../api`."""

from aiohttp import ClientSession

from aiohttp_client_middlewares import SSRFConnector, SSRFMiddleware


async def ssrf_usage() -> None:
    async with ClientSession(
        connector=SSRFConnector(),
        middlewares=(SSRFMiddleware(),),
    ) as session:
        # Raises SSRFError: metadata endpoints are blocked by default.
        await session.get("http://169.254.169.254/latest/meta-data/")
