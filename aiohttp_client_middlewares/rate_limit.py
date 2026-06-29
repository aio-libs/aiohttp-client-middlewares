"""Client-side rate-limiting middleware for aiohttp.

This middleware throttles outgoing requests using a token-bucket algorithm.
It is *not* server-side rate limiting -- it limits how fast the client sends
requests so it does not overwhelm upstream servers or exceed API quotas.

Features:
- Configurable rate and burst size
- Optional per-domain buckets
- Automatic ``Retry-After`` header handling
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from http import HTTPStatus

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse

_LOGGER = logging.getLogger(__name__)


class TokenBucket:
    """FIFO token-bucket using an ``asyncio.Event`` queue.

    Each caller appends its own event to a FIFO queue and waits. A single
    ``_schedule`` coroutine services the queue front-to-back, sleeping until
    each slot's send time arrives and then unblocking the corresponding
    caller. This guarantees strict FIFO ordering even under high concurrency.
    """

    def __init__(self, rate: float, burst: int) -> None:
        self._interval = 1.0 / rate
        self._burst = burst
        # Start *burst* intervals in the past so the first ``burst`` acquires
        # are instant.
        self._next_send = time.monotonic() - burst * self._interval
        self._waiters: deque[asyncio.Event] = deque()
        self._scheduling = False
        # Keep a strong reference to the scheduler task: the event loop only
        # holds a weak reference to it, so an otherwise-unreferenced task can
        # be garbage collected mid-run.
        self._scheduler_task: asyncio.Task[None] | None = None

    async def acquire(self) -> None:
        """Reserve the next send slot and wait until it arrives."""
        event = asyncio.Event()
        self._waiters.append(event)
        self._ensure_scheduling()
        await event.wait()

    def _ensure_scheduling(self) -> None:
        """Start the scheduler loop if it is not already running."""
        if not self._scheduling:
            self._scheduling = True
            self._scheduler_task = asyncio.ensure_future(self._schedule())

    async def _schedule(self) -> None:
        """Service waiters in FIFO order, one slot at a time."""
        while self._waiters:
            now = time.monotonic()
            # Cap drift so idle periods never accumulate more than *burst*
            # free slots.
            self._next_send = max(self._next_send, now - self._burst * self._interval)
            self._next_send += self._interval
            delay = self._next_send - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._waiters.popleft().set()
        self._scheduling = False


class RateLimitMiddleware:
    """Client middleware that throttles requests with a token bucket.

    The middleware delays each outgoing request until the bucket grants it a
    slot, so the client never sends faster than ``rate`` requests per second
    (allowing short bursts of up to ``burst`` requests).

    :param float rate: Sustained request rate, in requests per second.
    :param int burst: Number of requests allowed to go out back-to-back before
        throttling kicks in.
    :param bool per_domain: When ``True``, keep an independent bucket per
        target host instead of a single global bucket.
    :param bool respect_retry_after: When ``True``, sleep for the duration of a
        numeric ``Retry-After`` header on an HTTP 429 response before returning
        it to the caller.
    """

    rate: float
    burst: int
    per_domain: bool
    respect_retry_after: bool

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 10,
        per_domain: bool = False,
        respect_retry_after: bool = True,
    ) -> None:
        self.rate = rate
        self.burst = burst
        self.per_domain = per_domain
        self.respect_retry_after = respect_retry_after
        self._global_bucket = TokenBucket(rate, burst)
        self._domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, burst)
        )

    def _get_bucket(self, request: ClientRequest) -> TokenBucket:
        if self.per_domain:
            domain = request.url.host or "unknown"
            return self._domain_buckets[domain]
        return self._global_bucket

    async def _handle_retry_after(self, response: ClientResponse) -> None:
        if response.status != HTTPStatus.TOO_MANY_REQUESTS:
            return
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                wait_seconds = float(retry_after)
                _LOGGER.info("Server requested Retry-After: %ss", wait_seconds)
                await asyncio.sleep(wait_seconds)
            except ValueError:
                _LOGGER.debug(
                    "Retry-After is not a number (likely HTTP-date): %s", retry_after
                )

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Run the request through the rate limiter."""
        bucket = self._get_bucket(request)
        await bucket.acquire()

        response = await handler(request)

        if self.respect_retry_after:
            await self._handle_retry_after(response)

        return response
