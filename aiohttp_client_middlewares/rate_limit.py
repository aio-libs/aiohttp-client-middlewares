"""Client-side rate-limiting middleware for aiohttp.

This middleware throttles outgoing requests using a token-bucket algorithm.
It is *not* server-side rate limiting -- it limits how fast the client sends
requests so it does not overwhelm upstream servers or exceed API quotas.

Features:
- Configurable rate and burst size
- Optional per-domain buckets
- Automatic ``Retry-After`` header handling (bounded, and safe against
  non-finite/hostile values)
"""

import asyncio
import logging
import math
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

    The scheduler binds to whichever event loop is running when it first
    starts, but the bucket heals across loops: if the scheduler is cancelled
    (for example, the loop is torn down while a request is throttled), the
    next ``acquire`` -- possibly on a new loop -- restarts it.
    """

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be > 0, got {rate!r}")
        if burst < 1:
            raise ValueError(f"burst must be >= 1, got {burst!r}")
        self._interval = 1.0 / rate
        self._burst = burst
        # Start *burst* intervals in the past so the first ``burst`` acquires
        # are instant.
        self._next_send = time.monotonic() - burst * self._interval
        self._waiters: deque[asyncio.Event] = deque()
        # Strong reference to the running scheduler task (the loop only keeps a
        # weak one, so an otherwise-unreferenced task could be garbage collected
        # mid-run). ``None`` also means "no scheduler is running".
        self._scheduler_task: asyncio.Task[None] | None = None

    async def acquire(self) -> None:
        """Reserve the next send slot and wait until it arrives."""
        event = asyncio.Event()
        self._waiters.append(event)
        self._ensure_scheduling()
        try:
            await event.wait()
        except asyncio.CancelledError:
            # Drop our slot so the scheduler does not waste an interval on a
            # waiter that will never be served.
            try:
                self._waiters.remove(event)
            except ValueError:  # pragma: no cover - scheduler already served it
                pass
            raise

    def _ensure_scheduling(self) -> None:
        """Start the scheduler loop if one is not already running."""
        if self._scheduler_task is None:
            self._scheduler_task = asyncio.ensure_future(self._schedule())

    async def _schedule(self) -> None:
        """Service waiters in FIFO order, one slot at a time."""
        try:
            while self._waiters:
                now = time.monotonic()
                # Cap drift so idle periods never accumulate more than *burst*
                # free slots.
                self._next_send = max(
                    self._next_send, now - self._burst * self._interval
                )
                self._next_send += self._interval
                delay = self._next_send - now
                if delay > 0:
                    await asyncio.sleep(delay)
                if self._waiters:
                    self._waiters.popleft().set()
                else:
                    # The waiter was cancelled while we slept; hand the slot
                    # back rather than losing it to the drift cap.
                    self._next_send -= self._interval
        finally:
            # Always clear the reference -- even on cancellation -- so a later
            # ``acquire`` restarts the scheduler (including on a new loop).
            self._scheduler_task = None


class RateLimitMiddleware:
    """Client middleware that throttles requests with a token bucket.

    The middleware delays each outgoing request until the bucket grants it a
    slot, so the client never sends faster than ``rate`` requests per second
    (allowing short bursts of up to ``burst`` requests).

    :param float rate: Sustained request rate, in requests per second. Must be
        greater than 0.
    :param int burst: Number of requests allowed to go out back-to-back before
        throttling kicks in. Must be at least 1.
    :param bool per_domain: When ``True``, keep an independent bucket per target
        host instead of a single global bucket. The per-host buckets are never
        evicted, so only enable this for a bounded, trusted set of hosts.
    :param bool respect_retry_after: When ``True``, sleep for the duration of a
        numeric ``Retry-After`` header on an HTTP 429 response before returning
        it to the caller.
    :param max_retry_after: Upper bound, in seconds, on how long a
        ``Retry-After`` header may make the client sleep. Must be ``None`` (no
        cap) or a non-negative, finite number. A server-sent ``Retry-After``
        that is itself non-finite (``inf``/``nan``) or non-positive is always
        ignored, so a hostile server cannot stall the client indefinitely.
    :type max_retry_after: float or None
    :raises ValueError: if ``rate``, ``burst`` or ``max_retry_after`` is out of
        range.
    """

    rate: float
    burst: int
    per_domain: bool
    respect_retry_after: bool
    max_retry_after: float | None

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 10,
        per_domain: bool = False,
        respect_retry_after: bool = True,
        max_retry_after: float | None = 300.0,
    ) -> None:
        self.rate = rate
        self.burst = burst
        self.per_domain = per_domain
        self.respect_retry_after = respect_retry_after
        self.max_retry_after = max_retry_after
        # Building the bucket validates rate/burst eagerly (fail fast).
        self._global_bucket = TokenBucket(rate, burst)
        self._domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, burst)
        )
        if max_retry_after is not None and (
            not math.isfinite(max_retry_after) or max_retry_after < 0
        ):
            raise ValueError(
                "max_retry_after must be None or a non-negative finite "
                f"number, got {max_retry_after!r}"
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
        if not retry_after:
            return
        try:
            wait_seconds = float(retry_after)
        except ValueError:
            _LOGGER.debug(
                "Retry-After is not a number (likely HTTP-date): %s", retry_after
            )
            return
        # ``float()`` also accepts "inf"/"nan"; never sleep on those (or on a
        # non-positive value) -- an untrusted server could otherwise stall or
        # hang the client.
        if not math.isfinite(wait_seconds) or wait_seconds <= 0:
            _LOGGER.debug(
                "Ignoring non-finite or non-positive Retry-After: %s", retry_after
            )
            return
        if self.max_retry_after is not None:
            wait_seconds = min(wait_seconds, self.max_retry_after)
        _LOGGER.info("Server requested Retry-After: %ss", wait_seconds)
        await asyncio.sleep(wait_seconds)

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
