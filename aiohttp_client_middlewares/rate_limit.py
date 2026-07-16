"""Client-side rate-limiting middleware for aiohttp.

This middleware throttles outgoing requests using a token-bucket algorithm.
It is *not* server-side rate limiting -- it limits how fast the client sends
requests so it does not overwhelm upstream servers or exceed API quotas.

Features:
- Configurable rate and burst size
- Injectable bucket (room for alternative algorithms later)
- Optional per-domain buckets
- Automatic ``Retry-After`` header handling (bounded, and safe against
  non-finite/hostile values)
"""

import asyncio
import logging
import math
import time
from collections import defaultdict
from http import HTTPStatus

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse

_LOGGER = logging.getLogger(__name__)


class TokenBucket:
    """Synchronous token bucket: ``acquire`` returns how long to wait.

    Tokens accrue continuously at ``rate`` per second, capped at ``burst``.
    ``acquire`` takes one token immediately and returns the delay the caller
    must sleep before sending; the count may go negative, which is what
    queues callers up (each successive over-limit acquire owes one more
    interval). Because ``acquire`` is synchronous, callers on one event loop
    reserve slots atomically in arrival order.

    The bucket never sleeps and holds no tasks or loop state, so it can be
    shared across sequential event loops. It is not thread-safe: use it from
    one loop at a time.
    """

    def __init__(self, rate: float = 10.0, burst: int = 10) -> None:
        if not math.isfinite(rate) or rate <= 0:
            raise ValueError(f"rate must be a positive finite number, got {rate!r}")
        if burst < 1:
            raise ValueError(f"burst must be >= 1, got {burst!r}")
        self._interval = 1.0 / rate
        if not math.isfinite(self._interval):
            raise ValueError(f"rate is too small, got {rate!r}")
        self._burst = burst
        # Start full so the first ``burst`` acquires are instant.
        self._tokens = float(burst)
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(
            self._tokens + (now - self._last_refill) / self._interval,
            float(self._burst),
        )
        self._last_refill = now

    def acquire(self, timeout: float | None = None) -> float:
        """Take one token and return the delay to sleep before sending.

        The delay is the exact fractional deficit (not rounded to whole
        intervals), so a caller never waits longer than the bucket needs.
        When the delay would exceed *timeout*, the token is handed back and
        :exc:`asyncio.TimeoutError` is raised instead, so a request that
        could never be sent in time fails fast without consuming a slot.
        """
        self._refill()
        self._tokens -= 1.0
        delay = max(0.0, -self._tokens) * self._interval
        if timeout is not None and delay > timeout:
            self._tokens += 1.0
            raise asyncio.TimeoutError(
                f"rate limiter would delay the request {delay:.3f}s, "
                f"beyond the {timeout:.3f}s timeout"
            )
        return delay

    def release(self) -> None:
        """Return one token, e.g. when a granted slot will not be used.

        Called by the middleware when a caller is cancelled while sleeping
        out its delay, so the unused slot goes back to the pool instead of
        penalising later requests.
        """
        self._refill()
        self._tokens = min(self._tokens + 1.0, float(self._burst))


class RateLimitMiddleware:
    """Client middleware that throttles requests with a token bucket.

    The middleware asks the bucket for a delay and sleeps it out before
    sending, so the client never sends faster than ``rate`` requests per
    second (allowing short bursts of up to ``burst`` requests). Slots are
    granted in arrival order. When aiohttp exposes the request's total
    timeout to the middleware (newer versions do), a wait that would exceed
    it fails immediately with :exc:`asyncio.TimeoutError` instead of
    sleeping toward a guaranteed timeout.

    Configuration is fixed at construction time: changing the attributes of an
    existing instance does not reconfigure buckets that were already built.

    Middleware order matters: middlewares listed earlier wrap the ones listed
    later, and a middleware that retries internally (for example,
    :class:`~aiohttp_client_middlewares.DigestAuthMiddleware` replaying a
    request after a 401) re-invokes only the middlewares listed *after* it.
    List ``RateLimitMiddleware`` last so that every request hitting the wire
    -- including such replays -- is throttled.

    :param bucket: The :class:`TokenBucket` to throttle with. When ``None``
        (default), one is built from ``rate`` and ``burst``. Mutually
        exclusive with ``per_domain`` (per-domain mode builds one bucket per
        host from ``rate`` and ``burst``).
    :type bucket: TokenBucket or None
    :param float rate: Sustained request rate, in requests per second. Must be
        a positive, finite number.
    :param int burst: Number of requests allowed to go out back-to-back before
        throttling kicks in. Must be at least 1.
    :param bool per_domain: When ``True``, keep an independent bucket per target
        host instead of a single global bucket. Buckets are keyed on the URL
        host only (port and scheme are not distinguished) and are never
        evicted, so only enable this for a bounded, trusted set of hosts.
    :param bool respect_retry_after: When ``True``, sleep for the duration of a
        numeric ``Retry-After`` header on an HTTP 429 response before returning
        it to the caller. Only the request that received the 429 sleeps --
        concurrent requests are not held back -- and the response is returned
        as-is afterwards (there is no automatic retry). Other statuses that may
        carry ``Retry-After`` (such as 503) are not inspected.
    :param max_retry_after: Upper bound, in seconds, on how long a
        ``Retry-After`` header may make the client sleep (default ``60.0``;
        ``0.0`` disables the sleep entirely). Must be ``None`` (no cap) or a
        non-negative, finite number. A server-sent ``Retry-After`` that is
        itself non-finite (``inf``/``nan``) or non-positive is always ignored,
        so a hostile server cannot stall the client indefinitely. The sleep
        happens inside the request and counts against the session's
        :class:`~aiohttp.ClientTimeout` (whose default ``total`` is 300
        seconds), so keep the cap well below your total timeout or the request
        will fail with a timeout error instead of returning the 429 response.
    :type max_retry_after: float or None
    :raises ValueError: if ``rate``, ``burst`` or ``max_retry_after`` is out of
        range, or if ``bucket`` is combined with ``per_domain``.
    """

    rate: float
    burst: int
    per_domain: bool
    respect_retry_after: bool
    max_retry_after: float | None

    def __init__(
        self,
        bucket: TokenBucket | None = None,
        *,
        rate: float = 10.0,
        burst: int = 10,
        per_domain: bool = False,
        respect_retry_after: bool = True,
        max_retry_after: float | None = 60.0,
    ) -> None:
        if bucket is not None and per_domain:
            raise ValueError(
                "bucket and per_domain are mutually exclusive; per-domain "
                "buckets are built from rate and burst"
            )
        if max_retry_after is not None and (
            not math.isfinite(max_retry_after) or max_retry_after < 0
        ):
            raise ValueError(
                "max_retry_after must be None or a non-negative finite "
                f"number, got {max_retry_after!r}"
            )
        self.rate = rate
        self.burst = burst
        self.per_domain = per_domain
        self.respect_retry_after = respect_retry_after
        self.max_retry_after = max_retry_after
        # Building the global bucket validates rate/burst eagerly (fail fast).
        self._global_bucket = bucket if bucket is not None else TokenBucket(rate, burst)
        self._domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, burst)
        )

    def _get_bucket(self, request: ClientRequest) -> TokenBucket:
        if self.per_domain:
            # aiohttp raises InvalidUrlClientError for host-less URLs before
            # any middleware runs (on redirects too), so ``host`` is only
            # ``None`` in the type; the assert narrows it for mypy.
            domain = request.url.host
            assert domain is not None
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
            if wait_seconds <= 0:
                _LOGGER.debug("Retry-After sleep disabled by max_retry_after=0")
                return
        _LOGGER.debug("Server requested Retry-After: sleeping %ss", wait_seconds)
        await asyncio.sleep(wait_seconds)

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Run the request through the rate limiter."""
        bucket = self._get_bucket(request)
        # aiohttp does not expose the request's ClientTimeout to middlewares
        # yet: 3.x carries only the timer context, whose armed deadline
        # cannot be read or rescheduled from here. When a version provides
        # ``_timeout`` (current master does, privately), use its total as
        # the bail bound so a wait that would blow the whole budget fails
        # fast instead of sleeping toward a guaranteed timeout.
        client_timeout = getattr(request, "_timeout", None)
        delay = bucket.acquire(None if client_timeout is None else client_timeout.total)
        if delay > 0.0:
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                # The granted slot will never be used; give it back so
                # later requests are not penalised for it.
                bucket.release()
                raise

        response = await handler(request)

        if self.respect_retry_after:
            await self._handle_retry_after(response)

        return response
