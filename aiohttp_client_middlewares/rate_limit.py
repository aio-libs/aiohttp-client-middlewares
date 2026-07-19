"""Client-side rate-limiting middleware for aiohttp.

This middleware throttles outgoing requests so the client does not overwhelm
upstream servers or exceed API quotas. It is *not* server-side rate limiting.

Features:
- Pluggable algorithm through the :class:`RateLimiter` base class
  (:class:`TokenBucket` included)
- Optional per-domain limiters
"""

import asyncio
import math
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse


class RateLimiter(ABC):
    """Base class for rate-limit algorithms.

    Implementations provide the synchronous :meth:`acquire`; the async
    sleeping logic lives here in :meth:`wait`, shared by every algorithm.
    Because :meth:`acquire` is synchronous, callers on one event loop
    reserve slots atomically in arrival order.
    """

    @abstractmethod
    def acquire(self, timeout: float | None = None) -> float:
        """Reserve a slot and return the delay to sleep before sending.

        When the delay would exceed *timeout*, the limiter state must be
        left untouched and :exc:`asyncio.TimeoutError` raised instead, so a
        request that could never be sent in time fails fast without
        consuming a slot.
        """

    def release(self) -> None:
        """Hand back a reserved slot that will not be used.

        Called by :meth:`wait` when the caller is cancelled while sleeping
        out its delay. The default is a no-op for algorithms that have
        nothing to return.
        """

    async def wait(self, timeout: float | None = None) -> None:
        """Reserve a slot and sleep out its delay."""
        delay = self.acquire(timeout)
        if delay > 0.0:
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                # The reserved slot will never be used; give it back so
                # later requests are not penalised for it.
                self.release()
                raise


class TokenBucket(RateLimiter):
    """Token bucket: tokens accrue at ``rate`` per second, capped at ``burst``.

    ``acquire`` takes one token immediately and returns the delay the caller
    must sleep before sending; the count may go negative, which is what
    queues callers up (each successive over-limit acquire owes one more
    interval).

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
        self._burst = float(burst)
        # Start full so the first ``burst`` acquires are instant.
        self._tokens = self._burst
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(
            self._tokens + (now - self._last_refill) / self._interval,
            self._burst,
        )
        self._last_refill = now

    def acquire(self, timeout: float | None = None) -> float:
        """Take one token and return the delay to sleep before sending.

        The delay is the exact fractional deficit (not rounded to whole
        intervals), so a caller never waits longer than the bucket needs.
        When the delay would exceed *timeout*, the token is handed back and
        :exc:`asyncio.TimeoutError` is raised instead.
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
        """Return one token to the bucket."""
        self._refill()
        self._tokens = min(self._tokens + 1.0, self._burst)


class RateLimitMiddleware:
    """Client middleware that throttles requests through a :class:`RateLimiter`.

    The middleware waits on the limiter before sending, so the client never
    sends faster than the limiter allows and slots are granted in arrival
    order. When aiohttp exposes the request's total timeout to the middleware
    (newer versions do), a wait that would exceed it fails immediately with
    :exc:`asyncio.TimeoutError` instead of sleeping toward a guaranteed
    timeout.

    Middleware order matters: middlewares listed earlier wrap the ones listed
    later, and a middleware that retries internally (for example,
    :class:`~aiohttp_client_middlewares.DigestAuthMiddleware` replaying a
    request after a 401) re-invokes only the middlewares listed *after* it.
    List ``RateLimitMiddleware`` last so that every request hitting the wire
    -- including such replays -- is throttled.

    :param limiter: The :class:`RateLimiter` to throttle with -- for example
        ``TokenBucket(rate=5.0, burst=2)``. With ``per_domain=True``, pass a
        zero-argument factory instead (for example ``lambda:
        TokenBucket(rate=5.0)``); it is called once per target host, the
        first time that host is seen.
    :type limiter: RateLimiter or Callable[[], RateLimiter]
    :param bool per_domain: When ``True``, keep an independent limiter per
        target host instead of a single global one. Limiters are keyed on the
        URL host only (port and scheme are not distinguished) and are never
        evicted, so only enable this for a bounded, trusted set of hosts.
    :raises TypeError: if ``limiter`` does not match the mode: an instance is
        required without ``per_domain``, a factory with it.
    """

    per_domain: bool

    def __init__(
        self,
        limiter: "RateLimiter | Callable[[], RateLimiter]",
        *,
        per_domain: bool = False,
    ) -> None:
        self.per_domain = per_domain
        self._global_limiter: RateLimiter | None = None
        if per_domain:
            if isinstance(limiter, RateLimiter) or not callable(limiter):
                raise TypeError(
                    "per_domain mode builds one limiter per host: pass a "
                    "zero-argument factory such as lambda: TokenBucket(rate=5.0)"
                )
            self._domain_limiters: dict[str, RateLimiter] = defaultdict(limiter)
        else:
            if not isinstance(limiter, RateLimiter):
                raise TypeError(
                    "limiter must be a RateLimiter instance (pass a factory "
                    "only together with per_domain=True)"
                )
            self._global_limiter = limiter

    def _get_limiter(self, request: ClientRequest) -> RateLimiter:
        if self._global_limiter is not None:
            return self._global_limiter
        # aiohttp raises InvalidUrlClientError for host-less URLs before
        # any middleware runs (on redirects too), so ``host`` is only
        # ``None`` in the type; the assert narrows it for mypy.
        domain = request.url.host
        assert domain is not None
        return self._domain_limiters[domain]

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Run the request through the rate limiter."""
        limiter = self._get_limiter(request)
        # aiohttp does not expose the request's ClientTimeout publicly yet:
        # 3.x carries only the private ``_timeout``. Prefer the public
        # read-only ``timeout`` attribute once a version provides it.
        client_timeout = getattr(request, "timeout", None) or getattr(
            request, "_timeout", None
        )
        await limiter.wait(None if client_timeout is None else client_timeout.total)
        return await handler(request)
