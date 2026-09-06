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

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientTimeout


class RateLimiter(ABC):
    """Base class for rate-limit algorithms.

    Implementations provide an async :meth:`acquire` and a synchronous
    :meth:`clone`. The sleeping, timeout and post-reservation cancellation
    logic lives in :meth:`wait`, shared by every algorithm, so reserving a
    slot may perform I/O of its own -- against Redis or a database, say.

    Until :meth:`acquire` returns, cleaning up a half-made reservation is
    its own responsibility; once it returns, :meth:`wait` owns the slot and
    calls :meth:`release` if it cannot be used.

    An async method that contains no suspension point still runs atomically
    when awaited directly. :class:`TokenBucket` relies on that property to
    preserve arrival ordering on one event loop.
    """

    @abstractmethod
    async def acquire(self) -> float:
        """Reserve a slot and return the delay to sleep before sending.

        The delay must be non-negative, finite seconds; :meth:`wait` takes that
        on trust, and a NaN would send the request through unthrottled. If
        cancellation or another exception prevents this method from
        returning, it must not leave a reservation behind.
        """

    @abstractmethod
    def clone(self, host: str, /) -> "RateLimiter":
        """Return a fresh limiter, configured the same, scoped to *host*.

        Per-domain mode calls this the first time it meets a host, so state
        (queued slots, accrued tokens) must not carry over. Threads racing on
        that first contact may each build one and only one is kept, so the
        call itself should have no side effects. An algorithm that keeps its
        state in-process can ignore *host*; one that keeps it in a shared
        backend needs it in the key, or every host draws on one limit.
        """

    def release(self) -> None:
        """Hand back a reserved slot that will not be used.

        Called by :meth:`wait` when the reserved slot cannot be used:
        the delay would exceed the caller's timeout, or the caller is
        cancelled while sleeping. The default is a no-op for algorithms
        that have nothing to return.

        Must neither await nor raise, since one of those calls is from an
        ``except asyncio.CancelledError`` block: awaiting there can be
        truncated part-way, and raising would replace the exception the
        caller is owed. A limiter that has to reach its backend to hand a
        slot back can schedule that round trip as a task from here.
        """

    async def wait(self, timeout: float | None = None) -> None:
        """Reserve a slot and wait until the request may be sent.

        Time in :meth:`acquire` is charged against *timeout* once it
        returns, though not bounded by it, so an implementation that can
        hang needs its own deadline. When the delay exceeds what is left,
        the slot is handed back and :exc:`asyncio.TimeoutError` raised
        without sleeping.
        """
        started = time.monotonic()
        delay = await self.acquire()

        if timeout is not None:
            # Goes negative when acquiring alone outlasted the timeout; the
            # message reports it as such rather than clamping it to zero.
            remaining = timeout - (time.monotonic() - started)
            if delay > remaining:
                self.release()
                raise asyncio.TimeoutError(
                    f"rate limiter would delay the request {delay:.3f}s, "
                    f"beyond the {remaining:.3f}s remaining timeout"
                )
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
        self._rate = rate
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

    async def acquire(self) -> float:
        """Take one token and return the delay to sleep before sending.

        The delay is the exact fractional deficit (not rounded to whole
        intervals), so a caller never waits longer than the bucket needs.
        There is deliberately no suspension point: callers on one event
        loop reserve slots atomically, in arrival order.
        """
        self._refill()
        self._tokens -= 1.0
        return max(0.0, -self._tokens) * self._interval

    def clone(self, host: str, /) -> "TokenBucket":
        """Return a fresh, full bucket with the same rate and burst.

        The bucket's state is per-object, so *host* needs no part in it.
        """
        return TokenBucket(rate=self._rate, burst=int(self._burst))

    def release(self) -> None:
        """Return one token to the bucket."""
        self._refill()
        self._tokens = min(self._tokens + 1.0, self._burst)


class RateLimitMiddleware:
    """Client middleware that throttles requests through a :class:`RateLimiter`.

    The middleware waits on the limiter before sending, so the client never
    sends faster than the limiter allows. What that ordering is worth is the
    limiter's to say. :class:`TokenBucket` grants slots in arrival order
    because its :meth:`~RateLimiter.acquire` has no suspension point.

    For :class:`TokenBucket`, cancellation is the one exception to arrival
    order: a handed-back slot frees capacity that queued callers have already
    been given fixed delays against, so two of them can briefly send in the
    same instant. When aiohttp exposes the request's timeout (aiohttp 3.15
    and newer), a wait that would exceed it fails immediately with
    :exc:`asyncio.TimeoutError` instead of sleeping toward a guaranteed timeout.

    Middleware order matters: middlewares listed earlier wrap the ones listed
    later, and a middleware that retries internally (for example,
    :class:`~aiohttp_client_middlewares.DigestAuthMiddleware` replaying a
    request after a 401) re-invokes only the middlewares listed *after* it.
    List ``RateLimitMiddleware`` last so that every request hitting the wire
    -- including such replays -- is throttled.

    :param RateLimiter limiter: The :class:`RateLimiter` to throttle with --
        for example ``TokenBucket(rate=5.0, burst=2)``. With
        ``per_domain=True`` it acts as a template: each target host gets
        ``limiter.clone(host)`` the first time that host is seen.
    :param bool per_domain: When ``True``, keep an independent limiter per
        target host instead of a single global one. Limiters are keyed on the
        URL host only (port and scheme are not distinguished) and are never
        evicted, so only enable this for a bounded, trusted set of hosts.
    :raises TypeError: if ``limiter`` is not a :class:`RateLimiter`.
    """

    def __init__(
        self,
        limiter: RateLimiter,
        *,
        per_domain: bool = False,
    ) -> None:
        if not isinstance(limiter, RateLimiter):
            raise TypeError(f"limiter must be a RateLimiter, got {limiter!r}")
        # The one limiter in global mode; the template to clone in per-domain
        # mode. Whether the per-host dict exists is what says which.
        self._limiter = limiter
        self._domain_limiters: dict[str, RateLimiter] | None = (
            {} if per_domain else None
        )

    @property
    def per_domain(self) -> bool:
        """Whether this middleware keeps one limiter per target host.

        Read-only: which limiter a request gets is decided in ``__init__``,
        so flipping this afterwards could not take effect.
        """
        return self._domain_limiters is not None

    def _get_limiter(self, request: ClientRequest) -> RateLimiter:
        limiters = self._domain_limiters
        if limiters is None:
            return self._limiter
        # aiohttp raises InvalidUrlClientError for host-less URLs before
        # any middleware runs (on redirects too), so ``host`` is only
        # ``None`` in the type; the assert narrows it for mypy.
        domain = request.url.host
        assert domain is not None
        limiter = limiters.get(domain)
        if limiter is None:
            # setdefault, not an assignment: threads racing for a host they
            # have not seen before must all leave with the limiter that was
            # stored, or each gets a private full budget and the burst
            # allowance is briefly multiplied by the number of racers.
            limiter = limiters.setdefault(domain, self._limiter.clone(domain))
        return limiter

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Run the request through the rate limiter."""
        limiter = self._get_limiter(request)
        # ``ClientRequest.timeout`` is public and read-only since aiohttp
        # 3.15 (aio-libs/aiohttp#13176); older releases have no such
        # attribute at all, so the limiter waits without a budget there.
        # The annotation keeps the value type-checked even though the
        # attribute cannot be resolved statically on 3.12 to 3.14. Dropping
        # the getattr() is gated on raising the floor to 3.15; that change
        # is ready in #23 and waits only on the aiohttp release.
        client_timeout: ClientTimeout | None = getattr(request, "timeout", None)
        total = None if client_timeout is None else client_timeout.total
        if total is not None and total <= 0.0:
            # aiohttp arms its own deadline only for a positive total, so a
            # zero or negative one means "no timeout", not "no budget left".
            total = None
        await limiter.wait(total)
        return await handler(request)
