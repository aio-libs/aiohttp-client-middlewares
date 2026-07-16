"""Tests for the rate-limiting middleware."""

import asyncio
import gc
import threading
import time
from unittest import mock

import pytest
from aiohttp import ClientRequest, web
from pytest_aiohttp import AiohttpClient
from yarl import URL

from aiohttp_client_middlewares.rate_limit import RateLimitMiddleware, TokenBucket


async def _ok_handler(request: web.Request) -> web.Response:
    return web.Response(text="OK")


def _make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api", _ok_handler)
    return app


def _fake_request(host: str) -> ClientRequest:
    """A stand-in ``ClientRequest`` exposing just ``.url``."""
    req = mock.create_autospec(ClientRequest, instance=True)
    req.url = URL(f"http://{host}")
    return req  # type: ignore[no-any-return]


def _retry_after_app(value: str) -> web.Application:
    """An app whose single route always answers 429 with the given header."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=429, headers={"Retry-After": value})

    app = web.Application()
    app.router.add_get("/api", handler)
    return app


async def _cancel_and_join(task: "asyncio.Future[None]") -> None:
    """Cancel a pending acquire and wait for it to finish unwinding."""
    task.cancel()
    await asyncio.wait({task})
    assert task.cancelled()


async def test_token_bucket_allows_burst() -> None:
    """Tokens up to burst size should be available immediately."""
    bucket = TokenBucket(rate=10.0, burst=3)
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    # All three should be near-instant (within the burst allowance).
    assert elapsed < 0.05


async def test_token_bucket_refills_after_idle() -> None:
    """After draining, idle time should replenish burst slots."""
    bucket = TokenBucket(rate=100.0, burst=1)
    await bucket.acquire()
    await asyncio.sleep(0.05)
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # Should be near-instant because idle time refilled the slot.
    assert elapsed < 0.05


async def test_token_bucket_fifo_ordering() -> None:
    """Concurrent acquires should be served in FIFO order."""
    bucket = TokenBucket(rate=100.0, burst=1)
    order: list[int] = []

    async def numbered_acquire(n: int) -> None:
        await bucket.acquire()
        order.append(n)

    tasks = [asyncio.create_task(numbered_acquire(i)) for i in range(3)]
    await asyncio.gather(*tasks)
    assert order == [0, 1, 2]


async def test_rate_limit_middleware_throttles(aiohttp_client: AiohttpClient) -> None:
    """Global middleware should throttle requests beyond burst."""
    middleware = RateLimitMiddleware(rate=50.0, burst=2)
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    start = time.monotonic()
    for _ in range(4):
        resp = await client.get("/api")
        assert resp.status == 200
    elapsed = time.monotonic() - start

    # 2 burst + 2 throttled at 50/s ~= 0.04s minimum wait. The upper bound
    # catches hangs or accidental double-sleeps while staying generous for CI.
    assert 0.02 <= elapsed < 0.5


async def test_rate_limit_middleware_per_domain(aiohttp_client: AiohttpClient) -> None:
    """Per-domain buckets should still throttle requests to the same host."""
    middleware = RateLimitMiddleware(rate=100.0, burst=1, per_domain=True)
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    start = time.monotonic()
    # Same host, so the two requests share a bucket and the second one waits.
    resp1 = await client.get("/api")
    resp2 = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp1.status == 200
    assert resp2.status == 200
    assert 0.005 <= elapsed < 0.5


async def test_rate_limit_middleware_respects_retry_after(
    aiohttp_client: AiohttpClient,
) -> None:
    """The middleware should sleep on a 429 with a numeric ``Retry-After``."""
    call_count = 0

    async def rate_limited_handler(request: web.Request) -> web.Response:
        nonlocal call_count
        call_count += 1
        if call_count <= 1:
            return web.Response(status=429, headers={"Retry-After": "0.1"})
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/api", rate_limited_handler)

    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=True)
    client = await aiohttp_client(app, middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert 0.08 <= elapsed < 0.5


async def test_retry_after_missing_header(aiohttp_client: AiohttpClient) -> None:
    """A 429 without a ``Retry-After`` header is returned without sleeping."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=429)

    app = web.Application()
    app.router.add_get("/api", handler)
    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=True)
    client = await aiohttp_client(app, middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert elapsed < 0.5  # nothing to wait on


async def test_retry_after_non_numeric(aiohttp_client: AiohttpClient) -> None:
    """A non-numeric ``Retry-After`` (HTTP-date) is ignored without sleeping."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(
            status=429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
        )

    app = web.Application()
    app.router.add_get("/api", handler)
    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=True)
    client = await aiohttp_client(app, middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert elapsed < 0.5  # an HTTP-date is not parsed as seconds


async def test_retry_after_disabled(aiohttp_client: AiohttpClient) -> None:
    """With ``respect_retry_after=False`` a 429 + ``Retry-After`` is not honored."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=429, headers={"Retry-After": "5"})

    app = web.Application()
    app.router.add_get("/api", handler)
    middleware = RateLimitMiddleware(rate=100.0, burst=10, respect_retry_after=False)
    client = await aiohttp_client(app, middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert elapsed < 0.5  # respect_retry_after=False, so Retry-After: 5 is ignored


# --- Input validation -------------------------------------------------------


@pytest.mark.parametrize("rate", [0.0, -1.0, -0.5, float("nan"), float("inf"), 5e-324])
def test_invalid_rate_raises(rate: float) -> None:
    """A non-positive, non-finite, or too-small rate is rejected eagerly.

    ``nan``/``inf`` pass a plain ``rate <= 0`` check, and the subnormal
    ``5e-324`` overflows ``1.0 / rate`` to ``inf`` -- each would silently
    disable throttling if accepted.
    """
    with pytest.raises(ValueError, match="rate"):
        TokenBucket(rate=rate, burst=1)
    with pytest.raises(ValueError, match="rate"):
        RateLimitMiddleware(rate=rate)


@pytest.mark.parametrize("burst", [0, -1])
def test_invalid_burst_raises(burst: int) -> None:
    """A burst below 1 is rejected at construction time."""
    with pytest.raises(ValueError, match="burst"):
        TokenBucket(rate=10.0, burst=burst)
    with pytest.raises(ValueError, match="burst"):
        RateLimitMiddleware(burst=burst)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), -1.0])
def test_invalid_max_retry_after_raises(value: float) -> None:
    """A non-finite or negative max_retry_after is rejected at construction."""
    with pytest.raises(ValueError, match="max_retry_after"):
        RateLimitMiddleware(max_retry_after=value)


@pytest.mark.parametrize("value", [None, 0.0, 0.5, 300.0])
def test_valid_max_retry_after_accepted(value: "float | None") -> None:
    """None and any non-negative finite max_retry_after are accepted."""
    middleware = RateLimitMiddleware(max_retry_after=value)
    assert middleware.max_retry_after == value


# --- Retry-After edge cases -------------------------------------------------


@pytest.mark.parametrize("value", ["inf", "Infinity", "-inf", "nan", "0", "-5"])
async def test_retry_after_non_finite_or_nonpositive_ignored(
    aiohttp_client: AiohttpClient, value: str
) -> None:
    """inf/nan and non-positive Retry-After values must never make us sleep."""
    middleware = RateLimitMiddleware(rate=100.0, burst=10)
    client = await aiohttp_client(_retry_after_app(value), middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert elapsed < 0.2  # returned promptly, not stalled by a hostile header


async def test_retry_after_clamped_to_max(aiohttp_client: AiohttpClient) -> None:
    """A huge Retry-After is clamped down to ``max_retry_after``."""
    middleware = RateLimitMiddleware(rate=100.0, burst=10, max_retry_after=0.1)
    client = await aiohttp_client(_retry_after_app("3600"), middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert 0.08 <= elapsed < 0.5  # slept the 0.1s cap, not the requested hour


async def test_retry_after_without_cap(aiohttp_client: AiohttpClient) -> None:
    """``max_retry_after=None`` disables the clamp; a short wait is still honored."""
    middleware = RateLimitMiddleware(rate=100.0, burst=10, max_retry_after=None)
    client = await aiohttp_client(_retry_after_app("0.1"), middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert 0.08 <= elapsed < 0.5  # honored the ~0.1s wait with no cap applied


async def test_retry_after_sleep_disabled_by_zero_cap(
    aiohttp_client: AiohttpClient,
) -> None:
    """``max_retry_after=0.0`` disables the Retry-After sleep entirely."""
    middleware = RateLimitMiddleware(rate=100.0, burst=10, max_retry_after=0.0)
    client = await aiohttp_client(_retry_after_app("5"), middlewares=(middleware,))

    start = time.monotonic()
    resp = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp.status == 429
    assert elapsed < 0.5  # would be ~5s if the header were honored


# --- Per-domain vs global bucket selection ----------------------------------


def test_per_domain_uses_distinct_buckets() -> None:
    """``per_domain=True`` yields one bucket per host, reused per host."""
    middleware = RateLimitMiddleware(rate=10.0, burst=1, per_domain=True)

    bucket_a = middleware._get_bucket(_fake_request("a.example"))
    bucket_b = middleware._get_bucket(_fake_request("b.example"))
    bucket_a_again = middleware._get_bucket(_fake_request("a.example"))

    assert bucket_a is not bucket_b  # distinct hosts -> isolated buckets
    assert bucket_a is bucket_a_again  # same host -> same bucket
    assert len(middleware._domain_buckets) == 2


def test_global_mode_shares_one_bucket() -> None:
    """``per_domain=False`` (default) funnels every host through one bucket."""
    middleware = RateLimitMiddleware(rate=10.0, burst=1, per_domain=False)

    bucket_a = middleware._get_bucket(_fake_request("a.example"))
    bucket_b = middleware._get_bucket(_fake_request("b.example"))

    assert bucket_a is bucket_b is middleware._global_bucket
    assert len(middleware._domain_buckets) == 0


# --- Scheduler invariants ---------------------------------------------------


async def test_drift_cap_limits_idle_burst() -> None:
    """Idle time must not accumulate more than ``burst`` free slots."""
    bucket = TokenBucket(rate=10.0, burst=2)  # interval 0.1s
    await bucket.acquire()
    await bucket.acquire()  # drain the two burst tokens
    await asyncio.sleep(0.25)  # idle far longer than burst * interval

    start = time.monotonic()
    for _ in range(2):
        await bucket.acquire()  # exactly *burst* acquires should be instant
    assert time.monotonic() - start < 0.05

    start = time.monotonic()
    await bucket.acquire()  # the (burst + 1)th must throttle
    assert time.monotonic() - start >= 0.08


async def test_cancelled_acquire_reclaims_slot_for_next_waiter() -> None:
    """A cancelled acquire must hand its slot to the next waiter, not waste it."""
    bucket = TokenBucket(rate=5.0, burst=1)  # interval 0.2s
    await bucket.acquire()  # drain the single burst token

    start = time.monotonic()
    ghost = asyncio.ensure_future(bucket.acquire())
    await asyncio.sleep(0)  # let the ghost queue and the scheduler start
    real = asyncio.ensure_future(bucket.acquire())
    await asyncio.sleep(0)  # let the real waiter queue behind the ghost
    await _cancel_and_join(ghost)

    await asyncio.wait_for(real, timeout=2.0)
    elapsed = time.monotonic() - start
    # The real waiter inherits the ghost's slot: served after ~1 interval
    # (0.2s), not forced to wait ~2 (0.4s) because the ghost still occupied
    # the queue.
    assert elapsed < 0.32


async def test_cancel_sole_waiter_recovers() -> None:
    """Cancelling the only waiter mid-sleep must leave the bucket usable."""
    bucket = TokenBucket(rate=10.0, burst=1)  # interval 0.1s
    await bucket.acquire()  # drain the single burst token

    sole = asyncio.ensure_future(bucket.acquire())
    await asyncio.sleep(0.02)  # let the scheduler start sleeping for it
    await _cancel_and_join(sole)

    # Let the scheduler wake into the now-empty queue (slot-reclaim path), then
    # a fresh acquire must still be served without hanging.
    await asyncio.sleep(0.12)
    await asyncio.wait_for(bucket.acquire(), timeout=1.0)


async def test_scheduler_cancelled_before_first_run_recovers() -> None:
    """A scheduler cancelled before it ever runs must not poison the bucket.

    Cancelling a task before its first step skips the coroutine body entirely,
    so the ``finally`` that normally clears ``_scheduler_task`` never runs --
    this is how a loop teardown can catch a scheduler that was just started.
    A later acquire must notice the done task and restart scheduling.
    """
    bucket = TokenBucket(rate=10.0, burst=1)
    await bucket.acquire()  # drain the burst token

    ghost = asyncio.ensure_future(bucket.acquire())
    await asyncio.sleep(0)  # the ghost queues itself and spawns the scheduler
    scheduler = bucket._scheduler_task
    assert scheduler is not None
    scheduler.cancel()  # cancelled before the scheduler's first step
    await asyncio.wait({scheduler})
    assert scheduler.cancelled()
    assert bucket._scheduler_task is scheduler  # the stale reference survives
    await _cancel_and_join(ghost)

    # A fresh acquire must restart scheduling instead of hanging forever.
    await asyncio.wait_for(bucket.acquire(), timeout=1.0)


def test_bucket_survives_abandoned_event_loop_mid_throttle() -> None:
    """A loop closed *without cancelling tasks* must not strand the bucket.

    ``run_until_complete`` + ``close`` (unlike ``asyncio.run``) never cancels
    the scheduler, so it stays suspended forever and its waiters can never be
    woken. Reusing the bucket on a fresh loop must drop those unservable
    waiters and restart scheduling rather than hang.
    """
    bucket = TokenBucket(rate=10.0, burst=1)  # interval 0.1s

    async def start_throttled_acquire() -> "asyncio.Future[None]":
        await bucket.acquire()  # instant (burst)
        pending = asyncio.ensure_future(bucket.acquire())
        await asyncio.sleep(0.02)  # the scheduler is now sleeping for it
        return pending

    async def reuse() -> None:
        # Would hang forever if the stranded scheduler or waiter were kept.
        await asyncio.wait_for(bucket.acquire(), timeout=1.0)
        throttled = asyncio.ensure_future(bucket.acquire())
        await asyncio.sleep(0)  # a replacement scheduler is now registered
        replacement = bucket._scheduler_task
        assert replacement is not None
        # Collect the stranded scheduler *while the replacement runs*: it
        # pins itself through a reference cycle with its own task, and
        # closing it runs its ``finally``, which must not clear the
        # replacement's registration.
        gc.collect()
        assert bucket._scheduler_task is replacement
        await asyncio.wait_for(throttled, timeout=1.0)

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            loop = asyncio.new_event_loop()
            pending = loop.run_until_complete(start_throttled_acquire())
            loop.close()  # abandoned: neither pending task was cancelled
            assert not pending.cancelled()
            asyncio.run(reuse())
        except Exception as exc:  # deadlock/timeout is surfaced by the asserts
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=5.0)

    assert not thread.is_alive(), "acquire after loop abandonment deadlocked"
    assert not errors, f"worker raised: {errors[0]!r}"


def test_bucket_survives_event_loop_teardown_mid_throttle() -> None:
    """A bucket reused on a new loop must not deadlock after the first loop was
    torn down while a request was still throttled.

    Both loops run in a worker thread so the nested ``asyncio.run`` calls stay
    isolated from the test session's own event loop.
    """
    bucket = TokenBucket(rate=10.0, burst=1)  # interval 0.1s

    async def first_loop() -> None:
        await bucket.acquire()  # instant (burst)
        # Queue a second acquire and let the scheduler start sleeping for it;
        # returning here makes asyncio.run cancel the pending scheduler task.
        pending = asyncio.ensure_future(bucket.acquire())
        await asyncio.sleep(0.02)
        await _cancel_and_join(pending)

    async def second_loop() -> None:
        # Would hang forever if the scheduler reference were stranded True.
        await asyncio.wait_for(bucket.acquire(), timeout=1.0)

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            asyncio.run(first_loop())
            asyncio.run(second_loop())
        except Exception as exc:  # deadlock/timeout is surfaced by the asserts
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=5.0)

    assert not thread.is_alive(), "acquire on the second loop deadlocked"
    assert not errors, f"worker raised: {errors[0]!r}"
