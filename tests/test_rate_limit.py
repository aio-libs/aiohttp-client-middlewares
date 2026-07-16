"""Tests for the rate-limiting middleware."""

import asyncio
import time
from unittest import mock

import aiohttp
import pytest
from aiohttp import ClientRequest, ClientResponse, web
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


class _FakeClock:
    """A controllable stand-in for ``time.monotonic`` (sync tests only)."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _FakeClock:
    fake = _FakeClock()
    monkeypatch.setattr(time, "monotonic", fake)
    return fake


def test_token_bucket_burst_is_instant(clock: _FakeClock) -> None:
    """The first ``burst`` acquires owe no delay; the next one throttles."""
    bucket = TokenBucket(rate=10.0, burst=3)
    assert [bucket.acquire() for _ in range(3)] == [0.0, 0.0, 0.0]
    assert bucket.acquire() == pytest.approx(0.1)


def test_token_bucket_exact_fractional_delays(clock: _FakeClock) -> None:
    """Delays are the exact deficit, not rounded up to whole intervals."""
    bucket = TokenBucket(rate=10.0, burst=1)
    assert bucket.acquire() == 0.0
    assert bucket.acquire() == pytest.approx(0.1)
    clock.advance(0.05)  # half a token accrues
    assert bucket.acquire() == pytest.approx(0.15)


def test_token_bucket_queues_in_arrival_order(clock: _FakeClock) -> None:
    """Consecutive over-limit acquires owe strictly increasing delays."""
    bucket = TokenBucket(rate=10.0, burst=1)
    delays = [bucket.acquire() for _ in range(4)]
    assert delays == [0.0, pytest.approx(0.1), pytest.approx(0.2), pytest.approx(0.3)]


def test_token_bucket_refills_after_idle(clock: _FakeClock) -> None:
    """Idle time replenishes tokens, capped at ``burst``."""
    bucket = TokenBucket(rate=10.0, burst=2)
    bucket.acquire()
    bucket.acquire()  # drained
    clock.advance(10.0)  # far more than burst * interval
    assert bucket.acquire() == 0.0
    assert bucket.acquire() == 0.0  # exactly *burst* free slots accrued
    assert bucket.acquire() == pytest.approx(0.1)  # the cap held


def test_token_bucket_timeout_bail_returns_token(clock: _FakeClock) -> None:
    """A doomed acquire raises TimeoutError and does not consume a slot."""
    bucket = TokenBucket(rate=10.0, burst=1)
    bucket.acquire()
    with pytest.raises(asyncio.TimeoutError):
        bucket.acquire(timeout=0.05)  # would need 0.1s
    # The failed acquire handed its token back: the next caller owes one
    # interval, not two.
    assert bucket.acquire() == pytest.approx(0.1)


def test_token_bucket_acquire_within_timeout(clock: _FakeClock) -> None:
    """A delay inside the timeout budget is granted normally."""
    bucket = TokenBucket(rate=10.0, burst=1)
    bucket.acquire()
    assert bucket.acquire(timeout=1.0) == pytest.approx(0.1)


def test_token_bucket_release_returns_token(clock: _FakeClock) -> None:
    """``release`` gives an unused slot back to the pool."""
    bucket = TokenBucket(rate=10.0, burst=1)
    bucket.acquire()
    bucket.acquire()  # goes into debt
    bucket.release()
    assert bucket.acquire() == pytest.approx(0.1)  # debt was cancelled


def test_token_bucket_release_caps_at_burst(clock: _FakeClock) -> None:
    """``release`` never grows the bucket beyond ``burst``."""
    bucket = TokenBucket(rate=10.0, burst=1)
    bucket.release()  # already full
    assert bucket.acquire() == 0.0
    assert bucket.acquire() == pytest.approx(0.1)  # only one free slot existed


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


# --- New-design behavior ------------------------------------------------------


async def test_middleware_early_bail_on_timeout(aiohttp_client: AiohttpClient) -> None:
    """A request whose wait exceeds its total timeout fails promptly.

    On aiohttp versions that expose the request timeout to middlewares the
    limiter bails before sleeping at all; on today's 3.x the session's own
    total timeout fires at 0.1s. Either way the caller gets a prompt
    ``asyncio.TimeoutError`` rather than a full 1s limiter sleep.
    """
    middleware = RateLimitMiddleware(rate=1.0, burst=1)  # 1s between requests
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    resp = await client.get("/api")  # consumes the burst slot
    assert resp.status == 200

    start = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await client.get("/api", timeout=aiohttp.ClientTimeout(total=0.1))
    elapsed = time.monotonic() - start
    assert elapsed < 0.5  # never slept out the limiter's ~1s delay


async def test_middleware_bails_before_sleeping_when_timeout_known() -> None:
    """With the request timeout visible, the limiter fails without sleeping."""
    middleware = RateLimitMiddleware(rate=1.0, burst=1)  # 1s between requests
    request = _fake_request("example.com")
    request._timeout = aiohttp.ClientTimeout(total=0.05)  # type: ignore[attr-defined]

    async def handler(req: ClientRequest) -> ClientResponse:
        raise AssertionError("a doomed request must never be sent")

    bucket = middleware._global_bucket
    assert bucket.acquire() == 0.0  # drain the burst slot

    start = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await middleware(request, handler)
    assert time.monotonic() - start < 0.5  # bailed, did not sleep ~1s
    # The doomed request handed its token back.
    assert bucket.acquire() <= 1.0


async def test_middleware_cancel_during_sleep_releases_slot() -> None:
    """A caller cancelled while sleeping hands its slot back to the bucket."""
    middleware = RateLimitMiddleware(rate=5.0, burst=1)  # 0.2s interval
    request = _fake_request("example.com")
    request._timeout = aiohttp.ClientTimeout(total=None)  # type: ignore[attr-defined]

    async def handler(req: ClientRequest) -> ClientResponse:
        raise AssertionError("the cancelled request must never be sent")

    bucket = middleware._global_bucket
    assert bucket.acquire() == 0.0  # drain the burst slot

    task = asyncio.ensure_future(middleware(request, handler))
    await asyncio.sleep(0.05)  # the middleware is now sleeping out its delay
    task.cancel()
    await asyncio.wait({task})
    assert task.cancelled()

    # The slot went back: the next caller owes at most one interval, not two.
    assert bucket.acquire() <= 0.2


def test_bucket_injection_is_used_directly() -> None:
    """A caller-provided bucket is throttling, not a copy of it."""
    bucket = TokenBucket(rate=100.0, burst=1)
    middleware = RateLimitMiddleware(bucket)
    assert middleware._global_bucket is bucket


def test_bucket_with_per_domain_rejected() -> None:
    """A single injected bucket contradicts per-domain isolation."""
    with pytest.raises(ValueError, match="mutually exclusive"):
        RateLimitMiddleware(TokenBucket(rate=1.0, burst=1), per_domain=True)


def test_token_bucket_needs_no_event_loop() -> None:
    """The bucket holds no loop state and works without a running loop."""
    bucket = TokenBucket(rate=1000.0, burst=1)
    assert bucket.acquire() == 0.0
    assert bucket.acquire() > 0.0
