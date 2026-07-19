"""Tests for the rate-limiting middleware."""

import asyncio
import time
from unittest import mock

import aiohttp
import pytest
from aiohttp import ClientRequest, ClientResponse, web
from pytest_aiohttp import AiohttpClient
from yarl import URL

from aiohttp_client_middlewares.rate_limit import (
    RateLimiter,
    RateLimitMiddleware,
    TokenBucket,
)


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


async def test_wait_timeout_bail_returns_slot(clock: _FakeClock) -> None:
    """A doomed wait raises TimeoutError without consuming a slot."""
    bucket = TokenBucket(rate=10.0, burst=1)
    bucket.acquire()
    with pytest.raises(asyncio.TimeoutError):
        await bucket.wait(timeout=0.05)  # would need 0.1s
    # The failed wait handed its token back: the next caller owes one
    # interval, not two.
    assert bucket.acquire() == pytest.approx(0.1)


async def test_wait_within_timeout_sleeps_out_the_delay() -> None:
    """A delay inside the timeout budget is granted normally."""
    bucket = TokenBucket(rate=1000.0, burst=1)
    bucket.acquire()
    await bucket.wait(timeout=1.0)  # ~1ms delay, well within budget


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
    middleware = RateLimitMiddleware(TokenBucket(rate=50.0, burst=2))
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
    middleware = RateLimitMiddleware(TokenBucket(rate=100.0, burst=1), per_domain=True)
    client = await aiohttp_client(_make_app(), middlewares=(middleware,))

    start = time.monotonic()
    # Same host, so the two requests share a bucket and the second one waits.
    resp1 = await client.get("/api")
    resp2 = await client.get("/api")
    elapsed = time.monotonic() - start

    assert resp1.status == 200
    assert resp2.status == 200
    assert 0.005 <= elapsed < 0.5


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


@pytest.mark.parametrize("burst", [0, -1])
def test_invalid_burst_raises(burst: int) -> None:
    """A burst below 1 is rejected at construction time."""
    with pytest.raises(ValueError, match="burst"):
        TokenBucket(rate=10.0, burst=burst)


# --- Per-domain vs global bucket selection ----------------------------------


def test_per_domain_uses_distinct_limiters() -> None:
    """``per_domain=True`` yields one limiter per host, reused per host."""
    middleware = RateLimitMiddleware(TokenBucket(rate=10.0, burst=1), per_domain=True)

    limiter_a = middleware._get_limiter(_fake_request("a.example"))
    limiter_b = middleware._get_limiter(_fake_request("b.example"))
    limiter_a_again = middleware._get_limiter(_fake_request("a.example"))

    assert limiter_a is not limiter_b  # distinct hosts -> isolated limiters
    assert limiter_a is limiter_a_again  # same host -> same limiter
    assert len(middleware._domain_limiters) == 2


def test_global_mode_shares_one_limiter() -> None:
    """Without ``per_domain`` every host goes through the one limiter."""
    middleware = RateLimitMiddleware(TokenBucket(rate=10.0, burst=1))

    limiter_a = middleware._get_limiter(_fake_request("a.example"))
    limiter_b = middleware._get_limiter(_fake_request("b.example"))

    assert limiter_a is limiter_b is middleware._global_limiter


# --- New-design behavior ------------------------------------------------------


async def test_middleware_early_bail_on_timeout(aiohttp_client: AiohttpClient) -> None:
    """A request whose wait exceeds its total timeout fails promptly.

    On aiohttp versions that expose the request timeout to middlewares the
    limiter bails before sleeping at all; on today's 3.x the session's own
    total timeout fires at 0.1s. Either way the caller gets a prompt
    ``asyncio.TimeoutError`` rather than a full 1s limiter sleep.
    """
    middleware = RateLimitMiddleware(TokenBucket(rate=1.0, burst=1))  # 1s apart
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
    middleware = RateLimitMiddleware(TokenBucket(rate=1.0, burst=1))  # 1s apart
    request = _fake_request("example.com")
    request._timeout = aiohttp.ClientTimeout(total=0.05)  # type: ignore[attr-defined]

    async def handler(req: ClientRequest) -> ClientResponse:
        raise AssertionError("a doomed request must never be sent")

    bucket = middleware._global_limiter
    assert bucket is not None
    assert bucket.acquire() == 0.0  # drain the burst slot

    start = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await middleware(request, handler)
    assert time.monotonic() - start < 0.5  # bailed, did not sleep ~1s
    # The doomed request handed its token back.
    assert bucket.acquire() <= 1.0


async def test_middleware_cancel_during_sleep_releases_slot() -> None:
    """A caller cancelled while sleeping hands its slot back to the bucket."""
    middleware = RateLimitMiddleware(TokenBucket(rate=5.0, burst=1))  # 0.2s interval
    request = _fake_request("example.com")
    request._timeout = aiohttp.ClientTimeout(total=None)  # type: ignore[attr-defined]

    async def handler(req: ClientRequest) -> ClientResponse:
        raise AssertionError("the cancelled request must never be sent")

    bucket = middleware._global_limiter
    assert bucket is not None
    assert bucket.acquire() == 0.0  # drain the burst slot

    task = asyncio.ensure_future(middleware(request, handler))
    await asyncio.sleep(0.05)  # the middleware is now sleeping out its delay
    task.cancel()
    await asyncio.wait({task})
    assert task.cancelled()

    # The slot went back: the next caller owes at most one interval, not two.
    assert bucket.acquire() <= 0.2


def test_limiter_injection_is_used_directly() -> None:
    """The caller-provided limiter is the one throttling, not a copy of it."""
    bucket = TokenBucket(rate=100.0, burst=1)
    middleware = RateLimitMiddleware(bucket)
    assert middleware._global_limiter is bucket


def test_non_limiter_rejected() -> None:
    """Anything that is not a RateLimiter instance is rejected eagerly."""
    with pytest.raises(TypeError, match="RateLimiter"):
        RateLimitMiddleware(lambda: TokenBucket(rate=1.0, burst=1))  # type: ignore[arg-type]


def test_token_bucket_clone_is_fresh(clock: _FakeClock) -> None:
    """``clone`` copies the configuration, never the drained state."""
    template = TokenBucket(rate=10.0, burst=2)
    template.acquire()
    template.acquire()
    assert template.acquire() > 0.0  # template drained into debt

    fresh = template.clone()
    assert fresh.acquire() == 0.0  # full burst again
    assert fresh.acquire() == 0.0
    assert fresh.acquire() == pytest.approx(0.1)  # same rate as the template


def test_token_bucket_needs_no_event_loop() -> None:
    """The bucket holds no loop state and works without a running loop."""
    bucket = TokenBucket(rate=1000.0, burst=1)
    assert bucket.acquire() == 0.0
    assert bucket.acquire() > 0.0


# --- RateLimiter base class ---------------------------------------------------


class _FixedDelay(RateLimiter):
    """Minimal limiter: fixed delay, inherits the no-op ``release``."""

    def __init__(self, delay: float) -> None:
        self._delay = delay

    def acquire(self) -> float:
        return self._delay

    def clone(self) -> "_FixedDelay":
        return _FixedDelay(self._delay)


async def test_rate_limiter_wait_zero_delay_returns_immediately() -> None:
    """A zero delay never touches the event loop's sleep."""
    start = time.monotonic()
    await _FixedDelay(0.0).wait()
    assert time.monotonic() - start < 0.05


async def test_rate_limiter_wait_cancel_uses_default_release() -> None:
    """Cancellation during the shared sleep runs the base no-op release."""
    limiter = _FixedDelay(5.0)
    task = asyncio.ensure_future(limiter.wait())
    await asyncio.sleep(0.05)  # the wait is now sleeping out its delay
    await _cancel_and_join(task)


async def test_rate_limiter_wait_timeout_uses_default_release() -> None:
    """The base timeout bail calls release(); the default no-op suffices."""
    with pytest.raises(asyncio.TimeoutError):
        await _FixedDelay(5.0).wait(timeout=0.1)
