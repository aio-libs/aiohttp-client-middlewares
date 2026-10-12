"""Tests for the retry middleware."""

import asyncio
import functools
import io
import socket
import ssl
import time
from collections.abc import AsyncIterator, Callable, Collection, Iterator
from datetime import datetime, timezone
from http import HTTPStatus
from types import SimpleNamespace
from typing import cast
from unittest import mock

import aiohttp
import pytest
from aiohttp import (
    ClientConnectionError,
    ClientConnectionResetError,
    ClientConnectorCertificateError,
    ClientConnectorDNSError,
    ClientConnectorError,
    ClientConnectorSSLError,
    ClientHandlerType,
    ClientOSError,
    ClientPayloadError,
    ClientRequest,
    ClientResponse,
    ClientResponseError,
    ClientTimeout,
    ConnectionTimeoutError,
    ServerDisconnectedError,
    ServerFingerprintMismatch,
    ServerTimeoutError,
    SocketTimeoutError,
    web,
)
from aiohttp.payload import (
    AsyncIterablePayload,
    BytesIOPayload,
    BytesPayload,
    JsonPayload,
    StringPayload,
)
from multidict import CIMultiDict
from pytest_aiohttp import AiohttpClient, AiohttpServer
from yarl import URL

from aiohttp_client_middlewares import (
    DigestAuthMiddleware,
    RateLimiter,
    RateLimitMiddleware,
    RetryMiddleware,
    retry,
)

# The example date of RFC 9110, section 5.6.7, and the instant 30 s before it.
_DATE = "Sun, 06 Nov 1994 08:49:37 GMT"
_THIRTY_SECONDS_BEFORE = datetime(1994, 11, 6, 8, 49, 7, tzinfo=timezone.utc)


def _request(
    method: str = "GET",
    body: object = b"",
    timeout: ClientTimeout | None = None,
) -> ClientRequest:
    """A stand-in ``ClientRequest`` exposing what the middleware reads.

    ``timeout`` is set while the mock is untyped: ``ClientRequest.timeout``
    exists only from aiohttp 3.15, where it is a read-only property.
    """
    req = mock.create_autospec(ClientRequest, instance=True)
    req.method = method
    req.body = body
    req.headers = CIMultiDict()
    req.url = URL("http://example.com/")
    req.session = SimpleNamespace(closed=False)
    req.timeout = ClientTimeout(total=None) if timeout is None else timeout
    return req  # type: ignore[no-any-return]


def _response(status: int, *retry_after: str | bytes) -> ClientResponse:
    """A stand-in ``ClientResponse`` with one ``Retry-After`` per argument.

    A ``str`` value is sent as UTF-8, a ``bytes`` one as it is.
    """
    resp = mock.create_autospec(ClientResponse, instance=True)
    resp.status = status
    resp.raw_headers = tuple(
        (b"Retry-After", value.encode() if isinstance(value, str) else value)
        for value in retry_after
    )
    return resp  # type: ignore[no-any-return]


def _releases(response: ClientResponse) -> int:
    """How many times the middleware released a stand-in response."""
    return cast(mock.Mock, response.release).call_count


class _Handler:
    """The next handler in the chain: each call returns or raises the next outcome."""

    def __init__(
        self,
        *outcomes: ClientResponse | BaseException,
        on_call: Callable[[], None] = lambda: None,
    ) -> None:
        self._outcomes = list(outcomes)
        self._on_call = on_call
        self.calls = 0

    async def __call__(self, request: ClientRequest) -> ClientResponse:
        self.calls += 1
        self._on_call()
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the middleware's waits instead of sleeping through them."""
    waits: list[float] = []

    async def sleep(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(retry, "asyncio", SimpleNamespace(sleep=sleep))
    return waits


@pytest.fixture
def ceilings(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Make every jittered wait its ceiling, and record the ceilings."""
    drawn: list[float] = []

    def uniform(low: float, high: float) -> float:
        assert low == 0.0
        drawn.append(high)
        return high

    monkeypatch.setattr(retry, "random", SimpleNamespace(uniform=uniform))
    return drawn


class _FakeClock:
    """Stand-ins for the middleware's ``time.time`` and ``time.monotonic``."""

    def __init__(self) -> None:
        self.wall = _THIRTY_SECONDS_BEFORE.timestamp()
        self.mono = 1000.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _FakeClock:
    """Freeze the middleware's clocks, not the event loop's.

    Swapping the module reference instead of patching :func:`time.monotonic`
    keeps ``asyncio.sleep`` working (see the rate limiter's ``clock``).
    """
    fake = _FakeClock()
    monkeypatch.setattr(
        retry, "time", SimpleNamespace(time=fake.time, monotonic=fake.monotonic)
    )
    return fake


# --- Statuses, methods and attempts --------------------------------------


async def test_retries_a_transient_status(
    sleeps: list[float], ceilings: list[float]
) -> None:
    """A 503 is released and the request sent again; the 200 comes back."""
    unavailable, ok = _response(503), _response(200)
    handler = _Handler(unavailable, ok)

    assert await RetryMiddleware()(_request(), handler) is ok
    assert handler.calls == 2
    assert _releases(unavailable) == 1
    assert _releases(ok) == 0
    assert sleeps == [1.0]  # the first ceiling is base_delay


async def test_returns_the_last_response_when_attempts_run_out(
    sleeps: list[float], ceilings: list[float]
) -> None:
    """The caller gets the last response, unreleased, so it can still read it."""
    responses = [_response(503) for _ in range(3)]
    handler = _Handler(*responses)

    assert await RetryMiddleware()(_request(), handler) is responses[-1]
    assert handler.calls == 3
    assert [_releases(r) for r in responses] == [1, 1, 0]
    assert sleeps == [1.0, 2.0]


@pytest.mark.parametrize("attempts", [1, 2, 5])
async def test_attempts_count_the_first_request(
    attempts: int, sleeps: list[float]
) -> None:
    """``attempts`` is the total number of sends; ``1`` turns retries off."""
    handler = _Handler(*(_response(503) for _ in range(attempts)))

    await RetryMiddleware(attempts=attempts)(_request(), handler)

    assert handler.calls == attempts
    assert len(sleeps) == attempts - 1


@pytest.mark.parametrize("status", [200, 404, 429, 501, 505])
async def test_other_statuses_are_returned_as_they_are(
    status: int, sleeps: list[float]
) -> None:
    """Only statuses in ``statuses`` are retried; 429 is not in this one."""
    response = _response(status)
    handler = _Handler(response)

    middleware = RetryMiddleware(statuses={503})
    assert await middleware(_request(), handler) is response
    assert handler.calls == 1
    assert _releases(response) == 0


async def test_exactly_the_documented_statuses_are_retried_by_default(
    sleeps: list[float],
) -> None:
    """408, 429, 500, 502, 503 and 504, and no other status from 400 to 599."""
    request, response, ok = _request(), _response(503), _response(200)
    retried: set[int] = set()
    for status in range(400, 600):
        response.status = status
        handler = _Handler(response, ok)
        await RetryMiddleware()(request, handler)
        if handler.calls == 2:
            retried.add(status)

    assert retried == {408, 429, 500, 502, 503, 504}


@pytest.mark.parametrize("method", ["POST", "PATCH", "CONNECT"])
async def test_a_response_to_a_non_idempotent_method_is_not_retried(
    method: str, sleeps: list[float]
) -> None:
    """The server may have acted on a POST that got a 503."""
    response = _response(503)
    handler = _Handler(response)

    assert await RetryMiddleware()(_request(method), handler) is response
    assert handler.calls == 1


@pytest.mark.parametrize(
    "method", ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "QUERY"]
)
async def test_idempotent_methods_are_retried_by_default(
    method: str, sleeps: list[float]
) -> None:
    """The idempotent methods of RFC 9110, plus QUERY."""
    handler = _Handler(_response(503), _response(200))

    assert (await RetryMiddleware()(_request(method), handler)).status == 200


async def test_methods_opt_in_is_case_insensitive(sleeps: list[float]) -> None:
    """A method added in lower case still matches aiohttp's upper-case one."""
    handler = _Handler(_response(503), _response(200))

    middleware = RetryMiddleware(methods={"post"})
    assert (await middleware(_request("POST"), handler)).status == 200


async def test_empty_methods_still_retry_connections_never_opened(
    sleeps: list[float],
) -> None:
    """``methods`` gates what may have reached the server, nothing else."""
    refused = [_connector_error() for _ in range(2)]
    handler = _Handler(*refused, _response(503))
    middleware = RetryMiddleware(methods=frozenset())

    response = await middleware(_request(), handler)

    assert response.status == 503  # not retried: no method is listed
    assert handler.calls == 3


# --- Exceptions -----------------------------------------------------------


def _connector_error() -> ClientConnectorError:
    return ClientConnectorError(mock.Mock(), OSError(61, "Connection refused"))


_RETRIED_FOR_EVERY_METHOD: list[Callable[[], BaseException]] = [
    _connector_error,
    lambda: ClientConnectorDNSError(mock.Mock(), OSError(8, "nodename nor servname")),
    lambda: ConnectionTimeoutError("Connection timeout to host"),
    lambda: ClientConnectionResetError("Cannot write to closing transport"),
]
_RETRIED_FOR_LISTED_METHODS: list[Callable[[], BaseException]] = [
    lambda: SocketTimeoutError("Timeout on reading data from socket"),
]
_NEVER_RETRIED: list[Callable[[], BaseException]] = [
    lambda: ClientConnectorCertificateError(
        mock.Mock(), ssl.SSLCertVerificationError("certificate verify failed")
    ),
    lambda: ClientConnectorSSLError(mock.Mock(), ssl.SSLError(1, "wrong version")),
    lambda: ServerDisconnectedError(),
    lambda: ClientOSError(54, "Connection reset by peer"),
    lambda: ServerTimeoutError("No PONG received"),
    lambda: ServerFingerprintMismatch(b"expected", b"got", "example.com", 443),
    lambda: ClientResponseError(mock.Mock(), ()),
    lambda: ClientPayloadError("Response payload is not completed"),
    lambda: asyncio.TimeoutError(),
    lambda: ValueError("Newline or carriage return detected in headers"),
]


def _ids(factories: list[Callable[[], BaseException]]) -> list[str]:
    return [type(factory()).__name__ for factory in factories]


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "error", _RETRIED_FOR_EVERY_METHOD, ids=_ids(_RETRIED_FOR_EVERY_METHOD)
)
async def test_a_connection_never_opened_is_retried_for_every_method(
    method: str, error: Callable[[], BaseException], sleeps: list[float]
) -> None:
    """Nothing reached the server, so even a POST is safe to send again."""
    errors = [error() for _ in range(3)]
    handler = _Handler(*errors)

    with pytest.raises(type(errors[0])) as excinfo:
        await RetryMiddleware()(_request(method), handler)

    assert excinfo.value is errors[-1]  # the last error, not wrapped
    assert handler.calls == 3
    assert len(sleeps) == 2  # none after the last error


@pytest.mark.parametrize(
    ("method", "calls"), [("GET", 3), ("POST", 1)], ids=["listed", "unlisted"]
)
@pytest.mark.parametrize(
    "error", _RETRIED_FOR_LISTED_METHODS, ids=_ids(_RETRIED_FOR_LISTED_METHODS)
)
async def test_a_request_that_may_have_been_processed_is_retried_for_methods(
    method: str, calls: int, error: Callable[[], BaseException], sleeps: list[float]
) -> None:
    """The request was sent, so only ``methods`` may be sent again."""
    errors = [error() for _ in range(calls)]
    handler = _Handler(*errors)

    with pytest.raises(type(errors[0])) as excinfo:
        await RetryMiddleware()(_request(method), handler)

    assert excinfo.value is errors[-1]
    assert handler.calls == calls
    assert len(sleeps) == calls - 1


@pytest.mark.parametrize(
    "error", _RETRIED_FOR_LISTED_METHODS, ids=_ids(_RETRIED_FOR_LISTED_METHODS)
)
async def test_a_request_that_may_have_been_processed_follows_custom_methods(
    error: Callable[[], BaseException], sleeps: list[float]
) -> None:
    opted_out = _Handler(error(), _response(200))
    with pytest.raises(type(error())):
        await RetryMiddleware(methods=frozenset())(_request("GET"), opted_out)
    assert opted_out.calls == 1

    opted_in = _Handler(error(), _response(200))
    response = await RetryMiddleware(methods={"POST"})(_request("POST"), opted_in)
    assert response.status == 200


@pytest.mark.parametrize("error", _NEVER_RETRIED, ids=_ids(_NEVER_RETRIED))
async def test_other_errors_are_raised_at_once(
    error: Callable[[], BaseException], sleeps: list[float]
) -> None:
    """TLS failures, dropped connections, the total timeout and the rest.

    ``ServerDisconnectedError`` and ``ClientOSError`` are left to aiohttp,
    which re-runs the chain itself (see the plain-session test below).
    """
    handler = _Handler(error(), _response(200))

    with pytest.raises(BaseException) as excinfo:
        await RetryMiddleware()(_request(), handler)

    assert type(excinfo.value) is type(error())
    assert handler.calls == 1
    assert sleeps == []


async def test_cancellation_from_the_handler_is_not_caught(
    sleeps: list[float],
) -> None:
    """A cancelled request is never sent again."""
    handler = _Handler(asyncio.CancelledError(), _response(200))

    with pytest.raises(asyncio.CancelledError):
        await RetryMiddleware()(_request(), handler)

    assert handler.calls == 1


async def test_cancellation_during_the_wait_propagates(ceilings: list[float]) -> None:
    """Cancelling while the middleware waits cancels the request."""
    unavailable = _response(503)
    handler = _Handler(unavailable, _response(200))
    task = asyncio.ensure_future(RetryMiddleware(base_delay=30.0)(_request(), handler))
    for _ in range(100):  # until the wait is drawn; the sleep comes next
        if ceilings:
            break
        await asyncio.sleep(0)
    else:
        pytest.fail("the middleware never drew a wait")
    await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert handler.calls == 1
    assert _releases(unavailable) == 1


# --- Bodies ---------------------------------------------------------------


async def _chunks() -> AsyncIterator[bytes]:
    yield b"data"  # pragma: no cover  # never iterated


def _resendable_bodies() -> list[object]:
    return [
        b"",
        BytesPayload(b"data"),
        StringPayload("data"),
        JsonPayload({"data": 1}),
    ]


def _single_send_bodies() -> list[object]:
    writer = aiohttp.MultipartWriter()
    writer.append(b"data")
    return [
        BytesIOPayload(io.BytesIO(b"data")),
        AsyncIterablePayload(_chunks()),
        writer,
    ]


@pytest.mark.parametrize("body", _resendable_bodies(), ids=lambda b: type(b).__name__)
@pytest.mark.parametrize(
    "first", [lambda: _response(503), _connector_error], ids=["503", "refused"]
)
async def test_a_body_that_replays_is_sent_again(
    first: Callable[[], ClientResponse | BaseException],
    body: object,
    sleeps: list[float],
) -> None:
    """No body, bytes, str, JSON and form data replay byte for byte."""
    handler = _Handler(first(), _response(200))

    response = await RetryMiddleware()(_request("PUT", body), handler)

    assert response.status == 200
    assert handler.calls == 2


@pytest.mark.parametrize("body", _single_send_bodies(), ids=lambda b: type(b).__name__)
@pytest.mark.parametrize(
    "first", [lambda: _response(503), _connector_error], ids=["503", "refused"]
)
async def test_a_body_that_may_not_replay_is_sent_once(
    first: Callable[[], ClientResponse | BaseException],
    body: object,
    sleeps: list[float],
) -> None:
    """Streams, files and multipart bodies are sent once, even after a
    connection that was never opened: a middleware after this one may
    already have sent the body within the same attempt.
    """
    outcome = first()
    handler = _Handler(outcome, _response(200))

    if isinstance(outcome, BaseException):
        with pytest.raises(type(outcome)):
            await RetryMiddleware()(_request("PUT", body), handler)
    else:
        assert await RetryMiddleware()(_request("PUT", body), handler) is outcome
        assert _releases(outcome) == 0
    assert handler.calls == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "first", [lambda: _response(503), _connector_error], ids=["503", "refused"]
)
async def test_a_request_expecting_100_continue_is_sent_once(
    first: Callable[[], ClientResponse | BaseException], sleeps: list[float]
) -> None:
    """aiohttp cannot send the body again after a response that came before
    ``100 Continue`` (see the test against a server below).
    """
    request = _request("PUT", b"data")
    request.headers["Expect"] = "100-Continue"
    outcome = first()
    handler = _Handler(outcome, _response(200))

    if isinstance(outcome, BaseException):
        with pytest.raises(type(outcome)):
            await RetryMiddleware()(request, handler)
    else:
        assert await RetryMiddleware()(request, handler) is outcome
    assert handler.calls == 1


# --- Waits ----------------------------------------------------------------


async def test_the_ceiling_doubles_up_to_max_delay(
    sleeps: list[float], ceilings: list[float]
) -> None:
    """Full jitter: each wait is drawn from zero to a doubling ceiling."""
    handler = _Handler(*(_response(503) for _ in range(6)))

    await RetryMiddleware(attempts=6, base_delay=1.0, max_delay=5.0)(
        _request(), handler
    )

    assert ceilings == [1.0, 2.0, 4.0, 5.0, 5.0]
    assert sleeps == ceilings


async def test_waits_after_errors_are_jittered_too(
    sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_connector_error(), _connector_error(), _response(200))

    await RetryMiddleware()(_request(), handler)

    assert ceilings == [1.0, 2.0]
    assert sleeps == ceilings


async def test_each_request_starts_from_base_delay(
    sleeps: list[float], ceilings: list[float]
) -> None:
    """The instance holds only its configuration, so a session can share it."""
    middleware = RetryMiddleware()
    first = _Handler(_response(503), _response(503), _response(200))
    second = _Handler(_response(503), _response(200))

    await middleware(_request(), first)
    await middleware(_request(), second)

    assert ceilings == [1.0, 2.0, 1.0]


async def test_base_delay_above_max_delay_is_capped(
    sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_response(503), _response(200))

    await RetryMiddleware(base_delay=10.0, max_delay=3.0)(_request(), handler)

    assert sleeps == [3.0]


async def test_zero_max_delay_retries_at_once(
    sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_response(503), _response(503), _response(200))

    await RetryMiddleware(max_delay=0.0)(_request(), handler)

    assert sleeps == [0.0, 0.0]


async def test_many_attempts_do_not_overflow_the_ceiling(
    sleeps: list[float], ceilings: list[float]
) -> None:
    """``base_delay * 2 ** n`` overflows a float from n = 1024; doubling a
    capped ceiling never does.
    """
    attempts = 1100
    handler = _Handler(*[_response(503)] * attempts)

    await RetryMiddleware(attempts=attempts, max_delay=60.0)(_request(), handler)

    assert handler.calls == attempts
    assert sleeps[-1] == 60.0


async def test_waits_are_drawn_from_zero(sleeps: list[float]) -> None:
    """With the real RNG, waits fall between zero and the ceiling."""
    handler = _Handler(*(_response(503) for _ in range(30)))

    await RetryMiddleware(attempts=30, base_delay=1.0, max_delay=1.0)(
        _request(), handler
    )

    assert all(0.0 <= wait <= 1.0 for wait in sleeps)
    assert len(set(sleeps)) > 1  # jittered, not a constant


# --- Retry-After ----------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("120", 120.0),
        (" 120 \t", 120.0),  # aiohttp's C parser kept trailing whitespace
        ("0", 0.0),
        ("9" * 5000, float("inf")),  # int() refuses more than 4300 digits
        (_DATE, 30.0),
        ("Sunday, 06-Nov-94 08:49:37 GMT", 30.0),  # RFC 850
        ("Sun Nov  6 08:49:37 1994", 30.0),  # asctime: no zone, means UTC
        ("Sun, 06 Nov 1994 10:49:37 +0200", 30.0),  # the offset is kept
        ("Sun, 06 Nov 1994 08:48:37 GMT", 0.0),  # in the past
    ],
)
def test_retry_after_values(value: str, expected: float, clock: _FakeClock) -> None:
    assert retry._retry_after(_response(503, value)) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "soon",
        "-5",
        "+120",
        "1.5",
        "1_000",
        "１２０",  # full-width digits
        b"\xb2",  # "²" in Latin-1: isdigit() alone accepts it
        "120, 30",
        "Sun, 06 Nov 99999999999999999999 08:49:37 GMT",  # OverflowError
        "Sun Nov  6 08:49:37 99999999999999999999",  # OverflowError
        "Sun, 06 Nov 1994 08:49:37 +99999999999999999999",  # OverflowError
        "Sun, 06 Nov 1994 99:49:37 GMT",
    ],
)
def test_malformed_retry_after_is_ignored(
    value: str | bytes, clock: _FakeClock
) -> None:
    """Delay-seconds is ASCII digits only; nothing malformed raises."""
    assert retry._retry_after(_response(503, value)) is None


@pytest.fixture
def local_zone_behind_utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make the process's local time zone three hours behind UTC."""
    monkeypatch.setenv("TZ", "UTC+3")  # POSIX offsets count west of UTC
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="needs time.tzset()")
def test_a_date_without_a_zone_is_utc_in_any_local_zone(
    clock: _FakeClock, local_zone_behind_utc: None
) -> None:
    """Read as local time, the asctime date would be three hours off."""
    assert retry._retry_after(_response(503, "Sun Nov  6 08:49:37 1994")) == 30.0


@pytest.mark.parametrize(
    "values", [("1", "2"), (_DATE, _DATE)], ids=["seconds", "dates"]
)
def test_retry_after_sent_twice_is_ignored(
    values: tuple[str, str], clock: _FakeClock
) -> None:
    """RFC 9110 suggests ignoring a singleton field sent with several values."""
    assert retry._retry_after(_response(503, *values)) is None


def test_no_retry_after(clock: _FakeClock) -> None:
    assert retry._retry_after(_response(503)) is None


async def test_retry_after_is_the_shortest_wait(
    sleeps: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server's value is never jittered down."""
    monkeypatch.setattr(retry, "random", SimpleNamespace(uniform=lambda a, b: 0.0))
    handler = _Handler(_response(503, "5"), _response(200))

    await RetryMiddleware()(_request(), handler)

    assert sleeps == [5.0]


async def test_a_longer_backoff_wins_over_retry_after(
    sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_response(503, "5"), _response(200))

    await RetryMiddleware(base_delay=10.0)(_request(), handler)

    assert sleeps == [10.0]


async def test_retry_after_beyond_max_delay_returns_the_response(
    sleeps: list[float],
) -> None:
    """Retrying before the server is ready would waste the attempt."""
    response = _response(429, "120")
    handler = _Handler(response, _response(200))

    assert await RetryMiddleware(max_delay=60.0)(_request(), handler) is response
    assert handler.calls == 1
    assert sleeps == []
    assert _releases(response) == 0


async def test_retry_after_of_exactly_max_delay_is_waited(
    sleeps: list[float],
) -> None:
    handler = _Handler(_response(503, "60"), _response(200))

    assert (await RetryMiddleware(max_delay=60.0)(_request(), handler)).status == 200
    assert sleeps == [60.0]


async def test_retry_after_on_a_status_not_retried_is_ignored(
    sleeps: list[float],
) -> None:
    response = _response(501, "1")
    handler = _Handler(response, _response(200))

    assert await RetryMiddleware()(_request(), handler) is response
    assert handler.calls == 1


async def test_a_malformed_retry_after_falls_back_to_the_backoff(
    sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_response(503, "soon"), _response(200))

    await RetryMiddleware()(_request(), handler)

    assert sleeps == [1.0]


async def test_a_response_is_released_if_deciding_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whatever goes wrong after the handler returned, the connection is freed.

    aiohttp only cleans up a response the chain returns.
    """

    def broken(response: ClientResponse) -> float | None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(retry, "_retry_after", broken)
    response = _response(503, "1")

    with pytest.raises(RuntimeError, match="unexpected"):
        await RetryMiddleware()(_request(), _Handler(response))

    assert _releases(response) == 1


# --- Total timeout (aiohttp 3.15+) ----------------------------------------


async def test_a_wait_past_the_total_timeout_returns_the_response(
    clock: _FakeClock, sleeps: list[float]
) -> None:
    """Instead of waiting toward a certain ``asyncio.TimeoutError``."""
    response = _response(503, "20")
    handler = _Handler(response, _response(200))
    request = _request(timeout=ClientTimeout(total=10.0))

    assert await RetryMiddleware()(request, handler) is response
    assert sleeps == []


async def test_a_wait_within_the_total_timeout_is_kept(
    clock: _FakeClock, sleeps: list[float]
) -> None:
    handler = _Handler(_response(503, "5"), _response(200))
    request = _request(timeout=ClientTimeout(total=10.0))

    assert (await RetryMiddleware()(request, handler)).status == 200
    assert sleeps == [5.0]


async def test_time_spent_sending_counts_against_the_total_timeout(
    clock: _FakeClock, sleeps: list[float]
) -> None:
    response = _response(503, "5")
    handler = _Handler(response, _response(200), on_call=lambda: clock.advance(8.0))
    request = _request(timeout=ClientTimeout(total=10.0))

    assert await RetryMiddleware()(request, handler) is response
    assert sleeps == []


async def test_one_deadline_spans_every_attempt_and_wait(
    clock: _FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a fresh total for each attempt."""
    waits: list[float] = []

    async def sleep(delay: float) -> None:
        waits.append(delay)
        clock.advance(delay)

    monkeypatch.setattr(retry, "asyncio", SimpleNamespace(sleep=sleep))
    second = _response(503, "5")
    handler = _Handler(
        _response(503, "5"), second, _response(200), on_call=lambda: clock.advance(1.0)
    )
    request = _request(timeout=ClientTimeout(total=10.0))

    assert await RetryMiddleware()(request, handler) is second
    assert waits == [5.0]


async def test_an_error_is_raised_rather_than_waiting_past_the_total_timeout(
    clock: _FakeClock, sleeps: list[float], ceilings: list[float]
) -> None:
    handler = _Handler(_connector_error(), _response(200))
    request = _request(timeout=ClientTimeout(total=3.0))

    with pytest.raises(ClientConnectorError):
        await RetryMiddleware(base_delay=5.0)(request, handler)

    assert handler.calls == 1
    assert sleeps == []


@pytest.mark.parametrize("total", [None, 0.0, -1.0])
async def test_no_positive_total_timeout_means_no_deadline(
    total: float | None, clock: _FakeClock, sleeps: list[float]
) -> None:
    """aiohttp arms its own deadline only for a positive total."""
    handler = _Handler(_response(503, "50"), _response(200))
    request = _request(timeout=ClientTimeout(total=total))

    assert (await RetryMiddleware()(request, handler)).status == 200
    assert sleeps == [50.0]


async def test_no_deadline_without_request_timeout(
    clock: _FakeClock, sleeps: list[float]
) -> None:
    """Before aiohttp 3.15 a request carries no ``timeout`` attribute."""
    request = _request()
    delattr(request, "timeout")
    handler = _Handler(_response(503, "50"), _response(200))

    assert (await RetryMiddleware()(request, handler)).status == 200
    assert sleeps == [50.0]


# --- Construction ---------------------------------------------------------


@pytest.mark.parametrize("attempts", [0, -1])
def test_attempts_below_one_are_rejected(attempts: int) -> None:
    with pytest.raises(ValueError, match="attempts"):
        RetryMiddleware(attempts=attempts)


@pytest.mark.parametrize("attempts", [2.5, float("inf"), "3"])
def test_non_integer_attempts_are_rejected(attempts: object) -> None:
    """``inf`` must not mean "retry forever"."""
    with pytest.raises(TypeError):
        RetryMiddleware(attempts=attempts)  # type: ignore[arg-type]


@pytest.mark.parametrize("status", [100, 200, 301, 399, 600])
def test_statuses_outside_400_to_599_are_rejected(status: int) -> None:
    """A retried 3xx would never be followed: aiohttp redirects after the chain."""
    with pytest.raises(ValueError, match="statuses"):
        RetryMiddleware(statuses={status})


@pytest.mark.parametrize("status", [400, 599])
async def test_statuses_from_400_to_599_are_accepted(
    status: int, sleeps: list[float]
) -> None:
    handler = _Handler(_response(status), _response(200))

    assert (await RetryMiddleware(statuses={status})(_request(), handler)).status == 200


@pytest.mark.parametrize("status", [503.5, "503"])
def test_non_integer_statuses_are_rejected(status: object) -> None:
    """503.5 would never match a response."""
    with pytest.raises(TypeError):
        RetryMiddleware(statuses={status})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "statuses",
    [[503], (503,), range(500, 600), {HTTPStatus.SERVICE_UNAVAILABLE}],
    ids=["list", "tuple", "range", "HTTPStatus"],
)
async def test_statuses_can_be_any_collection_of_integers(
    statuses: Collection[int], sleeps: list[float]
) -> None:
    handler = _Handler(_response(503), _response(200))

    response = await RetryMiddleware(statuses=statuses)(_request(), handler)
    assert response.status == 200


def test_a_string_of_methods_is_rejected() -> None:
    """``frozenset("GET")`` would be ``{"G", "E", "T"}``."""
    with pytest.raises(TypeError, match="methods"):
        RetryMiddleware(methods="GET")  # type: ignore[arg-type]


@pytest.mark.parametrize("method", [b"GET", 1])
def test_non_string_methods_are_rejected(method: object) -> None:
    """A bytes method would never match aiohttp's ``str`` one."""
    with pytest.raises(TypeError):
        RetryMiddleware(methods={method})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "build",
    [lambda v: RetryMiddleware(base_delay=v), lambda v: RetryMiddleware(max_delay=v)],
    ids=["base_delay", "max_delay"],
)
@pytest.mark.parametrize("value", [-1.0, float("nan"), float("inf")])
def test_delays_must_be_finite_and_not_negative(
    build: Callable[[float], RetryMiddleware], value: float
) -> None:
    with pytest.raises(ValueError, match="_delay must be a finite number"):
        build(value)


def test_middleware_is_hashable_by_identity() -> None:
    """aiohttp 4 caches the middleware chain keyed on the middleware tuple."""
    first, second = RetryMiddleware(), RetryMiddleware()

    assert first != second
    assert len({first, second, first}) == 2

    @functools.lru_cache(maxsize=64)  # as aiohttp 4 builds the chain
    def chain(middlewares: tuple[RetryMiddleware, ...]) -> int:
        return len(middlewares)

    assert chain((first,)) == 1


# --- Against a server -----------------------------------------------------


class _Server:
    """Answers each request with the next status and records its body."""

    def __init__(
        self, *statuses: int, body: bytes = b"", headers: dict[str, str] | None = None
    ) -> None:
        self._statuses = list(statuses)
        self._body = body
        self._headers = headers
        self.bodies: list[bytes] = []

    async def handle(self, request: web.Request) -> web.Response:
        self.bodies.append(await request.read())
        status = self._statuses.pop(0)
        if status == 200:
            return web.Response(text="OK")
        return web.Response(status=status, body=self._body, headers=self._headers)

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("*", "/", self.handle)
        return app


class _CountSends:
    """A middleware listed after the retry one: counts the sends."""

    def __init__(self) -> None:
        self.sends = 0

    async def __call__(
        self, request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        self.sends += 1
        return await handler(request)


async def test_retries_against_a_server(aiohttp_client: AiohttpClient) -> None:
    server = _Server(503, 502, 200)
    client = await aiohttp_client(
        server.app(), middlewares=(RetryMiddleware(base_delay=0.0),)
    )

    async with client.get("/") as resp:
        assert resp.status == 200
        assert await resp.text() == "OK"
    assert len(server.bodies) == 3


async def test_a_retried_response_is_released_unread(
    aiohttp_client: AiohttpClient,
) -> None:
    """With one connection in the pool and a 503 whose body never ends,
    reading the 503 or not releasing it would leave the retry waiting until
    the timeout.
    """
    sends = 0

    async def handle(request: web.Request) -> web.StreamResponse:
        nonlocal sends
        sends += 1
        if sends > 1:
            return web.Response(text="OK")
        resp = web.StreamResponse(status=503)
        resp.enable_chunked_encoding()
        await resp.prepare(request)
        await resp.write(b"x" * 1024)
        await asyncio.Event().wait()  # cancelled when the client disconnects
        return resp  # pragma: no cover

    app = web.Application(handler_args={"handler_cancellation": True})
    app.router.add_get("/", handle)
    client = await aiohttp_client(
        app,
        connector=aiohttp.TCPConnector(limit=1),
        middlewares=(RetryMiddleware(base_delay=0.0),),
    )

    async with client.get("/", timeout=ClientTimeout(total=2.0)) as resp:
        assert resp.status == 200
    assert sends == 2


async def test_bytes_bodies_are_sent_again_unchanged(
    aiohttp_client: AiohttpClient,
) -> None:
    server = _Server(503, 200)
    client = await aiohttp_client(
        server.app(), middlewares=(RetryMiddleware(base_delay=0.0),)
    )

    async with client.put("/", data=b"payload") as resp:
        assert resp.status == 200
    assert server.bodies == [b"payload", b"payload"]


async def test_opted_in_post_with_json_is_sent_again_unchanged(
    aiohttp_client: AiohttpClient,
) -> None:
    server = _Server(503, 200)
    middleware = RetryMiddleware(methods={"POST"}, base_delay=0.0)
    client = await aiohttp_client(server.app(), middlewares=(middleware,))

    async with client.post("/", json={"id": 1}) as resp:
        assert resp.status == 200
    assert server.bodies == [b'{"id": 1}', b'{"id": 1}']


async def test_a_stream_is_not_sent_again(aiohttp_client: AiohttpClient) -> None:
    """aiohttp would send the drained stream empty, and the server accept it."""
    server = _Server(503, 200)
    client = await aiohttp_client(
        server.app(), middlewares=(RetryMiddleware(base_delay=0.0),)
    )

    async def stream() -> AsyncIterator[bytes]:
        yield b"payload"

    async with client.put("/", data=stream()) as resp:
        assert resp.status == 503
    assert server.bodies == [b"payload"]


async def test_a_file_object_is_not_sent_again(aiohttp_client: AiohttpClient) -> None:
    """aiohttp 3.12.0 closes a file after the first send."""
    server = _Server(503, 200)
    client = await aiohttp_client(
        server.app(), middlewares=(RetryMiddleware(base_delay=0.0),)
    )

    async with client.put("/", data=io.BytesIO(b"payload")) as resp:
        assert resp.status == 503
    assert server.bodies == [b"payload"]


@pytest.mark.parametrize(
    ("expect100", "headers"),
    [(True, None), (False, {"Expect": "100-continue"})],
    ids=["expect100", "header"],
)
async def test_a_request_rejected_before_100_continue_is_not_sent_again(
    expect100: bool, headers: dict[str, str] | None, aiohttp_client: AiohttpClient
) -> None:
    """A second send would never write its body: it would hang, or fail with
    an error that is not a ClientError.
    """
    rejected = 0

    async def reject(request: web.Request) -> web.Response:
        nonlocal rejected
        rejected += 1
        return web.Response(status=503)

    async def handle(request: web.Request) -> web.Response:
        return web.Response(text="OK")  # pragma: no cover  # never reached

    app = web.Application()
    app.router.add_put("/", handle, expect_handler=reject)
    client = await aiohttp_client(app, middlewares=(RetryMiddleware(base_delay=0.0),))

    async with client.put(
        "/",
        data=b"payload",
        expect100=expect100,
        headers=headers,
        timeout=ClientTimeout(total=5.0),
    ) as resp:
        assert resp.status == 503
    assert rejected == 1


async def test_raise_for_status_sees_only_the_final_response(
    aiohttp_client: AiohttpClient,
) -> None:
    """aiohttp checks the status after the middleware chain has returned."""
    server = _Server(503, 200, 503, 503, 503)
    client = await aiohttp_client(
        server.app(),
        raise_for_status=True,
        middlewares=(RetryMiddleware(base_delay=0.0),),
    )

    async with client.get("/") as resp:
        assert resp.status == 200
    with pytest.raises(ClientResponseError) as excinfo:
        await client.get("/")
    assert excinfo.value.status == 503
    assert len(server.bodies) == 5


async def test_every_attempt_goes_through_a_later_rate_limiter(
    aiohttp_client: AiohttpClient,
) -> None:
    """Listed after RetryMiddleware, the limiter throttles every send."""

    class Counting(RateLimiter):
        def __init__(self) -> None:
            self.acquired = 0

        async def acquire(self) -> float:
            self.acquired += 1
            return 0.0

        def clone(self, host: str, /) -> "Counting":
            raise NotImplementedError  # pragma: no cover

    limiter = Counting()
    server = _Server(503, 503, 200)
    client = await aiohttp_client(
        server.app(),
        middlewares=(RetryMiddleware(base_delay=0.0), RateLimitMiddleware(limiter)),
    )

    async with client.get("/") as resp:
        assert resp.status == 200
    assert limiter.acquired == 3


async def test_every_attempt_is_signed_afresh_by_a_later_digest_middleware(
    aiohttp_client: AiohttpClient,
) -> None:
    """Each send gets the next nonce count, which a server may require."""
    counts: list[str] = []

    async def handle(request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization")
        if auth is None:
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
            return web.Response(status=401, headers={"WWW-Authenticate": challenge})
        counts.append(auth.split("nc=")[1].split(",")[0])
        return web.Response(status=503 if len(counts) == 1 else 200)

    app = web.Application()
    app.router.add_get("/", handle)
    middlewares = (RetryMiddleware(base_delay=0.0), DigestAuthMiddleware("u", "p"))
    client = await aiohttp_client(app, middlewares=middlewares)

    async with client.get("/") as resp:
        assert resp.status == 200
    assert counts == ["00000001", "00000002"]


async def test_a_session_closed_during_a_wait_ends_the_request(
    aiohttp_server: AiohttpServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rather than with an AssertionError from aiohttp at the next send."""
    server = await aiohttp_server(_Server(503, 200).app())
    session = aiohttp.ClientSession(middlewares=(RetryMiddleware(),))

    async def sleep(delay: float) -> None:
        await session.close()

    monkeypatch.setattr(retry, "asyncio", SimpleNamespace(sleep=sleep))
    with pytest.raises(ClientConnectionError, match="Session is closed"):
        await session.get(server.make_url("/"))


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_a_refused_connection_is_retried(method: str) -> None:
    counter = _CountSends()
    middlewares = (RetryMiddleware(base_delay=0.0), counter)
    url = f"http://127.0.0.1:{_closed_port()}/"

    async with aiohttp.ClientSession(middlewares=middlewares) as session:
        with pytest.raises(ClientConnectorError):
            await session.request(method, url)

    assert counter.sends == 3


@pytest.mark.parametrize(("method", "sends"), [("GET", 2), ("POST", 1)])
async def test_dropped_connections_are_left_to_aiohttp(
    method: str, sends: int, aiohttp_server: AiohttpServer
) -> None:
    """aiohttp sends an idempotent request once more after a dropped
    connection, re-running the middleware chain; retrying here as well
    would make it 6 sends instead of 2.

    A plain session: aiohttp's TestClient turns that retry off.
    """

    async def drop(request: web.Request) -> web.StreamResponse:
        assert request.transport is not None
        request.transport.close()
        return web.Response()  # pragma: no cover  # never sent

    app = web.Application()
    app.router.add_route("*", "/", drop)
    server = await aiohttp_server(app)
    counter = _CountSends()
    middlewares = (RetryMiddleware(base_delay=0.0), counter)

    async with aiohttp.ClientSession(middlewares=middlewares) as session:
        with pytest.raises((ServerDisconnectedError, ClientOSError)):
            await session.request(method, server.make_url("/"))

    assert counter.sends == sends


async def test_aiohttp_s_own_resend_starts_a_fresh_count(
    aiohttp_server: AiohttpServer,
) -> None:
    """Two 503s, then a dropped connection: aiohttp sends the GET again by
    itself, running the middleware from its first attempt, so the request is
    sent twice ``attempts`` times. A plain session, as in the test above.
    """
    sends = 0

    async def handle(request: web.Request) -> web.Response:
        nonlocal sends
        sends += 1
        if sends == 3:
            assert request.transport is not None
            request.transport.close()
        return web.Response(status=503)

    app = web.Application()
    app.router.add_get("/", handle)
    server = await aiohttp_server(app)
    middlewares = (RetryMiddleware(base_delay=0.0),)

    async with aiohttp.ClientSession(middlewares=middlewares) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 503
    assert sends == 6


async def test_retry_after_from_a_server_is_honoured(
    aiohttp_client: AiohttpClient, sleeps: list[float]
) -> None:
    server = _Server(429, 200, headers={"Retry-After": "2"})
    client = await aiohttp_client(
        server.app(), middlewares=(RetryMiddleware(base_delay=0.0),)
    )

    async with client.get("/") as resp:
        assert resp.status == 200
    assert sleeps == [2.0]
