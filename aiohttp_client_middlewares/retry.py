"""Client middleware that retries requests after transient failures.

A request is sent again when its outcome is likely to be different next time:
a connection that could not be opened, a response with a status such as 503,
or a response that did not start within the read timeout. Each retry waits a
random time under an exponentially growing ceiling, and at least as long as a
``Retry-After`` header asks.
"""

import asyncio
import math
import operator
import random
import time
from collections.abc import Collection, Set as AbstractSet
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import cast

from aiohttp import (
    BytesPayload,
    ClientConnectionError,
    ClientConnectionResetError,
    ClientConnectorError,
    ClientError,
    ClientHandlerType,
    ClientHttpProxyError,
    ClientRequest,
    ClientResponse,
    ClientSSLError,
    ClientTimeout,
    ConnectionTimeoutError,
    SocketTimeoutError,
    hdrs,
)

# RFC 9110, section 9.2.2, plus QUERY, which aiohttp treats as idempotent
# from 3.15.
_IDEMPOTENT_METHODS = frozenset(
    {"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "QUERY"}
)
_TRANSIENT_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


class RetryMiddleware:
    """Client middleware that retries a request after a transient failure.

    Whether an outcome is retried depends on whether the request may have
    reached the server:

    - A connection that could not be opened (``ConnectionTimeoutError``, and
      ``ClientConnectorError`` other than TLS and certificate errors), a
      proxy that answered ``CONNECT`` with one of ``statuses``
      (``ClientHttpProxyError``), or a connection that aiohttp found closed
      before writing the request (``ClientConnectionResetError``), is retried
      for every method: nothing reached the server.
    - A response whose status is in ``statuses``, and a response that sent
      nothing for ``ClientTimeout.sock_read`` seconds
      (``SocketTimeoutError``), are retried only for ``methods``: the server
      may already have acted on the request.
    - A connection the server dropped or reset once the request was on its
      way (``ServerDisconnectedError``, ``ClientOSError``) is left to aiohttp,
      which re-runs the whole middleware chain once for its own idempotent
      methods.
    - Nothing else is retried. The request's total timeout and cancellation
      are never caught, so they reach the caller untouched.

    A request is only sent again when its body can be: no body, or bytes,
    ``str``, JSON or urlencoded-form data, and no ``Expect: 100-continue``.
    aiohttp re-sends a drained stream as an empty body without raising, so
    streams, files and multipart bodies are sent once.

    Each retry waits a random time between zero and a ceiling that starts at
    ``base_delay`` and doubles with every retry, up to ``max_delay`` ("full
    jitter"). A ``Retry-After`` header sets the shortest wait; when it asks
    for longer than ``max_delay``, the response is returned instead of being
    retried before the server is ready.

    A response that is about to be retried is released unread. When no
    attempt is left, the caller gets the last response or exception
    unchanged.

    :param int attempts: How many times this middleware sends a request,
        including the first time. ``1`` turns its retries off.
    :param statuses: Response statuses to retry, each from 400 to 599.
    :param methods: Methods that may be retried after the request may have
        reached the server. The set replaces the default one.
    :param float base_delay: Ceiling of the first wait, in seconds.
    :param float max_delay: Longest wait before any retry, in seconds,
        including one asked for by ``Retry-After``.
    :raises ValueError: if ``attempts`` is below 1, a status is not from 400
        to 599, or a delay is negative or not finite.
    :raises TypeError: if ``attempts`` or a status is not an integer, a
        delay is not a number, or ``methods`` is a string or holds anything
        but strings.
    """

    def __init__(
        self,
        *,
        attempts: int = 3,
        statuses: Collection[int] = _TRANSIENT_STATUSES,
        methods: AbstractSet[str] = _IDEMPOTENT_METHODS,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
    ) -> None:
        # operator.index() refuses floats: inf cannot mean "retry forever",
        # and 503.5 cannot be a status that never matches.
        try:
            self._attempts = operator.index(attempts)
        except TypeError:
            raise TypeError(f"attempts must be an integer, got {attempts!r}") from None
        if self._attempts < 1:
            raise ValueError(f"attempts must be >= 1, got {attempts!r}")
        checked: set[int] = set()
        for status in statuses:
            try:
                code = operator.index(status)
            except TypeError:
                raise TypeError(
                    f"statuses must hold integers, got {status!r}"
                ) from None
            # Only 4xx and 5xx can be transient: aiohttp consumes 1xx itself
            # (a 101 reaches the chain only through ws_connect), and follows
            # redirects only once the chain has returned the 3xx.
            if not 400 <= code <= 599:
                raise ValueError(f"statuses must be from 400 to 599, got {status!r}")
            checked.add(code)
        self._statuses = frozenset(checked)
        # Checked for callers without a type checker: frozenset("GET") is
        # {"G", "E", "T"}, which would silently turn off every retry that
        # depends on the method. So would a bytes method.
        if isinstance(cast(object, methods), str):
            raise TypeError(f"methods must be a set of strings, got {methods!r}")
        for method in methods:
            if not isinstance(cast(object, method), str):
                raise TypeError(f"methods must hold strings, got {method!r}")
        # aiohttp upper-cases ClientRequest.method, so compare in upper case.
        self._methods = frozenset(method.upper() for method in methods)
        for name, delay in (("base_delay", base_delay), ("max_delay", max_delay)):
            # A Decimal would pass isfinite() and fail the arithmetic on the
            # first retry instead, outside __init__.
            if not isinstance(cast(object, delay), (int, float)):
                raise TypeError(f"{name} must be a number, got {delay!r}")
            if not math.isfinite(delay) or delay < 0:
                raise ValueError(f"{name} must be a finite number >= 0, got {delay!r}")
        self._base_delay = float(base_delay)
        self._max_delay = float(max_delay)

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Send the request, and send it again while the failure is transient."""
        deadline = _deadline(request)
        headers = request.headers.copy()
        ceiling = min(self._base_delay, self._max_delay)
        for _ in range(self._attempts - 1):
            try:
                response = await handler(request)
            except ClientError as exc:
                # The body is checked even after a connection that could not
                # be opened: a middleware listed after this one may already
                # have sent it within the same attempt, as DigestAuthMiddleware
                # does after a 401.
                if not (_can_resend(request) and self._is_transient(request, exc)):
                    raise
                delay = random.uniform(0.0, ceiling)
                if _ends_too_late(deadline, delay):
                    raise
            else:
                try:
                    retry_delay = self._retry_delay(
                        request, response, ceiling, deadline
                    )
                except BaseException:
                    # aiohttp only cleans up a response the chain returns;
                    # this one would keep its connection out of the pool.
                    response.release()
                    raise
                if retry_delay is None:
                    return response
                # Unread, so a large body is not downloaded; aiohttp closes
                # the connection instead of reusing it when the body has not
                # arrived yet.
                response.release()
                delay = retry_delay
            await asyncio.sleep(delay)
            if request.session.closed:
                # The next send would fail inside aiohttp with an
                # AssertionError rather than a ClientError.
                raise ClientConnectionError("Session is closed")
            ceiling = min(ceiling * 2, self._max_delay)
            # Each attempt starts from the headers this middleware received,
            # as aiohttp's own resend starts from a fresh request. A later
            # middleware may have changed them: DigestAuthMiddleware leaves
            # its signature behind, and its nonce count must not be reused.
            request.headers.clear()
            request.headers.extend(headers)
        # The last attempt's response or exception reaches the caller as is.
        return await handler(request)

    def _is_transient(self, request: ClientRequest, exc: ClientError) -> bool:
        if isinstance(exc, ClientSSLError):
            # A subclass of ClientConnectorError. Most TLS and certificate
            # failures are permanent (a bad certificate, a protocol mismatch),
            # and a retry would only repeat the handshake.
            return False
        if isinstance(
            exc,
            (ClientConnectorError, ConnectionTimeoutError, ClientConnectionResetError),
        ):
            # Nothing reached the server: the connection was never opened, or
            # aiohttp found it closed before writing the request. A reset
            # while the body is being written is a ClientOSError instead.
            return True
        if isinstance(exc, ClientHttpProxyError):
            # The proxy refused to open the tunnel for an HTTPS request, so
            # the origin saw nothing. A plain-HTTP request gets the proxy's
            # answer as a response instead, which follows the status rules.
            return exc.status in self._statuses
        if isinstance(exc, SocketTimeoutError):
            # The request was sent and may have been acted on.
            return request.method in self._methods
        return False

    def _retry_delay(
        self,
        request: ClientRequest,
        response: ClientResponse,
        ceiling: float,
        deadline: float | None,
    ) -> float | None:
        """Return how long to wait before retrying, or ``None`` not to retry."""
        if (
            response.status not in self._statuses
            or request.method not in self._methods
            or not _can_resend(request)
        ):
            return None
        delay = random.uniform(0.0, ceiling)
        retry_after = _retry_after(response)
        if retry_after is not None:
            if retry_after > self._max_delay:
                # Retrying sooner than the server asked would most likely
                # waste the attempt; the caller gets the hint instead.
                return None
            delay = max(delay, retry_after)
        if _ends_too_late(deadline, delay):
            return None
        return delay


def _can_resend(request: ClientRequest) -> bool:
    """Whether aiohttp sends this request the same way a second time.

    Bytes, ``str``, JSON and urlencoded-form bodies are ``BytesPayload`` and
    replay byte for byte on every supported aiohttp version; ``b""`` is the
    empty body on aiohttp 3 (on aiohttp 4 it is a ``BytesPayload``). An async
    iterable is sent empty the second time, with no error, and aiohttp 3.12.0
    closes a file after the first send, so the rest are sent once.

    aiohttp waits for ``100 Continue`` on a future that it creates once per
    request. A response that comes before it cancels the future, so a second
    send never writes its body: it hangs, or fails with an error that is not
    a ``ClientError``.
    """
    return (
        isinstance(request.body, (bytes, BytesPayload))
        and request.headers.get(hdrs.EXPECT, "").lower() != "100-continue"
    )


def _retry_after(response: ClientResponse) -> float | None:
    """Return the wait a ``Retry-After`` header asks for, in seconds.

    ``None`` when there is no usable value. Never raises: anything malformed
    is ignored, as RFC 9110, section 16.3.2.2, suggests for a singleton field
    sent with several values. ``raw_headers`` keeps each field apart and
    unparsed on every aiohttp version; aiohttp 4's ``headers`` splits values
    at commas, which an HTTP date contains.
    """
    values = [
        value for name, value in response.raw_headers if name.lower() == b"retry-after"
    ]
    if len(values) != 1:
        return None
    # aiohttp's C parser kept trailing whitespace in field values before 3.14.4.
    value = values[0].decode("latin-1").strip(" \t")
    if value.isascii() and value.isdigit():
        # delay-seconds. float() rather than int(), which refuses more than
        # 4300 digits; a value that long becomes inf and exceeds any cap.
        return float(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            # The asctime format carries no zone and is UTC (RFC 9110,
            # section 5.6.7).
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        # OverflowError: numeric fields far too large for a date.
        return None


def _deadline(request: ClientRequest) -> float | None:
    """Return when the request's total timeout runs out, if it is known.

    ``ClientRequest.timeout`` is public and read-only from aiohttp 3.15
    (aio-libs/aiohttp#13176); earlier releases have no such attribute, so
    there is no deadline to check. The annotation keeps the value
    type-checked even though the attribute cannot be resolved statically on
    3.12 to 3.14. Dropping the getattr() is gated on raising the floor to
    3.15, as in RateLimitMiddleware (#23).

    aiohttp arms the timeout once per session request and calls the
    middlewares again for every redirect and for its own re-send after a
    dropped connection, so a later call misses the time already spent. The
    first call can be up to a second early instead: aiohttp rounds its
    deadline up to a whole second when the total is at least
    ``ClientTimeout.ceil_threshold`` (5 s by default).
    """
    client_timeout: ClientTimeout | None = getattr(request, "timeout", None)
    total = None if client_timeout is None else client_timeout.total
    if total is None or total <= 0.0:
        # aiohttp arms its own deadline only for a positive total.
        return None
    return time.monotonic() + total


def _ends_too_late(deadline: float | None, delay: float) -> bool:
    """Whether waiting ``delay`` seconds would run into the total timeout.

    Waiting would end in ``asyncio.TimeoutError``, give or take aiohttp's
    rounding of its deadline, so the outcome in hand is handed back instead.
    """
    return deadline is not None and time.monotonic() + delay >= deadline
