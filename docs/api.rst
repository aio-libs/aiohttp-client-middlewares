API reference
=============

.. module:: aiohttp_client_middlewares

This page documents the public API of ``aiohttp-client-middlewares``.


Digest authentication
----------------------

.. class:: DigestAuthMiddleware(login, password, preemptive=True)

   HTTP digest authentication client middleware.

   :param str login: login
   :param str password: password
   :param bool preemptive: Enable preemptive authentication (default: ``True``)

   This middleware implements HTTP Digest Authentication according to
   :rfc:`7616`. It supports both ``auth`` and ``auth-int`` quality of
   protection (qop) modes and a variety of hashing algorithms (MD5, SHA,
   SHA-256, SHA-512 and their session variants).

   It automatically handles the digest authentication handshake by:

   - Parsing 401 Unauthorized responses with ``WWW-Authenticate: Digest``
     headers.
   - Generating the appropriate ``Authorization: Digest`` header on retry.
   - Maintaining nonce counts and challenge data per request.
   - Reusing authentication credentials for subsequent requests to the same
     protection space when ``preemptive=True`` (following :rfc:`7616`
     Section 3.6).

   **Preemptive authentication**

   By default (``preemptive=True``) the middleware remembers successful
   authentication challenges and automatically includes the ``Authorization``
   header in subsequent requests to the same protection space. This avoids an
   extra round trip and matches how modern web browsers handle digest
   authentication.

   If the server rejects the nonce as expired (a second 401, typically with
   ``stale=true``), the middleware reissues the request once using the
   refreshed challenge.

   To disable preemptive authentication and require a 401 challenge for every
   request, set ``preemptive=False``::

       # Default behavior - preemptive auth enabled
       digest = DigestAuthMiddleware(login="user", password="pass")

       # Disable preemptive auth - always wait for the 401 challenge
       digest = DigestAuthMiddleware(login="user", password="pass", preemptive=False)

   **Origin scoping**

   The credentials are scoped to the origin of the first request the middleware
   handles. A request to a different origin is passed through untouched, so it
   never receives a digest response computed from those credentials, unless that
   origin falls within a protection space the anchor origin advertised through
   the :rfc:`7616` ``domain`` directive. Make the first request through the
   middleware against the intended origin, as the anchor is pinned to it and not
   reset for the life of the instance.

   **Usage**

   ::

       from aiohttp import ClientSession
       from aiohttp_client_middlewares import DigestAuthMiddleware

       digest = DigestAuthMiddleware(login="user", password="pass")
       async with ClientSession(middlewares=(digest,)) as session:
           # The middleware automatically handles the digest auth handshake.
           async with session.get("http://protected.example.com") as resp:
               assert resp.status == 200


Rate limiting
-------------

.. class:: RateLimiter()

   Abstract base class for rate-limit algorithms, and the type
   :class:`RateLimitMiddleware` accepts. Implementations provide async
   ``acquire()``, which reserves a slot and returns its delay as a non-negative
   finite number of seconds -- ``wait()`` takes that on trust -- and
   ``clone(host)``, which returns a fresh limiter with the same configuration
   scoped to one host (called when per-domain mode first meets a host; a
   racing thread's extra clone is discarded, so it should have no side
   effects)::

       class RedisLimiter(RateLimiter):
           def __init__(self, redis, key, script):
               self._redis, self._key, self._script = redis, key, script

           async def acquire(self):
               # An atomic script reserves the next slot and returns the delay
               # in milliseconds: Redis turns Lua numbers into integers, so a
               # fractional second cannot come back as one.
               ms = await self._redis.evalsha(self._script, 1, self._key)
               return ms / 1000

           def clone(self, host):
               return RedisLimiter(self._redis, f"{self._key}:{host}", self._script)

   Putting *host* in the key is what makes ``per_domain=True`` mean a budget
   per host for a shared backend; a limiter that keeps its state in-process,
   like :class:`TokenBucket`, has nothing to key and can ignore it. Redirects
   pick hosts too, so give those keys an expiry of their own rather than let a
   shared backend keep one for every host ever seen. The sketch also leaves
   ``release()`` at the default no-op, and a cancelled round trip can leave a
   reservation nobody holds; an expiry on each reservation covers both.

   ``wait(timeout=None)`` is supplied by the base class. It charges async
   acquisition against *timeout* once ``acquire()`` returns -- without bounding
   the call itself, so an implementation that can hang needs its own deadline --
   then fails fast when the delay exceeds what is left, sleeps otherwise, and
   calls ``release()`` if an acquired slot cannot be used. ``release()`` defaults
   to a no-op for algorithms with nothing to return, and stays synchronous: one
   of those calls is from a cancellation handler, where awaiting can be truncated
   part-way and lose the slot for good, and raising would replace the exception
   the caller is owed. A limiter that has to reach its backend to hand a slot
   back can schedule that round trip as a task.

   ``acquire()`` must be cancellation-safe: if cancellation or another
   exception prevents it from returning, it must leave no reservation behind.
   Once it returns successfully, ``wait()`` owns that cleanup. A backend whose
   reservation can outlive a cancelled network operation should use an
   idempotency key, transaction, or expiry so interrupted acquisition cannot
   leak capacity.

   An async ``acquire()`` with no suspension point still reserves atomically
   across callers on one event loop. An implementation that performs I/O
   determines its own ordering at those suspension points.

.. class:: TokenBucket(rate=10.0, burst=10)

   A :class:`RateLimiter`: tokens accrue continuously at ``rate`` per second,
   capped at ``burst``; async ``acquire()`` takes one token and the count may
   go negative, which is what queues callers up in arrival order. It contains
   no suspension point and the bucket holds no tasks or loop state.

   :param float rate: Token accrual rate, in tokens per second. Must be a
      positive, finite number.
   :param int burst: Bucket capacity. Must be at least 1.
   :raises ValueError: if ``rate`` or ``burst`` is out of range.

.. class:: RateLimitMiddleware(limiter, per_domain=False)

   Client middleware that throttles outgoing requests through a
   :class:`RateLimiter`.

   :param RateLimiter limiter: The :class:`RateLimiter` to throttle with --
      for example ``TokenBucket(rate=5.0, burst=2)``. With ``per_domain=True``
      it acts as a template: each target host gets ``limiter.clone(host)`` the
      first time that host is seen.
   :param bool per_domain: Keep an independent limiter per target host instead
      of a single global one. Limiters are keyed on the URL host only (port
      and scheme are not distinguished) and are never evicted, so only enable
      this for a bounded, trusted set of hosts. Redirects count, so the set of
      hosts is not entirely under the caller's control. Readable afterwards as
      the read-only ``per_domain`` attribute.
   :raises TypeError: if ``limiter`` is not a :class:`RateLimiter`.

   The middleware waits on the limiter before sending, so the client never
   sends faster than the limiter allows. What that ordering is worth is the
   limiter's to say: :class:`TokenBucket` grants slots in arrival order because
   its async ``acquire()`` does not suspend, while an I/O-backed limiter orders
   callers according to its backend. For :class:`TokenBucket`, cancellation is
   the one exception: a slot handed back by ``release()`` frees capacity that
   queued callers already hold fixed delays against, so two of them can
   briefly send in the same instant. When aiohttp
   exposes the request's total timeout to the middleware
   (aiohttp 3.15 and newer), a wait that would exceed it fails immediately
   with :exc:`asyncio.TimeoutError` instead of sleeping toward a guaranteed
   timeout.

   Middleware order matters: middlewares listed earlier wrap the ones listed
   later, and a middleware that retries internally (for example,
   :class:`DigestAuthMiddleware` replaying a request after a 401) re-invokes
   only the middlewares listed *after* it. List ``RateLimitMiddleware`` last so
   that every request hitting the wire -- including such replays -- is
   throttled.


   **Usage**

   .. literalinclude:: code/api.py
      :pyobject: rate_limit_usage
      :lines: 2-
      :dedent:


Retries
-------

.. class:: RetryMiddleware(*, attempts=3, \
              statuses=frozenset({408, 429, 500, 502, 503, 504}), \
              methods=frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "QUERY"}), \
              base_delay=1.0, max_delay=60.0)

   Client middleware that sends a request again after a transient failure: a
   connection that could not be opened, a response with a status such as 503,
   or a response that did not start within the read timeout.

   :param int attempts: How many times this middleware sends a request,
      including the first time. ``1`` turns its retries off. aiohttp's own
      re-send after a dropped connection (see below) runs the middlewares again
      with a fresh count, so a request can be sent up to twice ``attempts``
      times. Each redirect starts a fresh count too.
   :param statuses: Response statuses to retry, each from 400 to 599. The
      default covers a request timeout (408), throttling (429) and the server
      errors that are usually temporary (500, 502, 503 and 504).
   :type statuses: ~collections.abc.Collection of int
   :param methods: Methods that may be sent again once the request may have
      reached the server: by default the idempotent methods of :rfc:`9110` and
      ``QUERY``. The set replaces the default one, so list the default methods
      as well when adding ``POST`` or ``PATCH``, and add those only when the
      server makes them idempotent, for example with an idempotency key.
   :type methods: set of str
   :param float base_delay: Ceiling of the first wait, in seconds, never more
      than ``max_delay``. It doubles with every retry. ``0`` sends every retry
      at once, unless a ``Retry-After`` header asks for a wait.
   :param float max_delay: Longest wait before any retry, in seconds, including
      one that a ``Retry-After`` header asks for. ``0`` sends every retry at
      once and returns any response whose ``Retry-After`` asks for a wait.
   :raises ValueError: if ``attempts`` is below 1, a status is not from 400 to
      599, or a delay is negative or not finite.
   :raises TypeError: if ``attempts`` or a status is not an integer, a delay
      is not a number, or ``methods`` is a string or holds anything but
      strings.

   Whether an outcome is retried depends on whether the request may have
   reached the server:

   - A connection that could not be opened is retried for every method:
     nothing reached the server. That is :exc:`~aiohttp.ConnectionTimeoutError`,
     :exc:`~aiohttp.ClientConnectorError` other than TLS and certificate errors,
     :exc:`~aiohttp.ClientConnectionResetError` (aiohttp found the connection
     closed before writing the request) and ``ClientHttpProxyError``
     with one of ``statuses`` (a proxy refused the ``CONNECT`` of an HTTPS
     request; the proxy's ``Retry-After`` is not read, and a plain-HTTP request
     gets the proxy's answer as a response instead).
   - A response whose status is in ``statuses``, and a response that sent
     nothing for ``ClientTimeout.sock_read`` seconds
     (:exc:`~aiohttp.SocketTimeoutError`), are retried only for ``methods``:
     the server may already have acted on the request. aiohttp sets no
     ``sock_read`` by default. Without one, a server that never answers is
     waited on until the total timeout, which is never retried.
   - A connection that the server dropped or reset once the request was on its
     way (:exc:`~aiohttp.ServerDisconnectedError`, :exc:`~aiohttp.ClientOSError`)
     is left to aiohttp. aiohttp sends a ``GET``, ``HEAD``, ``OPTIONS``,
     ``TRACE``, ``PUT`` or ``DELETE`` request, and from aiohttp 3.15 a
     ``QUERY`` request, once more by itself, running the middlewares again, so
     a server that keeps dropping connections gets two sends rather than twice
     ``attempts``. Other methods, including any added to ``methods``, are not
     sent again after a dropped connection. aiohttp's ``TestClient`` turns this
     re-send off.
   - Nothing else is retried. TLS and certificate errors, other statuses, the
     request's total timeout and cancellation reach the caller untouched.

   This middleware sends a request again only when its body can be sent again:
   no body, or ``bytes``, ``str``, JSON or urlencoded-form data. aiohttp sends
   a stream that it has already sent as an empty body, without any error, and
   aiohttp 3.12.0 closes a file after sending it, so this middleware never
   sends a stream, a file or a multipart body twice. Pass the data as
   ``bytes`` to make the request retryable. aiohttp's own re-send after a
   dropped connection checks the body only from aiohttp 3.14.4, where a file
   is sent again from the start and a drained stream ends the request with the
   disconnect error; before 3.14.4 a drained stream or a file is sent again as
   an empty body (on aiohttp 3.12.0, a file fails with a bare
   :exc:`ValueError` instead). A request sent with
   ``Expect: 100-continue`` (``expect100=True``) is not sent again either,
   because aiohttp cannot send its body after a response that came before
   ``100 Continue``.

   Each retry waits a random time between zero and a ceiling that starts at
   ``base_delay`` and doubles with every retry, up to ``max_delay`` ("full
   jitter"). A ``Retry-After`` header, in seconds or as an HTTP date, sets the
   shortest wait. When it asks for longer than ``max_delay``, the response is
   returned at once rather than retried before the server is ready. A
   ``Retry-After`` that is malformed or sent more than once is ignored.

   A response that is about to be retried is released without being read, which
   closes its connection if its body has not fully arrived. When no attempt is
   left, the caller gets the last response or exception unchanged.
   ``raise_for_status``, which aiohttp applies once the middlewares have
   returned, sees only that response. If the session is closed while a request
   waits, the request ends with :exc:`~aiohttp.ClientConnectionError` when the
   wait is over.

   The request's total timeout (``ClientTimeout.total``) covers every attempt
   and every wait. When aiohttp exposes it to middlewares (aiohttp 3.15 and
   newer), a wait that would run past it is skipped and the last response or
   exception is returned at once. :class:`RateLimitMiddleware` raises
   :exc:`asyncio.TimeoutError` in that situation instead, because it has no
   response to hand back. The middleware counts the time from when aiohttp
   calls it, which leaves out earlier redirects and the sends before aiohttp's
   own re-send; after those, a wait can still end in
   :exc:`asyncio.TimeoutError`. With older aiohttp versions nothing is checked:
   keep ``(attempts - 1) * max_delay``, plus the time the attempts themselves
   take, below the total timeout, or the caller gets
   :exc:`asyncio.TimeoutError` instead of the last response.

   Middleware order matters: middlewares listed earlier wrap the ones listed
   later. List ``RetryMiddleware`` first. A :class:`DigestAuthMiddleware` listed
   after it then signs every attempt with a fresh nonce count, and a
   :class:`RateLimitMiddleware` listed last throttles every attempt. Without
   preemptive authentication (``preemptive=False``), a retry first carries the
   previous attempt's signature; a server that rejects a repeated nonce count
   answers 401 once more before the attempt is signed afresh.

   A ``Set-Cookie`` header on a response that is retried does not reach the
   session's cookie jar, because aiohttp stores cookies only from the response
   that the middlewares return.

   **Usage**

   .. literalinclude:: code/api.py
      :pyobject: retry_usage
      :lines: 2-
      :dedent:
