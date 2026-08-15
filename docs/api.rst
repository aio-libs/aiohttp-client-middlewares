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
   :class:`RateLimitMiddleware` accepts. Implementations provide the async
   ``wait(timeout=None)``, which reserves a slot and returns once the request
   may be sent -- raising :exc:`asyncio.TimeoutError` rather than waiting past
   *timeout*, which is ``None`` to wait as long as it takes -- and ``clone()``,
   which returns a fresh limiter with the same
   configuration (used once per host by per-domain mode).

   Subclass this one when reserving a slot needs I/O of its own, against Redis
   or a database say, by implementing ``wait()`` as a coroutine::

       class RedisLimiter(RateLimiter):
           def __init__(self, redis, key):
               self._redis, self._key = redis, key

           async def _reserve(self):
               while not await self._redis.set(
                   self._key, "1", nx=True, ex=1
               ):
                   await asyncio.sleep(0.05)

           async def wait(self, timeout=None):
               await asyncio.wait_for(self._reserve(), timeout)

           def clone(self):
               return RedisLimiter(self._redis, self._key)

   That sketch charges its round trips against *timeout*, and no further. A
   caller that gives up is almost always still polling, so it holds nothing to
   hand back and must not delete the key -- that would release whoever does
   hold it. An abandoned reservation instead idles out with the key's own
   expiry. Nor does the sketch order concurrent callers, whichever polls next
   wins, and its clones share one key, so under ``per_domain=True`` every host
   draws on the same limit. Ordering, prompt hand-back and per-host keys are
   the implementation's to provide if it needs them. For an algorithm that can
   reserve a slot without awaiting, subclass :class:`SyncRateLimiter` instead.

.. class:: SyncRateLimiter()

   A :class:`RateLimiter` for algorithms that reserve a slot without awaiting.
   Implementations provide the synchronous ``acquire()``, which reserves a
   slot and returns the delay, in seconds, to sleep before sending, plus
   ``clone()``; ``release()`` defaults to a no-op for algorithms that have
   nothing to return.

   ``wait()`` is supplied here and shared by every such algorithm: it acquires
   a slot, fails fast with :exc:`asyncio.TimeoutError` -- handing the slot
   back -- when the delay would exceed *timeout*, sleeps out the delay
   otherwise, and hands the slot back if the caller is cancelled mid-sleep.

   Neither ``acquire()`` nor ``release()`` may await. Their being synchronous
   is what reserves slots atomically, in arrival order, across concurrent
   callers on one event loop, and ``release()`` additionally runs from a
   cancellation handler, where an awaiting implementation can be truncated and
   lose the slot.

.. class:: TokenBucket(rate=10.0, burst=10)

   A :class:`SyncRateLimiter`: tokens accrue continuously at ``rate`` per second,
   capped at ``burst``; ``acquire()`` takes one token and the count may go
   negative, which is what queues callers up in arrival order. The bucket
   holds no tasks or loop state.

   :param float rate: Token accrual rate, in tokens per second. Must be a
      positive, finite number.
   :param int burst: Bucket capacity. Must be at least 1.
   :raises ValueError: if ``rate`` or ``burst`` is out of range.

.. class:: RateLimitMiddleware(limiter, per_domain=False)

   Client middleware that throttles outgoing requests through a
   :class:`RateLimiter`.

   :param RateLimiter limiter: The :class:`RateLimiter` to throttle with --
      for example ``TokenBucket(rate=5.0, burst=2)``. With ``per_domain=True``
      it acts as a template: each target host gets ``limiter.clone()`` the
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
   limiter's to say: a :class:`SyncRateLimiter` grants slots in arrival order,
   while a :class:`RateLimiter` implementing ``wait()`` itself orders callers
   however it chooses. Under a :class:`SyncRateLimiter`, cancellation is the
   one exception: a slot handed back by ``release()`` frees capacity that
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
