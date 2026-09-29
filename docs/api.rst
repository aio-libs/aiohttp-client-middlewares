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

SSRF protection
---------------

Server-side request forgery (SSRF) protection comes as two cooperating
layers, and both are required. :class:`SSRFConnector` is the primary control
for direct connections: it validates every address a request would actually
connect to -- IP-literals and DNS answers alike, on the initial request and on
every redirect hop -- so a hostname that *resolves* to an internal address is
stopped at connect time. :class:`SSRFMiddleware` is the URL-level layer; it
never sees resolved addresses, so it cannot be the sole control, but it is the
only layer that can constrain the target when a forward proxy is configured
(see the note on :class:`SSRFConnector`).

.. class:: SSRFConnector(*, exempt_hosts=None, **kwargs)

   A :class:`~aiohttp.TCPConnector` that refuses to connect to non-public
   addresses.

   Loopback, private, link-local, site-local, multicast, reserved,
   unspecified and other non-global addresses are blocked, as are
   carrier-grade NAT, NAT64 local-use, 6to4 and Teredo ranges and the RFC
   9637 documentation range. IPv4-mapped (``::ffff:0:0/96``) and NAT64
   (``64:ff9b::/96``) addresses are judged, and matched against rules, as
   the IPv4 address they embed. A blocked address raises :exc:`SSRFError`.

   .. note::
      When a forward proxy is configured (``proxy=`` on the request, or
      ``trust_env=True`` with ``HTTP_PROXY``/``HTTPS_PROXY`` set), only the
      *proxy* endpoint is resolved and validated here; the target is resolved
      by the proxy and is never seen. Constrain proxied targets with
      :class:`SSRFMiddleware` and an ``allowlist``.

      A proxy on an internal address is blocked like any other host, so
      exempt it by hostname; exempting its IP address or network would also
      exempt every name that resolves into it. The exemption covers that host
      on every port, so also put the name on the middleware's ``denylist``,
      which checks request targets and never the proxy, to keep the proxy
      itself from being requested as a target.

   :param exempt_hosts: Entries exempted from blocking, layered on top of the
      default public-only policy. Note this is the *opposite* sense to
      :class:`SSRFMiddleware`'s restrictive ``allowlist``: it never narrows
      what is reachable, so an empty value still lets all public traffic
      through. An exact hostname (case-insensitive, trailing dot ignored,
      IDNA normalized) exempts everything that host resolves to; an IP address
      or CIDR network exempts resolved addresses inside it. Use this to reach
      known-internal services deliberately.
   :type exempt_hosts: iterable of str or None
   :raises ValueError: for a malformed entry, which includes an IPv4 address
      written in any form but dotted-quad (``127.1``, ``2130706433``,
      ``::ffff:127.0.0.1``).
   :raises TypeError: if a bare string is passed instead of an iterable.

   Every other keyword argument is forwarded to
   :class:`~aiohttp.TCPConnector`, which takes no positional arguments.

.. class:: SSRFMiddleware(*, allowlist=None, denylist=None, allowed_schemes=("http", "https", "ws", "wss"))

   Client middleware enforcing URL-level rules against SSRF. It runs for
   every redirect hop, so the rules also apply to redirect targets.

   A literal-IP host is checked against the same address classification the
   connector uses, failing fast before any connection -- but only when no
   ``allowlist`` is configured; with one, allowlist membership is the only
   host check performed. Non-canonical numeric forms (``0x7f000001``,
   ``2130706433``, ``127.1``, ``0177.0.0.1``) are recognized as addresses
   here too, which matters under a proxy where the connector never sees the
   target.

   :param allowlist: When given, only requests whose URL host matches one of
      these entries are allowed; ``None`` disables the allowlist, while an
      empty list blocks every request (fail closed). An entry may deliberately
      permit an internal address. Entries are exact hostnames
      (case-insensitive, trailing dot ignored, IDNA normalized) or IP
      addresses/CIDR networks matched against literal-IP URL hosts. Hostname
      matching is deliberately exact -- no substring or suffix matching -- so
      an allowlisted ``example.com`` can never be matched by ``notexample.com``.
   :type allowlist: iterable of str or None
   :param denylist: Requests whose URL host matches one of these entries are
      rejected. Same entry forms as ``allowlist``; checked first.
   :type denylist: iterable of str or None
   :param allowed_schemes: URL schemes that may pass. aiohttp rejects schemes
      its connector cannot handle before middlewares run, but
      :class:`~aiohttp.TCPConnector` handles ``tcp://`` as well as
      http/https/ws/wss, which the default leaves out. Use
      ``("https", "wss")`` to require TLS.
   :type allowed_schemes: iterable of str
   :raises ValueError: for a malformed rule entry, which includes an IPv4
      address written in any form but dotted-quad (``127.1``,
      ``2130706433``, ``::ffff:127.0.0.1``).
   :raises TypeError: if a bare string is passed instead of an iterable.

.. function:: is_unsafe_address(address)

   Return ``True`` unless *address* is a public, globally-routable IP. Accepts
   a string or an :class:`~ipaddress.IPv4Address`/:class:`~ipaddress.IPv6Address`.
   A string that does not parse as an IP address is unsafe (fail closed).
   This is the classifier both layers share; it is exported so that a custom
   resolver or connector can apply the same policy.

.. exception:: SSRFError

   Raised (a :exc:`aiohttp.ClientError` subclass) when a request is blocked.
   Carries ``host`` -- the blocked host, or the full URL with any credentials
   removed when the rejection is not host-specific -- and a human-readable
   ``reason``.

**Usage**

.. literalinclude:: code/api.py
   :pyobject: ssrf_usage
   :lines: 2-
   :dedent:
