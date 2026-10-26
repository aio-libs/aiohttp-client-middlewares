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

:class:`SSRFConnector` protects a session against server-side request forgery
(SSRF): pass it as the session's ``connector``. It refuses to connect to any
address that is not publicly routable, judging IP literals in the URL and every
address a hostname resolves to, and it applies URL rules. Because the checks
run in the connector, they cover every request, redirect hop and
``ws_connect()``, a request-level ``middlewares=`` argument cannot skip them,
and they see the URL after any middleware has rewritten it.

.. class:: SSRFConnector(*, allowlist=None, denylist=None, exempt_hosts=None, allowed_schemes=("http", "https", "ws", "wss"), trust_proxy=False, **kwargs)

   A :class:`~aiohttp.TCPConnector` that refuses to reach non-public
   addresses.

   Loopback, private, link-local, site-local, multicast, reserved,
   unspecified and other non-global addresses are refused, as are
   carrier-grade NAT, IETF protocol assignments (``192.0.0.0/24``), 6to4 relay
   anycast (``192.88.99.0/24``), NAT64 local-use, 6to4 and Teredo ranges and
   the RFC 9637 documentation range. IPv4-mapped (``::ffff:0:0/96``) and NAT64
   (``64:ff9b::/96``) addresses are judged, and matched against rules, as the
   IPv4 address they embed, and other spellings of an IPv4 literal
   (``0x7f000001``, ``2130706433``, ``127.1``, ``127.0.0.1.``) as the address
   they reach. A URL host that is neither an IP address nor a valid hostname,
   such as one with a NUL or a space in it, is refused: a resolver could read
   it as a different host than the rules do. If any address in a DNS answer
   is refused, the whole request is refused; aiohttp connects only to the
   addresses checked here, so a second DNS answer cannot swap in another one.
   A refusal raises :exc:`SSRFError`.

   Rule entries are exact hostnames or IP addresses and CIDR networks.
   Hostnames are matched case-insensitively, with trailing dots ignored and
   IDNA normalized; there is no suffix or wildcard matching, so list each
   host. A malformed entry raises :exc:`ValueError` at construction rather than
   becoming a rule that never matches.

   :param allowlist: When given, the URL host must match one of these entries,
      and everything else is refused. ``None`` disables the check; an empty
      list refuses every request. The allowlist only narrows: an allowlisted
      internal address is still refused unless ``exempt_hosts`` covers it.
   :type allowlist: ~collections.abc.Iterable[str] | None
   :param denylist: URL hosts that are refused; checked before anything else.
      Network entries also apply to every resolved address, so a hostname that
      resolves into a denied network is refused too. Use them for sensitive
      addresses that are public, such as a cloud provider's platform address.
   :type denylist: ~collections.abc.Iterable[str] | None
   :param exempt_hosts: Internal hosts or networks that may be reached on
      purpose. A hostname exempts whatever it resolves to; an address or
      network exempts addresses inside it. Exemptions apply to every request
      made through the connector, untrusted URLs and redirect targets
      included, and a network exemption admits every hostname that resolves
      into it, so prefer hostnames, and prefer a separate session for
      internal services.
   :type exempt_hosts: ~collections.abc.Iterable[str] | None
   :param allowed_schemes: URL schemes that may be requested. aiohttp's
      :class:`~aiohttp.TCPConnector` also accepts ``tcp://`` and scheme-less
      URLs, which the default leaves out. Use ``("https", "wss")`` to require
      TLS.
   :type allowed_schemes: ~collections.abc.Iterable[str]
   :param bool trust_proxy: Behind a forward proxy the connector sees only the
      proxy, never what the target resolves to. A proxied request to a
      hostname is therefore refused unless the host is allowlisted or exempt.
      Set ``trust_proxy=True`` when the proxy itself refuses internal targets,
      as an egress proxy such as Smokescreen does. Literal-IP targets are
      checked either way.
   :raises ValueError: for a malformed rule entry.
   :raises TypeError: if a bare string is passed instead of an iterable, or a
      rule entry is not a string.

   A proxy is used when ``proxy=`` is given to the session, a request or
   ``ws_connect()``, or with ``trust_env=True`` when ``HTTP_PROXY``,
   ``HTTPS_PROXY``, ``WS_PROXY`` or ``WSS_PROXY`` is set or, on macOS and
   Windows, a system proxy is configured. A proxy on an internal address is
   refused like any other host, so exempt it by hostname, and put the same
   name on the ``denylist`` so the proxy itself cannot be requested as a
   target.

   Every other keyword argument is passed to :class:`~aiohttp.TCPConnector`.

.. function:: is_unsafe_address(address)

   Return ``True`` unless *address* is a public, globally-routable IP. Accepts
   a string or an :class:`~ipaddress.IPv4Address`/:class:`~ipaddress.IPv6Address`;
   a string that does not parse as an IP address is unsafe (fail closed), and
   any other type raises :exc:`TypeError`. This is the classification
   :class:`SSRFConnector` starts from, without any of its rules; new releases
   may classify more addresses as unsafe. It cannot protect a custom
   resolver on its own, because aiohttp does not call the resolver for
   IP-literal hosts.

.. exception:: SSRFError(host, reason, address=None)

   Raised when a request is blocked; a subclass of :exc:`aiohttp.ClientError`.
   ``host`` is the blocked host in its ASCII (punycode) form, ``reason`` says
   why, and ``address`` is the refused resolved address when a DNS answer was
   the reason. The address is left out of the message, so the message can be
   shown to users without revealing internal addresses.

   A block is a policy decision, not a network failure: do not retry it, and
   catch it before any generic ``except aiohttp.ClientError``.

**Usage**

.. literalinclude:: code/api.py
   :pyobject: ssrf_usage
   :lines: 2-
   :dedent:
