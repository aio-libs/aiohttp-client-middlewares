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


SSRF protection
---------------

Server-side request forgery (SSRF) protection comes as two cooperating
layers. :class:`SSRFConnector` is the primary control for direct connections:
it validates every address a request would actually connect to -- IP-literals
and DNS answers alike, on the initial request and on every redirect hop -- so
a hostname that *resolves* to an internal address is stopped at connect time.
:class:`SSRFMiddleware` is the URL-level layer (scheme and hostname rules) with
clearer, earlier errors; it never sees resolved addresses, so it cannot be the
sole control, but it is required for scheme policing and is the only layer that
can constrain the target when a forward proxy is configured (see the note on
:class:`SSRFConnector`). Use both together.

.. class:: SSRFConnector(*args, allowlist=None, **kwargs)

   A :class:`~aiohttp.TCPConnector` that refuses to connect to non-public
   addresses.

   Loopback, private, link-local, multicast, reserved, unspecified and other
   non-global addresses are blocked, as are carrier-grade NAT, NAT64, 6to4
   and Teredo ranges and the RFC 9637 documentation range; IPv4-mapped IPv6
   addresses are judged by their embedded IPv4 address. A blocked address
   raises :exc:`SSRFError`.

   .. note::
      When a forward proxy is configured (``proxy=`` on the request, or
      ``trust_env=True`` with ``HTTP_PROXY``/``HTTPS_PROXY`` set), the connector
      resolves and validates only the *proxy* endpoint; the target is resolved
      by the proxy and is not seen here. Pair with :class:`SSRFMiddleware` to
      constrain proxied targets.

   :param allowlist: Entries exempted from blocking, layered on top of the
      default public-only policy -- an empty list means "no extra exemptions".
      An exact hostname (case-insensitive, trailing dot ignored, IDNA
      normalized) exempts everything that host resolves to; an IP address or
      CIDR network exempts resolved addresses inside it. Use this to reach
      known-internal services deliberately.
   :type allowlist: iterable of str or None

   All other positional and keyword arguments are forwarded to
   :class:`~aiohttp.TCPConnector`.

.. class:: SSRFMiddleware(allowlist=None, denylist=None, allowed_schemes=("http", "https"))

   Client middleware enforcing URL-level rules against SSRF. It runs for
   every redirect hop, so the rules also apply to redirect targets. A request
   with a canonical literal-IP host is additionally checked against the same
   address classification the connector uses, failing fast before any
   connection. Non-canonical numeric IP forms (``0x7f000001``, ``2130706433``,
   ``127.1``) are treated as hostnames here and are stopped only by
   :class:`SSRFConnector`.

   :param allowlist: When given, only requests whose URL host matches one of
      these entries are allowed; ``None`` disables the allowlist, while an
      empty list blocks every request (fail closed). Entries are exact
      hostnames (case-insensitive, trailing dot ignored, IDNA normalized) or
      IP addresses/CIDR networks matched against literal-IP URL hosts. Hostname
      matching is deliberately exact -- no substring or suffix matching -- so
      an allowlisted ``example.com`` can never be matched by ``notexample.com``.
   :type allowlist: iterable of str or None
   :param denylist: Requests whose URL host matches one of these entries are
      rejected. Same entry forms as ``allowlist``; checked first.
   :type denylist: iterable of str or None
   :param allowed_schemes: URL schemes that may pass (default ``http`` and
      ``https``).
   :type allowed_schemes: iterable of str

.. exception:: SSRFError

   Raised (a :exc:`aiohttp.ClientError` subclass) when a request is blocked.
   Carries the offending ``host`` and a human-readable ``reason``.

   **Usage**

   ::

       from aiohttp import ClientSession
       from aiohttp_client_middlewares import SSRFConnector, SSRFMiddleware

       async with ClientSession(
           connector=SSRFConnector(),
           middlewares=(SSRFMiddleware(),),
       ) as session:
           # Raises SSRFError: metadata endpoints are never reachable.
           await session.get("http://169.254.169.254/latest/meta-data/")
