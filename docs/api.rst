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
