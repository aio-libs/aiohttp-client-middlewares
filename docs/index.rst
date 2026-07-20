aiohttp-client-middlewares
==========================

Reusable client middlewares for :mod:`aiohttp`.

This package collects ready-to-use middlewares for
:class:`aiohttp.ClientSession`. Available middlewares:

- :class:`~aiohttp_client_middlewares.DigestAuthMiddleware` -- HTTP Digest
  authentication.
- :class:`~aiohttp_client_middlewares.RateLimitMiddleware` -- client-side
  token-bucket rate limiting.


Installation
------------

.. code-block:: console

   $ pip install aiohttp-client-middlewares


Quickstart
----------

Attach one or more middlewares to a session through the ``middlewares``
argument. HTTP Digest authentication:

.. literalinclude:: code/index.py
   :pyobject: digest_auth_example
   :lines: 2-
   :dedent:

Client-side rate limiting (the limiter goes last so that internal replays,
such as digest's 401 handshake, are throttled too):

.. literalinclude:: code/index.py
   :pyobject: rate_limit_example
   :lines: 2-
   :dedent:


Contents
--------

.. toctree::
   :maxdepth: 2

   api


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
