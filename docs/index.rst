aiohttp-client-middlewares
==========================

Reusable client middlewares for :mod:`aiohttp`.

This package collects ready-to-use middlewares for
:class:`aiohttp.ClientSession`. Available middlewares:

- :class:`~aiohttp_client_middlewares.DigestAuthMiddleware` -- HTTP Digest
  authentication.
- :class:`~aiohttp_client_middlewares.SSRFMiddleware` and
  :class:`~aiohttp_client_middlewares.SSRFConnector` -- server-side request
  forgery (SSRF) protection.


Installation
------------

.. code-block:: console

   $ pip install aiohttp-client-middlewares


Quickstart
----------

Attach a middleware to a session through the ``middlewares`` argument and
let it handle authentication for every request:

.. literalinclude:: code/digest_auth.py

For SSRF protection, combine the connector (which validates every resolved
address) with the middleware (which enforces URL-level rules):

.. literalinclude:: code/ssrf.py


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
