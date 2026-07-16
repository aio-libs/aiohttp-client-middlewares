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
argument. For example, HTTP Digest authentication combined with
client-side rate limiting:

.. literalinclude:: code/index.py


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
