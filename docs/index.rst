aiohttp-client-middlewares
==========================

Reusable client middlewares for :mod:`aiohttp`.

This package collects ready-to-use *client* middlewares for
:class:`aiohttp.ClientSession`, starting with HTTP Digest authentication
via :class:`~aiohttp_client_middlewares.DigestAuthMiddleware`.


Installation
------------

.. code-block:: console

   $ pip install aiohttp-client-middlewares

The package requires Python 3.10 or newer and depends on
``aiohttp >= 3.12`` (the first release shipping the client-middleware API)
and ``yarl >= 1.17.0``.


Quickstart
----------

Attach a middleware to a session through the ``middlewares`` argument and
let it handle authentication for every request:

.. code-block:: python

   import asyncio

   from aiohttp import ClientSession
   from aiohttp_client_middlewares import DigestAuthMiddleware


   async def main() -> None:
       digest_auth = DigestAuthMiddleware(login="user", password="secret")
       async with ClientSession(middlewares=(digest_auth,)) as session:
           async with session.get("https://httpbin.org/digest-auth/auth/user/secret") as resp:
               resp.raise_for_status()
               print(await resp.json())


   asyncio.run(main())


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
