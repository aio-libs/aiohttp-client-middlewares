============================
aiohttp-client-middlewares
============================

.. image:: https://github.com/aio-libs/aiohttp-client-middlewares/actions/workflows/ci-cd.yml/badge.svg
   :target: https://github.com/aio-libs/aiohttp-client-middlewares/actions/workflows/ci-cd.yml
   :alt: GitHub Actions CI status

.. image:: https://codecov.io/gh/aio-libs/aiohttp-client-middlewares/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/aio-libs/aiohttp-client-middlewares
   :alt: codecov.io status

.. image:: https://badge.fury.io/py/aiohttp-client-middlewares.svg
   :target: https://pypi.org/project/aiohttp-client-middlewares
   :alt: Latest PyPI package version

.. image:: https://img.shields.io/pypi/pyversions/aiohttp-client-middlewares.svg
   :target: https://pypi.org/project/aiohttp-client-middlewares
   :alt: Supported Python versions

.. image:: https://readthedocs.org/projects/aiohttp-client-middlewares/badge/?version=latest
   :target: https://aiohttp-client-middlewares.readthedocs.io/
   :alt: Latest Read The Docs


Reusable client middlewares for aiohttp.

``aiohttp-client-middlewares`` is a small, pure-Python collection of
ready-to-use *client* middlewares for ``aiohttp``. It currently provides
``DigestAuthMiddleware``, vendored from aiohttp core; this package is the
canonical home for it going forward.

Middlewares plug into ``aiohttp.ClientSession`` through the client
middleware API introduced in aiohttp 3.12, so they can wrap every outgoing
request without subclassing the session.


Installation
============

.. code-block:: console

   $ pip install aiohttp-client-middlewares

This requires ``aiohttp >= 3.12`` (the first release with the client-middleware
API and ``DigestAuthMiddleware``) and ``yarl >= 1.17.0``. Both are pulled in
automatically.

Supported Python versions: 3.10, 3.11, 3.12, 3.13 and 3.14.


Quickstart
==========

Pass one or more middlewares to ``aiohttp.ClientSession`` via the
``middlewares`` argument. ``DigestAuthMiddleware`` transparently performs the
HTTP Digest authentication handshake for every request made with the session:

.. code-block:: python

   import asyncio

   import aiohttp
   from aiohttp_client_middlewares import DigestAuthMiddleware


   async def main() -> None:
       digest = DigestAuthMiddleware("user", "pass")
       async with aiohttp.ClientSession(middlewares=(digest,)) as session:
           async with session.get("https://httpbin.org/digest-auth/auth/user/pass") as resp:
               print("Status:", resp.status)
               print("Body:", await resp.json())


   asyncio.run(main())


Documentation
=============

https://aiohttp-client-middlewares.readthedocs.io/


Links
=====

* Documentation: https://aiohttp-client-middlewares.readthedocs.io/
* Changelog: https://github.com/aio-libs/aiohttp-client-middlewares/blob/master/CHANGES.rst
* Issue tracker: https://github.com/aio-libs/aiohttp-client-middlewares/issues
* Source code: https://github.com/aio-libs/aiohttp-client-middlewares


Communication channels
=======================

*aio-libs Discussions*:
https://github.com/aio-libs/aiohttp-client-middlewares/discussions

*Matrix*: `#aio-libs:matrix.org <https://matrix.to/#/#aio-libs:matrix.org>`_


License
=======

``aiohttp-client-middlewares`` is offered under the Apache-2.0 license.
See the ``LICENSE`` file for the full text.
