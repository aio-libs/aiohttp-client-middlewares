============
Contributing
============

Thanks for taking the time to contribute to
``aiohttp-client-middlewares``! This page explains how to set up a
development environment, run the checks, and submit your change.


Setting up a development environment
====================================

Fork and clone the GitHub_ repository, then install the package in
editable mode together with the development requirements:

.. code-block:: console

   $ pip install -e . -r requirements/test.txt -r requirements/lint.txt -r requirements/doc.txt

This installs the runtime dependencies plus everything needed to run the
tests, the linters, and to build the documentation.


Running the tests
=================

The test suite uses pytest_:

.. code-block:: console

   $ pytest

To measure coverage the same way CI does:

.. code-block:: console

   $ pytest --cov=aiohttp_client_middlewares --cov-report=xml --cov-report=term


Linting and type checking
=========================

All style checks run through pre-commit_, and types are verified with
mypy_:

.. code-block:: console

   $ pre-commit run --all-files
   $ mypy

Code is formatted with black_ (88 columns) and imports are sorted with
isort_, both enforced by pre-commit, so there is no need to format by
hand.


Building the documentation
==========================

.. code-block:: console

   $ sphinx-build -b html docs docs/_build/html


Adding a changelog fragment
===========================

We use towncrier_ to manage the changelog. Every user-visible change
needs a news fragment in the ``CHANGES/`` directory. Name the file
``####.type.rst`` where ``####`` is the issue or pull request number and
``type`` is one of the eight categories below:

- ``bugfix``: A bug fix for undesired behavior that got corrected.
- ``feature``: A new behavior or public API.
- ``deprecation``: A declaration of future API removals or behavior
  changes.
- ``breaking``: When something public gets removed in a breaking way.
- ``doc``: Notable updates to the documentation or its build process.
- ``packaging``: Notes for downstreams about tooling, packaging, or
  runtime assumptions.
- ``contrib``: Changes that affect the contributor experience (tests,
  docs build, development setup).
- ``misc``: Changes that do not fit any of the categories above.

Write the fragment in the past tense using reStructuredText, and sign it
with ``-- by :user:`your-github-handle```. If a single pull request needs
more than one fragment of the same type, add a sequence number:
``####.feature.rst`` and ``####.feature.1.rst``. See ``CHANGES/README.rst``
for more detail and examples.


Pull request flow
=================

1. Create a branch for your change.
2. Make the change and add a test that covers it.
3. Make sure ``pytest``, ``pre-commit run --all-files`` and
   ``mypy`` all pass.
4. Add a news fragment under ``CHANGES/``.
5. Open a pull request against the ``master`` branch.

.. _GitHub: https://github.com/aio-libs/aiohttp-client-middlewares
.. _pytest: https://docs.pytest.org/
.. _pre-commit: https://pre-commit.com/
.. _mypy: https://mypy.readthedocs.io/
.. _black: https://black.readthedocs.io/
.. _isort: https://pycqa.github.io/isort/
.. _towncrier: https://towncrier.readthedocs.io/
