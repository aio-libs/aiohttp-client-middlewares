.. _Adding change notes with your PRs:

Adding change notes with your PRs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is important to maintain a log of how updating to a new version of
``aiohttp-client-middlewares`` will affect end-users. The idea is that
when somebody makes a change, they record the bits that would affect
end-users, including only information that is useful to them. When the
maintainers publish a release, these records are combined automatically
into the change log for that version.

So how do I add a news fragment?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This project uses `towncrier <https://towncrier.readthedocs.io/>`_ for
changelog management. To submit a change note about your PR, add a text
file into the ``CHANGES/`` folder describing what applying your PR will
change for end-users. One sentence is usually enough, but feel free to
add as many details as you feel are necessary.

**Use the past tense** for the text in your fragment because, combined
with others, it becomes part of the "news digest" telling readers *what
changed* in a specific version since the previous one. Use
*reStructuredText* syntax for highlighting code (inline or block) and
for linking parts of the docs or external sites. You do not need to
reference the issue or PR numbers in the body, as *towncrier* adds those
references automatically. If you wish to sign your change, add ``-- by
:user:`github-username``` at the end (replace ``github-username`` with
your own handle).

Name your file following the convention that towncrier understands:
``<pr_number>.<category>.rst``. It starts with the number of an issue or
PR, followed by a dot, then a category, then ``.rst``. If you need more
than one fragment of the same category, add an optional sequence number
(delimited with another period) between the category and the suffix, for
example ``1234.feature.rst`` and ``1234.feature.1.rst``.

The eight categories are:

- ``bugfix``: A bug fix for something we deemed an improper, undesired
  behavior that got corrected to match pre-agreed expectations.
- ``feature``: A new behavior or public API. That sort of stuff.
- ``deprecation``: A declaration of future API removals and breaking
  changes in behavior.
- ``breaking``: When something public gets removed in a breaking way.
  Could have been deprecated in an earlier release.
- ``doc``: Notable updates to the documentation structure or build
  process.
- ``packaging``: Notes for downstreams about unobvious side effects and
  tooling. Changes in test invocation considerations and runtime
  assumptions.
- ``contrib``: Stuff that affects the contributor experience, e.g.
  running tests, building the docs, setting up the development
  environment.
- ``misc``: Changes that are hard to assign to any of the above
  categories.

A pull request may have more than one of these components. For example,
a code change may introduce a new feature that deprecates an old one, in
which case two fragments should be added. It is not necessary to make a
separate documentation fragment for documentation changes accompanying
the relevant code changes.

Examples for adding changelog entries to your pull requests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

File :file:`CHANGES/1234.feature.rst`:

.. code-block:: rst

    Added ``RetryMiddleware`` for automatic retries of idempotent
    requests -- by :user:`octocat`.

File :file:`CHANGES/2345.bugfix.rst`:

.. code-block:: rst

    Fixed ``DigestAuthMiddleware`` not reusing a cached nonce across
    requests on the same session -- by :user:`octocat`.

.. tip::

   See :file:`pyproject.toml` for all available categories
   (``tool.towncrier.type``).

.. _Towncrier philosophy:
   https://towncrier.readthedocs.io/en/stable/#philosophy
