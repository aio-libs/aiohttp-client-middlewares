<!-- Thank you for your contribution! -->

## What do these changes do?

<!-- Please give a short brief about these changes. -->

## Are there changes in behavior for the user?

<!-- Outline any notable behaviour for the end users. -->

## Related issue number

<!-- Will this resolve any open issues? -->
<!-- Remember to prefix with 'Fixes' if it closes an issue (e.g. 'Fixes #123'). -->

## Checklist

- [ ] Unit tests for the changes exist and pass (`pytest`).
- [ ] `pre-commit run --all-files` and `mypy` pass.
- [ ] Documentation reflects the changes where applicable.
- [ ] Add a new news fragment into the `CHANGES/` folder
  * name it `<issue_or_pr_num>.<type>.rst` (e.g. `42.bugfix.rst`)
  * if you don't have an issue number, use the pull request number after
    creating the PR
  * the `<type>` is one of: `bugfix`, `feature`, `deprecation`, `breaking`,
    `doc`, `packaging`, `contrib`, `misc` (see `CHANGES/README.rst`)
  * use full sentences in the past tense, e.g.:
    ```rst
    Fixed ``DigestAuthMiddleware`` not reusing a cached nonce
    -- by :user:`your-github-handle`.
    ```
