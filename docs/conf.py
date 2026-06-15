#!/usr/bin/env python3
#
# aiohttp-client-middlewares documentation build configuration file.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# -- Project information -----------------------------------------------------

github_url = "https://github.com"
github_repo_org = "aio-libs"
github_repo_name = "aiohttp-client-middlewares"
github_repo_slug = f"{github_repo_org}/{github_repo_name}"
github_repo_url = f"{github_url}/{github_repo_slug}"

project = "aiohttp-client-middlewares"
author = "aio-libs team"
copyright = f"{project} contributors"

# The full version, including alpha/beta/rc tags.
try:
    release = _pkg_version("aiohttp-client-middlewares")
except PackageNotFoundError:
    release = "0.1.0"
# The short X.Y version.
version = ".".join(release.split(".")[:2])


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The suffix of source filenames.
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ["_build"]

# The default language to highlight source code in.
highlight_language = "python3"


# -- Options for autodoc -----------------------------------------------------

# Render type hints in the description rather than the signature, keeping
# signatures readable and warning-free.
autodoc_typehints = "description"
autodoc_member_order = "bysource"


# -- Options for intersphinx -------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
    "yarl": ("https://yarl.readthedocs.io/en/stable/", None),
}


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = "aiohttp_theme"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    "description": "Reusable client middlewares for aiohttp",
    "canonical_url": "https://aiohttp-client-middlewares.readthedocs.io/en/stable/",
    "github_user": github_repo_org,
    "github_repo": github_repo_name,
    "github_button": True,
    "github_type": "star",
    "github_banner": True,
}

# Custom sidebar templates, maps document names to template names.
html_sidebars = {
    "**": [
        "about.html",
        "navigation.html",
        "searchbox.html",
    ]
}


# Output file base name for HTML help builder.
htmlhelp_basename = f"{project}doc"
