# Simple developer tasks for aiohttp-client-middlewares (pure-Python, UNIX only).

PIP ?= python -m pip
PACKAGE := aiohttp_client_middlewares

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  install-dev  Install the package with all dev requirements + pre-commit hooks"
	@echo "  fmt          Auto-format the code (black + isort) via pre-commit"
	@echo "  lint         Run pre-commit on all files and mypy on the package"
	@echo "  test         Run the test suite with pytest"
	@echo "  cov          Run the tests with coverage (term-missing + xml)"
	@echo "  doc          Build the HTML documentation with Sphinx"
	@echo "  build        Build the sdist and wheel with python -m build"
	@echo "  clean        Remove build, cache and generated artifacts"

.PHONY: install-dev
install-dev:
	$(PIP) install -e . -r requirements/test.txt -r requirements/lint.txt -r requirements/doc.txt
	pre-commit install

.PHONY: fmt format
fmt format:
	pre-commit run black --all-files
	pre-commit run isort --all-files

.PHONY: lint
lint:
	pre-commit run --all-files
	mypy

.PHONY: test
test:
	pytest

.PHONY: cov
cov:
	pytest --cov=$(PACKAGE) --cov-report=term-missing --cov-report=xml

.PHONY: doc
doc:
	sphinx-build -b html docs docs/_build/html

.PHONY: build
build:
	python -m build

.PHONY: clean
clean:
	@rm -rf build
	@rm -rf dist
	@rm -rf docs/_build
	@rm -rf *.egg-info
	@rm -rf $(PACKAGE).egg-info
	@rm -rf .pytest_cache
	@rm -rf .mypy_cache
	@rm -rf `find . -name __pycache__`
	@rm -f .coverage
	@rm -f coverage.xml
