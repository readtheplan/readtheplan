PYTHON ?= python
IMAGE ?= readtheplan:local
SBOM ?= build/sbom/readtheplan.cdx.json

.DEFAULT_GOAL := test

.PHONY: install install-devsecops test lint site check build security sbom container ci

install:
	$(PYTHON) -m pip install -e ".[dev]"

install-devsecops:
	$(PYTHON) -m pip install -e ".[dev,devsecops]"

test:
	pytest

lint:
	ruff check .

site:
	npm --prefix site test && npm --prefix site run build

check: lint test

build:
	$(PYTHON) -m build

# These targets intentionally fail when their optional tools are unavailable.
# Install them with `make install-devsecops`; ordinary `make check` stays lean.
security:
	$(PYTHON) -m pip_audit --local
	$(PYTHON) -m bandit -q -r src/readtheplan

sbom:
	$(PYTHON) -c "from pathlib import Path; Path('$(SBOM)').parent.mkdir(parents=True, exist_ok=True)"
	$(PYTHON) -m cyclonedx_py environment --output-format JSON --output-file "$(SBOM)"

container:
	docker build --tag "$(IMAGE)" .

# Python CI contract. The separately locked Node site remains under `make site`.
ci: check build
