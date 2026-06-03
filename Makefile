.PHONY: test lint site check

test:
	pytest

lint:
	ruff check .

site:
	npm --prefix site test && npm --prefix site run build

check: lint test
