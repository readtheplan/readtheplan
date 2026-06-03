# Contributing to readtheplan

Thanks for your interest! Here's how to get started.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Quickstart

1. **Fork** the repo and clone it
2. Install deps: `pip install -e ".[dev]"`
3. Run tests: `pytest`
4. Make your change, open a PR

## Good First Issues

Check [issues labeled "good-first-issue"](https://github.com/readtheplan/readtheplan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). These are small, scoped tasks perfect for new contributors.

## Code Style

- Type hints required on all public functions
- pytest for tests, colocated in `tests/`
- Ruff linting and formatting (line length 100)
- Conventional commits: `feat:`, `fix:`, `docs:`, etc.

## PR Process

1. Open an issue first for feature requests
2. PRs need one approving review
3. CI must pass (lint + test + build)
4. We use AI-assisted review disclosure — mention it in your PR body if applicable

## Communication

- Issues are the primary discussion channel
- Tag maintainers with @mention if something is urgent
- Be patient — this is a side project maintained by volunteers

## License

By contributing, you agree your code will be licensed under the project's MIT license.
