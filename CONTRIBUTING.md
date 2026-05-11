# Contributing to readtheplan

Thanks for your interest! This guide covers everything you need to start contributing.

## Quickstart

```bash
git clone https://github.com/readtheplan/readtheplan.git
cd readtheplan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
python -m pytest
```

## Development environment

- **Python**: 3.9+ (3.10+ for MCP extra)
- **Dependencies**: `pip install -e ".[test,mcp]"`
- **Tests**: `python -m pytest`
- **Lint**: `ruff check src/`
- **Site**: `npm --prefix site install && npm --prefix site test && npm --prefix site run build`

## What makes a good contribution

readtheplan is a Terraform plan risk analyzer. Good contributions:

- **Add rules for AWS resource types** — new resource categories, edge cases, or compliance mappings
- **Improve compliance catalogs** — expand SOC 2 / ISO 27001 / HIPAA control mappings
- **Fix classification bugs** — resources misclassified as safe when they should be review/dangerous
- **Add examples** — real-world plan scenarios with explanations
- **Improve documentation** — tutorials, troubleshooting guides, comparison articles
- **Port the analyzer to JS** — help build the in-browser playground

## Good first issues

Look for issues tagged [`good first issue`](https://github.com/readtheplan/readtheplan/labels/good%20first%20issue). These are scoped, well-documented, and don't require deep knowledge of the codebase.

Examples of good first issues:
- Add a resource rule for an uncovered AWS service
- Add compliance control mappings for an existing framework
- Improve error messages for malformed plan JSON
- Add a test case for an edge case
- Update documentation for a feature

## Project structure

```
readtheplan/
├── src/readtheplan/      # Python package
│   ├── cli.py            # CLI entry point
│   ├── plan.py           # Plan parsing and classification
│   ├── rules.py           # Resource-aware risk rules (~30 AWS types)
│   ├── controls.py        # Compliance framework mapping
│   ├── agent_gate.py      # Agent gate contract
│   ├── evidence.py        # Evidence envelope generation
│   ├── attestation.py      # Signed attestation verification
│   └── data/controls/     # Compliance catalogs (YAML)
├── site/                  # Cloudflare Pages static site
│   ├── index.html         # Landing page
│   ├── demo/              # Live demo page
│   ├── scripts/           # Build, validate, and JS tools
│   └── tests/             # Site tests
├── examples/              # Sample plans with rendered output
├── docs/                  # ADRs, briefs, and documentation
│   ├── adr/               # Architecture Decision Records
│   └── briefs/            # Implementation briefs
├── tests/                 # Python test suite
├── action.yml             # GitHub Action definition
└── pyproject.toml         # Package configuration
```

## How rules work

The risk classification engine in `src/readtheplan/rules.py` works in two layers:

1. **Baseline classification** — maps Terraform action tuples (`create`, `update`, `delete`, `delete+create`) to risk tiers
2. **Resource-specific rules** — inspects change attributes for known dangerous patterns (public access grants, major version bumps, security group openings, etc.)

To add a new resource rule:

1. Add the resource type dispatch in `apply_resource_rules()`
2. Implement the classification function (returns a risk tier string)
3. Add test cases in `tests/test_rules.py`
4. If relevant, add compliance control mappings in `data/controls/*.yaml`

See [ADR 0003](docs/adr/0003-risk-classification-taxonomy.md) for the classification contract.

## PR process

1. **Open an issue first** — discuss the change before writing code
2. **Branch from `main`** — use a descriptive branch name
3. **Keep PRs focused** — one concern per PR
4. **Include tests** — new rules need test cases; bug fixes need regression tests
5. **Update docs** — if you change behavior, update the relevant ADR or README
6. **Run the full test suite** — `python -m pytest && npm --prefix site test`
7. **Sign your commits** — DCO sign-off required (`git commit -s`)

### AI assistance disclosure

If you used AI tools (Claude, Codex, Gemini, etc.) to write or review code, disclose it in the PR description:

```
AI assistance: [tool name] used for [purpose]
```

This is a transparency convention, not a restriction. We use AI tools ourselves.

## Code style

- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/). Use type hints. Run `ruff` before committing.
- **JavaScript**: ES2020+. No frameworks. No CDN imports. Must pass `npm --prefix site test`.
- **Commits**: Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`)
- **Docstrings**: Google-style for public functions

## Testing

```bash
# Python tests
python -m pytest

# Specific test file
python -m pytest tests/test_rules.py -v

# With coverage
python -m pytest --cov=readtheplan

# Site tests
npm --prefix site test

# Site build
npm --prefix site run build
```

Tests use `uv` when `python -m pytest` is unavailable:
```bash
UV_CACHE_DIR=/tmp/uv-cache uv run --with pytest --with PyYAML python -m pytest
```

## Getting help

- **Questions**: Open a [discussion](https://github.com/readtheplan/readtheplan/discussions)
- **Bugs**: Open an [issue](https://github.com/readtheplan/readtheplan/issues)
- **Security**: Email the maintainer directly (see [SECURITY.md](SECURITY.md))

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
