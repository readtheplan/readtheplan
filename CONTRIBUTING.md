# Contributing to readtheplan

Thanks for your interest! This guide gets you from clone to merged PR.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Dev setup

readtheplan is a pure-Python package (3.10+) with no runtime services. The only
required dependency is PyYAML; signing and MCP are optional extras.

```bash
git clone https://github.com/readtheplan/readtheplan
cd readtheplan
python -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -e ".[dev]"                             # editable install + pytest, ruff
```

Optional extras, only if you touch those areas:

```bash
pip install -e ".[sign]"   # sigstore signing/verification
pip install -e ".[mcp]"    # local MCP stdio server
```

## Everyday commands

```bash
pytest                      # run the test suite (with coverage; gate is fail_under=77)
ruff check .                # lint
make check                  # ruff + pytest in one go
scripts/regenerate-examples.sh   # rebuild examples/*/analysis.{md,json} after a rule change
```

Run a single test while iterating:

```bash
pytest tests/test_rules.py -k eks -q
```

## Project layout

| Path | What lives there |
| --- | --- |
| `src/readtheplan/rules.py` | Resource-aware risk classification (the core) |
| `src/readtheplan/plan.py` | Terraform plan JSON parsing |
| `src/readtheplan/data/controls/*.yaml` | Compliance control catalogs (SOC 2, ISO 27001, HIPAA, …) |
| `src/readtheplan/overlays.py` | User-supplied rule/control overrides (`--rules-file`) |
| `src/readtheplan/adapters/` | Non-Terraform inputs (e.g. CloudFormation) |
| `src/readtheplan/cli.py` | Command-line entry point |
| `examples/` | Sample plans + their rendered output |
| `docs/authoring-rules.md` | **How to add rules, controls, overlays, and adapters** |

## Good first contributions

These are concrete, well-scoped, and reviewed quickly:

1. **Add a resource rule.** Pick an AWS resource readtheplan doesn't classify yet
   (it currently covers 40+ types) and add a rule + test. Step-by-step in
   [docs/authoring-rules.md](docs/authoring-rules.md#add-a-resource-rule).
2. **Add a control mapping.** Map an existing resource/action to a control in one
   of the catalogs under `src/readtheplan/data/controls/`. See
   [docs/authoring-rules.md](docs/authoring-rules.md#add-a-compliance-mapping).
3. **Add an example.** Drop a real (sanitized) plan into `examples/`, run
   `scripts/regenerate-examples.sh`, and document what it demonstrates.
4. **Improve an explanation string.** If a rule's guidance is vague, sharpen it —
   these are what reviewers actually read.

Browse [issues labeled "good first issue"](https://github.com/readtheplan/readtheplan/labels/good%20first%20issue) too.

## Code style

- Type hints required on all public functions.
- pytest for tests, colocated in `tests/`. **Add or update a test for any behavior change** — a new rule needs a test asserting its risk tier and explanation.
- Ruff for lint/format (line length 100).
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, etc.

## PR process

1. Open an issue first for feature requests so we can agree on scope.
2. PRs need one approving review; CI must pass (lint + test + build).
3. Keep changes scoped — one rule, one fix, or one doc per PR is ideal.
4. If you used AI assistance, note it in the PR body (our disclosure norm).

## Communication

- Issues and [Discussions](https://github.com/readtheplan/readtheplan/discussions) are the primary channels.
- Be patient — this is maintained by volunteers.

## License

By contributing, you agree your code will be licensed under the project's MIT license.
