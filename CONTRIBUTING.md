# Contributing to readtheplan

Thanks for your interest! Here's how to get started.

## Quickstart

1. **Fork** the repo and clone it
2. Install deps: `pip install -e ".[dev]"`
3. Run tests: `pytest`
4. Make your change, open a PR


## Making Your First Contribution

New to open source? Here's the exact sequence to make your first contribution:

### 1. Fork and clone
```bash
gh repo fork readtheplan/readtheplan --clone
cd readtheplan
```

### 2. Set up a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

### 3. Install in dev mode
```bash
pip install -e ".[dev]"
```

### 4. Run the tests to confirm everything works
```bash
pytest
```

### 5. Create a branch
```bash
git checkout -b feat/my-change
```

### 6. Make your change, write/update tests, run the test suite again

### 7. Commit with a conventional commit message
```bash
git commit -m "feat: short description of change"
```

### 8. Push and open a PR
```bash
git push -u origin feat/my-change
```

Then open a Pull Request on GitHub against the `main` branch.

### Key files to explore
- `src/readtheplan/rules.py` — resource risk rules
- `tests/test_rules.py` — tests for rules
- `site/playground/classifier.js` — browser playground classifier
- `site/app.js` — landing page setup generator
## Good First Issues

Check [issues labeled "good-first-issue"](https://github.com/readtheplan/readtheplan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). These are small, scoped tasks perfect for new contributors.

## Code Style

- Type hints required on all public functions
- pytest for tests, colocated in `tests/`
- Black formatting (line length 100)
- Conventional commits: `feat:`, `fix:`, `docs:`, etc.

## PR Process

1. Open an issue first for feature requests
2. PRs need one approving review
3. CI must pass (lint + test + build)
4. We use AI-assisted review disclosure â€” mention it in your PR body if applicable

## Communication

- Issues are the primary discussion channel
- Tag maintainers with @mention if something is urgent
- Be patient â€” this is a side project maintained by volunteers

## License

By contributing, you agree your code will be licensed under the project's MIT license.
