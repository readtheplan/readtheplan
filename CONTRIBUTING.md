# Contributing to readtheplan

Thanks for your interest! Here's how to get started.

## Quickstart

1. **Fork** the repo and clone it
2. Install deps: `pip install -e ".[dev]"`
3. Run tests: `pytest`
4. Make your change, open a PR

## Good First Issues

Check [issues labeled "good-first-issue"](https://github.com/readtheplan/readtheplan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). These are small, scoped tasks perfect for new contributors.

## Making Your First Contribution

New to the project? Here's a step-by-step walkthrough:

1. **Fork and clone**
   ```bash
   gh repo fork readtheplan/readtheplan --clone
   cd readtheplan
   ```

2. **Install dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Run the tests** to verify everything works
   ```bash
   pytest
   ```
   All tests should pass before you start.

4. **Pick an issue** — browse [good first issues](https://github.com/readtheplan/readtheplan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and comment to claim one.

5. **Create a branch**
   ```bash
   git checkout -b feat/my-change
   ```

6. **Make your change** — follow the code style below. Add tests if applicable.

7. **Run tests again**
   ```bash
   pytest
   ```

8. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: your change description"
   git push origin feat/my-change
   ```

9. **Open a PR** — from your branch to `main`. CI will run automatically. A maintainer will review within a few days.

**Need help?** Comment on your issue or open a discussion. We're a small team but responsive.

## Code Style

- Type hints required on all public functions
- pytest for tests, colocated in `tests/`
- Black formatting (line length 100)
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
