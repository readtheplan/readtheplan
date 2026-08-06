# Release Process

This document describes how to prepare and publish a readtheplan release. Preparing a release does not authorize merging, tagging, publishing, or deploying it. Those remain explicit maintainer decisions.

## Version numbering

readtheplan follows [Semantic Versioning](https://semver.org/):

- **Patch** (0.3.0 → 0.3.1): bug fixes, documentation, and other backwards-compatible corrections.
- **Minor** (0.3.0 → 0.4.0): backwards-compatible features, rules, adapters, or compliance catalogs.
- **Major** (1.0.0): first stable release after the API surface is finalized.

## 1. Prepare an isolated release branch

```bash
export VERSION=X.Y.Z
git fetch origin
git switch --create "release/${VERSION}" origin/main
```

Keep positioning, telemetry, infrastructure, and unrelated feature work in separate pull requests.

## 2. Update current release surfaces

Update and reconcile:

- `pyproject.toml` and `src/readtheplan/__init__.py`;
- root and site `package.json` metadata plus `site/package-lock.json`;
- `site/data/index.json` and current site Function/OpenAPI version metadata;
- current README, CI, Action, CLI-help, and issue-form release examples;
- the supported-version table in `SECURITY.md`; and
- `CHANGELOG.md`, leaving a fresh empty `Unreleased` section above the release entry.

Use this changelog shape:

```markdown
## [Unreleased]

## [X.Y.Z] — YYYY-MM-DD

### Added
- Feature description here.

### Fixed
- Bug fix description here.
```

Do not bulk-rewrite historical changelog entries, benchmark records, ADR examples, dependency versions, network addresses, or compatibility fixtures. `tests/test_release_metadata.py` distinguishes current release surfaces from those historical literals.

## 3. Validate the exact release tree

From an isolated environment bound to the release worktree:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q

cd site
npm ci
npm test
npm run build
cd ..

python -m build
python -m twine check dist/*
```

Install the built wheel into a fresh virtual environment and verify both the import and CLI report the intended version:

```bash
python -m venv .release-smoke
.release-smoke/bin/python -m pip install "dist/readtheplan-${VERSION}-py3-none-any.whl"
.release-smoke/bin/python -c "import readtheplan; print(readtheplan.__version__)"
.release-smoke/bin/readtheplan --version
```

On Windows, use `.release-smoke/Scripts/python.exe` and `.release-smoke/Scripts/readtheplan.exe`.

## 4. Review and merge the release-prep pull request

Commit the bounded release-prep diff and open it as a draft pull request:

```bash
git add -A
git commit -m "chore: prepare ${VERSION} release"
git push --set-upstream origin "release/${VERSION}"
```

Require green hosted checks and an independent review of the exact candidate tree. Record any intentionally retained old literals in the pull-request body. Merge only after explicit maintainer approval. Do not create the tag from an unmerged branch commit.

## 5. Tag the reviewed merge commit

After the release-prep pull request is merged, fetch and verify the exact merged commit before tagging:

```bash
export VERSION=X.Y.Z
git fetch origin --tags
git checkout --detach <reviewed-merge-sha>
test -z "$(git status --porcelain)"
git tag -a "v${VERSION}" -m "v${VERSION}"
git push origin "v${VERSION}"
```

Pushing a tag matching `v*` triggers `.github/workflows/publish.yml`, which builds and publishes to PyPI through Trusted Publishing and creates the GitHub Release. Never reuse or move a published tag.

## 6. Verify publication

After the workflow succeeds:

```bash
python -m venv .published-smoke
.published-smoke/bin/python -m pip install "readtheplan==${VERSION}"
.published-smoke/bin/readtheplan --version
```

Also verify the PyPI project page, GitHub Release, tag target, release assets, and package metadata all report the same version. On failure, stop and investigate; do not overwrite the tag or fabricate a successful release result.
