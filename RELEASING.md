# Release Process

This document describes how to publish a new version of readtheplan.

## Version numbering

readtheplan follows [Semantic Versioning](https://semver.org/):

- **Patch** (0.3.0 → 0.3.1): bug fixes, documentation, non-breaking changes.
- **Minor** (0.3.0 → 0.4.0): new features, new rules, new adapters, new compliance frameworks — backwards-compatible.
- **Major** (1.0.0): first stable release after the API surface is finalized.

## Step-by-step

### 1. Update version

```bash
# Edit src/readtheplan/__init__.py — update __version__
# Edit pyproject.toml — update version under [project]
```

### 2. Update CHANGELOG.md

Open `CHANGELOG.md` and add an entry under the new version:

```markdown
## [0.4.0] — 2026-06-12

### Added
- Feature description here.

### Fixed
- Bug fix description here.

### Changed
- Breaking or notable changes here.
```

### 3. Commit and tag

```bash
git add -A
git commit -m "chore: bump version to 0.4.0"
git tag -a v0.4.0 -m "v0.4.0"
git push origin main --tags
```

### 4. CI publishes automatically

The `.github/workflows/publish.yml` workflow triggers when a tag matching `v*` is pushed:

1. Builds the wheel and source distribution
2. Publishes to PyPI via trusted publishing (OIDC)
3. Creates a GitHub Release with release notes

You do not need to manually run `twine upload` or create a GitHub Release — the workflow handles both.

### 5. Verify

```bash
pip install readtheplan==0.4.0
readtheplan --version
```
