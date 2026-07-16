# Release Process

This document describes how to publish a new version of readtheplan.

## Version numbering

readtheplan follows [Semantic Versioning](https://semver.org/):

- **Patch** (0.3.0 â†’ 0.3.1): bug fixes, documentation, non-breaking changes.
- **Minor** (0.3.0 â†’ 0.4.0): new features, new rules, new adapters, new compliance frameworks â€” backwards-compatible.
- **Major** (1.0.0): first stable release after the API surface is finalized.

## Step-by-step

### 1. Update version

```bash
# Edit src/readtheplan/__init__.py â€” update __version__
# Edit pyproject.toml â€” update version under [project]
```

### 2. Update CHANGELOG.md

Open `CHANGELOG.md` and add an entry under the new version:

```markdown
## [0.4.0] â€” 2026-06-12

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

When the enterprise integrations are enabled, SBOM generation, artifact
signing, Nexus policy evaluation, and Nexus publication must consume the same
`dist` artifact from step 1. They must not rebuild the package for another
destination. Commercial integrations remain opt-in as described in
[`docs/devsecops.md`](docs/devsecops.md).

You do not need to manually run `twine upload` or create a GitHub Release â€” the workflow handles both.

### 5. Verify

```bash
pip install readtheplan==0.4.0
readtheplan --version
```

If Nexus publication is enabled, compare the Nexus component SHA-256 with the
workflow's original `dist` artifact before promotion. For staged releases,
tag the verified component and move it from the configured source hosted repository to the immutable destination only after its policy
evaluation succeeds; never resolve a failure by rebuilding the version.
