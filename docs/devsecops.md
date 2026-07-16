# Enterprise DevSecOps

readtheplan keeps its public CI path usable without commercial accounts while
providing explicit integration points for enterprise controls. Open-source
checks are the default. Commercial scanners, artifact publication, and signing
are opt-in and must never turn a missing license or a forked pull request into a
misleading successful scan.

## Control ownership

Each class of finding has one authoritative owner. Overlapping tools can provide
additional telemetry, but should not create duplicate release gates.

| Capability | Enterprise owner | Open-source/default coverage |
| --- | --- | --- |
| Code quality and coverage | SonarQube | Ruff, pytest, pytest-cov |
| SAST | Checkmarx One | CodeQL and Bandit |
| Dependency and license policy | Nexus Lifecycle / IQ | pip-audit |
| Secrets | Gitleaks | Gitleaks in pre-commit and CI |
| IaC and repository posture | Prisma Cloud AppSec | Checkov and Trivy configuration scan |
| Container and runtime risk | Prisma Cloud Compute | Trivy when an exact candidate image is available |
| SBOM | Enterprise inventory ingestion | CycloneDX for Python and Syft for images |
| Artifact integrity | Sigstore/Cosign and GitHub OIDC | Checksums and keyless signatures |
| Artifact storage and promotion | Nexus Repository | Protected GitHub Release assets for durable evidence; run artifacts only for short-lived handoff |
| Orchestration | GitHub Actions | The same Makefile commands run locally |

SonarQube is the quality authority, Checkmarx is the SAST authority, Nexus IQ is
the SCA and license authority, and Prisma owns IaC, image, cloud, and runtime
risk. Configure only the authoritative tool as a blocking source for each class
unless the security team has deliberately approved a second gate.

## Local commands

The ordinary developer path remains small:

```bash
python -m pip install -e ".[dev]"
make check
```

Install the optional local DevSecOps tools only when needed:

```bash
python -m pip install -e ".[dev,devsecops]"
pre-commit install
make security
make sbom
```

The targets have intentionally different contracts:

- `make check` runs the existing Ruff and pytest gates.
- `make ci` runs `make check` and builds the Python distributions.
- `make site` runs the existing locked Node site tests and build. Run
  `npm ci --prefix site` first in a fresh checkout.
- `make security` runs pip-audit and Bandit and fails on tool errors or
  reportable findings. It does not silently skip missing tools.
- `make sbom` writes a CycloneDX inventory of the current Python environment
  to `build/sbom/readtheplan.cdx.json`. Release jobs separately inventory the
  built package and image.
- `make container` builds `readtheplan:local` from the checked-out source.

The pre-commit configuration pins whitespace, EOF, YAML, Ruff, and Gitleaks
hooks. `.gitleaks.toml` exempts only three exact synthetic private-key fixtures that
contains a deliberately fake private-key marker.

## Opt-in policy

Repository variables are policy switches. They default to absent/false. A
commercial integration runs only when its `ENABLE_*` variable is exactly
`true` and the event is trusted.

| Repository variable | Effect |
| --- | --- |
| `ENABLE_SONARQUBE` | Run SonarQube analysis and quality-gate evaluation. |
| `ENABLE_CHECKMARX` | Run Checkmarx One SAST. |
| `ENABLE_NEXUS_IQ` | Run Nexus Lifecycle/IQ component and license policy evaluation. |
| `ENABLE_PRISMA_APPSEC` | Run Prisma Cloud AppSec/Checkov repository and IaC scanning. |
| `ENABLE_PRISMA_COMPUTE` | Scan the built image with Prisma Cloud Compute. |
| `ENABLE_NEXUS_PUBLISH` | Publish trusted main/tag artifacts to Nexus Repository. |
| `ENABLE_ARTIFACT_SIGNING` | Keylessly sign `SHA256SUMS`; PyPI and GitHub Release publication then require signing success. |
| `STRICT_ENTERPRISE_GATES` | Fail when an enabled integration is misconfigured instead of explicitly skipping it during rollout. |

An enabled job that is missing required configuration must report that fact
plainly. With strict gates enabled it must fail. Without strict gates it may
explicitly skip during initial configuration, but its summary must say that no
enterprise policy decision was produced. Once a vendor scan starts, its policy
or finding exit is always a gate regardless of `STRICT_ENTERPRISE_GATES`.

### Integration configuration

Store endpoints, project identifiers, and repository names as GitHub variables.
Store commercial scanner credentials only as environment secrets in the
`security-scanning` environment; never duplicate them as repository or
organization secrets.

| Integration | Variables | Secrets | Manual prerequisite |
| --- | --- | --- | --- |
| SonarQube | `SONAR_HOST_URL`, optional `SONAR_PROJECT_KEY` | `SONAR_TOKEN` | Create the project, token, and quality gate. The checked-in key is `readtheplan` and may be overridden by the scanner. |
| Checkmarx One | `CX_BASE_URI`, `CX_TENANT`, optional `CX_PROJECT_NAME` | `CX_CLIENT_ID`, `CX_CLIENT_SECRET` | Create an OAuth client with scan-only scope and assign the project. |
| Nexus IQ | `NEXUS_IQ_URL`, `NEXUS_IQ_APPLICATION_ID`, optional `NEXUS_IQ_SCAN_TARGETS` | `NEXUS_IQ_USERNAME`, `NEXUS_IQ_PASSWORD` | Create the application and map build, stage-release, and release policy stages. |
| Prisma AppSec | `PRISMA_API_URL` | `PRISMA_ACCESS_KEY_ID`, `PRISMA_SECRET_KEY` | Create a least-privilege AppSec access key and Checkov policy assignment. |
| Prisma Compute | `PCC_CONSOLE_URL`, `PCC_USER` | `PCC_PASS` | Create a CI image-scan user and allow access to the Compute API/CLI. |
| Nexus Repository | `NEXUS_PYPI_REPOSITORY_URL`, `NEXUS_EXPECTED_HOST`, `NEXUS_EXPECTED_PATH_PREFIX`, and optional staging variables below | `NEXUS_USERNAME`, `NEXUS_PASSWORD` | Pin the exact approved host[:port] and Nexus context path, then create hosted repositories, a deployment role, TLS, and immutable release policy. Redirects are rejected so Basic credentials cannot be forwarded. |
| Keyless signing | no secret; optional identity policy variables | no long-lived signing key | Allow `id-token: write` only on the signing job, configure the verifier's expected repository identity, and require successful signing before Nexus publication when enabled. |

Commercial products can change their authentication fields between editions.
Map these repository-level names to the vendor action or CLI in one workflow;
do not spread vendor-specific names through application code.

### Forks and untrusted pull requests

- Every pull request, including one from the same repository, runs open-source
  checks with read-only repository permissions and receives no repository or
  environment secrets. Commercial scans run only on protected-branch pushes,
  schedules, or manual events.
- The separate PR/trusted callers and workflow `if` conditions are defense in
  depth, not the secret boundary: a same-repository PR can edit them. The actual
  boundary is the `security-scanning` environment restricted to protected
  main/tag refs, with an independent required reviewer and **prevent self-review**
  enabled, and scanner credentials stored only as environment secrets.
- Publishing, signing, cloud authentication, and Prisma Compute image upload
  run only on trusted push, protected tag, schedule, or manually approved events.
- Do not use `pull_request_target` to check out and execute untrusted pull
  request code. A skipped commercial job is not evidence that a scan passed.

## Scan cadence

| Event | Required/default work | Optional enterprise work |
| --- | --- | --- |
| Pull request | Lint, unit tests, site tests, CodeQL/Bandit, Gitleaks, pip-audit, IaC/config scan, AI/demo smoke tests | Commercial jobs always skip; no scanner secrets are mapped into PR workflow code |
| Main | Repeat required checks; build wheel/sdist and image once; generate checksums and SBOMs; scan the exact artifacts | Full enterprise scans, keyless signing, immutable Nexus snapshot publication |
| Protected version tag | Build once and pass that `dist` artifact to the protected `pypi` environment | Sign the same evidence when enabled; publish the same bytes to Nexus; attach wheel, sdist, checksums, SPDX SBOM, and Sigstore bundles to the protected GitHub Release |
| Nightly/weekly | CodeQL, dependency refresh, full secret/history and image/base-image scans | Full Checkmarx, Nexus IQ re-evaluation, Prisma AppSec/Compute, and drift/posture reports |

PR checks should stay responsive. Deep scans belong on main or a schedule unless
the vendor supports a reliable incremental mode.

## Build once, promote the same bytes

A release pipeline should:

1. Check out one commit and record its full Git SHA.
2. Build the wheel, source distribution, and container once.
3. Calculate package SHA-256 values and the container digest.
4. Upload immutable run artifacts named with the Git SHA.
5. Run SCA, image scans, SBOM generation, and signing against those exact
   artifacts.
6. Publish the same package bytes and image digest to the snapshot repository.
7. Promote or copy the verified bytes into a release repository without
   rebuilding them.
8. Record Git SHA, package checksums, image digest, SBOM digest, scanner policy
   results, and signing identity in the release evidence.

Version tags are labels for an artifact digest, not instructions to compile a
new artifact per environment. Both the Nexus source hosted repository and the
destination release repository must have server-side redeploy disabled. Source
immutability prevents replacement after the inventory is signed; destination
immutability prevents replacement after promotion. Client preflight checks do
not remove this server-side requirement. Use commit-SHA names for snapshots and
immutable semantic-version paths for releases.

The PyPI trusted-publishing workflow passes one `dist` artifact from build to
the protected `pypi` environment. Configure the PyPI trusted publisher with the
environment claim exactly `pypi`. Nexus publication and signing consume that
same artifact rather than invoke `python -m build` again. When signing is
enabled, both PyPI and GitHub Release jobs require signing success.

## Nexus Repository setup

At minimum, create:

- a PyPI proxy and group for dependency downloads;
- a hosted PyPI staging/source repository with cleanup as appropriate and
  **redeploy disabled**;
- a hosted PyPI release/destination repository with **redeploy disabled**;
- a hosted raw repository for checksums, SBOMs, signatures, and scan reports;
- an OCI/Docker hosted repository if images are stored in Nexus.

Use separate read and deploy roles. The CI deploy identity should be unable to
delete or overwrite release components. Enforce TLS, back up blob stores and
metadata, and test restore procedures.

`NEXUS_PYPI_REPOSITORY_URL` is the direct upload endpoint. Set
`NEXUS_STAGING_BASE_URL` and `NEXUS_STAGING_SOURCE_REPOSITORY` for both CE
reference verification and Pro promotion. Set `NEXUS_STAGING_PROMOTION_TARGET`
only when Pro should move the signed component set into an immutable hosted
release repository. `NEXUS_EXPECTED_HOST` is the exact approved host or
host:port; `NEXUS_EXPECTED_PATH_PREFIX` is `/` for a root installation or the
exact Nexus context path such as `/nexus`.

Staging is not enabled merely by setting a URL. An administrator must create the
source and destination repositories, disable redeploy on both, and configure
policy rules, exact tag/move permissions, and the target repository. A PyPI
wheel and sdist can be separate Nexus components; the publisher therefore
captures and signs the exact component set and every asset path, SHA-256, and
size for the logical release. It associates the Pro tag with each exact
component by asset digest rather than broadly tagging a name/version.

The signed Nexus manifest, its Sigstore bundle, `SHA256SUMS`, SPDX SBOM, and
package files are attached to the protected GitHub Release. `promote.yml` takes
only that protected release tag, verifies the publish-workflow Sigstore identity,
checks the durable evidence and current source inventory, then either verifies
the CE reference or moves the signed Pro tag. After a Pro move it requires the
complete destination inventory to be byte-identical and the tagged source set to
be empty. Operator-supplied paths, digests, repository names, or component tags
never authorize promotion. Nexus Repository 3 Pro uses
`POST /service/rest/v1/staging/move/{destination}?repository={source}&tag=...`;
Nexus Repository 2 staging profile IDs do not drive this NXRM3 operation.

Checkmarx One, Nexus Lifecycle/IQ, and Prisma Cloud normally require commercial
licenses. SonarQube quality-gate and security features depend on the installed
edition. Nexus Repository features, including staging, depend on edition and
license. Open-source fallbacks provide useful technical coverage, but they do
not reproduce commercial license governance, organization policy, or runtime
posture features.

## GitHub environments and OIDC

Create `development`, `staging`, `production`, `security-scanning`,
`artifact-publish`, and `pypi` environments in repository settings. Git cannot
configure required reviewers for those environments.

- Protect `main` and `v*` tags with GitHub rulesets: block deletion and force
  updates, require the release checks, and restrict tag creation.
- Restrict `security-scanning`, `artifact-publish`, `pypi`, and production to
  protected branches/tags. Require an independent reviewer and enable **prevent
  self-review**. These settings—not the two-caller layout—are the actual
  same-repository-PR secret and publication boundary.
- Configure the PyPI trusted publisher for this repository, `publish.yml`, and
  the environment claim `pypi`; do not use a long-lived PyPI token.
- Put Nexus publishing and deployment credentials in the narrowest
  environment, not at repository scope.
- Give `id-token: write` only to PyPI trusted publishing and keyless signing
  jobs. Keep all other jobs at `contents: read` unless a documented operation
  needs another permission.

Cloud authentication placeholders should be non-secret identifiers: for
example `AWS_ROLE_TO_ASSUME` and `AWS_REGION`,
`AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID`, or
`GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT`. Add only the
official provider login action needed by the selected cloud and pin it to a
reviewed commit. Do not add long-lived cloud keys as placeholders.

## Container trust model

The Dockerfile has two stages:

1. The builder copies only package metadata and `src/`, then builds the local
   readtheplan wheel and all runtime dependency wheels.
2. The runtime installs only from that wheelhouse with `--no-index`. It does
   not install an unrelated public readtheplan release and does not contain the
   checkout source tree, Git history, tests, plans, or local build output. The
   installed Python package necessarily includes its wheel's runtime modules.

The runtime uses UID/GID 10001, has no login shell, retains
`/workspace` as its working directory, and preserves the existing
`readtheplan` entrypoint and `--help` default. The evolution state lives under `/home/readtheplan/.readtheplan`; mount that path when self-improving mode must persist across runs. There is no health check
because this image is a one-shot CLI, not a long-running service.

The build needs network access to obtain the base image and dependency wheels.
Normal analysis does not need network access. A hardened invocation is:

```bash
docker run --rm --read-only --cap-drop=ALL \
  --security-opt no-new-privileges --network=none \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src="$PWD",dst=/workspace,readonly \
  readtheplan:local analyze plan.json
```

`PYTHON_IMAGE` defaults to `python:3.10-slim` for compatibility. Production
builders should pass an approved digest, for example
`--build-arg PYTHON_IMAGE=python:3.10-slim@sha256:<digest>`. Dependabot is
configured for Docker ecosystem updates, while the image digest and SBOM remain
release evidence.

## Manual enablement checklist

1. Obtain licenses and create vendor projects/applications.
2. Protect `main` and `v*` tags. Create `security-scanning`,
   `artifact-publish`, and `pypi` environments restricted to protected refs,
   require an independent reviewer, enable prevent self-review, and keep
   credentials only in their environment. Configure the PyPI trusted publisher
   with environment claim `pypi`.
3. Configure Nexus hosted/proxy/group repositories, redeploy-disabled source
   and destination repositories, deployment policy, roles, cleanup, backups,
   and optional Pro staging.
4. Set one `ENABLE_*` variable at a time and validate a manual run.
5. Keep `STRICT_ENTERPRISE_GATES=false` while wiring credentials so an
   incomplete enabled integration is reported and skipped. Any scan that
   actually runs remains blocking.
6. Turn on strict gates after all enabled integrations are configured so later
   credential or endpoint drift fails closed.
7. Add stable blocking check names to the branch ruleset.
8. Verify a release's PyPI and Nexus package checksums match the workflow build
   artifact and that the deployed image resolves to the signed digest.
