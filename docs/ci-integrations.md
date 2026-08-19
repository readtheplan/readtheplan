# CI/CD integrations

The `readtheplan` CLI is the stable integration surface for any CI/CD system.
The native GitHub Action wraps the same analyzer, but GitHub Actions is not
required.

## Portable contract

Generate Terraform/OpenTofu plan JSON, install a pinned release, and choose the
risk level that should fail the job:

```bash
terraform plan -out=tfplan -input=false
terraform show -json tfplan > plan.json
python -m pip install "readtheplan==0.5.0"
readtheplan analyze --fail-on dangerous plan.json
```

The command prints its report before returning:

| Exit | Meaning | Typical CI behavior |
| --- | --- | --- |
| `0` | Analysis succeeded below the threshold | Continue |
| `1` | Invalid input, I/O failure, or another hard error | Fail closed |
| `2` | Analysis succeeded and reached the threshold | Block the job |

`--fail-on` accepts `safe`, `review`, `dangerous`, or `irreversible`. Omit it
for report-only operation.

## Supported CI providers

Copy-ready examples live under [`ci/`](../ci/README.md) for:

- GitHub Actions (native composite action)
- GitLab CI
- Jenkins
- Azure DevOps Pipelines
- CircleCI
- Buildkite
- Bitbucket Pipelines
- Any Bash-capable runner

The same command also works in TeamCity, Travis CI, Drone, Woodpecker, Concourse,
Bamboo, AWS CodeBuild, Google Cloud Build, and other systems that can run Python
3.10+ or the project Docker image.

## Evidence and sensitive plans

Add `--format json --framework soc2 --evidence readtheplan-evidence.json` to
produce machine-readable output and a compliance evidence envelope. Archive the
derived output with the CI system's normal artifact mechanism.

Do not publish `plan.json` as a broadly readable build artifact. Terraform plan
JSON can contain sensitive values. Prefer running the gate in the same job that
creates the plan. If a plan must cross job boundaries, use protected artifacts,
least-privilege access, encryption, and the shortest practical retention period.

## Agent gate

Agentic pipelines can consume the versioned decision contract instead:

```bash
readtheplan agent-gate plan.json > agent-gate.json
```

Validate `schema == "rtp-agent-gate-v1"`, then treat `block` as a mandatory stop.
The portable helper [`ci/readtheplan-gate.sh`](../ci/readtheplan-gate.sh) maps
`proceed`, `warn`, and `block` to process exit codes and produces a Markdown
review comment.
