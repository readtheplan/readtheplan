# CI/CD integration examples

`readtheplan` is CI-neutral. The GitHub Action is a native convenience wrapper;
every other CI system can use the same versioned CLI and exit-code contract.

All examples in this directory assume an earlier step in the same job has produced
Terraform/OpenTofu plan JSON:

```bash
terraform plan -out=tfplan -input=false
terraform show -json tfplan > plan.json
```

Then the portable gate is:

```bash
python -m pip install "readtheplan==0.5.0"
readtheplan analyze --fail-on dangerous plan.json
```

`0` means the analysis completed below the threshold, `2` means the analysis
completed and met the threshold, and `1` means a hard input or execution error.
CI systems normally treat either non-zero result as a failed step.

Copy the example for your platform after the step that creates `plan.json`:

- [GitLab CI](gitlab-ci.example.yml)
- [Jenkins](Jenkinsfile.example)
- [Azure DevOps](azure-pipelines.example.yml)
- [CircleCI](circleci.example.yml)
- [Buildkite](buildkite.example.yml)
- [Bitbucket Pipelines](bitbucket-pipelines.example.yml)
- [Generic Bash gate](readtheplan-gate.sh)

The examples save only derived summaries and evidence. They do not publish
`plan.json`, because Terraform plan JSON can contain sensitive values. If jobs must
exchange a plan artifact, use your CI provider's protected artifact controls and
shortest practical retention period.

To change the gate, replace `dangerous` with `safe`, `review`, or `irreversible`.
Omit `--fail-on` for report-only operation.
