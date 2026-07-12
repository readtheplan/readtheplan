# readtheplan examples

Real Terraform plans plus the readtheplan output for each. Read these to see the tool produce evidence on actual input.

## 01-small-create

Three small additions: KMS key, IAM role update, CloudWatch log group.
Demonstrates baseline risk classification.

- [Input plan](01-small-create/plan.json)
- [Markdown output](01-small-create/analysis.md)
- [JSON output (SOC 2)](01-small-create/analysis.json)

## 02-dangerous-replacement

The interesting one: a customer-data KMS key replacement and an RDS replacement.
Includes a mock-signed evidence envelope.

- [Input plan](02-dangerous-replacement/plan.json)
- [Markdown output](02-dangerous-replacement/analysis.md)
- [JSON output (SOC 2)](02-dangerous-replacement/analysis.json)
- [Signed evidence](02-dangerous-replacement/evidence.json) - mock fixture; `readtheplan verify examples/02-dangerous-replacement/evidence.json`
  completes with a fixture-bundle failure unless replaced with a real Sigstore bundle.

## 03-multi-resource

A realistic multi-component release. EKS, RDS, S3, IAM, and networking.
Shows `controls_touched` aggregation across many changes.

- [Input plan](03-multi-resource/plan.json)
- [Markdown output](03-multi-resource/analysis.md)
- [JSON output (SOC 2)](03-multi-resource/analysis.json)

## 04-agent-gate-ci

Dogfood example of `readtheplan agent-gate` for coding agents and CI/CD pipelines.
Demonstrates the structured JSON contract and a GitHub Actions workflow.

- [Example README](04-agent-gate-ci/README.md)
- [JSON output](04-agent-gate-ci/agent-gate.json)
- [GitHub Actions workflow](04-agent-gate-ci/github-actions.yml)

## Infrastructure adapters

Runnable source inputs for the built-in cross-tool agent gates:

- [Ansible playbook](07-ansible-playbook/playbook.yml): `readtheplan ansible examples/07-ansible-playbook/playbook.yml`
- [Jenkins pipeline](08-jenkins-pipeline/Jenkinsfile): `readtheplan jenkins examples/08-jenkins-pipeline/Jenkinsfile`
- [Chef recipe](09-chef-recipe/default.rb): `readtheplan chef examples/09-chef-recipe/default.rb`
- [Puppet manifest](10-puppet-manifest/site.pp): `readtheplan puppet examples/10-puppet-manifest/site.pp`
- [Pulumi preview](11-pulumi-preview/preview.json): `readtheplan pulumi examples/11-pulumi-preview/preview.json`
- [Rendered Kubernetes YAML](12-kubernetes-yaml/rendered.yaml): `readtheplan kubernetes examples/12-kubernetes-yaml/rendered.yaml`

## Regenerate

If the CLI changes, regenerate outputs with:

```bash
scripts/regenerate-examples.sh
```
