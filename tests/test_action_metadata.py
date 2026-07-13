from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_action_uses_json_cli_contract() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    parser = (ROOT / "scripts" / "parse_action_output.py").read_text(encoding="utf-8")

    assert "readtheplan analyze --format json" in action
    assert "summary-json" in action
    assert "$GITHUB_ACTION_PATH" in action
    assert "install-source" in action
    assert 'default: ""' in action
    assert "action and CLI versions match" in action
    assert "parse_action_output.py" in action
    assert "fail-on-any-change" in action
    assert "fail-on-threshold" in action
    assert "input-file" in action
    assert "tool:" in action
    assert (
        "scan|terraform-config|terraform-lock|terraform-state|terraform-stack|terragrunt|terramate|spacelift|cloudformation|cdk|azure|bicep|kubernetes|helm|helmfile|kustomize|skaffold|devspace|tilt|cue|jsonnet|tanka|ytt|vendir|kbld|imgpkg|kapp|crossplane|serverless|sam|pulumi|pulumi-project|"
        "ansible|ansible-project|jenkins|jenkins-jcasc|jenkins-project|teamcity|chef|chef-project|inspec|"
        "puppet|puppet-project|"
        "github-actions|gitlab-ci|circleci|azure-pipelines|bitbucket-pipelines|buildkite|"
        "travis-ci|drone-ci|woodpecker-ci|concourse|bamboo|"
        "codebuild|cloud-build|codepipeline|"
        "atlantis|"
        "docker-compose|docker-bake|"
        "dockerfile|nomad|packer|salt|salt-project|nix|dsc|cfengine|opa|sentinel|sops|vagrant|"
        "cloud-init|systemd|nginx|haproxy|envoy|traefik|caddy|grafana|loki|vault|consul|"
        "prometheus|alertmanager|"
        "otel-collector"
    ) in action
    assert "RESOLVED_INPUT_FILE" in action
    assert '[ ! -e "$INPUT_FILE" ]' in action
    assert "p.get('risks', p.get('risk_counts', {}))" in action
    assert "deprecationMessage" in action
    assert "risk_counts=" in action
    assert "threshold_reached" in action
    assert "FAIL_ON_CHANGES: ${{ inputs.fail-on-changes }}" in action
    assert 'FAIL_ON_CHANGES="${{ inputs.fail-on-changes }}"' not in action
    assert "resource_change_count" in parser
    assert "### Changes" in parser
    assert "_markdown_cell" in parser
    assert "changes[:20]" in parser
    assert "MAX_GITHUB_OUTPUT_BYTES" in parser
    assert '"rtp-agent-gate-v1"' in parser
    assert "grep" not in action
    assert "pip install readtheplan" not in action


def test_action_workflow_covers_success_and_failure_paths() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test-action.yml").read_text(encoding="utf-8")

    assert "tests/fixtures/valid_plan.json" in workflow
    assert "tool: scan" in workflow
    assert "input-file: tests/fixtures/project_scan" in workflow
    provider_fixtures = (
        "cloudflare_plan_risky.json",
        "github_provider_plan_risky.json",
        "gitlab_provider_plan_risky.json",
        "datadog_provider_plan_risky.json",
        "vault_provider_plan_risky.json",
        "grafana_provider_plan_risky.json",
        "tfe_provider_plan_risky.json",
        "kubernetes_helm_provider_plan_risky.json",
        "pagerduty_provider_plan_risky.json",
        "newrelic_provider_plan_risky.json",
    )
    for fixture in provider_fixtures:
        assert f"fixture: tests/fixtures/{fixture}" in workflow
    assert "provider-action:" in workflow
    assert "name: provider-action (${{ matrix.provider }})" in workflow
    assert "fail-fast: false" in workflow
    assert "max-parallel: 5" in workflow
    assert "input-file: ${{ matrix.fixture }}" in workflow
    serial_workflow = workflow.split("\n  provider-action:", maxsplit=1)[0]
    assert all(fixture not in serial_workflow for fixture in provider_fixtures)
    assert "tests/fixtures/invalid_plan.json" in workflow
    assert "tests/fixtures/does-not-exist.json" in workflow
    assert 'fail-on-any-change: "true"' in workflow
    assert 'fail-on-threshold: "dangerous"' in workflow
    assert "tool: pulumi" in workflow
    assert "input-file: tests/fixtures/pulumi_preview_mixed.json" in workflow
    assert "tool: pulumi-project" in workflow
    assert "input-file: tests/fixtures/pulumi_project_risky.yaml" in workflow
    assert "tool: terraform-state" in workflow
    assert "input-file: tests/fixtures/terraform_state_show_risky.json" in workflow
    assert "tool: cdk" in workflow
    assert "input-file: tests/fixtures/cdk_assembly_risky.json" in workflow
    assert "tool: azure" in workflow
    assert "input-file: tests/fixtures/azure_whatif_mixed.json" in workflow
    assert "tool: bicep" in workflow
    assert "input-file: tests/fixtures/bicep_source_risky.bicep" in workflow
    assert "tool: github-actions" in workflow
    assert "input-file: tests/fixtures/github_actions_deploy.yml" in workflow
    assert "tool: docker-compose" in workflow
    assert "input-file: tests/fixtures/docker_compose_risky.yml" in workflow
    assert "tool: docker-bake" in workflow
    assert "input-file: tests/fixtures/docker-bake.risky.hcl" in workflow
    assert "tool: terraform-stack" in workflow
    assert "input-file: tests/fixtures/terraform_stack_risky.tfdeploy.hcl" in workflow
    assert "tool: nomad" in workflow
    assert "input-file: tests/fixtures/nomad_plan_risky.json" in workflow
    assert "input-file: tests/fixtures/flux_gitops_risky.yml" in workflow
    assert "input-file: tests/fixtures/tekton_risky.yml" in workflow
    assert "input-file: tests/fixtures/kubernetes_controllers_risky.yml" in workflow
    assert "input-file: tests/fixtures/kubernetes_infra_controllers_risky.yml" in workflow
    assert "input-file: tests/fixtures/kubernetes_mesh_policy_serverless_risky.yml" in workflow
    assert "tool: packer" in workflow
    assert "input-file: tests/fixtures/packer_inspect_risky.txt" in workflow
    assert "tool: skaffold" in workflow
    assert "input-file: tests/fixtures/skaffold_risky.yaml" in workflow
    assert "tool: devspace" in workflow
    assert "input-file: tests/fixtures/devspace_risky.yaml" in workflow
    assert "tool: tilt" in workflow
    assert "input-file: tests/fixtures/Tiltfile.risky" in workflow
    assert "tool: cue" in workflow
    assert "input-file: tests/fixtures/deploy_risky_tool.cue" in workflow
    assert "tool: tanka" in workflow
    assert "input-file: tests/fixtures/tanka_main_risky.jsonnet" in workflow
    assert "tool: helmfile" in workflow
    assert "input-file: tests/fixtures/helmfile_risky.yaml.gotmpl" in workflow
    assert "tool: terramate" in workflow
    assert "tool: spacelift" in workflow
    assert "input-file: tests/fixtures/spacelift_runtime_risky.yml" in workflow
    assert "input-file: tests/fixtures/terramate_risky.tm.hcl" in workflow
    assert "tool: vendir" in workflow
    assert "input-file: tests/fixtures/vendir_risky.yml" in workflow
    assert "tool: salt" in workflow
    assert "input-file: tests/fixtures/salt_states_risky.sls" in workflow
    assert "tool: salt-project" in workflow
    assert "input-file: tests/fixtures/salt_master_project_risky.yaml" in workflow
    assert "tool: nix" in workflow
    assert "input-file: tests/fixtures/nixos_module_risky.nix" in workflow
    assert "tool: dsc" in workflow
    assert "input-file: tests/fixtures/powershell_dsc_risky.ps1" in workflow
    assert "tool: cfengine" in workflow
    assert "input-file: tests/fixtures/cfengine_policy_risky.cf" in workflow
    assert "tool: vagrant" in workflow
    assert "input-file: tests/fixtures/Vagrantfile.risky" in workflow
    assert "tool: cloud-init" in workflow
    assert "input-file: tests/fixtures/cloud_init_risky.yml" in workflow
    assert "tool: systemd" in workflow
    assert "input-file: tests/fixtures/systemd_risky.service" in workflow
    assert "tool: nginx" in workflow
    assert "input-file: tests/fixtures/nginx_risky.conf" in workflow
    assert "tool: haproxy" in workflow
    assert "input-file: tests/fixtures/haproxy_risky.cfg" in workflow
    assert "tool: dockerfile" in workflow
    assert "input-file: tests/fixtures/Dockerfile.risky" in workflow
    assert "tool: azure-pipelines" in workflow
    assert "input-file: tests/fixtures/azure_pipelines_deploy.yml" in workflow
    assert "tool: bitbucket-pipelines" in workflow
    assert "input-file: tests/fixtures/bitbucket_pipelines_deploy.yml" in workflow
    assert "tool: buildkite" in workflow
    assert "input-file: tests/fixtures/buildkite_deploy.yml" in workflow
    assert "tool: travis-ci" in workflow
    assert "input-file: tests/fixtures/travis_ci_risky.yml" in workflow
    assert "tool: drone-ci" in workflow
    assert "input-file: tests/fixtures/drone_ci_risky.yml" in workflow
    assert "tool: woodpecker-ci" in workflow
    assert "input-file: tests/fixtures/woodpecker_ci_risky.yml" in workflow
    assert "tool: concourse" in workflow
    assert "input-file: tests/fixtures/concourse_risky.yml" in workflow
    assert "tool: bamboo" in workflow
    assert "input-file: tests/fixtures/bamboo_risky.yml" in workflow
    assert "tool: teamcity" in workflow
    assert "input-file: tests/fixtures/teamcity_risky.kts" in workflow
    assert "tool: codebuild" in workflow
    assert "input-file: tests/fixtures/codebuild_risky.yml" in workflow
    assert "tool: cloud-build" in workflow
    assert "input-file: tests/fixtures/google_cloud_build_risky.yml" in workflow
    assert "tool: codepipeline" in workflow
    assert "input-file: tests/fixtures/codepipeline_risky.json" in workflow
    assert "tool: sops" in workflow
    assert "input-file: tests/fixtures/secret.sops.yaml" in workflow
    assert "tool: atlantis" in workflow
    assert "input-file: tests/fixtures/atlantis_risky.yaml" in workflow
    assert "tool: envoy" in workflow
    assert "input-file: tests/fixtures/envoy_risky.yaml" in workflow
    assert "tool: prometheus" in workflow
    assert "input-file: tests/fixtures/prometheus_risky.yml" in workflow
    assert "tool: alertmanager" in workflow
    assert "input-file: tests/fixtures/alertmanager_risky.yml" in workflow
    assert "tool: otel-collector" in workflow
    assert "input-file: tests/fixtures/otel_collector_risky.yml" in workflow
    assert "tool: traefik" in workflow
    assert "input-file: tests/fixtures/traefik_risky.yml" in workflow
    assert "tool: grafana" in workflow
    assert "input-file: tests/fixtures/grafana_provisioning_risky.yml" in workflow
    assert "tool: vault" in workflow
    assert "input-file: tests/fixtures/vault_risky.hcl" in workflow
    assert "tool: consul" in workflow
    assert "input-file: tests/fixtures/consul_risky.hcl" in workflow
    assert "tool: loki" in workflow
    assert "input-file: tests/fixtures/loki_risky.yml" in workflow
    assert "tool: caddy" in workflow
    assert "input-file: tests/fixtures/Caddyfile.risky" in workflow
    assert "tool: terraform-config" in workflow
    assert "input-file: tests/fixtures/terraform_config_risky.tf" in workflow
    assert "tool: terraform-lock" in workflow
    assert "input-file: tests/fixtures/terraform_lock_risky.hcl" in workflow
    assert "tool: terragrunt" in workflow
    assert "input-file: tests/fixtures/terragrunt_risky.hcl" in workflow
    assert "tool: helm" in workflow
    assert "input-file: tests/fixtures/helm_template_risky.yaml" in workflow
    assert "tool: kustomize" in workflow
    assert "input-file: tests/fixtures/kustomization_risky.yml" in workflow
    assert "tool: crossplane" in workflow
    assert "input-file: tests/fixtures/crossplane_risky.yml" in workflow
    assert "tool: serverless" in workflow
    assert "input-file: tests/fixtures/serverless_framework_risky.yml" in workflow
    assert "tool: sam" in workflow
    assert "input-file: tests/fixtures/sam_template_risky.yml" in workflow
    assert "input-file: tests/fixtures/ansible_config_management_risky.yml" in workflow
    assert "tool: ansible-project" in workflow
    assert "input-file: tests/fixtures/ansible_project_risky.cfg" in workflow
    assert "input-file: tests/fixtures/ansible_inventory_plugin_risky.aws_ec2.yml" in workflow
    assert "input-file: tests/fixtures/ansible_content_policy_risky/.ansible-lint" in workflow
    assert "input-file: tests/fixtures/ansible_controller_export_risky.json" in workflow
    assert "input-file: tests/fixtures/ansible_rulebook_risky.yml" in workflow
    assert "input-file: tests/fixtures/Jenkinsfile.config-management-risky" in workflow
    assert "tool: jenkins-jcasc" in workflow
    assert "input-file: tests/fixtures/jenkins_jcasc_risky.yml" in workflow
    assert "tool: jenkins-project" in workflow
    assert "input-file: tests/fixtures/jenkins_plugins_risky.txt" in workflow
    assert "input-file: tests/fixtures/chef_config_management_risky.rb" in workflow
    assert "tool: chef-project" in workflow
    assert "input-file: tests/fixtures/chef_policyfile_risky.rb" in workflow
    assert "input-file: tests/fixtures/chef_runtime/client.rb" in workflow
    assert "input-file: tests/fixtures/chef_test_kitchen_risky/.kitchen.yml" in workflow
    assert "input-file: tests/fixtures/chef_habitat_risky/habitat/plan.sh" in workflow
    assert "tool: inspec" in workflow
    assert "input-file: tests/fixtures/inspec_profile_risky/controls/main.rb" in workflow
    assert "input-file: tests/fixtures/puppet_config_management_risky.pp" in workflow
    assert "tool: puppet-project" in workflow
    assert "input-file: tests/fixtures/Puppetfile.project-risky" in workflow
    assert "input-file: tests/fixtures/puppet_server_policy_risky/auth.conf" in workflow
    assert "steps.unsupported_tool.outcome != 'failure'" in workflow
    assert "steps.invalid.outcome != 'failure'" in workflow
    assert "steps.fail_on_changes.outcome != 'failure'" in workflow
    assert "steps.fail_on_threshold.outcome != 'failure'" in workflow


def test_repository_collaboration_templates_exist() -> None:
    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    bug = ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml"
    feature = ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml"
    pr_template = ROOT / ".github" / "pull_request_template.md"
    dependabot = ROOT / ".github" / "dependabot.yml"

    assert "* @texasich" in codeowners
    assert bug.exists()
    assert feature.exists()
    assert "Tests added or updated" in pr_template.read_text(encoding="utf-8")
    assert "AI assistance disclosed" in pr_template.read_text(encoding="utf-8")
    assert "github-actions" in dependabot.read_text(encoding="utf-8")
