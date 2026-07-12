from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.jenkins_jcasc import (
    JenkinsJCasCAdapter,
    JenkinsJCasCInputError,
    analyze_jenkins_jcasc,
    parse_jenkins_jcasc,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    source = (FIXTURES / fixture).read_text(encoding="utf-8")
    return JenkinsJCasCAdapter().analyze(parse_jenkins_jcasc(source), tool_name="Jenkins JCasC")


def test_jcasc_surfaces_controller_identity_execution_agents_and_secrets() -> None:
    changes = _changes("jenkins_jcasc_risky.yml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["jenkins_jcasc_security_realm"].risk == "dangerous"
    assert by_type["jenkins_jcasc_authorization"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_credential"].risk == "dangerous"
    assert by_type["jenkins_jcasc_secret_interpolation"].risk == "dangerous"
    assert by_type["jenkins_jcasc_controller_execution"].risk == "dangerous"
    assert by_type["jenkins_jcasc_privileged_agent"].risk == "dangerous"
    assert by_type["jenkins_jcasc_mutable_agent_image"].risk == "dangerous"
    assert by_type["jenkins_jcasc_global_libraries"].risk == "dangerous"
    assert by_type["jenkins_jcasc_tls_verification"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_endpoint"].risk == "dangerous"
    assert by_type["jenkins_jcasc_script_approval"].risk == "dangerous"
    assert by_type["jenkins_jcasc_csrf_protection"].risk == "dangerous"
    assert by_type["jenkins_jcasc_job_dsl"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_environment_secret"].risk == "dangerous"


def test_jcasc_external_secrets_pinned_agents_and_libraries_stay_review() -> None:
    changes = _changes("jenkins_jcasc_review.yml")
    kinds = {change.resource_type for change in changes}
    assert "jenkins_jcasc_plaintext_credential" not in kinds
    assert "jenkins_jcasc_secret_interpolation" not in kinds
    assert "jenkins_jcasc_privileged_agent" not in kinds
    assert "jenkins_jcasc_mutable_agent_image" not in kinds
    assert {change.risk for change in changes} == {"review"}


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("services:\n  web: {}\n", "recognized JCasC"),
        ("jenkins:\n  numExecutors: 0\n  numExecutors: 2\n", "duplicate YAML key"),
        ("---\njenkins: {}\n---\ncredentials: {}\n", "exactly one YAML"),
    ],
)
def test_jcasc_parser_rejects_invalid_or_ambiguous_yaml(source: str, error: str) -> None:
    with pytest.raises(JenkinsJCasCInputError, match=error):
        parse_jenkins_jcasc(source)


def test_jcasc_parser_supports_documented_yaml_anchors() -> None:
    data = parse_jenkins_jcasc(
        """x-agent: &agent
  remoteFS: /home/jenkins
  launcher:
    inbound: {}
jenkins:
  nodes:
    - permanent:
        <<: *agent
        name: agent-one
    - permanent:
        <<: *agent
        name: agent-two
"""
    )
    assert len(data["jenkins_jcasc"]["jenkins"]["nodes"]) == 2


def test_jcasc_nonverifying_ssh_agent_fails_dangerous() -> None:
    data = parse_jenkins_jcasc(
        """jenkins:
  nodes:
    - permanent:
        name: unsafe
        launcher:
          ssh:
            hostKeyVerificationStrategy:
              nonVerifyingKeyVerificationStrategy: {}
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["jenkins_jcasc_privileged_agent"].risk == "dangerous"


def test_jcasc_role_authorization_catches_broad_subject_assignment() -> None:
    data = parse_jenkins_jcasc(
        """jenkins:
  authorizationStrategy:
    roleBased:
      roles:
        global:
          - name: administrators
            permissions:
              - Overall/Administer
            assignments:
              - authenticated
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    authorization = next(
        change for change in changes if change.resource_type == "jenkins_jcasc_authorization"
    )
    assert authorization.risk == "dangerous"


def test_jcasc_secret_interpolation_in_credential_description_is_exposed() -> None:
    data = parse_jenkins_jcasc(
        """credentials:
  system:
    domainCredentials:
      - credentials:
          - usernamePassword:
              id: registry
              username: robot
              password: ${REGISTRY_PASSWORD}
              description: ${ADMIN_SECRET}
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    kinds = {change.resource_type for change in changes}
    assert "jenkins_jcasc_plaintext_credential" not in kinds
    assert "jenkins_jcasc_secret_interpolation" in kinds


def test_jcasc_gate_uses_shared_contract() -> None:
    source = (FIXTURES / "jenkins_jcasc_risky.yml").read_text(encoding="utf-8")
    gate = analyze_jenkins_jcasc(parse_jenkins_jcasc(source))
    assert gate["adapter"] == "jenkins-jcasc"
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())


def test_jcasc_cli_reads_yaml(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "jenkins.yaml"
    source.write_text(
        (FIXTURES / "jenkins_jcasc_risky.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert main(["jenkins-jcasc", "--framework", "soc2", str(source)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "jenkins-jcasc"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
